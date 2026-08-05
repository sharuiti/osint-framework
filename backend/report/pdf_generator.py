"""
pdf_generator.py
Génère un rapport PDF complet à partir d'un ScanResult, en rendant
report/template.html (Jinja2) puis en le convertissant en PDF avec
WeasyPrint.

Pourquoi HTML/CSS -> PDF plutôt que reportlab ?
Le rapport a besoin de mise en page riche (tableaux, badges colorés,
barres de score, page de garde) qui colle au thème violet du reste du
framework. Écrire ça avec CSS est très largement plus rapide à itérer
et à maintenir qu'en construisant chaque élément avec l'API Platypus
de reportlab.

Dépendances système (à installer sur Kali AVANT `pip install weasyprint`) :
    sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 libcairo2 libffi-dev

Usage CLI :
    python report/pdf_generator.py --input result.json --out rapport.pdf
    python report/pdf_generator.py --demo --out rapport_demo.pdf
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402

from models.scan_result import ScanResult, build_scan_result  # noqa: E402
from core.scoring_engine import apply_score, WEIGHTS           # noqa: E402

TEMPLATE_DIR = Path(__file__).resolve().parent
CATEGORY_LABELS = {
    "attack_surface": "Surface d'attaque",
    "technologies": "Technologies obsolètes / exposées",
    "employees": "Employés exposés",
    "leaks": "Fuites de credentials",
    "email_security": "Surface de phishing (SPF/DKIM/DMARC)",
    "takeover": "Subdomain takeover",
    "environments": "Environnements hors-prod / panneaux admin",
}


# --------------------------------------------------------------------------
# Recommandations automatiques — dérivées des sous-scores
# --------------------------------------------------------------------------
def _build_recommendations(scan: ScanResult) -> list[dict]:
    """
    Génère des recommandations priorisées à partir des catégories de
    score les plus élevées. Heuristique simple mais transparente :
    un score de catégorie >= 60 déclenche une recommandation associée.
    """
    if not scan.score_details:
        return []

    recs = []
    categories = scan.score_details["categories"]

    admin_panels = [c for c in scan.environment_candidates if c.category == "admin_panel"]
    if admin_panels:
        subdomains_list = ", ".join(c.subdomain for c in admin_panels[:5])
        more = f" (+{len(admin_panels) - 5} autre(s))" if len(admin_panels) > 5 else ""
        recs.append({
            "priority": "Élevée",
            "text": (f"Restreindre l'accès public aux interfaces d'administration détectées : "
                     f"{subdomains_list}{more} (VPN, liste blanche d'IP, authentification "
                     f"renforcée). Ce sont des cibles directement exploitables en cas "
                     f"d'identifiants faibles ou par défaut."),
        })

    if scan.takeover_candidates:
        high_conf = [c for c in scan.takeover_candidates if c.confidence == "high"]
        if high_conf:
            subdomains_list = ", ".join(c.subdomain for c in high_conf[:5])
            more = f" (+{len(high_conf) - 5} autre(s))" if len(high_conf) > 5 else ""
            recs.append({
                "priority": "Critique",
                "text": (f"Vérifier manuellement et retirer ou reconfigurer les enregistrements "
                         f"DNS orphelins suivants, candidats probables au subdomain takeover : "
                         f"{subdomains_list}{more}. Ne jamais tenter de revendiquer la ressource "
                         f"tierce sans autorisation explicite du programme concerné."),
            })
        else:
            recs.append({
                "priority": "Moyenne",
                "text": (f"{len(scan.takeover_candidates)} sous-domaine(s) pointent vers des "
                         f"services potentiellement vulnérables au takeover, sans confirmation "
                         f"par fingerprint — à vérifier manuellement (voir section dédiée)."),
            })

    if categories["leaks"]["score"] >= 60:
        recs.append({
            "priority": "Critique",
            "text": ("Forcer la réinitialisation des mots de passe pour les comptes "
                     "associés aux emails retrouvés dans des fuites, et activer le MFA "
                     "sur tous les comptes exposés."),
        })

    if categories["attack_surface"]["score"] >= 60:
        recs.append({
            "priority": "Élevée",
            "text": ("Auditer la liste des sous-domaines actifs pour identifier ceux qui "
                     "ne sont plus utilisés et réduire la surface exposée publiquement."),
        })

    if categories["technologies"]["score"] >= 40:
        recs.append({
            "priority": "Moyenne",
            "text": ("Mettre à jour les technologies détectées comme obsolètes et masquer "
                     "les bannières de version (headers Server/X-Powered-By) pour limiter "
                     "le fingerprinting."),
        })

    if categories["employees"]["score"] >= 40:
        recs.append({
            "priority": "Moyenne",
            "text": ("Sensibiliser les employés identifiés publiquement au risque de "
                     "phishing ciblé (spear phishing) exploitant ces informations."),
        })

    if categories.get("email_security", {}).get("score", 0) >= 60:
        recs.append({
            "priority": "Critique",
            "text": ("Configurer DMARC avec une politique 'reject' (ou au minimum "
                     "'quarantine') et un enregistrement SPF strict (-all). Sans ça, "
                     "le domaine peut être usurpé pour du phishing ciblant clients, "
                     "partenaires ou employés — indépendamment de toute autre faille."),
        })
    elif categories.get("email_security", {}).get("score", 0) >= 30:
        recs.append({
            "priority": "Moyenne",
            "text": ("Renforcer la politique DMARC actuelle (passer de 'none' à "
                     "'quarantine' ou 'reject') pour transformer la surveillance "
                     "passive en protection active contre l'usurpation de domaine."),
        })

    if not recs:
        recs.append({
            "priority": "Faible",
            "text": "Aucune action prioritaire — poursuivre une surveillance périodique.",
        })

    return recs


# --------------------------------------------------------------------------
# Construction du contexte Jinja2
# --------------------------------------------------------------------------
def _build_context(scan: ScanResult) -> dict:
    """Aplati le ScanResult (+ scoring) en dict prêt pour le template."""
    if scan.score_details:
        score_categories = [
            {
                "label": CATEGORY_LABELS.get(key, key),
                "score": data["score"],
                "weight_pct": int(WEIGHTS.get(key, data["weight"]) * 100),
                "reason": data["reason"],
            }
            for key, data in scan.score_details["categories"].items()
        ]
        score_band = scan.score_details["band"]
    else:
        score_categories, score_band = [], "Low"

    summary = scan.summary()

    return {
        "domain": scan.domain,
        "scanned_at": scan.scanned_at,
        "score": scan.score,
        "score_band": score_band,
        "score_categories": score_categories,
        "total_subdomains": summary["total_subdomains"],
        "total_technologies": summary["total_technologies"],
        "total_employees": summary["total_employees"],
        "total_emails_checked": summary["total_emails_checked"],
        "total_emails_leaked": summary["total_emails_leaked"],
        "subdomains": [s.model_dump() for s in scan.subdomains],
        "technologies": [t.model_dump() for t in scan.technologies],
        "employees": [e.model_dump() for e in scan.employees],
        "leaks": [l.model_dump() for l in scan.leaks],
        "email_security": scan.email_security.model_dump() if scan.email_security else None,
        "takeover_candidates": [c.model_dump() for c in scan.takeover_candidates],
        "environment_candidates": [c.model_dump() for c in scan.environment_candidates],
        "recommendations": _build_recommendations(scan),
    }


# --------------------------------------------------------------------------
# Génération
# --------------------------------------------------------------------------
def generate_pdf(scan: ScanResult, output_path: str) -> str:
    """
    Rend le template avec les données du scan et écrit le PDF sur disque.
    Retourne le chemin du fichier généré.
    """
    # Import différé : weasyprint peut être lourd à charger et n'est
    # nécessaire que pour cette fonction, pas pour --demo sans rendu.
    from weasyprint import HTML

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("template.html")

    context = _build_context(scan)
    html_content = template.render(**context)

    HTML(string=html_content, base_url=str(TEMPLATE_DIR)).write_pdf(output_path)
    return output_path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Génère un rapport PDF depuis un ScanResult")
    parser.add_argument("--input", help="Fichier JSON d'un ScanResult (scoré ou non)")
    parser.add_argument("--out", required=True, help="Chemin du PDF à générer")
    parser.add_argument("--demo", action="store_true", help="Utilise des données factices")
    args = parser.parse_args()

    if args.demo:
        from models.scan_result import _fake_module_outputs
        scan = build_scan_result(domain="example.com", **_fake_module_outputs())
        scan = apply_score(scan)
    elif args.input:
        raw = json.loads(Path(args.input).read_text())
        scan = ScanResult.model_validate(raw)
        if scan.score is None:
            scan = apply_score(scan)
    else:
        parser.error("Fournis --input <fichier.json> ou --demo")
        return

    path = generate_pdf(scan, args.out)
    print(f"[+] Rapport généré : {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
