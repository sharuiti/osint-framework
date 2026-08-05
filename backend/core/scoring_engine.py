"""
scoring_engine.py
Calcule un score d'exposition (0-100) à partir d'un ScanResult, selon
une grille pondérée inspirée des critères MSRC (impact / surface
d'exposition), adaptée à un contexte de reconnaissance OSINT
pré-exploitation (pas de preuve d'exploitation, juste de l'exposition).

Grille de pondération (v4 — 7 catégories) :
    - Surface d'attaque (sous-domaines actifs)      : 9%
    - Technologies obsolètes / versions exposées     : 13%
    - Employés / emails exposés                      : 9%
    - Fuites de credentials                           : 22%
    - Surface de phishing (SPF/DKIM/DMARC)            : 13%
    - Subdomain takeover                              : 22%
    - Environnements hors-prod / panneaux admin       : 12%

Pourquoi ce rééquilibrage (v4) et pas juste "+12% quelque part" :
Contrairement au takeover (signal quasi-confirmé) ou aux fuites
(exposition confirmée), la détection hors-prod est un heuristique sur
le NOM du sous-domaine — "staging.example.com" est probablement un
environnement de test, mais rien ne le garantit. Son poids (12%) reste
donc volontairement inférieur à celui du takeover/fuites, comparable à
la surface de phishing. Plutôt que de choisir ce chiffre à la main puis
de rogner arbitrairement sur les autres, les 6 poids précédents ont été
réduits PROPORTIONNELLEMENT (facteur 0.88 = 1 - 0.12) pour lui faire de
la place — chacun garde son importance relative par rapport aux autres,
seule l'échelle change.

Choix méthodologique assumé : CE SCORE EST QUALITATIF, PAS DU CVSS.
Le CVSS/EPSS a du sens PAR vulnérabilité individuelle (voir la future
corrélation CVE), pas comme moyenne agrégée au niveau d'un domaine —
additionner des CVSS de nature différente n'a pas de fondement
méthodologique et donnerait une fausse impression de rigueur. Cette
grille pondérée, elle, est explicite sur ce qu'elle mesure et pourquoi.

Chaque sous-score est calculé sur 0-100 puis pondéré. Le score final
est mappé sur une échelle Low / Medium / High / Critical.

Usage CLI :
    python core/scoring_engine.py --demo
    python core/scoring_engine.py --input result.json --out scored.json
"""

import argparse
import json
import sys
from pathlib import Path

# Permet d'importer "models.scan_result" quel que soit le dossier
# depuis lequel ce script est lancé (voir run_pipeline.py pour la
# même logique).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.scan_result import ScanResult, build_scan_result  # noqa: E402


# --------------------------------------------------------------------------
# Base de versions considérées obsolètes — À ENRICHIR avec un vrai flux
# CVE (ex: NVD, EndOfLife.date) pour un usage en production. En l'état,
# c'est une heuristique volontairement simple et transparente.
# --------------------------------------------------------------------------
OUTDATED_THRESHOLDS = {
    "wordpress": "6.4",
    "php": "8.0",
    "jquery": "3.5",
    "drupal": "9.0",
    "joomla": "4.0",
    "apache": "2.4.50",
    "nginx": "1.20",
    "openssl": "3.0",
    "laravel": "9.0",
}


def _version_tuple(version: str) -> tuple:
    """Convertit '6.4.1' en (6, 4, 1) pour comparaison, sans dépendance externe."""
    parts = []
    for chunk in version.split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def _is_outdated(tech_name: str, version: str | None) -> bool:
    """Compare la version détectée au seuil connu pour cette techno."""
    if not version:
        return False
    threshold = OUTDATED_THRESHOLDS.get(tech_name.lower())
    if not threshold:
        return False
    return _version_tuple(version) < _version_tuple(threshold)


# --------------------------------------------------------------------------
# Sous-scores (chacun retourne 0-100)
# --------------------------------------------------------------------------
def score_attack_surface(scan: ScanResult) -> tuple[float, str]:
    """
    Basé sur le nombre de sous-domaines actifs. Plus la surface est
    grande, plus il y a de points d'entrée potentiels à auditer.
    """
    count = len(scan.subdomains)

    if count == 0:
        return 0.0, "Aucun sous-domaine actif détecté"
    elif count <= 5:
        return 20.0, f"{count} sous-domaine(s) actif(s) — surface limitée"
    elif count <= 15:
        return 40.0, f"{count} sous-domaines actifs — surface modérée"
    elif count <= 30:
        return 60.0, f"{count} sous-domaines actifs — surface étendue"
    elif count <= 50:
        return 80.0, f"{count} sous-domaines actifs — surface large"
    else:
        return 100.0, f"{count} sous-domaines actifs — surface très large"


def score_technologies(scan: ScanResult) -> tuple[float, str]:
    """
    Combine deux signaux :
      - divulgation de version (une version exacte visible facilite
        le ciblage d'exploits connus, même sans confirmer l'obsolescence)
      - obsolescence confirmée via OUTDATED_THRESHOLDS
    """
    all_techs = [t for entry in scan.technologies for t in entry.technologies]

    if not all_techs:
        return 0.0, "Aucune technologie détectée"

    version_disclosed = sum(1 for t in all_techs if t.version)
    outdated = sum(1 for t in all_techs if _is_outdated(t.name, t.version))

    disclosure_ratio = version_disclosed / len(all_techs)
    disclosure_score = min(50.0, disclosure_ratio * 50.0)

    outdated_score = min(50.0, outdated * 25.0)  # chaque techno obsolète pèse lourd

    total = disclosure_score + outdated_score
    reason = (f"{version_disclosed}/{len(all_techs)} technologies avec version visible, "
              f"{outdated} obsolète(s) détectée(s)")
    return total, reason


def score_employees(scan: ScanResult) -> tuple[float, str]:
    """
    Basé sur le nombre d'employés/emails identifiés, pondéré par la
    confiance : 'high' (Hunter.io, score de confiance élevé) compte
    plein, 'medium' (nom deviné via theHarvester) compte aux 3/4,
    'low' (email générique type contact@) compte pour moitié.
    """
    if not scan.employees:
        return 0.0, "Aucun employé identifié"

    CONFIDENCE_WEIGHTS = {"high": 1.0, "medium": 0.75, "low": 0.5}
    weighted_count = sum(CONFIDENCE_WEIGHTS.get(e.confidence, 0.5) for e in scan.employees)

    if weighted_count <= 2:
        return 20.0, f"{len(scan.employees)} employé(s) identifié(s) — exposition limitée"
    elif weighted_count <= 5:
        return 40.0, f"{len(scan.employees)} employés identifiés — exposition modérée"
    elif weighted_count <= 10:
        return 60.0, f"{len(scan.employees)} employés identifiés — exposition notable"
    elif weighted_count <= 20:
        return 80.0, f"{len(scan.employees)} employés identifiés — exposition élevée"
    else:
        return 100.0, f"{len(scan.employees)} employés identifiés — exposition très élevée"


def score_leaks(scan: ScanResult) -> tuple[float, str]:
    """
    La présence de fuites de credentials est le signal le plus critique :
    un score plancher élevé s'applique dès la première fuite confirmée,
    puis augmente avec la proportion d'emails touchés.
    """
    if not scan.leaks:
        return 0.0, "Aucun email vérifié"

    leaked = [l for l in scan.leaks if l.leaked]
    if not leaked:
        return 0.0, f"0/{len(scan.leaks)} email(s) retrouvé(s) dans des fuites connues"

    ratio = len(leaked) / len(scan.leaks)
    # Plancher à 60 dès qu'une fuite existe (cf. spec : "présence = score élevé"),
    # puis monte jusqu'à 100 si une large part des emails est touchée.
    score = 60.0 + min(40.0, ratio * 40.0)
    return score, f"{len(leaked)}/{len(scan.leaks)} email(s) retrouvé(s) dans des fuites connues"


def score_email_security(scan: ScanResult) -> tuple[float, str]:
    """
    Combine SPF, DMARC et DKIM en un score de surface de phishing.

    DMARC pèse le plus (55%) : c'est le seul des trois qui détermine
    RÉELLEMENT ce qui arrive à un email usurpé (rejeté, mis en spam,
    ou délivré normalement). SPF pèse 35% : nécessaire mais contournable
    sans DMARC pour l'appliquer. DKIM ne pèse que 10% et de façon
    plafonnée : son absence parmi les sélecteurs courants ne prouve
    rien (voir email_security.py), on ne peut donc pas lui donner le
    même poids qu'un signal certain comme DMARC/SPF.
    """
    if not scan.email_security:
        return 0.0, "Analyse SPF/DKIM/DMARC non exécutée"

    RISK_POINTS = {"low": 10.0, "medium": 40.0, "high": 70.0, "critical": 100.0}

    dmarc_points = RISK_POINTS.get(scan.email_security.dmarc.risk, 40.0)
    spf_points = RISK_POINTS.get(scan.email_security.spf.risk, 40.0)
    # Score plafonné à 30 (pas 100) : un DKIM "non trouvé" reste une
    # hypothèse faible, jamais une certitude d'absence.
    dkim_points = 0.0 if scan.email_security.dkim.detected else 30.0

    total = dmarc_points * 0.55 + spf_points * 0.35 + dkim_points * 0.10

    reason = (f"DMARC: {scan.email_security.dmarc.policy or 'absent'} "
              f"({scan.email_security.dmarc.risk}) | "
              f"SPF: {scan.email_security.spf.qualifier or 'absent'} "
              f"({scan.email_security.spf.risk}) | "
              f"DKIM: {'confirmé' if scan.email_security.dkim.detected else 'non trouvé'}")

    return total, reason


def score_takeover(scan: ScanResult) -> tuple[float, str]:
    """
    Score basé sur la confiance des candidats détectés. Un seul
    candidat à haute confiance suffit à pousser le score très haut —
    contrairement aux autres catégories, ce n'est pas un signal qui a
    besoin de "volume" pour être pris au sérieux.
    """
    if not scan.takeover_candidates:
        return 0.0, "Aucun candidat de subdomain takeover détecté"

    high = [c for c in scan.takeover_candidates if c.confidence == "high"]
    low = [c for c in scan.takeover_candidates if c.confidence == "low"]

    if high:
        score = min(100.0, 75.0 + (len(high) - 1) * 10.0)
        return score, (f"{len(high)} candidat(s) à haute confiance "
                        f"(CNAME orphelin ou fingerprint confirmé) — "
                        f"vérification manuelle prioritaire avant tout signalement")

    score = min(55.0, 25.0 + len(low) * 10.0)
    return score, (f"{len(low)} candidat(s) à confiance faible "
                    f"(service potentiellement vulnérable, fingerprint non confirmé)")


def score_environments(scan: ScanResult) -> tuple[float, str]:
    """
    Score basé sur les candidats hors-prod/admin détectés. Les
    panneaux d'administration pèsent plus lourd que les environnements
    hors-prod génériques — ce sont des cibles directement exploitables
    (souvent avec des identifiants faibles/par défaut), alors qu'un
    "staging." est surtout un signal de surface élargie.
    """
    if not scan.environment_candidates:
        return 0.0, "Aucun environnement hors-prod ou panneau d'administration détecté"

    admin = [c for c in scan.environment_candidates if c.category == "admin_panel"]
    nonprod = [c for c in scan.environment_candidates if c.category == "non_prod"]

    ADMIN_POINTS, NONPROD_POINTS = 25.0, 12.0
    score = min(100.0, len(admin) * ADMIN_POINTS + len(nonprod) * NONPROD_POINTS)

    reason = (f"{len(admin)} panneau(x) d'administration exposé(s), "
              f"{len(nonprod)} environnement(s) hors-prod détecté(s) "
              f"(heuristique sur le nom, vérification manuelle nécessaire)")
    return score, reason


# --------------------------------------------------------------------------
# Agrégation
# --------------------------------------------------------------------------
WEIGHTS = {
    "attack_surface": 0.09,
    "technologies": 0.13,
    "employees": 0.09,
    "leaks": 0.22,
    "email_security": 0.13,
    "takeover": 0.22,
    "environments": 0.12,
}


def _score_band(score: float) -> str:
    """Mappe le score 0-100 sur une échelle qualitative type MSRC."""
    if score < 25:
        return "Low"
    elif score < 50:
        return "Medium"
    elif score < 75:
        return "High"
    else:
        return "Critical"


def calculate_score(scan: ScanResult) -> dict:
    """
    Calcule le score pondéré complet et retourne le détail par
    catégorie, prêt à être injecté dans ScanResult.score_details.
    """
    surface_score, surface_reason = score_attack_surface(scan)
    tech_score, tech_reason = score_technologies(scan)
    employees_score, employees_reason = score_employees(scan)
    leaks_score, leaks_reason = score_leaks(scan)
    email_sec_score, email_sec_reason = score_email_security(scan)
    takeover_score, takeover_reason = score_takeover(scan)
    environments_score, environments_reason = score_environments(scan)

    weighted_total = (
        surface_score * WEIGHTS["attack_surface"]
        + tech_score * WEIGHTS["technologies"]
        + employees_score * WEIGHTS["employees"]
        + leaks_score * WEIGHTS["leaks"]
        + email_sec_score * WEIGHTS["email_security"]
        + takeover_score * WEIGHTS["takeover"]
        + environments_score * WEIGHTS["environments"]
    )

    return {
        "total": round(weighted_total, 1),
        "band": _score_band(weighted_total),
        "categories": {
            "attack_surface": {
                "score": round(surface_score, 1),
                "weight": WEIGHTS["attack_surface"],
                "reason": surface_reason,
            },
            "technologies": {
                "score": round(tech_score, 1),
                "weight": WEIGHTS["technologies"],
                "reason": tech_reason,
            },
            "employees": {
                "score": round(employees_score, 1),
                "weight": WEIGHTS["employees"],
                "reason": employees_reason,
            },
            "leaks": {
                "score": round(leaks_score, 1),
                "weight": WEIGHTS["leaks"],
                "reason": leaks_reason,
            },
            "email_security": {
                "score": round(email_sec_score, 1),
                "weight": WEIGHTS["email_security"],
                "reason": email_sec_reason,
            },
            "takeover": {
                "score": round(takeover_score, 1),
                "weight": WEIGHTS["takeover"],
                "reason": takeover_reason,
            },
            "environments": {
                "score": round(environments_score, 1),
                "weight": WEIGHTS["environments"],
                "reason": environments_reason,
            },
        },
    }


def apply_score(scan: ScanResult) -> ScanResult:
    """Calcule le score et l'injecte directement dans le ScanResult."""
    details = calculate_score(scan)
    scan.score = details["total"]
    scan.score_details = details
    return scan


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Moteur de scoring — ScanResult")
    parser.add_argument("--input", help="Fichier JSON d'un ScanResult (ex: sortie de run_pipeline.py)")
    parser.add_argument("--out", help="Fichier de sortie (sinon affiché en stdout)")
    parser.add_argument("--demo", action="store_true", help="Utilise des données factices")
    args = parser.parse_args()

    if args.demo:
        from models.scan_result import _fake_module_outputs
        scan = build_scan_result(domain="example.com", **_fake_module_outputs())
    elif args.input:
        raw = json.loads(Path(args.input).read_text())
        scan = ScanResult.model_validate(raw)
    else:
        parser.error("Fournis --input <fichier.json> ou --demo")
        return

    scan = apply_score(scan)

    print("=== Score ===", file=sys.stderr)
    print(f"  Total : {scan.score}/100 ({scan.score_details['band']})", file=sys.stderr)
    for cat, data in scan.score_details["categories"].items():
        print(f"  - {cat}: {data['score']}/100 (poids {int(data['weight']*100)}%) — {data['reason']}",
              file=sys.stderr)

    output = scan.to_json()
    if args.out:
        Path(args.out).write_text(output)
        print(f"\n[+] Résultat écrit dans {args.out}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
