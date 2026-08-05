"""
run_pipeline.py
Script d'orchestration : chaîne les 4 modules de scan (subdomain_scanner,
tech_detector, employee_finder, leak_checker) et construit un ScanResult
unifié via models/scan_result.py.

Ce fichier est SÉPARÉ de scan_result.py — il l'utilise, il ne le remplace
pas. Place-le à la racine de backend/ (à côté de core/ et models/).

Usage CLI :
    python backend/run_pipeline.py example.com
    python backend/run_pipeline.py example.com --provider xposedornot --out result.json
"""

import argparse
import sys
from pathlib import Path
from typing import Callable, Optional

# On force l'ajout du dossier backend/ (parent de ce script) dans sys.path.
# Ça garantit que "core" et "models" sont importables quel que soit
# l'endroit depuis lequel tu lances le script (racine du projet,
# depuis backend/, etc.) — c'est ça qui causait le ModuleNotFoundError.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.subdomain_scanner import scan_subdomains          # noqa: E402
from core.tech_detector import scan_multiple as scan_tech   # noqa: E402
from core.employee_finder import find_employees             # noqa: E402
from core.leak_checker import check_emails                  # noqa: E402
from core.email_security import analyze_email_security       # noqa: E402
from core.takeover_detector import scan_takeovers            # noqa: E402
from core.environment_classifier import classify_environments # noqa: E402
from core.scoring_engine import apply_score                 # noqa: E402
from models.scan_result import build_scan_result            # noqa: E402

# Limite de sécurité : sur un domaine avec des milliers de sous-domaines
# actifs (ex: microsoft.com), lancer WhatWeb + le détecteur lite en
# SÉQUENTIEL sur chaque cible peut tourner pendant des heures et finit
# par épuiser les ressources système (sockets, mémoire, processus Ruby
# de WhatWeb qui s'accumulent) — c'est ce qui a fait planter la Kali.
# On plafonne donc le nombre de cibles réellement passées à l'étape
# technologies. Les sous-domaines ne sont PAS perdus : ils restent
# dans scan.subdomains, seule l'analyse de technos est limitée.
DEFAULT_MAX_TECH_TARGETS = 40

# Même logique pour le takeover detector, plafond plus généreux car le
# coût par cible est plus léger (résolution DNS parallélisée + requête
# HTTP uniquement pour le petit sous-ensemble avec CNAME suspect).
DEFAULT_MAX_TAKEOVER_TARGETS = 150


def run_pipeline(domain: str, provider: str = "xposedornot",
                  leakcheck_key: str | None = None, hibp_key: str | None = None,
                  hunter_key: str | None = None,
                  tech_engine: str = "both",
                  max_tech_targets: int = DEFAULT_MAX_TECH_TARGETS,
                  max_takeover_targets: int = DEFAULT_MAX_TAKEOVER_TARGETS,
                  progress_callback: Optional[Callable[[str], None]] = None) -> dict:
    """
    Exécute les modules dans l'ordre et retourne un ScanResult complet.
    Chaque étape est indépendante : si l'une échoue, les suivantes
    continuent avec des données partielles plutôt que de tout arrêter.

    max_tech_targets : nombre maximum de sous-domaines analysés à
    l'étape technologies. Sur un gros domaine (des milliers de
    sous-domaines actifs), analyser TOUT séquentiellement peut tourner
    pendant des heures et épuiser les ressources système. Au-delà de
    cette limite, seuls les N premiers (triés) sont analysés — mets
    None pour désactiver la limite (déconseillé sur un gros domaine).

    max_takeover_targets : même principe pour la détection de
    subdomain takeover.

    progress_callback : fonction optionnelle appelée avec un texte
    descriptif à chaque étape (ex: pour mettre à jour un statut en base
    depuis app.py). Un callback qui lève une exception ne doit jamais
    interrompre le scan — l'erreur est absorbée silencieusement.
    """
    def report(step_text: str) -> None:
        print(f"\n=== {step_text} ===", file=sys.stderr)
        if progress_callback:
            try:
                progress_callback(step_text)
            except Exception:
                pass  # un callback buggé ne doit jamais faire échouer le scan

    report(f"[1/8] Sous-domaines : {domain}")
    sub_result = scan_subdomains(domain)
    active_domains = [e["subdomain"] for e in sub_result["active_subdomains"]]
    all_valid_domains = sub_result.get("all_valid_subdomains", active_domains)

    report(f"[2/8] Subdomain takeover ({len(all_valid_domains)} candidats potentiels)")
    takeover_result = scan_takeovers(all_valid_domains, domain, max_targets=max_takeover_targets)

    report(f"[3/8] Environnements hors-prod / panneaux admin ({len(active_domains)} cibles)")
    # Uniquement les sous-domaines ACTIFS : un "admin." qui ne répond
    # même pas n'est pas une exposition actuelle, contrairement au
    # takeover où l'inactivité elle-même est le signal.
    environment_result = classify_environments(active_domains)

    tech_targets = active_domains
    truncated = False
    if max_tech_targets is not None and len(active_domains) > max_tech_targets:
        truncated = True
        tech_targets = sorted(active_domains)[:max_tech_targets]
        print(f"[!] {len(active_domains)} sous-domaines actifs détectés — "
              f"analyse technos limitée aux {max_tech_targets} premiers pour éviter "
              f"de saturer les ressources système. Les {len(active_domains)} restent "
              f"listés dans scan.subdomains.", file=sys.stderr)

    report(f"[4/8] Technologies ({len(tech_targets)} cibles"
           + (f", {len(active_domains) - len(tech_targets)} ignorées" if truncated else "") + ")")
    tech_results = scan_tech(tech_targets, engine=tech_engine) if tech_targets else []

    report(f"[5/8] Employés / emails : {domain}")
    emp_result = find_employees(domain, hunter_api_key=hunter_key)

    report(f"[6/8] Fuites de credentials ({len(emp_result['emails'])} emails)")
    leak_results = check_emails(
        emp_result["emails"], provider=provider,
        leakcheck_key=leakcheck_key, hibp_key=hibp_key,
    ) if emp_result["emails"] else []

    report(f"[7/8] Surface de phishing (SPF/DKIM/DMARC) : {domain}")
    email_sec_result = analyze_email_security(domain, employees=emp_result.get("employees"))

    scan = build_scan_result(
        domain=domain,
        subdomain_scan=sub_result,
        tech_scans=tech_results,
        employee_scan=emp_result,
        leak_results=leak_results,
        email_security_scan=email_sec_result,
        takeover_scan=takeover_result,
        environment_scan=environment_result,
    )

    report("[8/8] Calcul du score")
    scan = apply_score(scan)
    print(f"    -> {scan.score}/100 ({scan.score_details['band']})", file=sys.stderr)

    return scan


def main():
    import os

    parser = argparse.ArgumentParser(description="Pipeline complet de scan OSINT")
    parser.add_argument("domain", help="Domaine cible, ex: example.com")
    parser.add_argument("--provider", choices=["leakcheck", "hibp", "xposedornot", "both"],
                         default="xposedornot")
    parser.add_argument("--tech-engine", choices=["whatweb", "lite", "both"], default="both")
    parser.add_argument("--max-tech-targets", type=int, default=DEFAULT_MAX_TECH_TARGETS,
                         help=f"Limite de sous-domaines analysés pour les technos "
                              f"(défaut: {DEFAULT_MAX_TECH_TARGETS}, 0 = illimité)")
    parser.add_argument("--max-takeover-targets", type=int, default=DEFAULT_MAX_TAKEOVER_TARGETS,
                         help=f"Limite de sous-domaines analysés pour le takeover "
                              f"(défaut: {DEFAULT_MAX_TAKEOVER_TARGETS}, 0 = illimité)")
    parser.add_argument("--out", help="Fichier de sortie JSON (sinon affiché en stdout)")
    args = parser.parse_args()

    scan = run_pipeline(
        args.domain,
        provider=args.provider,
        leakcheck_key=os.environ.get("LEAKCHECK_API_KEY"),
        hibp_key=os.environ.get("HIBP_API_KEY"),
        hunter_key=os.environ.get("HUNTER_API_KEY"),
        tech_engine=args.tech_engine,
        max_tech_targets=None if args.max_tech_targets == 0 else args.max_tech_targets,
        max_takeover_targets=None if args.max_takeover_targets == 0 else args.max_takeover_targets,
    )

    print("\n=== Résumé ===", file=sys.stderr)
    for key, value in scan.summary().items():
        print(f"  {key}: {value}", file=sys.stderr)

    if args.out:
        Path(args.out).write_text(scan.to_json())
        print(f"\n[+] Résultat écrit dans {args.out}", file=sys.stderr)
    else:
        print(scan.to_json())


if __name__ == "__main__":
    main()
