"""
environment_classifier.py
Classe les sous-domaines déjà découverts en deux catégories de risque :
  - "non_prod"    : environnements de dev/staging/test (mots-clés dans
                     le nom, ex: dev., staging., uat., preprod.)
  - "admin_panel" : interfaces d'administration/gestion exposées
                     (ex: admin., jenkins., grafana., phpmyadmin.)

HONNÊTETÉ MÉTHODOLOGIQUE — À CONSERVER DANS TOUTE MODIFICATION :
Cette détection est un PUR heuristique sur le NOM du sous-domaine, pas
une confirmation. "test.example.com" peut être un vrai environnement
de test... ou un site marketing nommé par coïncidence. Ce module ne
fait AUCUNE requête HTTP pour vérifier le contenu réel — contrairement
à takeover_detector.py qui confirme par fingerprint, ici il n'y a que
le nom. C'est délibéré (rester passif et rapide), mais ça doit rester
visible partout où ce résultat est affiché : "candidat", jamais
"confirmé".

Usage CLI :
    python core/environment_classifier.py sub1.example.com sub2.example.com
    python core/environment_classifier.py --json sub1.example.com
"""

import argparse
import json
import re
import sys

# Mots-clés d'environnement hors-prod. Recherchés comme LABEL DNS
# complet (entre points) pour éviter les faux positifs grossiers du
# type "latest.example.com" qui contiendrait "test" en sous-chaîne.
NON_PROD_KEYWORDS = [
    "dev", "development", "staging", "stage", "stg", "uat", "preprod",
    "pre-prod", "test", "testing", "qa", "sandbox", "sbx", "demo",
    "beta", "alpha", "integration", "int", "poc", "sit", "preview",
]

# Mots-clés de panneau d'administration / interface de gestion —
# risque plus élevé car ce sont des cibles directement exploitables
# (souvent avec des identifiants par défaut ou faibles).
ADMIN_PANEL_KEYWORDS = [
    "admin", "administrator", "panel", "cpanel", "phpmyadmin", "adminer",
    "portainer", "rancher", "jenkins", "gitlab", "grafana", "kibana",
    "dashboard", "manage", "management", "mgmt", "console", "webmail",
    "vpn", "remote", "rdp", "citrix", "sso", "auth", "keycloak",
    "wp-admin", "manager",
]

ADMIN_POINTS = 25.0
NON_PROD_POINTS = 12.0

_LABEL_SPLIT_RE = re.compile(r"[.\-_]")


def _extract_labels(hostname: str) -> set[str]:
    """
    Découpe un hostname en labels individuels sur '.', '-' et '_' pour
    matcher des mots entiers plutôt que des sous-chaînes. Ex:
    "old-admin-panel.example.com" -> {"old", "admin", "panel", "example", "com"}
    """
    return {label.lower() for label in _LABEL_SPLIT_RE.split(hostname) if label}


def classify_subdomain(hostname: str) -> dict | None:
    """
    Classe un sous-domaine. Retourne None s'il ne matche aucun
    mot-clé (cas normal, pas un candidat). Si les deux catégories
    matchent, "admin_panel" prend le dessus (risque plus élevé).
    """
    labels = _extract_labels(hostname)

    admin_match = next((kw for kw in ADMIN_PANEL_KEYWORDS if kw in labels), None)
    if admin_match:
        return {
            "subdomain": hostname,
            "category": "admin_panel",
            "matched_keyword": admin_match,
            "risk": "high",
            "detail": f"Le nom contient '{admin_match}', évocateur d'une interface "
                      f"d'administration/gestion exposée publiquement. Candidat à "
                      f"vérifier manuellement — le nom seul ne confirme rien.",
        }

    nonprod_match = next((kw for kw in NON_PROD_KEYWORDS if kw in labels), None)
    if nonprod_match:
        return {
            "subdomain": hostname,
            "category": "non_prod",
            "matched_keyword": nonprod_match,
            "risk": "medium",
            "detail": f"Le nom contient '{nonprod_match}', évocateur d'un "
                      f"environnement hors-production (souvent moins durci que la "
                      f"prod). Candidat à vérifier manuellement — le nom seul ne "
                      f"confirme rien.",
        }

    return None


def classify_environments(hostnames: list[str]) -> dict:
    """Point d'entrée principal du module."""
    print(f"[*] Classification de {len(hostnames)} sous-domaines "
          f"(dev/staging/admin...) ...", file=sys.stderr)

    candidates = [c for c in (classify_subdomain(h) for h in hostnames) if c]
    candidates.sort(key=lambda c: (c["category"] != "admin_panel", c["subdomain"]))

    admin_count = sum(1 for c in candidates if c["category"] == "admin_panel")
    nonprod_count = len(candidates) - admin_count

    print(f"    -> {admin_count} panneau(x) d'administration, "
          f"{nonprod_count} environnement(s) hors-prod (heuristique nom uniquement)",
          file=sys.stderr)

    return {
        "total_checked": len(hostnames),
        "candidates": candidates,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Classification des environnements hors-prod / panneaux admin")
    parser.add_argument("subdomains", nargs="+", help="Sous-domaines à classer")
    parser.add_argument("--json", action="store_true", help="Sortie JSON brute")
    args = parser.parse_args()

    result = classify_environments(args.subdomains)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\n{result['total_checked']} sous-domaine(s) analysé(s)\n")
        if not result["candidates"]:
            print("Aucun candidat détecté.")
        for c in result["candidates"]:
            label = "ADMIN" if c["category"] == "admin_panel" else "NON-PROD"
            print(f"  [{label:8s}] {c['subdomain']:<40} (mot-clé: {c['matched_keyword']})")


if __name__ == "__main__":
    main()
