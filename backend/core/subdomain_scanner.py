"""
subdomain_scanner.py
Découverte de sous-domaines via Sublist3r + crt.sh, puis validation DNS.

Usage CLI :
    python core/subdomain_scanner.py example.com
    python core/subdomain_scanner.py example.com --json
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] dnspython manquant. Installe avec : pip install dnspython", file=sys.stderr)
    raise

DNS_TIMEOUT = 3
DNS_MAX_WORKERS = 30
CRTSH_TIMEOUT = 30

# Un nom d'hôte valide : labels alphanumériques/tirets séparés par des
# points, pas de label vide, pas de caractères exotiques. Ça filtre les
# entrées "sales" que crt.sh renvoie parfois (wildcards imbriqués,
# entrées malformées) avant même de tenter une résolution DNS dessus.
VALID_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_hostname(name: str) -> bool:
    """Vérifie qu'un nom ressemble à un hostname DNS valide."""
    if not name or len(name) > 253:
        return False
    return bool(VALID_HOSTNAME_RE.match(name))


# --------------------------------------------------------------------------
# 1. Sublist3r
# --------------------------------------------------------------------------
def run_sublist3r(domain: str, timeout: int = 120) -> list[str]:
    """
    Lance Sublist3r en sous-processus et retourne la liste brute des
    sous-domaines trouvés. Sublist3r n'a pas de sortie JSON native,
    on utilise donc son option -o pour écrire dans un fichier temporaire
    qu'on relit ensuite (un sous-domaine par ligne).
    """
    sublist3r_bin = shutil.which("sublist3r") or shutil.which("sublist3r.py")

    if not sublist3r_bin:
        print("[!] Binaire Sublist3r introuvable dans le PATH. "
              "Installe-le avec : sudo apt install sublist3r", file=sys.stderr)
        return []

    with tempfile.NamedTemporaryFile(mode="r", suffix=".txt", delete=False) as tmp:
        output_path = tmp.name

    cmd = [sublist3r_bin, "-d", domain, "-o", output_path]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] Sublist3r a dépassé le timeout ({timeout}s), résultats partiels ignorés.",
              file=sys.stderr)
        return []
    except FileNotFoundError:
        print("[!] Impossible d'exécuter Sublist3r.", file=sys.stderr)
        return []

    subdomains = []
    out_file = Path(output_path)
    if out_file.exists():
        content = out_file.read_text(errors="ignore").splitlines()
        subdomains = [line.strip() for line in content if line.strip()]
        out_file.unlink(missing_ok=True)

    return subdomains


# --------------------------------------------------------------------------
# 2. crt.sh
# --------------------------------------------------------------------------
def query_crtsh(domain: str) -> list[str]:
    """
    Interroge crt.sh (transparence des certificats) pour lister les
    sous-domaines historiquement présents dans des certificats SSL émis
    pour ce domaine. Aucune clé API nécessaire.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "osint-framework/1.0"}

    try:
        resp = requests.get(url, headers=headers, timeout=CRTSH_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[!] Erreur crt.sh : {exc}", file=sys.stderr)
        return []

    # crt.sh renvoie parfois du JSON mal formé (objets concaténés).
    # On tente un parsing standard puis un fallback ligne par ligne.
    try:
        data = resp.json()
    except json.JSONDecodeError:
        try:
            data = json.loads(
                "[" + resp.text.replace("}\n{", "},{") + "]"
            )
        except json.JSONDecodeError:
            print("[!] Impossible de parser la réponse crt.sh.", file=sys.stderr)
            return []

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name:
                subdomains.add(name)

    return list(subdomains)


# --------------------------------------------------------------------------
# 3. Résolution DNS
# --------------------------------------------------------------------------
def _resolve_one(resolver: dns.resolver.Resolver, subdomain: str) -> tuple[str, list[str] | None]:
    """Résout un sous-domaine en A record. Retourne (subdomain, ips|None)."""
    try:
        answers = resolver.resolve(subdomain, "A")
        ips = [str(a) for a in answers]
        return subdomain, ips
    except dns.exception.DNSException:
        # Couvre NXDOMAIN, NoAnswer, NoNameservers, Timeout, YXDOMAIN,
        # labels malformés, etc. — toute la famille dnspython plutôt
        # qu'une liste blanche qui finit toujours par en oublier une.
        return subdomain, None
    except Exception as exc:
        # Filet de sécurité : une entrée vraiment corrompue ne doit
        # jamais faire planter tout le pool de threads. On la logue
        # et on continue sur les autres sous-domaines.
        print(f"[!] Erreur inattendue en résolvant {subdomain!r} : {exc}", file=sys.stderr)
        return subdomain, None


def resolve_active(subdomains: list[str]) -> dict[str, list[str]]:
    """
    Résout en parallèle une liste de sous-domaines et ne garde que
    ceux qui répondent réellement (actifs). Retourne {subdomain: [ips]}.

    Un seul Resolver est créé et partagé entre tous les threads (plutôt
    qu'un par sous-domaine) — resolve() est thread-safe en lecture, et
    ça évite de recréer potentiellement des milliers d'objets Resolver
    sur un domaine avec beaucoup d'entrées (ex: crt.sh sur un grand
    groupe peut renvoyer des dizaines de milliers de noms).
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    active = {}
    with ThreadPoolExecutor(max_workers=DNS_MAX_WORKERS) as executor:
        futures = {executor.submit(_resolve_one, resolver, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            sub, ips = future.result()
            if ips:
                active[sub] = ips
    return active


# --------------------------------------------------------------------------
# 4. Orchestration
# --------------------------------------------------------------------------
def scan_subdomains(domain: str) -> dict:
    """
    Point d'entrée principal du module. Combine Sublist3r + crt.sh,
    déduplique, résout en DNS, et retourne un résultat normalisé.
    """
    print(f"[*] Sublist3r sur {domain} ...", file=sys.stderr)
    sublist3r_results = run_sublist3r(domain)
    print(f"    -> {len(sublist3r_results)} résultats", file=sys.stderr)

    print(f"[*] crt.sh sur {domain} ...", file=sys.stderr)
    crtsh_results = query_crtsh(domain)
    print(f"    -> {len(crtsh_results)} résultats", file=sys.stderr)

    merged = set(sublist3r_results) | set(crtsh_results)
    merged.add(domain)  # on inclut toujours le domaine racine
    merged = {s.lower() for s in merged if domain in s}

    valid = {s for s in merged if is_valid_hostname(s)}
    invalid_count = len(merged) - len(valid)
    if invalid_count:
        print(f"[*] {invalid_count} entrée(s) invalide(s) filtrée(s) avant résolution DNS.",
              file=sys.stderr)

    print(f"[*] Résolution DNS de {len(valid)} sous-domaines uniques ...", file=sys.stderr)
    active = resolve_active(sorted(valid))
    print(f"    -> {len(active)} actifs", file=sys.stderr)

    return {
        "domain": domain,
        "total_found": len(valid),
        "total_active": len(active),
        "sources": {
            "sublist3r_count": len(sublist3r_results),
            "crtsh_count": len(crtsh_results),
        },
        "active_subdomains": [
            {"subdomain": sub, "ips": ips} for sub, ips in sorted(active.items())
        ],
        # Tous les hostnames valides, actifs OU non. Nécessaire pour le
        # takeover detector : un sous-domaine avec un CNAME orphelin
        # (cible supprimée) échoue justement la résolution A et serait
        # sinon invisible — c'est pourtant l'un des signaux les plus
        # forts de subdomain takeover.
        "all_valid_subdomains": sorted(valid),
    }


def main():
    parser = argparse.ArgumentParser(description="Scanner de sous-domaines OSINT")
    parser.add_argument("domain", help="Domaine cible, ex: example.com")
    parser.add_argument("--json", action="store_true", help="Sortie JSON brute")
    args = parser.parse_args()

    result = scan_subdomains(args.domain)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\nDomaine : {result['domain']}")
        print(f"Total trouvés : {result['total_found']} | Actifs : {result['total_active']}\n")
        for entry in result["active_subdomains"]:
            print(f"  {entry['subdomain']:<40} {', '.join(entry['ips'])}")


if __name__ == "__main__":
    main()
