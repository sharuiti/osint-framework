"""
takeover_detector.py
Détecte les candidats au subdomain takeover : CNAME pointant vers un
service tiers (S3, GitHub Pages, Heroku, Azure, Shopify, etc.) qui
n'est plus revendiqué, ou vers une cible qui ne résout plus du tout.

RAPPEL ÉTHIQUE — À LIRE AVANT TOUTE MODIFICATION :
Ce module s'arrête STRICTEMENT à la détection passive. Il ne tente
JAMAIS de revendiquer un sous-domaine (créer le bucket S3, l'app
Heroku, etc.) pour "confirmer" le takeover — ça constituerait une
prise de contrôle réelle, hors scope de la reconnaissance passive et
illégale sans autorisation explicite du programme concerné. Le module
signale des "candidats probables", jamais des "takeovers confirmés".

Deux signaux combinés :
  1. CNAME orphelin générique (confiance haute) : le CNAME pointe vers
     un hôte qui ne résout MÊME PLUS (NXDOMAIN) — signal universel,
     valable pour n'importe quel fournisseur, pas seulement ceux
     catalogués ci-dessous.
  2. Fingerprint de service connu (confiance haute si match, basse
     sinon) : le CNAME résout mais pointe vers un service dont la
     page "non revendiqué" a une signature textuelle caractéristique.

La liste SIGNATURES est volontairement non exhaustive (~20 services).
Pour un usage sérieux, la maintenir à jour depuis une source vivante
comme le projet "can-i-take-over-xyz" sur GitHub.

Usage CLI :
    python core/takeover_detector.py example.com sub1.example.com sub2.example.com
    python core/takeover_detector.py --domain example.com --json
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

# verify=False est utilisé volontairement dans _fetch_fingerprint : une
# ressource non revendiquée (bucket S3 supprimé, etc.) n'a souvent plus
# de certificat TLS valide, et un échec SSL ne doit pas nous priver du
# fingerprint HTTP. On supprime le warning correspondant globalement
# (pas seulement en CLI) puisque ce module est aussi importé comme lib.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] dnspython manquant. Installe avec : pip install dnspython", file=sys.stderr)
    raise

DNS_TIMEOUT = 4
HTTP_TIMEOUT = 8
CNAME_LOOKUP_WORKERS = 20
USER_AGENT = "Mozilla/5.0 (osint-framework recon tool)"

# Signatures de services connus pour être vulnérables au takeover
# quand un CNAME pointe vers eux sans que la ressource soit revendiquée.
# Format : nom -> (liste de suffixes CNAME, liste de fingerprints HTML).
SIGNATURES = {
    "AWS S3":            (["s3.amazonaws.com", "s3-website"], ["NoSuchBucket"]),
    "GitHub Pages":      (["github.io"], ["There isn't a GitHub Pages site here"]),
    "Heroku":            (["herokuapp.com"], ["No such app", "herokucdn.com/error-pages/no-such-app"]),
    "Azure Web Apps":    (["azurewebsites.net"], ["404 Web Site not found"]),
    "Azure Blob":        (["blob.core.windows.net"], ["BlobNotFound"]),
    "Shopify":           (["myshopify.com"], ["Sorry, this shop is currently unavailable"]),
    "Fastly":            (["fastly.net"], ["Fastly error: unknown domain"]),
    "Pantheon":          (["pantheonsite.io"], ["The gods are wise"]),
    "Unbounce":          (["unbouncepages.com"], ["The requested URL was not found on this server"]),
    "Surge.sh":          (["surge.sh"], ["project not found"]),
    "Zendesk":           (["zendesk.com"], ["Help Center Closed"]),
    "UserVoice":         (["uservoice.com"], ["This UserVoice subdomain is currently available"]),
    "Bitbucket":         (["bitbucket.io"], ["Repository not found"]),
    "Tumblr":            (["tumblr.com"], ["Whatever you were looking for doesn't currently exist"]),
    "WordPress.com":     (["wordpress.com"], ["Do you want to register"]),
    "Cargo Collective":  (["cargocollective.com"], ["404 Not Found"]),
    "Netlify":           (["netlify.app"], ["Not Found - Request ID"]),
    "Statuspage":        (["statuspage.io"], ["You are being"]),
    "Helpjuice":         (["helpjuice.com"], ["We could not find what you're looking for"]),
    "Ghost (Pro)":       (["ghost.io"], ["The thing you were looking for is no longer here"]),
}


# --------------------------------------------------------------------------
# 1. DNS
# --------------------------------------------------------------------------
def _get_cname(hostname: str) -> str | None:
    """Retourne la cible CNAME d'un hostname, ou None s'il n'en a pas."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".").lower()
    except dns.exception.DNSException:
        return None
    except Exception:
        return None


def _resolves(hostname: str) -> bool:
    """True si le hostname a au moins un enregistrement A résolvable."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        resolver.resolve(hostname, "A")
        return True
    except dns.exception.DNSException:
        return False
    except Exception:
        return False


def _is_same_organization(cname_target: str, own_domain: str) -> bool:
    """
    Un CNAME vers un sous-domaine du MÊME domaine (ex: a.example.com ->
    b.example.com) n'est pas un candidat takeover tiers — on l'exclut
    pour éviter le bruit.
    """
    return cname_target.endswith(own_domain.lower())


def _match_known_service(cname_target: str) -> str | None:
    """Retourne le nom du service si le CNAME correspond à une signature connue."""
    for service, (suffixes, _fingerprints) in SIGNATURES.items():
        if any(cname_target.endswith(suffix) or suffix in cname_target for suffix in suffixes):
            return service
    return None


# --------------------------------------------------------------------------
# 2. HTTP fingerprint
# --------------------------------------------------------------------------
def _fetch_fingerprint(hostname: str, service: str) -> tuple[bool, str | None]:
    """
    Récupère la page du sous-domaine et cherche le fingerprint du
    service correspondant. Retente en HTTP si HTTPS échoue (un service
    non revendiqué n'a souvent pas de certificat TLS valide).
    """
    _, fingerprints = SIGNATURES[service]
    headers = {"User-Agent": USER_AGENT}

    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{hostname}", headers=headers,
                                 timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
        except requests.RequestException:
            continue

        for fp in fingerprints:
            if fp.lower() in resp.text.lower():
                return True, fp
        return False, None  # réponse obtenue mais aucun fingerprint trouvé

    return False, None  # aucune requête n'a abouti (ni https, ni http)


# --------------------------------------------------------------------------
# 3. Orchestration par sous-domaine
# --------------------------------------------------------------------------
def _check_one(hostname: str, own_domain: str) -> dict | None:
    """
    Analyse un sous-domaine. Retourne None s'il n'est pas candidat
    (pas de CNAME tiers, ou CNAME résolvant vers un service non
    catalogué), sinon un dict décrivant le candidat.
    """
    cname = _get_cname(hostname)
    if not cname or _is_same_organization(cname, own_domain):
        return None

    target_resolves = _resolves(cname)
    matched_service = _match_known_service(cname)

    if not target_resolves:
        # Signal universel, valable même pour un fournisseur non catalogué.
        return {
            "subdomain": hostname,
            "cname": cname,
            "service": matched_service or "Fournisseur non catalogué",
            "confidence": "high",
            "method": "dangling_cname",
            "fingerprint_matched": None,
            "detail": f"Le CNAME pointe vers {cname}, qui ne résout plus du tout "
                      f"(NXDOMAIN) — la ressource cible a probablement été supprimée. "
                      f"Candidat à haute confiance, à vérifier manuellement avant tout "
                      f"signalement (ne jamais tenter de revendiquer la ressource).",
        }

    if matched_service:
        fp_found, fp_snippet = _fetch_fingerprint(hostname, matched_service)
        if fp_found:
            return {
                "subdomain": hostname,
                "cname": cname,
                "service": matched_service,
                "confidence": "high",
                "method": "fingerprint_match",
                "fingerprint_matched": fp_snippet,
                "detail": f"CNAME vers {matched_service} ({cname}), page renvoyant le "
                          f"message caractéristique d'une ressource non revendiquée "
                          f"('{fp_snippet}'). Candidat à haute confiance.",
            }
        return {
            "subdomain": hostname,
            "cname": cname,
            "service": matched_service,
            "confidence": "low",
            "method": "known_vulnerable_service_pattern",
            "fingerprint_matched": None,
            "detail": f"CNAME vers {matched_service} ({cname}), service connu pour être "
                      f"vulnérable au takeover en général, mais le fingerprint de page "
                      f"non-revendiquée n'a pas été trouvé (la ressource est peut-être "
                      f"légitimement active). Confiance faible, vérification manuelle "
                      f"nécessaire.",
        }

    return None  # CNAME tiers mais service non catalogué et cible résolvante -> pas de signal


# --------------------------------------------------------------------------
# 4. Point d'entrée
# --------------------------------------------------------------------------
def scan_takeovers(hostnames: list[str], own_domain: str,
                    max_targets: int | None = None) -> dict:
    """
    Analyse une liste de hostnames et retourne les candidats détectés.
    La phase de résolution DNS (légère, I/O-bound) est parallélisée ;
    les requêtes HTTP de fingerprint ne sont faites que pour le petit
    sous-ensemble dont le CNAME matche une signature connue.
    """
    targets = hostnames
    truncated = False
    if max_targets is not None and len(hostnames) > max_targets:
        truncated = True
        targets = sorted(hostnames)[:max_targets]
        print(f"[!] {len(hostnames)} sous-domaines à vérifier — analyse takeover "
              f"limitée aux {max_targets} premiers.", file=sys.stderr)

    print(f"[*] Vérification CNAME de {len(targets)} sous-domaines ...", file=sys.stderr)

    candidates = []
    with ThreadPoolExecutor(max_workers=CNAME_LOOKUP_WORKERS) as executor:
        futures = {executor.submit(_check_one, h, own_domain): h for h in targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                candidates.append(result)

    candidates.sort(key=lambda c: (c["confidence"] != "high", c["subdomain"]))

    print(f"    -> {len(candidates)} candidat(s) détecté(s) "
          f"({sum(1 for c in candidates if c['confidence'] == 'high')} haute confiance)",
          file=sys.stderr)

    return {
        "domain": own_domain,
        "total_checked": len(targets),
        "truncated": truncated,
        "candidates": candidates,
    }


def main():
    parser = argparse.ArgumentParser(description="Détecteur de subdomain takeover")
    parser.add_argument("domain", help="Domaine racine (pour exclure les CNAME internes)")
    parser.add_argument("subdomains", nargs="*",
                         help="Sous-domaines à vérifier (défaut: juste le domaine racine)")
    parser.add_argument("--json", action="store_true", help="Sortie JSON brute")
    args = parser.parse_args()

    hostnames = args.subdomains or [args.domain]
    result = scan_takeovers(hostnames, args.domain)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\nDomaine : {result['domain']} ({result['total_checked']} vérifiés)\n")
        if not result["candidates"]:
            print("Aucun candidat détecté.")
        for c in result["candidates"]:
            print(f"  [{c['confidence'].upper():6s}] {c['subdomain']:<35} -> {c['cname']} "
                  f"({c['service']})")


if __name__ == "__main__":
    main()
