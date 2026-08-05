"""
leak_checker.py (v2)
Vérification de fuites de credentials pour une liste d'emails, via
LeakCheck.io et/ou HaveIBeenPwned.

SÉCURITÉ : ce module ne journalise ni n'affiche jamais un mot de passe
en clair. Tout mot de passe retourné par une API est masqué avant
d'être stocké ou affiché (voir mask_secret()).

Changements v2 :
- Les erreurs HTTP affichent désormais le message réel renvoyé par
  l'API (ex: "A paid plan is required", "Invalid API key") au lieu
  du seul code HTTP — un 403 LeakCheck signifie généralement un
  souci de plan/quota, pas une erreur de code.
- Header "Accept: application/json" ajouté (conforme à la doc officielle).
- Email URL-encodé avant insertion dans l'URL.
- --provider accepte désormais "xposedornot" (gratuit, sans clé API)
  et "both" pour interroger tous les providers disponibles.
- Provider par défaut passé à "xposedornot" : fonctionne sans aucune
  clé API configurée.

Usage CLI :
    # Sans clé API (XposedOrNot, gratuit) :
    python core/leak_checker.py john.doe@example.com

    # Avec clés payantes en option :
    export LEAKCHECK_API_KEY="ta_cle"
    export HIBP_API_KEY="ta_cle"
    python core/leak_checker.py john.doe@example.com jane@example.com --provider both --json
"""

import argparse
import json
import os
import sys
import time
from urllib.parse import quote

import requests

LEAKCHECK_URL = "https://leakcheck.io/api/v2/query/{query}"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
XPOSEDORNOT_URL = "https://api.xposedornot.com/v1/check-email/{email}"

REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 1.5  # secondes entre deux requêtes, pour respecter les ToS


# --------------------------------------------------------------------------
# Masquage — ne JAMAIS retirer cette étape
# --------------------------------------------------------------------------
def mask_secret(value: str, visible_start: int = 1, visible_end: int = 1) -> str:
    """
    Masque une chaîne sensible (mot de passe, hash) en ne gardant que
    quelques caractères visibles. Ex: "password123" -> "p*********3".
    """
    if not value:
        return ""
    if len(value) <= visible_start + visible_end:
        return "*" * len(value)
    return value[:visible_start] + "*" * (len(value) - visible_start - visible_end) + value[-visible_end:]


def _extract_api_error(resp: requests.Response) -> str:
    """
    Essaie d'extraire un message d'erreur exploitable du corps JSON
    de la réponse. Retombe sur le code HTTP brut si le corps n'est
    pas exploitable.
    """
    try:
        body = resp.json()
    except (ValueError, json.JSONDecodeError):
        return f"HTTP {resp.status_code}"

    for key in ("error", "message", "msg", "detail"):
        if isinstance(body, dict) and body.get(key):
            return f"HTTP {resp.status_code} - {body[key]}"

    return f"HTTP {resp.status_code}"


# --------------------------------------------------------------------------
# 1. LeakCheck.io
# --------------------------------------------------------------------------
def check_leakcheck(email: str, api_key: str) -> dict:
    """
    Interroge l'API LeakCheck v2 Pro. Nécessite une clé API payante
    pour obtenir les enregistrements complets (un compte gratuit/essai
    peut renvoyer 403 "A paid plan is required" pour cet endpoint —
    dans ce cas utilise l'API publique gratuite en fallback, voir
    check_leakcheck_public()).
    """
    headers = {
        "Accept": "application/json",
        "X-API-Key": api_key,
    }
    url = LEAKCHECK_URL.format(query=quote(email, safe=""))

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return {"email": email, "leaked": None, "error": str(exc), "sources": []}

    if resp.status_code == 404:
        return {"email": email, "leaked": False, "sources": []}

    if resp.status_code != 200:
        return {
            "email": email, "leaked": None,
            "error": _extract_api_error(resp), "sources": [],
        }

    data = resp.json()
    results = data.get("result", [])

    sources = []
    for entry in results:
        sources.append({
            "source": entry.get("source", {}).get("name", "unknown"),
            "breach_date": entry.get("source", {}).get("breach_date"),
            "password_masked": mask_secret(entry["password"]) if entry.get("password") else None,
            "fields_exposed": [k for k in entry.keys() if k not in ("password", "source")],
        })

    return {
        "email": email,
        "leaked": len(sources) > 0,
        "sources": sources,
    }


def check_leakcheck_public(email: str) -> dict:
    """
    API publique LeakCheck : gratuite, sans clé, mais ne renvoie que
    la liste des sources de breach (pas les données elles-mêmes).
    Utile en fallback si le compte n'a pas d'accès Pro.
    """
    url = "https://leakcheck.io/api/public"

    try:
        resp = requests.get(
            url, params={"check": email}, timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException as exc:
        return {"email": email, "leaked": None, "error": str(exc), "sources": []}

    if resp.status_code != 200:
        return {"email": email, "leaked": None, "error": _extract_api_error(resp), "sources": []}

    data = resp.json()
    sources = [{"source": s, "breach_date": None, "password_masked": None, "fields_exposed": []}
               for s in data.get("sources", [])]

    return {
        "email": email,
        "leaked": bool(data.get("found")),
        "sources": sources,
    }


# --------------------------------------------------------------------------
# 2. HaveIBeenPwned
# --------------------------------------------------------------------------
def check_hibp(email: str, api_key: str) -> dict:
    """
    Interroge l'API HIBP v3 (payante). Ne retourne jamais de mot de
    passe en clair — HIBP fournit uniquement les noms des breaches.
    """
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "osint-framework",
    }
    url = HIBP_URL.format(email=quote(email, safe="")) + "?truncateResponse=false"

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return {"email": email, "leaked": None, "error": str(exc), "sources": []}

    if resp.status_code == 404:
        return {"email": email, "leaked": False, "sources": []}

    if resp.status_code != 200:
        return {
            "email": email, "leaked": None,
            "error": _extract_api_error(resp), "sources": [],
        }

    breaches = resp.json()
    sources = [{
        "source": b.get("Name"),
        "breach_date": b.get("BreachDate"),
        "password_masked": None,
        "fields_exposed": b.get("DataClasses", []),
    } for b in breaches]

    return {
        "email": email,
        "leaked": len(sources) > 0,
        "sources": sources,
    }


# --------------------------------------------------------------------------
# 3. XposedOrNot (gratuit, sans clé API)
# --------------------------------------------------------------------------
def check_xposedornot(email: str) -> dict:
    """
    Interroge l'API publique XposedOrNot. Gratuite, sans clé API,
    limitée à 2 requêtes/seconde par IP (voir RATE_LIMIT_DELAY).
    Ne renvoie que les noms des breaches, jamais de mot de passe.
    """
    url = XPOSEDORNOT_URL.format(email=quote(email, safe=""))

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return {"email": email, "leaked": None, "error": str(exc), "sources": []}

    if resp.status_code == 404:
        return {"email": email, "leaked": False, "sources": []}

    if resp.status_code != 200:
        return {
            "email": email, "leaked": None,
            "error": _extract_api_error(resp), "sources": [],
        }

    data = resp.json()
    breaches = data.get("breaches", [])
    # L'API renvoie parfois une liste de listes (groupée) — on aplatit.
    flat_breaches = []
    for b in breaches:
        if isinstance(b, list):
            flat_breaches.extend(b)
        else:
            flat_breaches.append(b)

    sources = [{
        "source": name,
        "breach_date": None,
        "password_masked": None,
        "fields_exposed": [],
    } for name in flat_breaches]

    return {
        "email": email,
        "leaked": len(sources) > 0,
        "sources": sources,
    }


# --------------------------------------------------------------------------
# 4. Orchestration
# --------------------------------------------------------------------------
def _merge_provider_results(results_list: list[dict]) -> dict:
    """Fusionne les résultats de plusieurs providers pour un même email."""
    email = results_list[0]["email"]
    all_sources = []
    errors = []
    leaked_flags = []

    for r in results_list:
        all_sources.extend(r.get("sources", []))
        if r.get("error"):
            errors.append(r["error"])
        if r.get("leaked") is not None:
            leaked_flags.append(r["leaked"])

    return {
        "email": email,
        "leaked": any(leaked_flags) if leaked_flags else None,
        "sources": all_sources,
        "errors": errors or None,
    }


def check_emails(emails: list[str], provider: str = "leakcheck",
                  leakcheck_key: str | None = None, hibp_key: str | None = None) -> list[dict]:
    """
    Vérifie une liste d'emails. provider : "leakcheck", "hibp",
    "xposedornot" ou "both" (interroge tous les providers disponibles).
    Respecte un délai minimal entre requêtes.
    """
    results = []

    for i, email in enumerate(emails):
        print(f"[*] Vérification {email} ({i + 1}/{len(emails)}) ...", file=sys.stderr)
        provider_results = []

        if provider in ("leakcheck", "both"):
            if leakcheck_key:
                provider_results.append(check_leakcheck(email, leakcheck_key))
            else:
                print("[*] Pas de clé LeakCheck Pro, utilisation de l'API publique (gratuite).",
                      file=sys.stderr)
                provider_results.append(check_leakcheck_public(email))

        if provider in ("hibp", "both"):
            if hibp_key:
                provider_results.append(check_hibp(email, hibp_key))
            else:
                provider_results.append(
                    {"email": email, "leaked": None, "error": "no_api_key", "sources": []}
                )

        if provider in ("xposedornot", "both"):
            provider_results.append(check_xposedornot(email))

        results.append(_merge_provider_results(provider_results))

        if i < len(emails) - 1:
            time.sleep(RATE_LIMIT_DELAY)

    return results


def main():
    parser = argparse.ArgumentParser(description="Vérificateur de fuites de credentials")
    parser.add_argument("emails", nargs="+", help="Un ou plusieurs emails à vérifier")
    parser.add_argument("--provider", choices=["leakcheck", "hibp", "xposedornot", "both"],
                         default="xposedornot")
    parser.add_argument("--json", action="store_true", help="Sortie JSON brute")
    args = parser.parse_args()

    leakcheck_key = os.environ.get("LEAKCHECK_API_KEY")
    hibp_key = os.environ.get("HIBP_API_KEY")

    results = check_emails(
        args.emails, provider=args.provider,
        leakcheck_key=leakcheck_key, hibp_key=hibp_key,
    )

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for r in results:
            status = "?" if r["leaked"] is None else ("LEAKED" if r["leaked"] else "clean")
            print(f"\n{r['email']} : {status}")
            if r.get("errors"):
                for err in r["errors"]:
                    print(f"  Erreur : {err}")
            for src in r.get("sources", []):
                pw = f", pwd: {src['password_masked']}" if src.get("password_masked") else ""
                print(f"  - {src['source']} ({src.get('breach_date') or '?'}){pw}")


if __name__ == "__main__":
    main()

