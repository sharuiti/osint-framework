"""
tech_detector.py (v2)
Détection des technologies exposées par sous-domaine, via WhatWeb et un
détecteur "lite" maison basé uniquement sur `requests` + regex.

Pourquoi pas python-Wappalyzer ?
Ce package n'est plus maintenu depuis 2021 et dépend d'aiohttp/multidict/
yarl (extensions C). Sur des interpréteurs récents (ex: Python 3.13), ces
extensions peuvent lever une ImportError silencieuse au chargement même
si `pip show` confirme l'installation (mismatch d'ABI binaire). Plutôt que
de dépendre de ce package fragile, ce module embarque une base de
signatures courantes (headers, HTML, cookies) suffisante pour du recon
OSINT. C'est moins exhaustif que Wappalyzer officiel mais 100% fiable.

Usage CLI :
    python core/tech_detector.py example.com www.example.com
    python core/tech_detector.py example.com --json
    python core/tech_detector.py example.com --engine whatweb
    python core/tech_detector.py example.com --engine lite
"""

import argparse
import json
import re
import shutil
import subprocess
import sys

import requests

WHATWEB_TIMEOUT = 60
HTTP_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (osint-framework recon tool)"


# --------------------------------------------------------------------------
# 1. WhatWeb
# --------------------------------------------------------------------------
def run_whatweb(target: str) -> list[dict]:
    """
    Lance WhatWeb sur une cible et retourne sa sortie JSON parsée.
    WhatWeb doit être disponible dans le PATH (préinstallé sur Kali).
    """
    whatweb_bin = shutil.which("whatweb")
    if not whatweb_bin:
        print("[!] WhatWeb introuvable dans le PATH.", file=sys.stderr)
        return []

    # -a 1 = aggression passive (rapide), évite les faux timeouts
    cmd = [whatweb_bin, "--log-json=-", "--no-errors", "-a", "1", target]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=WHATWEB_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        print(f"[!] WhatWeb timeout sur {target} (>{WHATWEB_TIMEOUT}s). "
              f"Vérifie que la cible répond bien en HTTP.", file=sys.stderr)
        return []

    if result.returncode != 0 and not result.stdout.strip():
        print(f"[!] WhatWeb a échoué sur {target} : {result.stderr.strip()[:200]}",
              file=sys.stderr)
        return []

    entries = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return entries


def _normalize_whatweb(raw_entries: list[dict]) -> list[dict]:
    """Transforme la sortie brute WhatWeb en liste {name, version, category}."""
    normalized = []
    for entry in raw_entries:
        plugins = entry.get("plugins", {})
        for plugin_name, plugin_data in plugins.items():
            if plugin_name in ("Title", "Country", "IP"):
                continue

            version = None
            if isinstance(plugin_data, dict):
                versions = plugin_data.get("version")
                if versions:
                    version = versions[0] if isinstance(versions, list) else versions

            normalized.append({
                "name": plugin_name,
                "version": version,
                "category": None,
                "source": "whatweb",
            })

    return normalized


# --------------------------------------------------------------------------
# 2. Détecteur "lite" maison (remplace python-Wappalyzer)
# --------------------------------------------------------------------------
# Base de signatures volontairement compacte : couvre les technologies les
# plus fréquemment rencontrées en bug bounty. Facile à étendre : ajoute une
# entrée avec les patterns pertinents (headers/html/cookies en regex).
TECH_SIGNATURES = {
    "WordPress":      {"category": "CMS", "html": [r"wp-content/", r"wp-includes/", r'name="generator" content="WordPress']},
    "Joomla":         {"category": "CMS", "html": [r"/media/jui/", r'content="Joomla']},
    "Drupal":         {"category": "CMS", "html": [r"sites/default/files", r'content="Drupal'], "headers": {"X-Generator": r"Drupal"}},
    "Magento":        {"category": "E-commerce", "html": [r"Mage\.Cookies", r"/skin/frontend/"]},
    "Shopify":        {"category": "E-commerce", "html": [r"cdn\.shopify\.com"], "headers": {"X-Shopify-Stage": r".*"}},
    "WooCommerce":    {"category": "E-commerce", "html": [r"woocommerce"]},
    "React":          {"category": "JS Framework", "html": [r"__REACT_DEVTOOLS", r"data-reactroot", r"react-dom"]},
    "Angular":        {"category": "JS Framework", "html": [r"ng-version", r"ng-app"]},
    "Vue.js":         {"category": "JS Framework", "html": [r"__vue__", r"data-v-[a-f0-9]{8}"]},
    "jQuery":         {"category": "JS Library", "html": [r"jquery(?:-[\d.]+)?\.js"]},
    "Bootstrap":      {"category": "CSS Framework", "html": [r"bootstrap(?:\.min)?\.css", r"class=\"[^\"]*\bcontainer-fluid\b"]},
    "Tailwind CSS":   {"category": "CSS Framework", "html": [r"tailwindcss"]},
    "Laravel":        {"category": "Framework", "html": [r"laravel_session"], "headers": {"Set-Cookie": r"laravel_session"}},
    "Django":         {"category": "Framework", "html": [r"csrfmiddlewaretoken"], "headers": {"Set-Cookie": r"csrftoken"}},
    "Express":        {"category": "Framework", "headers": {"X-Powered-By": r"Express"}},
    "ASP.NET":        {"category": "Framework", "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".*"}},
    "PHP":            {"category": "Language", "headers": {"X-Powered-By": r"PHP"}},
    "Nginx":          {"category": "Web Server", "headers": {"Server": r"nginx"}},
    "Apache":         {"category": "Web Server", "headers": {"Server": r"Apache"}},
    "IIS":            {"category": "Web Server", "headers": {"Server": r"Microsoft-IIS"}},
    "LiteSpeed":      {"category": "Web Server", "headers": {"Server": r"LiteSpeed"}},
    "Cloudflare":     {"category": "CDN / Security", "headers": {"Server": r"cloudflare", "CF-Ray": r".*"}},
    "AWS CloudFront": {"category": "CDN", "headers": {"Via": r"CloudFront", "X-Amz-Cf-Id": r".*"}},
    "Akamai":         {"category": "CDN", "headers": {"Server": r"AkamaiGHost"}},
    "Varnish":        {"category": "Cache", "headers": {"X-Varnish": r".*", "Via": r"varnish"}},
    "Google Analytics": {"category": "Analytics", "html": [r"google-analytics\.com/(?:ga|analytics)\.js", r"gtag\("]},
    "Google Tag Manager": {"category": "Tag Manager", "html": [r"googletagmanager\.com/gtm\.js"]},
    "Font Awesome":   {"category": "Font", "html": [r"font-awesome"]},
    "Elementor":      {"category": "Page Builder", "html": [r"elementor"]},
    "cPanel":         {"category": "Control Panel", "html": [r"cpanel", r":2083"]},
}


def run_wappalyzer_lite(url: str) -> list[dict]:
    """
    Analyse une URL en récupérant sa page d'accueil et en comparant
    headers/HTML aux signatures connues. Aucune dépendance externe
    fragile — uniquement `requests`.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        resp = requests.get(
            url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        print(f"[!] Détecteur lite : erreur réseau sur {url} ({exc})", file=sys.stderr)
        return []

    html = resp.text
    headers = resp.headers
    set_cookie = headers.get("Set-Cookie", "")

    detected = []
    for tech_name, sig in TECH_SIGNATURES.items():
        matched = False

        for header_name, pattern in sig.get("headers", {}).items():
            header_value = headers.get(header_name, "") + (set_cookie if header_name == "Set-Cookie" else "")
            if header_value and re.search(pattern, header_value, re.IGNORECASE):
                matched = True
                break

        if not matched:
            for pattern in sig.get("html", []):
                if re.search(pattern, html, re.IGNORECASE):
                    matched = True
                    break

        if matched:
            detected.append({
                "name": tech_name,
                "version": None,
                "category": sig.get("category"),
                "source": "lite",
            })

    return detected


# --------------------------------------------------------------------------
# 3. Orchestration
# --------------------------------------------------------------------------
def _merge_technologies(whatweb_techs: list[dict], lite_techs: list[dict]) -> list[dict]:
    """Fusionne les deux sources, marque 'both' en cas de double détection."""
    merged: dict[str, dict] = {}

    for tech in whatweb_techs + lite_techs:
        key = tech["name"].lower()
        if key not in merged:
            merged[key] = tech
        else:
            existing = merged[key]
            if existing["source"] != tech["source"]:
                existing["source"] = "both"
            if not existing.get("version") and tech.get("version"):
                existing["version"] = tech["version"]
            if not existing.get("category") and tech.get("category"):
                existing["category"] = tech["category"]

    return list(merged.values())


def scan_technologies(domain: str, engine: str = "both") -> dict:
    """
    Point d'entrée principal du module.
    engine : "whatweb", "lite" ou "both" (défaut).
    """
    whatweb_techs, lite_techs = [], []

    if engine in ("whatweb", "both"):
        print(f"[*] WhatWeb sur {domain} ...", file=sys.stderr)
        whatweb_techs = _normalize_whatweb(run_whatweb(domain))

    if engine in ("lite", "both"):
        print(f"[*] Détecteur lite sur {domain} ...", file=sys.stderr)
        lite_techs = run_wappalyzer_lite(domain)

    technologies = _merge_technologies(whatweb_techs, lite_techs)

    return {"domain": domain, "technologies": technologies}


def scan_multiple(domains: list[str], engine: str = "both") -> list[dict]:
    return [scan_technologies(d, engine=engine) for d in domains]


def main():
    parser = argparse.ArgumentParser(description="Détecteur de technologies OSINT")
    parser.add_argument("domains", nargs="+", help="Un ou plusieurs sous-domaines à analyser")
    parser.add_argument("--engine", choices=["whatweb", "lite", "both"], default="both",
                         help="Moteur(s) à utiliser (défaut: both)")
    parser.add_argument("--json", action="store_true", help="Sortie JSON brute")
    args = parser.parse_args()

    results = scan_multiple(args.domains, engine=args.engine)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for entry in results:
            print(f"\n{entry['domain']} :")
            if not entry["technologies"]:
                print("  Aucune technologie détectée")
            for tech in entry["technologies"]:
                version = f" v{tech['version']}" if tech["version"] else ""
                category = f" [{tech['category']}]" if tech["category"] else ""
                print(f"  - {tech['name']}{version}{category} (source: {tech['source']})")


if __name__ == "__main__":
    main()
