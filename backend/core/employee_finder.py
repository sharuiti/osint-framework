"""
employee_finder.py
Découverte d'emails et d'employés via Hunter.io (si une clé API est
fournie) ou theHarvester en repli.

Pourquoi Hunter.io en priorité ?
theHarvester s'appuie sur du scraping de Google/Bing, de plus en plus
bloqué par de l'anti-bot (CAPTCHA, rate-limiting) — d'où les scans qui
renvoient systématiquement 0 email. Hunter.io est une vraie API (pas de
scraping), gratuite jusqu'à 25 requêtes/mois, et renvoie un score de
confiance par email calculé par leur service plutôt que deviné par nous.

Note sur les rôles : Hunter.io fournit parfois un poste ("position")
que theHarvester ne fournit jamais. Pour theHarvester, on tente une
extraction heuristique de noms à partir des adresses email.

À SAVOIR — 0 résultat n'est pas forcément un bug (sans clé Hunter) :
Google/Bing bloquent de plus en plus le scraping automatisé, donc les
sources gratuites de theHarvester échouent souvent silencieusement. La
sortie stdout/stderr de theHarvester est capturée et affichée (voir
_log_harvester_output) pour voir concrètement quelle source a bloqué.

Usage CLI :
    # Avec Hunter.io (recommandé) :
    export HUNTER_API_KEY="ta_cle"
    python core/employee_finder.py example.com

    # Sans clé, repli automatique sur theHarvester :
    python core/employee_finder.py example.com --json --sources google,bing,linkedin
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

HUNTER_URL = "https://api.hunter.io/v2/domain-search"
HUNTER_TIMEOUT = 15
# Le plan gratuit Hunter.io plafonne à 10 résultats — demander plus fait
# échouer TOUTE la requête (pas de troncature côté API). On part donc
# sur 10 par défaut, robuste au plan gratuit, et on s'adapte
# automatiquement si un plan payant permet une limite différente (voir
# LIMIT_ERROR_RE ci-dessous).
HUNTER_DEFAULT_LIMIT = 10
LIMIT_ERROR_RE = re.compile(r"limited to (\d+) email addresses")

THEHARVESTER_TIMEOUT = 120
# Sous-ensemble volontairement restreint : sources gratuites, sans clé
# API, qui trouvent effectivement des emails (pas juste des hosts).
# "all" est déconseillé par défaut — trop de sources y échouent
# lentement faute de clé API, sans rien apporter.
# NB: "bing"/"google" ont été retirés des versions récentes de
# theHarvester (dépréciés par les mainteneurs suite aux blocages
# anti-scraping) — absents du défaut pour éviter un aller-retour de
# retry systématique, mais le mécanisme de retry (voir
# UNSUPPORTED_ENGINES_RE) reste actif si de nouveaux moteurs sont
# dépréciés à l'avenir, ou si tu les ajoutes manuellement via --sources.
DEFAULT_SOURCES = "baidu,crtsh,duckduckgo,yahoo"
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


# --------------------------------------------------------------------------
# 0. Hunter.io — source primaire si une clé est fournie
# --------------------------------------------------------------------------
def _hunter_request(domain: str, api_key: str, limit: int) -> requests.Response:
    params = {"domain": domain, "api_key": api_key, "limit": limit}
    return requests.get(HUNTER_URL, params=params, timeout=HUNTER_TIMEOUT)


def query_hunter(domain: str, api_key: str, limit: int = HUNTER_DEFAULT_LIMIT) -> dict:
    """
    Interroge l'API Hunter.io Domain Search. Retourne le même format
    normalisé que parse_employees() pour que find_employees() puisse
    traiter les deux sources de façon interchangeable.

    Le score de confiance Hunter (0-100, calculé par leur service à
    partir du nombre de sources corroborantes) est mappé sur nos trois
    niveaux "low"/"medium"/"high" plutôt que gardé en brut, pour rester
    cohérent avec le reste du framework.

    La limite du plan (10 en gratuit, différente en payant) n'est pas
    connue à l'avance sans appel dédié — plutôt que de la coder en dur,
    on retente automatiquement une fois avec la valeur exacte que
    l'API elle-même communique dans son message d'erreur.
    """
    try:
        resp = _hunter_request(domain, api_key, limit)
    except requests.RequestException as exc:
        print(f"[!] Erreur réseau Hunter.io : {exc}", file=sys.stderr)
        return {}

    if resp.status_code == 401:
        print("[!] Clé Hunter.io invalide (401).", file=sys.stderr)
        return {}
    if resp.status_code == 429:
        print("[!] Quota Hunter.io dépassé (25 requêtes/mois en gratuit) — "
              "repli sur theHarvester.", file=sys.stderr)
        return {}

    if resp.status_code != 200:
        body = resp.json().get("errors", [{}]) if resp.content else [{}]
        detail = body[0].get("details", f"HTTP {resp.status_code}") if body else f"HTTP {resp.status_code}"

        # Cas précis : la limite demandée dépasse celle du plan. L'API
        # communique la vraie valeur autorisée dans le message — on
        # l'utilise pour un unique retry plutôt que d'abandonner.
        match = LIMIT_ERROR_RE.search(detail)
        if match and int(match.group(1)) != limit:
            real_limit = int(match.group(1))
            print(f"[i] Limite de plan Hunter.io détectée : {real_limit} "
                  f"(demandé: {limit}) — nouvelle tentative.", file=sys.stderr)
            try:
                resp = _hunter_request(domain, api_key, real_limit)
            except requests.RequestException as exc:
                print(f"[!] Erreur réseau Hunter.io (retry) : {exc}", file=sys.stderr)
                return {}
            if resp.status_code != 200:
                print(f"[!] Erreur Hunter.io persistante après retry : "
                      f"HTTP {resp.status_code}", file=sys.stderr)
                return {}
        else:
            print(f"[!] Erreur Hunter.io : {detail}", file=sys.stderr)
            return {}

    data = resp.json().get("data", {})
    raw_emails = data.get("emails", []) or []

    if not raw_emails:
        print("[i] Hunter.io n'a trouvé aucun email pour ce domaine "
              "(peut être légitime — pas forcément un problème de quota/clé).",
              file=sys.stderr)
        return {"emails": [], "employees": [], "hosts": []}

    employees = []
    for e in raw_emails:
        email = e.get("value")
        if not email:
            continue
        first, last = e.get("first_name"), e.get("last_name")
        name = f"{first} {last}".strip() if (first or last) else None
        score = e.get("confidence", 0)  # 0-100

        if score >= 75:
            confidence = "high"
        elif score >= 40:
            confidence = "medium"
        else:
            confidence = "low"

        employees.append({
            "name": name,
            "email": email,
            "confidence": confidence,
            "position": e.get("position"),  # champ bonus, absent chez theHarvester
        })

    print(f"[*] Hunter.io : {len(employees)} email(s), "
          f"{data.get('organization', domain)} — quota restant non communiqué par ce endpoint",
          file=sys.stderr)

    return {
        "emails": sorted(e["email"] for e in employees),
        "employees": employees,
        "hosts": [],
    }


def _log_harvester_output(stdout: str, stderr: str) -> None:
    """
    Affiche les dernières lignes utiles de theHarvester sur stderr.
    Avant ce correctif, cette sortie était capturée puis jetée — donc
    un blocage anti-bot ("Google usage exceeded", CAPTCHA, etc.) était
    invisible. On filtre les lignes vides et on tronque pour rester
    lisible sur un scan avec beaucoup de sources.
    """
    combined = (stdout or "") + (stderr or "")
    useful_lines = [l.strip() for l in combined.splitlines() if l.strip()]
    if not useful_lines:
        return
    print("[*] Sortie theHarvester (diagnostic) :", file=sys.stderr)
    for line in useful_lines[-25:]:
        print(f"      {line}", file=sys.stderr)


# theHarvester rejette TOUTE la commande si un seul moteur listé via -b
# n'est plus supporté par la version installée (ex: "bing"/"google" ont
# été retirés dans les versions récentes suite aux blocages anti-bot).
# On détecte ce message précis pour retirer automatiquement les moteurs
# fautifs et relancer, plutôt que d'abandonner avec 0 résultat alors que
# les autres sources (crtsh, duckduckgo, yahoo...) auraient fonctionné.
UNSUPPORTED_ENGINES_RE = re.compile(r"following engines are not supported:\s*\{([^}]*)\}")


def _run_theharvester_once(binary: str, domain: str, sources: str,
                            output_basename: str, timeout: int) -> subprocess.CompletedProcess:
    cmd = [binary, "-d", domain, "-b", sources, "-f", output_basename]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


# --------------------------------------------------------------------------
# 1. Exécution de theHarvester
# --------------------------------------------------------------------------
def run_theharvester(domain: str, sources: str = DEFAULT_SOURCES,
                      timeout: int = THEHARVESTER_TIMEOUT) -> dict:
    """
    Lance theHarvester et retourne le contenu JSON généré.
    theHarvester écrit son résultat dans <basename>.json quand on
    utilise -f <basename> (l'extension est ajoutée automatiquement).

    Si theHarvester rejette la liste de sources à cause d'un moteur
    déprécié (message "following engines are not supported"), on
    retire automatiquement ce(s) moteur(s) et on relance UNE fois avec
    le reste — plutôt que d'abandonner avec 0 résultat.
    """
    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    if not binary:
        print("[!] theHarvester introuvable dans le PATH. "
              "Installe-le avec : sudo apt install theharvester", file=sys.stderr)
        return {}

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_basename = str(Path(tmp_dir) / "harvest_output")

        try:
            result = _run_theharvester_once(binary, domain, sources, output_basename, timeout)
            _log_harvester_output(result.stdout, result.stderr)

            match = UNSUPPORTED_ENGINES_RE.search((result.stdout or "") + (result.stderr or ""))
            if match:
                unsupported = {s.strip().strip("'\"") for s in match.group(1).split(",") if s.strip()}
                remaining = [s for s in sources.split(",") if s.strip() not in unsupported]

                if remaining:
                    remaining_str = ",".join(remaining)
                    print(f"[i] Moteur(s) non supporté(s) par cette version de theHarvester : "
                          f"{', '.join(sorted(unsupported))} — nouvelle tentative avec : "
                          f"{remaining_str}", file=sys.stderr)
                    result = _run_theharvester_once(binary, domain, remaining_str,
                                                     output_basename, timeout)
                    _log_harvester_output(result.stdout, result.stderr)
                else:
                    print("[!] Tous les moteurs demandés sont non supportés par cette "
                          "version de theHarvester — installe une version à jour ou "
                          "précise --sources manuellement.", file=sys.stderr)
                    return {}

        except subprocess.TimeoutExpired as exc:
            print(f"[!] theHarvester a dépassé le timeout ({timeout}s).", file=sys.stderr)
            # Même en cas de timeout, subprocess capture parfois du stdout
            # partiel — utile pour voir où ça bloquait.
            _log_harvester_output(
                exc.stdout.decode(errors="ignore") if exc.stdout else "",
                exc.stderr.decode(errors="ignore") if exc.stderr else "",
            )
            return {}
        except FileNotFoundError:
            print("[!] Impossible d'exécuter theHarvester.", file=sys.stderr)
            return {}

        json_path = Path(output_basename + ".json")
        if not json_path.exists():
            print("[!] Aucun fichier JSON généré par theHarvester "
                  "(vérifie les sources et la connectivité).", file=sys.stderr)
            return {}

        try:
            return json.loads(json_path.read_text(errors="ignore"))
        except json.JSONDecodeError:
            print("[!] JSON de theHarvester illisible.", file=sys.stderr)
            return {}


# --------------------------------------------------------------------------
# 2. Extraction et normalisation
# --------------------------------------------------------------------------
def _guess_name_from_email(email: str) -> str | None:
    """
    Heuristique simple : john.doe@example.com -> "John Doe".
    Retourne None si le format local-part ne ressemble pas à un nom
    (ex: contact@, info@, no-reply@).
    """
    generic_prefixes = {
        "contact", "info", "admin", "support", "sales", "hello",
        "noreply", "no-reply", "webmaster", "office", "help",
    }
    local_part = email.split("@")[0].lower()

    if local_part in generic_prefixes:
        return None

    separators = [".", "_", "-"]
    parts = [local_part]
    for sep in separators:
        if sep in local_part:
            parts = local_part.split(sep)
            break

    if len(parts) < 2 or any(not p.isalpha() for p in parts):
        return None

    return " ".join(p.capitalize() for p in parts)


def parse_employees(raw_data: dict) -> dict:
    """
    Normalise la sortie theHarvester en :
    {
        "emails": [...],
        "employees": [{"name": ..., "email": ..., "confidence": "low|medium"}],
        "hosts": [...],
    }
    """
    emails = set(raw_data.get("emails", []) or [])

    # Fallback : si theHarvester n'a pas structuré les emails,
    # on les extrait par regex depuis n'importe quel champ texte.
    if not emails:
        flat_text = json.dumps(raw_data)
        emails.update(EMAIL_REGEX.findall(flat_text))

    employees = []
    for email in sorted(emails):
        guessed_name = _guess_name_from_email(email)
        employees.append({
            "name": guessed_name,
            "email": email,
            "confidence": "medium" if guessed_name else "low",
        })

    return {
        "emails": sorted(emails),
        "employees": employees,
        "hosts": raw_data.get("hosts", []) or [],
    }


# --------------------------------------------------------------------------
# 3. Orchestration
# --------------------------------------------------------------------------
def find_employees(domain: str, sources: str = DEFAULT_SOURCES,
                    hunter_api_key: str | None = None) -> dict:
    """
    Point d'entrée principal du module.

    Si hunter_api_key est fourni : Hunter.io est utilisé en premier.
    S'il renvoie au moins un email, theHarvester n'est pas lancé (pas
    besoin de payer le temps d'exécution d'un scraping qui a de fortes
    chances d'échouer). Si Hunter.io ne renvoie rien (quota, clé
    invalide, ou réellement aucun résultat), on retombe sur
    theHarvester pour ne pas repartir bredouille.
    """
    if hunter_api_key:
        print(f"[*] Hunter.io sur {domain} ...", file=sys.stderr)
        hunter_result = query_hunter(domain, hunter_api_key)
        if hunter_result.get("emails"):
            return {"domain": domain, "source": "hunter.io", **hunter_result}
        print("[*] Repli sur theHarvester ...", file=sys.stderr)

    print(f"[*] theHarvester sur {domain} (sources: {sources}) ...", file=sys.stderr)
    raw = run_theharvester(domain, sources=sources)
    parsed = parse_employees(raw)

    print(f"    -> {len(parsed['emails'])} emails, "
          f"{sum(1 for e in parsed['employees'] if e['name'])} noms devinés", file=sys.stderr)

    if not parsed["emails"]:
        print("[i] 0 email trouvé — souvent dû au blocage anti-scraping de "
              "Google/Bing sur les requêtes automatisées, pas forcément un bug. "
              "Regarde le diagnostic theHarvester ci-dessus pour confirmer. "
              "Pour des résultats plus fiables, configure HUNTER_API_KEY.", file=sys.stderr)

    return {
        "domain": domain,
        "source": "theharvester",
        **parsed,
    }


def main():
    import os

    parser = argparse.ArgumentParser(description="OSINT humain : emails et employés")
    parser.add_argument("domain", help="Domaine cible, ex: example.com")
    parser.add_argument("--sources", default=DEFAULT_SOURCES,
                         help=f"Sources theHarvester séparées par virgule (défaut: {DEFAULT_SOURCES})")
    parser.add_argument("--json", action="store_true", help="Sortie JSON brute")
    args = parser.parse_args()

    result = find_employees(args.domain, sources=args.sources,
                             hunter_api_key=os.environ.get("HUNTER_API_KEY"))

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\nDomaine : {result['domain']} (source: {result['source']})")
        print(f"{len(result['emails'])} emails trouvés :\n")
        for emp in result["employees"]:
            name = emp["name"] or "(nom inconnu)"
            position = f" — {emp['position']}" if emp.get("position") else ""
            print(f"  {emp['email']:<35} {name:<25}{position} [confiance: {emp['confidence']}]")


if __name__ == "__main__":
    main()
