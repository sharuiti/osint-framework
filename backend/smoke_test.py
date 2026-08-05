"""
smoke_test.py
Test end-to-end de l'étape 8 : valide toute la chaîne en conditions
réelles (API démarrée, vrais outils Kali, vrai domaine) plutôt qu'en
mocks comme lors des étapes précédentes.

Vérifie dans l'ordre :
    1. L'API répond (health check)
    2. Le rejet propre d'un domaine invalide (422)
    3. Le 404 sur un scan inexistant
    4. Le démarrage d'un scan réel (202)
    5. Le polling jusqu'à "done" (avec timeout et affichage de la progression)
    6. La structure du JSON de résultats (clés attendues présentes)
    7. Le téléchargement du rapport PDF (magic bytes %PDF-)

Usage :
    # 1. Démarre l'API dans un autre terminal : uvicorn app:app --reload
    # 2. Lance ce script (depuis backend/) :
    python smoke_test.py ton-domaine-autorise.com

    # Avec un timeout de scan personnalisé (défaut 10 min) :
    python smoke_test.py ton-domaine.com --timeout 900
"""

import argparse
import sys
import time

import requests

API_BASE = "http://127.0.0.1:8000"

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
INFO = "\033[94mℹ\033[0m"


class SmokeTestFailure(Exception):
    pass


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label}" + (f" — {detail}" if detail else ""))
        raise SmokeTestFailure(label)


def step_health_check() -> None:
    print("\n[1/7] Health check API")
    try:
        resp = requests.get(f"{API_BASE}/docs", timeout=5)
    except requests.ConnectionError:
        raise SmokeTestFailure(
            f"API injoignable sur {API_BASE}. As-tu lancé `uvicorn app:app --reload` "
            f"dans un autre terminal, depuis backend/ ?"
        )
    check("API répond", resp.status_code == 200, f"status={resp.status_code}")


def step_invalid_domain() -> None:
    print("\n[2/7] Rejet d'un domaine invalide")
    resp = requests.post(f"{API_BASE}/scan", json={"domain": "pas un domaine !!"}, timeout=5)
    check("422 sur domaine mal formé", resp.status_code == 422, f"status={resp.status_code}")


def step_unknown_scan() -> None:
    print("\n[3/7] 404 sur un scan inexistant")
    resp = requests.get(f"{API_BASE}/scan/00000000-0000-0000-0000-000000000000/status", timeout=5)
    check("404 sur id inconnu", resp.status_code == 404, f"status={resp.status_code}")


def step_start_scan(domain: str, provider: str, tech_engine: str) -> str:
    print(f"\n[4/7] Démarrage d'un scan réel sur {domain}")
    resp = requests.post(
        f"{API_BASE}/scan",
        json={"domain": domain, "provider": provider, "tech_engine": tech_engine},
        timeout=10,
    )
    check("202 Accepted", resp.status_code == 202, f"status={resp.status_code} body={resp.text[:200]}")
    scan_id = resp.json()["id"]
    print(f"  {INFO} scan_id = {scan_id}")
    return scan_id


def step_poll_until_done(scan_id: str, timeout_s: int) -> dict:
    print(f"\n[5/7] Polling jusqu'à complétion (timeout {timeout_s}s)")
    started = time.time()
    last_progress = None

    while True:
        elapsed = time.time() - started
        if elapsed > timeout_s:
            raise SmokeTestFailure(
                f"Timeout après {timeout_s}s — le scan est peut-être juste lent "
                f"(theHarvester avec beaucoup de sources peut prendre du temps), "
                f"relance avec --timeout plus élevé si besoin."
            )

        resp = requests.get(f"{API_BASE}/scan/{scan_id}/status", timeout=10)
        check("status 200", resp.status_code == 200)
        data = resp.json()

        if data.get("progress") != last_progress:
            last_progress = data.get("progress")
            print(f"  {INFO} [{elapsed:5.0f}s] {data['status']:8s} — {last_progress}")

        if data["status"] == "done":
            print(f"  {PASS} Scan terminé en {elapsed:.0f}s")
            return data
        if data["status"] == "failed":
            raise SmokeTestFailure(f"Le scan a échoué : {data.get('error')}")

        time.sleep(2)


def step_check_results(scan_id: str) -> dict:
    print("\n[6/7] Validation de la structure des résultats")
    resp = requests.get(f"{API_BASE}/scan/{scan_id}/results", timeout=10)
    check("status 200", resp.status_code == 200)
    data = resp.json()

    expected_keys = {"domain", "scanned_at", "subdomains", "technologies",
                      "employees", "leaks", "score", "score_details"}
    missing = expected_keys - data.keys()
    check("toutes les clés attendues sont présentes", not missing, f"manquantes: {missing}")
    check("score calculé (non null)", data.get("score") is not None)
    check("score_details présent", data.get("score_details") is not None)

    print(f"  {INFO} {len(data['subdomains'])} sous-domaine(s), "
          f"{sum(len(t['technologies']) for t in data['technologies'])} technologie(s), "
          f"{len(data['employees'])} employé(s), "
          f"{len(data['leaks'])} email(s) vérifié(s)")
    print(f"  {INFO} Score : {data['score']}/100 ({data['score_details']['band']})")

    return data


def step_check_report(scan_id: str) -> None:
    print("\n[7/7] Génération et téléchargement du rapport PDF")
    resp = requests.get(f"{API_BASE}/scan/{scan_id}/report", timeout=60)
    check("status 200", resp.status_code == 200)
    check("content-type PDF", resp.headers.get("content-type") == "application/pdf",
          resp.headers.get("content-type"))
    check("magic bytes %PDF-", resp.content[:5] == b"%PDF-")
    check("taille non nulle", len(resp.content) > 1000, f"{len(resp.content)} bytes")

    out_path = f"smoke_test_report_{scan_id[:8]}.pdf"
    with open(out_path, "wb") as f:
        f.write(resp.content)
    print(f"  {INFO} Rapport sauvegardé : {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Test end-to-end du framework OSINT")
    parser.add_argument("domain", help="Domaine autorisé à scanner")
    parser.add_argument("--provider", default="xposedornot",
                         choices=["leakcheck", "hibp", "xposedornot", "both"])
    parser.add_argument("--tech-engine", default="both", choices=["whatweb", "lite", "both"])
    parser.add_argument("--timeout", type=int, default=600, help="Timeout du polling en secondes")
    args = parser.parse_args()

    print(f"=== Smoke test — {args.domain} ===")

    try:
        step_health_check()
        step_invalid_domain()
        step_unknown_scan()
        scan_id = step_start_scan(args.domain, args.provider, args.tech_engine)
        step_poll_until_done(scan_id, args.timeout)
        step_check_results(scan_id)
        step_check_report(scan_id)
    except SmokeTestFailure as exc:
        print(f"\n{FAIL} ÉCHEC : {exc}")
        sys.exit(1)

    print(f"\n{PASS} TOUS LES TESTS PASSENT — la chaîne complète fonctionne.")


if __name__ == "__main__":
    main()
