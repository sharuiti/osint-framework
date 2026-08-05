"""
email_security.py
Évalue la surface de phishing d'un domaine : configuration SPF, DKIM,
DMARC, et format d'adresse email déduit des employés déjà identifiés.

Pourquoi ce module a le meilleur ratio valeur/risque/effort du lot :
- 100% passif (uniquement des requêtes DNS TXT, rien d'actif).
- Déterministe : soit un enregistrement DMARC avec p=reject existe,
  soit non. Pas de faux positif possible sur SPF/DMARC eux-mêmes.
- Directement actionnable et compréhensible par un non-technicien
  ("votre domaine peut être usurpé par email").

Limite honnête sur DKIM : il n'existe AUCUN moyen de découvrir le
sélecteur DKIM utilisé par un domaine sans l'avoir reçu dans un email
(le sélecteur fait partie de l'enregistrement DNS
"{selecteur}._domainkey.{domaine}", et le nom du sélecteur est
arbitraire). On teste donc une liste de sélecteurs courants — un
résultat négatif signifie "non trouvé parmi les sélecteurs usuels",
PAS "DKIM absent". Ce module l'affiche explicitement plutôt que de
prétendre à une certitude qu'il n'a pas.

Usage CLI :
    python core/email_security.py example.com
    python core/email_security.py example.com --json
"""

import argparse
import json
import sys

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] dnspython manquant. Installe avec : pip install dnspython", file=sys.stderr)
    raise

DNS_TIMEOUT = 5

# Sélecteurs DKIM les plus fréquents (fournisseurs email + CMS courants).
# Liste volontairement non exhaustive — voir la limite honnête ci-dessus.
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",  # Google Workspace, Microsoft 365
    "k1", "k2", "mail", "dkim", "s1", "s2",           # Mailchimp/Sendgrid-like, génériques
    "smtp", "key1", "dkim1", "mandrill", "zoho",
    "amazonses", "mailgun", "pm",                      # Amazon SES, Mailgun, Postmark
]


# --------------------------------------------------------------------------
# Utilitaire DNS commun
# --------------------------------------------------------------------------
def _get_txt_records(name: str) -> list[str]:
    """
    Récupère et décode les enregistrements TXT d'un nom DNS. Un TXT
    peut être fragmenté en plusieurs chaînes — dnspython les expose
    via .strings, qu'on rejoint ici en une seule chaîne par
    enregistrement (comportement attendu pour SPF/DMARC).
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    try:
        answers = resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return []
    except Exception as exc:
        print(f"[!] Erreur DNS inattendue sur {name!r} : {exc}", file=sys.stderr)
        return []

    records = []
    for rdata in answers:
        joined = b"".join(rdata.strings).decode(errors="ignore")
        records.append(joined)
    return records


# --------------------------------------------------------------------------
# 1. SPF
# --------------------------------------------------------------------------
def check_spf(domain: str) -> dict:
    """
    Cherche l'enregistrement SPF (TXT commençant par "v=spf1") sur le
    domaine racine. Évalue le mécanisme final ("all") qui détermine le
    comportement pour tout expéditeur non explicitement autorisé :
        -all  = fail strict (bon)
        ~all  = softfail (acceptable, marque comme suspect sans bloquer)
        ?all  = neutral (faible, équivaut à ne rien dire)
        +all  = pass explicite (TRÈS mauvais — autorise n'importe qui)
        absent = aucun mécanisme "all", comportement ambigu
    """
    txt_records = _get_txt_records(domain)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return {
            "present": False, "record": None, "qualifier": None,
            "risk": "high", "detail": "Aucun enregistrement SPF trouvé.",
        }

    # Plusieurs enregistrements SPF sur un même domaine est en soi une
    # violation de la RFC 7208 (comportement indéfini) — on le signale.
    multiple = len(spf_records) > 1
    record = spf_records[0]

    qualifier, risk, detail = None, "medium", "SPF présent."
    lowered = record.lower()
    if lowered.rstrip().endswith("-all"):
        qualifier, risk, detail = "-all", "low", "SPF strict (-all) : bonne protection."
    elif lowered.rstrip().endswith("~all"):
        qualifier, risk, detail = "~all", "low", "SPF souple (~all) : protection correcte."
    elif lowered.rstrip().endswith("?all"):
        qualifier, risk, detail = "?all", "medium", "SPF neutre (?all) : protection faible."
    elif lowered.rstrip().endswith("+all"):
        qualifier, risk, detail = "+all", "critical", \
            "SPF permissif (+all) : autorise explicitement N'IMPORTE QUEL expéditeur. " \
            "Configuration dangereuse à corriger en priorité."
    else:
        qualifier, risk, detail = None, "medium", \
            "SPF présent sans mécanisme 'all' final — comportement ambigu pour les " \
            "expéditeurs non listés."

    if multiple:
        detail += " ATTENTION : plusieurs enregistrements SPF détectés (RFC 7208 : " \
                   "comportement indéfini, à corriger)."

    return {
        "present": True, "record": record, "qualifier": qualifier,
        "risk": risk, "detail": detail,
    }


# --------------------------------------------------------------------------
# 2. DMARC
# --------------------------------------------------------------------------
def check_dmarc(domain: str) -> dict:
    """
    Cherche l'enregistrement DMARC sur _dmarc.{domain}. La politique
    (p=) est le signal principal :
        reject     = bon (emails non-authentifiés rejetés)
        quarantine = acceptable (mis en spam)
        none       = surveillance seule, AUCUNE protection réelle
        absent     = aucune protection, domaine trivialement usurpable
    """
    txt_records = _get_txt_records(f"_dmarc.{domain}")
    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return {
            "present": False, "record": None, "policy": None, "pct": None,
            "risk": "critical",
            "detail": "Aucun enregistrement DMARC — le domaine peut être usurpé "
                      "par email sans aucune protection.",
        }

    record = dmarc_records[0]
    tags = _parse_dmarc_tags(record)
    policy = tags.get("p")
    pct = tags.get("pct", "100")

    if policy == "reject":
        risk, detail = "low", "Politique DMARC stricte (reject) : bonne protection."
    elif policy == "quarantine":
        risk, detail = "medium", "Politique DMARC modérée (quarantine) : emails " \
                                  "non-authentifiés mis en spam plutôt que rejetés."
    elif policy == "none":
        risk, detail = "high", "Politique DMARC en mode surveillance uniquement " \
                                "(p=none) : AUCUNE protection réelle, juste des rapports."
    else:
        risk, detail = "high", f"Politique DMARC non reconnue ou absente ({policy!r})."

    try:
        if int(pct) < 100 and policy in ("reject", "quarantine"):
            detail += f" Seulement {pct}% des emails non-conformes sont soumis à la politique."
            if risk == "low":
                risk = "medium"
    except (TypeError, ValueError):
        pass

    return {
        "present": True, "record": record, "policy": policy, "pct": pct,
        "risk": risk, "detail": detail,
    }


def _parse_dmarc_tags(record: str) -> dict:
    """Parse un enregistrement DMARC 'v=DMARC1; p=reject; pct=100; ...' en dict."""
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


# --------------------------------------------------------------------------
# 3. DKIM (best-effort — voir limite honnête en tête de fichier)
# --------------------------------------------------------------------------
def check_dkim(domain: str, selectors: list[str] = None) -> dict:
    """
    Teste une liste de sélecteurs DKIM courants. Un résultat négatif
    NE PROUVE PAS l'absence de DKIM — seulement qu'aucun des
    sélecteurs testés n'est utilisé. Le champ "confidence" reflète
    cette limite plutôt que de l'afficher comme "DKIM absent".
    """
    selectors = selectors or COMMON_DKIM_SELECTORS
    found = []

    for selector in selectors:
        records = _get_txt_records(f"{selector}._domainkey.{domain}")
        dkim_records = [r for r in records if "v=dkim1" in r.lower() or "p=" in r.lower()]
        if dkim_records:
            found.append({"selector": selector, "record": dkim_records[0]})

    if found:
        return {
            "detected": True, "selectors_found": found,
            "confidence": "confirmed",
            "detail": f"DKIM confirmé via le(s) sélecteur(s) : "
                      f"{', '.join(f['selector'] for f in found)}.",
        }

    return {
        "detected": False, "selectors_found": [],
        "confidence": "unknown",
        "detail": f"Aucun DKIM trouvé parmi {len(selectors)} sélecteurs courants testés. "
                  f"NE SIGNIFIE PAS que DKIM est absent — le domaine peut utiliser un "
                  f"sélecteur personnalisé non testé.",
    }


# --------------------------------------------------------------------------
# 4. Format d'email déduit (à partir des employés déjà identifiés)
# --------------------------------------------------------------------------
def deduce_email_format(employees: list[dict]) -> dict:
    """
    Déduit le format d'adresse email dominant à partir d'employés dont
    le nom ET l'email sont connus (typiquement fournis par Hunter.io ou
    devinés par employee_finder.py). Utile pour évaluer la facilité de
    prédire l'email d'une cible non encore identifiée (spear phishing).
    """
    patterns_count: dict[str, int] = {}

    for emp in employees:
        name, email = emp.get("name"), emp.get("email")
        if not name or not email or "@" not in email:
            continue

        local_part = email.split("@")[0].lower()
        name_parts = [p.lower() for p in name.split() if p.isalpha()]
        if len(name_parts) < 2:
            continue
        first, last = name_parts[0], name_parts[-1]

        pattern = None
        if local_part == f"{first}.{last}":
            pattern = "prenom.nom"
        elif local_part == f"{first[0]}{last}":
            pattern = "pnom"
        elif local_part == f"{first}{last}":
            pattern = "prenomnom"
        elif local_part == f"{first}":
            pattern = "prenom"
        elif local_part == f"{last}":
            pattern = "nom"
        elif local_part == f"{first[0]}.{last}":
            pattern = "p.nom"

        if pattern:
            patterns_count[pattern] = patterns_count.get(pattern, 0) + 1

    if not patterns_count:
        return {"format": None, "confidence": 0, "sample_size": 0,
                "detail": "Format d'email indéterminé (pas assez d'employés avec nom ET email connus)."}

    best_pattern = max(patterns_count, key=patterns_count.get)
    total_matched = sum(patterns_count.values())
    confidence = round(100 * patterns_count[best_pattern] / total_matched)

    return {
        "format": best_pattern,
        "confidence": confidence,
        "sample_size": total_matched,
        "detail": f"Format dominant : '{best_pattern}' ({patterns_count[best_pattern]}/"
                  f"{total_matched} employés analysés). Facilite la prédiction d'adresses "
                  f"email pour du spear phishing ciblé.",
    }


# --------------------------------------------------------------------------
# 5. Orchestration
# --------------------------------------------------------------------------
def analyze_email_security(domain: str, employees: list[dict] = None) -> dict:
    """Point d'entrée principal du module."""
    print(f"[*] SPF sur {domain} ...", file=sys.stderr)
    spf = check_spf(domain)

    print(f"[*] DMARC sur {domain} ...", file=sys.stderr)
    dmarc = check_dmarc(domain)

    print(f"[*] DKIM sur {domain} (sélecteurs courants) ...", file=sys.stderr)
    dkim = check_dkim(domain)

    email_format = deduce_email_format(employees or [])

    print(f"    -> SPF: {spf['risk']} | DMARC: {dmarc['risk']} | "
          f"DKIM: {'confirmé' if dkim['detected'] else 'non trouvé (sélecteurs courants)'}",
          file=sys.stderr)

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "email_format": email_format,
    }


def main():
    parser = argparse.ArgumentParser(description="Surface de phishing : SPF/DKIM/DMARC")
    parser.add_argument("domain", help="Domaine cible, ex: example.com")
    parser.add_argument("--json", action="store_true", help="Sortie JSON brute")
    args = parser.parse_args()

    result = analyze_email_security(args.domain)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"\nDomaine : {result['domain']}\n")
        print(f"SPF    : {result['spf']['detail']}")
        print(f"DMARC  : {result['dmarc']['detail']}")
        print(f"DKIM   : {result['dkim']['detail']}")


if __name__ == "__main__":
    main()
