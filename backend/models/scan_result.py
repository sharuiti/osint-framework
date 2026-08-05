"""
scan_result.py
Modèle de données commun (Pydantic) unifiant les sorties de :
  - subdomain_scanner.py
  - tech_detector.py
  - employee_finder.py
  - leak_checker.py

Chaque module de scan retourne son propre format normalisé (voir leurs
docstrings). Ce fichier fournit :
  1. Les sous-modèles typés (SubdomainInfo, TechnologyInfo, ...)
  2. Le modèle ScanResult qui les agrège
  3. build_scan_result() : convertit les dicts bruts retournés par les
     4 modules en un objet ScanResult unique, prêt pour le scoring
     (étape 4) et le rapport PDF (étape 6).

Usage CLI (démo avec données factices) :
    python models/scan_result.py --demo
"""

import argparse
import json
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------
# Sous-modèles — un par module de scan
# --------------------------------------------------------------------------
class SubdomainInfo(BaseModel):
    subdomain: str
    ips: list[str] = Field(default_factory=list)


class TechnologyInfo(BaseModel):
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    source: str  # "whatweb" | "lite" | "both"


class SubdomainTechnologies(BaseModel):
    """Technologies détectées pour un sous-domaine donné."""
    domain: str
    technologies: list[TechnologyInfo] = Field(default_factory=list)


class EmployeeInfo(BaseModel):
    name: Optional[str] = None
    email: str
    confidence: str = "low"  # "low" | "medium" | "high" (voir employee_finder.py)
    position: Optional[str] = None  # fourni par Hunter.io ; absent chez theHarvester


class LeakSource(BaseModel):
    source: str
    breach_date: Optional[str] = None
    password_masked: Optional[str] = None  # JAMAIS de mot de passe en clair
    fields_exposed: list[str] = Field(default_factory=list)


class LeakInfo(BaseModel):
    email: str
    leaked: Optional[bool] = None  # None = statut inconnu (erreur API)
    sources: list[LeakSource] = Field(default_factory=list)
    errors: Optional[list[str]] = None


class EnvironmentCandidate(BaseModel):
    subdomain: str
    category: str  # "non_prod" | "admin_panel"
    matched_keyword: str
    risk: str  # "medium" | "high"
    detail: str = ""


class TakeoverCandidate(BaseModel):
    subdomain: str
    cname: str
    service: str
    confidence: str  # "high" | "low" — jamais "confirmed", voir takeover_detector.py
    method: str  # "dangling_cname" | "fingerprint_match" | "known_vulnerable_service_pattern"
    fingerprint_matched: Optional[str] = None
    detail: str = ""


class SpfInfo(BaseModel):
    present: bool
    record: Optional[str] = None
    qualifier: Optional[str] = None  # "-all" | "~all" | "?all" | "+all" | None
    risk: str = "medium"  # "low" | "medium" | "high" | "critical"
    detail: str = ""


class DmarcInfo(BaseModel):
    present: bool
    record: Optional[str] = None
    policy: Optional[str] = None  # "reject" | "quarantine" | "none" | None
    pct: Optional[str] = None
    risk: str = "medium"
    detail: str = ""


class DkimSelectorMatch(BaseModel):
    selector: str
    record: str


class DkimInfo(BaseModel):
    detected: bool
    selectors_found: list[DkimSelectorMatch] = Field(default_factory=list)
    confidence: str = "unknown"  # "confirmed" | "unknown" (jamais "absent" — voir email_security.py)
    detail: str = ""


class EmailFormatInfo(BaseModel):
    format: Optional[str] = None  # ex: "prenom.nom"
    confidence: int = 0  # 0-100
    sample_size: int = 0
    detail: str = ""


class EmailSecurityInfo(BaseModel):
    """Surface de phishing : SPF, DMARC, DKIM (best-effort), format d'email déduit."""
    spf: SpfInfo
    dmarc: DmarcInfo
    dkim: DkimInfo
    email_format: EmailFormatInfo


# --------------------------------------------------------------------------
# Modèle agrégé
# --------------------------------------------------------------------------
class ScanResult(BaseModel):
    """
    Résultat complet d'un scan OSINT pour un domaine, agrégeant les
    4 modules. `score` et `score_details` restent vides tant que
    l'étape 4 (scoring_engine.py) n'a pas tourné dessus.
    """
    domain: str
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    subdomains: list[SubdomainInfo] = Field(default_factory=list)
    technologies: list[SubdomainTechnologies] = Field(default_factory=list)
    employees: list[EmployeeInfo] = Field(default_factory=list)
    leaks: list[LeakInfo] = Field(default_factory=list)
    email_security: Optional[EmailSecurityInfo] = None
    takeover_candidates: list[TakeoverCandidate] = Field(default_factory=list)
    environment_candidates: list[EnvironmentCandidate] = Field(default_factory=list)

    score: Optional[float] = None
    score_details: Optional[dict] = None

    # ----------------------------------------------------------------
    # Helpers de synthèse — utiles pour le dashboard et le rapport PDF
    # ----------------------------------------------------------------
    def summary(self) -> dict:
        """Statistiques agrégées rapides, prêtes pour l'affichage."""
        leaked_emails = [l for l in self.leaks if l.leaked]
        high_confidence_takeovers = [c for c in self.takeover_candidates if c.confidence == "high"]
        admin_panels = [c for c in self.environment_candidates if c.category == "admin_panel"]
        return {
            "domain": self.domain,
            "scanned_at": self.scanned_at,
            "total_subdomains": len(self.subdomains),
            "total_technologies": sum(len(t.technologies) for t in self.technologies),
            "total_employees": len(self.employees),
            "total_emails_checked": len(self.leaks),
            "total_emails_leaked": len(leaked_emails),
            "dmarc_policy": self.email_security.dmarc.policy if self.email_security else None,
            "total_takeover_candidates": len(self.takeover_candidates),
            "high_confidence_takeovers": len(high_confidence_takeovers),
            "total_environment_candidates": len(self.environment_candidates),
            "admin_panels_exposed": len(admin_panels),
            "score": self.score,
        }

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)


# --------------------------------------------------------------------------
# Construction depuis les sorties brutes des 4 modules
# --------------------------------------------------------------------------
def build_scan_result(
    domain: str,
    subdomain_scan: Optional[dict] = None,
    tech_scans: Optional[list[dict]] = None,
    employee_scan: Optional[dict] = None,
    leak_results: Optional[list[dict]] = None,
    email_security_scan: Optional[dict] = None,
    takeover_scan: Optional[dict] = None,
    environment_scan: Optional[dict] = None,
) -> ScanResult:
    """
    Convertit les dicts bruts retournés par les fonctions scan_subdomains(),
    scan_multiple() (tech_detector), find_employees(), check_emails() et
    analyze_email_security() en un unique ScanResult validé.

    Chaque paramètre est optionnel : si un module n'a pas encore tourné,
    on construit un ScanResult partiel (utile pour du scan incrémental
    ou pour tester un module isolément).
    """
    subdomains = []
    if subdomain_scan:
        subdomains = [
            SubdomainInfo(subdomain=e["subdomain"], ips=e.get("ips", []))
            for e in subdomain_scan.get("active_subdomains", [])
        ]

    technologies = []
    if tech_scans:
        technologies = [
            SubdomainTechnologies(
                domain=entry["domain"],
                technologies=[TechnologyInfo(**t) for t in entry.get("technologies", [])],
            )
            for entry in tech_scans
        ]

    employees = []
    if employee_scan:
        employees = [EmployeeInfo(**e) for e in employee_scan.get("employees", [])]

    leaks = []
    if leak_results:
        leaks = [LeakInfo(**l) for l in leak_results]

    email_security = None
    if email_security_scan:
        email_security = EmailSecurityInfo(
            spf=SpfInfo(**email_security_scan["spf"]),
            dmarc=DmarcInfo(**email_security_scan["dmarc"]),
            dkim=DkimInfo(**email_security_scan["dkim"]),
            email_format=EmailFormatInfo(**email_security_scan["email_format"]),
        )

    takeover_candidates = []
    if takeover_scan:
        takeover_candidates = [TakeoverCandidate(**c) for c in takeover_scan.get("candidates", [])]

    environment_candidates = []
    if environment_scan:
        environment_candidates = [EnvironmentCandidate(**c) for c in environment_scan.get("candidates", [])]

    return ScanResult(
        domain=domain,
        subdomains=subdomains,
        technologies=technologies,
        employees=employees,
        leaks=leaks,
        email_security=email_security,
        takeover_candidates=takeover_candidates,
        environment_candidates=environment_candidates,
    )


# --------------------------------------------------------------------------
# Démo / test CLI
# --------------------------------------------------------------------------
def _fake_module_outputs() -> dict:
    """Simule les sorties des 4 modules pour tester l'agrégation sans réseau."""
    return {
        "subdomain_scan": {
            "domain": "example.com",
            "active_subdomains": [
                {"subdomain": "www.example.com", "ips": ["93.184.216.34"]},
                {"subdomain": "mail.example.com", "ips": ["93.184.216.35"]},
            ],
        },
        "tech_scans": [
            {
                "domain": "www.example.com",
                "technologies": [
                    {"name": "Nginx", "version": None, "category": "Web Server", "source": "whatweb"},
                    {"name": "WordPress", "version": "6.4", "category": "CMS", "source": "both"},
                ],
            },
        ],
        "employee_scan": {
            "domain": "example.com",
            "emails": ["john.doe@example.com"],
            "employees": [
                {"name": "John Doe", "email": "john.doe@example.com", "confidence": "medium"},
            ],
        },
        "leak_results": [
            {
                "email": "john.doe@example.com",
                "leaked": True,
                "sources": [
                    {"source": "Adobe", "breach_date": None, "password_masked": None, "fields_exposed": []},
                ],
                "errors": None,
            },
        ],
        "email_security_scan": {
            "domain": "example.com",
            "spf": {"present": True, "record": "v=spf1 include:_spf.google.com ~all",
                    "qualifier": "~all", "risk": "low", "detail": "SPF souple (~all) : protection correcte."},
            "dmarc": {"present": True, "record": "v=DMARC1; p=none", "policy": "none", "pct": "100",
                      "risk": "high", "detail": "Politique DMARC en mode surveillance uniquement (p=none)."},
            "dkim": {"detected": False, "selectors_found": [], "confidence": "unknown",
                     "detail": "Aucun DKIM trouvé parmi les sélecteurs courants testés."},
            "email_format": {"format": "prenom.nom", "confidence": 100, "sample_size": 1,
                              "detail": "Format dominant : 'prenom.nom' (1/1 employés analysés)."},
        },
        "takeover_scan": {
            "domain": "example.com",
            "total_checked": 2,
            "truncated": False,
            "candidates": [
                {"subdomain": "old.example.com", "cname": "deleted-bucket.s3.amazonaws.com",
                 "service": "AWS S3", "confidence": "high", "method": "dangling_cname",
                 "fingerprint_matched": None,
                 "detail": "Le CNAME pointe vers une cible qui ne résout plus (NXDOMAIN)."},
            ],
        },
        "environment_scan": {
            "total_checked": 2,
            "candidates": [
                {"subdomain": "staging.example.com", "category": "non_prod",
                 "matched_keyword": "staging", "risk": "medium",
                 "detail": "Le nom contient 'staging', évocateur d'un environnement hors-prod."},
            ],
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Modèle ScanResult — démo d'agrégation")
    parser.add_argument("--demo", action="store_true", help="Lance une démo avec données factices")
    args = parser.parse_args()

    if not args.demo:
        print("Utilise --demo pour voir un exemple d'agrégation.")
        return

    fake = _fake_module_outputs()
    result = build_scan_result(domain="example.com", **fake)

    print("=== ScanResult complet (JSON) ===")
    print(result.to_json())

    print("\n=== Résumé ===")
    print(json.dumps(result.summary(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
