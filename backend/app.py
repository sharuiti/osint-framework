"""
app.py
API FastAPI du framework OSINT — Étape 5.

Expose 3 endpoints :
    POST /scan                 -> démarre un scan en tâche de fond, renvoie un id
    GET  /scan/{id}/status     -> statut + progression du scan
    GET  /scan/{id}/results    -> résultat complet (ScanResult JSON), une fois "done"

Pourquoi une tâche de fond (BackgroundTasks) ?
Un scan complet (sous-domaines + technos + employés + fuites) peut
prendre plusieurs minutes. Si POST /scan attendait la fin du pipeline
avant de répondre, la requête HTTP resterait bloquée tout ce temps —
inutilisable pour un frontend qui veut afficher une progression. À la
place : POST /scan crée une ligne en base avec le statut "pending",
lance le pipeline en arrière-plan, et répond IMMÉDIATEMENT avec un id.
Le frontend interroge ensuite /status en polling (toutes les 2-3s par
exemple) pour savoir quand aller chercher /results.

SÉCURITÉ : les clés API (LEAKCHECK_API_KEY, HIBP_API_KEY) sont lues
côté serveur depuis l'environnement — jamais transmises par le client
dans le corps de la requête. Voir config/api_keys.yaml (étape 9) pour
la gestion propre en prod.

Lancer le serveur (depuis backend/) :
    uvicorn app:app --reload

Ou depuis la racine du projet :
    uvicorn backend.app:app --reload --app-dir backend
"""

import json
import re
import shutil
import sys
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, field_validator

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config_loader import get_config, mask_key           # noqa: E402
from database import ScanJob, SessionLocal, init_db      # noqa: E402
from run_pipeline import run_pipeline                     # noqa: E402
from core.scoring_engine import apply_score                # noqa: E402
from models.scan_result import ScanResult                   # noqa: E402
from report.pdf_generator import generate_pdf               # noqa: E402

# Dossier de sortie des PDF générés à la demande. Écrit sur disque plutôt
# qu'en mémoire pour permettre le streaming via FileResponse sans tout
# charger en RAM ; purge automatique avec l'entrée d'historique associée.
REPORTS_DIR = Path(__file__).resolve().parent / "generated_reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Outils externes attendus. Leur absence n'empêche pas le démarrage —
# le pipeline dégrade gracieusement — mais on le signale explicitement
# au lancement plutôt que de laisser l'utilisateur découvrir des
# résultats vides sans comprendre pourquoi.
EXTERNAL_TOOLS = {
    "sublist3r": "sudo apt install sublist3r",
    "theHarvester": "sudo apt install theharvester",
    "whatweb": "sudo apt install whatweb",
}

# Validation basique de nom de domaine — évite de lancer un pipeline
# complet (subprocess, requêtes réseau) sur une entrée manifestement
# invalide. Les modules sous-jacents passent le domaine en argument de
# liste à subprocess (pas de shell=True) donc pas d'injection shell
# possible, mais autant filtrer tôt et donner un message clair.
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)


def _check_external_tools() -> dict[str, bool]:
    """Vérifie la présence des binaires externes dans le PATH."""
    found = {}
    for tool, install_hint in EXTERNAL_TOOLS.items():
        # theHarvester s'installe parfois en minuscules selon la distro.
        present = bool(shutil.which(tool) or shutil.which(tool.lower()))
        found[tool] = present
        if not present:
            print(f"[!] Outil externe absent : {tool} — installe-le avec `{install_hint}`. "
                  f"Le scan continuera sans lui, avec des résultats partiels.", file=sys.stderr)
    return found


def _purge_old_scans(max_entries: int) -> int:
    """
    Supprime les scans les plus anciens au-delà de max_entries, ainsi
    que leurs rapports PDF. Retourne le nombre d'entrées purgées.
    """
    db = SessionLocal()
    try:
        total = db.query(ScanJob).count()
        if total <= max_entries:
            return 0

        surplus = (
            db.query(ScanJob)
            .order_by(ScanJob.created_at.asc())
            .limit(total - max_entries)
            .all()
        )
        for job in surplus:
            pdf = REPORTS_DIR / f"{job.id}.pdf"
            pdf.unlink(missing_ok=True)
            db.delete(job)
        db.commit()
        return len(surplus)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pattern "lifespan" recommandé par FastAPI — remplace le décorateur
    # @app.on_event("startup") qui est deprecated et, selon le serveur
    # ASGI ou le contexte de test utilisé, peut ne pas se déclencher de
    # façon fiable (ex: TestClient sans context manager `with`).
    init_db()

    cfg = get_config()
    app.state.config = cfg
    app.state.tools = _check_external_tools()

    print(f"[*] Provider fuites par défaut : {cfg.default_provider}", file=sys.stderr)
    print(f"[*] Limite cibles technos      : {cfg.max_tech_targets}", file=sys.stderr)
    print(f"[*] Clé LeakCheck              : {mask_key(cfg.leakcheck_api_key)}", file=sys.stderr)
    print(f"[*] Clé HIBP                   : {mask_key(cfg.hibp_api_key)}", file=sys.stderr)

    if cfg.keep_scan_history:
        purged = _purge_old_scans(cfg.max_history_entries)
        if purged:
            print(f"[*] {purged} ancien(s) scan(s) purgé(s) "
                  f"(limite: {cfg.max_history_entries}).", file=sys.stderr)

    yield


app = FastAPI(title="OSINT Framework API", version="0.9.0", lifespan=lifespan)

# Le frontend (étape 7) tournera sur une origine différente (fichier
# statique local ou petit serveur dev) — CORS ouvert ici pour le dev,
# à restreindre à une origine précise avant toute mise en prod.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    """
    Filet de sécurité : toute exception non gérée renvoie un JSON propre
    plutôt qu'une trace HTML illisible côté frontend. La trace complète
    reste imprimée côté serveur pour le debug.
    """
    import traceback
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"detail": f"Erreur serveur inattendue : {type(exc).__name__}. "
                            f"Consulte les logs du backend pour la trace complète."},
    )


# --------------------------------------------------------------------------
# Schémas Pydantic
# --------------------------------------------------------------------------
class ScanRequest(BaseModel):
    domain: str
    # None = utiliser la valeur par défaut de la config serveur.
    provider: Optional[Literal["leakcheck", "hibp", "xposedornot", "both"]] = None
    tech_engine: Optional[Literal["whatweb", "lite", "both"]] = None

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not DOMAIN_REGEX.match(v):
            raise ValueError("Format de domaine invalide (attendu, ex: example.com)")
        return v


class ScanCreateResponse(BaseModel):
    id: str
    status: str


class ScanStatusResponse(BaseModel):
    id: str
    domain: str
    status: str
    progress: Optional[str] = None
    error: Optional[str] = None


class ScanHistoryEntry(BaseModel):
    """Une ligne d'historique — volontairement légère (pas le JSON complet)."""
    id: str
    domain: str
    status: str
    provider: str
    tech_engine: str
    created_at: Optional[str] = None
    score: Optional[float] = None
    band: Optional[str] = None
    error: Optional[str] = None


class ScanHistoryResponse(BaseModel):
    total: int
    entries: list[ScanHistoryEntry]


class HealthResponse(BaseModel):
    status: str
    version: str
    tools: dict[str, bool]
    default_provider: str
    max_tech_targets: int
    api_keys_configured: dict[str, bool]


# --------------------------------------------------------------------------
# Tâche de fond
# --------------------------------------------------------------------------
def _run_scan_job(job_id: str, domain: str, provider: str, tech_engine: str) -> None:
    """
    Exécute le pipeline complet et met à jour la ligne ScanJob correspondante
    au fur et à mesure. Chaque tâche de fond ouvre sa PROPRE session DB —
    une session SQLAlchemy n'est pas conçue pour être partagée entre
    threads/requêtes concurrentes.
    """
    cfg = get_config()
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()

    try:
        job.status = "running"
        db.commit()

        def _progress(step_text: str) -> None:
            job.progress = step_text
            db.commit()

        scan = run_pipeline(
            domain,
            provider=provider,
            tech_engine=tech_engine,
            leakcheck_key=cfg.leakcheck_api_key,
            hibp_key=cfg.hibp_api_key,
            hunter_key=cfg.hunter_api_key,
            max_tech_targets=None if cfg.max_tech_targets == 0 else cfg.max_tech_targets,
            progress_callback=_progress,
        )
        scan = apply_score(scan)

        job.status = "done"
        job.progress = "Terminé"
        job.result_json = scan.to_json()
        db.commit()

    except Exception as exc:  # noqa: BLE001 — on veut capturer TOUTE erreur du pipeline
        # La trace complète va dans les logs serveur ; seul un message
        # court remonte au client (pas de fuite de chemins internes).
        import traceback
        traceback.print_exc()
        db.rollback()
        job.status = "failed"
        job.error = f"{type(exc).__name__}: {exc}"
        db.commit()

    finally:
        db.close()


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------
@app.post("/scan", response_model=ScanCreateResponse, status_code=202)
def start_scan(payload: ScanRequest, background_tasks: BackgroundTasks):
    """
    Démarre un scan. Répond immédiatement (202 Accepted) avec un id —
    le scan continue en arrière-plan. Utiliser GET /scan/{id}/status
    pour suivre la progression.
    """
    cfg = get_config()
    provider = payload.provider or cfg.default_provider
    tech_engine = payload.tech_engine or cfg.default_tech_engine

    job_id = str(uuid.uuid4())

    db = SessionLocal()
    try:
        job = ScanJob(
            id=job_id,
            domain=payload.domain,
            status="pending",
            provider=provider,
            tech_engine=tech_engine,
        )
        db.add(job)
        db.commit()
    finally:
        db.close()

    background_tasks.add_task(
        _run_scan_job, job_id, payload.domain, provider, tech_engine
    )

    return ScanCreateResponse(id=job_id, status="pending")


@app.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(scan_id: str):
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan introuvable")
        return ScanStatusResponse(
            id=job.id, domain=job.domain, status=job.status,
            progress=job.progress, error=job.error,
        )
    finally:
        db.close()


@app.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan introuvable")

        if job.status == "failed":
            raise HTTPException(status_code=500, detail=f"Le scan a échoué : {job.error}")

        if job.status != "done":
            raise HTTPException(
                status_code=409,
                detail=f"Scan pas encore terminé (statut actuel : {job.status})",
            )

        return json.loads(job.result_json)
    finally:
        db.close()


@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str):
    """
    Génère (à la demande) et renvoie le rapport PDF du scan. Le PDF
    n'est pas pré-généré à la fin du pipeline : on ne construit un
    rapport que si quelqu'un le demande vraiment, pour éviter de
    payer le coût WeasyPrint sur chaque scan.
    """
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan introuvable")

        if job.status == "failed":
            raise HTTPException(status_code=500, detail=f"Le scan a échoué : {job.error}")

        if job.status != "done":
            raise HTTPException(
                status_code=409,
                detail=f"Scan pas encore terminé (statut actuel : {job.status})",
            )

        scan = ScanResult.model_validate(json.loads(job.result_json))

        pdf_path = REPORTS_DIR / f"{scan_id}.pdf"
        if not pdf_path.exists():
            generate_pdf(scan, str(pdf_path))

        safe_domain = job.domain.replace("/", "_")
        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=f"rapport_osint_{safe_domain}.pdf",
        )
    finally:
        db.close()


# --------------------------------------------------------------------------
# Étape 9 — santé, historique, suppression
# --------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse)
def health():
    """
    État du serveur : outils externes détectés, réglages actifs, et
    quelles clés API sont configurées (booléen uniquement — la valeur
    des clés n'est JAMAIS exposée via l'API).
    """
    cfg = get_config()
    return HealthResponse(
        status="ok",
        version=app.version,
        tools=getattr(app.state, "tools", _check_external_tools()),
        default_provider=cfg.default_provider,
        max_tech_targets=cfg.max_tech_targets,
        api_keys_configured={
            "leakcheck": bool(cfg.leakcheck_api_key),
            "hibp": bool(cfg.hibp_api_key),
            "hunter": bool(cfg.hunter_api_key),
            "securitytrails": bool(cfg.securitytrails_api_key),
            "shodan": bool(cfg.shodan_api_key),
        },
    )


@app.get("/scans", response_model=ScanHistoryResponse)
def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    domain: Optional[str] = Query(None, description="Filtre par domaine (correspondance partielle)"),
):
    """
    Historique des scans, du plus récent au plus ancien.

    On ne renvoie PAS le result_json complet ici — il peut peser
    plusieurs Mo sur un gros domaine, et une liste d'historique n'en a
    pas besoin. Le score est extrait à la volée pour l'affichage.
    """
    db = SessionLocal()
    try:
        query = db.query(ScanJob)
        if domain:
            query = query.filter(ScanJob.domain.like(f"%{domain.strip().lower()}%"))

        total = query.count()
        jobs = (
            query.order_by(ScanJob.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        entries = []
        for job in jobs:
            score, band = None, None
            if job.result_json:
                try:
                    data = json.loads(job.result_json)
                    score = data.get("score")
                    band = (data.get("score_details") or {}).get("band")
                except (ValueError, TypeError):
                    # Un JSON corrompu ne doit pas casser toute la liste.
                    pass

            entries.append(ScanHistoryEntry(
                id=job.id,
                domain=job.domain,
                status=job.status,
                provider=job.provider,
                tech_engine=job.tech_engine,
                created_at=job.created_at.isoformat() if job.created_at else None,
                score=score,
                band=band,
                error=job.error,
            ))

        return ScanHistoryResponse(total=total, entries=entries)
    finally:
        db.close()


@app.delete("/scan/{scan_id}", status_code=204)
def delete_scan(scan_id: str):
    """
    Supprime un scan et son rapport PDF associé. Utile pour purger des
    résultats contenant des données sensibles (emails, fuites) une fois
    le rapport livré au client.
    """
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan introuvable")

        (REPORTS_DIR / f"{scan_id}.pdf").unlink(missing_ok=True)
        db.delete(job)
        db.commit()
        return None
    finally:
        db.close()
