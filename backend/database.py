"""
database.py
Configuration SQLite (SQLAlchemy) pour le suivi des scans OSINT.

Une seule table : scan_jobs, qui stocke l'état de chaque scan lancé
via POST /scan (statut, progression, domaine, timestamps) ainsi que
le résultat final sérialisé en JSON une fois le scan terminé.

Usage :
    from database import init_db, SessionLocal, ScanJob
    init_db()  # à appeler une fois au démarrage de l'app (voir app.py)
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./scans.db"

engine = create_engine(
    DATABASE_URL,
    # SQLite n'autorise par défaut qu'un seul thread par connexion —
    # FastAPI + BackgroundTasks utilisent plusieurs threads, donc on
    # désactive cette vérification. Chaque requête/tâche ouvre de toute
    # façon sa propre session (voir SessionLocal ci-dessous), donc pas
    # de partage de connexion concurrent.
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanJob(Base):
    """
    Représente un scan OSINT en cours ou terminé.

    status      : "pending" | "running" | "done" | "failed"
    progress    : texte libre décrivant l'étape en cours (ex: "2/4 - Technologies")
    result_json : ScanResult sérialisé (JSON), rempli seulement si status == "done"
    error       : message d'erreur, rempli seulement si status == "failed"
    """
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, index=True)  # UUID4
    domain = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="pending")
    progress = Column(String, nullable=True)
    provider = Column(String, nullable=False, default="xposedornot")
    tech_engine = Column(String, nullable=False, default="both")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    result_json = Column(Text, nullable=True)
    error = Column(Text, nullable=True)


def init_db() -> None:
    """Crée les tables si elles n'existent pas encore. Idempotent — safe à
    appeler à chaque démarrage du serveur."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """
    Dependency FastAPI (optionnelle, utile si tu préfères l'injection de
    dépendances à l'ouverture manuelle de session) : fournit une session
    par requête, la ferme automatiquement ensuite.

        @app.get("/exemple")
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
