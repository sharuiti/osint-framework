"""
config_loader.py
Chargement centralisé des clés API et paramètres du framework.

Ordre de priorité (du plus fort au plus faible) :
    1. Variable d'environnement  (ex: export LEAKCHECK_API_KEY="...")
    2. config/api_keys.yaml      (fichier local, JAMAIS commité)
    3. Valeur par défaut          (None pour les clés, valeur codée pour les réglages)

Pourquoi cet ordre ?
L'environnement gagne toujours, ce qui permet de surcharger la config
en prod/CI sans toucher au fichier, et évite qu'un fichier oublié sur
disque prenne le pas sur une clé injectée volontairement. Le YAML sert
de confort en développement local, pour ne pas avoir à réexporter ses
clés à chaque nouveau terminal.

SÉCURITÉ :
- config/api_keys.yaml doit être dans .gitignore (il l'est par défaut).
- Les clés ne sont jamais journalisées ; mask_key() sert à l'affichage
  de diagnostic (ex: "sk-a***9f2") sans révéler le secret.

Usage :
    from config_loader import get_config

    cfg = get_config()
    cfg.leakcheck_api_key   # str | None
    cfg.default_provider    # "xposedornot"
    cfg.max_tech_targets    # 40
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

# config/ est un dossier frère de backend/, à la racine du projet.
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "api_keys.yaml"


def mask_key(value: Optional[str]) -> str:
    """
    Masque une clé pour affichage de diagnostic. Ne JAMAIS afficher une
    clé en clair, même dans un log local — un log finit souvent copié
    dans un ticket, un screenshot ou un dépôt.
    """
    if not value:
        return "(non définie)"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}***{value[-3:]}"


@dataclass
class Config:
    """Configuration résolue du framework."""

    # Clés API — toutes optionnelles, le framework fonctionne sans.
    leakcheck_api_key: Optional[str] = None
    hibp_api_key: Optional[str] = None
    hunter_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None

    # Réglages de scan
    default_provider: str = "xposedornot"
    default_tech_engine: str = "both"
    max_tech_targets: int = 40
    theharvester_sources: str = "baidu,bing,crtsh,duckduckgo,google,yahoo"
    theharvester_timeout: int = 120
    crtsh_timeout: int = 30

    # Rétention
    keep_scan_history: bool = True
    max_history_entries: int = 200

    # Champs internes de diagnostic
    _source_map: dict = field(default_factory=dict, repr=False)

    def describe(self) -> str:
        """Résumé lisible de la config résolue, sans révéler les secrets."""
        lines = ["Configuration résolue :"]
        for key in ("leakcheck_api_key", "hibp_api_key", "hunter_api_key",
                    "securitytrails_api_key", "shodan_api_key"):
            origin = self._source_map.get(key, "défaut")
            lines.append(f"  {key:26s} = {mask_key(getattr(self, key)):18s} [{origin}]")
        for key in ("default_provider", "default_tech_engine", "max_tech_targets",
                    "theharvester_sources", "theharvester_timeout", "crtsh_timeout",
                    "keep_scan_history", "max_history_entries"):
            origin = self._source_map.get(key, "défaut")
            lines.append(f"  {key:26s} = {str(getattr(self, key)):18s} [{origin}]")
        return "\n".join(lines)


# Correspondance champ de config -> nom de variable d'environnement.
ENV_MAP = {
    "leakcheck_api_key": "LEAKCHECK_API_KEY",
    "hibp_api_key": "HIBP_API_KEY",
    "hunter_api_key": "HUNTER_API_KEY",
    "securitytrails_api_key": "SECURITYTRAILS_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "default_provider": "OSINT_DEFAULT_PROVIDER",
    "default_tech_engine": "OSINT_DEFAULT_TECH_ENGINE",
    "max_tech_targets": "OSINT_MAX_TECH_TARGETS",
    "theharvester_sources": "OSINT_THEHARVESTER_SOURCES",
    "theharvester_timeout": "OSINT_THEHARVESTER_TIMEOUT",
    "crtsh_timeout": "OSINT_CRTSH_TIMEOUT",
    "keep_scan_history": "OSINT_KEEP_SCAN_HISTORY",
    "max_history_entries": "OSINT_MAX_HISTORY_ENTRIES",
}

INT_FIELDS = {"max_tech_targets", "theharvester_timeout", "crtsh_timeout", "max_history_entries"}
BOOL_FIELDS = {"keep_scan_history"}


def _coerce(field_name: str, raw: Any) -> Any:
    """Convertit une valeur brute (str d'env ou scalaire YAML) vers le bon type."""
    if raw is None:
        return None
    if field_name in INT_FIELDS:
        try:
            return int(raw)
        except (TypeError, ValueError):
            print(f"[!] Valeur non entière pour {field_name} : {raw!r} — ignorée.",
                  file=sys.stderr)
            return None
    if field_name in BOOL_FIELDS:
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on", "oui")
    return str(raw)


def _load_yaml(path: Path) -> dict:
    """Charge le YAML de config s'il existe. Un fichier absent n'est pas une erreur."""
    if not path.exists():
        return {}
    if yaml is None:
        print("[!] PyYAML absent — config/api_keys.yaml ignoré. "
              "Installe avec : pip install pyyaml", file=sys.stderr)
        return {}

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        print(f"[!] config/api_keys.yaml illisible ({exc}) — fichier ignoré.", file=sys.stderr)
        return {}

    if not isinstance(data, dict):
        print("[!] config/api_keys.yaml doit contenir un mapping clé: valeur — ignoré.",
              file=sys.stderr)
        return {}

    # Le YAML peut regrouper les clés sous "api_keys:" et les réglages
    # sous "scan:" — on aplatit les deux niveaux pour simplifier.
    flat = {}
    for key, value in data.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


def get_config(config_path: Optional[Path] = None) -> Config:
    """
    Résout la configuration complète. Appelable à volonté (pas de cache),
    ce qui permet de recharger après modification du YAML sans redémarrer
    l'interpréteur en développement.
    """
    path = config_path or CONFIG_PATH
    yaml_data = _load_yaml(path)

    cfg = Config()
    source_map = {}

    for field_name, env_name in ENV_MAP.items():
        value, origin = None, "défaut"

        if yaml_data.get(field_name) is not None:
            value, origin = _coerce(field_name, yaml_data[field_name]), "yaml"

        # L'environnement écrase toujours le YAML.
        env_raw = os.environ.get(env_name)
        if env_raw not in (None, ""):
            coerced = _coerce(field_name, env_raw)
            if coerced is not None:
                value, origin = coerced, "env"

        if value is not None:
            setattr(cfg, field_name, value)
            source_map[field_name] = origin

    cfg._source_map = source_map
    return cfg


if __name__ == "__main__":
    print(get_config().describe())
