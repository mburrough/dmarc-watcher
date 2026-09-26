"""Config loading. Secrets live in Windows Credential Manager, not on disk."""

from __future__ import annotations

import codecs
import os
import tomllib
from pathlib import Path

KEYRING_SERVICE = "dmarc-watcher"

DEFAULTS: dict = {
    "general": {
        "domain": "",
        "poll_minutes": 60,
        "summary_days": 30,
        "notify_on_clean": False,
        "stale_days": 10,
        "retain_days": 0,
        "startup_grace_minutes": 10,
        "retry_seconds": 30,
    },
    "source": {"mode": "imap"},
    "imap": {
        "host": "127.0.0.1",
        "port": 1143,
        "user": "",
        "folder": "Folders/DMARC",
        "security": "starttls",
        "verify_cert": False,
        "mark_read": "never",
    },
    "folder": {"path": ""},
}


def app_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "dmarc-watcher"


def config_path() -> Path:
    override = os.environ.get("DMARC_WATCHER_CONFIG")
    if override:
        return Path(override)
    local = Path(__file__).resolve().parent.parent / "config.toml"
    if local.is_file():
        return local
    return app_dir() / "config.toml"


def db_path() -> Path:
    return app_dir() / "reports.db"


def log_path() -> Path:
    return app_dir() / "dmarc-watcher.log"


def _merge(base: dict, over: dict) -> dict:
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _read_toml(path: Path) -> dict:
    """Parse a TOML file, tolerating a UTF-8 BOM.

    TOML forbids a BOM and tomllib rejects one outright, but Notepad and
    PowerShell's `Set-Content -Encoding utf8` both write one -- so a config
    saved with either would otherwise fail to load at all.
    """
    data = path.read_bytes()
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8):]
    return tomllib.loads(data.decode("utf-8"))


def load_config() -> dict:
    path = config_path()
    raw: dict = {}
    if path.is_file():
        raw = _read_toml(path)
    cfg = _merge(DEFAULTS, raw)
    cfg["_config_path"] = str(path)
    cfg["imap"]["_password"] = get_password(cfg["imap"].get("user", ""))
    return cfg


def get_password(user: str) -> str:
    """Password resolution order: env var, then Credential Manager.

    The env var exists for headless testing; normal use stores the Bridge
    password in Credential Manager so it never lands in a config file.
    """
    env = os.environ.get("DMARC_IMAP_PASSWORD")
    if env:
        return env
    if not user:
        return ""
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, user) or ""
    except Exception:
        return ""


def set_password(user: str, password: str) -> None:
    import keyring
    keyring.set_password(KEYRING_SERVICE, user, password)
