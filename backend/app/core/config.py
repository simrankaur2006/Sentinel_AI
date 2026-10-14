"""Application settings, read from environment variables (and an optional backend/.env file).

No credentials are hardcoded. DATABASE_URL is mandatory and has no default on purpose.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BACKEND_DIR / ".env")


class ConfigError(RuntimeError):
    pass


def _csv(value: str | None, default: list[str]) -> list[str]:
    if not value:
        return default
    return [v.strip() for v in value.split(",") if v.strip()]


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    cors_origins: list[str]
    max_upload_bytes: int
    max_upload_rows: int
    ai_provider: str  # "fallback" (default) or "ollama"
    ollama_base_url: str
    ollama_model: str
    ollama_timeout_seconds: float
    ollama_allow_remote: bool
    ai_max_events_per_alert: int
    ai_max_alerts: int
    log_level: str
    sql_echo: bool


def load_settings() -> Settings:
    db_url = os.environ.get("DATABASE_URL", "").strip()
    if not db_url:
        raise ConfigError(
            "DATABASE_URL is not set. Copy backend/.env.example to backend/.env and set it "
            "(see README: PostgreSQL setup)."
        )
    provider = os.environ.get("AI_PROVIDER", "fallback").strip().lower()
    if provider not in {"fallback", "ollama"}:
        raise ConfigError("AI_PROVIDER must be 'fallback' or 'ollama'.")
    return Settings(
        database_url=db_url,
        cors_origins=_csv(os.environ.get("CORS_ORIGINS"), ["http://localhost:5173", "http://127.0.0.1:5173"]),
        max_upload_bytes=int(float(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024),
        max_upload_rows=int(os.environ.get("MAX_UPLOAD_ROWS", "50000")),
        ai_provider=provider,
        ollama_base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "llama3.1:8b"),
        ollama_timeout_seconds=float(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "60")),
        ollama_allow_remote=_bool(os.environ.get("OLLAMA_ALLOW_REMOTE"), False),
        ai_max_events_per_alert=int(os.environ.get("AI_MAX_EVENTS_PER_ALERT", "15")),
        ai_max_alerts=int(os.environ.get("AI_MAX_ALERTS", "12")),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        sql_echo=_bool(os.environ.get("SQL_ECHO"), False),
    )


@lru_cache
def get_settings() -> Settings:
    return load_settings()
