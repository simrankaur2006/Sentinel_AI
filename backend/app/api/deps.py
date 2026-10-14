from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException, Query

from app.core.config import Settings, get_settings
from app.domain import ensure_utc


def settings_dep() -> Settings:
    return get_settings()


def parse_dt(value: str | None, name: str) -> datetime | None:
    if not value:
        return None
    try:
        return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{name} must be an ISO-8601 date or datetime.") from exc


def like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Pager:
    def __init__(self, page: int = Query(1, ge=1, le=100000), page_size: int = Query(50, ge=1, le=200)):
        self.page, self.page_size = page, page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size
