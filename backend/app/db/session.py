"""Engine/session management. The engine is created lazily from DATABASE_URL."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def _make_engine(url: str, echo: bool = False) -> Engine:
    if url.startswith("sqlite"):  # test/dev convenience only; PostgreSQL is the supported database
        kwargs = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url.rstrip("/") == "sqlite:":
            kwargs["poolclass"] = StaticPool
        eng = create_engine(url, echo=echo, **kwargs)

        @event.listens_for(eng, "connect")
        def _fk_on(dbapi_conn, _):  # noqa: ANN001
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
        return eng
    return create_engine(url, echo=echo, pool_pre_ping=True, pool_size=5, max_overflow=5)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        s = get_settings()
        _engine = _make_engine(s.database_url, s.sql_echo)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _factory
    if _factory is None:
        _factory = sessionmaker(bind=get_engine(), expire_on_commit=False, autoflush=False)
    return _factory


def get_db() -> Iterator[Session]:
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def dispose_engine() -> None:
    """Used by tests to point the app at a fresh database."""
    global _engine, _factory
    if _engine is not None:
        _engine.dispose()
    _engine, _factory = None, None
