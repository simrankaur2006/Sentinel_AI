"""FastAPI application entrypoint.  Run from backend/:  uvicorn app.main:app --host 127.0.0.1 --port 8000"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError

from app import __version__
from app.api import routes_alerts, routes_core
from app.core.config import ConfigError, get_settings

log = logging.getLogger("sentinelai")


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = FastAPI(title="SentinelAI", version=__version__,
                  description="AI-assisted SOC copilot (local demo mode: no authentication; use synthetic or authorised data only).")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "PATCH"], allow_headers=["Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # noqa: ANN001
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.exception_handler(OperationalError)
    async def db_down(_: Request, exc: OperationalError) -> JSONResponse:
        log.error("database error: %s", type(exc).__name__)
        return JSONResponse(status_code=503, content={"detail": "Database unavailable. Check DATABASE_URL and that PostgreSQL is running."})

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")  # stack trace stays in the server log, never in the response
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    app.include_router(routes_core.router, prefix="/api")
    app.include_router(routes_alerts.router, prefix="/api")
    return app


try:
    app = create_app()
except ConfigError as exc:  # clear message instead of an obscure import traceback
    raise SystemExit(f"Configuration error: {exc}")
