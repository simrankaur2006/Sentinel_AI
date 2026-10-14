"""Health, ingestion, events, dashboard and AI status routes."""
from __future__ import annotations

from datetime import datetime  # noqa: F401

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import __version__
from app.ai.ollama import check_status
from app.api.deps import Pager, like_escape, parse_dt, settings_dep
from app.core.config import Settings
from app.db.models import IngestionBatch, SecurityEvent
from app.db.session import get_db
from app.ingestion.parser import IngestionError
from app.schemas.api import HealthOut, Page
from app.services import ingest as ingest_svc
from app.services.dashboard import build_dashboard
from app.services.incident_service import ollama_cfg
from app.services.serializers import event_to_dict

router = APIRouter()


@router.get("/health", response_model=HealthOut, tags=["system"])
def health(db: Session = Depends(get_db)) -> HealthOut:
    try:
        db.execute(text("SELECT 1"))
        return HealthOut(status="ok", version=__version__, database="ok")
    except Exception:  # noqa: BLE001 - report, never leak connection details
        return HealthOut(status="degraded", version=__version__, database="unavailable", detail="Database connection failed.")


@router.get("/system/info", tags=["system"])
def system_info(s: Settings = Depends(settings_dep), db: Session = Depends(get_db)) -> dict:
    return {
        "version": __version__, "mode": "local-demo (no authentication)",
        "database_dialect": db.get_bind().dialect.name,
        "limits": {"max_upload_bytes": s.max_upload_bytes, "max_upload_rows": s.max_upload_rows},
        "ai": {"default_provider": s.ai_provider, "ollama_model": s.ollama_model, "ollama_base_url": s.ollama_base_url},
        "cors_origins": s.cors_origins,
        "counts": {"events": db.scalar(select(func.count()).select_from(SecurityEvent)) or 0},
        "limitations": [
            "No authentication: bind to localhost only and use synthetic or authorised data.",
            "Detections are leads, not proof of compromise.",
            "ML anomaly scores are relative to the uploaded data and are not probabilities; no accuracy metrics are computed.",
            "MITRE ATT&CK associations are hypotheses.",
        ],
    }


@router.get("/ai/status", tags=["ai"])
def ai_status(s: Settings = Depends(settings_dep)) -> dict:
    return {"default_provider": s.ai_provider, "fallback": {"available": True}, "ollama": check_status(ollama_cfg(s))}


# ------------------------------------------------------------------ ingestion
@router.get("/ingest/samples", tags=["ingestion"])
def list_samples() -> list[dict]:
    return [{"id": k, **{x: v[x] for x in ("title", "description")}} for k, v in ingest_svc.SAMPLES.items()]


@router.post("/ingest/sample/{sample_id}", status_code=201, tags=["ingestion"])
def load_sample(sample_id: str, db: Session = Depends(get_db), s: Settings = Depends(settings_dep)) -> dict:
    try:
        return ingest_svc.ingest_sample(db, sample_id, s)
    except KeyError:
        raise HTTPException(404, "Unknown sample dataset.")
    except ingest_svc.DuplicateIngestionConflict as exc:
        raise HTTPException(409, str(exc))


@router.post("/ingest/upload", status_code=201, tags=["ingestion"])
async def upload(file: UploadFile = File(...), db: Session = Depends(get_db), s: Settings = Depends(settings_dep)) -> dict:
    content = await file.read(s.max_upload_bytes + 1)  # never read more than limit+1 bytes
    if len(content) > s.max_upload_bytes:
        raise HTTPException(413, f"File is too large. Limit is {s.max_upload_bytes} bytes.")
    try:
        return ingest_svc.ingest_bytes(db, file.filename or "upload", content, s)
    except IngestionError as exc:
        raise HTTPException(422, str(exc))
    except ingest_svc.DuplicateIngestionConflict as exc:
        raise HTTPException(409, str(exc))


@router.get("/ingest/batches", tags=["ingestion"])
def batches(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(IngestionBatch).order_by(IngestionBatch.id.desc()).limit(50)).all()
    return [ingest_svc.batch_to_dict(b) for b in rows]


# ------------------------------------------------------------------ events
_EVENT_SORT = {"timestamp": SecurityEvent.timestamp, "source_ip": SecurityEvent.source_ip, "username": SecurityEvent.username,
               "event_type": SecurityEvent.event_type, "status": SecurityEvent.status, "bytes_sent": SecurityEvent.bytes_sent}


@router.get("/events", response_model=Page, tags=["events"])
def list_events(p: Pager = Depends(), db: Session = Depends(get_db), q: str | None = Query(None, max_length=200),
                source_ip: str | None = None, destination_ip: str | None = None, username: str | None = None,
                event_type: str | None = None, status: str | None = None, source: str | None = None,
                start: str | None = None, end: str | None = None, sort: str = "timestamp", order: str = "desc") -> Page:
    if sort not in _EVENT_SORT or order not in {"asc", "desc"}:
        raise HTTPException(422, "Invalid sort or order.")
    conds = []
    for col, val in ((SecurityEvent.source_ip, source_ip), (SecurityEvent.destination_ip, destination_ip), (SecurityEvent.username, username),
                     (SecurityEvent.event_type, event_type), (SecurityEvent.status, status), (SecurityEvent.source, source)):
        if val:
            conds.append(col == val)
    if q:
        pat = f"%{like_escape(q)}%"
        conds.append(SecurityEvent.message.ilike(pat, escape="\\") | SecurityEvent.username.ilike(pat, escape="\\")
                     | SecurityEvent.source_ip.ilike(pat, escape="\\") | SecurityEvent.destination_ip.ilike(pat, escape="\\"))
    if (s := parse_dt(start, "start")):
        conds.append(SecurityEvent.timestamp >= s)
    if (e := parse_dt(end, "end")):
        conds.append(SecurityEvent.timestamp <= e)
    total = db.scalar(select(func.count()).select_from(SecurityEvent).where(*conds)) or 0
    col = _EVENT_SORT[sort]
    rows = db.scalars(select(SecurityEvent).where(*conds).order_by(col.desc() if order == "desc" else col.asc(), SecurityEvent.id.desc())
                      .offset(p.offset).limit(p.page_size)).all()
    return Page(items=[event_to_dict(r) for r in rows], total=total, page=p.page, page_size=p.page_size)


@router.get("/events/{event_pk}", tags=["events"])
def get_event(event_pk: int, db: Session = Depends(get_db)) -> dict:
    row = db.get(SecurityEvent, event_pk)
    if row is None:
        raise HTTPException(404, "Event not found.")
    return event_to_dict(row)


# ------------------------------------------------------------------ dashboard
@router.get("/dashboard/metrics", tags=["dashboard"])
def dashboard(db: Session = Depends(get_db), start: str | None = None, end: str | None = None) -> dict:
    return build_dashboard(db, parse_dt(start, "start"), parse_dt(end, "end"))
