"""Persist parsed events with duplicate handling."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import BACKEND_DIR, Settings
from app.db.models import IngestionBatch, SecurityEvent
from app.ingestion.parser import parse_upload

SAMPLE_DIR = BACKEND_DIR / "sample_data"
# Allow-list: the API never accepts a path from the client, only one of these identifiers.
SAMPLES: dict[str, dict[str, str]] = {
    "security-logs-csv": {"file": "sample_security_logs.csv", "title": "Synthetic security logs (CSV, 270 events)",
                          "description": "Baseline activity plus brute force, spray, scan, exfiltration, watchlist, unusual-auth and ML-outlier scenarios."},
    "windows-auth-jsonl": {"file": "sample_windows_auth.jsonl", "title": "Synthetic Windows-style authentication (JSONL, 12 events)",
                           "description": "Different field names/event codes; brute force then success. Too small for ML, so ML is skipped gracefully."},
}
_CHUNK = 2000


class DuplicateIngestionConflict(RuntimeError):
    pass


def ingest_bytes(db: Session, filename: str, content: bytes, settings: Settings) -> dict[str, Any]:
    res = parse_upload(filename, content, max_bytes=settings.max_upload_bytes, max_rows=settings.max_upload_rows)
    fps = [e["fingerprint"] for e in res.events]
    existing: set[str] = set()
    for i in range(0, len(fps), _CHUNK):
        existing.update(db.scalars(select(SecurityEvent.fingerprint).where(SecurityEvent.fingerprint.in_(fps[i:i + _CHUNK]))))
    new_events = [e for e in res.events if e["fingerprint"] not in existing]
    batch = IngestionBatch(filename=filename[:255], file_format=res.file_format, rows_total=res.rows_total,
                           rows_imported=len(new_events), rows_duplicate=len(res.events) - len(new_events),
                           rows_invalid=res.rows_invalid, warnings=res.warnings, errors=res.errors)
    try:
        db.add(batch)
        db.flush()
        for i in range(0, len(new_events), _CHUNK):
            db.execute(insert(SecurityEvent), [{**e, "batch_id": batch.id} for e in new_events[i:i + _CHUNK]])
        db.commit()
    except IntegrityError as exc:  # concurrent upload of the same data
        db.rollback()
        raise DuplicateIngestionConflict("These events were being imported concurrently; retry the upload.") from exc
    return batch_to_dict(batch)


def ingest_sample(db: Session, sample_id: str, settings: Settings) -> dict[str, Any]:
    meta = SAMPLES.get(sample_id)
    if meta is None:
        raise KeyError(sample_id)
    path: Path = SAMPLE_DIR / meta["file"]
    return ingest_bytes(db, meta["file"], path.read_bytes(), settings)


def batch_to_dict(b: IngestionBatch) -> dict[str, Any]:
    return {"id": b.id, "filename": b.filename, "file_format": b.file_format, "rows_total": b.rows_total,
            "rows_imported": b.rows_imported, "rows_duplicate": b.rows_duplicate, "rows_invalid": b.rows_invalid,
            "warnings": b.warnings, "errors": b.errors or [], "created_at": b.created_at.isoformat() if b.created_at else None}
