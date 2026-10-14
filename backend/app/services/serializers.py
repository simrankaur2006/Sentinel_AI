"""ORM -> plain dict conversion (the single source of truth for API/report/AI shapes)."""
from __future__ import annotations

from typing import Any

from app.db.models import Alert, Incident, SecurityEvent
from app.domain import Event, alert_ref, ensure_utc, event_ref


def iso(dt) -> str | None:  # noqa: ANN001
    d = ensure_utc(dt)
    return d.isoformat() if d else None


def incident_ref(incident_id: int) -> str:
    return f"INC-{incident_id:04d}"


def event_to_dict(e: SecurityEvent) -> dict[str, Any]:
    return {
        "id": e.id, "ref": event_ref(e.id), "event_id": e.event_id, "timestamp": iso(e.timestamp), "source": e.source,
        "source_ip": e.source_ip, "destination_ip": e.destination_ip, "username": e.username, "event_type": e.event_type,
        "action": e.action, "status": e.status, "protocol": e.protocol, "port": e.port, "bytes_sent": e.bytes_sent,
        "bytes_received": e.bytes_received, "message": e.message, "additional_metadata": e.additional_metadata or {},
        "batch_id": e.batch_id,
    }


def event_to_domain(e: SecurityEvent) -> Event:
    return Event(pk=e.id, fingerprint=e.fingerprint, event_id=e.event_id, timestamp=ensure_utc(e.timestamp), source=e.source,
                 source_ip=e.source_ip, destination_ip=e.destination_ip, username=e.username, event_type=e.event_type,
                 action=e.action, status=e.status, protocol=e.protocol, port=e.port, bytes_sent=e.bytes_sent,
                 bytes_received=e.bytes_received, message=e.message, additional_metadata=e.additional_metadata or {})


def alert_to_dict(a: Alert, event_refs: list[str] | None = None) -> dict[str, Any]:
    d = {
        "id": a.id, "ref": alert_ref(a.id), "title": a.title, "description": a.description,
        "detection_source": a.detection_source, "rule_id": a.rule_id, "severity": a.severity, "confidence": a.confidence,
        "confidence_kind": a.confidence_kind, "status": a.status, "usernames": a.usernames or [], "ips": a.ips or [],
        "host": a.host, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen), "explanation": a.explanation,
        "recommended_steps": a.recommended_steps or [], "limitations": a.limitations or "", "mitre": a.mitre or [],
        "details": a.details or {}, "evidence_total": a.evidence_total, "created_at": iso(a.created_at), "updated_at": iso(a.updated_at),
    }
    if event_refs is not None:
        d["event_refs"] = event_refs
    return d


def incident_to_dict(i: Incident, alert_count: int | None = None) -> dict[str, Any]:
    return {
        "id": i.id, "ref": incident_ref(i.id), "title": i.title, "description": i.description, "severity": i.severity,
        "status": i.status, "created_at": iso(i.created_at), "updated_at": iso(i.updated_at),
        "alert_count": alert_count if alert_count is not None else len(i.alerts),
    }


def note_to_dict(n) -> dict[str, Any]:  # noqa: ANN001
    return {"id": n.id, "author": n.author, "body": n.body, "created_at": iso(n.created_at)}
