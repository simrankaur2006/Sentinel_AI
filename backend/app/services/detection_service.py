"""Run the detection pipeline against stored events and persist alerts (deduplicated by fingerprint)."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import Alert, DetectionConfigRow, DetectionRun, SecurityEvent, alert_events, incident_alerts
from app.detection.config import DetectionConfig
from app.detection.rules import run_rules
from app.domain import Finding
from app.ml.anomaly import detect_anomalies
from app.services.serializers import event_to_domain

MAX_ANALYSIS_EVENTS = 200_000
_CHUNK = 1000


def load_config(db: Session) -> DetectionConfig:
    row = db.get(DetectionConfigRow, 1)
    if row is None:
        return DetectionConfig()
    try:
        return DetectionConfig.from_dict(row.config)
    except ValueError:  # stored config became invalid (e.g. manual edit): fall back to safe defaults
        return DetectionConfig()


def save_config(db: Session, cfg: DetectionConfig) -> None:
    row = db.get(DetectionConfigRow, 1)
    if row is None:
        db.add(DetectionConfigRow(id=1, config=cfg.to_dict()))
    else:
        row.config = cfg.to_dict()
    db.commit()


def run_detection(db: Session, cfg: DetectionConfig, *, use_ml: bool = True, clear_existing: bool = False) -> dict[str, Any]:
    if not use_ml:
        cfg = replace(cfg, ml_enabled=False)
    run = DetectionRun(config=cfg.to_dict(), status="running")
    db.add(run)
    db.flush()

    rows = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp, SecurityEvent.id).limit(MAX_ANALYSIS_EVENTS)).all()
    by_pk = {r.id: r for r in rows}
    events = [event_to_domain(r) for r in rows]

    cleared = 0
    if clear_existing:
        # Only untouched alerts (status New) that are not part of an incident are cleared; analyst work is never deleted.
        ids = list(db.scalars(select(Alert.id).where(Alert.status == "New", ~Alert.id.in_(select(incident_alerts.c.alert_id)))))
        for i in range(0, len(ids), _CHUNK):
            chunk = ids[i:i + _CHUNK]
            db.execute(delete(alert_events).where(alert_events.c.alert_id.in_(chunk)))
            db.execute(delete(Alert).where(Alert.id.in_(chunk)))
        cleared = len(ids)

    outcome = run_rules(events, cfg)
    covered = {e.pk for f in outcome.findings if f.detection_source != "correlation" for e in f.evidence if e.pk is not None}
    ml = detect_anomalies(events, cfg, covered)
    findings: list[Finding] = outcome.findings + ml.findings

    created = updated = 0
    existing: dict[str, Alert] = {}
    fps = [f.fingerprint for f in findings]
    for i in range(0, len(fps), _CHUNK):
        for a in db.scalars(select(Alert).where(Alert.fingerprint.in_(fps[i:i + _CHUNK]))):
            existing[a.fingerprint] = a
    for f in findings:
        evidence_rows = [by_pk[e.pk] for e in f.evidence if e.pk in by_pk]
        a = existing.get(f.fingerprint)
        fields = dict(title=f.title[:300], description=f.description, detection_source=f.detection_source, rule_id=f.rule_id,
                      severity=f.severity, confidence=f.confidence, confidence_kind=f.confidence_kind, usernames=f.usernames,
                      ips=f.ips, host=f.host, first_seen=f.first_seen, last_seen=f.last_seen, explanation=f.explanation,
                      recommended_steps=f.recommended_steps, limitations=f.limitations, mitre=f.mitre, details=f.details,
                      evidence_total=f.details.get("evidence_total", len(evidence_rows)), run_id=run.id)
        if a is None:
            a = Alert(fingerprint=f.fingerprint, status="New", **fields)
            a.events = evidence_rows
            db.add(a)
            created += 1
        else:  # keep analyst-managed status; refresh detection-derived fields
            for k, v in fields.items():
                setattr(a, k, v)
            a.events = evidence_rows
            updated += 1

    run.finished_at = datetime.now(timezone.utc)
    run.status = "completed"
    run.events_analyzed = len(events)
    run.alerts_created, run.alerts_updated, run.alerts_cleared = created, updated, cleared
    run.skipped = {**outcome.skipped, **({"ML-IFOREST": ml.skipped_reason} if ml.skipped_reason else {})}
    run.ml_metadata = ml.metadata
    db.commit()
    return run_to_dict(run)


def run_to_dict(r: DetectionRun) -> dict[str, Any]:
    return {"id": r.id, "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None, "status": r.status, "config": r.config or {},
            "events_analyzed": r.events_analyzed, "alerts_created": r.alerts_created, "alerts_updated": r.alerts_updated,
            "alerts_cleared": r.alerts_cleared, "skipped": r.skipped or {}, "ml_metadata": r.ml_metadata or {}}
