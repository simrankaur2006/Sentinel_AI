"""Dashboard metrics computed from the database (nothing is hardcoded)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from app.db.models import Alert, DetectionRun, Incident, SecurityEvent
from app.domain import ALERT_STATUSES, SEVERITIES
from app.services.detection_service import run_to_dict
from app.services.serializers import alert_to_dict, event_to_dict, incident_to_dict, iso


def _bucket_expr(db: Session, unit: str):
    if db.get_bind().dialect.name == "postgresql":
        return func.date_trunc(literal_column(f"'{unit}'"), SecurityEvent.timestamp)  # literal: keeps GROUP BY identical
    fmt = "%Y-%m-%dT%H:00:00" if unit == "hour" else "%Y-%m-%dT00:00:00"
    return func.strftime(fmt, SecurityEvent.timestamp)


def build_dashboard(db: Session, start: datetime | None = None, end: datetime | None = None) -> dict[str, Any]:
    ev_conds = []
    al_conds = []
    if start:
        ev_conds.append(SecurityEvent.timestamp >= start)
        al_conds.append(Alert.last_seen >= start)
    if end:
        ev_conds.append(SecurityEvent.timestamp <= end)
        al_conds.append(Alert.first_seen <= end)

    total_events = db.scalar(select(func.count()).select_from(SecurityEvent).where(*ev_conds)) or 0
    total_alerts = db.scalar(select(func.count()).select_from(Alert).where(*al_conds)) or 0
    open_alerts = db.scalar(select(func.count()).select_from(Alert).where(*al_conds, Alert.status.in_(["New", "Investigating"]))) or 0
    total_incidents = db.scalar(select(func.count()).select_from(Incident)) or 0

    def grouped(col, order: list[str] | None = None) -> list[dict[str, Any]]:
        rows = dict(db.execute(select(col, func.count()).where(*al_conds).group_by(col)).all())
        names = order if order is not None else sorted(rows)
        return [{"name": n, "count": int(rows.get(n, 0))} for n in names]

    tmin, tmax = db.execute(select(func.min(SecurityEvent.timestamp), func.max(SecurityEvent.timestamp)).where(*ev_conds)).one()
    unit = "hour"
    if tmin and tmax and (tmax - tmin).total_seconds() > 3 * 86400:
        unit = "day"
    points: list[dict[str, Any]] = []
    if total_events:
        b = _bucket_expr(db, unit).label("b")
        for t, c in db.execute(select(b, func.count()).where(*ev_conds).group_by(b).order_by(b)).all():
            points.append({"time": t.isoformat() if hasattr(t, "isoformat") else str(t), "count": int(c)})

    users: Counter[str] = Counter()
    ips: Counter[str] = Counter()
    for u, i in db.execute(select(Alert.usernames, Alert.ips).where(*al_conds).limit(5000)).all():
        users.update(u or [])
        ips.update(i or [])

    recent_alerts = db.scalars(select(Alert).where(*al_conds).order_by(Alert.last_seen.desc()).limit(8)).all()
    recent_events = db.scalars(select(SecurityEvent).where(*ev_conds).order_by(SecurityEvent.timestamp.desc()).limit(8)).all()
    recent_incidents = db.scalars(select(Incident).order_by(Incident.updated_at.desc()).limit(5)).all()
    ml_alerts = db.scalars(select(Alert).where(*al_conds, Alert.detection_source == "ml").order_by(Alert.confidence.desc()).limit(5)).all()
    ml_total = db.scalar(select(func.count()).select_from(Alert).where(*al_conds, Alert.detection_source == "ml")) or 0
    last_run = db.scalars(select(DetectionRun).order_by(DetectionRun.id.desc()).limit(1)).first()

    return {
        "range": {"start": iso(start), "end": iso(end)},
        "totals": {"events": total_events, "alerts": total_alerts, "open_alerts": open_alerts, "incidents": total_incidents},
        "alerts_by_severity": grouped(Alert.severity, SEVERITIES),
        "alerts_by_source": grouped(Alert.detection_source, ["rule", "correlation", "ml"]),
        "alerts_by_status": grouped(Alert.status, ALERT_STATUSES),
        "events_over_time": {"bucket": unit, "points": points},
        "top_users": [{"name": n, "count": c} for n, c in users.most_common(5)],
        "top_ips": [{"name": n, "count": c} for n, c in ips.most_common(5)],
        "recent_alerts": [alert_to_dict(a) for a in recent_alerts],
        "recent_events": [event_to_dict(e) for e in recent_events],
        "recent_incidents": [incident_to_dict(i) for i in recent_incidents],
        "anomaly": {
            "alert_count": ml_total,
            "top": [alert_to_dict(a) for a in ml_alerts],
            "metadata": (last_run.ml_metadata if last_run else None) or {},
        },
        "latest_run": run_to_dict(last_run) if last_run else None,
    }
