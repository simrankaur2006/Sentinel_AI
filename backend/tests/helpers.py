"""Test helpers: build synthetic events without any database."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.domain import Event
from app.ingestion.parser import parse_upload

T0 = datetime(2025, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
SAMPLE_DIR = Path(__file__).resolve().parents[1] / "sample_data"
_pk = [0]


def ev(offset_s: float = 0, **kw) -> Event:
    _pk[0] += 1
    kw.setdefault("pk", _pk[0])
    return Event(timestamp=T0 + timedelta(seconds=offset_s), **kw)


def fail_login(offset_s, ip="203.0.113.50", user="admin", **kw):
    return ev(offset_s, event_type="authentication", status="failure", source_ip=ip, username=user, **kw)


def ok_login(offset_s, ip="203.0.113.50", user="admin", **kw):
    return ev(offset_s, event_type="authentication", status="success", source_ip=ip, username=user, **kw)


def load_sample(name: str) -> list[Event]:
    res = parse_upload(name, (SAMPLE_DIR / name).read_bytes())
    out = []
    for i, d in enumerate(res.events, 1):
        d = dict(d)
        d["pk"] = i
        out.append(Event(**d))
    return out


def finding_to_alert(f, alert_id: int, status: str = "New") -> dict:
    """Mirror of the API's alert serialization, for tests that do not use a database."""
    from app.domain import alert_ref
    return {"id": alert_id, "ref": alert_ref(alert_id), "title": f.title, "description": f.description,
            "detection_source": f.detection_source, "rule_id": f.rule_id, "severity": f.severity, "confidence": f.confidence,
            "confidence_kind": f.confidence_kind, "status": status, "usernames": f.usernames, "ips": f.ips, "host": f.host,
            "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(), "explanation": f.explanation,
            "recommended_steps": f.recommended_steps, "limitations": f.limitations, "mitre": f.mitre,
            "event_refs": [e.key() for e in f.evidence], "evidence_total": f.details.get("evidence_total", len(f.evidence)),
            "details": f.details, "fingerprint": f.fingerprint}


def make_context(events=None, rules=None, title="Test incident"):
    from app.detection.rules import run_rules
    from app.services.context import build_context
    events = events if events is not None else load_sample("sample_security_logs.csv")
    out = run_rules(events)
    findings = [f for f in out.findings if (rules is None or f.rule_id in rules)]
    alerts = [finding_to_alert(f, i + 1) for i, f in enumerate(findings)]
    emap = {e.key(): e for e in events}
    inc = {"id": 1, "ref": "INC-0001", "title": title, "description": "", "status": "Open", "severity": "High", "created_at": "2025-03-10T12:00:00+00:00"}
    return build_context(inc, alerts, emap, [], max_alerts=12, max_events_per_alert=15)
