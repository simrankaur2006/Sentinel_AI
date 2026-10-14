"""Incident helpers: context building from stored data, analysis and report creation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.ai.ollama import OllamaConfig
from app.ai.service import analyze_incident
from app.core.config import Settings
from app.db.models import Alert, Incident, Report
from app.domain import SEVERITY_RANK, event_ref
from app.mitre.mapping import merge_mappings
from app.reporting.report import build_report, render_markdown
from app.services.context import build_context
from app.services.serializers import alert_to_dict, event_to_domain, incident_ref, incident_to_dict, iso, note_to_dict


def load_incident(db: Session, incident_id: int) -> Incident | None:
    return db.scalars(select(Incident).where(Incident.id == incident_id)
                      .options(selectinload(Incident.alerts).selectinload(Alert.events), selectinload(Incident.notes))).first()


def max_severity(severities: list[str], default: str = "Medium") -> str:
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0)) if severities else default


def alert_dicts(incident: Incident) -> list[dict[str, Any]]:
    out = []
    for a in sorted(incident.alerts, key=lambda x: (-SEVERITY_RANK.get(x.severity, 0), x.first_seen)):
        out.append(alert_to_dict(a, [event_ref(e.id) for e in a.events]))
    return out


def timeline_rows(incident: Incident, cap: int = 1000):
    seen = {}
    for a in incident.alerts:
        for e in a.events:
            seen.setdefault(e.id, e)
    return sorted(seen.values(), key=lambda e: (e.timestamp, e.id))[:cap]


def incident_context(incident: Incident, notes_ok: bool = True, *, max_alerts: int, max_events_per_alert: int) -> dict[str, Any]:
    alerts = alert_dicts(incident)
    emap = {}
    for a in incident.alerts:
        for e in a.events:
            emap.setdefault(event_ref(e.id), event_to_domain(e))
    inc = {"id": incident.id, "ref": incident_ref(incident.id), "title": incident.title, "description": incident.description or "",
           "status": incident.status, "severity": incident.severity, "created_at": iso(incident.created_at)}
    return build_context(inc, alerts, emap, [note_to_dict(n) for n in incident.notes] if notes_ok else [],
                         max_alerts=max_alerts, max_events_per_alert=max_events_per_alert)


def ollama_cfg(settings: Settings) -> OllamaConfig:
    return OllamaConfig(base_url=settings.ollama_base_url, model=settings.ollama_model, timeout=settings.ollama_timeout_seconds,
                        allow_remote=settings.ollama_allow_remote)


def run_analysis(incident: Incident, provider: str, settings: Settings) -> dict[str, Any]:
    ctx = incident_context(incident, max_alerts=settings.ai_max_alerts, max_events_per_alert=settings.ai_max_events_per_alert)
    res = analyze_incident(ctx, provider, ollama_cfg(settings), default_provider=settings.ai_provider)
    return res.to_dict()


def create_report(db: Session, incident: Incident, provider: str, include_analysis: bool, settings: Settings) -> Report:
    now = datetime.now(timezone.utc)
    # Reports carry more evidence than a model prompt: bounded, but larger.
    ctx = incident_context(incident, max_alerts=100, max_events_per_alert=100)
    analysis = None
    if include_analysis:
        ai_ctx = incident_context(incident, max_alerts=settings.ai_max_alerts, max_events_per_alert=settings.ai_max_events_per_alert)
        analysis = analyze_incident(ai_ctx, provider, ollama_cfg(settings), default_provider=settings.ai_provider).to_dict()
    payload = build_report(ctx, analysis, now)
    md = render_markdown(payload)
    rep = Report(incident_id=incident.id, title=f"{incident_ref(incident.id)} {incident.title}"[:300], generated_at=now,
                 generator=(analysis or {}).get("generator", "none"), markdown=md, payload=payload)
    db.add(rep)
    db.commit()
    return rep


def report_to_dict(r: Report, include_body: bool = False) -> dict[str, Any]:
    d = {"id": r.id, "incident_id": r.incident_id, "incident_ref": incident_ref(r.incident_id), "title": r.title,
         "generated_at": iso(r.generated_at), "generator": r.generator}
    if include_body:
        d["markdown"] = r.markdown
        d["payload"] = r.payload
    return d


def mitre_for(incident: Incident) -> list[dict[str, Any]]:
    return merge_mappings([a.mitre or [] for a in incident.alerts])


def incident_detail(incident: Incident) -> dict[str, Any]:
    alerts = alert_dicts(incident)
    users = sorted({u for a in alerts for u in a["usernames"]})
    ips = sorted({i for a in alerts for i in a["ips"]})
    hosts = sorted({a["host"] for a in alerts if a["host"]})
    from app.services.serializers import event_to_dict
    return {
        **incident_to_dict(incident, len(alerts)),
        "alerts": alerts,
        "timeline": [event_to_dict(e) for e in timeline_rows(incident)],
        "notes": [note_to_dict(n) for n in incident.notes],
        "mitre": mitre_for(incident),
        "affected": {"users": users, "ips": ips, "hosts": hosts},
        "guidance": sorted({s for a in alerts for s in a["recommended_steps"]})[:20],
    }
