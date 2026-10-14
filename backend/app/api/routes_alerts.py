"""Detection, alerts, incidents and reports routes."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import String, case, cast, func, select
from sqlalchemy.orm import Session

from app.api.deps import Pager, like_escape, settings_dep
from app.core.config import Settings
from app.db.models import utcnow, Alert, DetectionRun, Incident, IncidentNote, Report, incident_alerts
from app.db.session import get_db
from app.detection.config import DetectionConfig
from app.detection.rules import RULE_CATALOG
from app.domain import event_ref
from app.mitre.mapping import load_mappings
from app.schemas.api import (AddAlerts, AlertStatusUpdate, AnalysisRequest, DetectionRunRequest, IncidentCreate, IncidentUpdate,
                             NoteCreate, Page, ReportRequest)
from app.services import detection_service as det
from app.services import incident_service as isvc
from app.services.serializers import alert_to_dict, event_to_dict, incident_to_dict, note_to_dict

router = APIRouter()

# ------------------------------------------------------------------ detection
@router.post("/detection/run", tags=["detection"])
def run_detection(body: DetectionRunRequest, db: Session = Depends(get_db)) -> dict:
    cfg = det.load_config(db)
    if body.contamination is not None:
        cfg = replace(cfg, ml_contamination=body.contamination)
    return det.run_detection(db, cfg, use_ml=body.use_ml, clear_existing=body.clear_existing)


@router.get("/detection/runs", tags=["detection"])
def list_runs(db: Session = Depends(get_db)) -> list[dict]:
    return [det.run_to_dict(r) for r in db.scalars(select(DetectionRun).order_by(DetectionRun.id.desc()).limit(20))]


@router.get("/detection/config", tags=["detection"])
def get_config(db: Session = Depends(get_db)) -> dict:
    return {"config": det.load_config(db).to_dict(), "defaults": DetectionConfig().to_dict()}


@router.put("/detection/config", tags=["detection"])
def put_config(body: dict[str, Any], db: Session = Depends(get_db)) -> dict:
    try:
        cfg = DetectionConfig.from_dict({**det.load_config(db).to_dict(), **body})
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    det.save_config(db, cfg)
    return {"config": cfg.to_dict(), "defaults": DetectionConfig().to_dict()}


@router.post("/detection/config/reset", tags=["detection"])
def reset_config(db: Session = Depends(get_db)) -> dict:
    cfg = DetectionConfig()
    det.save_config(db, cfg)
    return {"config": cfg.to_dict(), "defaults": cfg.to_dict()}


@router.get("/detection/rules", tags=["detection"])
def rules() -> list[dict]:
    return [{"id": k, **v} for k, v in RULE_CATALOG.items()] + [{
        "id": "ML-IFOREST", "name": "Isolation Forest anomaly", "requires": "at least ml_min_events events",
        "logic": "Unsupervised outlier ranking relative to the analysed dataset.",
        "limitations": "Anomalous is not malicious; scores are relative, not probabilities; no accuracy metrics are computed."}]


@router.get("/mitre/mappings", tags=["detection"])
def mitre() -> dict:
    return load_mappings()


# ------------------------------------------------------------------ alerts
_SEV_RANK = case({"Critical": 4, "High": 3, "Medium": 2, "Low": 1}, value=Alert.severity, else_=0)
_ALERT_SORT = {"severity": _SEV_RANK, "first_seen": Alert.first_seen, "last_seen": Alert.last_seen, "created_at": Alert.created_at,
               "confidence": Alert.confidence, "status": Alert.status, "title": Alert.title}


@router.get("/alerts", response_model=Page, tags=["alerts"])
def list_alerts(p: Pager = Depends(), db: Session = Depends(get_db), q: str | None = Query(None, max_length=200),
                severity: list[str] | None = Query(None), status: list[str] | None = Query(None),
                detection_source: str | None = None, rule_id: str | None = None, sort: str = "severity", order: str = "desc") -> Page:
    if sort not in _ALERT_SORT or order not in {"asc", "desc"}:
        raise HTTPException(422, "Invalid sort or order.")
    conds = []
    if severity:
        conds.append(Alert.severity.in_(severity))
    if status:
        conds.append(Alert.status.in_(status))
    if detection_source:
        conds.append(Alert.detection_source == detection_source)
    if rule_id:
        conds.append(Alert.rule_id == rule_id)
    if q:
        pat = f"%{like_escape(q)}%"
        conds.append(Alert.title.ilike(pat, escape="\\") | Alert.description.ilike(pat, escape="\\") | Alert.host.ilike(pat, escape="\\")
                     | cast(Alert.ips, String).ilike(pat, escape="\\") | cast(Alert.usernames, String).ilike(pat, escape="\\"))
    total = db.scalar(select(func.count()).select_from(Alert).where(*conds)) or 0
    col = _ALERT_SORT[sort]
    rows = db.scalars(select(Alert).where(*conds).order_by(col.desc() if order == "desc" else col.asc(), Alert.last_seen.desc(), Alert.id.desc())
                      .offset(p.offset).limit(p.page_size)).all()
    return Page(items=[alert_to_dict(a) for a in rows], total=total, page=p.page, page_size=p.page_size)


@router.get("/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> dict:
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "Alert not found.")
    events = a.events
    inc_ids = list(db.scalars(select(incident_alerts.c.incident_id).where(incident_alerts.c.alert_id == a.id)))
    return {**alert_to_dict(a, [event_ref(e.id) for e in events]), "events": [event_to_dict(e) for e in events[:500]], "incident_ids": inc_ids}


@router.patch("/alerts/{alert_id}", tags=["alerts"])
def update_alert(alert_id: int, body: AlertStatusUpdate, db: Session = Depends(get_db)) -> dict:
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "Alert not found.")
    a.status = body.status
    db.commit()
    return alert_to_dict(a)


# ------------------------------------------------------------------ incidents
def _get_incident(db: Session, incident_id: int) -> Incident:
    inc = isvc.load_incident(db, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found.")
    return inc


def _alerts_by_ids(db: Session, ids: list[int]) -> list[Alert]:
    found = list(db.scalars(select(Alert).where(Alert.id.in_(set(ids)))))
    missing = set(ids) - {a.id for a in found}
    if missing:
        raise HTTPException(404, f"Alerts not found: {sorted(missing)[:10]}")
    return found


@router.post("/incidents", status_code=201, tags=["incidents"])
def create_incident(body: IncidentCreate, db: Session = Depends(get_db)) -> dict:
    alerts = _alerts_by_ids(db, body.alert_ids) if body.alert_ids else []
    inc = Incident(title=body.title.strip(), description=body.description, severity=isvc.max_severity([a.severity for a in alerts]),
                   status="Open")
    inc.alerts = alerts
    for a in alerts:
        if a.status == "New":
            a.status = "Investigating"
    db.add(inc)
    db.commit()
    return isvc.incident_detail(_get_incident(db, inc.id))


@router.get("/incidents", response_model=Page, tags=["incidents"])
def list_incidents(p: Pager = Depends(), db: Session = Depends(get_db), status: str | None = None) -> Page:
    conds = [Incident.status == status] if status else []
    total = db.scalar(select(func.count()).select_from(Incident).where(*conds)) or 0
    counts = dict(db.execute(select(incident_alerts.c.incident_id, func.count()).group_by(incident_alerts.c.incident_id)).all())
    rows = db.scalars(select(Incident).where(*conds).order_by(Incident.updated_at.desc(), Incident.id.desc()).offset(p.offset).limit(p.page_size)).all()
    return Page(items=[incident_to_dict(i, counts.get(i.id, 0)) for i in rows], total=total, page=p.page, page_size=p.page_size)


@router.get("/incidents/{incident_id}", tags=["incidents"])
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> dict:
    return isvc.incident_detail(_get_incident(db, incident_id))


@router.patch("/incidents/{incident_id}", tags=["incidents"])
def update_incident(incident_id: int, body: IncidentUpdate, db: Session = Depends(get_db)) -> dict:
    inc = _get_incident(db, incident_id)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(inc, k, v.strip() if isinstance(v, str) and k == "title" else v)
    db.commit()
    return isvc.incident_detail(_get_incident(db, incident_id))


@router.post("/incidents/{incident_id}/alerts", tags=["incidents"])
def add_alerts(incident_id: int, body: AddAlerts, db: Session = Depends(get_db)) -> dict:
    inc = _get_incident(db, incident_id)
    have = {a.id for a in inc.alerts}
    for a in _alerts_by_ids(db, body.alert_ids):
        if a.id not in have:
            inc.alerts.append(a)
            if a.status == "New":
                a.status = "Investigating"
    inc.severity = isvc.max_severity([a.severity for a in inc.alerts], inc.severity)
    db.commit()
    return isvc.incident_detail(_get_incident(db, incident_id))


@router.post("/incidents/{incident_id}/notes", status_code=201, tags=["incidents"])
def add_note(incident_id: int, body: NoteCreate, db: Session = Depends(get_db)) -> dict:
    inc = _get_incident(db, incident_id)
    note = IncidentNote(incident_id=inc.id, author=body.author.strip() or "analyst", body=body.body.strip())
    db.add(note)
    inc.updated_at = utcnow()
    db.commit()
    return note_to_dict(note)


@router.post("/incidents/{incident_id}/analysis", tags=["ai"])
def analyze(incident_id: int, body: AnalysisRequest, db: Session = Depends(get_db), s: Settings = Depends(settings_dep)) -> dict:
    return isvc.run_analysis(_get_incident(db, incident_id), body.provider, s)


# ------------------------------------------------------------------ reports
@router.post("/incidents/{incident_id}/reports", status_code=201, tags=["reports"])
def create_report(incident_id: int, body: ReportRequest, db: Session = Depends(get_db), s: Settings = Depends(settings_dep)) -> dict:
    inc = _get_incident(db, incident_id)
    return isvc.report_to_dict(isvc.create_report(db, inc, body.provider, body.include_analysis, s))


@router.get("/reports", response_model=Page, tags=["reports"])
def list_reports(p: Pager = Depends(), db: Session = Depends(get_db), incident_id: int | None = None) -> Page:
    conds = [Report.incident_id == incident_id] if incident_id else []
    total = db.scalar(select(func.count()).select_from(Report).where(*conds)) or 0
    rows = db.scalars(select(Report).where(*conds).order_by(Report.id.desc()).offset(p.offset).limit(p.page_size)).all()
    return Page(items=[isvc.report_to_dict(r) for r in rows], total=total, page=p.page, page_size=p.page_size)


@router.get("/reports/{report_id}", tags=["reports"])
def get_report(report_id: int, db: Session = Depends(get_db)) -> dict:
    r = db.get(Report, report_id)
    if r is None:
        raise HTTPException(404, "Report not found.")
    return isvc.report_to_dict(r, include_body=True)


@router.get("/reports/{report_id}/download", tags=["reports"])
def download_report(report_id: int, format: str = Query("markdown", pattern="^(markdown|json)$"), db: Session = Depends(get_db)) -> Response:
    import json
    r = db.get(Report, report_id)
    if r is None:
        raise HTTPException(404, "Report not found.")
    name = f"sentinelai-incident-{r.incident_id:04d}-report-{r.id}"
    if format == "json":
        return Response(json.dumps(r.payload, indent=2, sort_keys=True), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}.json"', "X-Content-Type-Options": "nosniff"})
    return Response(r.markdown, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}.md"', "X-Content-Type-Options": "nosniff"})
