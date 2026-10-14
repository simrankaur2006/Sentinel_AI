"""Load sample datasets, run detection, and create a demo incident.   Usage: python -m scripts.seed_demo"""
from sqlalchemy import String, select

from app.core.config import get_settings
from app.db.models import Alert, Base, Incident, IncidentNote
from app.db.session import get_engine, get_session_factory
from app.services import detection_service as det
from app.services import ingest


def main() -> None:
    settings = get_settings()
    Base.metadata.create_all(get_engine())
    with get_session_factory()() as db:
        for sid in ingest.SAMPLES:
            b = ingest.ingest_sample(db, sid, settings)
            print(f"{b['filename']}: imported {b['rows_imported']}, duplicates {b['rows_duplicate']}, invalid {b['rows_invalid']}")
        run = det.run_detection(db, det.load_config(db))
        print(f"Detection: {run['alerts_created']} new alerts, {run['alerts_updated']} updated; skipped: {run['skipped'] or 'none'}")
        cor = db.scalars(select(Alert).where(Alert.rule_id == "R-COR-001", Alert.severity == "Critical")).first()
        if cor and not db.scalars(select(Incident).where(Incident.title.like("Demo:%"))).first():
            admin = db.scalars(select(Alert).where(Alert.usernames.cast(String).like('%"admin"%'))).all()
            inc = Incident(title="Demo: suspected compromise of 'admin' account", severity="Critical", status="Investigating",
                           description="Synthetic demo incident created by scripts.seed_demo.")
            inc.alerts = list({a.id: a for a in [cor, *admin]}.values())
            for a in inc.alerts:
                a.status = "Investigating"
            inc.notes = [IncidentNote(author="demo-analyst", body="Brute force from 203.0.113.50 followed by a successful login and egress. Awaiting confirmation from the account owner.")]
            db.add(inc)
            db.commit()
            print(f"Created demo incident #{inc.id} with {len(inc.alerts)} alerts.")


if __name__ == "__main__":
    main()
