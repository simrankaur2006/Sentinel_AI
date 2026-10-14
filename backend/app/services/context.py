"""Build the analysis/report context from stored data (pure function: no DB access)."""
from __future__ import annotations

from typing import Any

from app.domain import SEVERITY_RANK, Event


def build_context(incident: dict[str, Any], alerts: list[dict[str, Any]], events: dict[str, Event],
                  notes: list[dict[str, Any]], *, max_alerts: int, max_events_per_alert: int) -> dict[str, Any]:
    """`alerts` are serialized alert dicts (with full `event_refs`); `events` maps event ref -> Event.

    The result is bounded: at most `max_alerts` alerts (highest severity first) and `max_events_per_alert`
    evidence events per alert, so nothing unbounded is ever handed to an optional model.
    """
    ordered = sorted(alerts, key=lambda a: (-SEVERITY_RANK.get(a["severity"], 0), a["first_seen"]))
    chosen = ordered[:max_alerts]
    truncated = len(ordered) > len(chosen)
    picked: dict[str, dict[str, Any]] = {}
    slim_alerts = []
    for a in chosen:
        refs = a.get("event_refs", [])
        if len(refs) > max_events_per_alert:
            truncated = True
        for r in refs[:max_events_per_alert]:
            if r in events and r not in picked:
                picked[r] = events[r].brief()
        slim_alerts.append({**a, "event_refs": refs[:max(max_events_per_alert, 50)]})
    return {
        "incident": incident,
        "alerts": slim_alerts,
        "events": sorted(picked.values(), key=lambda e: (e["timestamp"], e["ref"])),
        "notes": [{"author": n["author"], "body": n["body"][:500], "created_at": n["created_at"]} for n in notes[:20]],
        "truncated": truncated,
    }
