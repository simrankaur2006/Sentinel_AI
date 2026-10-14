"""Framework-independent domain objects shared by ingestion, detection, ML, AI and reporting."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
ALERT_STATUSES = ["New", "Investigating", "Resolved", "False Positive"]
INCIDENT_STATUSES = ["Open", "Investigating", "Contained", "Resolved", "Closed"]


def ensure_utc(dt: datetime | None) -> datetime | None:
    """Treat naive datetimes (e.g. from SQLite) as UTC; convert aware ones to UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def alert_ref(alert_id: int) -> str:
    return f"ALT-{alert_id:05d}"


def event_ref(event_pk: int) -> str:
    return f"EVT-{event_pk}"


@dataclass
class Event:
    """A normalized security event (canonical schema)."""

    timestamp: datetime
    pk: int | None = None
    fingerprint: str | None = None
    event_id: str | None = None
    source: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    event_type: str | None = None
    action: str | None = None
    status: str | None = None
    protocol: str | None = None
    port: int | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    message: str | None = None
    additional_metadata: dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        return event_ref(self.pk) if self.pk is not None else (self.fingerprint or "EVT-?")

    def brief(self, max_message: int = 200) -> dict[str, Any]:
        return {
            "ref": self.key(),
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "event_type": self.event_type,
            "action": self.action,
            "status": self.status,
            "protocol": self.protocol,
            "port": self.port,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "message": (self.message or "")[:max_message] or None,
        }


@dataclass
class Finding:
    """A detection result (rule, correlation, or ML) before persistence."""

    rule_id: str
    detection_source: str  # "rule" | "correlation" | "ml"
    title: str
    description: str
    severity: str
    confidence: float  # heuristic strength / normalized anomaly score; NOT a probability
    confidence_kind: str  # "heuristic_strength" | "anomaly_score"
    first_seen: datetime
    last_seen: datetime
    evidence: list[Event]
    explanation: str
    recommended_steps: list[str]
    limitations: str
    fingerprint: str
    usernames: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    host: str | None = None
    mitre: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
