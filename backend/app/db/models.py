"""SQLAlchemy ORM models (PostgreSQL in production; JSONB is used on PostgreSQL, generic JSON elsewhere)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (JSON, BigInteger, Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Index,
                        Integer, String, Table, Text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


alert_events = Table(
    "alert_events", Base.metadata,
    Column("alert_id", Integer, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", Integer, ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True),
    Index("ix_alert_events_event_id", "event_id"),
)

incident_alerts = Table(
    "incident_alerts", Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", Integer, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Index("ix_incident_alerts_alert_id", "alert_id"),
)


class IngestionBatch(Base):
    __tablename__ = "ingestion_batches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_format: Mapped[str] = mapped_column(String(16))
    rows_total: Mapped[int] = mapped_column(Integer, default=0)
    rows_imported: Mapped[int] = mapped_column(Integer, default=0)
    rows_duplicate: Mapped[int] = mapped_column(Integer, default=0)
    rows_invalid: Mapped[int] = mapped_column(Integer, default=0)
    warnings: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    event_id: Mapped[str | None] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str | None] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    event_type: Mapped[str | None] = mapped_column(String(64), index=True)
    action: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str | None] = mapped_column(String(64), index=True)
    protocol: Mapped[str | None] = mapped_column(String(32))
    port: Mapped[int | None] = mapped_column(Integer)
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger)
    bytes_received: Mapped[int | None] = mapped_column(BigInteger)
    message: Mapped[str | None] = mapped_column(Text)
    additional_metadata: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    batch_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_batches.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionRun(Base):
    __tablename__ = "detection_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="running")
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    events_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0)
    alerts_updated: Mapped[int] = mapped_column(Integer, default=0)
    alerts_cleared: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    ml_metadata: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)


class DetectionConfigRow(Base):
    __tablename__ = "detection_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("severity IN ('Critical','High','Medium','Low')", name="ck_alert_severity"),
        CheckConstraint("status IN ('New','Investigating','Resolved','False Positive')", name="ck_alert_status"),
        CheckConstraint("detection_source IN ('rule','correlation','ml')", name="ck_alert_source"),
        Index("ix_alerts_severity_status", "severity", "status"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    detection_source: Mapped[str] = mapped_column(String(16), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    confidence_kind: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(24), default="New")
    usernames: Mapped[list[str]] = mapped_column(JSONType, default=list)
    ips: Mapped[list[str]] = mapped_column(JSONType, default=list)
    host: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    explanation: Mapped[str] = mapped_column(Text)
    recommended_steps: Mapped[list[str]] = mapped_column(JSONType, default=list)
    limitations: Mapped[str] = mapped_column(Text, default="")
    mitre: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    evidence_total: Mapped[int] = mapped_column(Integer, default=0)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("detection_runs.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    events: Mapped[list[SecurityEvent]] = relationship(secondary=alert_events, order_by=SecurityEvent.timestamp)
    incidents: Mapped[list["Incident"]] = relationship(secondary=incident_alerts, back_populates="alerts")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("severity IN ('Critical','High','Medium','Low')", name="ck_incident_severity"),
        CheckConstraint("status IN ('Open','Investigating','Contained','Resolved','Closed')", name="ck_incident_status"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="Medium")
    status: Mapped[str] = mapped_column(String(24), default="Open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    alerts: Mapped[list[Alert]] = relationship(secondary=incident_alerts, back_populates="incidents")
    notes: Mapped[list["IncidentNote"]] = relationship(back_populates="incident", cascade="all, delete-orphan",
                                                       order_by="IncidentNote.created_at")


class IncidentNote(Base):
    __tablename__ = "incident_notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(100), default="analyst")
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    incident: Mapped[Incident] = relationship(back_populates="notes")


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    generator: Mapped[str] = mapped_column(String(100))
    markdown: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    incident: Mapped[Incident] = relationship()
