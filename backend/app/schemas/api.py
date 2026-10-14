"""Pydantic request/response schemas."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Page(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    database: Literal["ok", "unavailable"]
    detail: str | None = None


class DetectionRunRequest(BaseModel):
    use_ml: bool = True
    clear_existing: bool = False
    contamination: float | None = Field(default=None, ge=0.001, le=0.5, description="Override ML sensitivity for this run only")


class AlertStatusUpdate(BaseModel):
    status: Literal["New", "Investigating", "Resolved", "False Positive"]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    alert_ids: list[int] = Field(default_factory=list, max_length=200)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    status: Literal["Open", "Investigating", "Contained", "Resolved", "Closed"] | None = None
    severity: Literal["Critical", "High", "Medium", "Low"] | None = None


class AddAlerts(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=200)


class NoteCreate(BaseModel):
    author: str = Field(default="analyst", min_length=1, max_length=100)
    body: str = Field(min_length=1, max_length=5000)


class AnalysisRequest(BaseModel):
    provider: Literal["auto", "fallback", "ollama"] = "auto"


class ReportRequest(BaseModel):
    provider: Literal["auto", "fallback", "ollama"] = "auto"
    include_analysis: bool = True
