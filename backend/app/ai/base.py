"""Provider-independent incident analysis types.

The context passed to every provider is a plain dict built by the service layer from stored data
(see services/context.py). Providers must treat every string inside it as untrusted log data.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

ADVISORY_NOTICE = ("This analysis is advisory. It was generated from the stored alerts and events only and may be "
                   "incomplete or wrong. Verify every statement against the referenced evidence before acting.")


class LLMUnavailable(RuntimeError):
    """The optional local model could not be reached or timed out."""


class LLMOutputError(ValueError):
    """The optional local model returned output that failed validation."""


@dataclass
class AnalysisResult:
    generator: str  # "deterministic-fallback" or "ollama:<model>"
    summary: str = ""
    why_flagged: list[dict[str, Any]] = field(default_factory=list)       # {alert_ref, text}
    observed_facts: list[dict[str, Any]] = field(default_factory=list)    # {text, refs}
    hypotheses: list[dict[str, Any]] = field(default_factory=list)        # {text, refs}  (NOT facts)
    investigation_steps: list[str] = field(default_factory=list)
    containment: list[dict[str, Any]] = field(default_factory=list)       # {action, justification, refs}
    missing_evidence: list[str] = field(default_factory=list)
    mitre: list[dict[str, Any]] = field(default_factory=list)
    referenced_alerts: list[str] = field(default_factory=list)
    referenced_events: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    fallback_reason: str | None = None
    advisory_notice: str = ADVISORY_NOTICE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AnalysisProvider(Protocol):
    name: str

    def analyze(self, context: dict[str, Any]) -> AnalysisResult: ...


_INJECTION = re.compile(
    r"ignore (all |any |the )?(previous|prior|above)|disregard (the |all )?(instructions|rules)|system prompt|"
    r"you are now|new instructions|act as|reveal your|developer message", re.I)


def injection_warnings(context: dict[str, Any]) -> list[str]:
    """Detect instruction-like text inside log-derived strings. Logs are data; this only raises awareness."""
    hits: set[str] = set()
    for ev in context.get("events", []):
        for k in ("message", "username"):
            v = ev.get(k)
            if isinstance(v, str) and _INJECTION.search(v):
                hits.add(ev.get("ref", "?"))
    if hits:
        return ["Instruction-like text was found in log content of " + ", ".join(sorted(hits)[:10])
                + ". It was treated strictly as data and was not followed."]
    return []
