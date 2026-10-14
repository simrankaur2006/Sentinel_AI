import json
from datetime import datetime, timezone

from app.ai.fallback import DeterministicProvider
from app.reporting.report import build_report, render_markdown
from tests.helpers import ev, make_context

NOW = datetime(2025, 3, 11, 9, 0, 0, tzinfo=timezone.utc)


def test_report_is_deterministic_and_contains_evidence():
    ctx = make_context()
    ai = DeterministicProvider().analyze(ctx).to_dict()
    r1, r2 = build_report(ctx, ai, NOW), build_report(ctx, ai, NOW)
    assert render_markdown(r1) == render_markdown(r2) and json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)
    md = render_markdown(r1)
    for a in ctx["alerts"]:
        assert a["ref"] in md
    assert "T1110" in md and "Timeline" in md and "advisory" in md.lower() and "deterministic-fallback" in md
    assert r1["summary"]["alert_count"] == len(ctx["alerts"]) and r1["generated_at"] == NOW.isoformat()


def test_report_without_ai_is_valid():
    ctx = make_context()
    md = render_markdown(build_report(ctx, None, NOW))
    assert "## Alerts" in md and "Analysis summary" not in md


def test_untrusted_text_cannot_break_markdown_tables_or_inject_html():
    events = [ev(i, source_ip="203.0.113.7", event_type="authentication", status="failure", username="a|b<script>alert(1)</script>\nfake | row |")
              for i in range(6)]
    ctx = make_context(events=events, rules={"R-AUTH-001"})
    md = render_markdown(build_report(ctx, None, NOW))
    assert "<script>" not in md and "\nfake" not in md
