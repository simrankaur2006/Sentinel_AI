"""The documented sample-data scenarios (sample_data/README.md) must keep producing the documented alerts."""
from app.detection.config import DetectionConfig
from app.detection.rules import run_rules
from app.ml.anomaly import detect_anomalies
from tests.helpers import load_sample


def rules_of(out):
    from collections import Counter
    return Counter(f.rule_id for f in out.findings)


def test_csv_dataset_triggers_each_documented_detection():
    out = run_rules(load_sample("sample_security_logs.csv"))
    c = rules_of(out)
    assert c["R-AUTH-001"] == 2 and c["R-AUTH-002"] == 1 and c["R-AUTH-003"] == 2
    assert c["R-NET-001"] == 1 and c["R-NET-002"] == 1 and c["R-NET-003"] == 1 and c["R-ACC-001"] == 1
    cor = [f for f in out.findings if f.rule_id == "R-COR-001"]
    assert len(cor) == 1 and cor[0].severity == "Critical"
    assert out.skipped == {}


def test_benign_events_do_not_alert():
    events = load_sample("sample_security_logs.csv")
    out = run_rules(events)
    flagged = {e.pk for f in out.findings for e in f.evidence}
    benign_markers = ("typo", "Large internal file transfer", "Cloud backup upload", "single attempt")
    benign = {e.pk for e in events if e.message and any(m in e.message for m in benign_markers)}
    assert len(benign) == 4 and not (benign & flagged)
    frank_fails = {e.pk for e in events if e.username == "frank" and e.status == "failure" and e.timestamp.hour == 10}
    assert frank_fails and not (frank_fails & flagged)


def test_ml_finds_outliers_the_rules_do_not_cover():
    events = load_sample("sample_security_logs.csv")
    out = run_rules(events)
    covered = {e.pk for f in out.findings for e in f.evidence}
    res = detect_anomalies(events, DetectionConfig(), covered)
    assert res.skipped_reason is None and res.findings
    assert any(f.evidence[0].protocol == "sctp" for f in res.findings)
    assert not ({f.evidence[0].pk for f in res.findings} & covered)


def test_windows_jsonl_dataset_and_ml_graceful_skip():
    events = load_sample("sample_windows_auth.jsonl")
    out = run_rules(events)
    c = rules_of(out)
    assert c["R-AUTH-001"] == 1 and c["R-AUTH-002"] == 1
    assert {"R-NET-001", "R-NET-003", "R-ACC-001"} <= set(out.skipped)  # missing fields -> skipped, not crashed
    assert "at least" in detect_anomalies(events, DetectionConfig()).skipped_reason
