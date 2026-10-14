import random

from app.detection.config import DetectionConfig
from app.ml.anomaly import AnomalyModel, detect_anomalies
from tests.helpers import ev


def benign(n=150, seed=1):
    r = random.Random(seed)
    return [ev(i * 40, source_ip=f"10.0.5.{r.randint(10, 20)}", destination_ip="203.0.113.20", username=f"u{r.randint(1, 6)}",
               event_type="network_connection", action="allow", status="success", protocol="tcp", port=443,
               bytes_sent=r.randint(500, 40_000), bytes_received=r.randint(5_000, 900_000)) for i in range(n)]


def outliers():
    return [ev(5000 + i, source_ip="10.0.4.44", destination_ip="10.0.1.30", event_type="network_connection", action="tunnel",
               status="success", protocol="sctp", port=9999, bytes_sent=9_000_000, bytes_received=8_000_000) for i in range(2)]


def test_obvious_outliers_rank_highest():
    evs = benign() + outliers()
    res = detect_anomalies(evs, DetectionConfig())
    top_pks = {f.evidence[0].pk for f in res.findings[:2]}
    assert top_pks == {e.pk for e in evs[-2:]}
    assert all(f.detection_source == "ml" for f in res.findings)


def test_findings_are_distinguished_and_never_above_medium():
    res = detect_anomalies(benign() + outliers(), DetectionConfig())
    for f in res.findings:
        assert f.rule_id == "ML-IFOREST" and f.confidence_kind == "anomaly_score" and f.severity in {"Medium", "Low"} and f.mitre == []
        assert "not mean malicious" in f.description.lower() or "unusual" in f.description.lower()
        assert 0.0 <= f.confidence <= 1.0


def test_results_are_reproducible_with_same_seed_and_metadata_recorded():
    evs = benign() + outliers()
    a = detect_anomalies(evs, DetectionConfig(ml_random_seed=7))
    b = detect_anomalies(evs, DetectionConfig(ml_random_seed=7))
    assert [f.confidence for f in a.findings] == [f.confidence for f in b.findings]
    m = a.metadata
    assert m["random_seed"] == 7 and m["contamination"] == 0.05 and m["n_estimators"] == 200 and "features" in m
    assert "not computed" in m["metrics"]  # never fabricates accuracy numbers


def test_sensitivity_changes_number_flagged():
    evs = benign() + outliers()
    low = detect_anomalies(evs, DetectionConfig(ml_contamination=0.01, ml_max_alerts=200))
    high = detect_anomalies(evs, DetectionConfig(ml_contamination=0.2, ml_max_alerts=200))
    assert high.metadata["n_flagged_before_filters"] > low.metadata["n_flagged_before_filters"]


def test_too_few_events_skips_gracefully():
    res = detect_anomalies(benign(10), DetectionConfig())
    assert res.findings == [] and "at least" in res.skipped_reason and res.metadata["skipped"]


def test_disabled_ml_is_skipped():
    assert detect_anomalies(benign(), DetectionConfig(ml_enabled=False)).skipped_reason


def test_unseen_categories_and_missing_values_do_not_crash():
    model = AnomalyModel(DetectionConfig())
    model.fit(benign())
    odd = [ev(0, protocol="brand-new-proto", event_type="never_seen", action="x"), ev(1)]  # second event has everything missing
    scored = model.score(odd)
    assert len(scored) == 2 and all(0.0 <= s["score"] <= 1.0 for s in scored)


def test_rule_covered_events_can_be_excluded():
    evs = benign() + outliers()
    covered = {e.pk for e in evs[-2:]}
    res = detect_anomalies(evs, DetectionConfig(), covered)
    assert not ({f.evidence[0].pk for f in res.findings} & covered)
    assert res.metadata["n_skipped_rule_covered"] >= 1
