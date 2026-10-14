from app.detection.config import DetectionConfig
from app.detection.rules import is_internal, run_rules
from tests.helpers import ev, fail_login, ok_login


def by_rule(out, rid):
    return [f for f in out.findings if f.rule_id == rid]


def test_failed_login_burst_triggers_and_includes_evidence():
    evs = [fail_login(i * 10) for i in range(6)]
    f = by_rule(run_rules(evs), "R-AUTH-001")
    assert len(f) == 1 and len(f[0].evidence) == 6 and f[0].mitre[0]["technique_id"] == "T1110"
    assert {e.pk for e in f[0].evidence} == {e.pk for e in evs}


def test_failed_logins_below_threshold_or_spread_over_time_do_not_trigger():
    assert not by_rule(run_rules([fail_login(i * 10) for i in range(4)]), "R-AUTH-001")
    slow = [fail_login(i * 600) for i in range(8)]  # one failure every 10 min: never 5 within 10 min
    assert not by_rule(run_rules(slow), "R-AUTH-001")


def test_threshold_is_configurable():
    evs = [fail_login(i * 10) for i in range(3)]
    assert not by_rule(run_rules(evs), "R-AUTH-001")
    assert by_rule(run_rules(evs, DetectionConfig(failed_login_threshold=3)), "R-AUTH-001")


def test_repeated_run_does_not_duplicate_findings_and_fingerprint_is_stable():
    evs = [fail_login(i * 10) for i in range(30)]  # one long burst must yield exactly one finding
    a, b = by_rule(run_rules(evs), "R-AUTH-001"), by_rule(run_rules(evs), "R-AUTH-001")
    assert len(a) == 1 and a[0].fingerprint == b[0].fingerprint


def test_password_spray_is_distinguished_and_maps_to_t1110_003():
    evs = [fail_login(i * 20, ip="192.0.2.77", user=f"user{i}") for i in range(8)]
    f = by_rule(run_rules(evs), "R-AUTH-001")[0]
    assert f.details["pattern"] == "spray"
    assert "T1110.003" in {m["technique_id"] for m in f.mitre}


def test_success_after_failures():
    evs = [fail_login(i * 20) for i in range(5)] + [ok_login(150)]
    f = by_rule(run_rules(evs), "R-AUTH-002")
    assert len(f) == 1 and f[0].severity == "High" and f[0].evidence[-1].status == "success"
    assert f[0].mitre[0]["technique_id"] == "T1078" and f[0].mitre[0]["relation"] == "potential_association"


def test_success_after_few_failures_or_from_other_ip_does_not_trigger():
    assert not by_rule(run_rules([fail_login(0), fail_login(5), ok_login(30)]), "R-AUTH-002")
    evs = [fail_login(i * 20, ip="203.0.113.50") for i in range(6)] + [ok_login(150, ip="10.0.5.11")]
    assert not by_rule(run_rules(evs), "R-AUTH-002")


def test_multi_ip_login_and_offhours():
    evs = [ok_login(0, ip="10.0.0.1", user="carol"), ok_login(300, ip="192.0.2.5", user="carol"), ok_login(600, ip="198.51.100.7", user="carol")]
    f = by_rule(run_rules(evs), "R-AUTH-003")
    assert len(f) == 1 and f[0].details["check"] == "multi_ip"
    from datetime import timedelta
    base = [ok_login(h * 3600 + 3600, ip="10.0.0.9", user="dave") for h in range(3)]  # 13:00,14:00,15:00
    night = ok_login(-9 * 3600, ip="10.0.0.9", user="dave")  # 03:00
    f2 = [x for x in by_rule(run_rules(base + [night]), "R-AUTH-003") if x.details["check"] == "off_hours"]
    assert len(f2) == 1 and f2[0].severity == "Low"


def test_offhours_requires_baseline():
    assert not by_rule(run_rules([ok_login(-9 * 3600, user="zed")]), "R-AUTH-003")


def test_port_scan():
    evs = [ev(i * 2, source_ip="198.51.100.9", destination_ip="10.0.2.20", port=1000 + i, event_type="network_connection") for i in range(20)]
    f = by_rule(run_rules(evs), "R-NET-001")
    assert len(f) == 1 and f[0].details["distinct_ports"] == 20 and f[0].mitre[0]["technique_id"] == "T1046"
    few = [ev(i * 2, source_ip="198.51.100.9", destination_ip="10.0.2.20", port=443) for i in range(50)]
    assert not by_rule(run_rules(few), "R-NET-001")  # many connections, one port


def test_watchlist_and_cidr():
    evs = [ev(0, source_ip="10.0.3.15", destination_ip="203.0.113.66", status="success", bytes_sent=500, event_type="network_connection")]
    f = by_rule(run_rules(evs), "R-NET-002")
    assert len(f) == 1 and f[0].severity == "High"
    cfg = DetectionConfig(suspicious_ips=["192.0.2.0/24"])
    assert by_rule(run_rules([ev(0, source_ip="192.0.2.99", destination_ip="10.0.0.1", event_type="network_connection")], cfg), "R-NET-002")


def test_outbound_volume_ignores_internal_destinations_and_small_transfers():
    big_ext = [ev(i * 60, source_ip="10.0.1.10", destination_ip="203.0.113.99", bytes_sent=30_000_000, event_type="network_connection") for i in range(2)]
    assert by_rule(run_rules(big_ext), "R-NET-003")
    internal = [ev(0, source_ip="10.0.1.10", destination_ip="10.0.1.30", bytes_sent=900_000_000, event_type="network_connection")]
    assert not by_rule(run_rules(internal), "R-NET-003")
    small = [ev(0, source_ip="10.0.1.10", destination_ip="203.0.113.99", bytes_sent=1_000, event_type="network_connection")]
    assert not by_rule(run_rules(small), "R-NET-003")


def test_sensitive_access_requires_resource_field_and_denied_status():
    evs = [ev(i * 30, username="admin", source_ip="203.0.113.50", status="denied", event_type="resource_access",
              additional_metadata={"resource": "/etc/shadow"}) for i in range(3)]
    f = by_rule(run_rules(evs), "R-ACC-001")
    assert len(f) == 1 and f[0].mitre[0]["technique_id"] == "T1003.008"
    ok = [ev(i * 30, username="admin", status="success", event_type="resource_access", additional_metadata={"resource": "/etc/shadow"}) for i in range(3)]
    assert not by_rule(run_rules(ok), "R-ACC-001")


def test_generic_sensitive_path_has_no_mitre_mapping():
    evs = [ev(i * 30, username="bob", status="denied", additional_metadata={"resource": "/admin/panel"}) for i in range(2)]
    f = by_rule(run_rules(evs), "R-ACC-001")
    assert len(f) == 1 and f[0].mitre == []


def test_rules_skip_safely_when_fields_are_missing():
    out = run_rules([ev(0, message="just a message")])
    assert out.findings == []
    for rid in ("R-AUTH-001", "R-AUTH-002", "R-AUTH-003", "R-NET-001", "R-NET-003", "R-ACC-001"):
        assert rid in out.skipped and out.skipped[rid]


def test_correlation_combines_rules_sharing_an_entity_and_can_be_critical():
    evs = ([fail_login(i * 20) for i in range(6)] + [ok_login(150)] +
           [ev(1000 + i * 60, source_ip="10.0.1.10", destination_ip="203.0.113.99", username="admin", bytes_sent=30_000_000, event_type="network_connection") for i in range(2)])
    out = run_rules(evs)
    cor = by_rule(out, "R-COR-001")
    assert len(cor) == 1 and cor[0].severity == "Critical" and cor[0].detection_source == "correlation"
    assert not by_rule(run_rules(evs, DetectionConfig(correlation_enabled=False)), "R-COR-001")


def test_is_internal_treats_documentation_ranges_as_external():
    assert is_internal("10.1.2.3") and is_internal("192.168.1.1") and is_internal("172.16.5.5")
    assert not is_internal("203.0.113.5") and not is_internal("8.8.8.8") and not is_internal(None)


def test_config_validation():
    import pytest
    with pytest.raises(ValueError):
        DetectionConfig.from_dict({"failed_login_threshold": 0})
    with pytest.raises(ValueError):
        DetectionConfig.from_dict({"nonsense": 1})
    with pytest.raises(ValueError):
        DetectionConfig.from_dict({"suspicious_ips": ["not-an-ip"]})
    assert DetectionConfig.from_dict({"failed_login_threshold": 7}).failed_login_threshold == 7
