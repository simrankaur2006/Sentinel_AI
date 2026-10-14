import re

import pytest

from app.mitre.mapping import build_mapping, load_mappings, merge_mappings


def test_all_mappings_are_well_formed():
    data = load_mappings()
    assert data["mappings"], "mapping file must not be empty"
    for key, m in data["mappings"].items():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", m["technique_id"]), key
        assert m["name"] and m["rationale"] and m["tactics"]
        assert all(re.fullmatch(r"TA\d{4}", t["id"]) and t["name"] for t in m["tactics"])
        assert m["technique_id"].replace(".", "/") in m["url"], key
        assert m["default_relation"] in data["relations"]


def test_known_ids_and_names():
    d = load_mappings()["mappings"]
    assert (d["brute_force"]["technique_id"], d["brute_force"]["name"]) == ("T1110", "Brute Force")
    assert d["valid_accounts"]["technique_id"] == "T1078"
    assert d["network_service_discovery"]["technique_id"] == "T1046"
    assert d["password_spraying"]["technique_id"] == "T1110.003"
    assert d["os_credential_dumping_passwd_shadow"]["technique_id"] == "T1003.008"


def test_build_mapping_records_observation_and_relation():
    m = build_mapping("valid_accounts", "5 failures then success")
    assert m["observed_behavior"] == "5 failures then success"
    assert m["relation"] == "potential_association"
    assert "plausible" in m["relation_meaning"].lower()
    assert build_mapping("brute_force", "x")["relation"] == "behavior_consistent"


def test_unknown_key_fails_loudly():
    with pytest.raises(KeyError):
        build_mapping("made_up", "x")


def test_merge_dedupes_by_technique():
    a, b = build_mapping("brute_force", "a"), build_mapping("brute_force", "b")
    assert len(merge_mappings([[a], [b]])) == 1
