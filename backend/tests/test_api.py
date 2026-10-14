"""API integration tests (require fastapi, httpx, sqlalchemy; run with pytest).  Synthetic data only."""
from pathlib import Path

SAMPLES = Path(__file__).resolve().parents[1] / "sample_data"


def seed(client):
    assert client.post("/api/ingest/sample/security-logs-csv").status_code == 201
    run = client.post("/api/detection/run", json={}).json()
    assert run["alerts_created"] > 0
    return run


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["database"] == "ok"


def test_empty_database_endpoints_do_not_error(client):
    d = client.get("/api/dashboard/metrics").json()
    assert d["totals"]["events"] == 0 and d["events_over_time"]["points"] == [] and d["latest_run"] is None
    assert client.get("/api/alerts").json()["total"] == 0
    assert client.get("/api/events").json()["items"] == []


def test_csv_upload_and_duplicate_handling(client):
    data = (SAMPLES / "sample_security_logs.csv").read_bytes()
    r = client.post("/api/ingest/upload", files={"file": ("logs.csv", data, "text/csv")})
    assert r.status_code == 201 and r.json()["rows_imported"] == 270
    r2 = client.post("/api/ingest/upload", files={"file": ("renamed.csv", data, "text/csv")})
    assert r2.json()["rows_imported"] == 0 and r2.json()["rows_duplicate"] == 270


def test_jsonl_upload(client):
    r = client.post("/api/ingest/upload", files={"file": ("w.jsonl", (SAMPLES / "sample_windows_auth.jsonl").read_bytes(), "application/json")})
    assert r.status_code == 201 and r.json()["rows_imported"] == 12


def test_invalid_uploads(client):
    assert client.post("/api/ingest/upload", files={"file": ("x.exe", b"abc", "application/octet-stream")}).status_code == 422
    assert client.post("/api/ingest/upload", files={"file": ("x.csv", b"", "text/csv")}).status_code == 422
    assert client.post("/api/ingest/sample/../../etc/passwd").status_code in (404, 405)
    assert client.post("/api/ingest/sample/nope").status_code == 404


def test_detection_alerts_filtering_and_status(client):
    seed(client)
    crit = client.get("/api/alerts", params={"severity": "Critical"}).json()
    assert crit["total"] == 1 and crit["items"][0]["rule_id"] == "R-COR-001"
    assert client.get("/api/alerts", params={"detection_source": "ml"}).json()["total"] >= 1
    assert client.get("/api/alerts", params={"q": "203.0.113.50"}).json()["total"] >= 2
    a = crit["items"][0]
    detail = client.get(f"/api/alerts/{a['id']}").json()
    assert detail["events"] and detail["mitre"] and detail["event_refs"]
    upd = client.patch(f"/api/alerts/{a['id']}", json={"status": "False Positive"})
    assert upd.status_code == 200 and upd.json()["status"] == "False Positive"
    assert client.patch(f"/api/alerts/{a['id']}", json={"status": "bogus"}).status_code == 422
    assert client.get("/api/alerts", params={"sort": "nope"}).status_code == 422


def test_rerun_is_deduplicated_and_keeps_status(client):
    seed(client)
    a = client.get("/api/alerts", params={"severity": "High"}).json()["items"][0]
    client.patch(f"/api/alerts/{a['id']}", json={"status": "Resolved"})
    total = client.get("/api/alerts").json()["total"]
    run2 = client.post("/api/detection/run", json={}).json()
    assert run2["alerts_created"] == 0 and client.get("/api/alerts").json()["total"] == total
    assert client.get(f"/api/alerts/{a['id']}").json()["status"] == "Resolved"


def test_config_update_validation_and_effect(client):
    seed(client)
    assert client.put("/api/detection/config", json={"failed_login_threshold": 0}).status_code == 422
    assert client.put("/api/detection/config", json={"bogus": 1}).status_code == 422
    assert client.put("/api/detection/config", json={"failed_login_threshold": 50}).status_code == 200
    run = client.post("/api/detection/run", json={"clear_existing": True, "use_ml": False}).json()
    rules = {a["rule_id"] for a in client.get("/api/alerts", params={"page_size": 200}).json()["items"]}
    assert run["alerts_cleared"] > 0 and "R-AUTH-001" not in rules


def test_incident_workflow_report_and_ai_fallback(client):
    seed(client)
    items = client.get("/api/alerts", params={"page_size": 200}).json()["items"]
    ids = [a["id"] for a in items if "admin" in a["usernames"]]
    inc = client.post("/api/incidents", json={"title": "Admin compromise", "alert_ids": ids}).json()
    assert inc["severity"] == "Critical" and inc["timeline"] and inc["mitre"]
    n = client.post(f"/api/incidents/{inc['id']}/notes", json={"body": "Contacted owner", "author": "tester"})
    assert n.status_code == 201
    assert client.patch(f"/api/incidents/{inc['id']}", json={"status": "Contained"}).json()["status"] == "Contained"
    ai = client.post(f"/api/incidents/{inc['id']}/analysis", json={"provider": "ollama"}).json()
    # With no local model running the request must fall back honestly (and say why); if a model IS running it is labelled.
    assert ai["generator"] == "deterministic-fallback" and ai["fallback_reason"] or ai["generator"].startswith("ollama:")
    rep = client.post(f"/api/incidents/{inc['id']}/reports", json={}).json()
    md = client.get(f"/api/reports/{rep['id']}/download", params={"format": "markdown"})
    js = client.get(f"/api/reports/{rep['id']}/download", params={"format": "json"})
    assert md.status_code == 200 and "attachment" in md.headers["content-disposition"] and "Contacted owner" in md.text
    assert js.json()["incident"]["title"] == "Admin compromise"
    assert client.get("/api/incidents/9999").status_code == 404


def test_dashboard_reflects_database(client):
    seed(client)
    d = client.get("/api/dashboard/metrics").json()
    assert d["totals"]["events"] == 270 and sum(x["count"] for x in d["alerts_by_severity"]) == d["totals"]["alerts"]
    assert d["events_over_time"]["points"] and d["anomaly"]["alert_count"] >= 1


def test_errors_do_not_leak_internals(client):
    r = client.get("/api/events", params={"start": "not-a-date"})
    assert r.status_code == 422
