import json

import pytest

from app.ingestion.parser import IngestionError, normalize_record, parse_timestamp, parse_upload


def test_csv_aliases_are_mapped_to_canonical_fields():
    data = b"Time,src_ip,dst_ip,user,dst_port,bytes_out,result,msg\n2025-03-10 10:00:00,10.0.0.5,203.0.113.5,alice,443,1200,Failed,hello\n"
    r = parse_upload("a.csv", data)
    e = r.events[0]
    assert (e["source_ip"], e["destination_ip"], e["username"], e["port"], e["bytes_sent"], e["status"]) == \
        ("10.0.0.5", "203.0.113.5", "alice", 443, 1200, "failure")
    assert e["timestamp"].tzinfo is not None
    assert e["source"] == "file:a.csv"  # default event source = originating file when the log has none


def test_json_array_and_wrapped_object_and_jsonl():
    rec = {"timestamp": "2025-03-10T10:00:00Z", "event_type": "login", "status": "ok", "src": "10.0.0.1"}
    assert parse_upload("a.json", json.dumps([rec]).encode()).events[0]["event_type"] == "authentication"
    assert len(parse_upload("a.json", json.dumps({"events": [rec, rec]}).encode()).events) == 2
    assert len(parse_upload("a.jsonl", (json.dumps(rec) + "\n" + json.dumps(rec) + "\n").encode()).events) == 2


def test_windows_event_codes_are_interpreted_but_flagged_as_inferred():
    r = parse_upload("w.jsonl", json.dumps({"TimeCreated": "2025-03-10 05:00:00", "EventID": 4625, "IpAddress": "192.0.2.1", "TargetUserName": "bob"}).encode())
    e = r.events[0]
    assert e["event_type"] == "authentication" and e["status"] == "failure"
    assert "status" in e["additional_metadata"]["inferred_fields"]
    assert e["additional_metadata"]["event_code"] == "4625"


@pytest.mark.parametrize("value", ["2025-03-10T10:00:00Z", "2025-03-10 10:00:00", 1741600800, "1741600800000", "10/Mar/2025:10:00:00 +0000"])
def test_timestamp_formats_normalize_to_utc(value):
    ts = parse_timestamp(value)
    assert ts is not None and ts.utcoffset().total_seconds() == 0 and ts.year == 2025


def test_invalid_timestamp_rows_are_reported_not_fatal():
    data = b"timestamp,event_type,status\n2025-03-10 10:00:00,login,ok\nnot-a-date,login,ok\n,login,ok\n"
    r = parse_upload("a.csv", data)
    assert r.rows_total == 3 and r.rows_invalid == 2 and len(r.events) == 1
    assert {e["message"] for e in r.errors} == {"unparseable timestamp", "missing timestamp"}


def test_invalid_optional_values_become_none_with_warning():
    e, err, warn = normalize_record({"timestamp": "2025-03-10 10:00:00", "event_type": "x", "src_ip": "999.1.1.1", "port": "70000", "bytes_out": "-5"})
    assert err is None and e["source_ip"] is None and e["port"] is None and e["bytes_sent"] is None and warn == 3
    assert e["additional_metadata"]["raw_source_ip"] == "999.1.1.1"


def test_missing_values_are_safe():
    e, err, _ = normalize_record({"timestamp": "2025-03-10 10:00:00", "message": "only a message"})
    assert err is None and e["username"] is None and e["port"] is None


@pytest.mark.parametrize("name,content,fragment", [
    ("a.exe", b"x", "Unsupported file type"),
    ("a.csv", b"", "empty"),
    ("a.csv", b"\xff\xfe\x00bad", "UTF-8"),
    ("a.json", b"{not json", "Invalid JSON"),
    ("a.csv", b"timestamp,event_type\nbad,login\n", "No valid records"),
])
def test_invalid_uploads_raise_clear_errors(name, content, fragment):
    with pytest.raises(IngestionError) as exc:
        parse_upload(name, content)
    assert fragment in str(exc.value)


def test_size_and_row_limits():
    with pytest.raises(IngestionError):
        parse_upload("a.csv", b"timestamp,event_type\n" + b"2025-03-10 10:00:00,x\n" * 10, max_bytes=50)
    with pytest.raises(IngestionError):
        parse_upload("a.csv", b"timestamp,event_type\n" + b"2025-03-10 10:00:00,x\n" * 10, max_rows=5)


def test_fingerprints_are_stable_and_identical_rows_in_one_file_are_kept():
    row = b"2025-03-10 10:00:00,failed,203.0.113.5\n"
    data = b"timestamp,status,src_ip\n" + row * 3
    a = parse_upload("a.csv", data)
    b = parse_upload("b.csv", data)
    fps = [e["fingerprint"] for e in a.events]
    assert len(set(fps)) == 3  # repeated identical lines are distinct events within one file
    assert fps == [e["fingerprint"] for e in b.events]  # but re-uploading yields the same fingerprints (dedup)


def test_file_content_is_never_evaluated():
    payload = b'timestamp,event_type,message\n2025-03-10 10:00:00,x,"=cmd|\' /C calc\'!A0; __import__(\'os\').system(\'id\')"\n'
    e = parse_upload("a.csv", payload).events[0]
    assert e["message"].startswith("=cmd")  # stored verbatim as inert text


def test_nul_characters_are_stripped_so_postgres_can_store_them():
    data = b'timestamp,event_type,message,extra\n2025-03-10 10:00:00,x,"bad\x00msg","a\x00b"\n'
    e = parse_upload("a.csv", data).events[0]
    assert "\x00" not in e["message"] and "\x00" not in str(e["additional_metadata"])
