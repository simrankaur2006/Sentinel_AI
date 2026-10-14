"""Parsing and normalization of uploaded security logs into the canonical event schema.

Pure Python (no web framework / DB). Uploaded content is treated strictly as untrusted data:
it is only decoded as text and parsed with csv/json; nothing is ever evaluated or executed.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SUPPORTED_EXTENSIONS = {".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl"}

# Canonical field -> accepted aliases (keys are normalized: lowercase, non-alphanumerics -> "_").
ALIASES: dict[str, list[str]] = {
    "timestamp": ["timestamp", "time", "datetime", "date_time", "_timestamp", "_time", "timecreated",
                  "time_created", "event_time", "eventtime", "ts", "created_at", "log_time", "date"],
    "source": ["source", "log_source", "sourcetype", "source_type", "host", "hostname", "computer",
               "computername", "device", "sensor", "system", "agent"],
    "source_ip": ["source_ip", "src_ip", "src", "srcip", "sourceip", "src_addr", "source_address",
                  "client_ip", "ipaddress", "ip_address", "ip", "remote_ip", "remote_addr", "c_ip",
                  "id_orig_h"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "dst", "destip", "destinationip",
                       "dst_addr", "destination_address", "server_ip", "id_resp_h", "target_ip"],
    "username": ["username", "user", "user_name", "account", "account_name", "targetusername",
                 "target_user_name", "subjectusername", "usr", "login"],
    "event_type": ["event_type", "type", "category", "event_category", "eventtype", "kind"],
    "action": ["action", "activity", "operation", "event_action", "verb"],
    "status": ["status", "result", "outcome", "event_outcome", "status_code"],
    "protocol": ["protocol", "proto", "network_protocol", "transport", "ip_protocol"],
    "port": ["port", "dst_port", "dest_port", "destination_port", "dport", "dstport", "target_port",
             "server_port", "id_resp_p"],
    "bytes_sent": ["bytes_sent", "bytes_out", "sent_bytes", "out_bytes", "src_bytes", "bytes_up",
                   "orig_bytes", "bytesout", "bytes_tx", "tx_bytes"],
    "bytes_received": ["bytes_received", "bytes_in", "recv_bytes", "received_bytes", "in_bytes",
                       "dst_bytes", "bytes_down", "resp_bytes", "bytesin", "bytes_rx", "rx_bytes"],
    "message": ["message", "msg", "description", "details", "log", "text", "event_message", "raw"],
    "event_id": ["event_id", "id", "uuid", "record_id", "log_id", "guid"],
}
# Windows security event codes with unambiguous meaning for this tool.
WINDOWS_CODES = {"4624": ("authentication", "success", "logon"), "4625": ("authentication", "failure", "logon")}

AUTH_TYPE_WORDS = {"login", "logon", "auth", "authentication", "authn", "signin", "sign_in", "ssh_login",
                   "user_login", "account_logon"}
NET_TYPE_WORDS = {"connection", "network", "netflow", "network_connection", "conn", "firewall", "traffic", "flow"}
RES_TYPE_WORDS = {"file_access", "resource_access", "access", "object_access", "web_access", "http_request", "file"}
SUCCESS_WORDS = {"success", "succeeded", "successful", "ok", "allowed", "accepted", "permit", "pass", "passed"}
FAILURE_WORDS = {"failure", "fail", "failed", "invalid", "error", "unsuccessful", "bad_password"}
DENIED_WORDS = {"denied", "deny", "blocked", "block", "rejected", "forbidden", "refused", "drop", "dropped"}
RESOURCE_KEYS = ("resource", "object", "path", "url", "file", "target", "uri")

MAX_META_KEYS = 50
MAX_META_VALUE_LEN = 1000
MAX_MESSAGE_LEN = 4000
MAX_STORED_ERRORS = 50


class IngestionError(ValueError):
    """Raised for file-level problems (bad extension, too large, undecodable, malformed)."""


@dataclass
class ParseResult:
    file_format: str
    rows_total: int = 0
    rows_invalid: int = 0
    warnings: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


def _norm_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_") if key is not None else ""


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        v = value.replace("\x00", "").strip()  # PostgreSQL cannot store NUL characters
        return None if v == "" or v.lower() in {"null", "none", "n/a", "na", "-", "nan"} else v
    return value


# ----------------------------------------------------------------------------- timestamps
_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S%z",
]


def parse_timestamp(value: Any) -> datetime | None:
    """Return an aware UTC datetime or None. Naive timestamps are assumed to be UTC."""
    value = _clean(value)
    if value is None:
        return None
    dt: datetime | None = None
    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            dt = _from_epoch(float(value))
        elif isinstance(value, str):
            s = value.strip()
            if re.fullmatch(r"\d{9,16}(\.\d+)?", s):
                dt = _from_epoch(float(s))
            else:
                try:
                    dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
                except ValueError:
                    for fmt in _TS_FORMATS:
                        try:
                            dt = datetime.strptime(s, fmt)
                            break
                        except ValueError:
                            continue
    except (ValueError, OverflowError, OSError):
        return None
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt if 1990 <= dt.year <= 2100 else None


def _from_epoch(x: float) -> datetime | None:
    if 1e9 <= x < 1e11:
        return datetime.fromtimestamp(x, tz=timezone.utc)
    if 1e11 <= x < 1e14:
        return datetime.fromtimestamp(x / 1000.0, tz=timezone.utc)
    if 1e14 <= x < 1e17:
        return datetime.fromtimestamp(x / 1_000_000.0, tz=timezone.utc)
    return None


# ----------------------------------------------------------------------------- field normalizers
def normalize_ip(value: Any) -> str | None:
    value = _clean(value)
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return None


def normalize_int(value: Any, lo: int, hi: int) -> int | None:
    value = _clean(value)
    if value is None or isinstance(value, bool):
        return None
    try:
        n = int(float(str(value).replace(",", "")))
    except ValueError:
        return None
    return n if lo <= n <= hi else None


def normalize_status(value: Any) -> str | None:
    value = _clean(value)
    if value is None:
        return None
    if isinstance(value, (int, float)) or re.fullmatch(r"\d{3}", str(value)):
        code = int(float(value))
        if 200 <= code < 400:
            return "success"
        if code in (401, 403):
            return "denied"
        if code >= 400:
            return "failure"
    s = _norm_key(value)
    if s in SUCCESS_WORDS:
        return "success"
    if s in FAILURE_WORDS:
        return "failure"
    if s in DENIED_WORDS:
        return "denied"
    return s[:64] or None


def normalize_event_type(value: Any) -> str | None:
    value = _clean(value)
    if value is None:
        return None
    s = _norm_key(value)
    if s in AUTH_TYPE_WORDS:
        return "authentication"
    if s in NET_TYPE_WORDS:
        return "network_connection"
    if s in RES_TYPE_WORDS:
        return "resource_access"
    return s[:64] or None


def _text(value: Any, limit: int) -> str | None:
    value = _clean(value)
    if value is None:
        return None
    return str(value)[:limit]


_MSG_FAIL = re.compile(r"failed password|authentication failure|invalid user|logon failure|login failed", re.I)
_MSG_OK = re.compile(r"accepted (password|publickey)|logon success|login succeeded|successful login", re.I)


# ----------------------------------------------------------------------------- record normalization
def normalize_record(raw: dict[str, Any], default_source: str | None = None) -> tuple[dict[str, Any] | None, str | None, int]:
    """Map one raw record to the canonical schema.

    Returns (event_dict | None, error_message | None, warning_count).
    """
    if not isinstance(raw, dict):
        return None, "record is not an object", 0
    warnings = 0
    keyed: dict[str, Any] = {}
    for k, v in raw.items():
        nk = _norm_key(k)
        if nk and nk not in keyed:
            keyed[nk] = v

    used: set[str] = set()
    picked: dict[str, Any] = {}
    for canon, names in ALIASES.items():
        for n in names:
            if n in keyed and _clean(keyed[n]) is not None:
                picked[canon] = keyed[n]
                used.add(n)
                break
        else:
            # mark empty alias columns as consumed so they do not clutter metadata
            for n in names:
                if n in keyed:
                    used.add(n)

    meta: dict[str, Any] = {}
    inferred: list[str] = []

    code = _clean(keyed.get("eventid"))
    if code is not None:
        used.add("eventid")
        meta["event_code"] = str(code)[:32]

    ts = parse_timestamp(picked.get("timestamp"))
    if ts is None:
        why = "missing timestamp" if picked.get("timestamp") is None else "unparseable timestamp"
        return None, why, 0

    ev: dict[str, Any] = {"timestamp": ts}
    ev["event_id"] = _text(picked.get("event_id"), 128)
    ev["source"] = _text(picked.get("source"), 255) or default_source
    ev["username"] = _text(picked.get("username"), 255)
    ev["action"] = _text(picked.get("action"), 128)
    ev["action"] = ev["action"].lower() if ev["action"] else None
    ev["protocol"] = (_text(picked.get("protocol"), 32) or "").lower() or None
    ev["message"] = _text(picked.get("message"), MAX_MESSAGE_LEN)

    for fld in ("source_ip", "destination_ip"):
        raw_v = _clean(picked.get(fld))
        ev[fld] = normalize_ip(raw_v)
        if raw_v is not None and ev[fld] is None:
            meta[f"raw_{fld}"] = str(raw_v)[:100]
            warnings += 1
    ev["port"] = normalize_int(picked.get("port"), 0, 65535)
    if _clean(picked.get("port")) is not None and ev["port"] is None:
        warnings += 1
    for fld in ("bytes_sent", "bytes_received"):
        ev[fld] = normalize_int(picked.get(fld), 0, 10**13)
        if _clean(picked.get(fld)) is not None and ev[fld] is None:
            warnings += 1

    ev["status"] = normalize_status(picked.get("status"))
    ev["event_type"] = normalize_event_type(picked.get("event_type"))

    if code is not None and str(code).strip() in WINDOWS_CODES:
        et, st, act = WINDOWS_CODES[str(code).strip()]
        if ev["event_type"] is None:
            ev["event_type"] = et
            inferred.append("event_type")
        if ev["status"] is None:
            ev["status"] = st
            inferred.append("status")
        ev["action"] = ev["action"] or act

    # Light, clearly-flagged inference from free-text messages (syslog-style sources).
    msg = ev["message"] or ""
    if ev["status"] is None and msg:
        if _MSG_FAIL.search(msg):
            ev["status"] = "failure"; inferred.append("status")
            if ev["event_type"] is None:
                ev["event_type"] = "authentication"; inferred.append("event_type")
        elif _MSG_OK.search(msg):
            ev["status"] = "success"; inferred.append("status")
            if ev["event_type"] is None:
                ev["event_type"] = "authentication"; inferred.append("event_type")
    if ev["event_type"] is None and ev["action"] in AUTH_TYPE_WORDS:
        ev["event_type"] = "authentication"; inferred.append("event_type")

    # Everything not mapped goes to additional_metadata (bounded).
    for nk, v in keyed.items():
        if nk in used or nk == "eventid":
            continue
        v = _clean(v)
        if v is None or len(meta) >= MAX_META_KEYS:
            continue
        meta[nk] = v if isinstance(v, (int, float, bool)) else str(v).replace("\x00", "")[:MAX_META_VALUE_LEN]
    if ev["event_type"] is None:
        res = next((meta[k] for k in RESOURCE_KEYS if k in meta), None)
        if res is not None:
            ev["event_type"] = "resource_access"; inferred.append("event_type")
        elif ev["destination_ip"] and ev["port"] is not None:
            ev["event_type"] = "network_connection"; inferred.append("event_type")
    if inferred:
        meta["inferred_fields"] = sorted(set(inferred))

    if not any(ev.get(k) for k in ("event_type", "action", "status", "message")):
        return None, "record has no event_type, action, status or message", warnings

    ev["additional_metadata"] = meta
    return ev, None, warnings


def event_fingerprint(ev: dict[str, Any], occurrence: int = 0) -> str:
    parts = [ev["timestamp"].isoformat()] + [
        str(ev.get(k)) for k in ("event_id", "source", "source_ip", "destination_ip", "username", "event_type",
                                 "action", "status", "protocol", "port", "bytes_sent", "bytes_received", "message")
    ]
    parts.append(json.dumps(ev.get("additional_metadata", {}), sort_keys=True, default=str))
    parts.append(str(occurrence))
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------- file-level parsing
def _extension(filename: str) -> str:
    name = (filename or "").lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def parse_upload(filename: str, content: bytes, *, max_bytes: int = 10 * 1024 * 1024, max_rows: int = 50_000) -> ParseResult:
    """Parse an uploaded CSV / JSON / JSONL file into normalized event dicts.

    Raises IngestionError for file-level problems. Row-level problems are collected in the result.
    """
    ext = _extension(filename)
    if ext not in SUPPORTED_EXTENSIONS:
        raise IngestionError(f"Unsupported file type '{ext or 'none'}'. Supported: .csv, .json, .jsonl, .ndjson.")
    if len(content) == 0:
        raise IngestionError("The file is empty.")
    if len(content) > max_bytes:
        raise IngestionError(f"File is too large ({len(content)} bytes). Limit is {max_bytes} bytes.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestionError("File is not valid UTF-8 text.") from exc

    fmt = SUPPORTED_EXTENSIONS[ext]
    records = _read_records(text, fmt, max_rows)
    result = ParseResult(file_format=fmt)
    default_source = f"file:{filename.rsplit('/', 1)[-1].rsplit(chr(92), 1)[-1][:200]}"
    counts: dict[str, int] = {}
    for idx, raw in enumerate(records, start=1):
        result.rows_total += 1
        ev, err, warn = normalize_record(raw, None)
        result.warnings += warn
        if ev is None:
            result.rows_invalid += 1
            if len(result.errors) < MAX_STORED_ERRORS:
                result.errors.append({"row": idx, "message": err})
            continue
        base = event_fingerprint(ev, 0)
        n = counts.get(base, 0)
        counts[base] = n + 1
        ev["fingerprint"] = base if n == 0 else event_fingerprint(ev, n)
        # The filename-derived default source is applied AFTER fingerprinting so the same content uploaded
        # under a different file name is still recognised as a duplicate.
        ev["source"] = ev["source"] or default_source
        result.events.append(ev)
    if result.rows_total == 0:
        raise IngestionError("The file contains no records.")
    if result.rows_total == result.rows_invalid:
        first = result.errors[0]["message"] if result.errors else "unknown"
        raise IngestionError(f"No valid records found. First problem: {first}. "
                             "Required: a parseable timestamp plus at least one of event_type, action, status or message.")
    return result


def _read_records(text: str, fmt: str, max_rows: int) -> list[Any]:
    if fmt == "csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise IngestionError("CSV has no header row.")
        rows: list[Any] = []
        try:
            for row in reader:
                row.pop(None, None)  # extra unnamed columns
                rows.append(row)
                if len(rows) > max_rows:
                    raise IngestionError(f"Too many rows. Limit is {max_rows}.")
        except csv.Error as exc:
            raise IngestionError(f"Malformed CSV: {exc}") from exc
        return rows
    if fmt == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return _read_jsonl(text, max_rows, strict_hint=True)
        if isinstance(data, dict):
            for k in ("events", "records", "logs", "data", "items"):
                if isinstance(data.get(k), list):
                    data = data[k]
                    break
            else:
                data = [data]
        if not isinstance(data, list):
            raise IngestionError("JSON must be an array of objects (or an object containing an 'events' array).")
        if len(data) > max_rows:
            raise IngestionError(f"Too many rows. Limit is {max_rows}.")
        return data
    return _read_jsonl(text, max_rows)


def _read_jsonl(text: str, max_rows: int, strict_hint: bool = False) -> list[Any]:
    rows: list[Any] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            hint = " (file is not valid JSON or JSON Lines)" if strict_hint else ""
            raise IngestionError(f"Invalid JSON on line {lineno}: {exc.msg}{hint}.") from exc
        if len(rows) > max_rows:
            raise IngestionError(f"Too many rows. Limit is {max_rows}.")
    return rows
