"""Generate the synthetic sample datasets (deterministic; seed fixed).

All data is fictional. External addresses use RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and internal hosts use RFC 1918 ranges, so nothing here refers to a real system.

Usage:  python sample_data/generate_sample_data.py   (run from the backend/ directory)
"""
from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent
BASE = datetime(2025, 3, 10, 0, 0, 0, tzinfo=timezone.utc)  # a Monday
rng = random.Random(1337)

USERS = {"alice": "10.0.5.11", "bob": "10.0.5.12", "carol": "10.0.5.13", "dave": "10.0.5.14",
         "erin": "10.0.5.15", "frank": "10.0.5.16", "grace": "10.0.5.17", "heidi": "10.0.5.18"}
EXTERNAL_OK = [f"203.0.113.{i}" for i in range(10, 31)] + [f"198.51.100.{i}" for i in range(100, 111)]
COLS = ["timestamp", "source", "src_ip", "dst_ip", "user", "event_type", "action", "status", "protocol",
        "dst_port", "bytes_out", "bytes_in", "message", "resource"]
rows: list[dict] = []


def at(h: int, m: int = 0, s: int = 0) -> datetime:
    return BASE + timedelta(hours=h, minutes=m, seconds=s)


def add(ts, source, src_ip=None, dst_ip=None, user=None, event_type=None, action=None, status=None, protocol=None,
        port=None, out=None, inb=None, message=None, resource=None):
    rows.append({"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": source, "src_ip": src_ip or "", "dst_ip": dst_ip or "",
                 "user": user or "", "event_type": event_type or "", "action": action or "", "status": status or "",
                 "protocol": protocol or "", "dst_port": "" if port is None else port, "bytes_out": "" if out is None else out,
                 "bytes_in": "" if inb is None else inb, "message": message or "", "resource": resource or ""})


# ---- Baseline (benign) activity ------------------------------------------------------------
for user, ip in USERS.items():
    for h, m in ((8, rng.randint(30, 59)), (12, rng.randint(0, 30)), (16, rng.randint(0, 40))):
        add(at(h, m, rng.randint(0, 59)), "vpn-gw01", ip, "10.0.1.10", user, "authentication", "login", "success", "tcp", 443,
            message=f"User {user} logged in")
    for _ in range(18):
        t = at(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
        kind = rng.choice(["web", "web", "web", "dns", "internal"])
        if kind == "web":
            add(t, "fw-edge01", ip, rng.choice(EXTERNAL_OK), user, "network_connection", "allow", "success", "tcp", rng.choice([443, 443, 80]),
                rng.randint(500, 40_000), rng.randint(5_000, 2_000_000), "Outbound web connection")
        elif kind == "dns":
            add(t, "fw-edge01", ip, "10.0.1.53", user, "network_connection", "allow", "success", "udp", 53, rng.randint(60, 200), rng.randint(100, 500), "DNS query")
        else:
            add(t, "fw-core01", ip, rng.choice(["10.0.1.20", "10.0.1.30"]), user, "network_connection", "allow", "success", "tcp",
                rng.choice([445, 5432]), rng.randint(2_000, 300_000), rng.randint(2_000, 900_000), "Internal service connection")
    for _ in range(3):
        add(at(rng.randint(9, 17), rng.randint(0, 59), rng.randint(0, 59)), "srv-files01", ip, "10.0.1.30", user, "resource_access", "file_read",
            "success", "tcp", 445, message="File read", resource=rng.choice(["/srv/files/projects/plan.docx", "/srv/files/hr/handbook.pdf", "/srv/files/finance/budget.xlsx"]))

# ---- Benign events that must NOT alert ---------------------------------------------------------
add(at(9, 40, 5), "vpn-gw01", USERS["erin"], "10.0.1.10", "erin", "authentication", "login", "failure", "tcp", 443, message="Failed password for erin (typo)")
add(at(9, 41, 2), "vpn-gw01", USERS["erin"], "10.0.1.10", "erin", "authentication", "login", "success", "tcp", 443, message="User erin logged in")
for k in range(2):
    add(at(10, 5, 10 * k), "vpn-gw01", USERS["frank"], "10.0.1.10", "frank", "authentication", "login", "failure", "tcp", 443, message="Failed password for frank")
add(at(10, 6, 0), "vpn-gw01", USERS["frank"], "10.0.1.10", "frank", "authentication", "login", "success", "tcp", 443, message="User frank logged in")
add(at(11, 30), "srv-files01", "10.0.1.30", "10.0.5.16", "frank", "network_connection", "allow", "success", "tcp", 445, 40_000_000, 10_000, "Large internal file transfer (to internal host)")
add(at(15, 0), "fw-edge01", USERS["grace"], "203.0.113.30", "grace", "network_connection", "allow", "success", "tcp", 443, 35_000_000, 20_000, "Cloud backup upload (below threshold)")
add(at(13, 15), "srv-files01", USERS["bob"], "10.0.1.30", "bob", "resource_access", "file_read", "denied", "tcp", 445, message="Access denied (single attempt)", resource="/admin/reports")

# ---- S1+S2: brute force then successful login (admin) -> R-AUTH-001, R-AUTH-002 ----------------
for i in range(12):
    add(at(2, 10, 20 * i), "srv-app01", "203.0.113.50", "10.0.1.10", "admin", "authentication", "login", "failure", "tcp", 22,
        message="Failed password for admin from 203.0.113.50")
add(at(2, 15, 30), "srv-app01", "203.0.113.50", "10.0.1.10", "admin", "authentication", "login", "success", "tcp", 22, message="Accepted password for admin from 203.0.113.50")
# ---- S7: sensitive resource attempts by admin after login -> R-ACC-001 --------------------------
add(at(2, 18), "srv-app01", "203.0.113.50", "10.0.1.10", "admin", "resource_access", "file_read", "success", "tcp", 22, message="Read file", resource="/etc/passwd")
for i, r in enumerate(["/etc/shadow", "/etc/shadow", "/home/svc_backup/.ssh/id_rsa", "/admin/keys"]):
    add(at(2, 20, 30 * i), "srv-app01", "203.0.113.50", "10.0.1.10", "admin", "resource_access", "file_read", "denied", "tcp", 22, message="Permission denied", resource=r)
# ---- S5: large outbound transfer from the same host/user -> R-NET-003 ---------------------------
for i in range(3):
    add(at(2, 40 + 5 * i), "fw-edge01", "10.0.1.10", "203.0.113.99", "admin", "network_connection", "allow", "success", "tcp", 443, 30_000_000, 40_000, "Large outbound transfer")

# ---- S3: password spray -> R-AUTH-001 (spray pattern) --------------------------------------------
for i, u in enumerate(list(USERS) + ["svc_backup"]):
    add(at(6, 0, 50 * i), "srv-app01", "192.0.2.77", "10.0.1.10", u, "authentication", "login", "failure", "tcp", 22, message=f"Failed password for {u} from 192.0.2.77")

# ---- S4: port scan -> R-NET-001 ---------------------------------------------------------------------
for i, p in enumerate(range(20, 50)):
    add(at(4, 30, 3 * i), "fw-edge01", "198.51.100.9", "10.0.2.20", None, "network_connection", "deny", "denied", "tcp", p, 60, 0, "Connection blocked by firewall")

# ---- S6: watchlisted IP -> R-NET-002 --------------------------------------------------------------
for i in range(3):
    add(at(14, 10 * i), "fw-edge01", "10.0.3.15", "203.0.113.66", "ivan", "network_connection", "allow", "success", "tcp", 8443, 40_000, 2_000, "Outbound connection")

# ---- S8: unusual authentication -> R-AUTH-003 ----------------------------------------------------------
for i, ip in enumerate(["198.51.100.31", "192.0.2.14", "203.0.113.140"]):
    add(at(11, 10 * i), "vpn-gw01", ip, "10.0.1.10", "carol", "authentication", "login", "success", "tcp", 443, message=f"User carol logged in from {ip}")
add(at(3, 12), "vpn-gw01", USERS["dave"], "10.0.1.10", "dave", "authentication", "login", "success", "tcp", 443, message="User dave logged in (off-hours)")

# ---- S9: statistical outliers that no rule covers (ML demo) -------------------------------------------
for i in range(3):
    add(at(3, 40 + 7 * i), "fw-core01", "10.0.4.44", "10.0.1.30", None, "network_connection", "tunnel", "success", "sctp", 9999, 9_000_000, 8_000_000, "Unusual internal tunnel-like session")

rows.sort(key=lambda r: r["timestamp"])
with (OUT / "sample_security_logs.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=COLS)
    w.writeheader()
    w.writerows(rows)

# ---- Second dataset: Windows-style JSON Lines (different field names, event codes) ---------------------
j: list[dict] = []
def win(ts, code, user, ip, host="WIN-DC01", extra=None):
    d = {"TimeCreated": ts.strftime("%Y-%m-%d %H:%M:%S"), "EventID": code, "Computer": host, "TargetUserName": user, "IpAddress": ip,
         "LogonType": 3, "Message": "An account failed to log on." if code == 4625 else "An account was successfully logged on."}
    d.update(extra or {})
    j.append(d)
for h, u in ((8, "svc_web"), (9, "tom"), (10, "tom"), (13, "svc_web"), (15, "tom")):
    win(at(h, 15), 4624, u, "10.0.9.5")
for i in range(6):
    win(at(5, 2, 40 * i), 4625, "svc_sql", "192.0.2.201")          # -> R-AUTH-001
win(at(5, 8, 0), 4624, "svc_sql", "192.0.2.201")                    # -> R-AUTH-002
(OUT / "sample_windows_auth.jsonl").write_text("\n".join(json.dumps(d) for d in j) + "\n", encoding="utf-8")
print(f"wrote {len(rows)} CSV rows and {len(j)} JSONL rows")
