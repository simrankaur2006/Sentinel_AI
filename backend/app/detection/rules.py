"""Deterministic, explainable detection rules.

Every rule:
  * reads only canonical Event objects (pure Python, easy to unit test),
  * is configurable through DetectionConfig,
  * attaches the exact events that triggered it as evidence,
  * states its limitations, and
  * is skipped (with a recorded reason) when the log fields it needs are absent.

A rule match is a lead for an analyst. It is never proof that an attack happened or succeeded.
"""
from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Iterable

from app.detection.config import DetectionConfig
from app.domain import Event, Finding
from app.mitre.mapping import build_mapping, merge_mappings

MAX_EVIDENCE = 500  # evidence events stored per alert (the alert records the true total)

FAIL_STATUSES = {"failure", "denied"}

RULE_CATALOG: dict[str, dict[str, str]] = {
    "R-AUTH-001": {
        "name": "Repeated failed logins",
        "requires": "event_type=authentication, status=failure; source_ip or username",
        "logic": "N or more failed authentication events from one source IP (or one user if no IP) within a sliding window.",
        "limitations": "Shared NAT/proxy addresses, misconfigured services and locked-out users can look like brute force. Low-and-slow attacks below the threshold are missed.",
    },
    "R-AUTH-002": {
        "name": "Successful login after repeated failures",
        "requires": "authentication events with username and status",
        "logic": "A successful login for a user preceded by at least N failures for that user (from the same IP when known) inside a window.",
        "limitations": "A legitimate user who forgot their password matches this pattern. The rule cannot tell whose hands were on the keyboard.",
    },
    "R-AUTH-003": {
        "name": "Unusual authentication activity",
        "requires": "successful authentication events with username; source_ip for the multi-origin check",
        "logic": "(a) Successful logins for one user from N or more distinct IPs inside a window. (b) Successful login during configured off-hours for a user whose other logins occur outside those hours.",
        "limitations": "VPNs, mobile networks, travel and shift work are common benign causes. The baseline is limited to the uploaded data, not long-term history.",
    },
    "R-NET-001": {
        "name": "Potential port scan",
        "requires": "source_ip and port",
        "logic": "One source IP contacting N or more distinct ports inside a sliding window.",
        "limitations": "Authorized vulnerability scanners, load balancers and some applications produce the same pattern. Slow scans are missed. This tool never scans networks itself.",
    },
    "R-NET-002": {
        "name": "Connection involving a watchlisted IP",
        "requires": "source_ip or destination_ip",
        "logic": "Any event whose source or destination matches an IP/CIDR in the configured watchlist.",
        "limitations": "Only as good as the watchlist. Addresses can be reassigned or shared; a hit shows contact, not compromise.",
    },
    "R-NET-003": {
        "name": "Unusual outbound traffic volume",
        "requires": "bytes_sent and destination_ip",
        "logic": "Total bytes sent by one source to non-internal destinations meets the threshold inside a window.",
        "limitations": "Backups, software updates and legitimate uploads cause large transfers. The rule sees volume only, not content.",
    },
    "R-ACC-001": {
        "name": "Access attempts on sensitive resources",
        "requires": "a resource/path/url/object field (stored in additional_metadata) and status",
        "logic": "N or more denied/failed accesses matching configured sensitive patterns by one user (or IP) inside a window.",
        "limitations": "Pattern matching is substring-based and can match benign paths. Successful accesses are not flagged on their own.",
    },
    "R-COR-001": {
        "name": "Correlated multi-stage activity",
        "requires": "two or more distinct rule findings sharing an IP address or username",
        "logic": "Findings from different rules that involve the same IP or user are combined into one higher-priority alert.",
        "limitations": "Sharing an IP or username is circumstantial. Correlation raises priority; it does not establish a single attacker or an attack chain.",
    },
}


@dataclass
class DetectionOutcome:
    findings: list[Finding] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    events_analyzed: int = 0
    rules_run: list[str] = field(default_factory=list)


# ----------------------------------------------------------------------------- helpers
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(ip: str | None) -> bool:
    """RFC1918 / loopback / link-local. Documentation ranges (TEST-NET) count as external on purpose."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _INTERNAL)


def _fp(rule_id: str, key: str, first_seen: Any) -> str:
    return hashlib.sha256(f"{rule_id}|{key}|{first_seen.isoformat()}".encode()).hexdigest()[:40]


def _is_auth(e: Event) -> bool:
    return e.event_type == "authentication"


def _sorted(events: Iterable[Event]) -> list[Event]:
    return sorted(events, key=lambda e: (e.timestamp, e.pk or 0))


def gap_clusters(events: list[Event], gap_minutes: int) -> list[list[Event]]:
    out: list[list[Event]] = []
    gap = timedelta(minutes=gap_minutes)
    for e in _sorted(events):
        if out and e.timestamp - out[-1][-1].timestamp <= gap:
            out[-1].append(e)
        else:
            out.append([e])
    return out


class _CountAgg:
    def __init__(self, thr: int):
        self.n, self.thr = 0, thr
    def add(self, e: Event): self.n += 1
    def remove(self, e: Event): self.n -= 1
    def ok(self) -> bool: return self.n >= self.thr


class _DistinctAgg:
    def __init__(self, attr: str, thr: int):
        self.attr, self.thr, self.c = attr, thr, Counter()
    def add(self, e: Event):
        v = getattr(e, self.attr)
        if v is not None: self.c[v] += 1
    def remove(self, e: Event):
        v = getattr(e, self.attr)
        if v is not None:
            self.c[v] -= 1
            if self.c[v] <= 0: del self.c[v]
    def ok(self) -> bool: return len(self.c) >= self.thr


class _SumAgg:
    def __init__(self, attr: str, thr: int):
        self.attr, self.thr, self.s = attr, thr, 0
    def add(self, e: Event): self.s += getattr(e, self.attr) or 0
    def remove(self, e: Event): self.s -= getattr(e, self.attr) or 0
    def ok(self) -> bool: return self.s >= self.thr


def qualifying_bursts(events: list[Event], window_minutes: int, agg: Any) -> list[list[Event]]:
    """Return merged groups of events where a sliding time window satisfied `agg.ok()`.

    Unlike gap clustering, this enforces the true "N within W minutes" semantics, so a slow trickle
    of events over hours does not qualify.
    """
    evs = _sorted(events)
    window = timedelta(minutes=window_minutes)
    left = 0
    intervals: list[tuple[int, int]] = []
    for right, e in enumerate(evs):
        agg.add(e)
        while e.timestamp - evs[left].timestamp > window:
            agg.remove(evs[left])
            left += 1
        if agg.ok():
            intervals.append((left, right))
    merged: list[list[int]] = []
    for s, t in intervals:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], t)
        else:
            merged.append([s, t])
    return [evs[s : t + 1] for s, t in merged]


def _make(rule_id: str, source: str, key: str, title: str, description: str, severity: str, confidence: float,
          evidence: list[Event], explanation: str, steps: list[str], usernames: Iterable[str | None] = (),
          ips: Iterable[str | None] = (), mitre: list[dict[str, Any]] | None = None,
          details: dict[str, Any] | None = None, kind: str = "heuristic_strength") -> Finding:
    ev = _sorted(evidence)
    hosts = Counter(e.source for e in ev if e.source)
    first, last = ev[0].timestamp, ev[-1].timestamp
    d = dict(details or {})
    d["evidence_total"] = len(ev)
    return Finding(
        rule_id=rule_id, detection_source=source, title=title, description=description, severity=severity,
        confidence=round(max(0.0, min(1.0, confidence)), 3), confidence_kind=kind, first_seen=first, last_seen=last,
        evidence=ev[:MAX_EVIDENCE], explanation=explanation, recommended_steps=steps,
        limitations=RULE_CATALOG[rule_id]["limitations"], fingerprint=_fp(rule_id, key, first),
        usernames=sorted({u for u in usernames if u}), ips=sorted({i for i in ips if i}),
        host=hosts.most_common(1)[0][0] if hosts else None, mitre=mitre or [], details=d,
    )


def _span(ev: list[Event]) -> str:
    ev = _sorted(ev)
    return f"{ev[0].timestamp.strftime('%Y-%m-%d %H:%M:%S')} to {ev[-1].timestamp.strftime('%H:%M:%S')} UTC"


# ----------------------------------------------------------------------------- rules
def rule_failed_logins(events: list[Event], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-AUTH-001"
    fails = [e for e in events if _is_auth(e) and e.status in FAIL_STATUSES]
    if not any(_is_auth(e) for e in events):
        out.skipped[rid] = "No events with event_type=authentication were found."
        return
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in fails:
        if e.source_ip:
            groups[("ip", e.source_ip)].append(e)
        elif e.username:
            groups[("user", e.username)].append(e)
    for (kind, key), evs in groups.items():
        for burst in qualifying_bursts(evs, cfg.failed_login_window_minutes, _CountAgg(cfg.failed_login_threshold)):
            users = sorted({e.username for e in burst if e.username})
            n = len(burst)
            spray = kind == "ip" and len(users) >= 3 and n / max(len(users), 1) <= 3
            who = f"IP {key}" if kind == "ip" else f"user {key}"
            sev = "High" if n >= 3 * cfg.failed_login_threshold else "Medium"
            mitre = [build_mapping("brute_force", f"{n} failed authentication events from {who} ({_span(burst)}).")]
            if spray:
                mitre.append(build_mapping("password_spraying",
                                           f"The failures targeted {len(users)} distinct accounts with few attempts each."))
            elif users:
                mitre.append(build_mapping("password_guessing", f"The failures targeted {len(users)} account(s)."))
            out.findings.append(_make(
                rid, "rule", f"{kind}:{key}", f"Repeated failed logins from {who}" if kind == "ip" else f"Repeated failed logins for {key}",
                f"{n} failed authentication events from {who} within {cfg.failed_login_window_minutes} minutes "
                f"({_span(burst)}). Accounts involved: {', '.join(users) or 'unknown'}.",
                sev, n / (2 * cfg.failed_login_threshold), burst,
                f"Rule {rid}: at least {cfg.failed_login_threshold} failed authentication events within "
                f"{cfg.failed_login_window_minutes} minutes were seen for the same {'source IP' if kind == 'ip' else 'username'}. "
                + ("The attempts spread across many accounts, a pattern consistent with password spraying." if spray else "")
                , ["Confirm whether the source is a known system, VPN/NAT egress or scanner.",
                   "Check whether any of the targeted accounts later logged in successfully (see R-AUTH-002).",
                   "Review account lockout status for the accounts involved.",
                   "If the source is not trusted, consider rate-limiting or temporarily blocking it after validation."],
                users, [key] if kind == "ip" else [e.source_ip for e in burst], mitre,
                {"failed_count": n, "distinct_users": len(users), "pattern": "spray" if spray else "repeated_failures"}))


def rule_success_after_failures(events: list[Event], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-AUTH-002"
    auth = [e for e in events if _is_auth(e) and e.username]
    if not auth:
        out.skipped[rid] = "No authentication events with a username were found."
        return
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in auth:
        by_user[e.username].append(e)  # type: ignore[index]
    window = timedelta(minutes=cfg.success_after_failures_window_minutes)
    for user, evs in by_user.items():
        evs = _sorted(evs)
        fails = [e for e in evs if e.status in FAIL_STATUSES]
        used: set[int] = set()
        for s in (e for e in evs if e.status == "success"):
            cands = [f for f in fails if id(f) not in used and timedelta(0) <= s.timestamp - f.timestamp <= window
                     and f.timestamp <= s.timestamp
                     and (not f.source_ip or not s.source_ip or f.source_ip == s.source_ip)]
            if len(cands) < cfg.success_after_failures_min:
                continue
            used.update(id(f) for f in cands)
            ip = s.source_ip
            n = len(cands)
            ev = cands + [s]
            out.findings.append(_make(
                rid, "rule", f"user:{user}|ip:{ip}", f"Successful login for {user} after {n} failed attempts",
                f"User {user} logged in successfully at {s.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC"
                f"{' from ' + ip if ip else ''} after {n} failed attempts in the preceding "
                f"{cfg.success_after_failures_window_minutes} minutes.",
                "High", n / (2 * cfg.success_after_failures_min), ev,
                f"Rule {rid}: a successful authentication followed at least {cfg.success_after_failures_min} failures "
                "for the same user (same source IP when known) inside the window. This ordering is what a successful "
                "guess would look like, but it is also what a user who mistyped a password looks like.",
                ["Contact the account owner through a separate channel to confirm the login.",
                 "Review activity by this account after the login time (commands, file access, new sessions).",
                 "Check whether the source IP is also tied to other alerts.",
                 "If the login is not confirmed, consider resetting credentials and revoking active sessions."],
                [user], [ip] + [f.source_ip for f in cands],
                [build_mapping("valid_accounts", f"Successful login after {n} failures for the same account.")],
                {"failed_before_success": n, "success_event": s.key()}))


def _in_offhours(hour: int, start: int, end: int) -> bool:
    return start <= hour < end if start <= end else (hour >= start or hour < end)


def rule_unusual_auth(events: list[Event], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-AUTH-003"
    succ = [e for e in events if _is_auth(e) and e.status == "success" and e.username]
    if not succ:
        out.skipped[rid] = "No successful authentication events with a username were found."
        return
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in succ:
        by_user[e.username].append(e)  # type: ignore[index]
    for user, evs in by_user.items():
        with_ip = [e for e in evs if e.source_ip]
        for burst in qualifying_bursts(with_ip, cfg.multi_ip_window_minutes, _DistinctAgg("source_ip", cfg.multi_ip_login_threshold)):
            ips = sorted({e.source_ip for e in burst if e.source_ip})
            out.findings.append(_make(
                rid, "rule", f"multi_ip|{user}", f"Logins for {user} from {len(ips)} different IPs in a short time",
                f"User {user} authenticated successfully from {len(ips)} distinct IPs ({', '.join(ips)}) within "
                f"{cfg.multi_ip_window_minutes} minutes ({_span(burst)}).", "Medium", len(ips) / (2 * cfg.multi_ip_login_threshold), burst,
                f"Rule {rid}(a): successful logins from at least {cfg.multi_ip_login_threshold} distinct source IPs for one user inside the window.",
                ["Ask the user whether they were switching networks (VPN, mobile, office).",
                 "Compare the IPs' geolocation/ownership and look for impossible travel.",
                 "Review the account's activity from each IP."],
                [user], ips, [build_mapping("valid_accounts", f"Successful logins for one account from {len(ips)} distinct IPs in a short window.")],
                {"distinct_ips": len(ips), "check": "multi_ip"}))
        normal = [e for e in evs if not _in_offhours(e.timestamp.hour, cfg.offhours_start_hour, cfg.offhours_end_hour)]
        odd = [e for e in evs if _in_offhours(e.timestamp.hour, cfg.offhours_start_hour, cfg.offhours_end_hour)]
        if len(normal) >= cfg.offhours_min_baseline_logins and odd:
            per_day: dict[Any, list[Event]] = defaultdict(list)
            for e in odd:
                per_day[e.timestamp.date()].append(e)
            for day, devs in per_day.items():
                out.findings.append(_make(
                    rid, "rule", f"offhours|{user}|{day}", f"Off-hours login for {user}",
                    f"User {user} logged in successfully during off-hours "
                    f"({cfg.offhours_start_hour:02d}:00-{cfg.offhours_end_hour:02d}:00 UTC) on {day}, while "
                    f"{len(normal)} other logins in the data occurred outside those hours.", "Low", 0.3, devs,
                    f"Rule {rid}(b): successful login inside the configured off-hours window for a user whose "
                    f"other logins (at least {cfg.offhours_min_baseline_logins}) fall outside it.",
                    ["Confirm with the user or their manager whether the access was expected (on-call, travel).",
                     "Check the source IP against the user's usual locations."],
                    [user], [e.source_ip for e in devs],
                    [build_mapping("valid_accounts", "Login at an hour that differs from this account's other logins.", "potential_association")],
                    {"check": "off_hours", "baseline_logins": len(normal)}))


def rule_port_scan(events: list[Event], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-NET-001"
    cand = [e for e in events if e.source_ip and e.port is not None]
    if not cand:
        out.skipped[rid] = "No events contain both source_ip and port."
        return
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in cand:
        by_ip[e.source_ip].append(e)  # type: ignore[index]
    for ip, evs in by_ip.items():
        for burst in qualifying_bursts(evs, cfg.portscan_window_minutes, _DistinctAgg("port", cfg.portscan_distinct_ports)):
            ports = {e.port for e in burst}
            dests = sorted({e.destination_ip for e in burst if e.destination_ip})
            sev = "High" if len(ports) >= 5 * cfg.portscan_distinct_ports else "Medium"
            out.findings.append(_make(
                rid, "rule", f"ip:{ip}", f"Possible port scan from {ip}",
                f"{ip} contacted {len(ports)} distinct ports on {len(dests) or 'unknown'} destination(s) within "
                f"{cfg.portscan_window_minutes} minutes ({_span(burst)}).", sev, len(ports) / (2 * cfg.portscan_distinct_ports), burst,
                f"Rule {rid}: one source contacted at least {cfg.portscan_distinct_ports} distinct ports inside the window.",
                ["Check whether the source is an authorized scanner or monitoring system.",
                 "Review firewall/IDS logs for the same source before and after the window.",
                 "Check which targeted ports responded (open services), if the logs show it.",
                 "If unauthorized, consider blocking the source after validation."],
                [e.username for e in burst], [ip] + dests,
                [build_mapping("network_service_discovery", f"{len(ports)} distinct ports contacted by one source in {cfg.portscan_window_minutes} minutes.")],
                {"distinct_ports": len(ports), "destinations": dests[:20]}))


def rule_watchlist(events: list[Event], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-NET-002"
    nets = []
    for entry in cfg.suspicious_ips:
        try:
            nets.append((entry, ipaddress.ip_network(entry, strict=False)))
        except ValueError:
            continue
    if not nets:
        out.skipped[rid] = "The suspicious IP watchlist is empty."
        return
    if not any(e.source_ip or e.destination_ip for e in events):
        out.skipped[rid] = "No events contain source_ip or destination_ip."
        return
    hits: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        for ip in (e.source_ip, e.destination_ip):
            if not ip:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in net for _, net in nets):
                hits[ip].append(e)
    for ip, evs in hits.items():
        for cl in gap_clusters(list({id(e): e for e in evs}.values()), cfg.suspicious_ip_window_minutes):
            outbound = [e for e in cl if e.destination_ip == ip and e.status == "success" and (e.bytes_sent or 0) > 0 and is_internal(e.source_ip)]
            internal_hosts = sorted({e.source_ip for e in cl if e.source_ip and e.source_ip != ip})
            out.findings.append(_make(
                rid, "rule", f"watch:{ip}", f"Activity involving watchlisted IP {ip}",
                f"{len(cl)} event(s) involve {ip}, which is on the configured watchlist ({_span(cl)}). "
                f"{len(outbound)} successful outbound connection(s) sent data to it. Hosts involved: {', '.join(internal_hosts) or 'unknown'}.",
                "High" if outbound else "Medium", min(1.0, 0.4 + 0.1 * len(cl)), cl,
                f"Rule {rid}: an event source or destination matched the watchlist entry covering {ip}.",
                ["Verify the watchlist entry's source and age; entries can become stale.",
                 "Identify the internal host(s) and the process or user behind the connection.",
                 "Review other traffic from the same host(s) in the surrounding hours.",
                 "If confirmed malicious, isolate the host per your incident response process."],
                [e.username for e in cl], [ip] + internal_hosts,
                [build_mapping("application_layer_protocol", f"{len(cl)} event(s) involved a watchlisted address.")] if outbound else [],
                {"watchlisted_ip": ip, "outbound_successes": len(outbound)}))


def rule_outbound_volume(events: list[Event], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-NET-003"
    cand = [e for e in events if e.bytes_sent is not None and e.destination_ip and not is_internal(e.destination_ip)]
    if not any(e.bytes_sent is not None for e in events):
        out.skipped[rid] = "No events contain bytes_sent."
        return
    by_src: dict[str, list[Event]] = defaultdict(list)
    for e in cand:
        by_src[e.source_ip or e.username or "unknown"].append(e)
    for src, evs in by_src.items():
        for burst in qualifying_bursts(evs, cfg.outbound_window_minutes, _SumAgg("bytes_sent", cfg.outbound_bytes_threshold)):
            total = sum(e.bytes_sent or 0 for e in burst)
            dests = Counter(e.destination_ip for e in burst)
            out.findings.append(_make(
                rid, "rule", f"src:{src}", f"Unusual outbound volume from {src}",
                f"{src} sent {total:,} bytes to {len(dests)} external destination(s) within "
                f"{cfg.outbound_window_minutes} minutes ({_span(burst)}). Top destination: {dests.most_common(1)[0][0]}.",
                "High", min(1.0, total / (2 * cfg.outbound_bytes_threshold)), burst,
                f"Rule {rid}: total bytes_sent to non-internal destinations reached {cfg.outbound_bytes_threshold:,} inside the window.",
                ["Identify the process/user responsible and whether a backup, update or upload explains it.",
                 "Check the destination's ownership and reputation.",
                 "Look for earlier signs of compromise on the host (see correlated alerts).",
                 "If unexplained, consider restricting the host's egress while investigating."],
                [e.username for e in burst], [src] + list(dests),
                [build_mapping("exfiltration_alt_protocol", f"{total:,} bytes sent to external destinations in {cfg.outbound_window_minutes} minutes.")],
                {"total_bytes_sent": total, "destinations": dict(dests.most_common(10))}))


def _resource_of(e: Event) -> str | None:
    for k in ("resource", "object", "path", "url", "file", "target", "uri"):
        v = e.additional_metadata.get(k)
        if v:
            return str(v)
    return None


def rule_sensitive_access(events: list[Event], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-ACC-001"
    with_res = [(e, _resource_of(e)) for e in events]
    with_res = [(e, r) for e, r in with_res if r]
    if not with_res:
        out.skipped[rid] = "No events contain a resource/path/url/object field."
        return
    pats = [p.lower() for p in cfg.sensitive_resource_patterns]
    if not pats:
        out.skipped[rid] = "No sensitive resource patterns are configured."
        return
    groups: dict[str, list[tuple[Event, str, str]]] = defaultdict(list)
    for e, r in with_res:
        hit = next((p for p in pats if p in r.lower()), None)
        if hit and e.status in FAIL_STATUSES:
            groups[e.username or e.source_ip or "unknown"].append((e, r, hit))
    for who, items in groups.items():
        by_ev = {id(e): (e, r, p) for e, r, p in items}
        for cl in gap_clusters([e for e, _, _ in items], cfg.sensitive_window_minutes):
            if len(cl) < cfg.sensitive_min_events:
                continue
            res = sorted({by_ev[id(e)][1] for e in cl})
            hits = {by_ev[id(e)][2] for e in cl}
            n = len(cl)
            cred = bool(hits & {"/etc/shadow", "/etc/passwd"})
            out.findings.append(_make(
                rid, "rule", f"who:{who}", f"Denied access attempts on sensitive resources by {who}",
                f"{n} denied/failed attempts by {who} touched sensitive resources ({', '.join(res[:5])}"
                f"{'...' if len(res) > 5 else ''}) within {cfg.sensitive_window_minutes} minutes ({_span(cl)}).",
                "High" if n >= 3 * cfg.sensitive_min_events else "Medium", n / (3 * cfg.sensitive_min_events), cl,
                f"Rule {rid}: at least {cfg.sensitive_min_events} failed/denied accesses matched configured sensitive patterns ({', '.join(sorted(hits))}).",
                ["Confirm whether the user's role should access these resources.",
                 "Check whether the same user or IP succeeded on other sensitive resources.",
                 "Review the account's recent logins (see authentication alerts)."],
                [e.username for e in cl], [e.source_ip for e in cl],
                [build_mapping("os_credential_dumping_passwd_shadow", "Denied attempts on /etc/shadow or /etc/passwd.")] if cred else [],
                {"denied_attempts": n, "matched_patterns": sorted(hits), "resources": res[:20]}))


def rule_correlation(findings: list[Finding], cfg: DetectionConfig, out: DetectionOutcome) -> None:
    rid = "R-COR-001"
    if not cfg.correlation_enabled:
        out.skipped[rid] = "Correlation is disabled in the detection configuration."
        return
    keyed: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        keys = {f"ip:{i}" for i in f.ips if not is_internal(i) or f.rule_id in {"R-AUTH-001", "R-AUTH-002", "R-NET-001"}}
        # Accounts targeted by a spray are victims, not actors: do not link unrelated findings through them.
        if not (f.rule_id == "R-AUTH-001" and f.details.get("pattern") == "spray"):
            keys |= {f"user:{u}" for u in f.usernames}
        for k in keys:
            keyed[k].append(f)
    groups = []
    for k, fs in keyed.items():
        uniq = list({f.fingerprint: f for f in fs}.values())
        if len({f.rule_id for f in uniq}) >= cfg.correlation_min_distinct_rules:
            groups.append((k, uniq))
    groups.sort(key=lambda g: -len(g[1]))
    emitted: list[frozenset[str]] = []
    for k, fs in groups:
        sig = frozenset(f.fingerprint for f in fs)
        if any(sig <= prev for prev in emitted):
            continue
        emitted.append(sig)
        rules = sorted({f.rule_id for f in fs})
        ev = list({id(e): e for f in fs for e in f.evidence}.values())
        crit = "R-AUTH-002" in rules and bool({"R-NET-003", "R-ACC-001"} & set(rules))
        what = k.split(":", 1)[1]
        out.findings.append(_make(
            rid, "correlation", f"{sorted(sig)}", f"Correlated activity involving {what} ({len(rules)} detection types)",
            f"{len(fs)} alerts from {len(rules)} different rules ({', '.join(rules)}) involve {k.replace(':', ' ')}. "
            "Together they may indicate staged activity, but the link is circumstantial.",
            "Critical" if crit else "High", min(1.0, 0.4 + 0.15 * len(rules)), ev,
            f"Rule {rid}: findings from at least {cfg.correlation_min_distinct_rules} different rules share the same {k.split(':')[0]}. "
            + ("Severity is Critical because a login success after failures coincides with data egress or sensitive-resource attempts."
               if crit else "Severity is High because multiple independent signals coincide."),
            ["Review the constituent alerts in time order to reconstruct the sequence.",
             "Decide which entity (IP, user, host) to scope containment around.",
             "Open an incident and record which hypotheses the evidence supports or contradicts."],
            [u for f in fs for u in f.usernames], [i for f in fs for i in f.ips], merge_mappings([f.mitre for f in fs]),
            {"constituent_rules": rules, "constituent_fingerprints": sorted(sig), "correlation_key": k}))


RULE_FUNCS: list[Callable[[list[Event], DetectionConfig, DetectionOutcome], None]] = [
    rule_failed_logins, rule_success_after_failures, rule_unusual_auth, rule_port_scan,
    rule_watchlist, rule_outbound_volume, rule_sensitive_access,
]


def run_rules(events: list[Event], cfg: DetectionConfig | None = None) -> DetectionOutcome:
    cfg = cfg or DetectionConfig()
    out = DetectionOutcome(events_analyzed=len(events))
    ordered = _sorted(events)
    for fn in RULE_FUNCS:
        fn(ordered, cfg, out)
        out.rules_run.append(fn.__name__)
    rule_correlation(list(out.findings), cfg, out)
    return out
