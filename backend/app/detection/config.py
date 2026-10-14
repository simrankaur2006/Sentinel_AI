"""Configurable detection thresholds with validation."""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field, fields
from typing import Any


@dataclass
class DetectionConfig:
    # R-AUTH-001
    failed_login_threshold: int = 5
    failed_login_window_minutes: int = 10
    # R-AUTH-002
    success_after_failures_min: int = 4
    success_after_failures_window_minutes: int = 15
    # R-AUTH-003
    multi_ip_login_threshold: int = 3
    multi_ip_window_minutes: int = 30
    offhours_start_hour: int = 0
    offhours_end_hour: int = 5
    offhours_min_baseline_logins: int = 3
    # R-NET-001
    portscan_distinct_ports: int = 15
    portscan_window_minutes: int = 5
    # R-NET-002 (RFC 5737 documentation addresses: synthetic demo watchlist)
    suspicious_ips: list[str] = field(default_factory=lambda: ["203.0.113.66", "198.51.100.23"])
    suspicious_ip_window_minutes: int = 60
    # R-NET-003
    outbound_bytes_threshold: int = 50_000_000
    outbound_window_minutes: int = 30
    # R-ACC-001
    sensitive_resource_patterns: list[str] = field(
        default_factory=lambda: ["/etc/shadow", "/etc/passwd", "/admin", ".ssh/", "payroll", "secrets"])
    sensitive_min_events: int = 2
    sensitive_window_minutes: int = 30
    # R-COR-001
    correlation_enabled: bool = True
    correlation_min_distinct_rules: int = 2
    # ML
    ml_enabled: bool = True
    ml_contamination: float = 0.05
    ml_n_estimators: int = 200
    ml_random_seed: int = 42
    ml_min_events: int = 50
    ml_max_alerts: int = 10
    ml_skip_rule_covered: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "DetectionConfig":
        """Build a validated config; unknown keys are rejected, missing keys use defaults."""
        base = cls()
        data = dict(data or {})
        names = {f.name for f in fields(cls)}
        unknown = set(data) - names
        if unknown:
            raise ValueError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
        for k, v in data.items():
            default = getattr(base, k)
            if isinstance(default, bool):
                if not isinstance(v, bool):
                    raise ValueError(f"{k} must be true or false")
            elif isinstance(default, int):
                if isinstance(v, bool) or not isinstance(v, (int, float)) or int(v) != v:
                    raise ValueError(f"{k} must be an integer")
                v = int(v)
            elif isinstance(default, float):
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    raise ValueError(f"{k} must be a number")
                v = float(v)
            elif isinstance(default, list):
                if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                    raise ValueError(f"{k} must be a list of strings")
                v = [x.strip() for x in v if x.strip()][:200]
            setattr(base, k, v)
        base.validate()
        return base

    def validate(self) -> None:
        def rng(name: str, lo: float, hi: float) -> None:
            v = getattr(self, name)
            if not (lo <= v <= hi):
                raise ValueError(f"{name} must be between {lo} and {hi}")

        for n in ("failed_login_threshold", "success_after_failures_min", "multi_ip_login_threshold",
                  "portscan_distinct_ports", "sensitive_min_events"):
            rng(n, 2, 10_000)
        for n in ("failed_login_window_minutes", "success_after_failures_window_minutes", "multi_ip_window_minutes",
                  "portscan_window_minutes", "suspicious_ip_window_minutes", "outbound_window_minutes",
                  "sensitive_window_minutes"):
            rng(n, 1, 1440)
        rng("offhours_start_hour", 0, 23)
        rng("offhours_end_hour", 0, 24)
        rng("offhours_min_baseline_logins", 1, 1000)
        rng("outbound_bytes_threshold", 1, 10**13)
        rng("correlation_min_distinct_rules", 2, 10)
        rng("ml_contamination", 0.001, 0.5)
        rng("ml_n_estimators", 10, 1000)
        rng("ml_random_seed", 0, 2**31 - 1)
        rng("ml_min_events", 20, 1_000_000)
        rng("ml_max_alerts", 1, 200)
        for entry in self.suspicious_ips:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"suspicious_ips contains an invalid IP/CIDR: {entry!r}") from exc
