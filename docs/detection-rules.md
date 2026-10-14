# Detection rules

All thresholds are configurable (Detection settings page or `PUT /api/detection/config`). Every rule attaches its evidence events, skips safely when required fields are missing (the run records why), and never claims a successful attack.

| ID | Detects | Needs | Default | Severity |
|---|---|---|---|---|
| R-AUTH-001 | Repeated failed logins (sliding window, per source IP, or per user if no IP) | authentication + failure status | ≥5 in 10 min | Medium; High at ≥3× threshold |
| R-AUTH-002 | Success after failures for same user (and same IP if known) | username, status | ≥4 failures within 15 min | High |
| R-AUTH-003 | (a) One user from ≥N distinct IPs in a window; (b) off-hours login vs. user baseline | successful auth, username (+IP) | 3 IPs/30 min; 00–05 UTC, ≥3 baseline logins | Medium / Low |
| R-NET-001 | Many distinct ports from one source | source_ip, port | ≥15 ports in 5 min | Medium; High at ≥5× |
| R-NET-002 | Event involves a watchlisted IP/CIDR | IPs | 2 demo entries (RFC 5737) | Medium; High if successful outbound data |
| R-NET-003 | Large volume to non-internal destinations | bytes_sent, destination_ip | ≥50 MB in 30 min | High |
| R-ACC-001 | Denied access to sensitive paths | resource-like field in metadata | ≥2 in 30 min | Medium; High at ≥3× |
| R-COR-001 | ≥2 distinct rules share an IP or user | findings | 2 rules | High; Critical if success-after-failures coincides with egress or sensitive attempts |
| ML-IFOREST | Isolation Forest outliers | ≥50 events | contamination 0.05, seed 42 | Low/Medium (never higher) |

## Severity model
Critical: converging evidence of possible account compromise plus data movement or sensitive access. High: strong single signal or correlated findings. Medium: suspicious pattern needing review. Low: weak or statistical signal. Severity is a documented, transparent heuristic, **not** a validated risk probability.

## Indicator
`confidence` is either *heuristic strength* (how far past the threshold, capped at 1) or a *normalized anomaly score* (min–max of the model score within one run). Neither is a calibrated probability.

## Deduplication
Each finding has a fingerprint (rule + entity + first-seen time). Re-running detection updates existing alerts and keeps analyst status; it does not create duplicates.

## ML notes
Features: log-scaled bytes, port, hour (sin/cos), status flags, internal/external flags, per-source/per-user volume and failure ratio, one-hot of the 12 most common event types/protocols/actions (unseen categories → zeros). The model is fit on the analysed data itself (unsupervised). No precision/recall/F1 is computed or reported because no labelled ground truth exists.

## MITRE ATT&CK
Mappings live in `backend/app/mitre/mappings.json` with rationale and a relation: `behavior_consistent` (logs match the technique's pattern) or `potential_association` (one plausible hypothesis). Generic sensitive-path attempts get **no** mapping. References: https://attack.mitre.org/ . ATT&CK evolves; verify names/IDs against the current release.
