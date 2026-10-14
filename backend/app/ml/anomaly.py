"""Isolation Forest anomaly detection over normalized events.

This is unsupervised, dataset-relative outlier detection: it ranks events that look unusual compared to
the rest of the data analysed in the same run. An anomaly is NOT necessarily malicious, the score is NOT a
probability, and no accuracy/precision/recall is reported because no labelled ground truth exists.
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.detection.config import DetectionConfig
from app.detection.rules import is_internal
from app.domain import Event, Finding

CATEGORICAL = ["event_type", "protocol", "action"]
TOP_K = 12
MODEL_VERSION = "iforest-v1"

FEATURE_LABELS = {
    "log_bytes_sent": "bytes sent", "log_bytes_received": "bytes received", "port": "destination port",
    "has_port": "presence of a port", "hour_sin": "time of day", "hour_cos": "time of day",
    "is_failure": "failure/denied status", "is_success": "success status", "is_external_dst": "external destination",
    "is_external_src": "external source", "log_src_event_count": "events from this source in the data",
    "src_failure_ratio": "failure ratio for this source", "log_user_event_count": "events by this user in the data",
}


@dataclass
class AnomalyResult:
    skipped_reason: str | None = None
    scored: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AnomalyModel:
    """Feature extraction + Isolation Forest with handling for missing values and unseen categories."""

    def __init__(self, cfg: DetectionConfig):
        self.cfg = cfg
        self.vocab: dict[str, list[str]] = {}
        self.columns: list[str] = []
        self.model: IsolationForest | None = None
        self.center: np.ndarray | None = None
        self.scale: np.ndarray | None = None
        self.train_stats: dict[str, Any] = {}

    # ---- features
    def _frame(self, events: list[Event]) -> pd.DataFrame:
        rows = []
        src_counts = Counter(e.source_ip for e in events if e.source_ip)
        src_fail = Counter(e.source_ip for e in events if e.source_ip and e.status in {"failure", "denied"})
        usr_counts = Counter(e.username for e in events if e.username)
        for e in events:
            h = e.timestamp.hour + e.timestamp.minute / 60.0
            rows.append({
                "log_bytes_sent": math.log1p(e.bytes_sent) if e.bytes_sent is not None else 0.0,
                "log_bytes_received": math.log1p(e.bytes_received) if e.bytes_received is not None else 0.0,
                "port": (e.port / 65535.0) if e.port is not None else 0.0,
                "has_port": 1.0 if e.port is not None else 0.0,
                "hour_sin": math.sin(2 * math.pi * h / 24), "hour_cos": math.cos(2 * math.pi * h / 24),
                "is_failure": 1.0 if e.status in {"failure", "denied"} else 0.0,
                "is_success": 1.0 if e.status == "success" else 0.0,
                "is_external_dst": 1.0 if e.destination_ip and not is_internal(e.destination_ip) else 0.0,
                "is_external_src": 1.0 if e.source_ip and not is_internal(e.source_ip) else 0.0,
                "log_src_event_count": math.log1p(src_counts.get(e.source_ip, 0)) if e.source_ip else 0.0,
                "src_failure_ratio": (src_fail.get(e.source_ip, 0) / src_counts[e.source_ip]) if e.source_ip else 0.0,
                "log_user_event_count": math.log1p(usr_counts.get(e.username, 0)) if e.username else 0.0,
                **{f"{c}={getattr(e, c) or '__missing__'}": 1.0 for c in CATEGORICAL},
            })
        return pd.DataFrame(rows).fillna(0.0)

    def _matrix(self, events: list[Event], fit: bool) -> np.ndarray:
        df = self._frame(events)
        if fit:
            for c in CATEGORICAL:
                cnt = Counter(getattr(e, c) or "__missing__" for e in events)
                self.vocab[c] = [v for v, _ in cnt.most_common(TOP_K)]
            numeric = [c for c in df.columns if "=" not in c]
            self.columns = numeric + [f"{c}={v}" for c in CATEGORICAL for v in self.vocab[c]]
        # Unseen categorical values / absent columns become 0 -> never an error.
        df = df.reindex(columns=self.columns, fill_value=0.0)
        return df.to_numpy(dtype=float)

    # ---- fit / score
    def fit(self, events: list[Event]) -> None:
        X = self._matrix(events, fit=True)
        self.model = IsolationForest(
            n_estimators=self.cfg.ml_n_estimators, contamination=self.cfg.ml_contamination,
            random_state=self.cfg.ml_random_seed, n_jobs=1)
        self.model.fit(X)
        q1, med, q3 = np.percentile(X, [25, 50, 75], axis=0)
        iqr_scale = (q3 - q1) / 1.349
        std = X.std(axis=0)
        self.center = med
        self.scale = np.where(iqr_scale > 1e-9, iqr_scale, np.where(std > 1e-9, std, np.inf))
        self.train_stats = {"n_train": int(X.shape[0])}

    def score(self, events: list[Event]) -> list[dict[str, Any]]:
        assert self.model is not None, "fit() must be called first"
        X = self._matrix(events, fit=False)
        raw = -self.model.score_samples(X)  # higher = more anomalous
        pred = self.model.predict(X)  # -1 anomaly, 1 normal (contamination-based threshold)
        lo, hi = float(raw.min()), float(raw.max())
        norm = (raw - lo) / (hi - lo) if hi - lo > 1e-12 else np.zeros_like(raw)
        out = []
        for i, e in enumerate(events):
            z = np.abs(X[i] - self.center) / self.scale
            top = np.argsort(-z)[:3]
            reasons = []
            seen = set()
            for j in top:
                if not np.isfinite(z[j]) or z[j] < 2.0:
                    continue
                name = self.columns[j]
                label = FEATURE_LABELS.get(name, name.replace("=", " = "))
                if label in seen:
                    continue
                seen.add(label)
                reasons.append({"feature": name, "label": label, "deviation": round(float(z[j]), 1), "value": round(float(X[i][j]), 3)})
            out.append({"event": e, "raw_score": float(raw[i]), "score": round(float(norm[i]), 4),
                        "is_anomaly": bool(pred[i] == -1), "reasons": reasons})
        return out


def detect_anomalies(events: list[Event], cfg: DetectionConfig, covered_event_ids: set[int] | None = None) -> AnomalyResult:
    """Fit on the supplied events and return anomaly findings (never above Medium severity)."""
    res = AnomalyResult()
    meta = {"model": "IsolationForest", "model_version": MODEL_VERSION, "n_estimators": cfg.ml_n_estimators,
            "contamination": cfg.ml_contamination, "random_seed": cfg.ml_random_seed, "n_events": len(events),
            "scoring": "normalized_anomaly_score = min-max of -score_samples within this run; relative, not a probability",
            "metrics": "not computed: no labelled ground truth is available"}
    if not cfg.ml_enabled:
        res.skipped_reason = "ML detection is disabled in the detection configuration."
    elif len(events) < cfg.ml_min_events:
        res.skipped_reason = (f"Only {len(events)} events are available; at least {cfg.ml_min_events} are needed for a "
                              "meaningful Isolation Forest. Rule-based detection still ran.")
    if res.skipped_reason:
        res.metadata = {**meta, "skipped": res.skipped_reason}
        return res

    model = AnomalyModel(cfg)
    model.fit(events)
    scored = model.score(events)
    res.scored = scored
    flagged = [s for s in scored if s["is_anomaly"]]
    raw_thr = min((s["raw_score"] for s in flagged), default=None)
    meta.update({"n_flagged_before_filters": len(flagged), "decision_threshold_raw": raw_thr,
                 "features": model.columns, "categorical_vocabulary": model.vocab})
    covered = covered_event_ids or set()
    cand = [s for s in flagged if not (cfg.ml_skip_rule_covered and s["event"].pk in covered)]
    meta["n_skipped_rule_covered"] = len(flagged) - len(cand)
    cand.sort(key=lambda s: -s["raw_score"])
    for s in cand[: cfg.ml_max_alerts]:
        e: Event = s["event"]
        reasons = s["reasons"]
        why = "; ".join(f"{r['label']} deviates strongly from typical ({r['deviation']} robust SDs)" for r in reasons) \
            or "its combination of features is rare in this dataset"
        res.findings.append(Finding(
            rule_id="ML-IFOREST", detection_source="ml",
            title=f"Statistical outlier: {e.event_type or 'event'}" + (f" from {e.source_ip}" if e.source_ip else ""),
            description=f"Isolation Forest ranked this event as unusual relative to the {len(events)} events analysed "
                        f"(normalized anomaly score {s['score']:.2f}). Unusual does not mean malicious.",
            severity="Medium" if s["score"] >= 0.85 else "Low", confidence=s["score"], confidence_kind="anomaly_score",
            first_seen=e.timestamp, last_seen=e.timestamp, evidence=[e],
            explanation=f"Model-generated finding (Isolation Forest, seed {cfg.ml_random_seed}, contamination {cfg.ml_contamination}). "
                        f"Main contributing features: {why}.",
            recommended_steps=["Check whether the activity is expected for this host, user or time of day.",
                               "Compare with the same source's earlier and later events.",
                               "Mark as False Positive if benign; this does not retrain the model."],
            limitations="Statistical outliers include rare-but-benign behavior. Scores are relative to this dataset, not calibrated probabilities, and the model has not been validated against labelled attacks.",
            fingerprint=hashlib.sha256(f"ML-IFOREST|{e.fingerprint or e.pk}".encode()).hexdigest()[:40],
            usernames=[e.username] if e.username else [], ips=[i for i in (e.source_ip, e.destination_ip) if i],
            host=e.source, mitre=[],
            details={"anomaly_score": s["score"], "raw_score": round(s["raw_score"], 4), "reasons": reasons,
                     "model_version": MODEL_VERSION, "contamination": cfg.ml_contamination,
                     "random_seed": cfg.ml_random_seed, "evidence_total": 1}))
    meta["n_alerts_created"] = len(res.findings)
    res.metadata = meta
    return res
