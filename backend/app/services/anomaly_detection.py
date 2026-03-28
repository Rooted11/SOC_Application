"""
Anomaly Detection Service
=========================
Uses Isolation Forest (unsupervised ML) to score every incoming log event.

Why Isolation Forest?
  - Works without labelled data (no ground-truth attack labels needed)
  - Handles high-dimensional, mixed-type log data well
  - Fast inference — suitable for near-real-time log ingestion
  - Explainable: we can inspect which features drove the anomaly

Pipeline:
  raw log dict → _extract_features() → 15-D numpy vector
               → StandardScaler       → normalised vector
               → IsolationForest      → decision score
               → _iso_to_risk()       → 0-100 risk score + severity label
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── Feature index constants (improves readability) ─────────────────────────
F_HOUR        = 0   # hour of day (0-23)  — off-hours = suspicious
F_WEEKDAY     = 1   # weekday (0=Mon … 6=Sun)
F_SRC_BUCKET  = 2   # hashed source-IP bucket — novel IPs score high
F_DST_BUCKET  = 3   # hashed destination-IP bucket
F_LOG_LEVEL   = 4   # error/critical weighted higher than info
F_EVENT_TYPE  = 5   # encoded event category
F_MSG_LEN     = 6   # unusually long messages may contain payloads
F_FAIL_AUTH   = 7   # rolling auth-failure count for this source
F_DISTINCT_DST= 8   # fan-out: how many destinations from this source
F_PRIV_PORT   = 9   # destination port < 1024
F_EXTERNAL    = 10  # source IP is non-RFC-1918
F_RAPID_CONN  = 11  # connection rate spike flag
F_SVC_USER    = 12  # service account used interactively
F_LATERAL     = 13  # cross-subnet internal traffic
F_TZ_ANOMALY  = 14  # off-hours external login
FEATURE_DIM   = 15

EVENT_TYPES = {
    "auth_success": 0, "auth_failure": 1, "privilege_escalation": 2,
    "network_scan": 3, "data_exfiltration": 4, "malware_detected": 5,
    "policy_violation": 6, "config_change": 7, "service_start": 8,
    "service_stop": 9, "file_access": 10, "process_create": 11,
    "lateral_movement": 12, "c2_beacon": 13, "dns_query": 14, "unknown": 15,
}
LOG_LEVELS = {
    "debug": 0, "info": 1, "notice": 2, "warning": 3,
    "error": 4, "critical": 5, "alert": 6, "emergency": 7,
}
HIGH_RISK_EVENTS = {2, 3, 4, 5, 12, 13}   # used in _explain()


class AnomalyDetector:
    """
    Wraps IsolationForest with feature extraction, scaling and risk scoring.
    A synthetic baseline is trained at startup so the detector is immediately
    ready without requiring historical data.
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 200):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler     = StandardScaler()
        self.is_trained = False
        # Per-source rolling window for frequency features
        self._window: Dict[str, Dict] = {}
        self._train_synthetic_baseline()

    # ── Training ────────────────────────────────────────────────────────────

    def _train_synthetic_baseline(self):
        """
        Generate ~2000 synthetic 'normal' feature vectors and fit the model.
        Distribution approximates a healthy weekday corporate network.
        In production, replace with 30 days of real log data.
        """
        rng = np.random.default_rng(42)
        n   = 2000
        X   = np.zeros((n, FEATURE_DIM))

        X[:, F_HOUR]         = np.clip(rng.normal(13, 3, n), 0, 23)
        X[:, F_WEEKDAY]      = rng.choice([0, 1, 2, 3, 4], n)
        X[:, F_SRC_BUCKET]   = rng.uniform(0, 0.3, n)
        X[:, F_DST_BUCKET]   = rng.uniform(0, 0.3, n)
        X[:, F_LOG_LEVEL]    = rng.choice([1, 2], n, p=[0.8, 0.2])
        X[:, F_EVENT_TYPE]   = rng.choice([0, 8, 10, 14], n)
        X[:, F_MSG_LEN]      = np.clip(rng.normal(100, 30, n), 20, 300)
        X[:, F_FAIL_AUTH]    = rng.poisson(0.1, n)
        X[:, F_DISTINCT_DST] = rng.poisson(1, n)
        X[:, F_PRIV_PORT]    = rng.binomial(1, 0.1, n)
        X[:, F_EXTERNAL]     = rng.binomial(1, 0.05, n)
        # F_RAPID_CONN, F_SVC_USER, F_LATERAL, F_TZ_ANOMALY all 0 for normal

        self.scaler.fit_transform(X)             # fit scaler on synthetic data
        self.model.fit(self.scaler.transform(X))
        self.is_trained = True

    # ── Feature extraction ──────────────────────────────────────────────────

    @staticmethod
    def _ip_bucket(ip: str) -> float:
        """Stable float in [0,1] for an IP string via MD5 hash."""
        if not ip:
            return 0.0
        return (int(hashlib.md5(ip.encode()).hexdigest()[:8], 16) % 1000) / 1000.0

    @staticmethod
    def _is_external(ip: str) -> int:
        if not ip:
            return 0
        rfc1918 = ("10.", "192.168.", "127.", "172.16.", "172.17.",
                   "172.18.", "172.19.", "172.2", "172.3")
        return 0 if any(ip.startswith(p) for p in rfc1918) else 1

    def _extract_features(self, log: Dict[str, Any]) -> np.ndarray:
        f = np.zeros(FEATURE_DIM, dtype=float)

        ts = log.get("timestamp", datetime.utcnow())
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except ValueError:
                ts = datetime.utcnow()

        ip_src = log.get("ip_src", "")
        ip_dst = log.get("ip_dst", "")
        raw    = log.get("raw_data") or {}

        f[F_HOUR]       = ts.hour
        f[F_WEEKDAY]    = ts.weekday()
        f[F_SRC_BUCKET] = self._ip_bucket(ip_src)
        f[F_DST_BUCKET] = self._ip_bucket(ip_dst)
        f[F_LOG_LEVEL]  = LOG_LEVELS.get(str(log.get("log_level", "info")).lower(), 1)
        f[F_EVENT_TYPE] = EVENT_TYPES.get(str(log.get("event_type", "unknown")).lower(), 15)
        f[F_MSG_LEN]    = len(str(log.get("message", "")))
        f[F_EXTERNAL]   = self._is_external(ip_src)

        # Rolling window state per source IP
        w = self._window.setdefault(ip_src or "?", {
            "fail_auth": 0, "dsts": set(), "conn_count": 0
        })
        if log.get("event_type") == "auth_failure":
            w["fail_auth"] += 1
        if ip_dst:
            w["dsts"].add(ip_dst)
        w["conn_count"] += 1

        f[F_FAIL_AUTH]    = min(w["fail_auth"], 20)
        f[F_DISTINCT_DST] = min(len(w["dsts"]), 50)
        f[F_PRIV_PORT]    = 1 if int(raw.get("dst_port", 9999)) < 1024 else 0
        f[F_RAPID_CONN]   = 1 if w["conn_count"] > 20 else 0

        user = str(log.get("user", "")).lower()
        f[F_SVC_USER] = 1 if any(x in user for x in ("svc_", "_svc", "$", "krbtgt")) else 0

        if ip_src and ip_dst:
            s_pre = ".".join(ip_src.split(".")[:2])
            d_pre = ".".join(ip_dst.split(".")[:2])
            both_internal = not self._is_external(ip_src) and not self._is_external(ip_dst)
            f[F_LATERAL] = 1 if (both_internal and s_pre != d_pre) else 0

        f[F_TZ_ANOMALY] = 1 if (f[F_EXTERNAL] and ts.hour not in range(8, 18)) else 0
        return f

    # ── Scoring ─────────────────────────────────────────────────────────────

    @staticmethod
    def _iso_to_risk(raw: float) -> Tuple[float, bool]:
        """
        Map IsolationForest decision_function output → (risk_score 0-100, is_anomaly).
        decision_function: positive = normal, negative = anomalous.
        """
        clamped = max(-0.5, min(0.5, raw))
        risk    = round((-clamped + 0.5) * 100, 2)
        return risk, raw < -0.05

    def score_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Score one log dict. Returns anomaly_score, risk_score, explanation."""
        features = self._extract_features(log)
        scaled   = self.scaler.transform(features.reshape(1, -1))
        raw      = float(self.model.decision_function(scaled)[0])
        risk, is_anom = self._iso_to_risk(raw)
        return {
            "anomaly_score": round(raw, 4),
            "risk_score":    risk,
            "is_anomalous":  is_anom,
            "features":      features.tolist(),
            "explanation":   self._explain(features, is_anom),
        }

    def score_batch(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.score_log(l) for l in logs]

    # ── Explainability ──────────────────────────────────────────────────────

    def _explain(self, f: np.ndarray, is_anom: bool) -> str:
        reasons = []
        if f[F_HOUR] < 6 or f[F_HOUR] > 22:
            reasons.append(f"after-hours activity ({int(f[F_HOUR]):02d}:00 UTC)")
        if f[F_WEEKDAY] >= 5:
            reasons.append("weekend access")
        if f[F_EXTERNAL]:
            reasons.append("external source IP")
        if f[F_FAIL_AUTH] >= 5:
            reasons.append(f"{int(f[F_FAIL_AUTH])} authentication failures")
        if f[F_DISTINCT_DST] >= 10:
            reasons.append(f"high fan-out ({int(f[F_DISTINCT_DST])} destinations)")
        if f[F_LATERAL]:
            reasons.append("cross-subnet lateral movement pattern")
        if f[F_SVC_USER]:
            reasons.append("service/system account used interactively")
        if f[F_TZ_ANOMALY]:
            reasons.append("off-hours external login")
        if f[F_LOG_LEVEL] >= 5:
            reasons.append("critical or emergency log level")
        if f[F_RAPID_CONN]:
            reasons.append("rapid connection rate spike")
        if int(f[F_EVENT_TYPE]) in HIGH_RISK_EVENTS:
            name = next((k for k, v in EVENT_TYPES.items() if v == int(f[F_EVENT_TYPE])), "")
            if name:
                reasons.append(f"high-risk event: {name}")
        if not reasons:
            return ("Anomaly: statistical outlier vs baseline." if is_anom
                    else "No significant anomaly indicators found.")
        prefix = "Anomaly detected — " if is_anom else "Elevated risk — "
        return prefix + "; ".join(reasons) + "."

    @staticmethod
    def classify_severity(risk_score: float) -> str:
        if risk_score >= 80: return "critical"
        if risk_score >= 60: return "high"
        if risk_score >= 40: return "medium"
        if risk_score >= 20: return "low"
        return "info"


# Module-level singleton imported by routes
detector = AnomalyDetector()
