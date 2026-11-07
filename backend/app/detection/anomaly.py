"""Unsupervised anomaly detection: an Isolation Forest over per-IP behaviour.

Rules catch known attack patterns; this catches IPs that simply behave very differently
from the rest (far more requests, failures, ports or paths than usual), and explains why.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..models import Event, is_external

FEATURES = {
    "events": "events",
    "peak_per_minute": "events in its busiest minute",
    "failure_ratio": "share of failed or blocked actions",
    "distinct_users": "different user names tried",
    "distinct_paths": "different URLs requested",
    "distinct_ports": "different ports contacted",
    "error_ratio": "share of HTTP errors",
    "log_sources": "log sources it appears in",
}
MIN_ENTITIES = 15
# A feature only counts as unusual above these values, so a shopper browsing 6 pages isn't flagged.
FLOORS = {"events": 60, "peak_per_minute": 20, "failure_ratio": 0.5, "distinct_users": 3, "distinct_paths": 40, "distinct_ports": 10, "error_ratio": 0.5, "log_sources": 3}


@dataclass
class Anomaly:
    ip: str
    score: float  # 0..1, higher is more unusual
    outlier: bool
    reasons: list[str]
    features: dict[str, float]


def features_by_ip(events: list[Event]) -> dict[str, dict[str, float]]:
    per: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.src_ip and is_external(e.src_ip):
            per[e.src_ip].append(e)
    out = {}
    for ip, evs in per.items():
        total = sum(e.count for e in evs)
        minutes: dict[int, int] = defaultdict(int)
        for e in evs:
            minutes[int(e.epoch // 60)] += e.count
        web = [e for e in evs if e.source == "web"]
        out[ip] = {
            "events": float(total),
            "peak_per_minute": float(max(minutes.values())),
            "failure_ratio": sum(e.count for e in evs if e.outcome == "failure") / total,
            "distinct_users": float(len({e.user for e in evs if e.user and e.source != "web"})),
            "distinct_paths": float(len({e.fields.get("path") for e in web})),
            "distinct_ports": float(len({e.dst_port for e in evs if e.dst_port})),
            "error_ratio": (sum(1 for e in web if int(e.fields.get("status", 0)) >= 400) / len(web)) if web else 0.0,
            "log_sources": float(len({e.source for e in evs})),
        }
    return out


def _fmt(name: str, value: float) -> str:
    return f"{value:.0%}" if name.endswith("ratio") else f"{value:,.0f}"


def detect(events: list[Event]) -> list[Anomaly]:
    table = features_by_ip(events)
    if len(table) < MIN_ENTITIES:
        return []
    import numpy as np
    from sklearn.ensemble import IsolationForest

    ips = list(table)
    names = list(FEATURES)
    raw = np.array([[table[ip][n] for n in names] for ip in ips], dtype=float)
    X = raw.copy()
    for j, n in enumerate(names):  # counts are heavy-tailed; compare them on a log scale
        if not n.endswith("ratio"):
            X[:, j] = np.log1p(X[:, j])
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=7).fit(X)
    scores = -model.score_samples(X)
    flags = model.predict(X) == -1
    medians = np.median(X, axis=0)
    mad = np.median(np.abs(X - medians), axis=0) * 1.4826 + 1e-6
    raw_medians = np.median(raw, axis=0)

    out = []
    for i, ip in enumerate(ips):
        z = (X[i] - medians) / mad
        reasons = []
        for j in np.argsort(-z):
            if z[j] < 3 or len(reasons) == 3:
                break
            n = names[j]
            if raw[i, j] < max(FLOORS[n], 2 * raw_medians[j]):
                continue
            reasons.append(f"{_fmt(n, raw[i, j])} {FEATURES[n]} (typical: {_fmt(n, raw_medians[j])})")
        out.append(Anomaly(ip, round(float(min(1.0, max(0.0, (scores[i] - 0.35) / 0.45))), 2), bool(flags[i] and reasons), reasons,
                           {n: round(float(raw[i, j]), 3) for j, n in enumerate(names)}))
    out.sort(key=lambda a: -a.score)
    return out


def score_label(score: float) -> str:
    return "very unusual" if score >= 0.75 else "unusual" if score >= 0.5 else "normal"


