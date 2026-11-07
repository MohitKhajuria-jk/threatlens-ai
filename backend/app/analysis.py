"""Runs the full analysis over every stored event: rules, threat intel, anomaly model, correlation."""

from __future__ import annotations

import json
import re
import threading
import time
from collections import Counter, defaultdict
from typing import Any

from .db import Database
from .detection import anomaly
from .detection.correlate import correlate, indicators
from .detection.mitre import technique
from .detection.playbooks import merged_steps, steps_for
from .detection.rules import make, run_rules
from .intel.service import IntelService
from .models import SEVERITY_RANK, Alert, Event, is_external

SUCCESS_KINDS = {"auth_success", "fw_allow", "net_connection"}
HASH_IN_TEXT = re.compile(r"\b(?:SHA256=)?([a-fA-F0-9]{64})\b")


def _succeeded(e: Event) -> bool:
    return e.kind in SUCCESS_KINDS or (e.source == "web" and 200 <= int(e.fields.get("status", 0)) < 400)


def intel_alerts(events: list[Event], intel: IntelService, alerts: list[Alert]) -> tuple[list[Alert], dict[str, dict[str, Any]]]:
    """Alerts for activity involving known-bad IPs, domains or file hashes."""
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        for ip in {e.src_ip, e.dst_ip}:
            if ip and is_external(ip):
                by_ip[ip].append(e)
    verdicts = {ip: intel.feed_verdict(ip) for ip in by_ip}
    out = []
    for ip, evs in by_ip.items():
        v = verdicts[ip]
        if v["verdict"] not in ("malicious", "suspicious"):
            continue
        ok = [e for e in evs if _succeeded(e)]
        if v["verdict"] == "malicious":
            severity, short = ("high" if ok else "medium"), "Known malicious IP"
            title = f"Activity involving known malicious IP {ip}"
        else:
            severity, short = "low", "Suspicious IP"
            title = f"Traffic from {ip}, flagged by threat intelligence"
        sources = Counter(e.source for e in evs)
        out.append(make("malicious_ip", title, short, severity, sources.most_common(1)[0][0], [], evs,
                        f"{ip} appears in {len(evs)} log event(s) across {', '.join(sources)}. " + "; ".join(v["reasons"][:3]) + "."
                        + (f" {len(ok)} of its actions succeeded." if ok else " None of its actions succeeded."),
                        ip=ip, host=(Counter(e.host for e in evs if e.host and e.source != "firewall") or Counter(e.host for e in evs if e.host) or Counter([None])).most_common(1)[0][0],
                        verdict=v["verdict"], reasons=v["reasons"], succeeded=len(ok)))

    # Domains and file hashes named in commands, scripts and service paths.
    for e in events:
        texts = [str(e.fields.get(k)) for k in ("command", "script", "task_content", "image_path", "hashes", "query") if e.fields.get(k)]
        if not texts:
            continue
        probe = make("probe", "", "", "low", e.source, [], [e], "")
        found = indicators(probe)
        hashes = {h.lower() for t in texts for h in HASH_IN_TEXT.findall(t)}
        for value in sorted(found["domains"] | hashes):
            v = intel.feed_verdict(value)
            if v["verdict"] != "malicious":
                continue
            kind = "file" if value in hashes else "domain"
            out.append(make(f"malicious_{kind}", f"Known malicious {kind} {'used' if kind == 'domain' else 'seen'} on {e.host}", f"Known malicious {kind}",
                            "high", e.source, ["T1105"] if kind == "domain" else [], [e],
                            f"The {kind} {value[:70]} appears in a command or file on {e.host}. " + "; ".join(v["reasons"][:2]) + ".",
                            user=e.user, host=e.host, indicator=value, reasons=v["reasons"], commands=texts[:2]))
            verdicts[value] = v
    # Merge duplicates of the same indicator on the same host.
    merged: dict[tuple, Alert] = {}
    for a in out:
        key = (a.rule_id, a.ip, a.details.get("indicator"), a.host)
        if key in merged:
            m = merged[key]
            m.evidence = (m.evidence + a.evidence)[:60]
            m.count += a.count
            m.last_seen = max(m.last_seen, a.last_seen)
        else:
            merged[key] = a
    return list(merged.values()), verdicts


def anomaly_alerts(events: list[Event], alerts: list[Alert]) -> tuple[list[Alert], list[anomaly.Anomaly]]:
    found = anomaly.detect(events)
    covered = {a.ip for a in alerts if a.ip}
    out = []
    per_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.src_ip:
            per_ip[e.src_ip].append(e)
    for an in found:
        if not an.outlier or an.ip in covered:
            continue
        evs = per_ip[an.ip]
        out.append(make("ml_anomaly", f"Unusual behaviour from {an.ip}", "Unusual behaviour (ML)", "medium" if an.score >= 0.75 else "low",
                        Counter(e.source for e in evs).most_common(1)[0][0], [], evs,
                        f"The anomaly model rates this IP {anomaly.score_label(an.score)} (score {an.score:.2f}) compared with the other {len(found) - 1} IPs: "
                        + "; ".join(an.reasons) + ".", ip=an.ip, score=an.score, reasons=an.reasons))
    return out, found


def _alert_row(a: Alert, alert_id: str, incident_id: str | None, anomalies: dict[str, anomaly.Anomaly]) -> dict[str, Any]:
    details = dict(a.details)
    details["steps"] = steps_for(a)
    details["mitre"] = [technique(t) for t in a.techniques]
    if a.ip and a.ip in anomalies:
        an = anomalies[a.ip]
        details["anomaly"] = {"score": an.score, "label": anomaly.score_label(an.score), "reasons": an.reasons}
    return {"id": alert_id, "rule_id": a.rule_id, "title": a.title, "short": a.short, "severity": a.severity, "source": a.source,
            "techniques": a.techniques, "first_seen": a.first_seen.timestamp(), "last_seen": a.last_seen.timestamp(), "count": a.count,
            "ip": a.ip, "user": a.user, "host": a.host, "description": a.description, "evidence": [e.id for e in a.evidence if e.id is not None],
            "details": details, "incident_id": incident_id}


class Analyzer:
    def __init__(self, db: Database, intel: IntelService):
        self.db = db
        self.intel = intel
        self.lock = threading.Lock()
        self.last_summary: dict[str, Any] | None = None

    def run(self) -> dict[str, Any]:
        with self.lock:
            started = time.time()
            events = self.db.all_events()
            alerts = run_rules(events)
            extra, verdicts = intel_alerts(events, self.intel, alerts)
            alerts += extra
            ml, found = anomaly_alerts(events, alerts)
            alerts += ml
            malicious = {k for k, v in verdicts.items() if v["verdict"] == "malicious"}
            incidents = correlate(alerts, events, malicious)
            anomalies = {an.ip: an for an in found}

            ids: dict[int, str] = {}
            used: set[str] = set()
            for a in alerts:
                fid = a.fingerprint
                while fid in used:
                    fid = fid[:-1] + "x" if not fid.endswith("x") else fid + "x"
                used.add(fid)
                ids[id(a)] = fid
            incident_of = {id(a): inc.id for inc in incidents for a in inc.alerts}
            alert_rows = [_alert_row(a, ids[id(a)], incident_of.get(id(a)), anomalies) for a in alerts]

            incident_rows = []
            for inc in incidents:
                d = inc.to_dict()
                d["alert_ids"] = [ids[id(a)] for a in inc.alerts]
                d["steps"] = merged_steps(inc.alerts)
                d["mitre"] = [technique(t) for t in inc.techniques]
                d["sources"] = sorted({a.source for a in inc.alerts})
                d["severity_counts"] = dict(Counter(a.severity for a in inc.alerts))
                d["intel"] = {ip: {"verdict": verdicts.get(ip, {}).get("verdict", "unknown"), "reasons": verdicts.get(ip, {}).get("reasons", [])} for ip in inc.ips}
                d["anomaly"] = {ip: {"score": anomalies[ip].score, "label": anomaly.score_label(anomalies[ip].score), "reasons": anomalies[ip].reasons}
                                for ip in inc.ips if ip in anomalies}
                d["event_count"] = sum(a.count for a in inc.alerts)
                incident_rows.append(d)

            self.db.save_results(alert_rows, incident_rows)
            self.db.x("INSERT OR REPLACE INTO meta (key, value) VALUES ('anomalies', ?)",
                      (json.dumps([{"ip": an.ip, "score": an.score, "outlier": an.outlier, "reasons": an.reasons, "features": an.features} for an in found[:25]]),))
            sev = Counter(a.severity for a in alerts)
            self.last_summary = {"events": len(events), "alerts": len(alerts), "incidents": len(incidents),
                                 "by_severity": {s: sev.get(s, 0) for s in ("critical", "high", "medium", "low")},
                                 "seconds": round(time.time() - started, 2)}
            return self.last_summary

    def alert_ips(self) -> list[str]:
        rows = self.db.alerts()
        rows.sort(key=lambda a: -SEVERITY_RANK.get(a["severity"], 0))
        out: list[str] = []
        for a in rows:
            if a["ip"] and is_external(a["ip"]) and a["ip"] not in out:
                out.append(a["ip"])
        return out
