"""Groups related alerts into incidents, even across log sources.

Two alerts belong together when they share an attacker IP, a user session on the same
host, or an indicator (an IP or domain mentioned in a command), within 24 hours.
A user's session is traced back to the IP it logged in from, so commands run later
by that user join the attacker's incident.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..models import SEVERITY_RANK, Alert, Event, is_external, max_severity
from .mitre import tactic_of

WINDOW = timedelta(hours=24)
URL_HOST = re.compile(r"https?://([A-Za-z0-9.-]+)", re.I)
IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CREATED_USER = re.compile(r"\b(?:useradd|adduser|usermod|gpasswd)\b.*?\s([a-z_][a-z0-9_.-]*)\s*$", re.I)
RISK_BASE = {"low": 15, "medium": 40, "high": 65, "critical": 85}

# rule -> (stage, phrase). Stages: 0 reconnaissance, 1 getting in, 2 taking hold, 3 the attacker's goal.
PHRASES: dict[str, tuple[int, str]] = {
    "port_scan": (0, "port scanning"), "host_sweep": (0, "network sweeps"), "web_scanner": (0, "vulnerability scanning"),
    "dir_bruteforce": (0, "URL guessing"), "sensitive_file": (0, "probing for exposed files"), "account_discovery": (2, "account discovery"),
    "brute_force": (1, "brute-force logins"), "login_after_brute_force": (1, "account break-in"), "rdp_from_internet": (1, "Remote Desktop login"),
    "root_ssh_login": (1, "root login"), "sql_injection": (1, "SQL injection"), "path_traversal": (1, "file-read attacks"),
    "command_injection": (1, "command injection"), "log4shell": (1, "Log4Shell exploitation"), "xss": (1, "XSS attempts"), "web_shell": (2, "web shell"),
    "sudo_root_shell": (2, "root access"), "sudo_sensitive_command": (2, "root access"), "sudo_failures": (2, "sudo attempts"),
    "user_created": (2, "backdoor account"), "privileged_group_add": (2, "backdoor account"), "net_user_add": (2, "backdoor account"),
    "suspicious_cron": (2, "malicious cron job"), "suspicious_service": (2, "malicious service"), "scheduled_task_created": (2, "scheduled task"),
    "run_key": (2, "autostart persistence"), "suspicious_powershell": (2, "malware download"), "encoded_powershell": (2, "hidden PowerShell"),
    "tool_download": (2, "malware download"), "malicious_file": (2, "known trojan"), "malicious_domain": (2, "malware download"),
    "defender_tamper": (2, "antivirus tampering"), "log_cleared": (3, "log tampering"), "shadow_copy_delete": (3, "ransomware preparation"),
    "credential_dumping": (3, "credential theft"), "suspicious_outbound": (3, "command-and-control callbacks"),
    "ml_anomaly": (0, "unusual behaviour spotted by the anomaly model"), "malicious_ip": (0, "activity from a known malicious IP"),
}


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    risk: int
    first_seen: datetime
    last_seen: datetime
    alerts: list[Alert]
    ips: list[str]
    users: list[str]
    hosts: list[str]
    tactics: list[str]
    techniques: list[str]
    indicators: dict[str, list[str]] = field(default_factory=dict)
    assets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity, "risk": self.risk,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "alert_ids": [a.fingerprint for a in self.alerts], "ips": self.ips, "users": self.users, "hosts": self.hosts,
            "tactics": self.tactics, "techniques": self.techniques, "indicators": self.indicators, "assets": self.assets,
        }


class _Union:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def join(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def _logins(events: list[Event]) -> dict[tuple[str, str], tuple[list[float], list[str]]]:
    """(host, user) -> times and external IPs of successful logins, to trace a session to its origin."""
    table: dict[tuple[str, str], list[tuple[float, str]]] = defaultdict(list)
    for e in events:
        if e.kind == "auth_success" and e.user and e.host and is_external(e.src_ip):
            table[(e.host.lower(), e.user.lower())].append((e.epoch, e.src_ip))
    out = {}
    for k, rows in table.items():
        rows.sort()
        out[k] = ([t for t, _ in rows], [ip for _, ip in rows])
    return out


def _texts(alert: Alert) -> list[str]:
    texts = []
    for e in alert.evidence:
        for key in ("command", "script", "task_content", "image_path", "decoded"):
            if e.fields.get(key):
                texts.append(str(e.fields[key]))
    return texts


def indicators(alert: Alert) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {"ips": set(), "domains": set()}
    for text in _texts(alert):
        for host in URL_HOST.findall(text):
            (found["ips"] if IP_IN_TEXT.fullmatch(host) else found["domains"]).add(host.lower())
        for ip in IP_IN_TEXT.findall(text):
            if is_external(ip):
                found["ips"].add(ip)
    return found


def alert_keys(alert: Alert, logins) -> set[str]:
    keys: set[str] = set()
    if alert.ip and is_external(alert.ip):
        keys.add(f"ip:{alert.ip}")
    host = (alert.host or "").lower()
    actors = {alert.user} | {alert.details.get(k) for k in ("created_by", "changed_by")}
    for cmd in alert.details.get("commands") or []:
        m = CREATED_USER.search(str(cmd))
        if m:
            actors.add(m.group(1))
    for user in filter(None, actors):
        if not host:
            continue
        keys.add(f"user:{str(user).lower()}@{host}")
        times, ips = logins.get((host, str(user).lower()), ([], []))
        i = bisect_right(times, alert.first_seen.timestamp())
        if i and alert.first_seen.timestamp() - times[i - 1] <= WINDOW.total_seconds() and not alert.ip:
            keys.add(f"ip:{ips[i - 1]}")
    if host and alert.source != "firewall" and (not alert.ip and not alert.user or SEVERITY_RANK[alert.severity] >= SEVERITY_RANK["high"]):
        keys.add(f"host:{host}")
    found = indicators(alert)
    keys |= {f"ip:{ip}" for ip in found["ips"]} | {f"domain:{d}" for d in found["domains"]}
    return keys


def _title(alerts: list[Alert], ips: list[str], hosts: list[str]) -> str:
    best: dict[int, tuple[int, str]] = {}
    for a in alerts:
        stage, phrase = PHRASES.get(a.rule_id, (-1, ""))
        if stage >= 0 and (stage not in best or SEVERITY_RANK[a.severity] > best[stage][0]):
            best[stage] = (SEVERITY_RANK[a.severity], phrase)
    phrases = [best[st][1] for st in (1, 2, 3) if st in best] or [best[0][1]] if best else []
    if not phrases and 0 in best:
        phrases = [best[0][1]]
    seen: list[str] = []
    for p in phrases:
        if p not in seen:
            seen.append(p)
    text = ", ".join(seen[:-1]) + (" and " if len(seen) > 1 else "") + seen[-1] if seen else "suspicious activity"
    text = text[0].upper() + text[1:]
    where = f" on {hosts[0]}" if hosts else ""
    origin = f" from {ips[0]}" if ips else ""
    return f"{text}{where}{origin}"


def correlate(alerts: list[Alert], events: list[Event], malicious_ips: set[str] | None = None) -> list[Incident]:
    if not alerts:
        return []
    malicious_ips = malicious_ips or set()
    logins = _logins(events)
    keys = [alert_keys(a, logins) for a in alerts]
    uf = _Union(len(alerts))
    by_key: dict[str, list[int]] = defaultdict(list)
    for i, ks in enumerate(keys):
        for k in ks:
            by_key[k].append(i)
    for members in by_key.values():
        members.sort(key=lambda i: alerts[i].first_seen)
        for a, b in zip(members, members[1:]):
            if alerts[b].first_seen - alerts[a].last_seen <= WINDOW:
                uf.join(a, b)

    groups: dict[int, list[Alert]] = defaultdict(list)
    for i, a in enumerate(alerts):
        groups[uf.find(i)].append(a)

    incidents = []
    for members in groups.values():
        members.sort(key=lambda a: a.first_seen)
        severity = max_severity(*(a.severity for a in members))
        if SEVERITY_RANK[severity] < SEVERITY_RANK["medium"] and len(members) < 2:
            continue
        tactics: list[str] = []
        techniques: list[str] = []
        for a in members:
            for t in a.techniques:
                if t not in techniques:
                    techniques.append(t)
                tac = tactic_of(t)
                if tac and tac not in tactics:
                    tactics.append(tac)
        ips = _ordered(a.ip for a in members if a.ip and is_external(a.ip))
        counts = defaultdict(int)
        for a in members:
            if a.host and a.source != "firewall" and not re.fullmatch(r"[\d.:]+", a.host):
                counts[a.host] += 1 + SEVERITY_RANK[a.severity]
        hosts = sorted(counts, key=lambda h: -counts[h])
        assets = _ordered(h for a in members for h in [a.host, a.details.get("internal_host")] if h and re.fullmatch(r"[\d.:]+", h))
        users = _ordered(u for a in members for u in [a.user, a.details.get("created_by")] if u)
        found = {"ips": set(), "domains": set()}
        for a in members:
            for k, v in indicators(a).items():
                found[k] |= v
        got_in = any(a.rule_id in ("login_after_brute_force", "web_shell") or (a.rule_id in ("sql_injection", "path_traversal", "command_injection") and a.details.get("succeeded")) for a in members)
        dug_in = any(tac in tactics for tac in ("Persistence", "Privilege Escalation", "Impact", "Defense Evasion"))
        if got_in and dug_in:
            severity = "critical"
        risk = RISK_BASE[severity] + 4 * max(0, len(tactics) - 1) + (10 if malicious_ips & set(ips) else 0) + min(6, len(members) - 1)
        first = members[0]
        incidents.append(Incident(
            id=hashlib.sha1(f"{first.fingerprint}|{ips[:1]}|{hosts[:1]}".encode()).hexdigest()[:10],
            title=_title(members, ips, hosts), severity=severity, risk=min(100, risk),
            first_seen=first.first_seen, last_seen=max(a.last_seen for a in members), alerts=members,
            ips=ips, users=users, hosts=hosts, tactics=tactics, techniques=techniques,
            indicators={"ips": sorted(found["ips"] - set(ips)), "domains": sorted(found["domains"])}, assets=assets,
        ))
    incidents.sort(key=lambda inc: (-inc.risk, -inc.last_seen.timestamp()))
    return incidents


def _ordered(values) -> list[str]:
    out: list[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out
