"""Shared data types: normalized log events, alerts and incidents."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def max_severity(*values: str) -> str:
    return max(values, key=lambda s: SEVERITY_RANK.get(s, 0)) if values else "low"


def bump(severity: str, steps: int = 1) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, SEVERITY_RANK.get(severity, 0) + steps)]


@dataclass
class Event:
    """One log line in a common shape, whatever format it came from."""

    ts: datetime  # always timezone-aware, UTC
    source: str  # linux | web | windows | firewall
    kind: str  # e.g. auth_failure, auth_success, sudo, http_request, process, fw_block
    raw: str
    host: str | None = None
    outcome: str | None = None  # success | failure
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    user: str | None = None
    message: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    line_no: int = 0
    id: int | None = None
    dataset_id: str | None = None

    @property
    def epoch(self) -> float:
        return self.ts.timestamp()

    @property
    def count(self) -> int:
        """Lines like 'message repeated 5 times' stand for several events."""
        return int(self.fields.get("repeat", 1) or 1)


@dataclass
class Alert:
    rule_id: str
    title: str
    short: str  # a few words, used to build incident titles
    severity: str
    source: str
    techniques: list[str]
    first_seen: datetime
    last_seen: datetime
    description: str
    evidence: list[Event]
    count: int = 1
    ip: str | None = None
    user: str | None = None
    host: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        import hashlib

        key = "|".join([self.rule_id, self.ip or "", self.user or "", self.host or "", self.first_seen.strftime("%Y-%m-%dT%H")])
        return hashlib.sha1(key.encode()).hexdigest()[:12]


def utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]
_DOCUMENTATION = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


@lru_cache(maxsize=65536)
def parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    value = value.strip().strip("[]")
    if value.startswith("::ffff:"):
        value = value[7:]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_internal(value: str | None) -> bool:
    ip = parse_ip(value)
    return bool(ip) and any(ip in net for net in _INTERNAL if net.version == ip.version)


def is_external(value: str | None) -> bool:
    """A routable or documentation address, i.e. traffic from outside your network."""
    ip = parse_ip(value)
    if not ip or ip.is_unspecified or ip.is_multicast or is_internal(value):
        return False
    return True


def is_documentation(value: str | None) -> bool:
    """The reserved example ranges (TEST-NET), used by the demo data. Never looked up with paid or rate-limited APIs."""
    ip = parse_ip(value)
    return bool(ip) and any(ip in net for net in _DOCUMENTATION if net.version == ip.version)


def clean_ip(value: str | None) -> str | None:
    ip = parse_ip(value)
    return str(ip) if ip else None
