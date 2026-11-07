"""Detects a log file's format and parses it into normalized events."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, tzinfo

from ..models import Event
from . import firewall, syslog, web, windows

FORMAT_LABELS = {
    "linux_syslog": "Linux auth / syslog",
    "web_access": "Web server access log",
    "linux_firewall": "Firewall log (UFW / iptables)",
    "windows_json": "Windows events (JSON)",
    "windows_csv": "Windows events (CSV)",
    "windows_evtx": "Windows event log (.evtx)",
    "windows_firewall": "Windows Firewall log",
    "firewall_kv": "Firewall log (key=value)",
    "firewall_csv": "Firewall log (CSV)",
}
SOURCE_LABELS = {"linux": "Linux", "web": "Web server", "windows": "Windows", "firewall": "Firewall"}


@dataclass
class ParseResult:
    format: str | None
    events: list[Event]
    lines: int
    recognised: int
    samples_skipped: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return FORMAT_LABELS.get(self.format or "", "Unknown format")

    @property
    def source(self) -> str | None:
        counts = Counter(e.source for e in self.events)
        return counts.most_common(1)[0][0] if counts else None


def parse_text(text: str, tz: tzinfo, now: datetime | None = None) -> ParseResult:
    text = text.lstrip("﻿")
    lines = text.splitlines()
    total = sum(1 for line in lines if line.strip())
    head = "\n".join(lines[:20])

    if "#Fields:" in head and "src-ip" in head:
        parsed = firewall.parse_windows_firewall(lines, tz)
        if parsed:
            return _result("windows_firewall", parsed, total, lines)

    stripped = text.lstrip()
    if stripped[:1] in "[{":
        parsed = windows.parse(text, tz)
        if parsed and parsed[0]:
            return _result("windows_json", parsed, total, lines)

    first = lines[0] if lines else ""
    if first.count(",") >= 2 and not syslog.header(first, tz, now) and not web.LINE.match(first):
        parsed = windows.parse(text, tz) if windows._records_from_csv(text) else None
        if parsed and parsed[0]:
            return _result("windows_csv", parsed, total, lines)
        parsed = firewall.parse_csv(text, tz)
        if parsed and parsed[0]:
            return _result("firewall_csv", parsed, total, lines)

    # Line-based formats: try each on a sample and keep the one that understands the most lines.
    sample = lines[:300]
    candidates = {
        "linux_syslog": syslog.parse(sample, tz, now)[1],
        "web_access": web.parse(sample, tz)[1],
        "firewall_kv": firewall.parse_kv(sample, tz)[1],
    }
    best, score = max(candidates.items(), key=lambda kv: kv[1])
    if score == 0:
        return ParseResult(None, [], total, 0, [line[:300] for line in lines if line.strip()][:5])
    if best == "linux_syslog":
        parsed = syslog.parse(lines, tz, now)
    elif best == "web_access":
        parsed = web.parse(lines, tz)
    else:
        parsed = firewall.parse_kv(lines, tz)
    return _result(best, parsed, total, lines)


def _result(fmt: str, parsed: tuple[list[Event], int], total: int, lines: list[str]) -> ParseResult:
    events, recognised = parsed
    if fmt in ("windows_json", "windows_csv"):
        total = recognised  # records, not text lines
    if fmt == "linux_syslog" and events and sum(e.source == "firewall" for e in events) > len(events) / 2:
        fmt = "linux_firewall"
    seen = {e.line_no for e in events}
    skipped = [line[:300] for no, line in enumerate(lines, 1) if line.strip() and no not in seen and not line.startswith("#")][:5] if fmt not in ("windows_json", "windows_csv") else []
    return ParseResult(fmt, events, total, recognised, skipped)
