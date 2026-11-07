"""Apache and Nginx access logs (common and combined formats, optionally with a vhost prefix)."""

from __future__ import annotations

import re
from datetime import tzinfo
from urllib.parse import unquote_plus, urlsplit

from ..models import Event, clean_ip
from .common import parse_time, to_int

LINE = re.compile(
    r'^(?:(?P<vhost>[\w.-]+(?::\d+)?) )?(?P<ip>[0-9a-fA-F.:]+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)


def decode(value: str) -> str:
    """URL-decode twice, which uncovers double-encoded attack strings like %252e%252e%252f."""
    once = unquote_plus(value)
    return unquote_plus(once) if "%" in once else once


def parse_line(line: str, tz: tzinfo) -> Event | None:
    m = LINE.match(line)
    if not m:
        return None
    ts = parse_time(m["ts"], tz)
    if ts is None:
        return None
    request = m["request"]
    parts = request.split(" ")
    method, target, protocol = (parts + ["", ""])[:3] if len(parts) >= 2 else ("", request, "")
    if not re.fullmatch(r"[A-Z]{3,10}", method or ""):
        method, target = "", request  # garbage or TLS bytes sent to a plain HTTP port
    split = urlsplit(target if target.startswith("/") else "/" + target) if method else None
    path = split.path if split else ""
    query = split.query if split else ""
    status = int(m["status"])
    user = m["user"] if m["user"] != "-" else None
    return Event(
        source="web",
        kind="http_request" if method else "http_malformed",
        outcome="success" if status < 400 else "failure",
        src_ip=clean_ip(m["ip"]),
        host=(m["vhost"] or "").split(":")[0] or None,
        user=user,
        message=f"{method or 'Malformed request'} {target[:180]} → {status}",
        raw=line[:2000],
        ts=ts,
        fields={
            "method": method or None,
            "path": path,
            "query": query,
            "target": target[:2000],
            "decoded": decode(target)[:2000],
            "status": status,
            "bytes": to_int(m["bytes"]) or 0,
            "referer": None if m["referer"] in (None, "-") else m["referer"],
            "user_agent": None if m["ua"] in (None, "-") else m["ua"],
            "protocol": protocol or None,
        },
    )


def parse(lines: list[str], tz: tzinfo) -> tuple[list[Event], int]:
    events = []
    for no, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        ev = parse_line(line, tz)
        if ev:
            ev.line_no = no
            events.append(ev)
    return events, len(events)
