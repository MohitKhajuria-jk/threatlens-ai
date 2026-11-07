"""Firewall logs that aren't syslog: Windows Firewall (pfirewall.log), key=value logs
(FortiGate and similar) and CSV exports with source/destination columns.
UFW and iptables lines are handled by the syslog parser."""

from __future__ import annotations

import csv
import io
import re
from datetime import tzinfo

from ..models import Event, clean_ip
from .common import parse_time, to_int

BLOCK_WORDS = ("drop", "block", "deny", "reject", "denied", "blocked", "dropped")
KV = re.compile(r'(\w[\w.-]*)=("(?:[^"\\]|\\.)*"|\S+)')
PROTOCOLS = {"6": "TCP", "17": "UDP", "1": "ICMP"}


def _event(ts, action: str, src, dst, dport, sport, proto, raw: str, host=None, extra=None) -> Event:
    action = "block" if any(w in str(action).lower() for w in BLOCK_WORDS) else "allow"
    proto = PROTOCOLS.get(str(proto), str(proto).upper() if proto else None)
    dport = to_int(dport)
    return Event(
        ts=ts, source="firewall", kind=f"fw_{action}", outcome="failure" if action == "block" else "success",
        src_ip=clean_ip(src), dst_ip=clean_ip(dst), dst_port=dport, host=host, raw=raw[:2000],
        message=f"Firewall {action} {proto or ''} {src} → {dst}{':' + str(dport) if dport else ''}".replace("  ", " "),
        fields={"action": action, "protocol": proto, "src_port": to_int(sport), **(extra or {})},
    )


def parse_windows_firewall(lines: list[str], tz: tzinfo) -> tuple[list[Event], int] | None:
    fields: list[str] | None = None
    events, recognised = [], 0
    for no, line in enumerate(lines, 1):
        line = line.strip()
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].split()
            continue
        if not line or line.startswith("#") or not fields:
            continue
        values = line.split()
        if len(values) < 6:
            continue
        rec = dict(zip(fields, values))
        ts = parse_time(f"{rec.get('date')} {rec.get('time')}", tz)
        if ts is None:
            continue
        recognised += 1
        direction = {"SEND": "outbound", "RECEIVE": "inbound"}.get(rec.get("path", "").upper())
        ev = _event(ts, rec.get("action", ""), rec.get("src-ip"), rec.get("dst-ip"), rec.get("dst-port"), rec.get("src-port"), rec.get("protocol"),
                    line, extra={"direction": direction, "rule": "Windows Firewall"})
        ev.line_no = no
        events.append(ev)
    return (events, recognised) if fields else None


def parse_kv(lines: list[str], tz: tzinfo) -> tuple[list[Event], int]:
    events = []
    for no, line in enumerate(lines, 1):
        pairs = {k.lower(): v.strip('"') for k, v in KV.findall(line)}
        src = pairs.get("srcip") or pairs.get("src") or pairs.get("src_ip")
        dst = pairs.get("dstip") or pairs.get("dst") or pairs.get("dst_ip")
        if not (src and dst and clean_ip(src) and clean_ip(dst)):
            continue
        when = f"{pairs['date']} {pairs['time']}" if "date" in pairs and "time" in pairs else pairs.get("timestamp") or pairs.get("eventtime")
        if when and when.isdigit():
            when = int(when) / (1e9 if len(when) > 16 else 1e6 if len(when) > 13 else 1e3 if len(when) > 10 else 1)
        ts = parse_time(when, tz)
        if ts is None:
            continue
        ev = _event(ts, pairs.get("action", ""), src, dst, pairs.get("dstport") or pairs.get("dpt") or pairs.get("dst_port"),
                    pairs.get("srcport") or pairs.get("spt"), pairs.get("proto") or pairs.get("protocol"), line.strip(),
                    host=pairs.get("devname") or pairs.get("hostname"), extra={"rule": pairs.get("policyname") or pairs.get("policyid"), "direction": None})
        ev.line_no = no
        events.append(ev)
    return events, len(events)


COLUMN_NAMES = {
    "ts": ("timestamp", "time", "datetime", "date_time", "date", "@timestamp", "event_time"),
    "action": ("action", "result", "disposition", "verdict"),
    "src": ("src_ip", "source_ip", "srcip", "src", "source", "source address", "src_addr"),
    "dst": ("dst_ip", "destination_ip", "dstip", "dst", "destination", "destination address", "dst_addr"),
    "dport": ("dst_port", "destination_port", "dstport", "dport", "dpt", "port", "destination port"),
    "sport": ("src_port", "source_port", "srcport", "sport", "spt", "source port"),
    "proto": ("protocol", "proto"),
}


def parse_csv(text: str, tz: tzinfo) -> tuple[list[Event], int] | None:
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    if not reader.fieldnames:
        return None
    lookup = {h.strip().lower(): h for h in reader.fieldnames}
    cols = {key: next((lookup[n] for n in names if n in lookup), None) for key, names in COLUMN_NAMES.items()}
    if not (cols["src"] and cols["dst"] and cols["ts"]):
        return None
    events = []
    for no, row in enumerate(reader, 2):
        ts = parse_time(row.get(cols["ts"]), tz)
        if ts is None:
            continue
        get = lambda k: row.get(cols[k]) if cols[k] else None  # noqa: E731
        ev = _event(ts, get("action") or "allow", get("src"), get("dst"), get("dport"), get("sport"), get("proto"), ",".join(str(v) for v in row.values()))
        ev.line_no = no
        events.append(ev)
    return events, len(events)
