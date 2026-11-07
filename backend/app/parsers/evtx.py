"""Raw Windows event log files (.evtx), read directly with python-evtx."""

from __future__ import annotations

import logging
import os
import tempfile
import xml.etree.ElementTree as ET
from datetime import tzinfo
from typing import Any

from ..models import Event
from .windows import normalize

log = logging.getLogger("parsers.evtx")
MAGIC = b"ElfFile\x00"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def record_to_dict(xml: str) -> dict[str, Any] | None:
    """Flattens one event's XML into the shape the Windows parser understands."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    system = root.find(f"{NS}System")
    if system is None:
        return None
    rec: dict[str, Any] = {}
    for child in system:
        name = _local(child.tag)
        if name == "EventID":
            rec["EventID"] = (child.text or "").strip()
        elif name == "TimeCreated":
            rec["TimeCreated"] = child.get("SystemTime")
        elif name == "Computer":
            rec["Computer"] = child.text
        elif name == "Provider":
            rec["ProviderName"] = child.get("Name")
        elif name == "Channel":
            rec["LogName"] = child.text
    data: dict[str, Any] = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for i, item in enumerate(event_data):
            data[item.get("Name") or f"Data{i}"] = item.text
    user_data = root.find(f"{NS}UserData")
    if user_data is not None:  # e.g. 1102 "log cleared" puts its fields here
        for wrapper in user_data:
            for item in wrapper:
                data[_local(item.tag)] = item.text
    rec["EventData"] = data
    rec["_raw"] = xml.replace("\n", "")[:2000]
    return rec


def parse(raw: bytes, tz: tzinfo, limit: int = 500_000) -> tuple[list[Event], int]:
    """Returns (events, records read). python-evtx reads from a path, so the bytes go to a temp file first."""
    import Evtx.Evtx as evtx  # imported here so the rest of the app still works without the package

    events: list[Event] = []
    seen = 0
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(raw)
        path = tmp.name
    try:
        with evtx.Evtx(path) as log:
            for record in log.records():
                if seen >= limit:
                    break
                seen += 1
                try:
                    rec = record_to_dict(record.xml())
                except Exception:  # a damaged record shouldn't stop the rest of the file
                    continue
                ev = normalize(rec, tz) if rec else None
                if ev:
                    ev.line_no = seen
                    events.append(ev)
    finally:
        os.unlink(path)
    return events, seen
