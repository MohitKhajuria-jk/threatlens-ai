"""Helpers shared by the log parsers: timestamps and timezones."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}


def local_tz(name: str = "") -> tzinfo:
    """The timezone for log lines without one. Falls back to this computer's timezone."""
    if name:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    return datetime.now().astimezone().tzinfo or timezone.utc


def syslog_time(month: str, day: str, clock: str, tz: tzinfo, now: datetime | None = None) -> datetime | None:
    """Classic syslog has no year: use the current one, or last year if that would be in the future."""
    m = MONTHS.get(month[:3].lower())
    if not m:
        return None
    now = now or datetime.now(timezone.utc)
    try:
        h, mi, s = (int(x) for x in clock.split(":"))
        ts = datetime(now.year, m, int(day), h, mi, s, tzinfo=tz)
    except ValueError:
        return None
    if ts.astimezone(timezone.utc) > now + timedelta(days=2):
        ts = ts.replace(year=now.year - 1)
    return ts.astimezone(timezone.utc)


_DOTNET_DATE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")


def parse_time(value: object, tz: tzinfo) -> datetime | None:
    """ISO 8601, '2026-11-06 10:15:01', Apache's '06/Nov/2026:10:15:01 +0530', .NET '/Date(ms)/' or epoch seconds."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, timezone.utc)
    if isinstance(value, dict):  # {"SystemTime": "..."} in EVTX exports
        for key in ("SystemTime", "#attributes", "@SystemTime", "value"):
            if key in value:
                return parse_time(value[key], tz)
        return None
    text = str(value).strip()
    m = _DOTNET_DATE.search(text)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, timezone.utc)
    try:
        return _with_tz(datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z"), tz)
    except ValueError:
        pass
    iso = text.replace(" ", "T", 1) if re.match(r"\d{4}-\d{2}-\d{2} \d", text) else text
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)  # Windows writes 7 fractional digits
    iso = re.sub(r"\.(\d{1,5})(?=\D|$)", lambda m: "." + m.group(1).ljust(6, "0"), iso)  # Python 3.10 needs 3 or 6
    iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", iso)  # journalctl writes +0530; older Pythons need +05:30
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    try:
        return _with_tz(datetime.fromisoformat(iso), tz)
    except ValueError:
        pass
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%d-%m-%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return _with_tz(datetime.strptime(text, fmt), tz)
        except ValueError:
            continue
    return None


def _with_tz(dt: datetime, tz: tzinfo) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.astimezone(timezone.utc)


def to_int(value: object) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
