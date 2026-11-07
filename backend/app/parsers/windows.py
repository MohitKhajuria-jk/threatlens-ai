"""Windows event logs exported as JSON or CSV.

Accepts the common export shapes:
- PowerShell:  Get-WinEvent ... | ConvertTo-Json   (or Export-Csv)
- Event Viewer: "Save All Events As" CSV
- Winlogbeat / Elastic (winlog.event_id, winlog.event_data)
- EVTX converters such as evtx_dump (Event.System / Event.EventData)
- Flat objects with EventID, TimeCreated, Computer and the event fields
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import tzinfo
from typing import Any

from ..models import Event, clean_ip
from .common import parse_time, to_int

# Fields we read from event data, by the names Windows uses.
MESSAGE_FIELDS = {
    "TargetUserName": ["Account Name", "New Account Name"],
    "IpAddress": ["Source Network Address"],
    "LogonType": ["Logon Type"],
    "WorkstationName": ["Workstation Name"],
    "ServiceName": ["Service Name"],
    "ImagePath": ["Service File Name"],
    "NewProcessName": ["New Process Name"],
    "CommandLine": ["Process Command Line"],
    "ParentProcessName": ["Creator Process Name", "Parent Process Name"],
    "TaskName": ["Task Name"],
    "GroupName": ["Group Name"],
    "MemberName": ["Member Name", "Member"],
}

SYSTEM_ACCOUNTS = re.compile(r"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|-|.*\$)$", re.I)
LOGON_TYPES = {2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock", 8: "network cleartext", 9: "new credentials", 10: "remote desktop", 11: "cached"}


def _dig(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _event_data(record: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for candidate in (_dig(record, "Event", "EventData"), _dig(record, "winlog", "event_data"), record.get("EventData"), record.get("event_data"), _dig(record, "Event", "UserData")):
        if isinstance(candidate, dict):
            if isinstance(candidate.get("Data"), list):  # [{"@Name": "TargetUserName", "#text": "bob"}]
                for item in candidate["Data"]:
                    if isinstance(item, dict):
                        name = item.get("@Name") or item.get("Name")
                        if name:
                            data[name] = item.get("#text", item.get("Value"))
            else:
                for k, v in candidate.items():
                    if isinstance(v, dict) and len(candidate) == 1:  # UserData wraps one element
                        data.update(v)
                    else:
                        data[k] = v
    for k, v in record.items():  # flat exports put the fields at the top level
        if k not in data and not isinstance(v, (dict, list)):
            data[k] = v
    return data


def _from_message(message: str, data: dict[str, Any]) -> None:
    """Event Viewer and Get-WinEvent CSVs only have the rendered message text; read fields from it.
    Messages list the acting account first ("Subject") and the target account later, so the last match wins."""
    if not message:
        return
    for field_name, labels in MESSAGE_FIELDS.items():
        if data.get(field_name) not in (None, "", "-"):
            continue
        for label in labels:
            found = re.findall(rf"^\s*{re.escape(label)}:\s*(.+?)\s*$", message, re.M)
            if found:
                data[field_name] = found[-1]
                break
    if "ScriptBlockText" not in data and "Creating Scriptblock text" in message:
        m = re.search(r"Creating Scriptblock text \(\d+ of \d+\):\s*(.*?)(?:\n\s*ScriptBlock ID:|$)", message, re.S)
        if m:
            data["ScriptBlockText"] = m.group(1).strip()


def normalize(record: dict[str, Any], tz: tzinfo) -> Event | None:
    event_id = to_int(record.get("EventID") or record.get("Id") or record.get("EventId") or record.get("Event ID") or record.get("event_id")
                      or _dig(record, "winlog", "event_id") or _dig(record, "event", "code") or _dig(record, "Event", "System", "EventID"))
    if isinstance(_dig(record, "Event", "System", "EventID"), dict):
        event_id = to_int(_dig(record, "Event", "System", "EventID", "#text"))
    when = (record.get("TimeCreated") or record.get("@timestamp") or record.get("timestamp") or record.get("TimeGenerated") or record.get("Date and Time")
            or _dig(record, "Event", "System", "TimeCreated", "#attributes", "SystemTime") or _dig(record, "Event", "System", "TimeCreated"))
    ts = parse_time(when, tz)
    if event_id is None or ts is None:
        return None
    host = (record.get("Computer") or record.get("MachineName") or _dig(record, "winlog", "computer_name") or _dig(record, "Event", "System", "Computer")
            or _dig(record, "host", "name"))
    provider = str(record.get("ProviderName") or record.get("Source") or _dig(record, "winlog", "provider_name") or _dig(record, "Event", "System", "Provider", "#attributes", "Name") or "")
    channel = str(record.get("LogName") or record.get("Channel") or _dig(record, "winlog", "channel") or _dig(record, "Event", "System", "Channel") or "")
    message = str(record.get("Message") or record.get("message") or record.get("Description") or "")
    data = _event_data(record)
    _from_message(message, data)
    raw = json.dumps(record, default=str)[:2000] if not record.get("_raw") else record["_raw"][:2000]
    return classify(event_id, ts, str(host) if host else None, provider, channel, message, data, raw)


def _clean_user(value: Any) -> str | None:
    if value in (None, "", "-"):
        return None
    text = str(value)
    if "\\" in text:
        text = text.split("\\")[-1]
    if text.upper().startswith("CN="):
        text = text[3:].split(",")[0]
    return text


def classify(event_id: int, ts, host, provider: str, channel: str, message: str, d: dict[str, Any], raw: str) -> Event:
    sysmon = "sysmon" in provider.lower() or "sysmon" in channel.lower()
    target = _clean_user(d.get("TargetUserName"))
    subject = _clean_user(d.get("SubjectUserName"))
    ip = clean_ip(str(d.get("IpAddress") or d.get("SourceNetworkAddress") or "")) if d.get("IpAddress") not in ("-", "::1", "127.0.0.1") else None
    base = {"ts": ts, "host": host, "raw": raw, "source": "windows"}
    fields: dict[str, Any] = {"event_id": event_id, "provider": provider or None, "channel": channel or None}

    if event_id in (4624, 4625) and not sysmon:
        logon_type = to_int(d.get("LogonType"))
        fields.update(logon_type=logon_type, logon_type_name=LOGON_TYPES.get(logon_type or 0), workstation=d.get("WorkstationName"),
                      status=d.get("Status") or d.get("SubStatus"), system_account=bool(target and SYSTEM_ACCOUNTS.match(target)))
        ok = event_id == 4624
        what = LOGON_TYPES.get(logon_type or 0, "logon")
        return Event(kind="auth_success" if ok else "auth_failure", outcome="success" if ok else "failure", user=target, src_ip=ip,
                     dst_port=3389 if logon_type == 10 else None, message=f"Windows {what} logon {'succeeded' if ok else 'failed'} for {target}",
                     fields=fields, **base)
    if event_id == 4740:
        return Event(kind="account_lockout", outcome="failure", user=target, message=f"Account {target} locked out", fields=fields, **base)
    if event_id == 4720:
        fields.update(new_user=target, created_by=subject)
        return Event(kind="user_created", outcome="success", user=target, message=f"New user account {target} created by {subject}", fields=fields, **base)
    if event_id in (4728, 4732, 4756):
        member = _clean_user(d.get("MemberName")) or _clean_user(d.get("MemberSid"))
        group = _clean_user(d.get("TargetUserName") if d.get("GroupName") in (None, "") else d.get("GroupName"))
        fields.update(member=member, group=group, changed_by=subject)
        return Event(kind="group_add", outcome="success", user=member, message=f"{member} added to group {group}", fields=fields, **base)
    if event_id in (4688,) or (event_id == 1 and sysmon):
        image = d.get("NewProcessName") or d.get("Image")
        cmd = d.get("CommandLine") or d.get("ProcessCommandLine") or image
        fields.update(image=image, command=cmd, parent=d.get("ParentProcessName") or d.get("ParentImage"), hashes=d.get("Hashes"))
        user = subject or _clean_user(d.get("User"))
        return Event(kind="process", outcome="success", user=user, message=f"Process started: {str(cmd)[:200]}", fields=fields, **base)
    if event_id in (7045, 4697):
        name = d.get("ServiceName")
        path = d.get("ImagePath") or d.get("ServiceFileName")
        fields.update(service_name=name, image_path=path, account=d.get("AccountName") or d.get("ServiceAccount"))
        return Event(kind="service_install", outcome="success", user=subject, message=f"Service installed: {name} ({path})", fields=fields, **base)
    if event_id == 4698:
        fields.update(task_name=d.get("TaskName"), task_content=str(d.get("TaskContent") or "")[:2000])
        return Event(kind="scheduled_task", outcome="success", user=subject, message=f"Scheduled task created: {d.get('TaskName')}", fields=fields, **base)
    if event_id in (1102, 104):
        return Event(kind="log_cleared", outcome="success", user=subject or _clean_user(d.get("SubjectUserName")), message="Event log cleared", fields=fields, **base)
    if event_id == 4104:
        script = str(d.get("ScriptBlockText") or "")
        fields.update(script=script[:4000], path=d.get("Path"))
        return Event(kind="powershell", outcome="success", user=subject, message=f"PowerShell ran: {script[:200]}", fields=fields, **base)
    if event_id == 3 and sysmon:
        fields.update(image=d.get("Image"), protocol=d.get("Protocol"))
        return Event(kind="net_connection", outcome="success", user=_clean_user(d.get("User")), src_ip=clean_ip(str(d.get("SourceIp") or "")),
                     dst_ip=clean_ip(str(d.get("DestinationIp") or "")), dst_port=to_int(d.get("DestinationPort")),
                     message=f"{d.get('Image')} connected to {d.get('DestinationIp')}:{d.get('DestinationPort')}", fields=fields, **base)
    if event_id == 22 and sysmon:
        fields.update(query=d.get("QueryName"), image=d.get("Image"))
        return Event(kind="dns_query", outcome="success", message=f"DNS lookup for {d.get('QueryName')}", fields=fields, **base)
    if event_id == 4672:
        return Event(kind="special_privileges", outcome="success", user=subject, message=f"Special privileges assigned to {subject}", fields=fields, **base)
    summary = message.strip().splitlines()[0][:200] if message.strip() else f"Event {event_id}"
    return Event(kind="windows_other", user=subject or target, message=summary, fields=fields, **base)


def _records_from_json(text: str) -> list[dict[str, Any]] | None:
    stripped = text.lstrip("﻿ \t\r\n")
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            for key in ("events", "Events", "records", "hits", "value"):
                if isinstance(data.get(key), list):
                    return [r for r in data[key] if isinstance(r, dict)]
            return [data]
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
    except json.JSONDecodeError:
        pass
    records = []  # JSON Lines
    for line in stripped.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    obj["_raw"] = line
                    records.append(obj)
            except json.JSONDecodeError:
                continue
    return records or None


def _records_from_csv(text: str) -> list[dict[str, Any]] | None:
    sample = text.lstrip("﻿")[:4000]
    first = sample.splitlines()[0] if sample else ""
    if not re.search(r"\b(Event ?ID|Id)\b", first, re.I):
        return None
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    rows = list(reader)
    if len(rows) < 2:
        return None
    head = [h.strip() for h in rows[0]]
    records = []
    for row in rows[1:]:
        if not row:
            continue
        rec = dict(zip(head, row))
        if len(row) > len(head):  # Event Viewer puts the description in an extra, unnamed column
            rec["Message"] = row[len(head)]
        rec["_raw"] = ",".join(row)
        records.append(rec)
    return records


def parse(text: str, tz: tzinfo) -> tuple[list[Event], int] | None:
    records = _records_from_json(text)
    if records is None:
        records = _records_from_csv(text)
    if not records:
        return None
    events = []
    for no, rec in enumerate(records, 1):
        ev = normalize(rec, tz)
        if ev:
            ev.line_no = no
            events.append(ev)
    return events, len(records)
