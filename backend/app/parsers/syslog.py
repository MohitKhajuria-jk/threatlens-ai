"""Linux syslog files: SSH and other authentication events (auth.log, secure), plus
UFW/iptables firewall lines, which the kernel writes into the same files."""

from __future__ import annotations

import re
from datetime import datetime, tzinfo

from ..models import Event, clean_ip
from .common import parse_time, syslog_time, to_int

# "Nov  6 10:15:01 web-01 sshd[1234]: message" or "2026-11-06T10:15:01.123+05:30 web-01 sshd[1234]: message"
CLASSIC = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")

REPEATED = re.compile(r"^message repeated (\d+) times: \[\s*(.*?)\s*\]$")
SSH_FAILED = re.compile(r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")
SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SSH_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")
SSH_MAX = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SSH_PROBE = re.compile(r"^(?:Did not receive identification string from|banner exchange: Connection from|Unable to negotiate with|Bad protocol version identification .* from) (?P<ip>[0-9a-fA-F.:]+)")
SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<error>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<target>\S+) ; (?:ENV=.*? ; )?COMMAND=(?P<cmd>.+)$")
PAM_FAIL = re.compile(r"pam_unix\((?P<svc>[\w-]+):auth\): authentication failure;.*?(?:rhost=(?P<ip>\S*))?(?:\s+user=(?P<user>\S+))?\s*$")
SU = re.compile(r"(?:Successful su for (?P<target>\S+) by (?P<user>\S+)|pam_unix\(su(?:-l)?:session\): session opened for user (?P<target2>\S+?)(?:\(uid=\d+\))? by (?P<user2>\S+?)(?:\(uid=\d+\))?$)")
USERADD = re.compile(r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")
GROUP_ADD = re.compile(r"(?:add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'|user (?P<user2>\S+) added by \S+ to group (?P<group2>\S+))")
PASSWD = re.compile(r"password changed for (?P<user>\S+)")
CRON = re.compile(r"^\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)\s*$")
KV = re.compile(r"\b([A-Z]+)=(\S*)")
FW_TAG = re.compile(r"\[(?P<tag>UFW [A-Z ]+|[A-Za-z0-9_ -]*(?:DROP|BLOCK|REJECT|DENY|ACCEPT|ALLOW)[A-Za-z0-9_ -]*)\]|(?P<prefix>[A-Za-z0-9_-]*(?:DROP|BLOCK|REJECT|DENY|ACCEPT|ALLOW)[A-Za-z0-9_-]*):?\s+IN=", re.I)


def header(line: str, tz: tzinfo, now: datetime | None = None) -> tuple[datetime, str, str, str] | None:
    m = CLASSIC.match(line)
    if m:
        ts = syslog_time(m["mon"], m["day"], m["clock"], tz, now)
    else:
        m = ISO.match(line)
        ts = parse_time(m["ts"], tz) if m else None
    if not m or ts is None:
        return None
    return ts, m["host"], m["prog"].lower(), m["msg"]


def parse_line(line: str, tz: tzinfo, now: datetime | None = None) -> Event | None:
    parts = header(line, tz, now)
    if not parts:
        return None
    ts, host, prog, msg = parts
    repeat = 1
    r = REPEATED.match(msg)
    if r:
        repeat, msg = int(r.group(1)), r.group(2)
    base = {"ts": ts, "host": host, "raw": line[:2000]}

    if prog == "kernel" and "SRC=" in msg:
        return firewall_event(msg, base)

    if prog.startswith("sshd"):
        if m := SSH_FAILED.search(msg):
            invalid = bool(m["invalid"])
            return Event(source="linux", kind="auth_failure", outcome="failure", src_ip=clean_ip(m["ip"]), user=m["user"] or None,
                         dst_port=22, message=f"Failed SSH {m['method']} for {'invalid user ' if invalid else ''}{m['user']}",
                         fields={"service": "ssh", "method": m["method"], "invalid_user": invalid, "src_port": to_int(m["port"]), "repeat": repeat}, **base)
        if m := SSH_ACCEPTED.search(msg):
            return Event(source="linux", kind="auth_success", outcome="success", src_ip=clean_ip(m["ip"]), user=m["user"], dst_port=22,
                         message=f"SSH login accepted for {m['user']} ({m['method']})", fields={"service": "ssh", "method": m["method"], "src_port": to_int(m["port"])}, **base)
        if m := SSH_INVALID.search(msg):
            return Event(source="linux", kind="auth_invalid_user", outcome="failure", src_ip=clean_ip(m["ip"]), user=m["user"] or None, dst_port=22,
                         message=f"SSH attempt for unknown user {m['user']}", fields={"service": "ssh", "repeat": repeat}, **base)
        if m := SSH_MAX.search(msg):
            return Event(source="linux", kind="auth_max_attempts", outcome="failure", src_ip=clean_ip(m["ip"]), user=m["user"], dst_port=22,
                         message=f"Too many SSH attempts for {m['user']}", fields={"service": "ssh"}, **base)
        if m := SSH_PROBE.search(msg):
            return Event(source="linux", kind="ssh_probe", src_ip=clean_ip(m["ip"]), dst_port=22, message="SSH connection without a login (probe)",
                         fields={"service": "ssh", "repeat": repeat}, **base)
        return None

    if prog == "sudo":
        if m := SUDO.match(msg):
            error = (m["error"] or "").strip()
            return Event(source="linux", kind="sudo", outcome="failure" if error else "success", user=m["user"],
                         message=f"sudo as {m['target']}: {m['cmd'][:200]}" + (f" ({error})" if error else ""),
                         fields={"command": m["cmd"], "target_user": m["target"], "tty": m["tty"], "cwd": m["pwd"], "error": error or None, "repeat": repeat}, **base)
        if m := PAM_FAIL.search(msg):
            return Event(source="linux", kind="sudo", outcome="failure", user=m["user"], message=f"sudo password failure for {m['user']}",
                         fields={"error": "authentication failure", "repeat": repeat}, **base)
        return None

    if prog in ("su", "su-l"):
        if m := SU.search(msg):
            return Event(source="linux", kind="su", outcome="success", user=m["user"] or m["user2"],
                         message=f"su to {m['target'] or m['target2']}", fields={"target_user": m["target"] or m["target2"]}, **base)
        return None

    if prog == "useradd" and (m := USERADD.search(msg)):
        return Event(source="linux", kind="user_created", outcome="success", user=m["user"].strip(), message=f"New user account {m['user'].strip()} created",
                     fields={"new_user": m["user"].strip(), "uid": to_int(m["uid"])}, **base)

    if prog in ("usermod", "gpasswd", "useradd"):
        if m := GROUP_ADD.search(msg):
            user, group = m["user"] or m["user2"], m["group"] or m["group2"]
            return Event(source="linux", kind="group_add", outcome="success", user=user, message=f"{user} added to group {group}",
                         fields={"member": user, "group": group}, **base)
        return None

    if prog in ("passwd", "chpasswd") and (m := PASSWD.search(msg)):
        return Event(source="linux", kind="password_change", outcome="success", user=m["user"], message=f"Password changed for {m['user']}", **base)

    if prog in ("cron", "crond") and (m := CRON.match(msg)):
        return Event(source="linux", kind="cron", user=m["user"], message=f"Scheduled command run: {m['cmd'][:200]}", fields={"command": m["cmd"]}, **base)

    if m := PAM_FAIL.search(msg):  # e.g. login, vsftpd, other services using PAM
        return Event(source="linux", kind="auth_failure", outcome="failure", src_ip=clean_ip(m["ip"]), user=m["user"],
                     message=f"{m['svc']} authentication failure", fields={"service": m["svc"], "repeat": repeat, "pam": True}, **base)
    return None


def firewall_event(msg: str, base: dict) -> Event:
    kv = dict(KV.findall(msg))
    tag_match = FW_TAG.search(msg)
    tag = (tag_match["tag"] or tag_match["prefix"] or "") if tag_match else ""
    upper = tag.upper()
    action = "block" if any(w in upper for w in ("BLOCK", "DROP", "REJECT", "DENY")) else "allow"
    direction = "outbound" if kv.get("OUT") and not kv.get("IN") else "inbound"
    proto = kv.get("PROTO", "").upper() or None
    dpt = to_int(kv.get("DPT"))
    return Event(source="firewall", kind=f"fw_{action}", outcome="failure" if action == "block" else "success",
                 src_ip=clean_ip(kv.get("SRC")), dst_ip=clean_ip(kv.get("DST")), dst_port=dpt,
                 message=f"Firewall {action} {proto or ''} {kv.get('SRC')} → {kv.get('DST')}{':' + str(dpt) if dpt else ''}".replace("  ", " "),
                 fields={"action": action, "protocol": proto, "src_port": to_int(kv.get("SPT")), "direction": direction, "rule": tag or None,
                         "interface": kv.get("IN") or kv.get("OUT") or None}, **base)


def parse(lines: list[str], tz: tzinfo, now: datetime | None = None) -> tuple[list[Event], int]:
    """Returns the events and the number of lines that looked like syslog (parsed or not)."""
    events, recognised = [], 0
    for no, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if header(line, tz, now):
            recognised += 1
        ev = parse_line(line, tz, now)
        if ev:
            ev.line_no = no
            events.append(ev)
    return events, recognised
