"""Detection rules. Each rule reads normalized events and returns alerts with evidence.

Rules group related events (by attacker IP, user or host, and time) so one attack
produces one alert with a count, not hundreds of alerts.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, Iterable

from ..models import Alert, Event, is_external, is_internal, max_severity

MAX_EVIDENCE = 60


@dataclass
class Thresholds:
    brute_force_attempts: int = 8
    brute_force_gap_minutes: int = 10
    success_lookback_minutes: int = 60
    success_min_failures: int = 5
    spray_min_users: int = 5
    port_scan_ports: int = 15
    host_sweep_hosts: int = 10
    scan_gap_minutes: int = 2
    dir_bruteforce_404s: int = 40
    sudo_failures: int = 3


def sessions(events: Iterable[Event], key: Callable[[Event], object], gap: timedelta) -> list[tuple[object, list[Event]]]:
    """Group events by key, then split each group wherever there is a quiet gap longer than `gap`."""
    groups: dict[object, list[Event]] = defaultdict(list)
    for e in events:
        k = key(e)
        if k is not None:
            groups[k].append(e)
    out = []
    for k, evs in groups.items():
        evs.sort(key=lambda e: e.ts)
        current = [evs[0]]
        for e in evs[1:]:
            if e.ts - current[-1].ts > gap:
                out.append((k, current))
                current = []
            current.append(e)
        out.append((k, current))
    return out


def weight(events: list[Event]) -> int:
    return sum(e.count for e in events)


def sample(events: list[Event]) -> list[Event]:
    """Keep the first and last events plus an even spread in between."""
    if len(events) <= MAX_EVIDENCE:
        return events
    step = len(events) / (MAX_EVIDENCE - 2)
    picked = [events[int(i * step)] for i in range(MAX_EVIDENCE - 2)]
    return [events[0], *picked[1:], events[-1]]


def make(rule_id, title, short, severity, source, techniques, events, description, *, ip=None, user=None, host=None, count=None, **details) -> Alert:
    events = sorted(events, key=lambda e: e.ts)
    return Alert(rule_id=rule_id, title=title, short=short, severity=severity, source=source, techniques=techniques,
                 first_seen=events[0].ts, last_seen=events[-1].ts, description=description, evidence=sample(events),
                 count=count if count is not None else weight(events), ip=ip, user=user, host=host, details=details)


def platform(source: str) -> str:
    return "Windows" if source == "windows" else "SSH" if source == "linux" else source


# --------------------------------------------------------------------- authentication

def brute_force(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    failures = [e for e in events if e.kind == "auth_failure" and not e.fields.get("system_account")]
    key = lambda e: (e.source, e.host, e.src_ip or f"user:{e.user}")  # noqa: E731
    for (source, host, who), evs in sessions(failures, key, timedelta(minutes=t.brute_force_gap_minutes)):
        attempts = weight(evs)
        if attempts < t.brute_force_attempts:
            continue
        users = Counter()
        for e in evs:
            users[e.user or "?"] += e.count
        ip = None if str(who).startswith("user:") else who
        spraying = len(users) >= t.spray_min_users and users.most_common(1)[0][1] <= max(3, attempts // len(users) + 2)
        what = "Windows logon" if source == "windows" else "SSH" if any(e.fields.get("service") == "ssh" for e in evs) else "Login"
        origin = f" from {ip}" if ip else ""
        top_user = users.most_common(1)[0][0] if len(users) == 1 else None
        minutes = max(1, round((evs[-1].ts - evs[0].ts).total_seconds() / 60))
        logon_types = Counter(e.fields.get("logon_type_name") for e in evs if e.fields.get("logon_type_name"))
        if spraying:
            title, short, tech = f"Password spraying against {host}{origin}", "Password spraying", ["T1110.003"]
        else:
            title, short, tech = f"{what} brute-force attack on {host}{origin}", f"{what} brute force", ["T1110.001"]
        severity = "high" if attempts >= 100 else "medium"
        alerts.append(make("brute_force", title, short, severity, source, tech, evs,
                           f"{attempts} failed {what} logins in {minutes} min against {len(users)} account(s)"
                           f"{' (' + ', '.join(u for u, _ in users.most_common(4)) + ')' if users else ''}.",
                           ip=ip, host=host, user=top_user, attempts=attempts, accounts=dict(users.most_common(10)),
                           invalid_users=sum(e.count for e in evs if e.fields.get("invalid_user")), logon_types=dict(logon_types)))
    return alerts


def login_after_brute_force(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    failures: dict[tuple, list[Event]] = defaultdict(list)
    lookback = timedelta(minutes=t.success_lookback_minutes)
    for e in sorted(events, key=lambda e: e.ts):
        if not e.src_ip:
            continue
        k = (e.source, e.host, e.src_ip)
        if e.kind == "auth_failure":
            failures[k].append(e)
        elif e.kind == "auth_success":
            recent = [f for f in failures[k] if e.ts - lookback <= f.ts <= e.ts]
            if weight(recent) >= t.success_min_failures:
                via = "RDP" if e.fields.get("logon_type") == 10 else "SSH" if e.fields.get("service") == "ssh" else "login"
                tech = ["T1110", "T1078"] + (["T1133"] if is_external(e.src_ip) else []) + (["T1021.001"] if via == "RDP" else [])
                alerts.append(make("login_after_brute_force", f"Successful {via} login as {e.user} after {weight(recent)} failed attempts",
                                   "Login after brute force", "critical", e.source, tech, [*recent[-20:], e],
                                   f"{e.src_ip} failed to log in {weight(recent)} times, then logged in to {e.host} as {e.user}. "
                                   "The password was probably guessed, so treat the account as compromised.",
                                   ip=e.src_ip, user=e.user, host=e.host, count=weight(recent) + 1, failed_before=weight(recent)))
                failures[k] = []
    return alerts


def remote_logins(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    for e in events:
        if e.kind != "auth_success" or not is_external(e.src_ip):
            continue
        if e.source == "windows" and e.fields.get("logon_type") == 10:
            alerts.append(make("rdp_from_internet", f"Remote Desktop login from the internet as {e.user}", "RDP login from the internet", "medium",
                               "windows", ["T1133", "T1021.001"], [e], f"{e.user} logged in to {e.host} over Remote Desktop from external address {e.src_ip}.",
                               ip=e.src_ip, user=e.user, host=e.host))
        elif e.source == "linux" and e.user == "root" and e.fields.get("service") == "ssh":
            alerts.append(make("root_ssh_login", f"Root logged in over SSH from {e.src_ip}", "Root SSH login", "high", "linux", ["T1078.003", "T1133"], [e],
                               f"The root account logged in to {e.host} directly over SSH from external address {e.src_ip}.",
                               ip=e.src_ip, user="root", host=e.host))
    return alerts


def lockouts(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    for host, evs in sessions([e for e in events if e.kind == "account_lockout"], lambda e: e.host, timedelta(minutes=30)):
        users = sorted({e.user for e in evs if e.user})
        alerts.append(make("account_lockout", f"{len(users)} account(s) locked out on {host}", "Account lockouts", "low", "windows", ["T1110"], evs,
                           f"Accounts locked out after repeated failed logins: {', '.join(users)}.", host=host, accounts=users))
    return alerts


# --------------------------------------------------------------------- Linux privilege use

SHELLS = re.compile(r"^(/usr)?/bin/(ba|z|da|k|c|tc)?sh$|^(/usr)?/bin/su$|^(/usr)?/bin/(ba)?sh -i$")
SENSITIVE_SUDO = re.compile(
    r"/etc/shadow|/etc/sudoers|visudo|chmod\s+(\+s|[0-7]*[4-7][0-7]{3})|\buseradd\b|\badduser\b|usermod\s+.*-a?G\s*\S*(sudo|wheel|root|admin)|passwd\s+root"
    r"|crontab|(curl|wget)\s[^|]*\|\s*(ba)?sh|\bnc\s+(-\w+\s+)*-e|ncat\s|/dev/tcp/|python[0-9.]*\s+-c|iptables\s+-F|ufw\s+disable|systemctl\s+stop\s+(auditd|rsyslog)"
    r"|history\s+-c|rm\s+-rf?\s+/var/log|base64\s+-d", re.I)


def sudo_activity(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    sudo = [e for e in events if e.kind == "sudo"]
    for (user, host), evs in sessions(sudo, lambda e: (e.user, e.host), timedelta(minutes=30)):
        ok = [e for e in evs if e.outcome == "success"]
        shells = [e for e in ok if SHELLS.match(str(e.fields.get("command", "")).strip())]
        sensitive = [e for e in ok if SENSITIVE_SUDO.search(str(e.fields.get("command", "")))]
        failed = [e for e in evs if e.outcome == "failure"]
        if shells:
            alerts.append(make("sudo_root_shell", f"{user} opened a root shell with sudo on {host}", "Root shell via sudo", "medium", "linux", ["T1548.003", "T1059.004"],
                               shells, f"{user} used sudo to start an interactive root shell ({shells[0].fields.get('command')}).", user=user, host=host))
        if sensitive:
            cmds = sorted({str(e.fields.get("command"))[:120] for e in sensitive})
            alerts.append(make("sudo_sensitive_command", f"Sensitive commands run as root by {user} on {host}", "Sensitive sudo commands", "high", "linux", ["T1548.003"],
                               sensitive, f"{user} ran {len(sensitive)} sensitive command(s) with sudo, e.g. {cmds[0]}.", user=user, host=host, commands=cmds[:10]))
        not_allowed = [e for e in failed if "NOT in sudoers" in str(e.fields.get("error"))]
        if weight(failed) >= t.sudo_failures or not_allowed:
            alerts.append(make("sudo_failures", f"Failed sudo attempts by {user} on {host}", "Failed sudo attempts", "medium", "linux", ["T1548.003"], failed,
                               f"{weight(failed)} failed sudo attempt(s)" + (" by a user who isn't allowed to use sudo." if not_allowed else "."), user=user, host=host))
    return alerts


PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "docker", "lxd", "administrators", "domain admins", "enterprise admins", "schema admins", "backup operators"}


def account_changes(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    for e in events:
        if e.kind == "user_created":
            by = e.fields.get("created_by")
            alerts.append(make("user_created", f"New user account '{e.user}' created on {e.host}", "New account created", "medium", e.source, ["T1136.001"], [e],
                               f"A new local account '{e.user}' was created{' by ' + by if by else ''}. Attackers create accounts to keep access.",
                               user=e.user, host=e.host, created_by=by))
    adds = [e for e in events if e.kind == "group_add" and str(e.fields.get("group") or "").lower() in PRIVILEGED_GROUPS | {"remote desktop users"}]
    for (user, host, group), evs in sessions(adds, lambda e: (e.user, e.host, str(e.fields.get("group")).lower()), timedelta(days=1)):
        name = evs[0].fields.get("group")
        severity = "medium" if group in ("docker", "lxd", "remote desktop users") else "high"
        alerts.append(make("privileged_group_add", f"'{user}' added to the {name} group on {host}", "Added to admin group", severity, evs[0].source, ["T1098"], evs,
                           f"{user} was added to the privileged group '{name}', which gives administrator rights.", user=user, host=host, group=name,
                           changed_by=evs[0].fields.get("changed_by"), count=1))
    return alerts


SUSPICIOUS_CRON = re.compile(r"(curl|wget)\s[^|]*\|\s*(ba)?sh|/tmp/|/dev/shm|base64\s+-d|\bnc\s+(-\w+\s+)*-e|/dev/tcp/|python[0-9.]*\s+-c", re.I)


def cron_jobs(events: list[Event], t: Thresholds) -> list[Alert]:
    hits = [e for e in events if e.kind == "cron" and SUSPICIOUS_CRON.search(str(e.fields.get("command", "")))]
    alerts = []
    for (user, host, cmd), evs in sessions(hits, lambda e: (e.user, e.host, e.fields.get("command")), timedelta(days=2)):
        alerts.append(make("suspicious_cron", f"Suspicious scheduled job for {user} on {host}", "Suspicious cron job", "high", "linux", ["T1053.003", "T1105"], evs,
                           f"A cron job downloads or runs code from an unusual place: {str(cmd)[:160]} (ran {len(evs)} time(s)).", user=user, host=host, command=cmd))
    return alerts


# --------------------------------------------------------------------- web attacks

WEB_PATTERNS: list[tuple[str, str, str, str, re.Pattern]] = [
    ("sql_injection", "SQL injection attempts", "SQL injection", "T1190", re.compile(
        r"\bunion\b[\s(]+(all\s+)?select\b|'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|\bsleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema|"
        r"\bselect\b.{1,80}\bfrom\b|;\s*drop\s+table|extractvalue\s*\(|updatexml\s*\(|waitfor\s+delay|'\s*(--|#)\s*$|order\s+by\s+\d+\s*(--|#)", re.I)),
    ("xss", "Cross-site scripting (XSS) attempts", "XSS", "T1190", re.compile(r"<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*(img|svg|iframe)[^>]*(src|onload)|alert\s*\(|document\.cookie", re.I)),
    ("path_traversal", "Path traversal / file read attempts", "Path traversal", "T1190", re.compile(r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|php://|file://|/proc/self/environ", re.I)),
    ("command_injection", "Command injection attempts", "Command injection", "T1190", re.compile(
        r"(;|\||&&|\$\(|`)\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh|ping|powershell)\b|\bcmd=|\bexec=", re.I)),
    ("log4shell", "Log4Shell (CVE-2021-44228) exploit attempts", "Log4Shell", "T1190", re.compile(r"\$\{\s*(jndi|lower|upper|env|\$\{)", re.I)),
]
SENSITIVE_FILES = re.compile(r"/(\.env|\.git/|\.svn/|\.aws/|\.ssh/|id_rsa|wp-config\.php|config\.php\.bak|phpinfo\.php|\.htpasswd|server-status|backup\.(zip|sql|tar\.gz)|db\.sql|\.DS_Store)", re.I)
SCANNERS = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb/|wfuzz|ffuf|nuclei|acunetix|wpscan|hydra|whatweb|openvas|nessus|feroxbuster|httpx/", re.I)
WEB_SHELL = re.compile(r"/(uploads?|images?|files|tmp|assets|media)/[^?]*\.(php\d?|phtml|jsp|aspx?)(\?|$)|/(c99|r57|wso|b374k|shell|cmd|webshell)\.(php|aspx?|jsp)", re.I)


def _session_alerts(rule_id, title, short, technique, hits, base, source="web"):
    alerts = []
    for (ip, host), evs in sessions(hits, lambda e: (e.src_ip, e.host or "web server"), timedelta(minutes=60)):
        succeeded = [e for e in evs if 200 <= int(e.fields.get("status", 0)) < 300]
        severity = base
        note = ""
        if succeeded and rule_id in ("sql_injection", "path_traversal", "command_injection", "log4shell", "web_shell", "sensitive_file"):
            severity = max_severity(base, "high")
            note = f" {len(succeeded)} of them got an HTTP 2xx response, so some may have worked."
        statuses = Counter(int(e.fields.get("status", 0)) for e in evs)
        alerts.append(make(rule_id, f"{title} from {ip}", short, severity, source, [technique], evs,
                           f"{len(evs)} request(s) from {ip} matched {short.lower()} patterns.{note}",
                           ip=ip, host=None if host == "web server" else host, succeeded=len(succeeded), statuses=dict(statuses.most_common(6)),
                           paths=[str(e.fields.get("path")) for e in evs[:8]]))
    return alerts


def web_attacks(events: list[Event], t: Thresholds) -> list[Alert]:
    web = [e for e in events if e.source == "web"]
    alerts: list[Alert] = []
    for rule_id, title, short, technique, pattern in WEB_PATTERNS:
        hits = [e for e in web if pattern.search(str(e.fields.get("decoded", ""))) or (rule_id == "log4shell" and pattern.search(str(e.fields.get("user_agent") or "")))]
        alerts += _session_alerts(rule_id, title, short, technique, hits, "medium")

    shells = [e for e in web if WEB_SHELL.search(str(e.fields.get("path", "")) + ("?" if e.fields.get("query") else "")) and
              (e.fields.get("method") == "POST" or re.search(r"\b(cmd|exec|c|command)=", str(e.fields.get("query", "")), re.I)) and int(e.fields.get("status", 0)) < 400]
    alerts += _session_alerts("web_shell", "Possible web shell in use", "Web shell", "T1505.003", shells, "high")

    sensitive = [e for e in web if SENSITIVE_FILES.search(str(e.fields.get("path", "")))]
    for a in _session_alerts("sensitive_file", "Probing for sensitive files", "Sensitive file probing", "T1595.003", sensitive, "low"):
        if a.details.get("succeeded"):
            a.title, a.short = a.title.replace("Probing for sensitive files", "Sensitive files exposed to"), "Sensitive file exposed"
        alerts.append(a)

    scanners = [e for e in web if SCANNERS.search(str(e.fields.get("user_agent") or ""))]
    for a in _session_alerts("web_scanner", "Vulnerability scanner", "Vulnerability scanning", "T1595.002", scanners, "medium"):
        tools = Counter(SCANNERS.search(str(e.fields.get("user_agent"))).group(0).lower() for e in a.evidence)
        a.title = f"Vulnerability scanner ({', '.join(t for t, _ in tools.most_common(2))}) from {a.ip}"
        a.details["tools"] = dict(tools)
        alerts.append(a)

    not_found = [e for e in web if int(e.fields.get("status", 0)) == 404]
    for (ip, host), evs in sessions(not_found, lambda e: (e.src_ip, e.host), timedelta(minutes=5)):
        if len(evs) >= t.dir_bruteforce_404s:
            alerts.append(make("dir_bruteforce", f"Directory brute-forcing from {ip}", "Directory brute force", "medium", "web", ["T1595.003"], evs,
                               f"{len(evs)} requests for pages that don't exist in {max(1, round((evs[-1].ts - evs[0].ts).total_seconds() / 60))} min, typical of a tool guessing URLs.",
                               ip=ip, host=host))
    return alerts


# --------------------------------------------------------------------- Windows activity

PROCESS_PATTERNS: list[tuple[str, str, str, str, list[str], re.Pattern]] = [
    ("shadow_copy_delete", "Shadow copies deleted (ransomware warning sign)", "Backups deleted", "critical", ["T1490"],
     re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit(\.exe)?.*recoveryenabled\s+no|wbadmin(\.exe)?\s+delete", re.I)),
    ("credential_dumping", "Credential dumping tool used", "Credential dumping", "critical", ["T1003.001"],
     re.compile(r"mimikatz|sekurlsa|lsadump|procdump(64)?(\.exe)?.*lsass|comsvcs(\.dll)?.*minidump|Invoke-Mimikatz", re.I)),
    ("tool_download", "File downloaded with a built-in Windows tool", "Tool download", "high", ["T1105"],
     re.compile(r"certutil(\.exe)?\s+.*-urlcache|bitsadmin(\.exe)?\s+/transfer|(Invoke-WebRequest|iwr|wget|curl)(\.exe)?\s+.*https?://.*-o(utfile)?\s", re.I)),
    ("encoded_powershell", "Encoded PowerShell command", "Encoded PowerShell", "high", ["T1059.001", "T1027"],
     re.compile(r"powershell(\.exe)?\s+.*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I)),
    ("net_user_add", "Account created or promoted from the command line", "Account added via net", "high", ["T1136.001", "T1098"],
     re.compile(r"net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add|net1?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add", re.I)),
    ("run_key", "Program set to run at logon (Run key)", "Run key persistence", "high", ["T1547.001"],
     re.compile(r"reg(\.exe)?\s+add\s+.*\\CurrentVersion\\Run", re.I)),
    ("defender_tamper", "Microsoft Defender protections turned off", "Defender disabled", "high", ["T1562.001"],
     re.compile(r"Set-MpPreference\s+.*-Disable\w*\s+\$?true|DisableRealtimeMonitoring|Add-MpPreference\s+-ExclusionPath", re.I)),
    ("schtasks_create", "Scheduled task created from the command line", "Scheduled task", "medium", ["T1053.005"],
     re.compile(r"schtasks(\.exe)?\s+/create", re.I)),
    ("account_discovery", "Account and privilege discovery commands", "Discovery commands", "low", ["T1087"],
     re.compile(r"whoami(\.exe)?\s+/(priv|groups|all)|net1?(\.exe)?\s+(user|group|localgroup)(\s+/domain)?\s*$|nltest(\.exe)?\s|net1?(\.exe)?\s+group\s+\"?domain admins", re.I)),
]
SUSPICIOUS_POWERSHELL = re.compile(
    r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String|\bIEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest.*\|\s*iex"
    r"|AmsiUtils|amsiInitFailed|-nop\b.*-w(indowstyle)?\s+hidden|Invoke-Mimikatz|Invoke-Shellcode|Start-BitsTransfer|Set-MpPreference", re.I)
USER_WRITABLE = re.compile(r"\\(Users|Temp|Windows\\Temp|ProgramData|AppData|Public|Downloads)\\|%TEMP%|%APPDATA%|powershell|cmd(\.exe)?\s+/c|rundll32|mshta|regsvr32", re.I)


def windows_activity(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    win = [e for e in events if e.source == "windows"]
    gap = timedelta(minutes=60)

    procs = [e for e in win if e.kind == "process"]
    scripts = [e for e in win if e.kind == "powershell"]
    for rule_id, title, short, severity, tech, pattern in PROCESS_PATTERNS:
        hits = [e for e in procs if pattern.search(str(e.fields.get("command", "")))]
        if rule_id in ("credential_dumping", "defender_tamper", "tool_download"):
            hits += [e for e in scripts if pattern.search(str(e.fields.get("script", "")))]
        for (host, user), evs in sessions(hits, lambda e: (e.host, e.user), gap):
            cmd = str(evs[0].fields.get("command") or evs[0].fields.get("script") or "")
            alerts.append(make(rule_id, f"{title} on {host}", short, severity, "windows", tech, evs,
                               f"{len(evs)} command(s) by {user or 'an unknown user'}, e.g. {cmd[:180]}", user=user, host=host, commands=sorted({str(e.fields.get('command') or e.fields.get('script'))[:200] for e in evs})[:8]))

    sus = [e for e in scripts if SUSPICIOUS_POWERSHELL.search(str(e.fields.get("script", "")))]
    for (host, user), evs in sessions(sus, lambda e: (e.host, e.user), gap):
        text = " ".join(str(e.fields.get("script", "")) for e in evs)
        tech = ["T1059.001"] + (["T1027"] if re.search(r"FromBase64String|-e(nc)?\s", text, re.I) else []) + (["T1105"] if re.search(r"Download(String|File)|WebClient|Invoke-WebRequest|BitsTransfer", text, re.I) else [])
        alerts.append(make("suspicious_powershell", f"Suspicious PowerShell on {host}", "Suspicious PowerShell", "high", "windows", tech, evs,
                           f"PowerShell ran {len(evs)} script block(s) that download or hide code, e.g. {str(evs[0].fields.get('script'))[:180]}", user=user, host=host))

    for e in win:
        if e.kind == "service_install" and USER_WRITABLE.search(str(e.fields.get("image_path", ""))):
            alerts.append(make("suspicious_service", f"Suspicious service '{e.fields.get('service_name')}' installed on {e.host}", "Suspicious service", "high", "windows",
                               ["T1543.003"], [e], f"A new service runs {e.fields.get('image_path')}, a location or command that normal software rarely uses.",
                               user=e.user, host=e.host, service=e.fields.get("service_name"), image_path=e.fields.get("image_path")))
        elif e.kind == "scheduled_task":
            bad = USER_WRITABLE.search(str(e.fields.get("task_content", "")))
            alerts.append(make("scheduled_task_created", f"Scheduled task '{e.fields.get('task_name')}' created on {e.host}", "Scheduled task", "high" if bad else "medium",
                               "windows", ["T1053.005"], [e], "A new scheduled task was created" + (" that runs from a user-writable folder or a script host." if bad else "."),
                               user=e.user, host=e.host, task=e.fields.get("task_name")))
        elif e.kind == "log_cleared":
            alerts.append(make("log_cleared", f"Windows event log cleared on {e.host}", "Logs cleared", "high", "windows", ["T1070.001"], [e],
                               f"The event log was cleared{' by ' + e.user if e.user else ''}. Attackers do this to hide what they did.", user=e.user, host=e.host))
    return alerts


# --------------------------------------------------------------------- network

C2_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 6668, 6669, 6697, 12345, 54321, 9001, 9030, 5555, 8888, 1080, 3127}


def network_activity(events: list[Event], t: Thresholds) -> list[Alert]:
    alerts = []
    fw = [e for e in events if e.source == "firewall" and e.src_ip]
    gap = timedelta(minutes=t.scan_gap_minutes)
    for src, evs in sessions(fw, lambda e: e.src_ip, gap):
        ports = {e.dst_port for e in evs if e.dst_port}
        if len(ports) >= t.port_scan_ports:
            allowed = sorted({e.dst_port for e in evs if e.kind == "fw_allow" and e.dst_port})
            targets = Counter(e.dst_ip for e in evs)
            alerts.append(make("port_scan", f"Port scan from {src}", "Port scan", "high" if len(ports) >= 100 else "medium", "firewall", ["T1595" if is_external(src) else "T1046"], evs,
                               f"{src} probed {len(ports)} ports on {len(targets)} host(s) in {max(1, round((evs[-1].ts - evs[0].ts).total_seconds()))} s."
                               + (f" Reachable ports: {', '.join(map(str, allowed[:10]))}." if allowed else " All were blocked."),
                               ip=src, host=targets.most_common(1)[0][0], ports=len(ports), open_ports=allowed[:20]))
    for (src, port), evs in sessions([e for e in fw if e.dst_port], lambda e: (e.src_ip, e.dst_port), gap):
        hosts = {e.dst_ip for e in evs}
        if len(hosts) >= t.host_sweep_hosts:
            alerts.append(make("host_sweep", f"Network sweep for port {port} from {src}", "Network sweep", "medium", "firewall", ["T1595" if is_external(src) else "T1046"], evs,
                               f"{src} tried port {port} on {len(hosts)} different hosts.", ip=src, port=port, hosts=len(hosts)))
    outbound = [e for e in events if e.kind in ("fw_allow", "net_connection") and is_internal(e.src_ip) and is_external(e.dst_ip) and e.dst_port in C2_PORTS]
    for (src, dst, port), evs in sessions(outbound, lambda e: (e.src_ip, e.dst_ip, e.dst_port), timedelta(hours=6)):
        alerts.append(make("suspicious_outbound", f"Outbound connection from {src} to {dst}:{port}", "Suspicious outbound traffic", "high", evs[0].source, ["T1571", "T1071.001"], evs,
                           f"{src} connected {len(evs)} time(s) to {dst} on port {port}, a port often used by malware and remote-access tools.",
                           ip=dst, host=src, port=port, internal_host=src))
    return alerts


RULES = [brute_force, login_after_brute_force, remote_logins, lockouts, sudo_activity, account_changes, cron_jobs, web_attacks, windows_activity, network_activity]


def run_rules(events: list[Event], thresholds: Thresholds | None = None) -> list[Alert]:
    t = thresholds or Thresholds()
    events = sorted(events, key=lambda e: e.ts)
    alerts: list[Alert] = []
    for rule in RULES:
        alerts.extend(rule(events, t))
    return alerts
