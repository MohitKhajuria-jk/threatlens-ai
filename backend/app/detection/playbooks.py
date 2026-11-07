"""Rule-based response steps for each kind of alert, with ready-to-run commands.

These work without the AI. The AI report adapts them to the specific incident.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..models import Alert

PHASES = ["contain", "investigate", "eradicate", "recover", "harden"]

# rule -> [(phase, action, linux command, windows command)]. {ip}, {user}, {host}, {service}, {port} are filled in.
STEPS: dict[str, list[tuple[str, str, str, str]]] = {
    "brute_force": [
        ("contain", "Block {ip} at the firewall", "sudo ufw deny from {ip}", 'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'),
        ("investigate", "Check whether any login from {ip} succeeded", "grep 'Accepted' /var/log/auth.log | grep {ip}",
         "Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624}} | Where-Object {{ $_.Message -match '{ip}' }}"),
        ("harden", "Turn off password logins for SSH and use keys only", "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh", ""),
        ("harden", "Lock accounts after repeated failures (fail2ban on Linux, account lockout policy on Windows)", "sudo apt install fail2ban", "net accounts /lockoutthreshold:5 /lockoutduration:30"),
    ],
    "login_after_brute_force": [
        ("contain", "Lock the compromised account {user}", "sudo passwd -l {user}", "Disable-LocalUser -Name {user}"),
        ("contain", "End the attacker's active sessions", "sudo pkill -KILL -u {user}", "quser; logoff <session id>"),
        ("contain", "Block {ip} at the firewall", "sudo ufw deny from {ip}", 'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'),
        ("investigate", "Review everything {user} did after logging in", "sudo grep -E 'sudo|{user}' /var/log/auth.log; sudo last {user}",
         "Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4688,4720,4732,7045}} -MaxEvents 200"),
        ("eradicate", "Reset {user}'s password and remove any SSH keys the attacker added", "sudo passwd {user}; sudo cat /home/{user}/.ssh/authorized_keys", "Set-LocalUser -Name {user} -Password (Read-Host -AsSecureString)"),
        ("recover", "Re-enable the account only after the host is confirmed clean", "sudo passwd -u {user}", "Enable-LocalUser -Name {user}"),
    ],
    "rdp_from_internet": [
        ("investigate", "Confirm with {user} whether this login was theirs", "", ""),
        ("harden", "Stop exposing Remote Desktop to the internet; allow it only over VPN", "", 'Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress LocalSubnet'),
        ("harden", "Require Network Level Authentication for Remote Desktop", "", "(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\\cimv2\\terminalservices).SetUserAuthenticationRequired(1)"),
    ],
    "root_ssh_login": [
        ("investigate", "Confirm whether an administrator logged in as root from {ip}", "sudo last root", ""),
        ("harden", "Disable direct root logins over SSH", "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload ssh", ""),
    ],
    "account_lockout": [("investigate", "Find the source of the failed logins that locked the accounts", "", "Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents 100")],
    "sudo_root_shell": [
        ("investigate", "Review what was done in the root shell", "sudo ausearch -ua {user} -i | tail -100; sudo cat /root/.bash_history", ""),
        ("harden", "Limit {user}'s sudo rights to the commands they need", "sudo visudo", ""),
    ],
    "sudo_sensitive_command": [
        ("investigate", "Review the sensitive commands and what they changed", "sudo grep 'COMMAND=' /var/log/auth.log | grep {user}", ""),
        ("eradicate", "Undo unauthorised changes (accounts, cron jobs, sudoers, file permissions)", "sudo cat /etc/sudoers /etc/sudoers.d/*; sudo crontab -l -u root", ""),
    ],
    "sudo_failures": [("investigate", "Check whether {user} should have sudo access, and who was typing", "sudo grep 'sudo' /var/log/auth.log | grep {user}", "")],
    "user_created": [
        ("investigate", "Confirm the new account {user} was authorised", "id {user}; sudo grep {user} /etc/passwd", "Get-LocalUser -Name {user}"),
        ("eradicate", "If not authorised, delete the account", "sudo userdel -r {user}", "Remove-LocalUser -Name {user}"),
    ],
    "privileged_group_add": [
        ("contain", "Remove {user} from the privileged group", "sudo gpasswd -d {user} sudo", "Remove-LocalGroupMember -Group Administrators -Member {user}"),
        ("investigate", "List all members of admin groups and check each one", "getent group sudo wheel", "Get-LocalGroupMember -Group Administrators"),
    ],
    "suspicious_cron": [
        ("contain", "Remove the malicious cron job", "sudo crontab -l -u {user}; sudo crontab -r -u {user}", ""),
        ("investigate", "Find what the job downloaded and look for other persistence", "ls -la /tmp /dev/shm; sudo ls /etc/cron.*; sudo systemctl list-timers", ""),
    ],
    "sql_injection": [
        ("contain", "Block {ip} at the web server or WAF", "sudo ufw deny from {ip}", ""),
        ("investigate", "Check the database logs for queries at the same time and look for data access", "sudo grep {ip} /var/log/nginx/access.log | grep -i select", ""),
        ("eradicate", "Fix the vulnerable page with parameterized queries", "", ""),
    ],
    "xss": [("contain", "Block {ip}", "sudo ufw deny from {ip}", ""), ("eradicate", "Encode output and add a Content-Security-Policy header", "", "")],
    "path_traversal": [
        ("contain", "Block {ip}", "sudo ufw deny from {ip}", ""),
        ("investigate", "Check which files were returned with HTTP 200", "sudo grep {ip} /var/log/nginx/access.log | grep ' 200 '", ""),
        ("eradicate", "Validate file names against an allow-list in the vulnerable page", "", ""),
    ],
    "command_injection": [
        ("contain", "Block {ip} and take the vulnerable page offline", "sudo ufw deny from {ip}", ""),
        ("investigate", "Look for files or processes the injected commands created", "ps aux --sort=start_time | tail -20; sudo find /tmp /var/tmp -newer /etc/hostname", ""),
    ],
    "log4shell": [("contain", "Block {ip}", "sudo ufw deny from {ip}", ""), ("eradicate", "Upgrade Log4j to 2.17.1 or later", "", "")],
    "web_shell": [
        ("contain", "Take the site offline or block access to the upload folder", "", ""),
        ("eradicate", "Delete the web shell and look for others", "sudo find /var/www -name '*.php' -newer /var/www/html/index.php", ""),
        ("investigate", "Find how it was uploaded and what commands it ran", "sudo grep -E 'POST .*(upload|\\.php)' /var/log/nginx/access.log", ""),
    ],
    "sensitive_file": [
        ("contain", "Block {ip}", "sudo ufw deny from {ip}", ""),
        ("eradicate", "Make sure files like .env and .git aren't served by the web server", "", ""),
    ],
    "web_scanner": [("contain", "Block or rate-limit {ip}", "sudo ufw deny from {ip}", "")],
    "dir_bruteforce": [("contain", "Rate-limit or block {ip}", "sudo ufw deny from {ip}", "")],
    "port_scan": [
        ("contain", "Block {ip} at the firewall", "sudo ufw deny from {ip}", 'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'),
        ("harden", "Close ports that don't need to be reachable from the internet", "sudo ss -tulpn", "Get-NetTCPConnection -State Listen"),
    ],
    "host_sweep": [("contain", "Block {ip} at the firewall", "sudo ufw deny from {ip}", "")],
    "suspicious_outbound": [
        ("contain", "Isolate {host} from the network", "", ""),
        ("contain", "Block traffic to {ip}", "sudo ufw deny out to {ip}", 'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Outbound -RemoteAddress {ip} -Action Block'),
        ("investigate", "Find the process making the connection", "sudo ss -tnp | grep {ip}", "Get-NetTCPConnection -RemoteAddress {ip} | Select-Object OwningProcess"),
    ],
    "suspicious_powershell": [
        ("contain", "Isolate {host} from the network", "", ""),
        ("investigate", "Look for persistence: new services, scheduled tasks and Run keys", "",
         "Get-ScheduledTask | Where-Object Date -gt (Get-Date).AddDays(-2); Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("harden", "Enable PowerShell Constrained Language Mode and script block logging", "", ""),
    ],
    "suspicious_service": [
        ("contain", "Stop and remove the service", "", "Stop-Service -Name {service}; sc.exe delete {service}"),
        ("investigate", "Check the service file's hash with VirusTotal", "", "Get-FileHash '{image_path}'"),
    ],
    "scheduled_task_created": [("investigate", "Review the task and remove it if unauthorised", "", "Get-ScheduledTask -TaskName '{task}' | Format-List *; Unregister-ScheduledTask -TaskName '{task}'")],
    "log_cleared": [
        ("investigate", "Assume tampering: collect logs from other sources (backups, SIEM, firewall)", "", ""),
        ("harden", "Forward logs to a central server so they can't be erased locally", "", ""),
    ],
    "shadow_copy_delete": [
        ("contain", "Isolate {host} immediately; this is a common step right before ransomware encrypts files", "", ""),
        ("recover", "Check that offline backups are intact before restoring", "", ""),
    ],
    "credential_dumping": [
        ("contain", "Isolate {host}", "", ""),
        ("eradicate", "Reset passwords for every account that logged in to {host}", "", ""),
    ],
    "tool_download": [("investigate", "Find and hash the downloaded file, then check it with VirusTotal", "", "Get-FileHash C:\\Users\\Public\\*")],
    "encoded_powershell": [("investigate", "Decode the command to see what it does", "", "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<encoded text>'))")],
    "net_user_add": [("eradicate", "Remove accounts and group memberships created from the command line", "", "Get-LocalUser; Get-LocalGroupMember -Group Administrators")],
    "run_key": [("eradicate", "Remove the Run key entry", "", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")],
    "defender_tamper": [("recover", "Turn Defender protections back on", "", "Set-MpPreference -DisableRealtimeMonitoring $false")],
    "schtasks_create": [("investigate", "Review recently created scheduled tasks", "", "Get-ScheduledTask | Sort-Object Date -Descending | Select-Object -First 10")],
    "account_discovery": [("investigate", "Check who ran discovery commands and whether it was expected", "", "")],
    "malicious_ip": [
        ("contain", "Block {ip} at the firewall", "sudo ufw deny from {ip}", 'New-NetFirewallRule -DisplayName "Block {ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'),
        ("investigate", "Review all activity from {ip}", "sudo grep -r {ip} /var/log/", ""),
    ],
    "ml_anomaly": [("investigate", "Review this IP's activity and decide whether it's expected", "", "")],
}


def steps_for(alert: Alert) -> list[dict[str, Any]]:
    values = {"ip": alert.ip or "<attacker ip>", "user": alert.user or "<user>", "host": alert.host or "<host>",
              "service": alert.details.get("service") or "<service>", "image_path": alert.details.get("image_path") or "<path>",
              "task": alert.details.get("task") or "<task>", "port": alert.details.get("port") or ""}
    windows = alert.source == "windows"
    out = []
    for phase, action, linux_cmd, windows_cmd in STEPS.get(alert.rule_id, []):
        cmd = (windows_cmd or "") if windows else (linux_cmd or "")
        text = action.format(**values)
        out.append({"key": hashlib.sha1(text.encode()).hexdigest()[:10], "phase": phase, "action": text,
                    "command": cmd.format(**values) if cmd else None, "platform": "Windows PowerShell" if windows else "Linux shell", "rule": alert.rule_id})
    return out


PHASE_LIMITS = {"contain": 5, "investigate": 6, "eradicate": 5, "recover": 3, "harden": 4}


def merged_steps(alerts: list[Alert]) -> list[dict[str, Any]]:
    """All steps for an incident, most serious alerts first, without repeats, a few per phase."""
    from ..models import SEVERITY_RANK

    seen_actions, seen_commands, out = set(), set(), []
    per_phase: dict[str, int] = {}
    for alert in sorted(alerts, key=lambda a: (-SEVERITY_RANK[a.severity], a.first_seen)):
        for step in steps_for(alert):
            if step["action"] in seen_actions or (step["command"] and step["command"] in seen_commands):
                continue
            if per_phase.get(step["phase"], 0) >= PHASE_LIMITS[step["phase"]]:
                continue
            seen_actions.add(step["action"])
            if step["command"]:
                seen_commands.add(step["command"])
            per_phase[step["phase"]] = per_phase.get(step["phase"], 0) + 1
            out.append(step)
    out.sort(key=lambda s: PHASES.index(s["phase"]))
    return out
