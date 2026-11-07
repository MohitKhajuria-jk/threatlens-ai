"""The MITRE ATT&CK techniques ThreatLens maps its detections to."""

from __future__ import annotations

TACTICS = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Command and Control", "Exfiltration", "Impact",
]

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Wordlist Scanning", "Reconnaissance"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1547.001": ("Boot or Logon Autostart: Registry Run Keys", "Persistence"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1548.003": ("Abuse Elevation Control: Sudo and Sudo Caching", "Privilege Escalation"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1490": ("Inhibit System Recovery", "Impact"),
}


def technique(tid: str) -> dict[str, str]:
    name, tactic = TECHNIQUES.get(tid, ("Unknown technique", ""))
    return {"id": tid, "name": name, "tactic": tactic, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}


def tactic_of(tid: str) -> str:
    return TECHNIQUES.get(tid, ("", ""))[1]
