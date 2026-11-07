import json

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from conftest import ScriptedModel, answer, tool_call
from test_ai import REPORT


@pytest.fixture
def make_client(settings):
    def make(model=None):
        app = create_app(settings, model=model or ScriptedModel([]), refresh_feeds=False)
        return TestClient(app)
    return make


def sse_events(text: str) -> list[tuple[str, dict]]:
    out = []
    for block in text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        out.append((lines["event"], json.loads(lines["data"])))
    return out


def test_demo_load_overview_and_incidents(make_client):
    with make_client() as c:
        r = c.post("/api/datasets/demo").json()
        assert len(r["added"]) == 4 and r["analysis"]["incidents"] == 4
        assert {d["format"] for d in r["added"]} == {"linux_syslog", "web_access", "windows_json", "linux_firewall"}
        ov = c.get("/api/overview").json()
        assert ov["severity"]["critical"] >= 3 and ov["timeline"] and ov["top_attackers"][0]["verdict"] == "malicious"
        assert {t["tactic"] for t in ov["tactics"] if t["alerts"]} >= {"Reconnaissance", "Initial Access", "Impact"}
        incidents = c.get("/api/incidents").json()
        top = incidents[0]
        assert top["severity"] == "critical" and "steps" not in top and top["alerts"] > 5
        detail = c.get(f"/api/incidents/{top['id']}").json()
        assert detail["alerts"] and detail["timeline"] and detail["steps"] and detail["intel_details"]
        alert = c.get(f"/api/alerts/{detail['alerts'][0]['id']}").json()
        assert alert["events"] and alert["details"]["steps"]
        status = c.get("/api/status").json()
        assert status["counts"]["datasets"] == 4 and status["llm"]["ready"] is True
        # Loading the demo again replaces it instead of doubling it.
        c.post("/api/datasets/demo")
        assert c.get("/api/status").json()["counts"]["datasets"] == 4


def test_incident_state_survives_reanalysis(make_client):
    with make_client() as c:
        c.post("/api/datasets/demo")
        inc = c.get("/api/incidents").json()[0]
        step = c.get(f"/api/incidents/{inc['id']}").json()["steps"][0]["key"]
        r = c.patch(f"/api/incidents/{inc['id']}", json={"status": "contained", "notes": "Blocked at the edge.", "done": [step]})
        assert r.json()["status"] == "contained"
        c.post("/api/analyze")
        again = c.get(f"/api/incidents/{inc['id']}").json()
        assert again["state"]["status"] == "contained" and again["state"]["done"] == [step]
        assert c.patch(f"/api/incidents/{inc['id']}", json={"status": "hacked"}).status_code == 422


def test_ai_report_endpoint(make_client):
    model = ScriptedModel([answer(json.dumps(REPORT))])
    with make_client(model) as c:
        c.post("/api/datasets/demo")
        inc = c.get("/api/incidents").json()[0]
        r = c.post(f"/api/incidents/{inc['id']}/report")
        assert r.status_code == 200 and r.json()["report"]["verdict"] == "true_positive" and r.json()["report_model"] == "scripted"
        prompt = model.calls[0]["messages"][1]["content"]
        assert "<log_evidence>" in prompt
        assert c.get("/api/incidents").json()[0]["has_report"] is True


def test_report_without_key_explains(settings):
    with TestClient(create_app(settings.model_copy(update={"llm_api_key": ""}), refresh_feeds=False)) as c:
        c.post("/api/datasets/demo")
        inc = c.get("/api/incidents").json()[0]
        r = c.post(f"/api/incidents/{inc['id']}/report")
        assert r.status_code == 400 and "LLM_API_KEY" in r.json()["detail"]
        assert c.get("/api/status").json()["llm"]["ready"] is False


def test_upload_paste_and_errors(make_client):
    auth = "\n".join(f"Nov  6 10:{i:02d}:00 web-01 sshd[1]: Failed password for root from 203.0.113.9 port 4000{i} ssh2" for i in range(12)) + "\n"
    with make_client() as c:
        r = c.post("/api/datasets", files=[("files", ("auth.log", auth.encode(), "text/plain")), ("files", ("notes.txt", b"just some notes\n", "text/plain"))])
        body = r.json()
        assert r.status_code == 200 and len(body["added"]) == 1 and body["errors"][0]["file"] == "notes.txt"
        assert body["analysis"]["alerts"] >= 1
        assert c.post("/api/datasets", files=[("files", ("x.evtx", b"ElfFile\x00\x00\x01", "application/octet-stream"))]).status_code == 422
        p = c.post("/api/datasets/paste", json={"name": "fw.csv", "text": "timestamp,action,src_ip,dst_ip,dst_port\n2026-11-06T10:00:00Z,deny,203.0.113.9,10.0.0.2,22\n"})
        assert p.status_code == 200 and p.json()["added"][0]["format"] == "firewall_csv"
        ds = c.get("/api/datasets").json()
        assert len(ds) == 2
        ev = c.get("/api/events", params={"ip": "203.0.113.9"}).json()
        assert ev["total"] == 13
        assert c.get(f"/api/events/{ev['events'][0]['id']}").json()["src_ip"] == "203.0.113.9"
        assert c.delete(f"/api/datasets/{ds[0]['id']}").status_code == 200
        assert c.delete("/api/datasets/nope").status_code == 404
        c.delete("/api/datasets")
        assert c.get("/api/status").json()["counts"]["events"] == 0


def test_utf16_powershell_export_is_accepted(make_client):
    records = '[{"EventID": 1102, "TimeCreated": "2026-11-06T09:10:00Z", "Computer": "PC-1", "SubjectUserName": "bob"}]'
    with make_client() as c:
        r = c.post("/api/datasets", files=[("files", ("security.json", b"\xff\xfe" + records.encode("utf-16-le"), "application/json"))])
        assert r.status_code == 200 and r.json()["added"][0]["format"] == "windows_json"


def test_binary_upload_points_to_file_check(make_client):
    with make_client() as c:
        r = c.post("/api/datasets", files=[("files", ("photo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(200), "image/png"))])
        assert r.status_code == 422 and "PNG image" in r.json()["detail"] and "Check a file" in r.json()["detail"]


def test_evtx_upload_is_routed_to_the_evtx_reader(make_client, monkeypatch):
    from app.parsers import evtx, windows
    from app.parsers.common import parse_time

    def fake_parse(raw, tz):
        ev = windows.classify(4625, parse_time("2026-11-06T09:10:00Z", tz), "PC-1", "Microsoft-Windows-Security-Auditing", "Security", "",
                              {"TargetUserName": "bob", "LogonType": "3", "IpAddress": "203.0.113.45"}, "<Event/>")
        ev.line_no = 1
        return [ev], 3

    monkeypatch.setattr(evtx, "parse", fake_parse)
    with make_client() as c:
        r = c.post("/api/datasets", files=[("files", ("Security.evtx", evtx.MAGIC + bytes(100), "application/octet-stream"))])
        added = r.json()["added"][0]
        assert added["format"] == "windows_evtx" and added["events"] == 1 and added["lines"] == 3


def test_gzip_and_zip_logs_are_unpacked(make_client):
    import gzip
    import io
    import zipfile

    lines = "\n".join(f"Nov  6 09:{i:02d}:00 web-01 sshd[1{i}]: Failed password for root from 203.0.113.45 port 4{i:04d} ssh2" for i in range(30))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("logs/auth.log", lines)
        z.writestr("logs/auth.log.2.gz", gzip.compress(lines.encode()))
        z.writestr("logs/notes.png", b"\x89PNG\r\n\x1a\n" + bytes(64))
    with make_client() as c:
        r = c.post("/api/datasets", files=[("files", ("auth.log.1.gz", gzip.compress(lines.encode()), "application/gzip"))]).json()
        assert r["added"][0]["name"] == "auth.log.1" and r["added"][0]["events"] == 30
        r = c.post("/api/datasets", files=[("files", ("rotated.zip", buf.getvalue(), "application/zip"))]).json()
        assert [d["name"] for d in r["added"]] == ["rotated.zip/auth.log", "rotated.zip/auth.log.2"]
        assert r["errors"][0]["file"] == "rotated.zip/notes.png"


def test_zip_bomb_is_stopped(make_client, settings):
    import gzip

    settings.max_unpacked_mb = 1
    bomb = gzip.compress(b"A" * (5 * 1024 * 1024))  # about 5 KB that expands to 5 MB
    with make_client() as c:
        r = c.post("/api/datasets", files=[("files", ("big.log.gz", bomb, "application/gzip"))])
        assert r.status_code == 422 and "more than 1 MB" in r.json()["detail"]


def test_check_a_file(make_client):
    from app import demo_sample

    with make_client() as c:
        r = c.post("/api/intel/file", files={"file": (demo_sample.NAME, demo_sample.CONTENT, "text/plain")}).json()
        assert r["verdict"] == "malicious" and r["file"]["sha256"] == demo_sample.SHA256 and r["file"]["type"] == "Text"
        assert r["feeds"][0]["feed"] == "demo"
        assert c.get("/api/intel/demo-sample").content == demo_sample.CONTENT
        exe = c.post("/api/intel/file", files={"file": ("setup.exe", b"MZ\x90\x00" + bytes(500), "application/octet-stream")}).json()
        assert exe["verdict"] == "unknown" and exe["file"]["can_run"] and exe["file"]["type"].startswith("Windows program")
        assert any("Unknown doesn't mean safe" in n for n in exe["notes"])
        assert c.post("/api/intel/file", files={"file": ("empty.bin", b"", "application/octet-stream")}).status_code == 400


def test_chat_stream_and_history(make_client):
    model = ScriptedModel([tool_call("list_alerts", {"severity": "critical"}), answer("Two accounts were broken into.")])
    with make_client(model) as c:
        c.post("/api/datasets/demo")
        r = c.post("/api/chat/global", json={"content": "Which accounts were compromised?"})
        kinds = [k for k, _ in sse_events(r.text)]
        assert kinds == ["user", "step", "step_done", "answer", "done"]
        prompt = [m for m in model.calls[1]["messages"] if m["role"] == "tool"][0]["content"]
        assert "Evidence you can cite: [E" in prompt
        history = c.get("/api/chat/global").json()
        assert [m["role"] for m in history] == ["user", "assistant"] and history[1]["steps"][0]["tool"] == "list_alerts"
        c.delete("/api/chat/global")
        assert c.get("/api/chat/global").json() == []


def test_chat_error_removes_question(settings):
    class Broken:
        label = "broken"

        async def chat(self, *a, **k):
            from app.llm import LLMError
            raise LLMError("The model API rejected the API key.")
    with TestClient(create_app(settings, model=Broken(), refresh_feeds=False)) as c:
        r = c.post("/api/chat/global", json={"content": "hi"})
        assert sse_events(r.text)[-1] == ("error", {"message": "The model API rejected the API key."})
        assert c.get("/api/chat/global").json() == []


def test_intel_lookup_endpoint(make_client):
    with make_client() as c:
        r = c.get("/api/intel/lookup", params={"value": "198.51.100.200"}).json()
        assert r["verdict"] == "malicious" and r["feeds"][0]["demo"] is True and r["notes"]
        assert c.get("/api/intel/lookup", params={"value": "hello world"}).status_code == 400
        assert c.post("/api/intel/refresh").status_code == 400  # feeds are off in tests
