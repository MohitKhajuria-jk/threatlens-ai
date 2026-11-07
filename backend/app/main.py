"""ThreatLens AI web API."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import zipfile
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import demo_data, demo_sample
from . import files as files_mod
from .ai import Investigator, generate_report
from .analysis import Analyzer
from .config import BACKEND_DIR, Settings, get_settings
from .db import Database, event_dict
from .detection.mitre import TACTICS, TECHNIQUES
from .intel.service import IntelService, combine
from .llm import ChatModel, LLMError, OpenAICompatibleClient
from .models import SEVERITIES
from .parsers import FORMAT_LABELS, evtx, parse_text
from .parsers.common import local_tz

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("threatlens")


class PasteBody(BaseModel):
    name: str = Field(default="pasted.log", max_length=120)
    text: str = Field(min_length=1, max_length=20_000_000)


class IncidentPatch(BaseModel):
    status: str | None = Field(default=None, pattern="^(open|investigating|contained|resolved|false_positive)$")
    notes: str | None = Field(default=None, max_length=20000)
    done: list[str] | None = None


class AskBody(BaseModel):
    content: str = Field(min_length=1, max_length=4000)


def sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


class State:
    def __init__(self, settings: Settings, model: ChatModel | None, http: httpx.AsyncClient):
        self.settings = settings
        self.http = http
        self.db = Database(settings.data_dir / "threatlens.db")
        self.intel = IntelService(settings, self.db, http)
        self.analyzer = Analyzer(self.db, self.intel)
        self.model = model
        self.tz = local_tz(settings.log_timezone)
        self.background: set[asyncio.Task] = set()

    async def analyze(self) -> dict[str, Any]:
        summary = await run_in_threadpool(self.analyzer.run)
        if self.intel.abuseipdb.configured:
            checked = await self.intel.enrich(self.analyzer.alert_ips())
            if checked:  # new reputation scores can change verdicts
                summary = await run_in_threadpool(self.analyzer.run)
        return summary

    def spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self.background.add(task)
        task.add_done_callback(self.background.discard)

    async def refresh_feeds(self, force: bool = False) -> int:
        updated = await self.intel.feeds.refresh(self.http, force=force)
        if updated and self.db.event_count():
            await self.analyze()
        return updated


def create_app(settings: Settings | None = None, model: ChatModel | None = None, http: httpx.AsyncClient | None = None, refresh_feeds: bool = True) -> FastAPI:
    settings = settings or get_settings()
    client = http or httpx.AsyncClient()
    if model is None and settings.llm_ready:
        model = OpenAICompatibleClient(settings, client)
    state = State(settings, model, client)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if refresh_feeds and settings.intel_feeds_enabled:
            state.spawn(state.refresh_feeds())
        yield
        for task in list(state.background):
            task.cancel()
        if http is None:
            await client.aclose()

    app = FastAPI(title="ThreatLens AI", lifespan=lifespan)
    app.state.tl = state
    app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_url, "http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])

    # ------------------------------------------------------------------ status and overview
    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        alerts = state.db.alerts()
        incidents = state.db.incidents()
        m = state.model
        return {
            "llm": {"ready": m is not None, "provider": settings.provider["label"], "model": settings.resolved_model,
                    "fallback_model": settings.resolved_fallback_model or None, "using_fallback": bool(getattr(m, "using_fallback", False)),
                    "label": getattr(m, "label", "Not configured")},
            "intel": state.intel.status(),
            "counts": {"datasets": len(state.db.datasets()), "events": state.db.event_count(), "alerts": len(alerts),
                       "open_incidents": sum(1 for i in incidents if i["state"]["status"] in ("open", "investigating")), "incidents": len(incidents)},
            "analyzed_at": state.db.analyzed_at(), "timezone": str(state.tz), "formats": FORMAT_LABELS,
            "limits": {"upload_mb": settings.max_upload_mb, "check_mb": settings.max_check_mb},
        }

    @app.get("/api/overview")
    async def overview() -> dict[str, Any]:
        alerts = state.db.alerts()
        incidents = state.db.incidents()
        rows = state.db.q("SELECT MIN(ts) AS a, MAX(ts) AS b, COUNT(*) AS n FROM events")[0]
        span = (rows["a"], rows["b"])
        timeline: list[dict[str, Any]] = []
        if rows["n"]:
            hours = max(1.0, (span[1] - span[0]) / 3600)
            bucket = 3600 if hours <= 48 else 6 * 3600 if hours <= 24 * 14 else 86400
            start = int(span[0] // bucket * bucket)
            counts = defaultdict(lambda: {"events": 0, "failures": 0})
            for r in state.db.q(f"SELECT CAST((ts - ?) / ? AS INTEGER) AS b, COUNT(*) AS n, SUM(outcome = 'failure') AS f FROM events GROUP BY b", (start, bucket)):
                counts[r["b"]] = {"events": r["n"], "failures": r["f"] or 0}
            alert_counts: dict[int, Counter] = defaultdict(Counter)
            for a in alerts:
                alert_counts[int((a["first_seen"] - start) // bucket)][a["severity"]] += 1
            n_buckets = int((span[1] - start) // bucket) + 1
            for i in range(n_buckets):
                timeline.append({"t": datetime.fromtimestamp(start + i * bucket, timezone.utc).isoformat(), **counts[i], "alerts": dict(alert_counts[i])})
        sev = Counter(a["severity"] for a in alerts)
        by_source = Counter(a["source"] for a in alerts)
        tactic_counts: Counter = Counter()
        for a in alerts:
            for t in {TECHNIQUES.get(tid, ("", ""))[1] for tid in a["techniques"]}:
                if t:
                    tactic_counts[t] += 1
        attackers: dict[str, dict[str, Any]] = {}
        for a in alerts:
            if not a["ip"]:
                continue
            row = attackers.setdefault(a["ip"], {"ip": a["ip"], "alerts": 0, "severity": "low", "last_seen": 0, "rules": []})
            row["alerts"] += 1
            row["last_seen"] = max(row["last_seen"], a["last_seen"])
            if SEVERITIES.index(a["severity"]) > SEVERITIES.index(row["severity"]):
                row["severity"] = a["severity"]
            if a["short"] not in row["rules"]:
                row["rules"].append(a["short"])
        top = sorted(attackers.values(), key=lambda r: (-SEVERITIES.index(r["severity"]), -r["alerts"]))[:8]
        for row in top:
            v = state.intel.feed_verdict(row["ip"])
            row["verdict"] = v["verdict"]
            row["country"] = (v.get("abuseipdb") or {}).get("country")
            row["abuse_score"] = (v.get("abuseipdb") or {}).get("score")
            row["events"] = state.db.q("SELECT COUNT(*) AS n FROM events WHERE src_ip = ? OR dst_ip = ?", (row["ip"], row["ip"]))[0]["n"]
        sources = {r["source"]: r["n"] for r in state.db.q("SELECT source, COUNT(*) AS n FROM events GROUP BY source")}
        anomalies = state.db.q("SELECT value FROM meta WHERE key = 'anomalies'")
        return {
            "span": {"start": span[0], "end": span[1]}, "events": rows["n"], "sources": sources,
            "severity": {s: sev.get(s, 0) for s in SEVERITIES}, "alerts": len(alerts), "alerts_by_source": dict(by_source),
            "tactics": [{"tactic": t, "alerts": tactic_counts.get(t, 0)} for t in TACTICS],
            "timeline": timeline, "top_attackers": top,
            "incidents": [{k: i[k] for k in ("id", "title", "severity", "risk", "last_seen", "ips", "hosts", "tactics")} | {"status": i["state"]["status"], "alerts": len(i["alert_ids"])}
                          for i in incidents[:6]],
            "recent_alerts": [{k: a[k] for k in ("id", "title", "severity", "source", "last_seen", "ip", "incident_id", "count")} for a in alerts[:8]],
            "anomalies": json.loads(anomalies[0]["value"])[:8] if anomalies else [],
            "intel_matches": sum(1 for a in alerts if a["rule_id"].startswith("malicious_")),
            "analyzed_at": state.db.analyzed_at(),
        }

    # ------------------------------------------------------------------ datasets
    async def ingest(name: str, raw: bytes, demo: bool = False) -> dict[str, Any]:
        if raw[:8] == evtx.MAGIC:
            try:
                events, records = await run_in_threadpool(evtx.parse, raw, state.tz)
            except ImportError as err:
                raise HTTPException(400, "Reading .evtx files needs the python-evtx package: run pip install -r requirements.txt.") from err
            except Exception as err:
                raise HTTPException(422, f"{name} looks like a Windows event log, but it couldn't be read ({type(err).__name__}). "
                                         "Copy the log with Event Viewer's Save All Events As, or export it to JSON (see the README).") from err
            if not events:
                raise HTTPException(422, f"{name} has {records} Windows events, but none with a time and event ID could be read.")
            return state.db.add_dataset(name, "windows_evtx", "windows", len(raw), records, events, [], demo)
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):  # PowerShell 5.1 writes UTF-16 with `>` and Out-File
            text = raw.decode("utf-16", errors="replace")
        else:
            text = raw.decode("utf-8-sig", errors="replace")
        if "\x00" in text[:2000] or "\ufffd" * 8 in text[:2000]:
            kind = files_mod.sniff(raw[:0x8010])
            raise HTTPException(400, f"{name} isn't a log file (it looks like: {kind}). To check whether a file is malware, "
                                     "use Check a file on the Threat intel page.")
        result = await run_in_threadpool(parse_text, text, state.tz)
        if not result.events:
            hint = " The first lines look like: " + " | ".join(result.samples_skipped[:2]) if result.samples_skipped else ""
            raise HTTPException(422, f"No log events were recognised in {name}. Supported: Linux auth/syslog, Apache/Nginx access logs, "
                                     f"Windows events (.evtx, JSON, CSV), UFW/iptables, Windows Firewall and CSV/key=value firewall logs, "
                                     f"plain or in .gz/.zip.{hint}")
        return state.db.add_dataset(name, result.format, result.source, len(raw), result.lines, result.events, result.samples_skipped, demo)

    async def ingest_upload(name: str, raw: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Unpacks .gz and .zip uploads, then loads each log file inside."""
        if len(raw) > settings.max_upload_mb * 1024 * 1024:
            raise HTTPException(413, f"{name} is larger than {settings.max_upload_mb} MB. Split it or raise MAX_UPLOAD_MB in backend/.env.")
        try:
            parts = await run_in_threadpool(files_mod.unpack, name, raw, settings.max_unpacked_mb * 1024 * 1024)
        except files_mod.UnpackError as err:
            raise HTTPException(422, f"{name} couldn't be unpacked: {err}.") from err
        added, errors = [], []
        for part_name, data in parts:
            try:
                added.append(await ingest(part_name, data))
            except HTTPException as err:
                if len(parts) == 1:
                    raise
                errors.append({"file": part_name, "error": err.detail})
        return added, errors

    @app.get("/api/datasets")
    async def datasets() -> list[dict[str, Any]]:
        return state.db.datasets()

    @app.post("/api/datasets")
    async def upload(files: list[UploadFile] = File(...)) -> dict[str, Any]:
        added, errors = [], []
        for f in files:
            try:
                ok, failed = await ingest_upload(f.filename or "upload.log", await f.read())
                added += ok
                errors += failed
            except HTTPException as err:
                errors.append({"file": f.filename, "error": err.detail})
        summary = await state.analyze() if added else None
        if not added and errors:
            raise HTTPException(422, errors[0]["error"])
        return {"added": added, "errors": errors, "analysis": summary}

    @app.post("/api/datasets/paste")
    async def paste(body: PasteBody) -> dict[str, Any]:
        raw = body.text.encode("utf-8")
        if len(raw) > settings.max_upload_mb * 1024 * 1024:
            raise HTTPException(413, f"The pasted text is larger than {settings.max_upload_mb} MB.")
        added = await ingest(body.name.strip() or "pasted.log", raw)
        return {"added": [added], "errors": [], "analysis": await state.analyze()}

    @app.post("/api/datasets/demo")
    async def load_demo() -> dict[str, Any]:
        for d in state.db.datasets():
            if d["demo"]:
                state.db.delete_dataset(d["id"])
        files = demo_data.generate(datetime.now(timezone.utc), state.tz)
        added = [await ingest(name, text.encode("utf-8"), demo=True) for name, text in files.items()]
        return {"added": added, "errors": [], "analysis": await state.analyze()}

    @app.get("/api/datasets/demo/download/{name}")
    async def demo_file(name: str):
        files = demo_data.generate(datetime.now(timezone.utc), state.tz)
        if name not in files:
            raise HTTPException(404, "No such demo file.")
        from fastapi.responses import Response

        return Response(files[name], media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.delete("/api/datasets/{ds_id}")
    async def delete_dataset(ds_id: str) -> dict[str, Any]:
        if not state.db.delete_dataset(ds_id):
            raise HTTPException(404, "That file isn't loaded.")
        return {"ok": True, "analysis": await state.analyze()}

    @app.delete("/api/datasets")
    async def clear_datasets() -> dict[str, Any]:
        state.db.clear_datasets()
        return {"ok": True, "analysis": await state.analyze()}

    @app.post("/api/analyze")
    async def analyze() -> dict[str, Any]:
        return await state.analyze()

    # ------------------------------------------------------------------ alerts and events
    @app.get("/api/alerts")
    async def alerts(severity: str = "", source: str = "", q: str = "", incident: str = "") -> list[dict[str, Any]]:
        rows = state.db.alerts()
        if severity:
            rows = [a for a in rows if a["severity"] in severity.split(",")]
        if source:
            rows = [a for a in rows if a["source"] == source]
        if incident:
            rows = [a for a in rows if a["incident_id"] == incident]
        if q:
            ql = q.lower()
            rows = [a for a in rows if ql in f"{a['title']} {a['description']} {a['ip']} {a['user']} {a['host']}".lower()]
        for a in rows:
            a["evidence_count"] = len(a.pop("evidence"))
            a["details"] = {k: v for k, v in a["details"].items() if k in ("mitre", "anomaly")}
        return rows

    @app.get("/api/alerts/{alert_id}")
    async def alert(alert_id: str) -> dict[str, Any]:
        a = state.db.alert(alert_id)
        if not a:
            raise HTTPException(404, "This alert no longer exists. It may have been replaced when the logs were re-analysed.")
        a["events"] = [event_dict(e) for e in state.db.events_by_id(a["evidence"])]
        a["intel"] = state.intel.feed_verdict(a["ip"]) if a["ip"] else None
        return a

    @app.get("/api/events")
    async def events(q: str = "", ip: str = "", user: str = "", host: str = "", kind: str = "", source: str = "", outcome: str = "", dataset: str = "",
                     limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)) -> dict[str, Any]:
        rows, total = state.db.search_events(text=q, ip=ip, user=user, host=host, kind=kind, source=source, outcome=outcome, dataset=dataset, limit=limit, offset=offset)
        return {"total": total, "events": [event_dict(e) for e in rows]}

    @app.get("/api/events/{event_id}")
    async def event(event_id: int) -> dict[str, Any]:
        rows = state.db.events_by_id([event_id])
        if not rows:
            raise HTTPException(404, "Event not found.")
        return event_dict(rows[0])

    # ------------------------------------------------------------------ incidents
    def incident_or_404(inc_id: str) -> dict[str, Any]:
        inc = state.db.incident(inc_id)
        if not inc:
            raise HTTPException(404, "This incident no longer exists. It may have been merged when the logs were re-analysed.")
        return inc

    @app.get("/api/incidents")
    async def incidents() -> list[dict[str, Any]]:
        out = []
        for inc in state.db.incidents():
            inc["alerts"] = len(inc.pop("alert_ids"))
            inc.pop("steps", None)
            inc["has_report"] = bool(inc["state"]["report"])
            inc["state"] = {k: inc["state"][k] for k in ("status", "report_at")}
            out.append(inc)
        return out

    @app.get("/api/incidents/{inc_id}")
    async def incident(inc_id: str) -> dict[str, Any]:
        inc = incident_or_404(inc_id)
        by_id = {a["id"]: a for a in state.db.alerts()}
        alerts = [by_id[i] for i in inc["alert_ids"] if i in by_id]
        ids = sorted({e for a in alerts for e in a["evidence"]})
        events = {e.id: e for e in state.db.events_by_id(ids)}
        timeline = []
        for a in alerts:
            for eid in a["evidence"][:4] + a["evidence"][-2:]:
                e = events.get(eid)
                if e:
                    timeline.append({**event_dict(e), "alert_id": a["id"], "alert_title": a["title"], "severity": a["severity"]})
        seen, unique = set(), []
        for t in sorted(timeline, key=lambda t: t["ts"]):
            if t["id"] not in seen:
                seen.add(t["id"])
                unique.append(t)
        for a in alerts:
            a["evidence_count"] = len(a["evidence"])
        indicators = {ip: state.intel.feed_verdict(ip) for ip in inc["ips"] + inc["indicators"].get("ips", []) + inc["indicators"].get("domains", [])}
        return {**inc, "alerts": alerts, "timeline": unique[:80], "intel_details": indicators}

    @app.patch("/api/incidents/{inc_id}")
    async def update_incident(inc_id: str, body: IncidentPatch) -> dict[str, Any]:
        incident_or_404(inc_id)
        return state.db.update_incident_state(inc_id, status=body.status, notes=body.notes, done=body.done)

    @app.post("/api/incidents/{inc_id}/report")
    async def report(inc_id: str) -> dict[str, Any]:
        if state.model is None:
            raise HTTPException(400, "Add your Gemini API key as LLM_API_KEY in backend/.env and restart the backend to generate AI reports.")
        inc = incident_or_404(inc_id)
        by_id = {a["id"]: a for a in state.db.alerts()}
        alerts = [by_id[i] for i in inc["alert_ids"] if i in by_id]
        evidence = {}
        for a in alerts:
            ids = a["evidence"]
            pick = ids if len(ids) <= 6 else ids[:3] + ids[-3:]
            evidence[a["id"]] = state.db.events_by_id(pick)
        intel = {ip: state.intel.feed_verdict(ip) for ip in inc["ips"] + inc["indicators"].get("domains", [])}
        started = time.monotonic()
        try:
            result = await generate_report(state.model, inc, alerts, evidence, intel)
        except LLMError as err:
            raise HTTPException(502, str(err)) from err
        log.info("Report for %s written in %.1fs", inc_id, time.monotonic() - started)
        return state.db.update_incident_state(inc_id, report=result, report_at=time.time(), report_model=getattr(state.model, "active_model", None) or settings.resolved_model)

    # ------------------------------------------------------------------ threat intel
    @app.get("/api/intel/lookup")
    async def lookup(value: str = Query(..., min_length=2, max_length=300), live: bool = True) -> dict[str, Any]:
        try:
            return await state.intel.lookup(value, live=live)
        except ValueError as err:
            raise HTTPException(400, str(err)) from err

    @app.post("/api/intel/refresh")
    async def refresh() -> dict[str, Any]:
        if not settings.intel_feeds_enabled:
            raise HTTPException(400, "Threat feeds are turned off (INTEL_FEEDS_ENABLED=false in backend/.env).")
        updated = await state.refresh_feeds(force=True)
        return {"updated": updated, **state.intel.status()}

    @app.post("/api/intel/file")
    async def check_file(file: UploadFile = File(...)) -> dict[str, Any]:
        """Hashes an uploaded file and checks the hashes. The file is read in pieces and never saved."""
        hasher = files_mod.Hasher(file.filename or "file")
        limit = settings.max_check_mb * 1024 * 1024
        while chunk := await file.read(1024 * 1024):
            hasher.update(chunk)
            if hasher.size > limit:
                raise HTTPException(413, f"The file is larger than {settings.max_check_mb} MB. Check its SHA-256 hash in the box above instead.")
        if hasher.size == 0:
            raise HTTPException(400, "The file is empty.")
        names = None
        if hasher.head[:4] == files_mod.ZIP_MAGIC:
            try:
                await file.seek(0)
                names = zipfile.ZipFile(file.file).namelist()[:2000]
            except (zipfile.BadZipFile, OSError):
                names = None
        info = hasher.finish(names)
        await file.close()
        result = await state.intel.lookup(info.sha256)
        extra = [hit for h in (info.md5, info.sha1) for hit in state.intel.feeds.lookup(h) if hit["feed"] not in {x["feed"] for x in result["feeds"]}]
        if extra:
            result["feeds"] += extra
            result["verdict"], result["reasons"] = combine(result["feeds"], result["abuseipdb"], result["virustotal"])
        notes = list(result["notes"])
        if result["verdict"] == "unknown" and result["virustotal"] is None:
            notes.insert(0, "Unknown doesn't mean safe: new or targeted malware isn't listed anywhere yet.")
        elif result["verdict"] == "unknown":
            notes.insert(0, "VirusTotal has no record of this file, so no antivirus engine has scanned it there yet.")
        if info.risky_type:
            notes.append("This kind of file can run code. Don't open it unless you trust where it came from.")
        result["notes"] = notes
        return {"file": info.to_dict(), **result}

    @app.get("/api/intel/demo-sample")
    async def demo_sample_file():
        from fastapi.responses import Response

        return Response(demo_sample.CONTENT, media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="{demo_sample.NAME}"'})

    # ------------------------------------------------------------------ investigation chat
    @app.get("/api/chat/{scope}")
    async def chat(scope: str) -> list[dict[str, Any]]:
        return state.db.chat(scope)

    @app.delete("/api/chat/{scope}")
    async def clear_chat(scope: str) -> dict[str, bool]:
        state.db.clear_chat(scope)
        return {"ok": True}

    @app.post("/api/chat/{scope}")
    async def ask(scope: str, body: AskBody) -> StreamingResponse:
        question = body.content.strip()

        async def stream() -> AsyncIterator[str]:
            if state.model is None:
                yield sse("error", {"message": "Add your Gemini API key as LLM_API_KEY in backend/.env, then restart the backend."})
                return
            user_msg = state.db.add_chat(scope, "user", question)
            yield sse("user", user_msg)
            agent = Investigator(state.model, state.db, state.intel, settings.max_agent_steps)
            try:
                async for ev in agent.run(scope, question):
                    if ev["type"] == "answer":
                        yield sse("answer", state.db.add_chat(scope, "assistant", ev["content"], ev["steps"], ev["cited"]))
                    elif ev["type"] == "error":
                        state.db.delete_chat_message(user_msg["id"])
                        yield sse("error", {"message": ev["message"]})
                        return
                    else:
                        yield sse(ev["type"], ev)
            except Exception:  # noqa: BLE001 - report any failure instead of a broken stream
                log.exception("Investigation failed")
                state.db.delete_chat_message(user_msg["id"])
                yield sse("error", {"message": "Something went wrong while investigating. Check the backend terminal for details."})
                return
            yield sse("done", {})

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------------ the built web app, if present
    dist = BACKEND_DIR.parent / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str):
            target = dist / path
            if path and target.is_file() and dist in target.resolve().parents:
                return FileResponse(target)
            return FileResponse(dist / "index.html")

    return app


app = create_app()
