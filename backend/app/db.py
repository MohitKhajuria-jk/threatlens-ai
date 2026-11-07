"""SQLite storage: uploaded datasets, normalized events, analysis results and analyst work."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, format TEXT, source TEXT, size_bytes INTEGER, lines INTEGER,
  events INTEGER, skipped_samples TEXT, demo INTEGER DEFAULT 0, uploaded_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE, line_no INTEGER,
  ts REAL NOT NULL, source TEXT, host TEXT, kind TEXT, outcome TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
  user TEXT, message TEXT, fields TEXT, raw TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS events_user ON events(user);
CREATE INDEX IF NOT EXISTS events_dataset ON events(dataset_id);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, rule_id TEXT, title TEXT, short TEXT, severity TEXT, source TEXT, techniques TEXT,
  first_seen REAL, last_seen REAL, count INTEGER, ip TEXT, user TEXT, host TEXT, description TEXT,
  evidence TEXT, details TEXT, incident_id TEXT
);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, data TEXT NOT NULL, risk INTEGER, last_seen REAL);
CREATE TABLE IF NOT EXISTS incident_state (
  id TEXT PRIMARY KEY, status TEXT DEFAULT 'open', notes TEXT DEFAULT '', done TEXT DEFAULT '[]',
  report TEXT, report_at REAL, report_model TEXT, updated_at REAL
);
CREATE TABLE IF NOT EXISTS intel_cache (indicator TEXT, provider TEXT, data TEXT, fetched_at REAL, PRIMARY KEY (indicator, provider));
CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY, scope TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, steps TEXT DEFAULT '[]',
  cited TEXT DEFAULT '[]', created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

EVENT_COLUMNS = "id, dataset_id, line_no, ts, source, host, kind, outcome, src_ip, dst_ip, dst_port, user, message, fields, raw"


def event_from_row(row: sqlite3.Row) -> Event:
    return Event(id=row["id"], dataset_id=row["dataset_id"], line_no=row["line_no"], ts=datetime.fromtimestamp(row["ts"], timezone.utc),
                 source=row["source"], host=row["host"], kind=row["kind"], outcome=row["outcome"], src_ip=row["src_ip"], dst_ip=row["dst_ip"],
                 dst_port=row["dst_port"], user=row["user"], message=row["message"] or "", fields=json.loads(row["fields"] or "{}"), raw=row["raw"] or "")


def event_dict(e: Event) -> dict[str, Any]:
    return {"id": e.id, "dataset_id": e.dataset_id, "line": e.line_no, "ts": e.ts.isoformat(), "source": e.source, "host": e.host, "kind": e.kind,
            "outcome": e.outcome, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port, "user": e.user, "message": e.message,
            "fields": e.fields, "raw": e.raw}


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def q(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, tuple(params)).fetchall()

    def x(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self.lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur

    # ------------------------------------------------------------------ datasets and events
    def add_dataset(self, name: str, fmt: str | None, source: str | None, size: int, lines: int, events: list[Event], skipped: list[str], demo: bool = False) -> dict[str, Any]:
        ds_id = uuid.uuid4().hex[:12]
        with self.lock:
            self.conn.execute("INSERT INTO datasets (id, name, format, source, size_bytes, lines, events, skipped_samples, demo, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (ds_id, name, fmt, source, size, lines, len(events), json.dumps(skipped), int(demo), time.time()))
            self.conn.executemany(
                "INSERT INTO events (dataset_id, line_no, ts, source, host, kind, outcome, src_ip, dst_ip, dst_port, user, message, fields, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(ds_id, e.line_no, e.epoch, e.source, e.host, e.kind, e.outcome, e.src_ip, e.dst_ip, e.dst_port, e.user, e.message, json.dumps(e.fields, default=str), e.raw) for e in events])
            self.conn.commit()
        return self.dataset(ds_id)

    def dataset(self, ds_id: str) -> dict[str, Any] | None:
        rows = self.q("SELECT * FROM datasets WHERE id = ?", (ds_id,))
        return self._dataset(rows[0]) if rows else None

    def datasets(self) -> list[dict[str, Any]]:
        return [self._dataset(r) for r in self.q("SELECT * FROM datasets ORDER BY uploaded_at DESC")]

    def _dataset(self, r: sqlite3.Row) -> dict[str, Any]:
        span = self.q("SELECT MIN(ts) AS a, MAX(ts) AS b FROM events WHERE dataset_id = ?", (r["id"],))[0]
        return {"id": r["id"], "name": r["name"], "format": r["format"], "source": r["source"], "size_bytes": r["size_bytes"], "lines": r["lines"],
                "events": r["events"], "skipped_samples": json.loads(r["skipped_samples"] or "[]"), "demo": bool(r["demo"]), "uploaded_at": r["uploaded_at"],
                "first_ts": span["a"], "last_ts": span["b"]}

    def delete_dataset(self, ds_id: str) -> bool:
        return self.x("DELETE FROM datasets WHERE id = ?", (ds_id,)).rowcount > 0

    def clear_datasets(self) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM events")
            self.conn.execute("DELETE FROM datasets")
            self.conn.commit()

    def all_events(self) -> list[Event]:
        return [event_from_row(r) for r in self.q(f"SELECT {EVENT_COLUMNS} FROM events ORDER BY ts, id")]

    def events_by_id(self, ids: list[int]) -> list[Event]:
        if not ids:
            return []
        out = []
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            out += [event_from_row(r) for r in self.q(f"SELECT {EVENT_COLUMNS} FROM events WHERE id IN ({','.join('?' * len(chunk))})", chunk)]
        return sorted(out, key=lambda e: (e.ts, e.id or 0))

    def search_events(self, *, text: str = "", ip: str = "", user: str = "", host: str = "", kind: str = "", source: str = "", outcome: str = "",
                      dataset: str = "", start: float | None = None, end: float | None = None, limit: int = 100, offset: int = 0) -> tuple[list[Event], int]:
        where, params = [], []
        if text:
            where.append("(raw LIKE ? OR message LIKE ?)")
            params += [f"%{text}%", f"%{text}%"]
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            params += [ip, ip]
        for col, val in (("user", user), ("host", host), ("kind", kind), ("source", source), ("outcome", outcome), ("dataset_id", dataset)):
            if val:
                where.append(f"{col} = ? COLLATE NOCASE")
                params.append(val)
        if start is not None:
            where.append("ts >= ?")
            params.append(start)
        if end is not None:
            where.append("ts <= ?")
            params.append(end)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self.q(f"SELECT COUNT(*) AS n FROM events {clause}", params)[0]["n"]
        rows = self.q(f"SELECT {EVENT_COLUMNS} FROM events {clause} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?", [*params, limit, offset])
        return [event_from_row(r) for r in rows], total

    def top_values(self, column: str, where: dict[str, Any], limit: int = 10) -> list[tuple[Any, int]]:
        allowed = {"src_ip", "dst_ip", "dst_port", "user", "host", "kind", "source", "outcome"}
        if column not in allowed:
            raise ValueError(f"Can't count by {column}")
        clauses, params = [f"{column} IS NOT NULL"], []
        for k, v in where.items():
            if v not in (None, "") and k in allowed:
                clauses.append(f"{k} = ?")
                params.append(v)
        rows = self.q(f"SELECT {column} AS v, COUNT(*) AS n FROM events WHERE {' AND '.join(clauses)} GROUP BY {column} ORDER BY n DESC LIMIT ?", [*params, limit])
        return [(r["v"], r["n"]) for r in rows]

    def event_count(self) -> int:
        return self.q("SELECT COUNT(*) AS n FROM events")[0]["n"]

    # ------------------------------------------------------------------ analysis results
    def save_results(self, alerts: list[dict[str, Any]], incidents: list[dict[str, Any]]) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM alerts")
            self.conn.execute("DELETE FROM incidents")
            self.conn.executemany(
                "INSERT OR REPLACE INTO alerts (id, rule_id, title, short, severity, source, techniques, first_seen, last_seen, count, ip, user, host, description, evidence, details, incident_id) "
                "VALUES (:id,:rule_id,:title,:short,:severity,:source,:techniques,:first_seen,:last_seen,:count,:ip,:user,:host,:description,:evidence,:details,:incident_id)",
                [{**a, "techniques": json.dumps(a["techniques"]), "evidence": json.dumps(a["evidence"]), "details": json.dumps(a["details"], default=str)} for a in alerts])
            self.conn.executemany("INSERT OR REPLACE INTO incidents (id, data, risk, last_seen) VALUES (?,?,?,?)",
                                  [(i["id"], json.dumps(i, default=str), i["risk"], datetime.fromisoformat(i["last_seen"]).timestamp()) for i in incidents])
            self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('analyzed_at', ?)", (str(time.time()),))
            self.conn.commit()

    def alerts(self) -> list[dict[str, Any]]:
        return [self._alert(r) for r in self.q("SELECT * FROM alerts ORDER BY last_seen DESC")]

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        rows = self.q("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return self._alert(rows[0]) if rows else None

    def _alert(self, r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        d["techniques"] = json.loads(d["techniques"] or "[]")
        d["evidence"] = json.loads(d["evidence"] or "[]")
        d["details"] = json.loads(d["details"] or "{}")
        return d

    def incidents(self) -> list[dict[str, Any]]:
        out = []
        for r in self.q("SELECT data FROM incidents ORDER BY risk DESC, last_seen DESC"):
            inc = json.loads(r["data"])
            inc["state"] = self.incident_state(inc["id"])
            out.append(inc)
        return out

    def incident(self, inc_id: str) -> dict[str, Any] | None:
        rows = self.q("SELECT data FROM incidents WHERE id = ?", (inc_id,))
        if not rows:
            return None
        inc = json.loads(rows[0]["data"])
        inc["state"] = self.incident_state(inc_id)
        return inc

    def incident_state(self, inc_id: str) -> dict[str, Any]:
        rows = self.q("SELECT * FROM incident_state WHERE id = ?", (inc_id,))
        if not rows:
            return {"status": "open", "notes": "", "done": [], "report": None, "report_at": None, "report_model": None}
        r = rows[0]
        return {"status": r["status"], "notes": r["notes"], "done": json.loads(r["done"] or "[]"), "report": json.loads(r["report"]) if r["report"] else None,
                "report_at": r["report_at"], "report_model": r["report_model"]}

    def update_incident_state(self, inc_id: str, **changes: Any) -> dict[str, Any]:
        state = self.incident_state(inc_id)
        state.update({k: v for k, v in changes.items() if v is not None})
        self.x("INSERT OR REPLACE INTO incident_state (id, status, notes, done, report, report_at, report_model, updated_at) VALUES (?,?,?,?,?,?,?,?)",
               (inc_id, state["status"], state["notes"], json.dumps(state["done"]), json.dumps(state["report"]) if state["report"] else None,
                state["report_at"], state["report_model"], time.time()))
        return state

    def analyzed_at(self) -> float | None:
        rows = self.q("SELECT value FROM meta WHERE key = 'analyzed_at'")
        return float(rows[0]["value"]) if rows else None

    # ------------------------------------------------------------------ intel cache
    def cached_intel(self, indicator: str, provider: str, max_age: float = 86400) -> dict[str, Any] | None:
        rows = self.q("SELECT data, fetched_at FROM intel_cache WHERE indicator = ? AND provider = ?", (indicator, provider))
        if rows and time.time() - rows[0]["fetched_at"] < max_age:
            return {**json.loads(rows[0]["data"]), "cached_at": rows[0]["fetched_at"]}
        return None

    def cache_intel(self, indicator: str, provider: str, data: dict[str, Any]) -> None:
        self.x("INSERT OR REPLACE INTO intel_cache (indicator, provider, data, fetched_at) VALUES (?,?,?,?)", (indicator, provider, json.dumps(data), time.time()))

    # ------------------------------------------------------------------ chat
    def chat(self, scope: str) -> list[dict[str, Any]]:
        return [{"id": r["id"], "role": r["role"], "content": r["content"], "steps": json.loads(r["steps"]), "cited": json.loads(r["cited"]), "created_at": r["created_at"]}
                for r in self.q("SELECT * FROM chat_messages WHERE scope = ? ORDER BY id", (scope,))]

    def add_chat(self, scope: str, role: str, content: str, steps: list | None = None, cited: list | None = None) -> dict[str, Any]:
        cur = self.x("INSERT INTO chat_messages (scope, role, content, steps, cited, created_at) VALUES (?,?,?,?,?,?)",
                     (scope, role, content, json.dumps(steps or []), json.dumps(cited or [], default=str), time.time()))
        return {"id": cur.lastrowid, "role": role, "content": content, "steps": steps or [], "cited": cited or [], "created_at": time.time()}

    def delete_chat_message(self, msg_id: int) -> None:
        self.x("DELETE FROM chat_messages WHERE id = ?", (msg_id,))

    def clear_chat(self, scope: str) -> None:
        self.x("DELETE FROM chat_messages WHERE scope = ?", (scope,))
