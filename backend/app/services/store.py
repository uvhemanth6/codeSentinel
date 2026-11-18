"""SQLite persistence: scans, per-finding review state, settings."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, name TEXT, source_type TEXT, source_ref TEXT, status TEXT, stage TEXT, error TEXT,
  stages_json TEXT, created_at REAL, finished_at REAL, options_json TEXT, summary_json TEXT, result_json TEXT);
CREATE TABLE IF NOT EXISTS reviews (
  scan_id TEXT, finding_id TEXT, reviewed INTEGER DEFAULT 0, note TEXT DEFAULT '', updated_at REAL,
  PRIMARY KEY (scan_id, finding_id));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---- scans
    def create_scan(self, name: str, source_type: str, source_ref: str, options: dict) -> str:
        sid = uuid.uuid4().hex[:12]
        with self.conn() as c:
            c.execute("INSERT INTO scans (id,name,source_type,source_ref,status,stage,stages_json,created_at,options_json)"
                      " VALUES (?,?,?,?,?,?,?,?,?)",
                      (sid, name[:120], source_type, source_ref[:300], "queued", "ingestion", "[]", time.time(),
                       json.dumps(options)))
        return sid

    def update_stage(self, sid: str, stages: list[dict], stage: str, status: str = "running") -> None:
        with self.conn() as c:
            c.execute("UPDATE scans SET status=?, stage=?, stages_json=? WHERE id=?",
                      (status, stage, json.dumps(stages), sid))

    def finish_scan(self, sid: str, result: dict | None, error: str | None, stages: list[dict]) -> None:
        with self.conn() as c:
            summary = None
            if result is not None:
                s = result["summary"]
                summary = {"files_scanned": s["files_scanned"], "code_lines": s["code_lines"],
                           "scores": s["scores"], "frameworks": result["structure"].get("frameworks", []),
                           "languages": result["languages"]["languages"][:6]}
            c.execute("UPDATE scans SET status=?, error=?, finished_at=?, summary_json=?, result_json=?, stages_json=?,"
                      " stage=? WHERE id=?",
                      ("failed" if error else "completed", error, time.time(), json.dumps(summary) if summary else None,
                       json.dumps(result) if result else None, json.dumps(stages),
                       "failed" if error else "report", sid))

    @staticmethod
    def _row(r: sqlite3.Row, with_result: bool) -> dict:
        d = {"id": r["id"], "name": r["name"], "source_type": r["source_type"], "source_ref": r["source_ref"],
             "status": r["status"], "stage": r["stage"], "error": r["error"], "created_at": r["created_at"],
             "finished_at": r["finished_at"], "stages": json.loads(r["stages_json"] or "[]"),
             "options": json.loads(r["options_json"] or "{}"),
             "summary": json.loads(r["summary_json"]) if r["summary_json"] else None}
        if with_result:
            d["result"] = json.loads(r["result_json"]) if r["result_json"] else None
        return d

    def get_scan(self, sid: str, with_result: bool = True) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        return self._row(r, with_result) if r else None

    def list_scans(self, limit: int = 100) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT id,name,source_type,source_ref,status,stage,error,created_at,finished_at,"
                             "stages_json,options_json,summary_json FROM scans ORDER BY created_at DESC LIMIT ?",
                             (limit,)).fetchall()
        return [self._row(r, False) for r in rows]

    def delete_scan(self, sid: str) -> bool:
        with self.conn() as c:
            n = c.execute("DELETE FROM scans WHERE id=?", (sid,)).rowcount
            c.execute("DELETE FROM reviews WHERE scan_id=?", (sid,))
        return n > 0

    def save_result(self, sid: str, result: dict) -> None:
        with self.conn() as c:
            c.execute("UPDATE scans SET result_json=? WHERE id=?", (json.dumps(result), sid))

    def fail_interrupted(self) -> None:
        with self.conn() as c:
            c.execute("UPDATE scans SET status='failed', error='Interrupted by server restart' "
                      "WHERE status IN ('queued','running')")

    # ---- reviews
    def set_review(self, sid: str, fid: str, reviewed: bool, note: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO reviews (scan_id,finding_id,reviewed,note,updated_at) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(scan_id,finding_id) DO UPDATE SET reviewed=excluded.reviewed, note=excluded.note, "
                      "updated_at=excluded.updated_at", (sid, fid, 1 if reviewed else 0, note[:1000], time.time()))

    def reviews(self, sid: str) -> dict[str, dict]:
        with self.conn() as c:
            rows = c.execute("SELECT finding_id,reviewed,note FROM reviews WHERE scan_id=?", (sid,)).fetchall()
        return {r["finding_id"]: {"reviewed": bool(r["reviewed"]), "note": r["note"]} for r in rows}

    # ---- settings
    def get_settings_overrides(self) -> dict:
        with self.conn() as c:
            r = c.execute("SELECT value FROM settings WHERE key='overrides'").fetchone()
        return json.loads(r["value"]) if r else {}

    def set_settings_overrides(self, overrides: dict) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO settings (key,value) VALUES ('overrides',?) ON CONFLICT(key) DO UPDATE SET "
                      "value=excluded.value", (json.dumps(overrides),))
