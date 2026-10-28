"""Local history: findings and endpoints saved to SQLite so culprits survive restarts, plus a
timeline of what each app did and when.

Stays on this machine (per-user data folder), keeps RETENTION_DAYS, and never blocks the event
loop: writes go through a queue to one background thread that commits in small batches.
Disable with `netpulse watch --no-history`; wipe with `netpulse history --clear`.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

RETENTION_DAYS = 30
FLUSH_SECONDS = 2.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS apps (
    app TEXT PRIMARY KEY, name TEXT, exe TEXT, info TEXT,
    first_seen REAL, last_seen REAL
);
CREATE TABLE IF NOT EXISTS endpoints (
    app TEXT, ip TEXT, port INTEGER, host TEXT, category TEXT, country TEXT, org TEXT,
    lat REAL, lon REAL, tracker_rule TEXT, threat_indicator TEXT, threat TEXT, flags TEXT,
    beacon_period REAL, name TEXT, exe TEXT, first_seen REAL, last_seen REAL, hits INTEGER,
    PRIMARY KEY (app, ip, port)
);
CREATE TABLE IF NOT EXISTS findings (
    app TEXT, kind TEXT, key TEXT, name TEXT, severity TEXT, title TEXT, detail TEXT,
    remote TEXT, first_seen REAL, last_seen REAL, hits INTEGER,
    PRIMARY KEY (app, kind, key)
);
CREATE INDEX IF NOT EXISTS findings_first_seen ON findings (first_seen);
"""


def default_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "netpulse" / "history.db"


class HistoryStore:
    def __init__(self, path: Optional[Path] = None, retention_days: int = RETENTION_DAYS):
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention = retention_days * 86400
        with self._connect() as db:
            db.executescript(SCHEMA)
            cutoff = time.time() - self.retention
            for table in ("endpoints", "findings", "apps"):
                db.execute(f"DELETE FROM {table} WHERE last_seen < ?", (cutoff,))
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._writer, name="netpulse-history", daemon=True)
        self._thread.start()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.row_factory = sqlite3.Row
        return db

    # ---- writes (any thread; applied by the writer thread) ---------------

    def record_app(self, app: str, name: str, exe: Optional[str], info: Optional[dict], ts: float) -> None:
        self._queue.put((
            "INSERT INTO apps VALUES (?,?,?,?,?,?) ON CONFLICT(app) DO UPDATE SET "
            "name=excluded.name, exe=COALESCE(excluded.exe, exe), info=COALESCE(excluded.info, info), "
            "last_seen=MAX(last_seen, excluded.last_seen)",
            (app, name, exe, json.dumps(info) if info else None, ts, ts),
        ))

    def record_endpoint(self, row: dict[str, Any]) -> None:
        self._queue.put((
            "INSERT INTO endpoints VALUES (:app,:ip,:port,:host,:category,:country,:org,:lat,:lon,:tracker_rule,"
            ":threat_indicator,:threat,:flags,:beacon_period,:name,:exe,:ts,:ts,1) "
            "ON CONFLICT(app, ip, port) DO UPDATE SET host=COALESCE(excluded.host, host), "
            "category=excluded.category, tracker_rule=COALESCE(excluded.tracker_rule, tracker_rule), "
            "threat_indicator=COALESCE(excluded.threat_indicator, threat_indicator), "
            "threat=COALESCE(excluded.threat, threat), flags=excluded.flags, "
            "beacon_period=COALESCE(excluded.beacon_period, beacon_period), "
            "last_seen=MAX(last_seen, excluded.last_seen), hits=hits+1",
            row,
        ))

    def record_finding(self, app: str, kind: str, key: str, name: str, severity: str, title: str,
                       detail: str, remote: Optional[str], ts: float) -> None:
        self._queue.put((
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,1) ON CONFLICT(app, kind, key) DO UPDATE SET "
            "severity=excluded.severity, title=excluded.title, detail=excluded.detail, "
            "last_seen=MAX(last_seen, excluded.last_seen), hits=hits+1",
            (app, kind, key, name, severity, title, detail, remote, ts, ts),
        ))

    def flush(self, timeout: float = 5.0) -> None:
        """Block until everything queued so far is committed (tests, shutdown)."""
        done = threading.Event()
        self._queue.put(done)
        done.wait(timeout)

    def _writer(self) -> None:
        db = self._connect()
        while True:
            items = [self._queue.get()]
            deadline = time.time() + FLUSH_SECONDS
            while time.time() < deadline:  # small batches: one commit per couple of seconds
                try:
                    items.append(self._queue.get(timeout=max(0.0, deadline - time.time())))
                except queue.Empty:
                    break
                if isinstance(items[-1], threading.Event):
                    break
            try:
                for item in items:
                    if not isinstance(item, threading.Event):
                        db.execute(*item)
                db.commit()
            except Exception:
                log.exception("history write failed; continuing")
            for item in items:
                if isinstance(item, threading.Event):
                    item.set()

    # ---- reads (caller's thread, own connection) -------------------------

    def _query(self, sql: str, args: tuple = ()) -> list[dict]:
        try:
            with self._connect() as db:
                return [dict(r) for r in db.execute(sql, args)]
        except sqlite3.Error:
            log.exception("history read failed")
            return []

    def endpoints(self, app: Optional[str] = None) -> list[dict]:
        cutoff = time.time() - self.retention
        if app is None:
            return self._query("SELECT * FROM endpoints WHERE last_seen >= ?", (cutoff,))
        return self._query("SELECT * FROM endpoints WHERE app = ? AND last_seen >= ? ORDER BY last_seen DESC",
                           (app, cutoff))

    def finding_keys(self) -> set[tuple[str, str, str]]:
        """Every (app, kind, key) already on record — alerts treat these as old news."""
        return {(r["app"], r["kind"], r["key"]) for r in self._query("SELECT app, kind, key FROM findings")}

    def apps(self) -> dict[str, dict]:
        return {r["app"]: r for r in self._query("SELECT * FROM apps")}

    def timeline(self, since: Optional[float] = None, app: Optional[str] = None, limit: int = 300,
                 min_severity: Optional[set[str]] = None) -> list[dict]:
        where, args = ["first_seen >= ?"], [since or time.time() - self.retention]
        if app:
            where.append("app = ?")
            args.append(app)
        if min_severity:
            where.append(f"severity IN ({','.join('?' * len(min_severity))})")
            args.extend(sorted(min_severity))
        return self._query(f"SELECT * FROM findings WHERE {' AND '.join(where)} ORDER BY first_seen DESC LIMIT ?",
                           (*args, limit))

    def clear_findings(self) -> None:
        """Empty the timeline (findings) only."""
        self.flush()
        with self._connect() as db:
            db.execute("DELETE FROM findings")

    def clear_activity(self) -> None:
        """Forget saved endpoints and apps (what restores culprits after a restart); keep the timeline."""
        self.flush()
        with self._connect() as db:
            db.execute("DELETE FROM endpoints")
            db.execute("DELETE FROM apps")

    def clear(self) -> None:
        with self._connect() as db:
            for table in ("endpoints", "findings", "apps"):
                db.execute(f"DELETE FROM {table}")
        log.info("history cleared")
