"""DuckDB storage: one local file holds every parsed event plus saved app state.

Writes happen in batches (about once a second). Dashboard queries run on their
own cursors in worker threads so they never block ingestion.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import pandas as pd

from .parser import Event

COLUMNS = ["ts", "dev_class", "device", "device_name", "location", "severity",
           "program", "kind", "template_id", "noise", "client_mac", "client_ip",
           "fw_action", "fw_app", "fw_cat", "dst_ip", "dst_port", "port", "raw"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts TIMESTAMPTZ, dev_class VARCHAR, device VARCHAR, device_name VARCHAR,
    location VARCHAR, severity TINYINT, program VARCHAR, kind VARCHAR,
    template_id UBIGINT, noise BOOLEAN, client_mac VARCHAR, client_ip VARCHAR,
    fw_action VARCHAR, fw_app VARCHAR, fw_cat VARCHAR, dst_ip VARCHAR,
    dst_port INTEGER, port VARCHAR, raw VARCHAR
);
CREATE TABLE IF NOT EXISTS kv (key VARCHAR PRIMARY KEY, value VARCHAR);
"""


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.con = duckdb.connect(path)
        self.con.execute("SET TimeZone='UTC'")
        self.con.execute(SCHEMA)
        self._lock = threading.Lock()
        self._buf: list[tuple] = []

    # ---- writes ------------------------------------------------------------
    def add(self, ev: Event):
        self._buf.append((ev.ts, ev.dev_class, ev.device, ev.device_name, ev.location,
                          ev.severity, ev.program, ev.kind, ev.template_id, ev.noise,
                          ev.client_mac, ev.client_ip, ev.fw_action, ev.fw_app, ev.fw_cat,
                          ev.dst_ip, ev.dst_port, ev.port, ev.raw))

    def flush(self) -> int:
        if not self._buf:
            return 0
        rows, self._buf = self._buf, []
        df = pd.DataFrame(rows, columns=COLUMNS)
        with self._lock:
            self.con.append("events", df)
        return len(rows)

    def prune(self, now: datetime, retention_days: int):
        cutoff = now - timedelta(days=retention_days)
        with self._lock:
            self.con.execute("DELETE FROM events WHERE ts < ?", [cutoff])

    def execute(self, sql: str, params=None):
        with self._lock:
            self.con.execute(sql, params or [])

    def save_kv(self, key: str, value):
        with self._lock:
            self.con.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)",
                             [key, json.dumps(value, default=str)])

    def load_kv(self, key: str, default=None):
        with self._lock:
            rows = self.con.execute("SELECT value FROM kv WHERE key = ?", [key]).fetchall()
        return json.loads(rows[0][0]) if rows else default

    def latest_ts(self):
        with self._lock:
            rows = self.con.execute("SELECT max(ts) FROM events").fetchall()
        return rows[0][0] if rows and rows[0][0] else None

    # ---- reads -------------------------------------------------------------
    def query(self, sql: str, params=None) -> list[dict]:
        """Run a read query on a separate cursor; returns rows as dicts."""
        cur = self.con.cursor()
        try:
            cur.execute("SET TimeZone='UTC'")   # settings are per cursor
            res = cur.execute(sql, params or [])
            cols = [d[0] for d in res.description]
            out = []
            for row in res.fetchall():
                d = {}
                for c, v in zip(cols, row):
                    if isinstance(v, datetime):
                        v = (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()
                    d[c] = v
                out.append(d)
            return out
        finally:
            cur.close()

    def close(self):
        self.flush()
        self.con.close()
