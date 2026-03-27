from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

import structlog

log = structlog.get_logger()

_local = threading.local()


def _get_connection(db_path: str) -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    conn = getattr(_local, "connection", None)
    if conn is None or getattr(_local, "db_path", None) != db_path:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        _local.connection = conn
        _local.db_path = db_path
    return conn


class Database:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        return _get_connection(self.db_path)

    def _init_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                hostname TEXT PRIMARY KEY,
                ip TEXT,
                providers TEXT,
                findings_critical INTEGER DEFAULT 0,
                findings_warning INTEGER DEFAULT 0,
                findings_info INTEGER DEFAULT 0,
                last_run TEXT,
                version TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT,
                findings_critical INTEGER,
                findings_warning INTEGER,
                findings_info INTEGER,
                run_at TEXT,
                FOREIGN KEY(hostname) REFERENCES agents(hostname)
            );
        """)
        conn.commit()
        log.info("database initialized", db_path=self.db_path)

    def upsert_agent(
        self,
        hostname: str,
        ip: str,
        providers: list[str],
        findings_summary: dict[str, int],
        last_run: str,
        version: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO agents
                (hostname, ip, providers, findings_critical, findings_warning, findings_info,
                 last_run, version, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                ip=excluded.ip,
                providers=excluded.providers,
                findings_critical=excluded.findings_critical,
                findings_warning=excluded.findings_warning,
                findings_info=excluded.findings_info,
                last_run=excluded.last_run,
                version=excluded.version,
                updated_at=excluded.updated_at
            """,
            (
                hostname,
                ip,
                json.dumps(providers),
                findings_summary.get("critical", 0),
                findings_summary.get("warning", 0),
                findings_summary.get("info", 0),
                last_run,
                version,
                now,
            ),
        )
        conn.commit()
        log.debug("agent upserted", hostname=hostname)

    def add_run(
        self,
        hostname: str,
        findings_summary: dict[str, int],
        run_at: str,
    ) -> None:
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO runs (hostname, findings_critical, findings_warning, findings_info, run_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                hostname,
                findings_summary.get("critical", 0),
                findings_summary.get("warning", 0),
                findings_summary.get("info", 0),
                run_at,
            ),
        )
        conn.commit()

    def get_all_agents(self) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM agents ORDER BY hostname").fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["providers"] = json.loads(d["providers"] or "[]")
            result.append(d)
        return result

    def get_agent(self, hostname: str) -> dict | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM agents WHERE hostname = ?", (hostname,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["providers"] = json.loads(d["providers"] or "[]")
        return d

    def get_runs_for_agent(self, hostname: str, limit: int = 100) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM runs WHERE hostname = ? ORDER BY run_at DESC LIMIT ?",
            (hostname, limit),
        ).fetchall()
        return [dict(row) for row in rows]
