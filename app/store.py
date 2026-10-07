"""SQLite-backed persistence for verdicts and execution receipts.

A single successful verdict is stored per leaf credential (leaf credentials
are single-use) and per (root key, chain digest, leaf id, request) tuple.
The combination of a process-wide lock and UNIQUE constraints makes
concurrent submissions converge to exactly one execution and one receipt,
surviving restarts.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    verdict_key  TEXT PRIMARY KEY,
    leaf_key     TEXT NOT NULL UNIQUE,
    root_key     TEXT NOT NULL,
    chain_digest TEXT NOT NULL,
    leaf_id      TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
"""


class Store:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        path = os.path.join(data_dir, "verdicts.db")
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self.lock = threading.Lock()

    # -- lookups -----------------------------------------------------------
    def get_by_verdict_key(self, verdict_key: str):
        row = self._conn.execute(
            "SELECT receipt_json FROM verdicts WHERE verdict_key = ?",
            (verdict_key,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def get_by_leaf_key(self, leaf_key: str):
        row = self._conn.execute(
            "SELECT verdict_key, request_hash, receipt_json FROM verdicts "
            "WHERE leaf_key = ?",
            (leaf_key,),
        ).fetchone()
        if not row:
            return None
        return {
            "verdict_key": row[0],
            "request_hash": row[1],
            "receipt": json.loads(row[2]),
        }

    def leaf_used(self, leaf_key: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM verdicts WHERE leaf_key = ?", (leaf_key,)
        ).fetchone()
        return row is not None

    # -- mutation ------------------------------------------------------------
    def insert_verdict(self, record: dict) -> None:
        """Insert a verdict row; raises sqlite3.IntegrityError on conflict."""
        with self._conn:
            self._conn.execute(
                "INSERT INTO verdicts (verdict_key, leaf_key, root_key, "
                "chain_digest, leaf_id, request_json, request_hash, "
                "receipt_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    record["verdict_key"],
                    record["leaf_key"],
                    record["root_key"],
                    record["chain_digest"],
                    record["leaf_id"],
                    json.dumps(record["request"], ensure_ascii=False, sort_keys=True),
                    record["request_hash"],
                    json.dumps(record["receipt"], ensure_ascii=False, sort_keys=True),
                    record["created_at"],
                ),
            )

    # -- review --------------------------------------------------------------
    def list_verdicts(self):
        rows = self._conn.execute(
            "SELECT verdict_key, leaf_key, root_key, chain_digest, leaf_id, "
            "request_json, request_hash, receipt_json, created_at "
            "FROM verdicts ORDER BY rowid"
        ).fetchall()
        return [
            {
                "verdict_key": r[0],
                "leaf_key": r[1],
                "root_key": r[2],
                "chain_digest": r[3],
                "leaf_id": r[4],
                "request": json.loads(r[5]),
                "request_hash": r[6],
                "receipt": json.loads(r[7]),
                "created_at": r[8],
            }
            for r in rows
        ]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]

    def close(self):
        self._conn.close()
