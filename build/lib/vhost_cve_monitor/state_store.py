from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict


class StateStore:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS alert_state (
                    fingerprint TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS repeated_failures (
                    scope TEXT PRIMARY KEY,
                    count INTEGER NOT NULL,
                    last_error_hash TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    last_alerted_hash TEXT
                );
                """
            )

    @staticmethod
    def stable_hash(payload: Dict) -> str:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def should_alert(self, fingerprint: str, payload: Dict) -> bool:
        payload_hash = self.stable_hash(payload)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_hash FROM alert_state WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row and row["payload_hash"] == payload_hash:
                connection.execute(
                    "UPDATE alert_state SET last_seen_at = ? WHERE fingerprint = ?",
                    (now, fingerprint),
                )
                return False
            if row:
                connection.execute(
                    "UPDATE alert_state SET payload_hash = ?, last_seen_at = ? WHERE fingerprint = ?",
                    (payload_hash, now, fingerprint),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO alert_state (fingerprint, payload_hash, last_seen_at, first_seen_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (fingerprint, payload_hash, now, now),
                )
            return True

    def register_failure(self, scope: str, detail: Dict, threshold: int) -> bool:
        error_hash = self.stable_hash(detail)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT count, last_error_hash, last_alerted_hash FROM repeated_failures WHERE scope = ?",
                (scope,),
            ).fetchone()
            if not row:
                connection.execute(
                    """
                    INSERT INTO repeated_failures (scope, count, last_error_hash, last_seen_at, last_alerted_hash)
                    VALUES (?, 1, ?, ?, NULL)
                    """,
                    (scope, error_hash, now),
                )
                return False
            count = row["count"] + 1 if row["last_error_hash"] == error_hash else 1
            connection.execute(
                """
                UPDATE repeated_failures
                SET count = ?, last_error_hash = ?, last_seen_at = ?
                WHERE scope = ?
                """,
                (count, error_hash, now, scope),
            )
            if count >= threshold and row["last_alerted_hash"] != error_hash:
                connection.execute(
                    "UPDATE repeated_failures SET last_alerted_hash = ? WHERE scope = ?",
                    (error_hash, scope),
                )
                return True
            return False
