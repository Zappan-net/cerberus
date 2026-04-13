from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


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
                CREATE TABLE IF NOT EXISTS current_findings (
                    vhost TEXT NOT NULL,
                    stack TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    dependency TEXT NOT NULL,
                    version TEXT NOT NULL,
                    advisory_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    fixed_version TEXT,
                    affected_range TEXT,
                    advisory_summary TEXT,
                    source_path TEXT NOT NULL,
                    source_line INTEGER,
                    aliases_json TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    PRIMARY KEY (vhost, stack, dependency, version, advisory_id, source_path, source_line)
                );
                CREATE TABLE IF NOT EXISTS current_scan_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    scanned_at TEXT NOT NULL,
                    findings_count INTEGER NOT NULL
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

    def replace_current_findings(self, findings: List[Dict], scanned_at: str) -> None:
        normalized_rows = []
        for finding in findings:
            normalized_rows.append(
                (
                    str(finding.get("vhost") or "unknown"),
                    str(finding.get("stack") or "unknown"),
                    str(finding.get("ecosystem") or "unknown"),
                    str(finding.get("dependency") or "unknown"),
                    str(finding.get("version") or "unknown"),
                    str(finding.get("advisory_id") or "unknown"),
                    str(finding.get("severity") or "UNKNOWN"),
                    finding.get("fixed_version"),
                    finding.get("affected_range"),
                    finding.get("advisory_summary"),
                    str(finding.get("source_path") or "unknown"),
                    finding.get("source_line"),
                    json.dumps(list(finding.get("aliases") or []), sort_keys=True),
                    json.dumps(list(finding.get("references") or []), sort_keys=True),
                    scanned_at,
                )
            )
        with self._connect() as connection:
            connection.execute("DELETE FROM current_findings")
            if normalized_rows:
                connection.executemany(
                    """
                    INSERT INTO current_findings (
                        vhost, stack, ecosystem, dependency, version, advisory_id, severity,
                        fixed_version, affected_range, advisory_summary, source_path, source_line,
                        aliases_json, references_json, scanned_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    normalized_rows,
                )
            connection.execute(
                """
                INSERT INTO current_scan_state (singleton, scanned_at, findings_count)
                VALUES (1, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET scanned_at = excluded.scanned_at, findings_count = excluded.findings_count
                """,
                (scanned_at, len(normalized_rows)),
            )

    def export_current_findings(self) -> Dict:
        with self._connect() as connection:
            state_row = connection.execute(
                "SELECT scanned_at, findings_count FROM current_scan_state WHERE singleton = 1"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT *
                FROM current_findings
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 6
                        WHEN 'HIGH' THEN 5
                        WHEN 'MEDIUM' THEN 4
                        WHEN 'WARNING' THEN 3
                        WHEN 'LOW' THEN 2
                        WHEN 'INFO' THEN 1
                        ELSE 0
                    END DESC,
                    vhost ASC,
                    dependency ASC,
                    advisory_id ASC
                """
            ).fetchall()
        findings = []
        breakdown: Dict[str, int] = {}
        for row in rows:
            severity = row["severity"] or "UNKNOWN"
            breakdown[severity] = breakdown.get(severity, 0) + 1
            findings.append(
                {
                    "vhost": row["vhost"],
                    "stack": row["stack"],
                    "ecosystem": row["ecosystem"],
                    "dependency": row["dependency"],
                    "version": row["version"],
                    "advisory_id": row["advisory_id"],
                    "severity": severity,
                    "fixed_version": row["fixed_version"],
                    "affected_range": row["affected_range"],
                    "advisory_summary": row["advisory_summary"],
                    "source_path": row["source_path"],
                    "source_line": row["source_line"],
                    "aliases": json.loads(row["aliases_json"]),
                    "references": json.loads(row["references_json"]),
                    "scanned_at": row["scanned_at"],
                }
            )
        return {
            "scanned_at": state_row["scanned_at"] if state_row else None,
            "findings_count": state_row["findings_count"] if state_row else 0,
            "breakdown": breakdown,
            "findings": findings,
        }
