from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .advisory_logic import advisory_ids_from_fields, normalize_severity


class StateStore:
    def __init__(self, db_path: str):
        self.scan_id = uuid.uuid4().hex
        self.dry_run = False
        self.decision_ids = {}
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
                    payload_json TEXT,
                    last_reason TEXT NOT NULL DEFAULT 'new',
                    last_seen_at TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alert_history (
                    equivalence_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    last_reason TEXT NOT NULL DEFAULT 'new',
                    last_seen_at TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    PRIMARY KEY (equivalence_key, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_alert_history_equivalence_seen
                    ON alert_history (equivalence_key, last_seen_at);
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
                    audit_scope TEXT NOT NULL DEFAULT 'runtime',
                    fix_is_semver_major INTEGER NOT NULL DEFAULT 0,
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
                CREATE TABLE IF NOT EXISTS codex_analysis_cache (
                    cache_key TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notification_journal (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    dry_run INTEGER NOT NULL,
                    vhost TEXT NOT NULL,
                    logical_identity TEXT NOT NULL,
                    aliases_json TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    before_json TEXT,
                    after_json TEXT NOT NULL,
                    changed_fields_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    notify INTEGER NOT NULL,
                    decision_id INTEGER,
                    notification_id TEXT
                );
                CREATE INDEX IF NOT EXISTS notification_journal_scan ON notification_journal(scan_id, id);
                CREATE TRIGGER IF NOT EXISTS notification_journal_no_update
                    BEFORE UPDATE ON notification_journal BEGIN
                    SELECT RAISE(ABORT, 'notification_journal is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS notification_journal_no_delete
                    BEFORE DELETE ON notification_journal BEGIN
                    SELECT RAISE(ABORT, 'notification_journal is append-only'); END;
                """
            )
            self._ensure_column(connection, "alert_state", "payload_json", "TEXT")
            self._ensure_column(connection, "alert_state", "last_reason", "TEXT NOT NULL DEFAULT 'new'")
            self._ensure_column(connection, "current_findings", "audit_scope", "TEXT NOT NULL DEFAULT 'runtime'")
            self._ensure_column(connection, "current_findings", "fix_is_semver_major", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(connection, "current_findings", "fix_details_json", "TEXT NOT NULL DEFAULT '{}'")
            self._ensure_column(connection, "current_findings", "runtime_context_json", "TEXT NOT NULL DEFAULT '{}'")

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info({})".format(table)).fetchall()
        }
        if column not in columns:
            connection.execute("ALTER TABLE {} ADD COLUMN {} {}".format(table, column, column_type))

    @staticmethod
    def stable_hash(payload: Dict) -> str:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def should_alert(self, fingerprint: str, payload: Dict) -> bool:
        return self.alert_decision(fingerprint, payload)[0]

    def begin_scan(self, dry_run: bool = False) -> str:
        self.scan_id = uuid.uuid4().hex
        self.dry_run = dry_run
        self.decision_ids = {}
        return self.scan_id

    def _journal(self, connection, fingerprint, before, after, reason, notify,
                 phase="decision", decision_id=None, notification_id=None):
        changed = sorted(key for key in set(before or {}) | set(after)
                         if (before or {}).get(key) != after.get(key))
        identity = {key: after.get(key) for key in
                    ("vhost", "stack", "ecosystem", "dependency", "version", "source_path")}
        aliases = sorted(self._alert_ids(after))
        identity["advisory_ids"] = aliases
        cursor = connection.execute(
            """INSERT INTO notification_journal
            (scan_id, recorded_at, phase, dry_run, vhost, logical_identity, aliases_json,
             fingerprint, before_json, after_json, changed_fields_json, reason, notify, decision_id, notification_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (self.scan_id, datetime.now(timezone.utc).isoformat(), phase, int(self.dry_run),
             str(after.get("vhost") or ""), json.dumps(identity, sort_keys=True), json.dumps(aliases),
             fingerprint, json.dumps(before) if before is not None else None, json.dumps(after),
             json.dumps(changed), reason, int(notify), decision_id, notification_id))
        return cursor.lastrowid

    def record_forced_decision(self, fingerprint: str, payload: Dict, reason: str = "forced") -> None:
        with self._connect() as connection:
            previous = self._find_related_alert(connection, payload)
            self.decision_ids[fingerprint] = self._journal(connection, fingerprint,
                json.loads(previous.get("original_payload_json", previous["payload_json"])) if previous else None, payload, reason, True)

    def record_delivery(self, decision_ids: List[int], phase: str, notification_id: str, reason: str) -> None:
        with self._connect() as connection:
            for decision_id in set(decision_ids):
                row = connection.execute("SELECT * FROM notification_journal WHERE id = ? AND phase = 'decision'",
                                         (decision_id,)).fetchone()
                if row:
                    self._journal(connection, row["fingerprint"], json.loads(row["before_json"]) if row["before_json"] else None,
                                  json.loads(row["after_json"]), reason, True, phase, decision_id, notification_id)

    def notification_history(self, limit=100, vhost=None, advisory=None, scan_id=None) -> List[Dict]:
        if not 1 <= limit <= 10000:
            raise ValueError("history limit must be between 1 and 10000")
        clauses, values = [], []
        for field, value in (("vhost", vhost), ("scan_id", scan_id)):
            if value:
                clauses.append(field + " = ?")
                values.append(value)
        query = "SELECT * FROM notification_journal"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        results = []
        with self._connect() as connection:
            related_ids = {advisory} if advisory else set()
            if advisory:
                alias_sets = [set(json.loads(row[0])) for row in connection.execute(
                    "SELECT aliases_json FROM notification_journal")]
                while True:
                    expanded = set(related_ids)
                    for aliases in alias_sets:
                        if related_ids & aliases:
                            expanded.update(aliases)
                    if expanded == related_ids:
                        break
                    related_ids = expanded
            for row in connection.execute(query + " ORDER BY id DESC", values):
                item = dict(row)
                item["aliases"] = json.loads(item.pop("aliases_json"))
                if advisory and not related_ids.intersection(item["aliases"]):
                    continue
                for source, target in (("before_json", "before"), ("after_json", "after"),
                                       ("changed_fields_json", "changed_fields"), ("logical_identity", "logical_identity")):
                    raw = item.pop(source)
                    item[target] = json.loads(raw) if raw else None
                results.append(item)
                if len(results) >= limit:
                    break
        return results

    def alert_decision(self, fingerprint: str, payload: Dict) -> Tuple[bool, str]:
        payload = dict(payload)
        equivalence_key = self._alert_equivalence_key(payload)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_hash, payload_json, first_seen_at FROM alert_state WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            related = self._find_related_alert(connection, payload)
            previous_row = related or row
            before = json.loads((related.get("original_payload_json", related["payload_json"]) if related
                                 else row["payload_json"]) or "{}") if previous_row else None
            if related:
                previous = json.loads(related["payload_json"])
                payload["aliases"] = sorted(self._alert_ids(previous) | self._alert_ids(payload))
                if normalize_severity(payload.get("severity")) == "UNKNOWN":
                    payload["severity"] = previous.get("severity", "UNKNOWN")
            payload_hash = self.stable_hash(payload)
            payload_json = json.dumps(payload, sort_keys=True)
            if row and row["payload_hash"] == payload_hash and previous_row["payload_hash"] == payload_hash:
                self.decision_ids[fingerprint] = self._journal(connection, fingerprint,
                    before, payload, "unchanged", False)
                if self.dry_run:
                    return False, "unchanged"
                connection.execute(
                    "UPDATE alert_state SET last_seen_at = ? WHERE fingerprint = ?",
                    (now, fingerprint),
                )
                self._record_alert_history(connection, equivalence_key, fingerprint, payload_hash, payload_json, "unchanged", now)
                return False, "unchanged"
            if related:
                reason = self._related_alert_reason(related["payload_json"], payload)
                should_alert = reason != "progressive_enrichment"
                first_seen_at = related["first_seen_at"]
            elif row:
                reason = self._alert_update_reason(row["payload_json"], payload)
                should_alert = reason != "progressive_enrichment"
                first_seen_at = row["first_seen_at"]
            else:
                reason = "new"
                should_alert = True
                first_seen_at = now
            self.decision_ids[fingerprint] = self._journal(connection, fingerprint,
                before,
                payload, reason, should_alert)
            if self.dry_run:
                return should_alert, reason
            if row:
                connection.execute(
                    """
                    UPDATE alert_state
                    SET payload_hash = ?, payload_json = ?, last_reason = ?, last_seen_at = ?
                    WHERE fingerprint = ?
                    """,
                    (payload_hash, payload_json, reason, now, fingerprint),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO alert_state (fingerprint, payload_hash, payload_json, last_reason, last_seen_at, first_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (fingerprint, payload_hash, payload_json, reason, now, first_seen_at),
                )
            self._record_alert_history(connection, equivalence_key, fingerprint, payload_hash, payload_json, reason, now, first_seen_at)
            return should_alert, reason

    @staticmethod
    def _alert_update_reason(previous_json: str, payload: Dict) -> str:
        try:
            previous = json.loads(previous_json or "{}")
        except json.JSONDecodeError:
            return "changed"
        if not isinstance(previous, dict):
            return "changed"
        stable_fields = {
            "vhost",
            "stack",
            "dependency",
            "version",
            "vuln_id",
            "severity",
            "source_path",
            "ecosystem",
            "audit_scope",
            "fix_is_semver_major",
        }
        enrichment_fields = {
            "fix_details",
            "source_line",
            "fixed_version",
            "affected_range",
            "advisory_summary",
            "aliases",
            "references",
            "codex_analysis",
        }
        stable_changed = any(previous.get(field) != payload.get(field) for field in stable_fields)
        enrichment_changed = any(previous.get(field) != payload.get(field) for field in enrichment_fields)
        if enrichment_changed and not stable_changed:
            return "progressive_enrichment"
        return "changed"

    @staticmethod
    def _alert_equivalence_key(payload: Dict) -> str:
        raw = {
            "vhost": str(payload.get("vhost") or "").strip().lower(),
            "stack": str(payload.get("stack") or "").strip().lower(),
            "ecosystem": str(payload.get("ecosystem") or "").strip().lower(),
            "dependency": str(payload.get("dependency") or "").strip().lower(),
            "version": str(payload.get("version") or "").strip(),
            "source_path": str(payload.get("source_path") or "").strip(),
        }
        return hashlib.sha256(json.dumps(raw, sort_keys=True).encode("utf-8")).hexdigest()

    @staticmethod
    def _related_alert_reason(previous_json: str, payload: Dict) -> str:
        try:
            previous = json.loads(previous_json or "{}")
        except json.JSONDecodeError:
            return "changed"
        if not isinstance(previous, dict):
            return "changed"
        material_fields = {"severity", "audit_scope"}
        if any(previous.get(field) != payload.get(field) for field in material_fields):
            return "changed"
        return "progressive_enrichment"

    @staticmethod
    def _record_alert_history(
        connection: sqlite3.Connection,
        equivalence_key: str,
        fingerprint: str,
        payload_hash: str,
        payload_json: str,
        reason: str,
        last_seen_at: str,
        first_seen_at: Optional[str] = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO alert_history (
                equivalence_key, fingerprint, payload_hash, payload_json, last_reason, last_seen_at, first_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(equivalence_key, fingerprint) DO UPDATE SET
                payload_hash = excluded.payload_hash,
                payload_json = excluded.payload_json,
                last_reason = excluded.last_reason,
                last_seen_at = excluded.last_seen_at
            """,
            (equivalence_key, fingerprint, payload_hash, payload_json, reason, last_seen_at, first_seen_at or last_seen_at),
        )

    @staticmethod
    def _alert_ids(payload: Dict) -> set:
        ids = set(advisory_ids_from_fields(
            payload.get("vuln_id", ""), payload.get("aliases") or [], payload.get("references") or []
        ))
        ids.update(str(value).strip() for value in [payload.get("vuln_id")] + list(payload.get("aliases") or []) if value)
        return ids

    def _find_related_alert(self, connection: sqlite3.Connection, payload: Dict):
        if not all(payload.get(key) for key in ("vhost", "dependency", "version", "source_path", "vuln_id")):
            return None
        scope = self._alert_equivalence_key(payload)
        ids = self._alert_ids(payload)
        candidates = []
        # Read existing payloads so databases predating alias correlation need no reset.
        for row in connection.execute("SELECT * FROM alert_state ORDER BY last_seen_at DESC"):
            try:
                previous = json.loads(row["payload_json"] or "{}")
            except json.JSONDecodeError:
                continue
            if not isinstance(previous, dict):
                continue
            if self._alert_equivalence_key(previous) == scope:
                candidates.append((row, self._alert_ids(previous)))
        matched = []
        while True:
            added = [(row, aliases) for row, aliases in candidates if aliases & ids]
            if not added:
                break
            for row, aliases in added:
                ids.update(aliases)
                matched.append(row)
            added_fingerprints = {row["fingerprint"] for row, _aliases in added}
            candidates = [(row, aliases) for row, aliases in candidates if row["fingerprint"] not in added_fingerprints]
        if not matched:
            return None
        latest = dict(max(matched, key=lambda row: row["last_seen_at"]))
        latest["original_payload_json"] = latest["payload_json"]
        previous = json.loads(latest["payload_json"])
        previous["aliases"] = sorted(ids)
        latest["payload_json"] = json.dumps(previous)
        return latest

    def get_codex_analysis_cache(self, cache_key: str) -> Dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT result_json
                FROM codex_analysis_cache
                WHERE cache_key = ? AND expires_at > ?
                """,
                (cache_key, now),
            ).fetchone()
        if not row:
            return {}
        try:
            result = json.loads(row["result_json"])
        except json.JSONDecodeError:
            return {}
        return result if isinstance(result, dict) else {}

    def put_codex_analysis_cache(self, cache_key: str, result: Dict, ttl_seconds: int) -> None:
        now_dt = datetime.now(timezone.utc)
        expires_at = now_dt + timedelta(seconds=max(ttl_seconds, 0))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO codex_analysis_cache (cache_key, result_json, status, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    result_json = excluded.result_json,
                    status = excluded.status,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (
                    cache_key,
                    json.dumps(result, sort_keys=True),
                    str(result.get("analysis_status") or "unknown"),
                    now_dt.isoformat(),
                    expires_at.isoformat(),
                ),
            )

    def register_failure(self, scope: str, detail: Dict, threshold: int) -> bool:
        error_hash = self.stable_hash(detail)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT count, last_error_hash, last_alerted_hash FROM repeated_failures WHERE scope = ?",
                (scope,),
            ).fetchone()
            count = row["count"] + 1 if row and row["last_error_hash"] == error_hash else 1
            notify = count >= threshold and (not row or row["last_alerted_hash"] != error_hash)
            reason = "failure_threshold_reached" if notify else "failure_already_notified" if row and row["last_alerted_hash"] == error_hash else "below_failure_threshold"
            self.decision_ids[scope] = self._journal(connection, scope, dict(row) if row else None,
                dict(detail, failure_count=count), reason, notify)
            if self.dry_run:
                return notify
            if not row:
                last_alerted_hash = error_hash if threshold <= 1 else None
                connection.execute(
                    """
                    INSERT INTO repeated_failures (scope, count, last_error_hash, last_seen_at, last_alerted_hash)
                    VALUES (?, 1, ?, ?, NULL)
                    """,
                    (scope, error_hash, now),
                )
                if last_alerted_hash:
                    connection.execute(
                        "UPDATE repeated_failures SET last_alerted_hash = ? WHERE scope = ?",
                        (last_alerted_hash, scope),
                    )
                    return True
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
                    json.dumps(finding.get("fix_details") or {}, sort_keys=True),
                    json.dumps(finding.get("runtime_context") or {}, sort_keys=True),
                    finding.get("affected_range"),
                    finding.get("advisory_summary"),
                    str(finding.get("source_path") or "unknown"),
                    finding.get("source_line"),
                    str(finding.get("audit_scope") or "runtime"),
                    1 if finding.get("fix_is_semver_major") else 0,
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
                        fixed_version, fix_details_json, runtime_context_json, affected_range, advisory_summary, source_path, source_line,
                        audit_scope, fix_is_semver_major, aliases_json, references_json, scanned_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    "fix_details": json.loads(row["fix_details_json"] or "{}"),
                    "runtime_context": json.loads(row["runtime_context_json"] or "{}"),
                    "affected_range": row["affected_range"],
                    "advisory_summary": row["advisory_summary"],
                    "source_path": row["source_path"],
                    "source_line": row["source_line"],
                    "audit_scope": row["audit_scope"],
                    "fix_is_semver_major": bool(row["fix_is_semver_major"]),
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
