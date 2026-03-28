from __future__ import annotations

import json
import logging
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from .models import Dependency, Vulnerability

LOGGER = logging.getLogger(__name__)


class CVEDatabase:
    def __init__(self, db_path: str, ttl_hours: int = 24, network_timeout_seconds: int = 30):
        self.db_path = Path(db_path)
        self.ttl_hours = ttl_hours
        self.network_timeout_seconds = network_timeout_seconds
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
                CREATE TABLE IF NOT EXISTS advisories (
                    vuln_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    aliases_json TEXT NOT NULL,
                    summary TEXT,
                    details TEXT,
                    published TEXT,
                    modified TEXT,
                    severity TEXT,
                    references_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS package_findings (
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vuln_id TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    PRIMARY KEY (ecosystem, package_name, version, vuln_id)
                );
                CREATE TABLE IF NOT EXISTS package_queries (
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    PRIMARY KEY (ecosystem, package_name, version)
                );
                """
            )

    def ensure_fresh(self, dependency: Dependency, allow_network: bool = True) -> List[Vulnerability]:
        cached = self.lookup(dependency)
        if self._is_fresh(dependency):
            LOGGER.debug(
                "Using fresh cached advisories for %s %s (%s)",
                dependency.name,
                dependency.version,
                dependency.ecosystem,
            )
            return cached
        if not allow_network:
            LOGGER.info(
                "Offline mode: using cached advisories for %s %s (%s)",
                dependency.name,
                dependency.version,
                dependency.ecosystem,
            )
            return cached
        try:
            LOGGER.info(
                "Refreshing advisories from OSV for %s %s (%s)",
                dependency.name,
                dependency.version,
                dependency.ecosystem,
            )
            advisories = self._fetch_osv(dependency)
            self._store_query_result(dependency, advisories)
            LOGGER.info(
                "Fetched %s advisories for %s %s (%s)",
                len(advisories),
                dependency.name,
                dependency.version,
                dependency.ecosystem,
            )
            return advisories
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Unable to refresh OSV advisories for %s: %s", dependency.name, exc)
            return cached

    def _is_fresh(self, dependency: Dependency) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT fetched_at
                FROM package_queries
                WHERE ecosystem = ? AND package_name = ? AND version = ?
                """,
                (dependency.ecosystem, dependency.name, dependency.version),
            ).fetchone()
        if not row:
            return False
        fetched_at = datetime.fromisoformat(row["fetched_at"])
        return fetched_at >= datetime.now(timezone.utc) - timedelta(hours=self.ttl_hours)

    def lookup(self, dependency: Dependency) -> List[Vulnerability]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT a.*
                FROM advisories a
                JOIN package_findings pf ON pf.vuln_id = a.vuln_id
                WHERE pf.ecosystem = ? AND pf.package_name = ? AND pf.version = ?
                ORDER BY a.severity DESC, a.vuln_id ASC
                """,
                (dependency.ecosystem, dependency.name, dependency.version),
            ).fetchall()
        vulnerabilities = []
        for row in rows:
            vulnerabilities.append(
                Vulnerability(
                    vuln_id=row["vuln_id"],
                    source=row["source"],
                    severity=row["severity"] or "UNKNOWN",
                    summary=row["summary"] or "",
                    details=row["details"] or "",
                    published=row["published"],
                    modified=row["modified"],
                    package_name=dependency.name,
                    ecosystem=dependency.ecosystem,
                    affected_version=dependency.version,
                    references=json.loads(row["references_json"]),
                    aliases=json.loads(row["aliases_json"]),
                )
            )
        return vulnerabilities

    def refresh_known_packages(self, allow_network: bool = True) -> int:
        if not allow_network:
            return 0
        refreshed = 0
        with self._connect() as connection:
            rows = connection.execute("SELECT ecosystem, package_name, version FROM package_queries").fetchall()
        LOGGER.info("Refreshing CVE cache for %s known package/version tuples", len(rows))
        for row in rows:
            dependency = Dependency(
                ecosystem=row["ecosystem"],
                name=row["package_name"],
                version=row["version"],
                source="cache",
            )
            try:
                advisories = self._fetch_osv(dependency)
                self._store_query_result(dependency, advisories)
                refreshed += 1
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("Refresh failed for %s %s: %s", dependency.name, dependency.version, exc)
        return refreshed

    def _fetch_osv(self, dependency: Dependency) -> List[Vulnerability]:
        payload = json.dumps(
            {
                "package": {
                    "name": dependency.name,
                    "ecosystem": dependency.ecosystem,
                },
                "version": dependency.version,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url="https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        LOGGER.debug("POST https://api.osv.dev/v1/query for %s %s", dependency.name, dependency.version)
        with urllib.request.urlopen(request, timeout=self.network_timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
        vulnerabilities = []
        for item in data.get("vulns", []):
            severity = "UNKNOWN"
            for affected in item.get("affected", []):
                affected_package = affected.get("package", {})
                if (
                    affected_package.get("name") == dependency.name
                    and affected_package.get("ecosystem") == dependency.ecosystem
                ):
                    severity = (
                        affected.get("ecosystem_specific", {}).get("severity")
                        or severity
                    )
            references = [entry.get("url", "") for entry in item.get("references", []) if entry.get("url")]
            vulnerabilities.append(
                Vulnerability(
                    vuln_id=item["id"],
                    source="OSV",
                    severity=severity,
                    summary=item.get("summary", ""),
                    details=item.get("details", ""),
                    published=item.get("published"),
                    modified=item.get("modified"),
                    package_name=dependency.name,
                    ecosystem=dependency.ecosystem,
                    affected_version=dependency.version,
                    references=references,
                    aliases=item.get("aliases", []),
                )
            )
        return vulnerabilities

    def _store_query_result(self, dependency: Dependency, advisories: List[Vulnerability]) -> None:
        fetched_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO package_queries (ecosystem, package_name, version, fetched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ecosystem, package_name, version)
                DO UPDATE SET fetched_at = excluded.fetched_at
                """,
                (dependency.ecosystem, dependency.name, dependency.version, fetched_at),
            )
            connection.execute(
                """
                DELETE FROM package_findings
                WHERE ecosystem = ? AND package_name = ? AND version = ?
                """,
                (dependency.ecosystem, dependency.name, dependency.version),
            )
            for advisory in advisories:
                connection.execute(
                    """
                    INSERT INTO advisories (
                        vuln_id, source, aliases_json, summary, details, published,
                        modified, severity, references_json, raw_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(vuln_id) DO UPDATE SET
                        source = excluded.source,
                        aliases_json = excluded.aliases_json,
                        summary = excluded.summary,
                        details = excluded.details,
                        published = excluded.published,
                        modified = excluded.modified,
                        severity = excluded.severity,
                        references_json = excluded.references_json,
                        raw_json = excluded.raw_json
                    """,
                    (
                        advisory.vuln_id,
                        advisory.source,
                        json.dumps(advisory.aliases),
                        advisory.summary,
                        advisory.details,
                        advisory.published,
                        advisory.modified,
                        advisory.severity,
                        json.dumps(advisory.references),
                        json.dumps(advisory.__dict__),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO package_findings (ecosystem, package_name, version, vuln_id, fetched_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        dependency.ecosystem,
                        dependency.name,
                        dependency.version,
                        advisory.vuln_id,
                        fetched_at,
                    ),
                )
