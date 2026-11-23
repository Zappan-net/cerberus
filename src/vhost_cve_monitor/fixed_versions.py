"""Package-scoped repair metadata; never infer fixes from an installed version."""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from .advisory_logic import advisory_ids_from_fields as advisory_aliases, format_fixed_versions
from .models import Dependency, Vulnerability

LOGGER = logging.getLogger(__name__)


def package_matches(name: str, ecosystem: str, dependency: Dependency) -> bool:
    if ecosystem != dependency.ecosystem:
        return False
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", str(name).lower()) == re.sub(r"[-_.]+", "-", dependency.name.lower())
    return name == dependency.name


def osv_records(item: Dict, dependency: Dependency, collected_at: str) -> List[Dict]:
    records = []
    for affected in item.get("affected", []) or []:
        package = affected.get("package", {})
        if not package_matches(package.get("name"), package.get("ecosystem"), dependency):
            continue
        for interval in affected.get("ranges", []) or []:
            # GIT fixed events are commits, not package versions.
            if interval.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            events = interval.get("events", []) or []
            versions = [e["fixed"] for e in events if isinstance(e.get("fixed"), str) and e["fixed"]]
            records.append({
                "source": "OSV", "url": "https://api.osv.dev/v1/vulns/" + item["id"],
                "collected_at": collected_at, "affected_range": interval,
                "fixed_versions": versions,
            })
    return records


def github_records(item: Dict, dependency: Dependency, collected_at: str) -> List[Dict]:
    records = []
    if item.get("withdrawn_at"):
        return records
    ecosystem = {"PyPI": "pip", "Go": "go", "crates.io": "rust", "RubyGems": "rubygems"}.get(
        dependency.ecosystem, dependency.ecosystem.lower())
    for vulnerability in item.get("vulnerabilities", []) or []:
        package = vulnerability.get("package", {})
        if package.get("ecosystem") != ecosystem or not package_matches(package.get("name"), dependency.ecosystem, dependency):
            continue
        if "first_patched_version" not in vulnerability:
            continue
        fixed = vulnerability["first_patched_version"]
        if isinstance(fixed, dict):
            fixed = fixed.get("identifier")
        if fixed is not None and not isinstance(fixed, str):
            continue
        records.append({
            "source": "GitHub", "url": "https://api.github.com/advisories/" + item["ghsa_id"],
            "collected_at": collected_at,
            "affected_range": vulnerability.get("vulnerable_version_range"),
            "fixed_versions": [fixed] if fixed else [],
            "not_published": fixed is None,
        })
    return records


def fix_description(details: Dict) -> str:
    if not details:
        return ""
    parts = ["Status: " + str(details.get("status", "unknown"))]
    for record in details.get("records", []):
        affected = record.get("affected_range")
        if isinstance(affected, dict):
            affected = json.dumps(affected, sort_keys=True)
        parts.append("{} ({}) collected {}: affected {}; patched {}".format(
            record["source"], record["url"], record["collected_at"], affected or "not supplied",
            ", ".join(record["fixed_versions"]) or "not published/unspecified"))
    if details.get("errors"):
        parts.append("Refresh: " + ", ".join(details["errors"]))
    if details.get("status") == "conflicting":
        parts.append("Sources disagree: verify the affected branch before upgrading.")
    return "; ".join(parts)


class FixedVersionResolver:
    """Bounded cache shared by vhosts and aliases, independent of installed version.

    Each record retains its affected ranges. Alternatives across release branches
    are not a claim that every greater version on every branch is safe.
    """

    def __init__(self, database) -> None:
        self.database = database
        self.github_retry_at = None
        with database._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS repair_cache (
                ecosystem TEXT NOT NULL, package TEXT NOT NULL, advisory TEXT NOT NULL,
                expires_at TEXT NOT NULL, data_json TEXT NOT NULL,
                PRIMARY KEY (ecosystem, package, advisory))""")

    def _get(self, url: str):
        request = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": "Cerberus-advisory-enrichment"})
        with urllib.request.urlopen(request, timeout=self.database.network_timeout_seconds) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
        if len(payload) > 2 * 1024 * 1024:
            raise ValueError("oversized advisory")
        return json.loads(payload.decode("utf-8"))

    def enrich(self, vulnerability: Vulnerability, dependency: Dependency, allow_network: bool = True) -> None:
        ids = advisory_aliases(vulnerability.vuln_id, vulnerability.aliases, vulnerability.references)
        ids = sorted(set(i for i in ids if re.fullmatch(r"(?:GHSA-[\w-]+|CVE-\d{4}-\d+)", i)))
        if not ids:
            return
        now = datetime.now(timezone.utc)
        cached = None
        with self.database._connect() as connection:
            for identifier in ids:
                row = connection.execute(
                    "SELECT * FROM repair_cache WHERE ecosystem=? AND package=? AND advisory=?",
                    (dependency.ecosystem, dependency.name, identifier)).fetchone()
                if row and (cached is None or row["expires_at"] > cached["expires_at"]):
                    cached = row
        previous = json.loads(cached["data_json"]) if cached else vulnerability.fix_details
        if cached and (cached["expires_at"] > now.isoformat() or not allow_network):
            self._apply(vulnerability, previous)
            return
        if not allow_network:
            return

        records = []
        errors = []
        identifier = next((i for i in ids if i.startswith("GHSA-")), ids[0])
        try:
            item = self._get("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(identifier, safe=""))
            records.extend(osv_records(item, dependency, now.isoformat()))
            ids = sorted(set(ids + advisory_aliases(item.get("id", identifier), item.get("aliases", []),
                [r.get("url", "") for r in item.get("references", [])])))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            errors.append("OSV:{}".format(getattr(exc, "code", type(exc).__name__)))

        # An incomplete OSV response must not hide the maintainer's patched version.
        if not any(r["fixed_versions"] for r in records):
            try:
                if self.github_retry_at and now < self.github_retry_at:
                    raise ValueError("rate_limit_backoff")
                ghsa = next((i for i in ids if i.startswith("GHSA-")), None)
                url = "https://api.github.com/advisories/" + ghsa if ghsa else (
                    "https://api.github.com/advisories?" + urllib.parse.urlencode({"cve_id": identifier, "per_page": 100}))
                response = self._get(url)
                for item in ([response] if ghsa else response):
                    records.extend(github_records(item, dependency, now.isoformat()))
                    ids = sorted(set(ids + [i["value"] for i in item.get("identifiers", [])]))
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
                code = getattr(exc, "code", None)
                if code in (403, 429):
                    # Bound Retry-After, including malformed values; no credential required.
                    try:
                        delay = int(exc.headers.get("Retry-After", "900"))
                    except (ValueError, TypeError, AttributeError):
                        delay = 900
                    self.github_retry_at = now + timedelta(seconds=max(60, min(delay, 3600)))
                errors.append("GitHub:{}".format(code or type(exc).__name__))

        # A newly discovered CVE/GHSA alias may already have confirmed cached data.
        with self.database._connect() as connection:
            for alias in ids:
                row = connection.execute(
                    "SELECT data_json FROM repair_cache WHERE ecosystem=? AND package=? AND advisory=?",
                    (dependency.ecosystem, dependency.name, alias)).fetchone()
                if row:
                    for record in json.loads(row["data_json"]).get("records", []):
                        if record not in previous.setdefault("records", []):
                            previous["records"].append(record)
        # Retain previously confirmed evidence when a source is temporarily missing.
        refreshed_sources = {r["source"] for r in records if r["fixed_versions"]}
        for record in previous.get("records", []):
            if record["fixed_versions"] and record["source"] not in refreshed_sources and record not in records:
                records.append(record)
        by_source = {}
        for record in records:
            if record["fixed_versions"]:
                by_source.setdefault(record["source"], set()).update(record["fixed_versions"])
        conflict = len({tuple(sorted(v)) for v in by_source.values()}) > 1
        status = "conflicting" if conflict else ("confirmed" if by_source else (
            "not_published" if any(r.get("not_published") for r in records) else (
                "retrieval_failed" if errors else "incomplete")))
        details = {"status": status, "records": records, "errors": errors, "aliases": ids,
                   "checked_at": now.isoformat()}
        ttl = 86400 if status == "confirmed" and not errors else 900
        with self.database._connect() as connection:
            for alias in ids:
                connection.execute("""INSERT INTO repair_cache VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ecosystem, package, advisory) DO UPDATE SET
                    expires_at=excluded.expires_at, data_json=excluded.data_json""",
                    (dependency.ecosystem, dependency.name, alias,
                     (now + timedelta(seconds=ttl)).isoformat(), json.dumps(details, sort_keys=True)))
        if errors:
            LOGGER.debug("Repair metadata %s: %s", identifier, ", ".join(errors))
        self._apply(vulnerability, details)

    @staticmethod
    def _apply(vulnerability: Vulnerability, details: Dict) -> None:
        # A short-lived negative cache must not replace fresher evidence already
        # supplied by this scan's OSV package query.
        incoming = vulnerability.fix_details.get("records", [])
        if not any(r["fixed_versions"] for r in details.get("records", [])) and any(
            r["fixed_versions"] for r in incoming
        ):
            details = dict(details, status="confirmed", records=list(details.get("records", [])) + incoming)
        vulnerability.fix_details = details
        for alias in details.get("aliases", []):
            if alias != vulnerability.vuln_id and alias not in vulnerability.aliases:
                vulnerability.aliases.append(alias)
        versions = [v for r in details.get("records", []) for v in r["fixed_versions"]]
        if versions:
            # Contradictions stay explicit instead of presenting an unsafe union as advice.
            vulnerability.fixed_version = (None if
                details["status"] == "conflicting" else format_fixed_versions(versions))
