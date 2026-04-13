from __future__ import annotations

import logging
import re
import socket
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

from .advisory_logic import (
    SEVERITY_ORDER,
    build_recommendation,
    canonical_advisory_id,
    merge_fixed_versions,
    normalize_severity,
    strongest_severity,
)
from .audits import scan_stack
from .cve_db import CVEDatabase
from .models import AuditIssue, NotificationEvent, ScanFailure, VhostScanResult
from .nginx_parser import load_vhosts
from .notify import Mailer
from .notify import NotificationDeliveryError
from .stack_detection import detect_stacks
from .state_store import StateStore

LOGGER = logging.getLogger(__name__)
BUG_REPORT_URL = "https://github.com/Zappan-net/cerberus/issues"


def _clean_text(value: str) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = re.sub(r"\s*\.\s*", ".", text)
    return text


@dataclass
class FindingProjection:
    vhost: str
    stack: str
    source_line: Optional[int]


@dataclass
class NormalizedFinding:
    advisory_id: str
    dependency: str
    version: str
    source_path: str
    ecosystem: str
    severity: str
    summary: str
    details: str
    fixed_version: Optional[str]
    affected_range: Optional[str]
    aliases: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    projections: List[FindingProjection] = field(default_factory=list)


def _is_allowed(name: str, path: Optional[str], config: Dict) -> bool:
    filters = config["filters"]
    allowlist = filters.get("vhost_allowlist") or []
    blocklist = filters.get("vhost_blocklist") or []
    path_allowlist = filters.get("path_allowlist") or []
    path_blocklist = filters.get("path_blocklist") or []
    if allowlist and not any(fnmatch(name, pattern) for pattern in allowlist):
        return False
    if any(fnmatch(name, pattern) for pattern in blocklist):
        return False
    if path:
        if path_allowlist and not any(fnmatch(path, pattern) for pattern in path_allowlist):
            return False
        if any(fnmatch(path, pattern) for pattern in path_blocklist):
            return False
    return True


class CerberusScanner:
    def __init__(self, config: Dict, dry_run: bool = False, allow_network: bool = True):
        self.config = config
        self.dry_run = dry_run
        self.allow_network = allow_network
        self.timeout = int(config["scanner"]["command_timeout_seconds"])
        self.failure_threshold = int(config["scanner"]["repeated_failure_threshold"])
        self.max_emails_per_run = int(config["notifications"].get("max_emails_per_run", 20))
        self.summary_only = bool(config["notifications"].get("summary_only", True))
        self.cve_db = CVEDatabase(
            db_path=config["state"]["database_path"],
            ttl_hours=int(config["state"]["cve_cache_ttl_hours"]),
            network_timeout_seconds=int(config["scanner"]["network_timeout_seconds"]),
        )
        self.state = StateStore(config["state"]["database_path"])
        self.mailer = Mailer(config, dry_run=dry_run)

    def refresh_cve_cache(self) -> int:
        LOGGER.info("Starting CVE cache refresh")
        return self.cve_db.refresh_known_packages(allow_network=self.allow_network)

    def export_findings(self) -> Dict:
        exported = self.state.export_current_findings()
        if exported.get("scanned_at") is None:
            LOGGER.info("No materialized findings snapshot found, running a collection pass for export")
            now, _results, issue_occurrences, _failures = self._collect_scan_data()
            self.state.replace_current_findings(
                self._current_findings_snapshot(issue_occurrences),
                scanned_at=now.isoformat(),
            )
            exported = self.state.export_current_findings()
        return exported

    def scan_once(self) -> Tuple[List[VhostScanResult], List[NotificationEvent]]:
        LOGGER.info("Starting scan cycle")
        now, results, issue_occurrences, failure_notifications = self._collect_scan_data()
        self.state.replace_current_findings(self._current_findings_snapshot(issue_occurrences), scanned_at=now.isoformat())
        notifications = self._build_issue_notifications(issue_occurrences) + failure_notifications
        LOGGER.info("Prepared %s notifications", len(notifications))
        for notification in self._prepare_notifications_for_delivery(notifications):
            LOGGER.info("Sending %s notification: %s", notification.category, notification.subject)
            self.mailer.send(notification)
        LOGGER.info("Scan cycle completed")
        return results, notifications

    def _collect_scan_data(self) -> Tuple[datetime, List[VhostScanResult], List[Dict], List[NotificationEvent]]:
        now = datetime.now(timezone.utc)
        vhosts = load_vhosts(self.config)
        LOGGER.info("Loaded %s nginx vhosts", len(vhosts))
        results: List[VhostScanResult] = []
        issue_occurrences: List[Dict] = []
        failure_notifications: List[NotificationEvent] = []
        for vhost in vhosts:
            if not _is_allowed(vhost.primary_server_name, vhost.primary_root, self.config):
                LOGGER.info("Skipping filtered vhost %s", vhost.primary_server_name)
                continue
            LOGGER.info(
                "Inspecting vhost %s (root=%s, proxies=%s)",
                vhost.primary_server_name,
                vhost.primary_root or "none",
                len(vhost.proxy_passes) + len(vhost.fastcgi_passes) + len(vhost.uwsgi_passes),
            )
            result = VhostScanResult(vhost=vhost)
            stacks = detect_stacks(vhost, self.config)
            LOGGER.info("Detected %s stack candidates for %s", len(stacks), vhost.primary_server_name)
            if not stacks:
                result.failures.append(ScanFailure(scope=vhost.primary_server_name, reason="stack_not_detected"))
            for stack in stacks:
                LOGGER.info(
                    "Processing stack %s for vhost %s at %s",
                    stack.stack_name,
                    vhost.primary_server_name,
                    stack.root_path or "unknown",
                )
                stack_result = scan_stack(
                    stack=stack,
                    cve_db=self.cve_db,
                    timeout=self.timeout,
                    allow_network=self.allow_network,
                )
                LOGGER.info(
                    "Stack %s finished for %s: %s deps, %s issues, %s failures",
                    stack.stack_name,
                    vhost.primary_server_name,
                    len(stack_result.dependencies),
                    len(stack_result.issues),
                    len(stack_result.failures),
                )
                result.stacks.append(stack_result)
                for issue in stack_result.issues:
                    issue_occurrences.append(
                        {
                            "vhost": vhost.primary_server_name,
                            "stack": stack_result.stack.stack_name,
                            "issue": issue,
                        }
                    )
                failure_notifications.extend(
                    self._build_failure_notifications(vhost.primary_server_name, stack_result.failures)
                )
            failure_notifications.extend(self._build_failure_notifications(vhost.primary_server_name, result.failures))
            results.append(result)
        return now, results, issue_occurrences, failure_notifications

    def _prepare_notifications_for_delivery(self, notifications: List[NotificationEvent]) -> List[NotificationEvent]:
        direct_notifications = [item for item in notifications if item.category == "internal-error"]
        digest_candidates = [item for item in notifications if item.category != "internal-error"]
        if not digest_candidates:
            return self._sort_notifications(direct_notifications)
        if self.summary_only:
            return self._sort_notifications(direct_notifications) + [
                self._build_digest_notification(self._sort_notifications(digest_candidates), subject_all=True)
            ]
        if len(digest_candidates) <= self.max_emails_per_run:
            return self._sort_notifications(direct_notifications + digest_candidates)
        sorted_notifications = self._sort_notifications(digest_candidates)
        capped_notifications = sorted_notifications[: self.max_emails_per_run]
        overflow = sorted_notifications[self.max_emails_per_run :]
        delivery_batch = self._sort_notifications(direct_notifications + capped_notifications)
        delivery_batch.append(self._build_digest_notification(overflow))
        LOGGER.warning(
            "Notification count %s exceeds per-run limit %s, sending %s direct alerts and one digest",
            len(digest_candidates),
            self.max_emails_per_run,
            len(delivery_batch) - len(direct_notifications) - 1,
        )
        return delivery_batch

    def _sort_notifications(self, notifications: List[NotificationEvent]) -> List[NotificationEvent]:
        return sorted(
            notifications,
            key=lambda item: (
                -SEVERITY_ORDER.get(str(item.metadata.get("severity", "UNKNOWN")).upper(), 0),
                item.subject,
            ),
        )

    def _build_digest_notification(self, events: List[NotificationEvent], subject_all: bool = False) -> NotificationEvent:
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        digest_items = self._digest_items(events)
        highest = self._digest_highest_severity(digest_items)
        severity_groups = self._group_digest_items_by_severity(digest_items)
        breakdown = self._digest_breakdown(severity_groups)
        lines = [
            f"Hostname: {hostname}",
            f"Date: {now.isoformat()}",
            f"Findings: {len(digest_items)}",
            f"Highest severity: {highest}",
            f"Breakdown: {breakdown}",
            "Summary: new or changed findings were grouped to avoid flooding the destination mailbox.",
        ]
        for severity, items in severity_groups:
            lines.extend(
                [
                    "",
                    "{} ({})".format(severity, len(items)),
                    "Recommendation: {}".format(self._digest_block_recommendation(severity, items)),
                ]
            )
            for item in items:
                source_suffix = ""
                if item["source_path"] and item["source_line"]:
                    source_suffix = " [{}:{}]".format(item["source_path"], item["source_line"])
                elif item["source_path"]:
                    source_suffix = " [{}]".format(item["source_path"])
                fixed_suffix = ""
                if item["fixed_version"]:
                    fixed_suffix = " -> fixed in {}".format(item["fixed_version"])
                lines.append(
                    "- {} | {}{}{}".format(
                        item["vhost"],
                        self._digest_stack_context(item),
                        " | {}".format(source_suffix.strip()) if source_suffix else "",
                        "",
                    )
                )
                lines.append(
                    "  [{}] {} {}{} | {}".format(
                        severity,
                        item["dependency"],
                        item["version"],
                        fixed_suffix,
                        item["vuln_id"],
                    )
                )
                if item.get("advisory_summary"):
                    lines.append("  Summary: {}".format(item["advisory_summary"]))
                if item.get("affected_range"):
                    lines.append("  Affected range: {}".format(item["affected_range"]))
        subject = "[Cerberus][{}][{}] {} alerts".format(highest, hostname, len(digest_items))
        return NotificationEvent(
            category="digest",
            fingerprint="digest:{}:{}".format(now.date().isoformat(), len(digest_items)),
            subject=subject,
            body="\n".join(lines),
            created_at=now,
            metadata={"severity": highest, "events": len(digest_items), "digest_items": digest_items, "hostname": hostname},
        )

    def _current_findings_snapshot(self, occurrences: List[Dict]) -> List[Dict]:
        snapshot = []
        for finding in self._normalize_findings(occurrences):
            severity = normalize_severity(finding.severity)
            for projection in finding.projections:
                snapshot.append(
                    {
                        "vhost": projection.vhost,
                        "stack": projection.stack,
                        "ecosystem": finding.ecosystem,
                        "dependency": finding.dependency,
                        "version": finding.version,
                        "advisory_id": finding.advisory_id,
                        "severity": severity,
                        "fixed_version": finding.fixed_version,
                        "affected_range": finding.affected_range,
                        "advisory_summary": finding.summary or None,
                        "source_path": finding.source_path,
                        "source_line": projection.source_line,
                        "aliases": list(finding.aliases),
                        "references": list(finding.references),
                    }
                )
        return snapshot

    def _digest_items(self, events: List[NotificationEvent]) -> List[Dict[str, object]]:
        items = {}
        for event in events:
            metadata = event.metadata
            item = {
                "vhost": _clean_text(metadata.get("vhost") or metadata.get("scope") or "unknown"),
                "dependency": _clean_text(metadata.get("dependency", "scan-pipeline")),
                "version": _clean_text(metadata.get("version", "unknown")),
                "vuln_id": _clean_text(metadata.get("vuln_id", metadata.get("reason", "n/a"))),
                "severity": _clean_text(metadata.get("severity", "UNKNOWN")).upper(),
                "fixed_version": _clean_text(metadata.get("fixed_version", "")) or None,
                "source_path": metadata.get("source_path"),
                "source_line": metadata.get("source_line"),
                "category": event.category,
                "ecosystem": _clean_text(metadata.get("ecosystem", "")) or None,
                "stack": _clean_text(metadata.get("stack", "")) or None,
                "advisory_summary": _clean_text(metadata.get("advisory_summary", "")) or None,
                "affected_range": _clean_text(metadata.get("affected_range", "")) or None,
            }
            key = (
                item["vhost"],
                item["dependency"],
                item["version"],
                item["vuln_id"],
                item["fixed_version"],
                item["source_path"],
                item["source_line"],
            )
            if key in items:
                items[key]["severity"] = strongest_severity(str(items[key]["severity"]), str(item["severity"]))
                if not items[key]["fixed_version"] and item["fixed_version"]:
                    items[key]["fixed_version"] = item["fixed_version"]
                if not items[key]["advisory_summary"] and item["advisory_summary"]:
                    items[key]["advisory_summary"] = item["advisory_summary"]
                if not items[key]["affected_range"] and item["affected_range"]:
                    items[key]["affected_range"] = item["affected_range"]
                continue
            items[key] = item
        return sorted(
            items.values(),
            key=lambda item: (
                -SEVERITY_ORDER.get(str(item["severity"]).upper(), -1),
                str(item["vhost"]),
                str(item["dependency"]),
                str(item["version"]),
                str(item["vuln_id"]),
            ),
        )

    def _digest_highest_severity(self, digest_items: List[Dict[str, object]]) -> str:
        highest = "UNKNOWN"
        for item in digest_items:
            highest = strongest_severity(highest, str(item.get("severity", "UNKNOWN")).upper())
        return highest

    def _group_digest_items_by_severity(self, digest_items: List[Dict[str, object]]) -> List[tuple[str, List[Dict[str, object]]]]:
        grouped = {}
        for item in digest_items:
            severity = str(item.get("severity", "UNKNOWN")).upper()
            grouped.setdefault(severity, []).append(item)
        ordered = []
        for severity, items in grouped.items():
            ordered.append(
                (
                    severity,
                    sorted(
                        items,
                        key=lambda item: (
                            str(item["vhost"]),
                            str(item["dependency"]),
                            str(item["version"]),
                            str(item["vuln_id"]),
                        ),
                    ),
                )
            )
        return sorted(ordered, key=lambda entry: -SEVERITY_ORDER.get(entry[0], -1))

    def _digest_breakdown(self, severity_groups: List[tuple[str, List[Dict[str, object]]]]) -> str:
        return ", ".join("{} {}".format(len(items), severity) for severity, items in severity_groups) or "0 UNKNOWN"

    def _digest_block_recommendation(self, severity: str, items: List[Dict[str, object]]) -> str:
        categories = {str(item.get("category") or "") for item in items}
        ecosystems = {
            str(item.get("ecosystem") or "").lower()
            for item in items
            if str(item.get("ecosystem") or "").strip()
        }
        if categories == {"scan-failure"}:
            return (
                "stabilize the failing audit commands or project trees in this block first, then rerun the scan "
                "to confirm the failures are gone."
            )
        if categories == {"internal-error"}:
            return (
                "treat these as Cerberus execution failures: inspect the local logs first and report a reproducible "
                "bug if the failure persists."
            )
        if len(ecosystems) == 1:
            ecosystem = next(iter(ecosystems))
            if ecosystem == "npm":
                if severity in ("CRITICAL", "HIGH"):
                    return (
                        "prioritize these npm dependency upgrades first, apply the fixed versions shown below, "
                        "review `package-lock.json` drift carefully, and verify runtime usage before deployment."
                    )
                return (
                    "schedule these npm dependency upgrades, rebuild `package-lock.json`, and validate runtime usage "
                    "before deployment."
                )
            if ecosystem == "pypi":
                if severity in ("CRITICAL", "HIGH"):
                    return (
                        "prioritize these Python package updates first, refresh requirements or lockfiles, rerun "
                        "`pip-audit`, and confirm the affected imports are used at runtime."
                    )
                return (
                    "schedule these Python package updates, refresh requirements or lockfiles, rerun `pip-audit`, "
                    "and validate runtime usage before deployment."
                )
            if ecosystem == "packagist":
                if severity in ("CRITICAL", "HIGH"):
                    return (
                        "prioritize these Composer updates first, review `composer.lock` changes carefully, and "
                        "confirm the affected packages are used in the deployed application."
                    )
                return (
                    "schedule these Composer dependency updates, review `composer.lock`, and validate application "
                    "behavior before deployment."
                )
            if ecosystem == "go":
                return (
                    "upgrade the Go modules in this block to the fixed versions below, refresh the module graph, "
                    "and confirm the affected packages are part of the deployed binary."
                )
            if ecosystem == "crates.io":
                return (
                    "update the Rust crates in this block to the fixed versions below, refresh `Cargo.lock`, and "
                    "verify the affected crates are part of the production build."
                )
        if severity in ("CRITICAL", "HIGH"):
            return (
                "prioritize the findings in this block first, upgrade each affected component to the listed fixed "
                "version, rebuild the relevant dependency state, and verify runtime usage before deployment."
            )
        return (
            "schedule the findings in this block for upgrade, apply the listed fixed versions, rebuild the relevant "
            "dependency state, and validate runtime usage before deployment."
        )

    def _digest_stack_context(self, item: Dict[str, object]) -> str:
        stack = str(item.get("stack") or "").strip()
        ecosystem = str(item.get("ecosystem") or "").strip()
        if stack and ecosystem:
            return "{} / {}".format(stack, ecosystem)
        if ecosystem:
            return ecosystem
        if stack:
            return stack
        return "unknown stack"

    def _normalize_findings(self, occurrences: List[Dict]) -> List[NormalizedFinding]:
        normalized = {}
        for occurrence in occurrences:
            issue = occurrence["issue"]
            canonical_id = canonical_advisory_id(issue.vulnerability.vuln_id, issue.vulnerability.aliases)
            key = (
                canonical_id,
                issue.dependency.name.lower(),
                issue.dependency.version,
                issue.dependency.source,
            )
            if key not in normalized:
                normalized[key] = NormalizedFinding(
                    advisory_id=canonical_id,
                    dependency=issue.dependency.name,
                    version=issue.dependency.version,
                    source_path=issue.dependency.source,
                    ecosystem=issue.dependency.ecosystem,
                    severity=normalize_severity(issue.vulnerability.severity),
                    summary=issue.vulnerability.summary,
                    details=issue.vulnerability.details,
                    fixed_version=issue.vulnerability.fixed_version,
                    affected_range=issue.vulnerability.affected_range,
                    aliases=list(issue.vulnerability.aliases),
                    references=list(issue.vulnerability.references),
                    projections=[
                        FindingProjection(
                            vhost=occurrence["vhost"],
                            stack=occurrence["stack"],
                            source_line=issue.dependency.source_line,
                        )
                    ],
                )
                continue
            current = normalized[key]
            current.severity = strongest_severity(current.severity, issue.vulnerability.severity)
            if len(issue.vulnerability.summary or "") > len(current.summary or ""):
                current.summary = issue.vulnerability.summary
            if len(issue.vulnerability.details or "") > len(current.details or ""):
                current.details = issue.vulnerability.details
            current.fixed_version = merge_fixed_versions(current.fixed_version, issue.vulnerability.fixed_version)
            current.affected_range = current.affected_range or issue.vulnerability.affected_range
            for alias in issue.vulnerability.aliases:
                if alias and alias not in current.aliases:
                    current.aliases.append(alias)
            for reference in issue.vulnerability.references:
                if reference and reference not in current.references:
                    current.references.append(reference)
            projection = FindingProjection(
                vhost=occurrence["vhost"],
                stack=occurrence["stack"],
                source_line=issue.dependency.source_line,
            )
            if not any(
                existing.vhost == projection.vhost and existing.stack == projection.stack and existing.source_line == projection.source_line
                for existing in current.projections
            ):
                current.projections.append(projection)
        return sorted(
            normalized.values(),
            key=lambda item: (
                -SEVERITY_ORDER.get(item.severity, -1),
                item.advisory_id,
                item.dependency.lower(),
                item.version,
                item.source_path,
            ),
        )

    def _build_issue_notifications(self, occurrences: List[Dict]) -> List[NotificationEvent]:
        notifications = []
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        for finding in self._normalize_findings(occurrences):
            recommendation = build_recommendation(
                ecosystem=finding.ecosystem,
                stack=finding.projections[0].stack,
                package_name=finding.dependency,
                installed_version=finding.version,
                fixed_version=finding.fixed_version,
                affected_range=finding.affected_range,
            )
            for projection in finding.projections:
                severity = normalize_severity(finding.severity)
                payload = {
                    "vhost": projection.vhost,
                    "stack": projection.stack,
                    "dependency": finding.dependency,
                    "version": finding.version,
                    "vuln_id": finding.advisory_id,
                    "severity": severity,
                    "fixed_version": finding.fixed_version,
                    "affected_range": finding.affected_range,
                    "advisory_summary": finding.summary,
                    "source_path": finding.source_path,
                    "source_line": projection.source_line,
                    "ecosystem": finding.ecosystem,
                }
                fingerprint = "issue:{}:{}:{}:{}:{}:{}".format(
                    projection.vhost,
                    projection.stack,
                    finding.dependency,
                    finding.version,
                    finding.advisory_id,
                    finding.source_path,
                )
                if not self.state.should_alert(fingerprint, payload):
                    continue
                fixed_line = (
                    "Fixed version: {}".format(finding.fixed_version)
                    if finding.fixed_version
                    else "Fixed version: unknown"
                )
                affected_line = (
                    "Affected range: {}".format(finding.affected_range)
                    if finding.affected_range
                    else None
                )
                body_lines = [
                    f"Hostname: {hostname}",
                    f"Date: {now.isoformat()}",
                    f"Vhost: {projection.vhost}",
                    f"Stack: {projection.stack}",
                    f"Dependency: {finding.dependency}",
                    f"Detected version: {finding.version}",
                    fixed_line,
                    "Source file: {}".format(finding.source_path),
                    "Source line: {}".format(projection.source_line if projection.source_line else "unknown"),
                    f"CVE / Advisory: {finding.advisory_id}",
                    f"Severity: {severity}",
                    "Summary: {}".format(finding.summary or "No summary provided by upstream advisory sources."),
                    "Recommendation: {}".format(recommendation),
                ]
                if affected_line:
                    body_lines.insert(7, affected_line)
                notifications.append(
                    NotificationEvent(
                        category="vulnerability",
                        fingerprint=fingerprint,
                        subject="[Cerberus][{}][{}] {} {} {}".format(
                            severity,
                            hostname,
                            _clean_text(projection.vhost),
                            _clean_text(finding.dependency),
                            _clean_text(finding.advisory_id),
                        ),
                        body="\n".join(body_lines),
                        created_at=now,
                        metadata=payload,
                    )
                )
        return notifications

    def _build_failure_notifications(self, scope: str, failures: List[ScanFailure]) -> List[NotificationEvent]:
        notifications = []
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        for failure in failures:
            severity = normalize_severity("warning", category="scan-failure")
            payload = {
                "scope": scope,
                "reason": failure.reason,
                "detail": failure.detail,
                "severity": severity,
            }
            repeated = self.state.register_failure(
                scope=f"{scope}:{failure.scope}:{failure.reason}",
                detail=payload,
                threshold=self.failure_threshold,
            )
            if not repeated:
                continue
            body = "\n".join(
                [
                    f"Hostname: {hostname}",
                    f"Date: {now.isoformat()}",
                    f"Vhost: {scope}",
                    f"Stack: {failure.scope}",
                    f"Component: scan pipeline",
                    f"Detected version: unknown",
                    f"CVE / Advisory: n/a",
                    f"Severity: {severity}",
                    f"Summary: repeated scan failure",
                    f"Recommendation: inspect logs and fix the audit environment or the broken project tree.",
                    f"Detail: {failure.reason} {failure.detail or ''}".strip(),
                ]
            )
            notifications.append(
                NotificationEvent(
                    category="scan-failure",
                    fingerprint=f"failure:{scope}:{failure.scope}:{failure.reason}",
                    subject=f"[Cerberus][{severity}][{hostname}] {scope} repeated scan failure: {failure.reason}",
                    body=body,
                    created_at=now,
                    metadata=payload,
                )
            )
        return notifications

    def report_internal_error(self, operation: str, error: BaseException) -> Optional[NotificationEvent]:
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        severity = normalize_severity("HIGH")
        trace = traceback.format_exc()
        if trace.strip() == "NoneType: None":
            trace = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        trace = trace.strip()
        payload = {
            "scope": operation,
            "reason": type(error).__name__,
            "detail": str(error),
            "severity": severity,
            "traceback": trace,
        }
        fingerprint = "internal-error:{}".format(operation)
        if not self.state.should_alert(fingerprint, payload):
            return None
        body_lines = [
            "Hostname: {}".format(hostname),
            "Date: {}".format(now.isoformat()),
            "Component: cerberus-daemon",
            "Operation: {}".format(operation),
            "Error type: {}".format(type(error).__name__),
            "Detail: {}".format(str(error) or "no exception message"),
            "Severity: {}".format(severity),
            "Summary: Cerberus hit an internal execution error.",
            "Recommendation: inspect the local logs and, if the failure is reproducible, report it on {}.".format(
                BUG_REPORT_URL
            ),
        ]
        if trace:
            body_lines.extend(["", "Traceback:", trace])
        event = NotificationEvent(
            category="internal-error",
            fingerprint=fingerprint,
            subject="[Cerberus][{}][{}] internal error during {}".format(severity, hostname, operation),
            body="\n".join(body_lines),
            created_at=now,
            metadata=payload,
        )
        for notification in self._prepare_notifications_for_delivery([event]):
            LOGGER.info("Sending %s notification: %s", notification.category, notification.subject)
            try:
                self.mailer.send(notification)
            except NotificationDeliveryError as delivery_error:
                LOGGER.error(
                    "Unable to send internal-error notification during %s: %s",
                    operation,
                    delivery_error,
                )
                return event
        return event

    def send_test_mail(self, severity: str = "INFO", category: str = "test") -> NotificationEvent:
        return self.send_custom_test_mail(severity=severity, category=category)

    def send_custom_test_mail(
        self,
        severity: str = "INFO",
        category: str = "test",
        stack: Optional[str] = None,
        ecosystem: Optional[str] = None,
        package_name: Optional[str] = None,
        installed_version: Optional[str] = None,
        fixed_version: Optional[str] = None,
        advisory_id: Optional[str] = None,
        vhost: Optional[str] = None,
        source_file: Optional[str] = None,
        source_line: Optional[int] = None,
    ) -> NotificationEvent:
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        normalized_severity = normalize_severity(severity, category=category)
        category = str(category or "test")
        subject_prefix = "[Cerberus][{}][{}]".format(normalized_severity, hostname)
        stack = str(stack or "test")
        package_name = str(package_name or "demo-package")
        installed_version = str(installed_version or "0.0.0")
        advisory_id = str(advisory_id or "TEST-0000")
        vhost = str(vhost or "test.example.internal")
        source_file = str(source_file or "/tmp/demo-manifest.lock")
        source_line = 1 if source_line is None else int(source_line)
        stack_to_ecosystem = {
            "nodejs": "npm",
            "npm": "npm",
            "python": "PyPI",
            "django": "PyPI",
            "php-composer": "Packagist",
            "composer": "Packagist",
            "gitea": "Gitea",
            "go": "Go",
            "cargo": "crates.io",
        }
        resolved_ecosystem = str(ecosystem or stack_to_ecosystem.get(stack.lower(), stack)).strip()
        if category == "vulnerability":
            advisory_summary = "simulated vulnerability notification from vhost-cve-monitor"
            recommendation = build_recommendation(
                ecosystem=resolved_ecosystem,
                stack=stack,
                package_name=package_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                affected_range=None,
            )
            subject = "{} {} {} {}".format(subject_prefix, vhost, package_name, advisory_id)
            body_lines = [
                f"Hostname: {hostname}",
                f"Date: {now.isoformat()}",
                "Vhost: {}".format(vhost),
                "Stack: {}".format(stack),
                "Dependency: {}".format(package_name),
                "Detected version: {}".format(installed_version),
                "Fixed version: {}".format(fixed_version or "unknown"),
                "Source file: {}".format(source_file),
                "Source line: {}".format(source_line),
                "CVE / Advisory: {}".format(advisory_id),
                "Severity: {}".format(normalized_severity.lower()),
                "Summary: {}".format(advisory_summary),
                "Recommendation: {}".format(recommendation),
            ]
        elif category == "scan-failure":
            subject = "{} test.example.internal repeated scan failure: test_failure".format(subject_prefix)
            body_lines = [
                f"Hostname: {hostname}",
                f"Date: {now.isoformat()}",
                "Vhost: test.example.internal",
                "Stack: test",
                "Component: scan pipeline",
                "Detected version: unknown",
                "CVE / Advisory: n/a",
                "Severity: {}".format(normalized_severity.lower()),
                "Summary: repeated scan failure",
                "Recommendation: inspect logs and fix the audit environment or the broken project tree.",
                "Detail: test_failure simulated by test-mail",
            ]
        elif category == "internal-error":
            subject = "{} internal error during test-mail".format(subject_prefix)
            body_lines = [
                f"Hostname: {hostname}",
                f"Date: {now.isoformat()}",
                "Component: cerberus-daemon",
                "Operation: test-mail",
                "Error type: RuntimeError",
                "Detail: simulated internal error from test-mail",
                "Severity: {}".format(normalized_severity),
                "Summary: Cerberus hit an internal execution error.",
                "Recommendation: inspect the local logs and, if the failure is reproducible, report it on {}.".format(
                    BUG_REPORT_URL
                ),
            ]
        elif category == "digest":
            subject = "{} 3 alerts".format(subject_prefix)
            body_lines = [
                f"Hostname: {hostname}",
                f"Date: {now.isoformat()}",
                "Events summarized: 3",
                "Highest severity: {}".format(normalized_severity),
                "Summary: additional alerts were grouped to avoid flooding the destination mailbox.",
                "Recommendation: upgrade the affected components to the fixed versions shown below, then rebuild lockfiles or dependencies before redeploying.",
                "",
                "Included alerts:",
                "- test.example.internal | demo-package 0.0.0 -> fixed in >= 0.0.1 | TEST-0000 [/tmp/demo-manifest.lock:1]",
                "- test.example.internal | demo-package 0.0.1 -> fixed in >= 0.0.2 | TEST-0001 [/tmp/demo-manifest.lock:2]",
                "- test.example.internal | demo-package 0.0.2 | TEST-0002 [/tmp/demo-manifest.lock:3]",
            ]
        else:
            subject = "{} Test notification".format(subject_prefix)
            body_lines = [
                f"Hostname: {hostname}",
                f"Date: {now.isoformat()}",
                "Vhost: test.example.internal",
                "Stack: test",
                "Dependency: demo-package",
                "Detected version: 0.0.0",
                "CVE / Advisory: TEST-0000",
                "Severity: {}".format(normalized_severity.lower()),
                "Summary: test notification from vhost-cve-monitor",
                "Recommendation: no action required.",
            ]
        event = NotificationEvent(
            category=category,
            fingerprint="test-mail",
            subject=subject,
            body="\n".join(body_lines),
            created_at=now,
            metadata={
                "severity": normalized_severity,
                "category": category,
                "stack": stack,
                "ecosystem": resolved_ecosystem,
                "dependency": package_name,
                "version": installed_version,
                "fixed_version": fixed_version,
                "vuln_id": advisory_id,
                "vhost": vhost if category == "vulnerability" else None,
                "source_path": source_file if category == "vulnerability" else None,
                "source_line": source_line if category == "vulnerability" else None,
                "advisory_summary": advisory_summary if category == "vulnerability" else None,
            },
        )
        self.mailer.send(event)
        return event

    def daemon_loop(self) -> None:
        interval = int(self.config["scanner"]["scan_interval_minutes"]) * 60
        while True:
            try:
                self.scan_once()
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Unhandled exception during scan cycle")
                self.report_internal_error("daemon", exc)
            time.sleep(interval)
