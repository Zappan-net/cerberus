from __future__ import annotations

import logging
import os
import re
import socket
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .advisory_logic import (
    SEVERITY_ORDER,
    advisory_ids_from_fields,
    build_recommendation,
    canonical_advisory_id,
    merge_fixed_versions,
    normalize_severity,
    strongest_severity,
)
from .audits import scan_stack
from .codex_analysis import CodexAnalysisRunner, codex_analysis_enabled
from .config import validate_config
from .cve_db import CVEDatabase
from .fixed_versions import fix_description
from .models import AuditIssue, NotificationEvent, ScanFailure, StackMatch, VhostScanResult
from .nginx_parser import load_vhosts
from .notify import Mailer
from .notify import NotificationDeliveryError
from .stack_detection import _detect_root_candidates, detect_stacks
from .state_store import StateStore
from .runtime_audit import RuntimeAuditor, runtime_description
from .subprocess_utils import command_exists

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
    fix_details: Dict = field(default_factory=dict)
    audit_scope: str = "runtime"
    fix_is_semver_major: bool = False
    aliases: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    projections: List[FindingProjection] = field(default_factory=list)
    runtime_context: Dict = field(default_factory=dict)


def _filter_reasons(name: str, path: Optional[str], config: Dict) -> List[str]:
    filters = config["filters"]
    reasons: List[str] = []
    allowlist = filters.get("vhost_allowlist") or []
    blocklist = filters.get("vhost_blocklist") or []
    path_allowlist = filters.get("path_allowlist") or []
    path_blocklist = filters.get("path_blocklist") or []
    if allowlist and not any(fnmatch(name, pattern) for pattern in allowlist):
        reasons.append("vhost not matched by filters.vhost_allowlist")
    if any(fnmatch(name, pattern) for pattern in blocklist):
        reasons.append("vhost matched filters.vhost_blocklist")
    if path:
        if path_allowlist and not any(fnmatch(path, pattern) for pattern in path_allowlist):
            reasons.append("path not matched by filters.path_allowlist")
        if any(fnmatch(path, pattern) for pattern in path_blocklist):
            reasons.append("path matched filters.path_blocklist")
    return reasons


def _is_allowed(name: str, path: Optional[str], config: Dict) -> bool:
    return not _filter_reasons(name, path, config)


def _matches_only_vhost(server_names: List[str], only_vhosts: Optional[List[str]]) -> bool:
    if not only_vhosts:
        return True
    names = server_names or []
    return any(fnmatch(name, pattern) for name in names for pattern in only_vhosts)


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
        self.codex_analyzer = CodexAnalysisRunner(config, self.state) if codex_analysis_enabled(config) else None

    def validate_loaded_config(self) -> Dict[str, object]:
        validation = validate_config(self.config)
        return {
            "status": "error" if validation["errors"] else "ok",
            "errors": validation["errors"],
            "warnings": validation["warnings"],
        }

    def _serialize_stack_match(self, stack) -> Dict[str, object]:
        return {
            "stack_name": stack.stack_name,
            "confidence": stack.confidence,
            "root_path": stack.root_path,
            "reasons": list(stack.reasons),
        }

    def _describe_vhost(self, vhost) -> Dict[str, object]:
        filter_reasons = _filter_reasons(vhost.primary_server_name, vhost.primary_root, self.config)
        candidate_roots = [str(path) for path in _detect_root_candidates(vhost, self.config)]
        detected_stacks = [self._serialize_stack_match(stack) for stack in detect_stacks(vhost, self.config)]
        return {
            "primary_server_name": vhost.primary_server_name,
            "server_names": list(vhost.server_names),
            "file_path": vhost.file_path,
            "primary_root": vhost.primary_root,
            "roots": list(vhost.roots),
            "includes": list(vhost.includes),
            "redirect_only": vhost.is_redirect_only,
            "passes_filters": not filter_reasons,
            "filter_reasons": filter_reasons,
            "candidate_roots": candidate_roots,
            "proxy_passes": list(vhost.proxy_passes),
            "fastcgi_passes": list(vhost.fastcgi_passes),
            "uwsgi_passes": list(vhost.uwsgi_passes),
            "upstream_paths": list(vhost.upstream_paths),
            "detected_stacks": detected_stacks,
        }

    def list_vhosts(self) -> Dict[str, object]:
        described = [self._describe_vhost(vhost) for vhost in load_vhosts(self.config)]
        described.sort(key=lambda item: item["primary_server_name"])
        return {"count": len(described), "vhosts": described}

    def explain_vhost(self, name: str) -> Dict[str, object]:
        query = str(name or "").strip()
        if not query:
            raise ValueError("vhost name must be provided")
        matches = []
        for vhost in load_vhosts(self.config):
            names = list(vhost.server_names) or [vhost.primary_server_name]
            if query in names or fnmatch(vhost.primary_server_name, query) or any(fnmatch(server_name, query) for server_name in names):
                matches.append(self._describe_vhost(vhost))
        if not matches:
            raise ValueError("vhost not found: {}".format(query))
        matches.sort(key=lambda item: item["primary_server_name"])
        return {"query": query, "matches_count": len(matches), "matches": matches}

    def doctor(self) -> Dict[str, object]:
        validation = validate_config(self.config)
        errors = list(validation["errors"])
        warnings = list(validation["warnings"])
        checks: List[Dict[str, str]] = []

        sites_dir = Path(str(self.config["nginx"].get("sites_enabled_dir") or ""))
        if sites_dir.is_dir():
            checks.append({"name": "nginx.sites_enabled_dir", "status": "ok", "detail": str(sites_dir)})
        else:
            message = "directory not found: {}".format(sites_dir)
            checks.append({"name": "nginx.sites_enabled_dir", "status": "error", "detail": message})
            errors.append(message)

        db_path = Path(str(self.config["state"].get("database_path") or ""))
        db_parent = db_path.parent
        if db_parent.exists() and os.access(str(db_parent), os.W_OK):
            checks.append({"name": "state.database_path", "status": "ok", "detail": str(db_path)})
        elif db_parent.exists():
            message = "database parent is not writable: {}".format(db_parent)
            checks.append({"name": "state.database_path", "status": "error", "detail": message})
            errors.append(message)
        else:
            message = "database parent does not exist yet: {}".format(db_parent)
            checks.append({"name": "state.database_path", "status": "warning", "detail": message})
            warnings.append(message)

        log_file = str(self.config["logging"].get("file") or "").strip()
        if log_file:
            log_parent = Path(log_file).parent
            if log_parent.exists() and os.access(str(log_parent), os.W_OK):
                checks.append({"name": "logging.file", "status": "ok", "detail": log_file})
            else:
                message = "log parent is not writable or missing: {}".format(log_parent)
                checks.append({"name": "logging.file", "status": "warning", "detail": message})
                warnings.append(message)

        method = str(self.config["notifications"].get("method") or "").lower()
        if method == "sendmail":
            sendmail_path = Path(str(self.config["notifications"].get("sendmail_path") or ""))
            if sendmail_path.exists() and os.access(str(sendmail_path), os.X_OK):
                checks.append({"name": "notifications.sendmail", "status": "ok", "detail": str(sendmail_path)})
            else:
                message = "sendmail binary missing or not executable: {}".format(sendmail_path)
                checks.append({"name": "notifications.sendmail", "status": "error", "detail": message})
                errors.append(message)
        elif method == "smtp":
            detail = "{}:{} ssl={} starttls={}".format(
                self.config["notifications"].get("smtp_host"),
                self.config["notifications"].get("smtp_port"),
                bool(self.config["notifications"].get("smtp_ssl")),
                bool(self.config["notifications"].get("smtp_starttls")),
            )
            checks.append({"name": "notifications.smtp", "status": "ok", "detail": detail})

        for binary in ("npm", "composer", "pip-audit"):
            checks.append(
                {
                    "name": "binary:{}".format(binary),
                    "status": "ok" if command_exists(binary) else "warning",
                    "detail": "available" if command_exists(binary) else "not found in PATH",
                }
            )
            if not command_exists(binary):
                warnings.append("optional audit tool not found in PATH: {}".format(binary))

        vhosts = load_vhosts(self.config)
        checks.append({"name": "nginx.vhosts", "status": "ok", "detail": "{} vhost(s) parsed".format(len(vhosts))})
        if not vhosts:
            warnings.append("no nginx vhosts were parsed from {}".format(sites_dir))

        status = "error" if errors else "warning" if warnings else "ok"
        return {
            "status": status,
            "errors": errors,
            "warnings": warnings,
            "checks": checks,
        }

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

    def scan_once(
        self,
        only_vhosts: Optional[List[str]] = None,
        force_notify: bool = False,
    ) -> Tuple[List[VhostScanResult], List[NotificationEvent]]:
        LOGGER.info("Starting scan cycle")
        self.state.begin_scan(dry_run=self.dry_run)
        if force_notify:
            LOGGER.warning("Forced notification mode enabled; vulnerability deduplication state will not be changed")
        now, results, issue_occurrences, failure_notifications = self._collect_scan_data(only_vhosts=only_vhosts)
        self.state.replace_current_findings(self._current_findings_snapshot(issue_occurrences), scanned_at=now.isoformat())
        notifications = self._build_issue_notifications(issue_occurrences, force_notify=force_notify) + failure_notifications
        LOGGER.info("Prepared %s notifications", len(notifications))
        for notification in self._prepare_notifications_for_delivery(notifications):
            LOGGER.info("Sending %s notification: %s", notification.category, notification.subject)
            self._send_notification(notification)
        LOGGER.info("Scan cycle completed")
        return results, notifications

    def _send_notification(self, event: NotificationEvent) -> None:
        self.state.dry_run = self.dry_run
        decision_ids = event.metadata.get("decision_ids") or []
        if not decision_ids:
            decision_id = self.state.decision_ids.get(event.fingerprint)
            if decision_id:
                decision_ids = [decision_id]
        if not decision_ids:
            self.state.record_forced_decision(event.fingerprint, event.metadata, "explicit_notification")
            decision_ids = [self.state.decision_ids[event.fingerprint]]
        notification_id = uuid.uuid4().hex
        if self.dry_run:
            self.state.record_delivery(decision_ids, "dry_run", notification_id, "transport_not_called")
            self.mailer.send(event)
            return
        self.state.record_delivery(decision_ids, "attempt", notification_id, "transport_started")
        try:
            self.mailer.send(event)
        except Exception as exc:
            self.state.record_delivery(decision_ids, "failure", notification_id, type(exc).__name__)
            raise
        self.state.record_delivery(decision_ids, "success", notification_id, "accepted_by_transport")

    def _collect_scan_data(self, only_vhosts: Optional[List[str]] = None) -> Tuple[datetime, List[VhostScanResult], List[Dict], List[NotificationEvent]]:
        now = datetime.now(timezone.utc)
        vhosts = load_vhosts(self.config)
        LOGGER.info("Loaded %s nginx vhosts", len(vhosts))
        results: List[VhostScanResult] = []
        issue_occurrences: List[Dict] = []
        failure_occurrences: List[Dict[str, object]] = []
        runtime_auditor = RuntimeAuditor(self.config, self.cve_db, self.allow_network)
        for vhost in vhosts:
            server_names = list(vhost.server_names) or [vhost.primary_server_name]
            if not _matches_only_vhost(server_names, only_vhosts):
                LOGGER.info("Skipping non-selected vhost %s", vhost.primary_server_name)
                continue
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
            runtime_results = [item for item in runtime_auditor.scan(vhost)
                               if _is_allowed(vhost.primary_server_name, item.stack.root_path, self.config)]
            if not stacks and not runtime_results and not vhost.is_redirect_only:
                result.failures.append(ScanFailure(scope=vhost.primary_server_name, reason="stack_not_detected"))
            stack_results = []
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
                stack_results.append(stack_result)
            for stack_result in stack_results + runtime_results:
                stack = stack_result.stack
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
                    if not issue.runtime_context:
                        self.cve_db.repairs.enrich(issue.vulnerability, issue.dependency, self.allow_network)
                    issue_occurrences.append(
                        {
                            "vhost": vhost.primary_server_name,
                            "stack": stack_result.stack.stack_name,
                            "issue": issue,
                        }
                    )
                for failure in stack_result.failures:
                    failure_occurrences.append(
                        {
                            "vhost": vhost.primary_server_name,
                            "stack": stack_result.stack,
                            "failure": failure,
                        }
                    )
            for failure in result.failures:
                failure_occurrences.append(
                    {
                        "vhost": vhost.primary_server_name,
                        "stack": None,
                        "failure": failure,
                    }
                )
            results.append(result)
        failure_notifications = self._build_failure_notifications(failure_occurrences)
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
        subject_highest = self._digest_subject_severity(digest_items)
        severity_groups = self._group_digest_items_by_severity(digest_items)
        breakdown = self._digest_breakdown(severity_groups)
        npm_scope_summary = self._npm_scope_summary(digest_items)
        lines = [
            f"Hostname: {hostname}",
            f"Date: {now.isoformat()}",
            f"Findings: {len(digest_items)}",
            f"Highest severity: {subject_highest}",
            f"Breakdown: {breakdown}",
            "Summary: new or changed findings were grouped to avoid flooding the destination mailbox.",
        ]
        if highest != subject_highest:
            lines.append("Full audit highest severity: {}".format(highest))
        if npm_scope_summary:
            lines.append(npm_scope_summary)
        scope_sections = self._digest_scope_sections(digest_items)
        for section_title, scoped_items in scope_sections:
            if len(scope_sections) > 1:
                lines.extend(["", section_title])
            scoped_groups = self._group_digest_items_by_severity(scoped_items)
            for severity, items in scoped_groups:
                lines.extend(
                    [
                        "",
                        "{} ({})".format(severity, len(items)),
                        "Recommendation: {}".format(self._digest_block_recommendation(severity, items)),
                    ]
                )
                for item in items:
                    if item.get("category") == "scan-failure":
                        lines.extend(self._scan_failure_digest_lines(item))
                        continue
                    source_suffix = ""
                    if item["source_path"] and item["source_line"]:
                        source_suffix = " [{}:{}]".format(item["source_path"], item["source_line"])
                    elif item["source_path"]:
                        source_suffix = " [{}]".format(item["source_path"])
                    fixed_suffix = ""
                    if item["fixed_version"]:
                        fixed_suffix = " -> fixed in {}".format(item["fixed_version"])
                    lines.append(
                        "- Affected targets: {} | {}{}".format(
                            ", ".join(item["affected_targets"]),
                            self._digest_stack_context(item),
                            " | {}".format(source_suffix.strip()) if source_suffix else "",
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
                    if item.get("runtime_context"):
                        lines.append("  Runtime inventory: " + runtime_description(item["runtime_context"]))
                    if item.get("affected_range"):
                        lines.append("  Affected range: {}".format(item["affected_range"]))
                    if item.get("fix_details"):
                        lines.append("  Repair evidence: " + fix_description(item["fix_details"]))
                    if item.get("alert_reason"):
                        lines.append("  Alert reason: {}".format(self._alert_reason_label(str(item["alert_reason"]))))
                    if item.get("audit_scope") == "development":
                        lines.append("  Note: development/build finding absent from npm audit --omit=dev.")
                    if item.get("fix_is_semver_major"):
                        lines.append("  Risk: npm marks the available fix as semver-major; review breakage before applying it.")
                    if isinstance(item.get("codex_analysis"), dict):
                        lines.extend(
                            "  {}".format(line)
                            for line in self._codex_analysis_text_lines(item["codex_analysis"])
                        )
        subject_suffix = "{} alerts".format(len(digest_items))
        if self._has_runtime_npm_and_development_npm(digest_items):
            subject_suffix = "runtime npm findings"
        subject = "[Cerberus][{}][{}] {}".format(subject_highest, hostname, subject_suffix)
        return NotificationEvent(
            category="digest",
            fingerprint="digest:{}:{}".format(now.date().isoformat(), len(digest_items)),
            subject=subject,
            body="\n".join(lines),
            created_at=now,
            metadata={
                "severity": subject_highest,
                "body_severity": highest,
                "events": len(digest_items),
                "digest_items": digest_items,
                "decision_ids": [decision_id for event in events for decision_id in event.metadata.get("decision_ids", [])],
                "hostname": hostname,
            },
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
                        "fix_details": finding.fix_details,
                        "runtime_context": finding.runtime_context,
                        "affected_range": finding.affected_range,
                        "advisory_summary": finding.summary or None,
                        "source_path": finding.source_path,
                        "source_line": projection.source_line,
                        "audit_scope": finding.audit_scope,
                        "fix_is_semver_major": finding.fix_is_semver_major,
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
                "fix_details": metadata.get("fix_details", {}),
                "runtime_context": metadata.get("runtime_context", {}),
                "source_path": metadata.get("source_path"),
                "source_line": metadata.get("source_line"),
                "category": event.category,
                "ecosystem": _clean_text(metadata.get("ecosystem", "")) or None,
                "stack": _clean_text(metadata.get("stack", "")) or None,
                "advisory_summary": _clean_text(metadata.get("advisory_summary", "")) or None,
                "affected_range": _clean_text(metadata.get("affected_range", "")) or None,
                "audit_scope": _clean_text(metadata.get("audit_scope", "runtime")) or "runtime",
                "fix_is_semver_major": bool(metadata.get("fix_is_semver_major")),
                "alert_reason": _clean_text(metadata.get("alert_reason", "new")) or "new",
                "detail": _clean_text(metadata.get("detail", "")) or None,
                "recommendation": metadata.get("recommendation"),
                "aliases": list(metadata.get("aliases") or []),
                "references": list(metadata.get("references") or []),
                "codex_analysis": metadata.get("codex_analysis") if isinstance(metadata.get("codex_analysis"), dict) else None,
            }
            key = (
                item["source_path"],
                item["dependency"],
                item["version"],
                item["vuln_id"],
                item["audit_scope"],
            )
            if key in items:
                items[key]["severity"] = strongest_severity(str(items[key]["severity"]), str(item["severity"]))
                if item["vhost"] not in items[key]["affected_targets"]:
                    items[key]["affected_targets"].append(item["vhost"])
                    items[key]["affected_targets"].sort()
                if not items[key]["fixed_version"] and item["fixed_version"]:
                    items[key]["fixed_version"] = item["fixed_version"]
                if not items[key]["advisory_summary"] and item["advisory_summary"]:
                    items[key]["advisory_summary"] = item["advisory_summary"]
                if not items[key]["affected_range"] and item["affected_range"]:
                    items[key]["affected_range"] = item["affected_range"]
                items[key]["fix_is_semver_major"] = bool(items[key]["fix_is_semver_major"] or item["fix_is_semver_major"])
                if item["alert_reason"] == "progressive_enrichment":
                    items[key]["alert_reason"] = "progressive_enrichment"
                elif item["alert_reason"] == "changed" and items[key]["alert_reason"] == "new":
                    items[key]["alert_reason"] = "changed"
                if not items[key].get("codex_analysis") and item.get("codex_analysis"):
                    items[key]["codex_analysis"] = item["codex_analysis"]
                continue
            affected_targets = metadata.get("affected_targets")
            if isinstance(affected_targets, list):
                item["affected_targets"] = sorted({_clean_text(target) for target in affected_targets if _clean_text(target)})
            else:
                item["affected_targets"] = [item["vhost"]]
            if not item["affected_targets"]:
                item["affected_targets"] = [item["vhost"]]
            items[key] = item
        return sorted(
            items.values(),
            key=lambda item: (
                -SEVERITY_ORDER.get(str(item["severity"]).upper(), -1),
                ", ".join(item["affected_targets"]),
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

    def _digest_subject_severity(self, digest_items: List[Dict[str, object]]) -> str:
        if not self._has_runtime_npm_and_development_npm(digest_items):
            return self._digest_highest_severity(digest_items)
        runtime_items = [
            item
            for item in digest_items
            if str(item.get("ecosystem") or "").lower() == "npm"
            and str(item.get("audit_scope") or "runtime") == "runtime"
        ]
        if not runtime_items:
            return self._digest_highest_severity(digest_items)
        return self._digest_highest_severity(runtime_items)

    def _has_runtime_npm_and_development_npm(self, digest_items: List[Dict[str, object]]) -> bool:
        npm_scopes = {
            str(item.get("audit_scope") or "runtime")
            for item in digest_items
            if str(item.get("ecosystem") or "").lower() == "npm"
        }
        return "runtime" in npm_scopes and "development" in npm_scopes

    def _npm_scope_summary(self, digest_items: List[Dict[str, object]]) -> Optional[str]:
        development_items = [
            item
            for item in digest_items
            if str(item.get("ecosystem") or "").lower() == "npm"
            and str(item.get("audit_scope") or "runtime") == "development"
        ]
        if not development_items:
            return None
        highest = self._digest_highest_severity(development_items)
        return "Development/build findings include {} advisories.".format(highest)

    def _digest_scope_sections(self, digest_items: List[Dict[str, object]]) -> List[tuple[str, List[Dict[str, object]]]]:
        runtime = [
            item
            for item in digest_items
            if str(item.get("audit_scope") or "runtime") != "development"
        ]
        development = [
            item
            for item in digest_items
            if str(item.get("audit_scope") or "runtime") == "development"
        ]
        sections = []
        if runtime:
            sections.append(("Runtime / production findings", runtime))
        if development:
            sections.append(("Development / build findings", development))
        return sections

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
                            ", ".join(item.get("affected_targets", [str(item.get("vhost", ""))])),
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
        if any(item.get("runtime_context") for item in items):
            return (
                "verify distributor backport status for interpreter findings, update affected runtimes through "
                "their original supplier, validate application/extension compatibility and restart affected workers; "
                "dependency-manager updates alone do not patch the interpreter. "
                "For application dependency findings, apply the package fixes separately."
            )
        if any((item.get("fix_details") or {}).get("status") == "conflicting" for item in items):
            return "review conflicting repair sources and affected release branches before choosing an upgrade; validate application compatibility."
        categories = {str(item.get("category") or "") for item in items}
        ecosystems = {
            str(item.get("ecosystem") or "").lower()
            for item in items
            if str(item.get("ecosystem") or "").strip()
        }
        if categories == {"scan-failure"}:
            recommendations = list(dict.fromkeys(str(item["recommendation"]) for item in items if item.get("recommendation")))
            if recommendations:
                return " ".join(recommendations)
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
                scopes = {str(item.get("audit_scope") or "runtime") for item in items}
                if scopes == {"development"}:
                    return (
                        "schedule these npm development/build dependency updates, review `package-lock.json` drift, "
                        "and avoid `npm audit fix --force` unless semver-major breakage has been reviewed."
                    )
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

    def _scan_failure_digest_lines(self, item: Dict[str, object]) -> List[str]:
        lines = [
            "- Affected targets: {}".format(", ".join(item.get("affected_targets") or [str(item.get("vhost") or "unknown")])),
            "  Stack / Ecosystem: {}".format(self._digest_stack_context(item)),
            "  Component: {}".format(item.get("dependency") or "audit pipeline"),
            "  Reason: {}".format(item.get("vuln_id") or item.get("reason") or "scan_failed"),
            "  Severity: {}".format(item.get("severity") or "WARNING"),
        ]
        if item.get("advisory_summary"):
            lines.append("  Summary: {}".format(item["advisory_summary"]))
        if item.get("source_path"):
            lines.append("  Evidence: {}".format(item["source_path"]))
        detail = str(item.get("detail") or "").strip()
        if detail:
            lines.append("  Detail: {}".format(detail))
        if item.get("alert_reason"):
            lines.append("  Alert reason: {}".format(self._alert_reason_label(str(item["alert_reason"]))))
        return lines

    def _alert_reason_label(self, reason: str) -> str:
        labels = {
            "new": "new finding",
            "changed": "finding changed since the previous notification",
            "progressive_enrichment": "progressive advisory enrichment since the previous notification",
            "forced": "forced notification",
        }
        return labels.get(str(reason or ""), str(reason or "unknown"))

    def _normalize_findings(self, occurrences: List[Dict]) -> List[NormalizedFinding]:
        normalized: List[NormalizedFinding] = []
        finding_ids: Dict[int, set] = {}
        alias_groups = {}
        for occurrence in occurrences:
            issue = occurrence["issue"]
            scope = (issue.dependency.ecosystem.lower(), issue.dependency.name.lower(),
                     issue.dependency.version, issue.dependency.source)
            ids = set(advisory_ids_from_fields(issue.vulnerability.vuln_id,
                      issue.vulnerability.aliases, issue.vulnerability.references))
            ids.add(issue.vulnerability.vuln_id)
            ids.update(issue.vulnerability.aliases)
            groups = alias_groups.setdefault(scope, [])
            overlapping = [group for group in groups if group & ids]
            for group in overlapping:
                ids.update(group)
                groups.remove(group)
            groups.append(ids)
        for occurrence in occurrences:
            issue = occurrence["issue"]
            issue_ids = set(
                advisory_ids_from_fields(
                    issue.vulnerability.vuln_id,
                    issue.vulnerability.aliases,
                    issue.vulnerability.references,
                )
            )
            canonical_id = canonical_advisory_id(
                issue.vulnerability.vuln_id,
                issue.vulnerability.aliases,
                issue.vulnerability.references,
            )
            issue_ids.add(canonical_id)
            scope = (issue.dependency.ecosystem.lower(), issue.dependency.name.lower(),
                     issue.dependency.version, issue.dependency.source)
            for group in alias_groups[scope]:
                if group & issue_ids:
                    issue_ids.update(group)
            canonical_id = canonical_advisory_id(canonical_id, sorted(issue_ids), [])
            current = None
            for candidate in normalized:
                if (
                    candidate.dependency.lower() == issue.dependency.name.lower()
                    and candidate.ecosystem.lower() == issue.dependency.ecosystem.lower()
                    and candidate.version == issue.dependency.version
                    and candidate.source_path == issue.dependency.source
                    and finding_ids.get(id(candidate), set()).intersection(issue_ids)
                ):
                    current = candidate
                    break
            if current is None:
                finding = NormalizedFinding(
                    advisory_id=canonical_id,
                    dependency=issue.dependency.name,
                    version=issue.dependency.version,
                    source_path=issue.dependency.source,
                    ecosystem=issue.dependency.ecosystem,
                    severity=normalize_severity(issue.vulnerability.severity),
                    summary=issue.vulnerability.summary,
                    details=issue.vulnerability.details,
                    fixed_version=issue.vulnerability.fixed_version,
                    fix_details=issue.vulnerability.fix_details,
                    runtime_context=dict(issue.runtime_context),
                    affected_range=issue.vulnerability.affected_range,
                    audit_scope=issue.vulnerability.audit_scope,
                    fix_is_semver_major=issue.vulnerability.fix_is_semver_major,
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
                for alias in issue_ids:
                    if alias and alias != finding.advisory_id and alias not in finding.aliases:
                        finding.aliases.append(alias)
                normalized.append(finding)
                finding_ids[id(finding)] = issue_ids | {finding.advisory_id}
                continue
            finding_ids[id(current)].update(issue_ids)
            current.advisory_id = canonical_advisory_id(
                current.advisory_id,
                current.aliases + issue.vulnerability.aliases,
                current.references + issue.vulnerability.references,
            )
            current.severity = strongest_severity(current.severity, issue.vulnerability.severity)
            if not current.runtime_context and issue.runtime_context:
                current.runtime_context = dict(issue.runtime_context)
            if len(issue.vulnerability.summary or "") > len(current.summary or ""):
                current.summary = issue.vulnerability.summary
            if len(issue.vulnerability.details or "") > len(current.details or ""):
                current.details = issue.vulnerability.details
            current.fixed_version = merge_fixed_versions(current.fixed_version, issue.vulnerability.fixed_version)
            if issue.vulnerability.fix_details:
                current.fix_details = issue.vulnerability.fix_details
            current.affected_range = current.affected_range or issue.vulnerability.affected_range
            if issue.vulnerability.audit_scope == "runtime":
                current.audit_scope = "runtime"
            current.fix_is_semver_major = current.fix_is_semver_major or issue.vulnerability.fix_is_semver_major
            for alias in issue.vulnerability.aliases:
                if alias and alias not in current.aliases:
                    current.aliases.append(alias)
            for alias in issue_ids:
                if alias and alias != current.advisory_id and alias not in current.aliases:
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
                existing.vhost == projection.vhost and existing.stack == projection.stack
                for existing in current.projections
            ):
                current.projections.append(projection)
        return sorted(
            normalized,
            key=lambda item: (
                -SEVERITY_ORDER.get(item.severity, -1),
                item.advisory_id,
                item.dependency.lower(),
                item.version,
                item.source_path,
            ),
        )

    def _build_issue_notifications(
        self,
        occurrences: List[Dict],
        force_notify: bool = False,
    ) -> List[NotificationEvent]:
        notifications = []
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        for finding in self._normalize_findings(occurrences):
            severity = normalize_severity(finding.severity)
            base_analysis_payload = {
                "dependency": finding.dependency,
                "runtime_context": finding.runtime_context,
                "version": finding.version,
                "advisory_id": finding.advisory_id,
                "severity": severity,
                "fixed_version": finding.fixed_version,
                "fix_details": finding.fix_details,
                "affected_range": finding.affected_range,
                "advisory_summary": finding.summary,
                "source_path": finding.source_path,
                "ecosystem": finding.ecosystem,
                "audit_scope": finding.audit_scope,
                "affected_targets": sorted({projection.vhost for projection in finding.projections}),
            }
            recommendation = build_recommendation(
                ecosystem=finding.ecosystem,
                stack=finding.projections[0].stack,
                package_name=finding.dependency,
                installed_version=finding.version,
                fixed_version=finding.fixed_version,
                affected_range=finding.affected_range,
                audit_scope=finding.audit_scope,
                fix_is_semver_major=finding.fix_is_semver_major,
            )
            if finding.fix_details.get("status") == "conflicting":
                recommendation = "review conflicting repair sources and affected release branches before choosing an upgrade."
            pending = []
            for projection in finding.projections:
                payload = {
                    "vhost": projection.vhost,
                    "runtime_context": finding.runtime_context,
                    "stack": projection.stack,
                    "dependency": finding.dependency,
                    "version": finding.version,
                    "vuln_id": finding.advisory_id,
                    "severity": severity,
                    "fixed_version": finding.fixed_version,
                    "fix_details": finding.fix_details,
                    "affected_range": finding.affected_range,
                    "advisory_summary": finding.summary,
                    "source_path": finding.source_path,
                    "source_line": projection.source_line,
                    "ecosystem": finding.ecosystem,
                    "audit_scope": finding.audit_scope,
                    "fix_is_semver_major": finding.fix_is_semver_major,
                    "aliases": list(finding.aliases),
                    "references": list(finding.references),
                }
                fingerprint = "issue:{}:{}:{}:{}:{}:{}".format(
                    projection.vhost,
                    projection.stack,
                    finding.dependency,
                    finding.version,
                    finding.advisory_id,
                    finding.source_path,
                )
                alert_reason = "forced" if force_notify else "new"
                if not force_notify:
                    should_alert, alert_reason = self.state.alert_decision(fingerprint, payload)
                    if not should_alert:
                        continue
                else:
                    self.state.record_forced_decision(fingerprint, payload)
                payload["alert_reason"] = alert_reason
                payload["decision_ids"] = [self.state.decision_ids[fingerprint]]
                pending.append((projection, payload, fingerprint))
            codex_analysis = None
            if pending and self.codex_analyzer:
                analysis_payload = dict(base_analysis_payload)
                analysis_payload.update(
                    {
                        "stack": pending[0][0].stack,
                        "source_line": pending[0][0].source_line,
                        "affected_targets": sorted({item[0].vhost for item in pending}),
                    }
                )
                codex_analysis = self.codex_analyzer.analyze(analysis_payload)
            for projection, payload, fingerprint in pending:
                if self._should_include_codex_analysis(codex_analysis):
                    payload["codex_analysis"] = codex_analysis
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
                    "Repair evidence: {}".format(fix_description(finding.fix_details) or "not collected"),
                    "Source file: {}".format(finding.source_path),
                    "Source line: {}".format(projection.source_line if projection.source_line else "unknown"),
                    f"CVE / Advisory: {finding.advisory_id}",
                    f"Severity: {severity}",
                    "Audit scope: {}".format(finding.audit_scope),
                    "Alert reason: {}".format(self._alert_reason_label(alert_reason)),
                    "Summary: {}".format(finding.summary or "No summary provided by upstream advisory sources."),
                    "Recommendation: {}".format(recommendation),
                ]
                if finding.audit_scope == "development":
                    body_lines.append("Note: development/build finding absent from npm audit --omit=dev.")
                if finding.runtime_context:
                    body_lines.append("Runtime inventory: " + runtime_description(finding.runtime_context))
                if finding.fix_is_semver_major:
                    body_lines.append("Risk: npm marks the available fix as semver-major; review breakage before applying it.")
                if self._should_include_codex_analysis(codex_analysis):
                    body_lines.extend(["", *self._codex_analysis_text_lines(codex_analysis)])
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

    def _should_include_codex_analysis(self, analysis: object) -> bool:
        if not isinstance(analysis, dict):
            return False
        status = str(analysis.get("analysis_status") or "")
        if status in {"completed", "insufficient_context"}:
            return True
        settings = self.config.get("codex_analysis") or {}
        if not bool(settings.get("include_failure_diagnostics", False)):
            return False
        return status in {
            "unavailable",
            "timed_out",
            "non_zero_exit",
            "invalid_output",
            "schema_invalid",
            "oversized_output",
            "missing_repository",
        }

    def _codex_analysis_text_lines(self, analysis: Dict[str, object]) -> List[str]:
        status = str(analysis.get("analysis_status") or "unknown")
        if status not in {"completed", "insufficient_context"}:
            return [
                "Codex triage report: AI-assisted static analysis",
                "Analysis status: {}".format(status),
                "Result: Codex analysis was attempted, but no validated report was available.",
                "Diagnostic: {}".format(analysis.get("reason") or "no diagnostic detail available"),
            ]
        confidence = analysis.get("confidence")
        confidence_text = "unknown"
        if isinstance(confidence, (int, float)):
            confidence_text = "{}%".format(round(float(confidence) * 100))
        reachability = analysis.get("reachability") if isinstance(analysis.get("reachability"), dict) else {}
        recommendations = analysis.get("recommendations") if isinstance(analysis.get("recommendations"), list) else []
        limitations = analysis.get("limitations") if isinstance(analysis.get("limitations"), list) else []
        lines = [
            "Codex triage report: AI-assisted static analysis",
            "Verdict: {}".format(analysis.get("operator_summary") or analysis.get("summary") or "No operator summary provided."),
            "Current environment: {}".format(analysis.get("environment_assessment") or "No environment assessment provided."),
            "Official advisory severity: {}".format(analysis.get("advisory_severity") or "UNKNOWN"),
            "Estimated contextual risk: {}".format(analysis.get("contextual_risk") or "UNKNOWN"),
            "Exposure: {}".format(self._codex_label(analysis.get("exposure") or "unknown")),
            "Impact: {}".format(self._codex_label(analysis.get("impact") or "unknown")),
            "Action priority: {}".format(self._codex_label(analysis.get("action_priority") or "unknown")),
            "Confidence: {}".format(confidence_text),
            "Analysis status: {}".format(analysis.get("analysis_status") or "unknown"),
            "Dependency scope: {}".format(analysis.get("dependency_scope") or "unknown"),
            "Reachability: {}".format(reachability.get("status") or "unknown"),
            "Attacker-controlled input observed: {}".format(str(bool(reachability.get("attacker_controlled_input"))).lower()),
            "Why: {}".format(analysis.get("risk_rationale") or analysis.get("summary") or "No risk rationale provided."),
        ]
        if reachability.get("explanation"):
            lines.append("Reachability explanation: {}".format(reachability.get("explanation")))
        if analysis.get("likely_impact"):
            lines.append("Likely impact: {}".format(analysis.get("likely_impact")))
        if recommendations:
            actions = [
                str(item.get("action"))
                for item in recommendations[:3]
                if isinstance(item, dict) and str(item.get("action") or "").strip()
            ]
            if actions:
                lines.append("What to do: {}".format("; ".join(actions)))
        if limitations:
            lines.append("Limitations: {}".format("; ".join(str(item) for item in limitations[:3])))
        return lines

    def _codex_label(self, value: object) -> str:
        return str(value or "unknown").replace("_", " ")

    def _build_failure_notifications(self, occurrences: List[Dict[str, object]]) -> List[NotificationEvent]:
        notifications = []
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        grouped: Dict[Tuple[str, str, str, str], Dict[str, object]] = {}
        for occurrence in occurrences:
            failure = occurrence.get("failure")
            if not isinstance(failure, ScanFailure):
                continue
            stack = occurrence.get("stack")
            stack_name = stack.stack_name if isinstance(stack, StackMatch) else failure.scope
            root_path = stack.root_path if isinstance(stack, StackMatch) and stack.root_path else None
            key = (
                stack_name,
                root_path or "",
                failure.reason,
                failure.detail or "",
            )
            item = grouped.setdefault(
                key,
                {
                    "stack": stack_name,
                    "ecosystem": self._ecosystem_for_stack(stack_name),
                    "root_path": root_path,
                    "reason": failure.reason,
                    "detail": failure.detail or "",
                    "targets": set(),
                },
            )
            item["targets"].add(str(occurrence.get("vhost") or "unknown"))
        for item in grouped.values():
            severity = normalize_severity("warning", category="scan-failure")
            targets = sorted(item["targets"])
            stack_name = str(item["stack"] or "unknown")
            ecosystem = str(item["ecosystem"] or "unknown")
            root_path = str(item["root_path"] or "")
            reason = str(item["reason"] or "scan_failed")
            detail = str(item["detail"] or "")
            payload = {
                "scope": root_path or ",".join(targets),
                "vhost": targets[0] if targets else "unknown",
                "affected_targets": targets,
                "stack": stack_name,
                "ecosystem": ecosystem,
                "reason": reason,
                "detail": detail,
                "dependency": "stack discovery" if reason == "stack_not_detected" else "audit pipeline",
                "version": "n/a",
                "vuln_id": reason,
                "source_path": root_path or None,
                "source_line": None,
                "audit_scope": "scanner",
                "advisory_summary": self._failure_summary(reason, stack_name, root_path),
                "recommendation": self._failure_recommendation(reason, stack_name),
                "severity": severity,
            }
            failure_scope = "scan-failure:{}:{}:{}".format(stack_name, root_path or ",".join(targets), reason)
            repeated = self.state.register_failure(
                scope=failure_scope,
                detail=payload,
                threshold=self.failure_threshold,
            )
            if not repeated:
                continue
            payload["decision_ids"] = [self.state.decision_ids[failure_scope]]
            body = "\n".join(
                [
                    f"Hostname: {hostname}",
                    f"Date: {now.isoformat()}",
                    f"Affected targets: {', '.join(targets)}",
                    f"Stack: {stack_name}",
                    f"Ecosystem: {ecosystem}",
                    f"Component: {payload['dependency']}",
                    f"Reason: {reason}",
                    f"Severity: {severity}",
                    f"Summary: {payload['advisory_summary']}",
                    f"Evidence: {root_path or 'unknown'}",
                    f"Recommendation: {self._failure_recommendation(reason, stack_name)}",
                    f"Detail: {detail or 'no command output captured'}",
                ]
            )
            notifications.append(
                NotificationEvent(
                    category="scan-failure",
                    fingerprint="failure:{}:{}:{}".format(stack_name, root_path or ",".join(targets), reason),
                    subject="[Cerberus][{}][{}] {} {} failure".format(severity, hostname, stack_name, payload["dependency"]),
                    body=body,
                    created_at=now,
                    metadata=payload,
                )
            )
        return notifications

    @staticmethod
    def _ecosystem_for_stack(stack_name: str) -> str:
        mapping = {
            "nodejs": "npm",
            "python": "PyPI",
            "php-composer": "Packagist",
            "gitea": "Gitea",
            "go": "Go",
            "cargo": "crates.io",
        }
        return mapping.get(str(stack_name or "").lower(), "unknown")

    @staticmethod
    def _failure_summary(reason: str, stack_name: str, root_path: str) -> str:
        if reason.startswith("runtime_"):
            return "Runtime vulnerability coverage is incomplete; this is not a clean security result."
        if reason.endswith("_audit_unavailable"):
            return "Native dependency audit was not run: required tooling or manifest is unavailable for {}{}; coverage is incomplete.".format(stack_name, " at " + root_path if root_path else "")
        if reason == "stack_not_detected":
            return "No application project could be identified for this target; dependency auditing could not start."
        command = {
            "npm_audit_failed": "npm audit --json --omit=dev",
            "npm_full_audit_failed": "npm audit --json",
            "composer_audit_failed": "composer audit",
            "pip_audit_failed": "pip-audit",
        }.get(reason, "audit command")
        location = " at {}".format(root_path) if root_path else ""
        return "{} failed for {}{}".format(command, stack_name, location)

    @staticmethod
    def _failure_recommendation(reason: str, stack_name: str) -> str:
        if reason.startswith("runtime_"):
            return "verify the backend executable association and distributor advisory availability; configure a runtime binding for stopped/remote backends and resolve unsupported ranges before relying on coverage."
        if reason == "pip_audit_unavailable":
            return "make pip-audit available in the Cerberus service PATH and verify the requirements file; local advisory matching does not replace a successful native audit."
        if reason == "npm_audit_unavailable":
            return "verify npm availability and restore the project's reviewed lockfile before rerunning the native audit; do not blindly update production dependencies."
        if reason == "composer_audit_unavailable":
            return "verify Composer availability and the project's composer.lock, then rerun the native audit."
        if reason == "stack_not_detected":
            return "check the nginx upstream, listening process, private mount mappings, readable project manifests and allowed root hints, then rerun explain-vhost."
        if reason in {"npm_audit_failed", "npm_full_audit_failed"}:
            return (
                "rerun the failing npm audit command in the project root, check registry/network latency or lockfile "
                "health, then rerun Cerberus once the command is stable."
            )
        if reason == "composer_audit_failed":
            return "rerun Composer audit in the project root and fix Composer, network, or lockfile errors before relying on the scan."
        if reason == "pip_audit_failed":
            return "rerun pip-audit for the detected Python environment and fix environment or requirements issues before relying on the scan."
        if stack_name == "unknown":
            return "inspect the vhost and Cerberus logs to decide whether this target should be scanned or filtered."
        return "inspect Cerberus logs and fix the scanner environment or project tree, then rerun the scan."

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
                self._send_notification(notification)
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
        self._send_notification(event)
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
