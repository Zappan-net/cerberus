from __future__ import annotations

import logging
import socket
import time
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

from .audits import scan_stack
from .cve_db import CVEDatabase
from .models import NotificationEvent, ScanFailure, VhostScanResult
from .nginx_parser import load_vhosts
from .notify import Mailer
from .stack_detection import detect_stacks
from .state_store import StateStore

LOGGER = logging.getLogger(__name__)
SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "WARNING": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}


def _normalize_severity(value: str, category: str = "vulnerability") -> str:
    raw = str(value or "").upper()
    if raw in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", "INFO", "WARNING", "UNKNOWN"):
        if raw == "MODERATE":
            return "MEDIUM"
        return raw
    if raw in ("WARN",):
        return "WARNING"
    if category == "scan-failure":
        return "WARNING"
    return "UNKNOWN"


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

    def scan_once(self) -> Tuple[List[VhostScanResult], List[NotificationEvent]]:
        LOGGER.info("Starting scan cycle")
        vhosts = load_vhosts(self.config)
        LOGGER.info("Loaded %s nginx vhosts", len(vhosts))
        results = []
        notifications = []
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
                notifications.extend(self._build_issue_notifications(vhost.primary_server_name, stack_result))
                notifications.extend(self._build_failure_notifications(vhost.primary_server_name, stack_result.failures))
            notifications.extend(self._build_failure_notifications(vhost.primary_server_name, result.failures))
            results.append(result)
        LOGGER.info("Prepared %s notifications", len(notifications))
        for notification in self._prepare_notifications_for_delivery(notifications):
            LOGGER.info("Sending %s notification: %s", notification.category, notification.subject)
            self.mailer.send(notification)
        LOGGER.info("Scan cycle completed")
        return results, notifications

    def _prepare_notifications_for_delivery(self, notifications: List[NotificationEvent]) -> List[NotificationEvent]:
        if self.summary_only:
            if not notifications:
                return []
            return [self._build_digest_notification(self._sort_notifications(notifications), subject_all=True)]
        if len(notifications) <= self.max_emails_per_run:
            return self._sort_notifications(notifications)
        sorted_notifications = self._sort_notifications(notifications)
        direct_notifications = sorted_notifications[: self.max_emails_per_run]
        overflow = sorted_notifications[self.max_emails_per_run :]
        direct_notifications.append(self._build_digest_notification(overflow))
        LOGGER.warning(
            "Notification count %s exceeds per-run limit %s, sending %s direct alerts and one digest",
            len(notifications),
            self.max_emails_per_run,
            len(direct_notifications) - 1,
        )
        return direct_notifications

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
        highest = "INFO"
        for event in events:
            severity = str(event.metadata.get("severity", "UNKNOWN")).upper()
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
                highest = severity
        lines = [
            f"Hostname: {hostname}",
            f"Date: {now.isoformat()}",
            f"Events summarized: {len(events)}",
            f"Highest severity: {highest}",
            "Summary: additional alerts were grouped to avoid flooding the destination mailbox.",
            "Recommendation: inspect Cerberus logs and rerun a dry-run scan for the full detail.",
            "",
            "Included alerts:",
        ]
        for event in events:
            lines.append("- {}".format(event.subject))
        if subject_all:
            subject = "[Cerberus][ALERT][{}][{}] {} alerts in this scan".format(highest, hostname, len(events))
        else:
            subject = "[Cerberus][ALERT][{}][{}] {} additional alerts grouped".format(highest, hostname, len(events))
        return NotificationEvent(
            category="digest",
            fingerprint="digest:{}:{}".format(now.date().isoformat(), len(events)),
            subject=subject,
            body="\n".join(lines),
            created_at=now,
            metadata={"severity": highest, "events": len(events)},
        )

    def _build_issue_notifications(self, vhost_name: str, stack_result) -> List[NotificationEvent]:
        notifications = []
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        for issue in stack_result.issues:
            severity = _normalize_severity(issue.vulnerability.severity)
            payload = {
                "vhost": vhost_name,
                "stack": stack_result.stack.stack_name,
                "dependency": issue.dependency.name,
                "version": issue.dependency.version,
                "vuln_id": issue.vulnerability.vuln_id,
                "severity": severity,
            }
            fingerprint = f"issue:{vhost_name}:{stack_result.stack.stack_name}:{issue.dependency.name}:{issue.vulnerability.vuln_id}"
            if not self.state.should_alert(fingerprint, payload):
                continue
            body = "\n".join(
                [
                    f"Hostname: {hostname}",
                    f"Date: {now.isoformat()}",
                    f"Vhost: {vhost_name}",
                    f"Stack: {stack_result.stack.stack_name}",
                    f"Dependency: {issue.dependency.name}",
                    f"Detected version: {issue.dependency.version}",
                    f"CVE / Advisory: {issue.vulnerability.vuln_id}",
                    f"Severity: {severity}",
                    f"Summary: {issue.vulnerability.summary}",
                    f"Recommendation: Review upstream fix and upgrade the affected component.",
                ]
            )
            notifications.append(
                NotificationEvent(
                    category="vulnerability",
                    fingerprint=fingerprint,
                    subject=(
                        f"[Cerberus][ALERT][{severity}][{hostname}] "
                        f"{vhost_name} {issue.dependency.name} {issue.vulnerability.vuln_id}"
                    ),
                    body=body,
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
            severity = _normalize_severity("warning", category="scan-failure")
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
                    subject=f"[Cerberus][ALERT][{severity}][{hostname}] {scope} repeated scan failure: {failure.reason}",
                    body=body,
                    created_at=now,
                    metadata=payload,
                )
            )
        return notifications

    def send_test_mail(self) -> NotificationEvent:
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        event = NotificationEvent(
            category="test",
            fingerprint="test-mail",
            subject=f"[Cerberus][ALERT][INFO][{hostname}] Test notification",
            body="\n".join(
                [
                    f"Hostname: {hostname}",
                    f"Date: {now.isoformat()}",
                    "Vhost: test.example.internal",
                    "Stack: test",
                    "Dependency: demo-package",
                    "Detected version: 0.0.0",
                    "CVE / Advisory: TEST-0000",
                    "Severity: info",
                    "Summary: test notification from vhost-cve-monitor",
                    "Recommendation: no action required.",
                ]
            ),
            created_at=now,
            metadata={"severity": "INFO"},
        )
        self.mailer.send(event)
        return event

    def daemon_loop(self) -> None:
        interval = int(self.config["scanner"]["scan_interval_minutes"]) * 60
        while True:
            try:
                self.scan_once()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Unhandled exception during scan cycle")
            time.sleep(interval)
