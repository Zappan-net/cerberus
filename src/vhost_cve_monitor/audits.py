from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List

from .collectors import (
    collect_composer_dependencies,
    collect_gitea_dependencies,
    collect_node_dependencies,
    collect_python_dependencies,
)
from .cve_db import CVEDatabase
from .models import AuditIssue, Dependency, ScanFailure, StackMatch, StackScanResult
from .subprocess_utils import command_exists, run_command

LOGGER = logging.getLogger(__name__)


def _local_db_issues(
    dependencies: List[Dependency],
    cve_db: CVEDatabase,
    allow_network: bool,
) -> List[AuditIssue]:
    issues = []
    LOGGER.info("Correlating %s dependencies with local CVE cache", len(dependencies))
    for dependency in dependencies:
        for vulnerability in cve_db.ensure_fresh(dependency, allow_network=allow_network):
            issues.append(
                AuditIssue(
                    dependency=dependency,
                    vulnerability=vulnerability,
                    detection_method="osv-cache",
                )
            )
    return issues


def scan_stack(
    stack: StackMatch,
    cve_db: CVEDatabase,
    timeout: int,
    allow_network: bool,
) -> StackScanResult:
    if stack.stack_name == "nodejs":
        return _scan_node(stack, cve_db, timeout, allow_network)
    if stack.stack_name == "php-composer":
        return _scan_composer(stack, cve_db, timeout, allow_network)
    if stack.stack_name == "python":
        return _scan_python(stack, cve_db, timeout, allow_network)
    if stack.stack_name == "gitea":
        return _scan_gitea(stack, cve_db, timeout, allow_network)
    return StackScanResult(
        stack=stack,
        failures=[ScanFailure(scope=stack.stack_name, reason="unsupported_stack")],
    )


def _scan_node(stack: StackMatch, cve_db: CVEDatabase, timeout: int, allow_network: bool) -> StackScanResult:
    LOGGER.info("Scanning Node.js stack at %s", stack.root_path or "unknown")
    dependencies, failures = collect_node_dependencies(stack)
    LOGGER.info("Collected %s Node.js dependencies from %s", len(dependencies), stack.root_path or "unknown")
    issues = _local_db_issues(dependencies, cve_db, allow_network)
    audit_commands = []
    root = Path(stack.root_path) if stack.root_path else None
    if root and command_exists("npm") and (root / "package-lock.json").exists():
        LOGGER.info("Running npm audit in %s", root)
        result = run_command(["npm", "audit", "--json", "--omit=dev"], timeout=timeout, cwd=root)
        audit_commands.append("npm audit --json --omit=dev")
        if result.returncode in (0, 1):
            payload = result.json_stdout()
            if isinstance(payload, dict):
                issues.extend(_parse_npm_audit(payload, dependencies))
        else:
            failures.append(ScanFailure(scope="nodejs", reason="npm_audit_failed", detail=result.stderr.strip()))
    else:
        LOGGER.info("Skipping npm audit for %s: npm missing or package-lock.json absent", stack.root_path or "unknown")
        failures.append(ScanFailure(scope="nodejs", reason="npm_audit_unavailable", detail=stack.root_path))
    return StackScanResult(
        stack=stack,
        dependencies=dependencies,
        issues=_dedupe_issues(issues),
        failures=failures,
        audit_commands=audit_commands,
    )


def _parse_npm_audit(payload: Dict, dependencies: List[Dependency]) -> List[AuditIssue]:
    issues = []
    name_to_dependency = {dep.name: dep for dep in dependencies}
    vulnerabilities = payload.get("vulnerabilities") or {}
    for package_name, vuln in vulnerabilities.items():
        dependency = name_to_dependency.get(package_name)
        if not dependency:
            continue
        via_entries = vuln.get("via") or []
        for entry in via_entries:
            if not isinstance(entry, dict):
                continue
            vuln_id = entry.get("source") or entry.get("url") or f"npm-{package_name}"
            issues.append(
                AuditIssue(
                    dependency=dependency,
                    detection_method="npm-audit",
                    vulnerability=_build_runtime_vulnerability(
                        dependency,
                        vuln_id=str(vuln_id),
                        severity=str(entry.get("severity", "UNKNOWN")).upper(),
                        summary=str(entry.get("title", "npm audit finding")),
                        details=str(entry.get("url", "")),
                    ),
                )
            )
    return issues


def _scan_composer(stack: StackMatch, cve_db: CVEDatabase, timeout: int, allow_network: bool) -> StackScanResult:
    LOGGER.info("Scanning Composer stack at %s", stack.root_path or "unknown")
    dependencies, failures = collect_composer_dependencies(stack)
    LOGGER.info("Collected %s Composer dependencies from %s", len(dependencies), stack.root_path or "unknown")
    issues = _local_db_issues(dependencies, cve_db, allow_network)
    audit_commands = []
    root = Path(stack.root_path) if stack.root_path else None
    if root and command_exists("composer") and (root / "composer.lock").exists():
        LOGGER.info("Running composer audit in %s", root)
        result = run_command(["composer", "audit", "--format=json", "--locked"], timeout=timeout, cwd=root)
        audit_commands.append("composer audit --format=json --locked")
        if result.returncode in (0, 1):
            try:
                payload = json.loads(result.stdout or "{}")
            except json.JSONDecodeError:
                payload = {}
            issues.extend(_parse_composer_audit(payload, dependencies))
        else:
            failures.append(ScanFailure(scope="php-composer", reason="composer_audit_failed", detail=result.stderr.strip()))
    else:
        LOGGER.info("Skipping composer audit for %s: composer missing or composer.lock absent", stack.root_path or "unknown")
        failures.append(ScanFailure(scope="php-composer", reason="composer_audit_unavailable", detail=stack.root_path))
    return StackScanResult(
        stack=stack,
        dependencies=dependencies,
        issues=_dedupe_issues(issues),
        failures=failures,
        audit_commands=audit_commands,
    )


def _parse_composer_audit(payload: Dict, dependencies: List[Dependency]) -> List[AuditIssue]:
    issues = []
    name_to_dependency = {dep.name: dep for dep in dependencies}
    for advisory in payload.get("advisories", []):
        package_name = advisory.get("packageName")
        dependency = name_to_dependency.get(package_name)
        if not dependency:
            continue
        issues.append(
            AuditIssue(
                dependency=dependency,
                detection_method="composer-audit",
                vulnerability=_build_runtime_vulnerability(
                    dependency,
                    vuln_id=str(advisory.get("advisoryId", package_name)),
                    severity=str(advisory.get("severity", "UNKNOWN")).upper(),
                    summary=str(advisory.get("title", "composer audit finding")),
                    details=str(advisory.get("cve") or advisory.get("link") or ""),
                ),
            )
        )
    return issues


def _scan_python(stack: StackMatch, cve_db: CVEDatabase, timeout: int, allow_network: bool) -> StackScanResult:
    LOGGER.info("Scanning Python stack at %s", stack.root_path or "unknown")
    dependencies, failures = collect_python_dependencies(stack, timeout)
    LOGGER.info("Collected %s Python dependencies from %s", len(dependencies), stack.root_path or "unknown")
    issues = _local_db_issues(dependencies, cve_db, allow_network)
    audit_commands = []
    root = Path(stack.root_path) if stack.root_path else None
    requirements_path = root / "requirements.txt" if root else None
    if requirements_path and requirements_path.exists() and command_exists("pip-audit"):
        LOGGER.info("Running pip-audit against %s", requirements_path)
        result = run_command(["pip-audit", "-r", str(requirements_path), "--format", "json"], timeout=timeout, cwd=root)
        audit_commands.append(f"pip-audit -r {requirements_path} --format json")
        if result.returncode in (0, 1):
            payload = result.json_stdout()
            if isinstance(payload, list):
                issues.extend(_parse_pip_audit(payload, dependencies))
        else:
            failures.append(ScanFailure(scope="python", reason="pip_audit_failed", detail=result.stderr.strip()))
    else:
        LOGGER.info("Skipping pip-audit for %s: pip-audit missing or requirements.txt absent", stack.root_path or "unknown")
        failures.append(ScanFailure(scope="python", reason="pip_audit_unavailable", detail=stack.root_path))
    return StackScanResult(
        stack=stack,
        dependencies=dependencies,
        issues=_dedupe_issues(issues),
        failures=failures,
        audit_commands=audit_commands,
    )


def _parse_pip_audit(payload: List[Dict], dependencies: List[Dependency]) -> List[AuditIssue]:
    issues = []
    name_to_dependency = {dep.name.lower(): dep for dep in dependencies}
    for item in payload:
        dependency = name_to_dependency.get(str(item.get("name", "")).lower())
        if not dependency:
            continue
        for vuln in item.get("vulns", []):
            issues.append(
                AuditIssue(
                    dependency=dependency,
                    detection_method="pip-audit",
                    vulnerability=_build_runtime_vulnerability(
                        dependency,
                        vuln_id=str(vuln.get("id", dependency.name)),
                        severity="UNKNOWN",
                        summary=str(vuln.get("description", "pip-audit finding")),
                        details=str(vuln.get("fix_versions", "")),
                    ),
                )
            )
    return issues


def _scan_gitea(stack: StackMatch, cve_db: CVEDatabase, timeout: int, allow_network: bool) -> StackScanResult:
    LOGGER.info("Scanning Gitea stack at %s", stack.root_path or "unknown")
    dependencies, failures = collect_gitea_dependencies(stack, timeout)
    LOGGER.info("Collected %s Gitea dependencies from %s", len(dependencies), stack.root_path or "unknown")
    issues = _local_db_issues(dependencies, cve_db, allow_network)
    return StackScanResult(
        stack=stack,
        dependencies=dependencies,
        issues=_dedupe_issues(issues),
        failures=failures,
        audit_commands=[],
    )


def _build_runtime_vulnerability(
    dependency: Dependency,
    vuln_id: str,
    severity: str,
    summary: str,
    details: str,
):
    from .models import Vulnerability

    return Vulnerability(
        vuln_id=vuln_id,
        source="runtime-audit",
        severity=severity,
        summary=summary,
        details=details,
        published=None,
        modified=None,
        package_name=dependency.name,
        ecosystem=dependency.ecosystem,
        affected_version=dependency.version,
        references=[],
        aliases=[],
    )


def _dedupe_issues(issues: List[AuditIssue]) -> List[AuditIssue]:
    deduped = {}
    for issue in issues:
        key = (
            issue.dependency.name.lower(),
            issue.dependency.version,
            issue.vulnerability.vuln_id,
        )
        if key not in deduped:
            deduped[key] = issue
    return list(deduped.values())
