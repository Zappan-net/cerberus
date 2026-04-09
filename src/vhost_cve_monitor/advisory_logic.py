from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence


SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "WARNING": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": -1,
}

STANDARD_VULN_RE = re.compile(r"(GHSA-[A-Za-z0-9-]+|CVE-\d{4}-\d+)")
SIMPLE_UPPER_BOUND_RE = re.compile(r"^\s*<?=?\s*v?([0-9][A-Za-z0-9._-]*)\s*$")


def normalize_severity(value: str, category: str = "vulnerability") -> str:
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


def strongest_severity(*values: str) -> str:
    best = "UNKNOWN"
    for value in values:
        candidate = normalize_severity(value)
        if SEVERITY_ORDER.get(candidate, -1) > SEVERITY_ORDER.get(best, -1):
            best = candidate
    return best


def canonical_advisory_id(vuln_id: str, aliases: Optional[Sequence[str]] = None) -> str:
    candidates = [str(vuln_id or "").strip()] + [str(alias).strip() for alias in aliases or []]
    for candidate in candidates:
        match = STANDARD_VULN_RE.search(candidate)
        if match:
            return match.group(1)
    for candidate in candidates:
        if candidate:
            return candidate
    return "UNKNOWN-ADVISORY"


def infer_first_safe_from_range(affected_range: str) -> Optional[str]:
    if not affected_range:
        return None
    parts = [part.strip() for part in str(affected_range).split("||")]
    first_safe = []
    for part in parts:
        if "<" not in part or ">=" in part or ">" in part:
            continue
        candidate = part.replace("<=", "").replace("<", "").strip()
        match = SIMPLE_UPPER_BOUND_RE.match(candidate)
        if match:
            first_safe.append(match.group(1))
    if not first_safe:
        return None
    return format_fixed_versions(first_safe)


def format_fixed_versions(versions: Iterable[str]) -> Optional[str]:
    cleaned = []
    for version in versions:
        value = str(version or "").strip()
        if not value:
            continue
        if value.startswith(">="):
            cleaned.append(value)
        else:
            cleaned.append(">={}".format(value) if value.startswith(" ") else ">= {}".format(value))
    if not cleaned:
        return None
    deduped = []
    for item in cleaned:
        if item not in deduped:
            deduped.append(item)
    if len(deduped) == 1:
        return deduped[0]
    return " or ".join(deduped)


def merge_fixed_versions(*values: Optional[str]) -> Optional[str]:
    parts: List[str] = []
    for value in values:
        if not value:
            continue
        for part in str(value).split(" or "):
            cleaned = part.strip()
            if cleaned and cleaned not in parts:
                parts.append(cleaned)
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return " or ".join(parts)


def build_recommendation(
    ecosystem: str,
    stack: str,
    package_name: str,
    installed_version: str,
    fixed_version: Optional[str],
    affected_range: Optional[str] = None,
) -> str:
    safe_target = fixed_version or infer_first_safe_from_range(affected_range)
    ecosystem_name = str(ecosystem or "").lower()
    if ecosystem_name == "npm":
        if safe_target:
            return (
                "Upgrade `{}` from {} to {}, refresh `package-lock.json`, and review "
                "`npm audit fix` output before redeploying."
            ).format(package_name, installed_version, safe_target)
        return (
            "No fixed version is known. Review the dependency tree for `{}`, apply any available "
            "upstream workaround, and monitor `npm audit` for a patched release."
        ).format(package_name)
    if ecosystem_name == "pypi":
        if safe_target:
            return (
                "Pin `{}` from {} to {}, update the requirements or lockfile, and rerun `pip-audit` "
                "before redeploying."
            ).format(package_name, installed_version, safe_target)
        return (
            "No fixed version is known. Review constraints for `{}`, check upstream advisories, and "
            "consider temporary pinning or compensating controls."
        ).format(package_name)
    if ecosystem_name == "packagist":
        if safe_target:
            return (
                "Update `{}` from {} to {} with `composer update {}`, review `composer.lock`, and "
                "redeploy only after validating dependency drift."
            ).format(package_name, installed_version, safe_target, package_name)
        return (
            "No fixed version is known. Review upstream guidance for `{}` and keep `composer audit` "
            "under watch until a patched release is available."
        ).format(package_name)
    if ecosystem_name == "go":
        if safe_target:
            return (
                "Upgrade `{}` from {} to {}, refresh the Go module graph, and verify the rebuilt "
                "service before rollout."
            ).format(package_name, installed_version, safe_target)
        return (
            "No fixed version is known. Review upstream guidance for `{}` and assess whether the "
            "affected code path can be disabled or isolated."
        ).format(package_name)
    if safe_target:
        return "Upgrade `{}` from {} to {} and redeploy after validating the affected service.".format(
            package_name, installed_version, safe_target
        )
    return (
        "No fixed version is known for `{}` on stack `{}`. Review upstream guidance and apply "
        "compensating controls if the affected path is exposed."
    ).format(package_name, stack)
