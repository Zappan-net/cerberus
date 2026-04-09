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
CVSS_VECTOR_RE = re.compile(r"^CVSS:(3\.[01])/([A-Z]{1,3}:[A-Z0-9]/?)+$")

CVSS_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
CVSS_V3_AC = {"L": 0.77, "H": 0.44}
CVSS_V3_UI = {"N": 0.85, "R": 0.62}
CVSS_V3_S = {"U": "U", "C": "C"}
CVSS_V3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
CVSS_V3_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


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


def _round_up_cvss(score: float) -> float:
    return int(score * 10 + 0.000001 + 0.999999) / 10.0


def severity_from_cvss(value: Optional[str]) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "UNKNOWN"
    normalized = normalize_severity(raw)
    if normalized != "UNKNOWN":
        return normalized
    try:
        numeric = float(raw)
    except ValueError:
        numeric = None
    if numeric is not None:
        return severity_from_cvss_score(numeric)
    if raw.upper().startswith("CVSS:3."):
        score = _cvss_v3_base_score(raw)
        if score is None:
            return "UNKNOWN"
        return severity_from_cvss_score(score)
    return "UNKNOWN"


def severity_from_cvss_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _cvss_v3_base_score(vector: str) -> Optional[float]:
    raw = str(vector or "").strip().upper()
    if not raw.startswith("CVSS:3."):
        return None
    try:
        parts = raw.split("/")
        metrics = {}
        for part in parts[1:]:
            key, value = part.split(":", 1)
            metrics[key] = value
        scope = CVSS_V3_S[metrics["S"]]
        impact_sub_score = 1 - (
            (1 - CVSS_V3_CIA[metrics["C"]])
            * (1 - CVSS_V3_CIA[metrics["I"]])
            * (1 - CVSS_V3_CIA[metrics["A"]])
        )
        if scope == "U":
            impact = 6.42 * impact_sub_score
        else:
            impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * pow(impact_sub_score - 0.02, 15)
        exploitability = 8.22 * CVSS_V3_AV[metrics["AV"]] * CVSS_V3_AC[metrics["AC"]] * CVSS_V3_PR[scope][metrics["PR"]] * CVSS_V3_UI[metrics["UI"]]
        if impact <= 0:
            return 0.0
        if scope == "U":
            return _round_up_cvss(min(impact + exploitability, 10))
        return _round_up_cvss(min(1.08 * (impact + exploitability), 10))
    except (KeyError, ValueError, ZeroDivisionError):
        return None


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
    usage_warning = (
        " Verify whether `{}` is used at runtime or only during build/test before applying a broad upgrade."
    ).format(package_name)
    if ecosystem_name == "npm":
        if safe_target:
            return (
                "Upgrade `{}` from {} to {} with `npm install {package}@\"{target}\"`, refresh "
                "`package-lock.json`, and use `npm audit fix` only after reviewing the resulting dependency drift.{}"
            ).format(
                package_name,
                installed_version,
                safe_target,
                usage_warning,
                package=package_name,
                target=safe_target,
            )
        return (
            "No fixed version is known. Review the dependency tree for `{}`, apply any available "
            "upstream workaround, and monitor `npm audit` for a patched release.{}"
        ).format(package_name, usage_warning)
    if ecosystem_name == "pypi":
        if safe_target:
            return (
                "Upgrade `{}` from {} to {} with `pip install -U {package}{target_spec}`, update the "
                "requirements or lockfile, and rerun `pip-audit` before redeploying.{}"
            ).format(
                package_name,
                installed_version,
                safe_target,
                usage_warning,
                package=package_name,
                target_spec=safe_target.replace(" ", ""),
            )
        return (
            "No fixed version is known. Review constraints for `{}`, check upstream advisories, and "
            "consider temporary pinning or compensating controls.{}"
        ).format(package_name, usage_warning)
    if ecosystem_name == "packagist":
        if safe_target:
            return (
                "Update `{}` from {} to {} with `composer update {}`, review `composer.lock`, and "
                "redeploy only after validating dependency drift.{}"
            ).format(package_name, installed_version, safe_target, package_name, usage_warning)
        return (
            "No fixed version is known. Review upstream guidance for `{}` and keep `composer audit` "
            "under watch until a patched release is available.{}"
        ).format(package_name, usage_warning)
    if ecosystem_name == "go":
        if safe_target:
            return (
                "Upgrade `{}` from {} to {} with `go get {package}@{target}`, refresh the Go module "
                "graph, and verify the rebuilt service before rollout.{}"
            ).format(
                package_name,
                installed_version,
                safe_target,
                usage_warning,
                package=package_name,
                target=safe_target.replace(">= ", "").replace(">=", ""),
            )
        return (
            "No fixed version is known. Review upstream guidance for `{}` and assess whether the "
            "affected code path can be disabled or isolated.{}"
        ).format(package_name, usage_warning)
    if safe_target:
        return (
            "Upgrade `{}` from {} to {} and redeploy after validating the affected service.{}"
        ).format(package_name, installed_version, safe_target, usage_warning)
    return (
        "No fixed version is known for `{}` on stack `{}`. Review upstream guidance and apply "
        "compensating controls if the affected path is exposed.{}"
    ).format(package_name, stack, usage_warning)
