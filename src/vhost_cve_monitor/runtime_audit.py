"""Runtime inventory is separate from manifest audits and optional AI triage.

Never infer an interpreter from PATH. Debian source versions are queried as
Debian packages; upstream version ranges must not undo distributor backports.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import stat
import subprocess
import time
import urllib.request
from fnmatch import fnmatch
from pathlib import Path

from .advisory_logic import normalize_severity, severity_from_cvss, strongest_severity
from .models import AuditIssue, Dependency, ScanFailure, StackMatch, StackScanResult, Vulnerability
from .stack_detection import (
    _listening_tcp_inode, _loopback_proxy_port, _socket_inode_pid_map,
    _process_root_candidates,
)

LOGGER = logging.getLogger(__name__)
REPOSITORIES = {"php": "php/php-src", "node": "nodejs/node", "python": "python/cpython"}
MAX_FEED_BYTES = 4 * 1024 * 1024


def runtime_description(context):
    return "; ".join("{}={}".format(key, context[key]) for key in
                     ("kind", "version", "executable", "provenance", "package_version",
                      "association", "process_state", "assessment", "reachability") if context.get(key))


def _command(args, timeout=10):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                            cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C"}, check=False)
    if result.returncode or len(result.stdout) > MAX_FEED_BYTES:
        raise ValueError("runtime metadata command failed")
    return result.stdout.strip()


def version_in_range(version, expression):
    """Conservative stable-version comparator; unsupported grammar is NOT safe."""
    def number(value):
        if not re.fullmatch(r"v?\d+(?:\.\d+){0,2}", value):
            raise ValueError("unsupported runtime version/range")
        parts = tuple(int(x) for x in value.lstrip("v").split("."))
        return parts + (0,) * (3 - len(parts))
    current = number(version)
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("missing upstream range")
    alternatives = []
    for group in expression.split("||"):
        matches = []
        for clause in group.split(","):
            match = re.fullmatch(r"\s*(<=|>=|<|>|==|=)?\s*(v?\d+(?:\.\d+){0,2})\s*", clause)
            if not match:
                raise ValueError("unsupported upstream range")
            operator, value = match.groups()
            target = number(value)
            matches.append({"<": current < target, "<=": current <= target,
                            ">": current > target, ">=": current >= target,
                            "=": current == target, "==": current == target,
                            None: current == target}[operator])
        alternatives.append(all(matches))
    return any(alternatives)


def _unix_inode(endpoint):
    if not endpoint.startswith("unix:"):
        return None
    target = endpoint[5:].rstrip(":")
    for line in Path("/proc/net/unix").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) == 8 and fields[7] == target and fields[3] == "00010000":
            return fields[6]
    return None


def branch_records(records, version):
    """PHP/GitHub may publish one '< fixed' row per maintained release branch.

    Interpreting their union would mark a patched 8.2 as vulnerable because it
    is less than the 8.5 fix. Infer branch scope ONLY for this homogeneous shape;
    preserve general ranges unchanged. Older branches use the earliest available
    fixed branch (an upgrade, not a claim of a same-branch patch).
    """
    if len(records) < 2:
        return records, False
    packages = [record.get("package") for record in records]
    if any(package != packages[0] for package in packages):
        return records, False
    fixes = []
    for record in records:
        fixed = str(record.get("patched_versions") or "")
        if not re.fullmatch(r"\d+\.\d+\.\d+", fixed):
            return records, False
        if re.sub(r"\s", "", str(record.get("vulnerable_version_range"))) != "<" + fixed:
            return records, False
        fixes.append(tuple(int(x) for x in fixed.split(".")))
    if len({value[:2] for value in fixes}) != len(fixes):
        return records, False
    branch = tuple(int(x) for x in version.split(".")[:2])
    eligible = [(value, record) for value, record in zip(fixes, records) if value[:2] >= branch]
    return ([min(eligible, key=lambda item: item[0])[1]] if eligible else []), True


def discover_runtimes(vhost, config):
    """Return explicit bindings or executables owned by live local backends.

    No command lines/environments are exported. A socket configured in nginx
    is evidence of routing, not proof of internet reachability or successful use.
    """
    found = []
    for binding in config.get("runtime_audit", {}).get("bindings", []):
        if any(fnmatch(name, binding["vhost"]) for name in vhost.server_names):
            found.append({key: binding[key] for key in ("kind", "executable", "repository_path")})
            found[-1].update(association="administrator_binding", backend="configured", process_state="unverified")
    endpoints = [(item, "php") for item in vhost.fastcgi_passes]
    endpoints += [(item, None) for item in vhost.proxy_passes]
    inode_pids = _socket_inode_pid_map() if endpoints else {}
    failures = []
    for endpoint, expected in endpoints:
        try:
            port = _loopback_proxy_port(endpoint if expected is None else "http://" + endpoint)
            inode = _unix_inode(endpoint) if endpoint.startswith("unix:") else _listening_tcp_inode(port) if port else None
            pid = inode_pids.get(inode)
            if not pid:
                if expected and not any(item["kind"] == expected for item in found):
                    failures.append(ScanFailure("runtime", "runtime_not_identified", "PHP backend has no identifiable local process; configure an explicit binding if stopped or remote"))
                continue
            proc = Path("/proc") / pid
            executable = Path(os.readlink(str(proc / "exe")))
            # Reject deleted/replaced executables and different mount namespaces.
            if not executable.samefile(proc / "exe"):
                raise ValueError("process executable differs from host filesystem")
            name = executable.name
            kind = "php" if name.startswith("php") else "node" if name in {"node", "nodejs"} else "python" if name.startswith("python") else None
            if not kind or (expected and kind != expected):
                continue
            roots = [str(Path(p).parent) for p in vhost.php_script_paths] if kind == "php" else []
            roots = roots or [str(p) for p in _process_root_candidates(pid)]
            roots = roots or list(vhost.roots)
            for root in roots[:20] or [None]:
                found.append(dict(kind=kind, executable=str(executable), repository_path=root,
                                  association="listening_process", backend=endpoint, process_state="running"))
        except (OSError, ValueError):
            failures.append(ScanFailure("runtime", "runtime_not_identified", "Backend process metadata is unavailable or ambiguous"))
    unique = {(item["kind"], item["executable"], item["repository_path"]): item for item in found}
    return list(unique.values()), failures


def inspect_runtime(binding):
    executable = Path(binding["executable"])
    resolved = executable.resolve(strict=True)
    # Do not execute user-writable binaries or load app-specific startup hooks.
    for path in [resolved, *resolved.parents]:
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("runtime executable or parent is not administrator-controlled")
    kind = binding["kind"]
    args = {"php": [str(resolved), "-n", "-v"], "node": [str(resolved), "--version"],
            "python": [str(resolved), "-I", "-S", "--version"]}[kind]
    output = _command(args)
    pattern = {"php": r"^PHP (\d+\.\d+\.\d+)", "node": r"^v(\d+\.\d+\.\d+)",
               "python": r"^Python (\d+\.\d+\.\d+)"}[kind]
    match = re.search(pattern + r"(?=\s|$|-\d)", output)
    if not match:
        raise ValueError("unsupported runtime version output")
    if kind == "python" and "PyPy" in output:
        raise ValueError("only CPython releases are supported by the PSF advisory source")
    result = dict(binding, executable=str(resolved), version=match.group(1), provenance="upstream")
    # Distro revisions must be checked as source packages, never stripped to X.Y.Z.
    try:
        owner = _command(["dpkg-query", "-S", str(resolved)]).split(": ", 1)[0]
    except (OSError, ValueError, subprocess.SubprocessError):
        return result
    metadata = _command(["dpkg-query", "-W", "-f=${source:Package}\t${source:Version}\t${Maintainer}", owner]).split("\t")
    if len(metadata) != 3:
        raise ValueError("invalid package metadata")
    # Locally modified binaries cannot inherit the package's vulnerability status.
    verification = _command(["dpkg", "--verify", owner])
    if any(line.endswith(" " + str(resolved)) for line in verification.splitlines()):
        raise ValueError("installed runtime differs from its package")
    if "debian.org" not in metadata[2].lower():
        result.update(provenance="third-party", package_version=metadata[1])
        return result
    release = dict(re.findall(r'^([A-Z_]+)=["\']?([^"\'\n]+)', Path('/etc/os-release').read_text(), re.M))
    if release.get("ID") != "debian":
        raise ValueError("distribution advisory source unsupported")
    result.update(provenance="debian", package=metadata[0], package_version=metadata[1],
                  ecosystem="Debian:" + release["VERSION_ID"], distribution_release=release.get("VERSION_CODENAME"))
    return result


class RuntimeAuditor:
    def __init__(self, config, cve_db, allow_network):
        self.config, self.cve_db, self.allow_network = config, cve_db, allow_network
        self.settings = config.get("runtime_audit", {})
        self.memo = {}

    def _debian_status(self, runtime):
        key = "debian-security-tracker"
        path = self.config["state"]["database_path"]
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS runtime_advisory_cache (source TEXT PRIMARY KEY, fetched_at REAL NOT NULL, payload TEXT NOT NULL)")
            row = db.execute("SELECT fetched_at,payload FROM runtime_advisory_cache WHERE source=?", (key,)).fetchone()
        if row and time.time() - row[0] < self.settings.get("cache_ttl_hours", 24) * 3600:
            return json.loads(row[1]).get(runtime["package"], {})
        if not self.allow_network:
            raise ValueError("Debian tracker cache unavailable or expired")
        with urllib.request.urlopen("https://security-tracker.debian.org/tracker/data/json",
                                    timeout=self.config["scanner"]["network_timeout_seconds"]) as response:
            raw = response.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("Debian tracker response too large")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get(runtime["package"], {}), dict):
            raise ValueError("invalid Debian tracker response")
        with sqlite3.connect(path) as db:
            db.execute("INSERT OR REPLACE INTO runtime_advisory_cache VALUES (?,?,?)", (key, time.time(), json.dumps(payload)))
        return payload.get(runtime["package"], {})

    @staticmethod
    def _distributor_fixed(runtime, entry):
        release = (entry.get("releases") or {}).get(runtime.get("distribution_release"), {})
        fixed = release.get("fixed_version")
        if not fixed:
            return False
        if fixed == "0":
            return True  # Debian uses 0 for versions not affected by this CVE.
        result = subprocess.run(["/usr/bin/dpkg", "--compare-versions", runtime["package_version"], "ge", fixed],
                                capture_output=True, timeout=10, check=False)
        if result.returncode not in (0, 1):
            raise ValueError("invalid Debian version comparison")
        return result.returncode == 0

    def _feed(self, kind):
        """Additive cache table; no rewriting of notification/history tables."""
        key = REPOSITORIES[kind]
        path = self.config["state"]["database_path"]
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS runtime_advisory_cache (source TEXT PRIMARY KEY, fetched_at REAL NOT NULL, payload TEXT NOT NULL)")
            row = db.execute("SELECT fetched_at,payload FROM runtime_advisory_cache WHERE source=?", (key,)).fetchone()
        if row and time.time() - row[0] < self.settings.get("cache_ttl_hours", 24) * 3600:
            return json.loads(row[1])
        if not self.allow_network:
            if row:
                raise ValueError("runtime advisory cache expired; offline coverage incomplete")
            raise ValueError("runtime advisory cache missing; offline coverage incomplete")
        records = []
        for page in range(1, 11):
            url = "https://api.github.com/repos/{}/security-advisories?per_page=100&page={}".format(key, page)
            request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "Cerberus-runtime-audit"})
            with urllib.request.urlopen(request, timeout=self.config["scanner"]["network_timeout_seconds"]) as response:
                raw = response.read(MAX_FEED_BYTES + 1)
            if len(raw) > MAX_FEED_BYTES:
                raise ValueError("runtime advisory response too large")
            batch = json.loads(raw)
            if not isinstance(batch, list) or not all(isinstance(x, dict) for x in batch):
                raise ValueError("invalid runtime advisory response")
            records.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise ValueError("runtime advisory pagination limit reached")
        with sqlite3.connect(path) as db:
            db.execute("INSERT OR REPLACE INTO runtime_advisory_cache VALUES (?,?,?)", (key, time.time(), json.dumps(records)))
        return records

    def _python_feed(self, version):
        """Query OSV for the official CPython release commit, not PyPI packages.

        PSF records use Git commit ranges. A version-only comparison against
        those ranges would invent findings; OSV resolves the tagged commit.
        """
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("unsupported CPython release version")
        key = "psf-osv-cpython:" + version
        path = self.config["state"]["database_path"]
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS runtime_advisory_cache (source TEXT PRIMARY KEY, fetched_at REAL NOT NULL, payload TEXT NOT NULL)")
            row = db.execute("SELECT fetched_at,payload FROM runtime_advisory_cache WHERE source=?", (key,)).fetchone()
        if row and time.time() - row[0] < self.settings.get("cache_ttl_hours", 24) * 3600:
            return json.loads(row[1])
        if not self.allow_network:
            raise ValueError("CPython PSF advisory cache missing or expired; offline coverage incomplete")

        timeout = self.config["scanner"]["network_timeout_seconds"]
        tag_url = "https://api.github.com/repos/python/cpython/git/ref/tags/v" + version
        request = urllib.request.Request(tag_url, headers={"Accept": "application/vnd.github+json", "User-Agent": "Cerberus-runtime-audit"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_FEED_BYTES + 1)
        if len(raw) > MAX_FEED_BYTES:
            raise ValueError("CPython tag response too large")
        reference = json.loads(raw)
        target = reference.get("object") or {}
        if target.get("type") == "tag":
            tag_sha = target.get("sha")
            if not isinstance(tag_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", tag_sha):
                raise ValueError("invalid CPython tag reference")
            request = urllib.request.Request("https://api.github.com/repos/python/cpython/git/tags/" + tag_sha,
                                             headers={"Accept": "application/vnd.github+json", "User-Agent": "Cerberus-runtime-audit"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(MAX_FEED_BYTES + 1)
            if len(raw) > MAX_FEED_BYTES:
                raise ValueError("CPython annotated tag response too large")
            target = (json.loads(raw).get("object") or {})
        if target.get("type") != "commit" or not re.fullmatch(r"[0-9a-f]{40}", str(target.get("sha") or "")):
            raise ValueError("CPython release tag has no verified commit")

        request = urllib.request.Request("https://api.osv.dev/v1/query",
                                         data=json.dumps({"commit": target["sha"]}).encode("utf-8"),
                                         headers={"Content-Type": "application/json", "User-Agent": "Cerberus-runtime-audit"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_FEED_BYTES + 1)
        if len(raw) > MAX_FEED_BYTES:
            raise ValueError("CPython OSV response too large")
        payload = json.loads(raw)
        records = payload.get("vulns") if isinstance(payload, dict) else None
        if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
            raise ValueError("invalid CPython OSV response")
        if payload.get("next_page_token"):
            raise ValueError("CPython OSV response is paginated; coverage incomplete")
        # OSV also returns CVE copies of PSF findings. Keep only relevant pairs.
        psf = [record for record in records if re.fullmatch(r"PSF-\d{4}-\d+", str(record.get("id") or ""))]
        cve_ids = {alias for record in psf for alias in record.get("aliases", [])
                   if isinstance(alias, str) and re.fullmatch(r"CVE-\d{4}-\d+", alias)}
        selected = psf + [record for record in records if record.get("id") in cve_ids]
        if not psf:
            raise ValueError("no PSF advisories returned for the CPython release")
        with sqlite3.connect(path) as db:
            db.execute("INSERT OR REPLACE INTO runtime_advisory_cache VALUES (?,?,?)", (key, time.time(), json.dumps(selected)))
        return selected

    @staticmethod
    def _osv_severity(record):
        severity = normalize_severity((record.get("database_specific") or {}).get("severity"))
        for entry in record.get("severity") or []:
            if isinstance(entry, dict):
                severity = strongest_severity(severity, severity_from_cvss(entry.get("score")))
        return severity

    def _python_upstream(self, runtime, dependency):
        records = self._python_feed(runtime["version"])
        cves = {record["id"]: record for record in records if str(record.get("id", "")).startswith("CVE-")}
        issues = []
        for record in records:
            psf_id = str(record.get("id") or "")
            if not re.fullmatch(r"PSF-\d{4}-\d+", psf_id) or record.get("withdrawn"):
                continue
            aliases = [alias for alias in record.get("aliases") or []
                       if isinstance(alias, str) and re.fullmatch(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)", alias)]
            cve_id = next((alias for alias in aliases if alias.startswith("CVE-")), None)
            sibling = cves.get(cve_id, {})
            severity = strongest_severity(self._osv_severity(record), self._osv_severity(sibling))
            details = record.get("details") or sibling.get("details") or ""
            summary = record.get("summary") or sibling.get("summary") or details.split("\n", 1)[0][:220] or "CPython security advisory"
            vulnerability = Vulnerability(
                vuln_id=cve_id or psf_id, source="psf-osv-runtime", severity=severity,
                summary=summary, details=details, published=record.get("published"),
                modified=record.get("modified"), package_name=dependency.name,
                ecosystem=dependency.ecosystem, affected_version=dependency.version,
                aliases=[psf_id] + aliases,
                references=["https://github.com/psf/advisory-database/blob/main/advisories/python/" + psf_id + ".json"],
            )
            context = dict(runtime, assessment="upstream_release_tag_match", advisory_source="PSF via OSV")
            issues.append(AuditIssue(dependency, vulnerability, "runtime-psf-osv", context))
        return issues, []

    def _upstream(self, runtime, dependency):
        if runtime["kind"] == "python":
            return self._python_upstream(runtime, dependency)
        issues, failures = [], []
        feed = self._feed(runtime["kind"])
        if not feed:
            failures.append(ScanFailure("runtime", "runtime_advisory_coverage_unknown", "Official repository has no published advisories; this is not proof of absence of runtime CVEs"))
        for item in feed:
            if item.get("withdrawn_at"):
                continue
            advisory = item.get("cve_id") or item.get("ghsa_id")
            if not advisory:
                continue
            rows = item.get("vulnerabilities") or []
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                raise ValueError("invalid upstream vulnerability records")
            rows, inferred = branch_records(rows, runtime["version"])
            for affected in rows:
                # Official repository advisories can also describe other packages.
                package_info = affected.get("package") or {}
                if not isinstance(package_info, dict):
                    raise ValueError("invalid upstream package")
                package = str(package_info.get("name", "")).lower()
                accepted = {REPOSITORIES[runtime["kind"]].lower(), REPOSITORIES[runtime["kind"]].split("/")[-1], runtime["kind"],
                            {"php": "php", "node": "node.js", "python": "cpython"}[runtime["kind"]]}
                if package not in accepted:
                    failures.append(ScanFailure("runtime", "runtime_advisory_unmapped", "Official advisory package not mapped: " + str(advisory)))
                    continue
                expression = affected.get("vulnerable_version_range")
                try:
                    applicable = version_in_range(runtime["version"], expression)
                except ValueError:
                    failures.append(ScanFailure("runtime", "runtime_advisory_range_unknown", "Unsupported range for " + str(advisory)))
                    continue
                if not applicable:
                    continue
                vulnerability = Vulnerability(
                    vuln_id=advisory, source="github-runtime", severity=normalize_severity(item.get("severity")),
                    summary=item.get("summary") or "Runtime advisory", details=item.get("description") or "",
                    published=item.get("published_at"), modified=item.get("updated_at"), package_name=dependency.name,
                    ecosystem=dependency.ecosystem, affected_version=dependency.version,
                    fixed_version=affected.get("patched_versions"), affected_range=expression,
                    aliases=[value for value in [item.get("cve_id"), item.get("ghsa_id")] if value],
                    references=[item["html_url"]] if item.get("html_url") else [],
                )
                context = dict(runtime)
                if inferred:
                    context["range_selection"] = "release_branch_inferred_from_parallel_fixed_versions"
                issues.append(AuditIssue(dependency, vulnerability, "runtime-upstream", context))
        return issues, failures

    def scan(self, vhost):
        if not self.settings.get("enabled", True):
            return []
        try:
            bindings, failures = discover_runtimes(vhost, self.config)
        except (OSError, ValueError, KeyError):
            bindings = []
            failures = [ScanFailure("runtime", "runtime_not_identified", "Runtime inventory unavailable; check process permissions and bindings")]
        results = []
        if failures:
            results.append(StackScanResult(StackMatch("runtime", "low", ["runtime coverage incomplete"]), failures=failures))
        for binding in bindings:
            root = binding.get("repository_path")
            stack = StackMatch(binding["kind"] + "-runtime", "high", [binding["association"]], root)
            result = StackScanResult(stack)
            try:
                key = (binding["kind"], binding["executable"])
                if key not in self.memo:
                    self.memo[key] = inspect_runtime(binding)
                runtime = dict(self.memo[key], repository_path=root, backend=binding["backend"],
                               association=binding["association"], process_state=binding["process_state"],
                               reachability="not_verified", nginx_config=vhost.file_path)
                dependency = Dependency(runtime.get("ecosystem", "Runtime"), runtime.get("package", binding["kind"]),
                                        runtime.get("package_version", runtime["version"]), root or vhost.file_path)
                result.dependencies.append(dependency)
                if runtime["provenance"] == "debian":
                    vulnerabilities = self.cve_db.ensure_fresh(dependency, allow_network=self.allow_network)
                    try:
                        statuses = self._debian_status(runtime)
                    except (OSError, ValueError):
                        statuses = {}
                        result.failures.append(ScanFailure("runtime", "runtime_distribution_coverage", "Debian tracker unavailable; upstream candidates require distributor confirmation"))
                    result.issues.extend(AuditIssue(dependency, v, "runtime-debian", dict(runtime, assessment="distribution_advisory"))
                                         for v in vulnerabilities if not self._distributor_fixed(runtime, statuses.get(v.vuln_id, {})))
                    # Fresh upstream notices can precede distributor/OSV publication.
                    # Keep them explicitly provisional; never resurrect a known backport.
                    candidates, gaps = self._upstream(runtime, dependency)
                    result.failures.extend(gaps)
                    known = {v.vulnerability.vuln_id for v in result.issues}
                    for issue in candidates:
                        identifier = issue.vulnerability.vuln_id
                        for existing in result.issues:
                            if identifier == existing.vulnerability.vuln_id:
                                existing.vulnerability.severity = strongest_severity(existing.vulnerability.severity, issue.vulnerability.severity)
                                existing.vulnerability.aliases = sorted(set(existing.vulnerability.aliases + issue.vulnerability.aliases))
                        if identifier not in known and not self._distributor_fixed(runtime, statuses.get(identifier, {})):
                            issue.runtime_context["assessment"] = "upstream_match_distributor_status_unconfirmed"
                            issue.vulnerability.fixed_version = None  # Upstream fix is not a Debian package version.
                            issue.vulnerability.details = "Distributor status unconfirmed. " + issue.vulnerability.details
                            result.issues.append(issue)
                else:
                    result.issues, result.failures = self._upstream(runtime, dependency)
                    for issue in result.issues:
                        if runtime["provenance"] != "upstream":
                            issue.runtime_context["assessment"] = "upstream_match_distributor_status_unconfirmed"
                        else:
                            issue.runtime_context.setdefault("assessment", "upstream_version_match")
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, sqlite3.Error) as exc:
                LOGGER.warning("Runtime audit incomplete (%s)", type(exc).__name__)
                result.failures.append(ScanFailure("runtime", "runtime_audit_incomplete", str(exc) if isinstance(exc, ValueError) else type(exc).__name__))
            results.append(result)
        return results
