import os
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.audits import _scan_node
from vhost_cve_monitor.audits import _npm_dependency_audit_not_applicable, _scan_python
from vhost_cve_monitor.audits import _normalize_npm_vuln_id
from vhost_cve_monitor.audits import _parse_composer_audit
from vhost_cve_monitor.audits import _parse_npm_audit
from vhost_cve_monitor.audits import _parse_pip_audit
from vhost_cve_monitor.models import Dependency, StackMatch
from vhost_cve_monitor.subprocess_utils import CommandResult


class AuditsTestCase(unittest.TestCase):
    def test_dependency_free_node_project_does_not_warn_or_run_audit(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text('{"name":"example-api","type":"module"}')
            stack = StackMatch("nodejs", "high", [], tmp)
            with patch("vhost_cve_monitor.audits._local_db_issues", return_value=[]), \
                 patch("vhost_cve_monitor.audits.run_command") as run:
                result = _scan_node(stack, None, 1, False)
            self.assertEqual(result.failures, [])
            run.assert_not_called()

    def test_missing_lock_with_declared_dependencies_remains_a_warning(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "workspaces"):
                (root / "package.json").write_text(json.dumps({key: {"example": "1.0.0"}}))
                self.assertFalse(_npm_dependency_audit_not_applicable(root))
            (root / "package.json").write_text('{"dependencies":{"example":"1.0.0"}}')
            with patch("vhost_cve_monitor.audits._local_db_issues", return_value=[]), \
                 patch("vhost_cve_monitor.audits.command_exists", return_value=True):
                result = _scan_node(StackMatch("nodejs", "high", [], tmp), None, 1, False)
            self.assertEqual(result.failures[0].reason, "npm_audit_unavailable")
            self.assertIn("package-lock.json absent", result.failures[0].detail)

    def test_unreadable_invalid_or_existing_dependency_tree_is_not_silenced(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertFalse(_npm_dependency_audit_not_applicable(root))
            (root / "package.json").write_text("invalid")
            self.assertFalse(_npm_dependency_audit_not_applicable(root))
            (root / "package.json").write_text("{}")
            (root / "node_modules").mkdir()
            self.assertFalse(_npm_dependency_audit_not_applicable(root))

    def test_missing_pip_audit_has_explicit_diagnostic(self):
        with TemporaryDirectory() as tmp:
            (Path(tmp) / "requirements.txt").write_text("")
            with patch("vhost_cve_monitor.audits.collect_python_dependencies", return_value=([], [])), \
                 patch("vhost_cve_monitor.audits.command_exists", return_value=False):
                result = _scan_python(StackMatch("python", "high", [], tmp), None, 1, False)
            self.assertEqual(result.failures[0].detail, "pip-audit executable not found in service PATH")

    def test_npm_advisory_severity_overrides_package_aggregate(self):
        dependencies = [Dependency("npm", "sample", "1.0", "/srv/app/package-lock.json", 1)]
        entries = [{"source": advisory, "severity": "moderate"}
                   for advisory in ("CVE-2026-102277", "CVE-2026-100699")]
        entries += [{"source": "CVE-2026-11111"}, {"source": "CVE-2026-11112", "severity": "low"}]
        payload = {"vulnerabilities": {"sample": {"severity": "high", "via": entries}}}
        issues = _parse_npm_audit(payload, dependencies)
        self.assertEqual([issue.vulnerability.severity for issue in issues], ["MEDIUM", "MEDIUM", "HIGH", "LOW"])

    def test_normalize_npm_vuln_id_prefers_standard_aliases(self) -> None:
        entry = {
            "source": 1115806,
            "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        }

        self.assertEqual(_normalize_npm_vuln_id(entry, "lodash"), "GHSA-35jh-r3h4-6jhm")

    def test_normalize_npm_vuln_id_prefixes_numeric_npm_advisory(self) -> None:
        entry = {
            "source": 1115810,
            "url": "https://npmjs.com/advisories/1115810",
        }

        self.assertEqual(_normalize_npm_vuln_id(entry, "lodash"), "NPM-ADVISORY-1115810")

    def test_parse_npm_audit_preserves_multiple_findings_and_summaries(self) -> None:
        dependencies = [
            Dependency("npm", "nth-check", "1.0.2", "/tmp/package-lock.json", 17839),
            Dependency("npm", "postcss", "7.0.39", "/tmp/package-lock.json", 2247),
            Dependency("npm", "webpack-dev-server", "4.15.2", "/tmp/package-lock.json", 3286),
        ]
        payload = {
            "vulnerabilities": {
                "nth-check": {
                    "severity": "high",
                    "range": "<2.0.1",
                    "fixAvailable": {"version": "2.0.1"},
                    "via": [
                        {
                            "source": 1,
                            "title": "Inefficient Regular Expression Complexity in nth-check",
                            "url": "https://github.com/advisories/GHSA-rp65-9cf3-cjxr",
                            "severity": "high",
                            "range": "<2.0.1",
                        }
                    ],
                },
                "postcss": {
                    "severity": "medium",
                    "range": "<8.4.31",
                    "fixAvailable": {"version": "8.4.31"},
                    "via": [
                        {
                            "source": 2,
                            "title": "Line return parsing error in PostCSS",
                            "url": "https://github.com/advisories/GHSA-7fh5-64p2-3v2j",
                            "severity": "moderate",
                            "range": "<8.4.31",
                        }
                    ],
                },
                "webpack-dev-server": {
                    "severity": "high",
                    "range": "<5.2.1",
                    "fixAvailable": {"version": "5.2.1"},
                    "via": [
                        {
                            "source": 3,
                            "title": "Exposure of webpack-dev-server dev middleware",
                            "url": "https://github.com/advisories/GHSA-9jgg-88mc-972h",
                            "severity": "high",
                            "range": "<5.2.1",
                        }
                    ],
                },
            }
        }

        issues = _parse_npm_audit(payload, dependencies)

        self.assertEqual(len(issues), 3)
        summaries = {issue.dependency.name: issue.vulnerability.summary for issue in issues}
        self.assertEqual(summaries["nth-check"], "Inefficient Regular Expression Complexity in nth-check")
        self.assertEqual(summaries["postcss"], "Line return parsing error in PostCSS")
        self.assertEqual(summaries["webpack-dev-server"], "Exposure of webpack-dev-server dev middleware")

    def test_parse_npm_audit_preserves_scope_and_semver_major_fix(self) -> None:
        dependencies = [Dependency("npm", "form-data", "4.0.0", "/tmp/package-lock.json", 128)]
        payload = {
            "vulnerabilities": {
                "form-data": {
                    "severity": "high",
                    "range": "<4.0.4",
                    "fixAvailable": {"version": "5.0.0", "isSemVerMajor": True},
                    "via": [
                        {
                            "source": 10,
                            "title": "Unsafe random boundary in form-data",
                            "url": "https://github.com/advisories/GHSA-test-form-data",
                            "severity": "high",
                            "range": "<4.0.4",
                        }
                    ],
                }
            }
        }

        issues = _parse_npm_audit(payload, dependencies, audit_scope="development")

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].vulnerability.audit_scope, "development")
        self.assertTrue(issues[0].vulnerability.fix_is_semver_major)
        # npm fixAvailable can identify a parent package rather than this advisory's fix.
        self.assertIsNone(issues[0].vulnerability.fixed_version)

    def test_scan_node_keeps_runtime_and_full_audit_findings_separate(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            dependencies = [
                Dependency("npm", "nodemailer", "8.0.5", str(root / "package-lock.json"), 21),
                Dependency("npm", "form-data", "4.0.0", str(root / "package-lock.json"), 128),
            ]
            runtime_payload = {
                "vulnerabilities": {
                    "nodemailer": {
                        "severity": "moderate",
                        "range": "<8.0.9",
                        "fixAvailable": {"version": "8.0.9"},
                        "via": [
                            {
                                "source": 1,
                                "title": "Runtime nodemailer advisory",
                                "url": "https://github.com/advisories/GHSA-runtime",
                                "severity": "moderate",
                                "range": "<8.0.9",
                            }
                        ],
                    }
                }
            }
            full_payload = {
                "vulnerabilities": {
                    **runtime_payload["vulnerabilities"],
                    "form-data": {
                        "severity": "high",
                        "range": "<4.0.4",
                        "fixAvailable": {"version": "5.0.0", "isSemVerMajor": True},
                        "via": [
                            {
                                "source": 2,
                                "title": "Development form-data advisory",
                                "url": "https://github.com/advisories/GHSA-development",
                                "severity": "high",
                                "range": "<4.0.4",
                            }
                        ],
                    },
                }
            }

            class EmptyDb:
                def ensure_fresh(self, dependency, allow_network=True):
                    return []

            def fake_run(command, timeout, cwd=None):
                if "--omit=dev" in command:
                    return CommandResult(command=command, returncode=1, stdout=__import__("json").dumps(runtime_payload), stderr="")
                return CommandResult(command=command, returncode=1, stdout=__import__("json").dumps(full_payload), stderr="")

            with patch("vhost_cve_monitor.audits.collect_node_dependencies", return_value=(dependencies, [])):
                with patch("vhost_cve_monitor.audits.command_exists", return_value=True):
                    with patch("vhost_cve_monitor.audits.run_command", side_effect=fake_run):
                        result = _scan_node(StackMatch("nodejs", "high", [], str(root)), EmptyDb(), timeout=1, allow_network=False)

            scopes = {issue.dependency.name: issue.vulnerability.audit_scope for issue in result.issues}
            self.assertEqual(scopes["nodemailer"], "runtime")
            self.assertEqual(scopes["form-data"], "development")
            self.assertTrue(next(issue for issue in result.issues if issue.dependency.name == "form-data").vulnerability.fix_is_semver_major)

    def test_parse_pip_audit_preserves_description_as_summary(self) -> None:
        dependencies = [Dependency("PyPI", "jinja2", "3.1.3", "/tmp/requirements.txt", 10)]
        payload = [
            {
                "name": "jinja2",
                "vulns": [
                    {
                        "id": "PYSEC-2024-1",
                        "description": "Sandbox escape in Jinja2 environment handling",
                        "severity": "high",
                        "fix_versions": ["3.1.4"],
                        "link": "https://example.invalid/PYSEC-2024-1",
                    }
                ],
            }
        ]

        issues = _parse_pip_audit(payload, dependencies)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].vulnerability.summary, "Sandbox escape in Jinja2 environment handling")
        self.assertEqual(issues[0].vulnerability.fixed_version, ">= 3.1.4")

    def test_parse_composer_audit_preserves_title_as_summary(self) -> None:
        dependencies = [Dependency("Packagist", "symfony/http-foundation", "5.4.0", "/tmp/composer.lock", 22)]
        payload = {
            "advisories": [
                {
                    "packageName": "symfony/http-foundation",
                    "advisoryId": "PKSA-123",
                    "title": "Improper trusted proxy validation in HttpFoundation",
                    "severity": "high",
                    "affectedVersions": "<5.4.46",
                    "cve": "CVE-2026-1000",
                    "link": "https://example.invalid/CVE-2026-1000",
                }
            ]
        }

        issues = _parse_composer_audit(payload, dependencies)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].vulnerability.summary, "Improper trusted proxy validation in HttpFoundation")
        self.assertEqual(issues[0].vulnerability.fixed_version, ">= 5.4.46")


if __name__ == "__main__":
    unittest.main()
