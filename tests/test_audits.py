import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.audits import _normalize_npm_vuln_id
from vhost_cve_monitor.audits import _parse_composer_audit
from vhost_cve_monitor.audits import _parse_npm_audit
from vhost_cve_monitor.audits import _parse_pip_audit
from vhost_cve_monitor.models import Dependency


class AuditsTestCase(unittest.TestCase):
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
