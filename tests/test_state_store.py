import os
import sys
import unittest
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.state_store import StateStore


class StateStoreTestCase(unittest.TestCase):
    def test_alert_deduplication(self) -> None:
        with TemporaryDirectory() as tmp:
            store = StateStore(tmp + "/state.db")
            payload = {"severity": "HIGH", "vuln": "CVE-0001"}
            self.assertTrue(store.should_alert("issue:test", payload))
            self.assertFalse(store.should_alert("issue:test", payload))
            self.assertTrue(store.should_alert("issue:test", {"severity": "CRITICAL", "vuln": "CVE-0001"}))

    def test_alert_decision_reports_progressive_enrichment(self) -> None:
        with TemporaryDirectory() as tmp:
            store = StateStore(tmp + "/state.db")
            first_payload = {
                "vhost": "app.domain.tld",
                "stack": "nodejs",
                "dependency": "brace-expansion",
                "version": "5.0.8",
                "vuln_id": "CVE-2026-69152",
                "severity": "HIGH",
                "source_path": "/srv/app/package-lock.json",
                "source_line": 1204,
                "ecosystem": "npm",
                "audit_scope": "runtime",
                "fixed_version": None,
                "affected_range": ">=4.0.0 <5.0.9",
                "advisory_summary": "brace-expansion DoS",
                "aliases": ["GHSA-rgw5-rvv9-x895"],
                "references": ["https://github.com/advisories/GHSA-rgw5-rvv9-x895"],
            }
            enriched_payload = dict(first_payload)
            enriched_payload.update(
                {
                    "fixed_version": ">= 5.0.9",
                    "references": [
                        "https://github.com/advisories/GHSA-rgw5-rvv9-x895",
                        "https://nvd.nist.gov/vuln/detail/CVE-2026-69152",
                    ],
                }
            )

            self.assertEqual(store.alert_decision("issue:test", first_payload), (True, "new"))
            self.assertEqual(store.alert_decision("issue:test", enriched_payload), (False, "progressive_enrichment"))
            self.assertEqual(store.alert_decision("issue:test", enriched_payload), (False, "unchanged"))

    def test_alert_history_suppresses_alias_only_new_fingerprint(self) -> None:
        with TemporaryDirectory() as tmp:
            store = StateStore(tmp + "/state.db")
            ghsa_payload = {
                "vhost": "app.domain.tld",
                "stack": "nodejs",
                "dependency": "image-size",
                "version": "2.0.2",
                "vuln_id": "GHSA-5p2g-fcmc-qvqq",
                "severity": "HIGH",
                "source_path": "/srv/app/package-lock.json",
                "source_line": 22,
                "ecosystem": "npm",
                "audit_scope": "runtime",
                "fixed_version": None,
                "advisory_summary": "image-size parser denial of service",
                "aliases": [],
                "references": ["https://github.com/advisories/GHSA-5p2g-fcmc-qvqq"],
            }
            cve_payload = dict(ghsa_payload)
            cve_payload.update(
                {
                    "vuln_id": "CVE-2025-71329",
                    "fixed_version": ">= 2.0.2",
                    "aliases": ["GHSA-5p2g-fcmc-qvqq"],
                    "references": [
                        "https://github.com/advisories/GHSA-5p2g-fcmc-qvqq",
                        "https://nvd.nist.gov/vuln/detail/CVE-2025-71329",
                    ],
                }
            )

            self.assertEqual(store.alert_decision("issue:ghsa", ghsa_payload), (True, "new"))
            self.assertEqual(store.alert_decision("issue:cve", cve_payload), (False, "progressive_enrichment"))
            self.assertEqual(store.alert_decision("issue:cve", cve_payload), (False, "unchanged"))

    def test_alert_history_notifies_when_related_finding_scope_changes(self) -> None:
        with TemporaryDirectory() as tmp:
            store = StateStore(tmp + "/state.db")
            development_payload = {
                "vhost": "app.domain.tld",
                "stack": "nodejs",
                "dependency": "nanoid",
                "version": "3.3.16",
                "vuln_id": "GHSA-2v37-7h3g-55p8",
                "severity": "HIGH",
                "source_path": "/srv/app/package-lock.json",
                "source_line": 3376,
                "ecosystem": "npm",
                "audit_scope": "development",
                "fixed_version": ">= 3.3.17",
                "advisory_summary": "nanoid generators can loop indefinitely",
                "aliases": [],
                "references": [],
            }
            runtime_payload = dict(development_payload)
            runtime_payload.update(
                {
                    "vuln_id": "CVE-2026-67213",
                    "audit_scope": "runtime",
                    "fixed_version": ">= 3.3.17 or >= 5.1.6",
                    "aliases": ["GHSA-2v37-7h3g-55p8"],
                }
            )

            self.assertEqual(store.alert_decision("issue:nanoid-ghsa", development_payload), (True, "new"))
            self.assertEqual(store.alert_decision("issue:nanoid-cve", runtime_payload), (True, "changed"))

    def test_repeated_failure_threshold(self) -> None:
        with TemporaryDirectory() as tmp:
            store = StateStore(tmp + "/state.db")
            payload = {"reason": "timeout"}
            self.assertFalse(store.register_failure("failure:test", payload, threshold=3))
            self.assertFalse(store.register_failure("failure:test", payload, threshold=3))
            self.assertTrue(store.register_failure("failure:test", payload, threshold=3))
            self.assertFalse(store.register_failure("failure:test", payload, threshold=3))

    def test_replace_and_export_current_findings_snapshot(self) -> None:
        with TemporaryDirectory() as tmp:
            store = StateStore(tmp + "/state.db")
            scanned_at = "2026-04-13T10:00:00+00:00"
            store.replace_current_findings(
                [
                    {
                        "vhost": "app.domain.tld",
                        "stack": "nodejs",
                        "ecosystem": "npm",
                        "dependency": "webpack-dev-server",
                        "version": "4.15.2",
                        "advisory_id": "GHSA-9jgg-88mc-972h",
                        "severity": "HIGH",
                        "fixed_version": ">= 5.2.1",
                        "affected_range": "<5.2.1",
                        "advisory_summary": "Exposure of webpack-dev-server dev middleware",
                        "source_path": "/srv/app/package-lock.json",
                        "source_line": 3286,
                        "audit_scope": "development",
                        "fix_is_semver_major": True,
                        "aliases": ["CVE-2026-1001"],
                        "references": ["https://github.com/advisories/GHSA-9jgg-88mc-972h"],
                    }
                ],
                scanned_at=scanned_at,
            )

            exported = store.export_current_findings()

            self.assertEqual(exported["scanned_at"], scanned_at)
            self.assertEqual(exported["findings_count"], 1)
            self.assertEqual(exported["breakdown"], {"HIGH": 1})
            self.assertEqual(exported["findings"][0]["vhost"], "app.domain.tld")
            self.assertEqual(exported["findings"][0]["advisory_summary"], "Exposure of webpack-dev-server dev middleware")
            self.assertEqual(exported["findings"][0]["audit_scope"], "development")
            self.assertTrue(exported["findings"][0]["fix_is_semver_major"])


if __name__ == "__main__":
    unittest.main()
