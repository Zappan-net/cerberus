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


if __name__ == "__main__":
    unittest.main()
