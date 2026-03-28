import unittest
from tempfile import TemporaryDirectory

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


if __name__ == "__main__":
    unittest.main()
