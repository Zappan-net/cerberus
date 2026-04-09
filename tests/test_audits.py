import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.audits import _normalize_npm_vuln_id


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


if __name__ == "__main__":
    unittest.main()
