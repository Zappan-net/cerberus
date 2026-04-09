import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.cve_db import CVEDatabase
from vhost_cve_monitor.models import Dependency


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class CVEDatabaseTestCase(unittest.TestCase):
    def test_fetch_osv_prefers_top_level_database_specific_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = CVEDatabase(os.path.join(tmp, "state.db"))
            dependency = Dependency(
                ecosystem="npm",
                name="multer",
                version="1.4.5-lts.2",
                source="/tmp/package-lock.json",
            )
            payload = {
                "vulns": [
                    {
                        "id": "GHSA-test-1234",
                        "summary": "Example advisory",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {"name": "multer", "ecosystem": "npm"},
                                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                            }
                        ],
                        "references": [{"url": "https://github.com/advisories/GHSA-test-1234"}],
                        "aliases": ["GHSA-test-1234"],
                    }
                ]
            }

            with patch("urllib.request.urlopen", return_value=_FakeResponse(payload)):
                vulnerabilities = db._fetch_osv(dependency)

            self.assertEqual(len(vulnerabilities), 1)
            self.assertEqual(vulnerabilities[0].severity, "HIGH")
            self.assertEqual(vulnerabilities[0].fixed_version, ">= 2.0.0")

    def test_fetch_osv_uses_cvss_vector_when_text_severity_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = CVEDatabase(os.path.join(tmp, "state.db"))
            dependency = Dependency(
                ecosystem="npm",
                name="postcss",
                version="7.0.39",
                source="/tmp/package-lock.json",
            )
            payload = {
                "vulns": [
                    {
                        "id": "GHSA-test-cvss",
                        "summary": "Example advisory with cvss only",
                        "severity": [
                            {
                                "type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        ],
                        "affected": [
                            {
                                "package": {"name": "postcss", "ecosystem": "npm"},
                                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "8.4.31"}]}],
                            }
                        ],
                        "aliases": ["GHSA-test-cvss"],
                    }
                ]
            }

            with patch("urllib.request.urlopen", return_value=_FakeResponse(payload)):
                vulnerabilities = db._fetch_osv(dependency)

            self.assertEqual(len(vulnerabilities), 1)
            self.assertEqual(vulnerabilities[0].severity, "CRITICAL")


if __name__ == "__main__":
    unittest.main()
