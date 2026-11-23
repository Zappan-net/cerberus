import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.advisory_logic import (
    advisory_ids_from_fields,
    build_recommendation,
    canonical_advisory_id,
    merge_fixed_versions,
    severity_from_cvss,
    strongest_severity,
)


class AdvisoryLogicTestCase(unittest.TestCase):
    def test_strongest_severity_never_lets_unknown_win(self) -> None:
        self.assertEqual(strongest_severity("MEDIUM", "UNKNOWN"), "MEDIUM")
        self.assertEqual(strongest_severity("UNKNOWN", "HIGH"), "HIGH")

    def test_canonical_advisory_id_prefers_standard_alias(self) -> None:
        self.assertEqual(
            canonical_advisory_id("OSV-2024-1234", ["CVE-2024-1000", "GHSA-abcd-1234-efgh"]),
            "CVE-2024-1000",
        )

    def test_canonical_advisory_id_prefers_cve_over_ghsa_vuln_id(self) -> None:
        self.assertEqual(
            canonical_advisory_id("GHSA-5rvq-cxj2-64vf", ["CVE-2026-53539", "PYSEC-2026-3036"]),
            "CVE-2026-53539",
        )

    def test_advisory_ids_are_extracted_from_reference_urls(self) -> None:
        self.assertEqual(
            advisory_ids_from_fields(
                "GHSA-rgw5-rvv9-x895",
                [],
                [
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-69152",
                    "https://github.com/advisories/GHSA-rgw5-rvv9-x895",
                ],
            ),
            ["CVE-2026-69152", "GHSA-rgw5-rvv9-x895"],
        )

    def test_canonical_advisory_id_uses_reference_url_aliases(self) -> None:
        self.assertEqual(
            canonical_advisory_id(
                "GHSA-rgw5-rvv9-x895",
                [],
                ["https://nvd.nist.gov/vuln/detail/CVE-2026-69152"],
            ),
            "CVE-2026-69152",
        )

    def test_merge_fixed_versions_deduplicates(self) -> None:
        self.assertEqual(merge_fixed_versions(">= 4.17.24", ">= 4.17.24"), ">= 4.17.24")

    def test_build_recommendation_is_stack_aware_for_npm(self) -> None:
        recommendation = build_recommendation("npm", "nodejs", "lodash", "4.17.23", ">= 4.17.24")

        self.assertIn("package-lock.json", recommendation)
        self.assertIn("npm audit fix", recommendation)
        self.assertIn("npm install lodash@", recommendation)
        self.assertIn("used at runtime or only during build/test", recommendation)

    def test_build_recommendation_handles_missing_fix_version(self) -> None:
        recommendation = build_recommendation("PyPI", "python", "requests", "2.32.5", None)

        self.assertIn("No fixed version is known", recommendation)
        self.assertIn("used at runtime or only during build/test", recommendation)

    def test_severity_from_numeric_cvss_score(self) -> None:
        self.assertEqual(severity_from_cvss("8.8"), "HIGH")

    def test_severity_from_cvss_v3_vector(self) -> None:
        self.assertEqual(
            severity_from_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "CRITICAL",
        )


if __name__ == "__main__":
    unittest.main()
