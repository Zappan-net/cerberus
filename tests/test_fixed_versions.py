import copy
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.advisory_logic import infer_first_safe_from_range
from vhost_cve_monitor.cve_db import CVEDatabase
from vhost_cve_monitor.fixed_versions import github_records, osv_records
from vhost_cve_monitor.models import Dependency, Vulnerability
from vhost_cve_monitor.state_store import StateStore
from vhost_cve_monitor.config import load_config
from vhost_cve_monitor.scanner import CerberusScanner
from vhost_cve_monitor.models import AuditIssue
from vhost_cve_monitor.notify import _html_body
from vhost_cve_monitor.codex_analysis import CodexAnalysisRunner


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = CVEDatabase(self.tmp.name + "/state.db")
        self.resolver = self.db.repairs
        self.dep = Dependency("npm", "nodemailer", "10.0.4", "/srv/app/package-lock.json")
        self.github = json.loads((Path(__file__).parent / "fixtures/nodemailer-repair.json").read_text())
        self.vuln = Vulnerability("GHSA-prgh-xp8r-p3m5", "npm-audit", "HIGH", "title", "",
                                  None, None, "nodemailer", "npm", "10.0.4")

    def tearDown(self):
        self.tmp.cleanup()

    def expire(self):
        with self.db._connect() as connection:
            connection.execute("UPDATE repair_cache SET expires_at='2000-01-01'")

    def test_official_reference_and_offline_alias_cache(self):
        self.github["identifiers"].append({"value": "CVE-2026-12345"})
        with patch.object(self.resolver, "_get", side_effect=[{}, self.github]) as fetch:
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(self.vuln.fixed_version, ">= 10.0.5")
        self.assertEqual(self.vuln.severity, "HIGH")
        self.assertEqual(self.vuln.fix_details["records"][0]["affected_range"], ">= 9.1.0, <= 10.0.4")
        self.assertIn("collected_at", self.vuln.fix_details["records"][0])
        self.vuln.vuln_id, self.vuln.aliases = "CVE-2026-12345", []
        self.dep.version = "10.0.13"
        self.vuln.fixed_version = None
        with patch.object(self.resolver, "_get", side_effect=AssertionError("offline")):
            self.resolver.enrich(self.vuln, self.dep, False)
        self.assertEqual(self.vuln.fixed_version, ">= 10.0.5")

    def test_cve_fallback_uses_official_search(self):
        self.vuln.vuln_id = "CVE-2026-12345"
        with patch.object(self.resolver, "_get", side_effect=[{}, [self.github]]) as fetch:
            self.resolver.enrich(self.vuln, self.dep)
        self.assertIn("cve_id=CVE-2026-12345", fetch.call_args[0][0])
        self.assertEqual(self.vuln.fixed_version, ">= 10.0.5")

    def test_missing_fields_and_timeout_are_retried_but_bounded(self):
        with patch.object(self.resolver, "_get", side_effect=TimeoutError()) as fetch:
            self.resolver.enrich(self.vuln, self.dep)
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(self.vuln.fix_details["status"], "retrieval_failed")
        self.expire()
        with patch.object(self.resolver, "_get", side_effect=[{}, {}]):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fix_details["status"], "incomplete")
        self.assertIsNone(self.vuln.fixed_version)

    def test_not_published_is_not_a_network_failure(self):
        self.github["vulnerabilities"][0]["first_patched_version"] = None
        with patch.object(self.resolver, "_get", side_effect=[{}, self.github]):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fix_details["status"], "not_published")

    def test_malformed_api_is_best_effort(self):
        with patch.object(self.resolver, "_get", return_value=["invalid"]):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fix_details["status"], "retrieval_failed")
        self.assertEqual(self.vuln.severity, "HIGH")

    def test_negative_cache_cannot_replace_fresh_osv_evidence(self):
        with patch.object(self.resolver, "_get", side_effect=[{}, {}]):
            self.resolver.enrich(self.vuln, self.dep)
        self.vuln.fix_details = {"status": "confirmed", "records": [{
            "source": "OSV", "url": "https://api.osv.dev/v1/vulns/" + self.vuln.vuln_id,
            "collected_at": "now", "affected_range": "<10.0.5", "fixed_versions": ["10.0.5"]}]}
        with patch.object(self.resolver, "_get", side_effect=AssertionError("fresh cache")):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fixed_version, ">= 10.0.5")
        self.assertEqual(self.vuln.fix_details["status"], "confirmed")

    def test_network_failure_does_not_erase_confirmed_version(self):
        with patch.object(self.resolver, "_get", side_effect=[{}, self.github]):
            self.resolver.enrich(self.vuln, self.dep)
        self.expire()
        with patch.object(self.resolver, "_get", side_effect=TimeoutError()):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fixed_version, ">= 10.0.5")
        self.assertEqual(self.vuln.fix_details["status"], "confirmed")
        self.assertTrue(self.vuln.fix_details["errors"])

    def test_rate_limit_sets_bounded_backoff_for_other_advisories(self):
        error = urllib.error.HTTPError("url", 429, "limit", {"Retry-After": "999999"}, None)
        with patch.object(self.resolver, "_get", side_effect=[{}, error, {}]) as fetch:
            self.resolver.enrich(self.vuln, self.dep)
            self.vuln.vuln_id = "GHSA-aaaa-bbbb-cccc"
            self.vuln.aliases = []
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(fetch.call_count, 3)
        self.assertIsNotNone(self.resolver.github_retry_at)

    def test_branches_prereleases_and_package_filter(self):
        self.github["vulnerabilities"].extend([
            {"package": {"ecosystem": "npm", "name": "nodemailer"},
             "vulnerable_version_range": "< 11.0.0-beta.2", "first_patched_version": "11.0.0-beta.2"},
            {"package": {"ecosystem": "pip", "name": "nodemailer"}, "first_patched_version": "99.0.0"},
            {"package": {"ecosystem": "npm", "name": "unrelated"}, "first_patched_version": "99.0.0"}])
        with patch.object(self.resolver, "_get", side_effect=[{}, self.github]):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fixed_version, ">= 10.0.5 or >= 11.0.0-beta.2")
        self.assertEqual(len(self.vuln.fix_details["records"]), 2)
        self.expire()
        with patch.object(self.resolver, "_get", side_effect=TimeoutError()):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fixed_version, ">= 10.0.5 or >= 11.0.0-beta.2")
        self.assertEqual(len(self.vuln.fix_details["records"]), 2)

    def test_conflicting_sources_remain_explicit(self):
        with patch.object(self.resolver, "_get", side_effect=[{}, self.github]):
            self.resolver.enrich(self.vuln, self.dep)
        self.expire()
        osv = {"id": self.vuln.vuln_id, "affected": [{"package": {"ecosystem": "npm", "name": "nodemailer"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "9.1.0"}, {"fixed": "10.0.6"}]}]}]}
        with patch.object(self.resolver, "_get", return_value=osv):
            self.resolver.enrich(self.vuln, self.dep)
        self.assertEqual(self.vuln.fix_details["status"], "conflicting")
        self.assertIsNone(self.vuln.fixed_version)
        self.assertEqual(len(self.vuln.fix_details["records"]), 2)

    def test_osv_git_commits_are_not_package_versions_and_no_inclusive_inference(self):
        item = {"id": "GHSA-aaaa-bbbb-cccc", "affected": [{"package": {"name": "nodemailer", "ecosystem": "npm"},
                "ranges": [{"type": "GIT", "events": [{"fixed": "deadbeef"}]}]}]}
        self.assertEqual(osv_records(item, self.dep, "now"), [])
        self.assertIsNone(infer_first_safe_from_range("<= 10.0.4"))
        self.assertIsNone(infer_first_safe_from_range(">=9.1.0 <=10.0.4"))

    def test_cache_metadata_does_not_leak_across_packages_or_erase_confirmed_fix(self):
        self.vuln.fixed_version = ">= 10.0.5"
        self.db._store_query_result(self.dep, [self.vuln])
        other_dep = Dependency("npm", "other", "1", "lock")
        other = copy.deepcopy(self.vuln)
        other.package_name, other.fixed_version = "other", ">= 2"
        self.db._store_query_result(other_dep, [other])
        self.assertEqual(self.db.lookup(self.dep)[0].fixed_version, ">= 10.0.5")
        self.vuln.fixed_version = None
        self.db._store_query_result(self.dep, [self.vuln])
        self.assertEqual(self.db.lookup(self.dep)[0].fixed_version, ">= 10.0.5")

    def test_provenance_roundtrip_and_append_only_enrichment_decision(self):
        with patch.object(self.resolver, "_get", side_effect=[{}, self.github]):
            self.resolver.enrich(self.vuln, self.dep)
        state = StateStore(str(self.db.db_path))
        payload = dict(vhost="app.example.net", ecosystem="npm", dependency="nodemailer", version="10.0.4",
                       source_path=self.dep.source, vuln_id=self.vuln.vuln_id, severity="HIGH", fixed_version=None)
        state.begin_scan()
        self.assertTrue(state.should_alert("one", payload))
        state.record_delivery([state.decision_ids["one"]], "success", "test", "accepted")
        enriched = dict(payload, fix_details=self.vuln.fix_details, fixed_version=self.vuln.fixed_version)
        self.assertFalse(state.should_alert("one", enriched))
        record = state.notification_history()[0]
        self.assertEqual(record["reason"], "progressive_enrichment")
        self.assertIn("fix_details", record["changed_fields"])
        self.assertEqual(record["after"]["fix_details"], self.vuln.fix_details)
        state.replace_current_findings([dict(enriched, advisory_id=self.vuln.vuln_id)], "now")
        exported = state.export_current_findings()
        self.assertEqual(exported["findings"][0]["fix_details"], self.vuln.fix_details)

    def test_text_html_digest_export_and_ai_share_evidence_without_mail(self):
        with patch.object(self.resolver, "_get", side_effect=[{}, self.github]):
            self.resolver.enrich(self.vuln, self.dep)
        config = load_config(None)
        config["state"]["database_path"] = str(self.db.db_path)
        config["codex_analysis"]["enabled"] = False
        scanner = CerberusScanner(config, dry_run=True, allow_network=False)
        occurrences = [{"vhost": host, "stack": "nodejs", "issue": AuditIssue(self.dep, self.vuln, "npm-audit")}
                       for host in ("app.example.net", "admin.example.net")]
        with patch.object(scanner.mailer, "send", side_effect=AssertionError("no mail")):
            events = scanner._build_issue_notifications(occurrences)
            digest = scanner._build_digest_notification(events, subject_all=True)
            self.assertIn("10.0.5", digest.body)
            self.assertIn("Repair evidence: Status: confirmed", digest.body)
            self.assertIn("GitHub", _html_body(digest))
            self.assertIn("10.0.5", _html_body(events[0]))
            self.assertIn("Repair evidence: Status: confirmed", events[0].body)
            items = digest.metadata["digest_items"]
            self.assertEqual(len(items), 1)
            self.assertEqual(len(items[0]["affected_targets"]), 2)
        runner = CodexAnalysisRunner.__new__(CodexAnalysisRunner)
        runner.settings = {}
        self.assertIn('"fixed_versions": [', runner._prompt(events[0].metadata))
        self.assertIn('"10.0.5"', runner._prompt(events[0].metadata))
        events[0].metadata["fix_details"]["records"][0]["affected_range"] = "<script>unsafe</script>"
        self.assertNotIn("<script>", _html_body(events[0]))
        self.assertIn("&lt;script&gt;", _html_body(events[0]))


if __name__ == "__main__":
    unittest.main()
