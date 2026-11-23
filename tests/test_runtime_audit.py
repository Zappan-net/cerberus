import copy
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.config import DEFAULT_CONFIG, validate_config
from vhost_cve_monitor.models import VhostConfig
from vhost_cve_monitor.nginx_parser import parse_nginx_file
from vhost_cve_monitor.runtime_audit import RuntimeAuditor, branch_records, discover_runtimes, version_in_range, _command
from vhost_cve_monitor.scanner import CerberusScanner
from vhost_cve_monitor.notify import _html_body
from vhost_cve_monitor.state_store import StateStore
from vhost_cve_monitor.codex_analysis import CodexAnalysisRunner


def advisory(kind="php", identifier="CVE-2026-109618", severity="critical"):
    return {"ghsa_id": "GHSA-w8hw-w9fx-j79w", "cve_id": identifier,
            "summary": "Runtime memory corruption", "severity": severity,
            "html_url": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
            "vulnerabilities": [{"package": {"name": kind}, "vulnerable_version_range": "< 8.4.27",
                                  "patched_versions": "8.4.27"}]}


class RuntimeAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self.config["state"]["database_path"] = str(self.root / "state.db")
        self.config["state"]["state_dir"] = str(self.root)
        self.config["notifications"]["sendmail_path"] = "/nonexistent/no-mail"
        self.binding = dict(kind="php", executable="/opt/runtime/bin/php-fpm", repository_path=str(self.root),
                            association="administrator_binding", backend="configured", process_state="unverified")
        self.runtime = dict(self.binding, version="8.4.26", provenance="upstream")
        self.vhost = VhostConfig("/etc/nginx/sites-enabled/example", ["app.example.test"])
        self.auditor = RuntimeAuditor(self.config, Mock(), False)

    def test_defaults_ai_optional_runtime_enabled(self):
        self.assertFalse(self.config["codex_analysis"]["enabled"])
        self.assertTrue(self.config["runtime_audit"]["enabled"])
        self.assertEqual(validate_config(self.config)["errors"], [])

    def test_ranges_boundaries_and_fail_closed(self):
        self.assertTrue(version_in_range("8.4.26", ">= 8.4.0, < 8.4.27"))
        self.assertFalse(version_in_range("8.4.27", ">= 8.4.0, < 8.4.27"))
        self.assertTrue(version_in_range("7.4.33", "< 7.4.34 || >= 8.4.0, < 8.4.27"))
        for expression in [None, "", "*", "^8.4", "< 8.4.27rc1", "< 8.4.27 garbage"]:
            with self.assertRaises(ValueError):
                version_in_range("8.4.26", expression)

    def test_nested_php_no_composer(self):
        path = self.root / "nginx.conf"
        path.write_text('server { server_name app.example.test; location /voice/ { location = /voice/index.php { fastcgi_pass unix:/run/php/app.sock; fastcgi_param SCRIPT_FILENAME /srv/voice/index.php; } } }')
        host = parse_nginx_file(path)[0]
        self.assertIn("unix:/run/php/app.sock", host.fastcgi_passes)
        self.assertEqual(host.php_script_paths, ["/srv/voice/index.php"])

    def test_stopped_fpm_is_not_guessed_from_path(self):
        self.vhost.fastcgi_passes = ["unix:/run/php/missing.sock"]
        with patch("vhost_cve_monitor.runtime_audit._socket_inode_pid_map", return_value={}):
            bindings, failures = discover_runtimes(self.vhost, self.config)
        self.assertEqual(bindings, [])
        self.assertEqual(failures[0].reason, "runtime_not_identified")

    def test_binding_targets_are_not_collapsed(self):
        self.config["runtime_audit"]["bindings"] = [dict(self.binding, vhost="*.example.test")]
        for name in ["app.example.test", "admin.example.test"]:
            self.vhost.server_names = [name]
            bindings, failures = discover_runtimes(self.vhost, self.config)
            self.assertEqual(len(bindings), 1)
            self.assertFalse(failures)

    def scan(self, feed=None):
        with patch("vhost_cve_monitor.runtime_audit.discover_runtimes", return_value=([self.binding], [])), \
             patch("vhost_cve_monitor.runtime_audit.inspect_runtime", return_value=self.runtime), \
             patch.object(self.auditor, "_feed", return_value=feed if feed is not None else [advisory()]):
            return self.auditor.scan(self.vhost)[0]

    def test_upstream_three_kinds(self):
        for kind in ["php", "node"]:
            self.binding["kind"] = self.runtime["kind"] = kind
            result = self.scan([advisory(kind)])
            self.assertEqual(len(result.issues), 1)
            self.assertEqual(result.issues[0].vulnerability.severity, "CRITICAL")
            self.assertEqual(result.issues[0].vulnerability.fixed_version, "8.4.27")
            self.assertIn("GHSA-w8hw-w9fx-j79w", result.issues[0].vulnerability.aliases)

    def test_python_psf_osv_merges_cve_severity_without_duplicate(self):
        self.binding["kind"] = self.runtime["kind"] = "python"
        self.runtime["version"] = "3.11.7"
        psf = {"id": "PSF-2026-46", "aliases": ["CVE-2026-115557"],
               "details": "Reject compromised intermediate CA keys.\nAdditional detail.",
               "affected": [{"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abcdef"}]}]}]}
        cve = {"id": "CVE-2026-115557", "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        with patch.object(self.auditor, "_python_feed", return_value=[psf, cve]):
            result = self.scan()
        self.assertEqual(len(result.issues), 1)
        finding = result.issues[0]
        self.assertEqual(finding.vulnerability.vuln_id, "CVE-2026-115557")
        self.assertEqual(finding.vulnerability.severity, "CRITICAL")
        self.assertIn("PSF-2026-46", finding.vulnerability.aliases)
        self.assertIsNone(finding.vulnerability.fixed_version)
        self.assertIn("Reject compromised", finding.vulnerability.summary)
        self.assertEqual(finding.runtime_context["assessment"], "upstream_release_tag_match")

    def test_python_feed_uses_release_tag_and_caches_only_psf_pairs(self):
        self.auditor.allow_network = True
        self.runtime["version"] = "3.11.7"
        psf = {"id": "PSF-2026-46", "aliases": ["CVE-2026-115557"]}
        cve = {"id": "CVE-2026-115557", "severity": [{"score": "7.5"}]}
        unrelated = {"id": "CVE-2026-999999", "severity": [{"score": "9.8"}]}
        responses = [
            {"object": {"type": "tag", "sha": "a" * 40}},
            {"object": {"type": "commit", "sha": "b" * 40}},
            {"vulns": [psf, cve, unrelated]},
        ]
        class Response(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *_):
                self.close()
        def urlopen(request, timeout):
            return Response(json.dumps(responses.pop(0)).encode())
        with patch("vhost_cve_monitor.runtime_audit.urllib.request.urlopen", side_effect=urlopen) as mocked:
            records = self.auditor._python_feed("3.11.7")
            self.assertEqual({item["id"] for item in records}, {"PSF-2026-46", "CVE-2026-115557"})
            self.assertIn("v3.11.7", mocked.call_args_list[0].args[0].full_url)
            self.assertEqual(json.loads(mocked.call_args_list[2].args[0].data), {"commit": "b" * 40})
        self.auditor.allow_network = False
        with patch("vhost_cve_monitor.runtime_audit.urllib.request.urlopen", side_effect=AssertionError("network")):
            self.assertEqual(self.auditor._python_feed("3.11.7"), records)
        with sqlite3.connect(self.config["state"]["database_path"]) as db:
            db.execute("UPDATE runtime_advisory_cache SET fetched_at=0 WHERE source=?", ("psf-osv-cpython:3.11.7",))
        with self.assertRaises(ValueError):
            self.auditor._python_feed("3.11.7")

    def test_python_feed_rejects_missing_psf_or_invalid_tag(self):
        self.auditor.allow_network = True
        with patch("vhost_cve_monitor.runtime_audit.urllib.request.urlopen", return_value=io.BytesIO(
            json.dumps({"object": {"type": "tag", "sha": "bad"}}).encode())):
            with self.assertRaises(ValueError):
                self.auditor._python_feed("3.11.7")
        with patch("vhost_cve_monitor.runtime_audit.urllib.request.urlopen", side_effect=[
            io.BytesIO(json.dumps({"object": {"type": "commit", "sha": "a" * 40}}).encode()),
            io.BytesIO(json.dumps({"vulns": [{"id": "CVE-2026-115557"}]}).encode()),
        ]):
            with self.assertRaises(ValueError):
                self.auditor._python_feed("3.11.7")
        with sqlite3.connect(self.config["state"]["database_path"]) as db:
            self.assertIsNone(db.execute("SELECT payload FROM runtime_advisory_cache WHERE source=?", ("psf-osv-cpython:3.11.7",)).fetchone())

    def test_python_source_failure_is_a_coverage_diagnostic(self):
        self.binding["kind"] = self.runtime["kind"] = "python"
        self.runtime["version"] = "3.11.7"
        with patch.object(self.auditor, "_python_feed", side_effect=ValueError("CPython PSF advisory cache missing or expired")):
            result = self.scan()
        self.assertFalse(result.issues)
        self.assertEqual(result.failures[0].reason, "runtime_audit_incomplete")

    def test_patched_withdrawn_unknown_and_empty(self):
        self.runtime["version"] = "8.4.27"
        self.assertFalse(self.scan().issues)
        self.runtime["version"] = "8.4.26"
        record = advisory()
        record["withdrawn_at"] = "2026-10-22"
        self.assertFalse(self.scan([record]).issues)
        record = advisory()
        record["vulnerabilities"][0]["vulnerable_version_range"] = "*"
        self.assertEqual(self.scan([record]).failures[0].reason, "runtime_advisory_range_unknown")
        self.assertEqual(self.scan([]).failures[0].reason, "runtime_advisory_coverage_unknown")

    def test_real_php_parallel_fixed_branches(self):
        record = advisory()
        record["vulnerabilities"] = [{"package": {"name": "php-src", "ecosystem": "php"},
                                      "vulnerable_version_range": "< " + fixed, "patched_versions": fixed}
                                     for fixed in ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]]
        for version in ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]:
            self.runtime["version"] = version
            self.auditor.memo.clear()
            self.assertFalse(self.scan([record]).issues, version)
        self.runtime["version"] = "8.4.26"
        self.auditor.memo.clear()
        result = self.scan([record])
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].vulnerability.fixed_version, "8.4.27")
        self.assertIn("range_selection", result.issues[0].runtime_context)
        self.runtime["version"] = "7.3.31"
        self.auditor.memo.clear()
        self.assertEqual(self.scan([record]).issues[0].vulnerability.fixed_version, "8.2.35")

    def test_branch_inference_does_not_mix_packages(self):
        rows = [advisory("php")["vulnerabilities"][0], advisory("unrelated")["vulnerabilities"][0]]
        self.assertEqual(branch_records(rows, "8.4.26"), (rows, False))

    def test_metadata_probe_environment_and_arguments(self):
        with patch("vhost_cve_monitor.runtime_audit.subprocess.run", return_value=Mock(returncode=0, stdout="PHP 8.4.26")) as run:
            self.assertEqual(_command(["/opt/php/bin/php", "-n", "-v"]), "PHP 8.4.26")
        self.assertEqual(run.call_args[0][0], ["/opt/php/bin/php", "-n", "-v"])
        self.assertEqual(run.call_args[1]["env"], {"PATH": "/usr/bin:/bin", "LANG": "C"})
        self.assertFalse(run.call_args[1].get("shell", False))
        self.assertEqual(run.call_args[1]["timeout"], 10)

    def test_full_scan_without_manifest_dry_run_no_transport(self):
        scanner = CerberusScanner(self.config, dry_run=True, allow_network=False)
        with patch("vhost_cve_monitor.scanner.load_vhosts", return_value=[self.vhost]), \
             patch("vhost_cve_monitor.scanner.detect_stacks", return_value=[]), \
             patch("vhost_cve_monitor.runtime_audit.discover_runtimes", return_value=([self.binding], [])), \
             patch("vhost_cve_monitor.runtime_audit.inspect_runtime", return_value=self.runtime), \
             patch.object(RuntimeAuditor, "_feed", return_value=[advisory()]), \
             patch("vhost_cve_monitor.notify.subprocess.run", side_effect=AssertionError("no mail transport")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("offline")):
            results, notifications = scanner.scan_once()
            self.assertEqual(len(notifications), 1)
            self.assertEqual(results[0].stacks[0].stack.stack_name, "php-runtime")
            self.assertEqual(scanner.state.export_current_findings()["findings_count"], 1)
            # Dry runs must not consume alerts that have never been delivered.
            self.assertEqual(len(scanner.scan_once()[1]), 1)

    def test_html_runtime_context_escaped(self):
        result = self.scan()
        result.issues[0].runtime_context["executable"] = '/opt/<script>alert(1)</script>'
        scanner = CerberusScanner(self.config, dry_run=True, allow_network=False)
        events = scanner._build_issue_notifications([{"vhost": "app.example.test", "stack": "php-runtime", "issue": result.issues[0]}])
        for event in [events[0], scanner._build_digest_notification(events)]:
            rendered = _html_body(event)
            self.assertIn("&lt;script&gt;", rendered)
            self.assertNotIn("<script>", rendered)

    def test_legacy_database_migration_preserves_rows_and_history(self):
        path = self.config["state"]["database_path"]
        scanner = CerberusScanner(self.config, dry_run=True, allow_network=False)
        result = self.scan()
        occurrences = [{"vhost": "app.example.test", "stack": "php-runtime", "issue": result.issues[0]}]
        scanner.state.replace_current_findings(scanner._current_findings_snapshot(occurrences), "2026-10-22T00:00:00+00:00")
        scanner._build_issue_notifications(occurrences)
        with sqlite3.connect(path) as db:
            history = db.execute("SELECT * FROM notification_journal").fetchall()
            columns = [row[1] for row in db.execute("PRAGMA table_info(current_findings)") if row[1] != "runtime_context_json"]
            db.execute("CREATE TABLE legacy_findings AS SELECT " + ",".join(columns) + " FROM current_findings")
            db.execute("DROP TABLE current_findings")
            db.execute("ALTER TABLE legacy_findings RENAME TO current_findings")
        migrated = StateStore(path)
        exported = migrated.export_current_findings()
        self.assertEqual(exported["findings_count"], 1)
        self.assertEqual(exported["findings"][0]["runtime_context"], {})
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute("SELECT * FROM notification_journal").fetchall(), history)

    def test_debian_backport_wins_over_upstream(self):
        self.runtime.update(provenance="debian", package="php7.3", package_version="7.3.31-1+deb10u99",
                            ecosystem="Debian:10", distribution_release="buster")
        self.auditor.cve_db.ensure_fresh.return_value = []
        with patch.object(self.auditor, "_debian_status", return_value={"CVE-2026-109618": {"releases": {"buster": {"fixed_version": "7.3.31-1+deb10u98"}}}}):
            result = self.scan()
        self.assertFalse(result.issues)
        dependency = self.auditor.cve_db.ensure_fresh.call_args[0][0]
        self.assertEqual(dependency.version, "7.3.31-1+deb10u99")
        self.assertEqual(dependency.ecosystem, "Debian:10")

    def test_missing_distribution_status_is_explicit_not_fixed_upstream(self):
        self.runtime.update(provenance="debian", package="php7.3", package_version="7.3.31-1+deb10u1",
                            ecosystem="Debian:10", distribution_release="buster")
        self.auditor.cve_db.ensure_fresh.return_value = []
        with patch.object(self.auditor, "_debian_status", return_value={}):
            result = self.scan()
        self.assertEqual(result.issues[0].runtime_context["assessment"], "upstream_match_distributor_status_unconfirmed")
        self.assertIsNone(result.issues[0].vulnerability.fixed_version)

    def test_offline_cache_migration_and_expiry(self):
        state = StateStore(self.config["state"]["database_path"])
        with self.assertRaises(ValueError):
            self.auditor._feed("php")
        import time
        with sqlite3.connect(str(state.db_path)) as db:
            db.execute("INSERT INTO runtime_advisory_cache VALUES (?,?,?)", ("php/php-src", time.time(), json.dumps([advisory()])))
        with patch("urllib.request.urlopen", side_effect=AssertionError("offline network")):
            self.assertEqual(self.auditor._feed("php")[0]["cve_id"], "CVE-2026-109618")
        with sqlite3.connect(str(state.db_path)) as db:
            db.execute("UPDATE runtime_advisory_cache SET fetched_at=0")
        with self.assertRaises(ValueError):
            self.auditor._feed("php")

    def test_disabled_runtime_never_discovers(self):
        self.auditor.settings["enabled"] = False
        with patch("vhost_cve_monitor.runtime_audit.discover_runtimes", side_effect=AssertionError("disabled")):
            self.assertEqual(self.auditor.scan(self.vhost), [])

    def test_pipeline_db_mail_dedup_and_no_ai(self):
        result = self.scan()
        scanner = CerberusScanner(self.config, dry_run=True, allow_network=False)
        occurrences = [{"vhost": name, "stack": result.stack.stack_name, "issue": result.issues[0]}
                       for name in ["app.example.test", "admin.example.test"]]
        snapshot = scanner._current_findings_snapshot(occurrences)
        scanner.state.replace_current_findings(snapshot, "2026-10-22T00:00:00+00:00")
        exported = scanner.state.export_current_findings()
        self.assertEqual(exported["findings_count"], 2)
        self.assertEqual(exported["findings"][0]["runtime_context"]["version"], "8.4.26")
        self.assertIsNone(scanner.codex_analyzer)
        events = scanner._build_issue_notifications(occurrences)
        self.assertEqual(len(events), 2)
        digest = scanner._build_digest_notification(events)
        self.assertEqual(len(digest.metadata["digest_items"]), 1)
        self.assertIn("Runtime inventory", digest.body)
        self.assertIn("CRITICAL", digest.subject)
        self.assertIn("Runtime inventory", _html_body(digest))
        self.assertIn("Runtime inventory", _html_body(events[0]))
        self.assertFalse(scanner._build_issue_notifications(occurrences))

    def test_codex_context_optional_and_cache_invalidation(self):
        config = copy.deepcopy(self.config)
        config["codex_analysis"]["enabled"] = True
        runner = CodexAnalysisRunner(config, StateStore(config["state"]["database_path"]))
        finding = dict(severity="HIGH", source_path=str(self.root), runtime_context=self.runtime)
        self.assertEqual(runner._repository_for_finding(finding), self.root)
        self.assertIn('"runtime_context"', runner._prompt(finding))
        first = runner.cache_key(finding, self.root)
        finding["runtime_context"] = dict(self.runtime, process_state="stopped")
        self.assertNotEqual(first, runner.cache_key(finding, self.root))
        finding["runtime_context"] = {"kind": "php"}
        self.assertIsNone(runner._repository_for_finding(finding))


if __name__ == "__main__":
    unittest.main()
