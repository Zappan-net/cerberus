import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.codex_analysis import CodexAnalysisRunner, validate_analysis_result
from vhost_cve_monitor.config import load_config, validate_config
from vhost_cve_monitor.state_store import StateStore


def valid_analysis(severity: str = "HIGH") -> dict:
    return {
        "analysis_status": "completed",
        "component_status": "present",
        "dependency_scope": "runtime",
        "dependency_path": ["application", "lodash"],
        "advisory_severity": severity,
        "contextual_risk": "LOW",
        "exposure": "not_observed",
        "impact": "denial_of_service",
        "action_priority": "scheduled",
        "operator_summary": "Low contextual risk: the component is installed, but no attacker-controlled reachable path was observed.",
        "environment_assessment": "The package is installed in the analysed repository, but no public route using it was found.",
        "risk_rationale": "The vulnerable code path was not observed with attacker-controlled input in the available source tree.",
        "confidence": 0.82,
        "reachability": {
            "status": "not_observed",
            "attacker_controlled_input": False,
            "explanation": "No attacker-controlled input path was identified.",
        },
        "exploitation_prerequisites": ["An attacker must control the vulnerable input."],
        "likely_impact": "Potential denial of service.",
        "evidence": [
            {
                "file": "package-lock.json",
                "line_start": 10,
                "line_end": 20,
                "finding": "The vulnerable version is installed.",
            }
        ],
        "limitations": ["Static analysis cannot prove absence of dynamic inputs."],
        "recommendations": [
            {
                "priority": 1,
                "type": "upgrade",
                "action": "Upgrade after compatibility testing.",
            }
        ],
        "summary": "The vulnerable component is present, but no reachable external path was observed.",
    }


class CodexAnalysisTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.lockfile = self.repo / "package-lock.json"
        self.lockfile.write_text('{"packages":{"node_modules/lodash":{"version":"4.17.23"}}}', encoding="utf-8")
        self.state = StateStore(str(Path(self.tmp.name) / "state.db"))
        self.config = {
            "codex_analysis": {
                "enabled": True,
                "executable": "codex",
                "codex_home": str(Path(self.tmp.name) / "codex"),
                "language": "en",
                "model": "",
                "timeout_seconds": 3,
                "retry_attempts": 1,
                "retry_delay_seconds": 0,
                "maximum_output_bytes": 10000,
                "maximum_findings_per_run": 10,
                "minimum_severity": "MEDIUM",
                "repository_path": str(self.repo),
                "sandbox": "read-only",
                "network_access": False,
                "ignore_user_config": True,
                "cache_ttl_seconds": 86400,
                "include_failure_diagnostics": True,
                "prompt_template": "",
            }
        }
        self.finding = {
            "dependency": "lodash",
            "version": "4.17.23",
            "advisory_id": "GHSA-35jh-r3h4-6jhm",
            "severity": "HIGH",
            "fixed_version": ">= 4.17.24",
            "affected_range": "< 4.17.24",
            "advisory_summary": "Prototype pollution in lodash",
            "source_path": str(self.lockfile),
            "source_line": 10,
            "ecosystem": "npm",
            "stack": "nodejs",
            "audit_scope": "runtime",
            "affected_targets": ["app.example.net"],
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_feature_disabled_by_default_shape(self) -> None:
        runner = CodexAnalysisRunner({"codex_analysis": {"enabled": False}}, self.state)

        self.assertEqual(runner.analyze(self.finding)["analysis_status"], "disabled")

    def test_severity_change_invalidates_cached_report(self):
        runner = CodexAnalysisRunner(self.config, self.state)
        self.assertNotEqual(runner.cache_key(self.finding, self.repo),
                            runner.cache_key(dict(self.finding, severity="MEDIUM"), self.repo))

    def test_read_only_codex_home_fails_before_subprocess_or_retries(self) -> None:
        runner = CodexAnalysisRunner(self.config, self.state)
        with patch.object(runner, "_executable_available", return_value=True), \
                patch("tempfile.TemporaryFile", side_effect=OSError("read-only filesystem")), \
                patch("subprocess.run") as run:
            result = runner.analyze(self.finding)
        self.assertEqual(result["analysis_status"], "unavailable")
        self.assertIn("systemd drop-in", result["reason"])
        run.assert_not_called()

    def test_successful_structured_analysis_preserves_official_severity(self) -> None:
        def fake_run(command, **kwargs):
            result_path = Path(command[command.index("--output-last-message") + 1])
            result_path.write_text(json.dumps(valid_analysis("HIGH")), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch("subprocess.run", side_effect=fake_run) as run_mock:
                result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "completed")
        self.assertEqual(result["advisory_severity"], "HIGH")
        self.assertEqual(result["contextual_risk"], "LOW")
        args, kwargs = run_mock.call_args
        self.assertEqual(args[0][0:2], ["codex", "exec"])
        self.assertIn("--ephemeral", args[0])
        self.assertIn('approval_policy="never"', args[0])
        self.assertIn("--sandbox", args[0])
        self.assertIn("read-only", args[0])
        self.assertIn("--ignore-user-config", args[0])
        self.assertIn("--skip-git-repo-check", args[0])
        self.assertEqual(kwargs["shell"], False)
        self.assertEqual(kwargs["cwd"], str(self.repo))

    def test_user_config_can_be_loaded_when_explicitly_requested(self) -> None:
        self.config["codex_analysis"]["ignore_user_config"] = False
        runner = CodexAnalysisRunner(self.config, self.state)

        command = runner._command("codex", Path("/tmp/schema.json"), Path("/tmp/result.json"), "prompt")

        self.assertNotIn("--ignore-user-config", command)

    def test_git_repo_check_can_be_kept_when_explicitly_requested(self) -> None:
        self.config["codex_analysis"]["skip_git_repo_check"] = False
        runner = CodexAnalysisRunner(self.config, self.state)

        command = runner._command("codex", Path("/tmp/schema.json"), Path("/tmp/result.json"), "prompt")

        self.assertNotIn("--skip-git-repo-check", command)

    def test_prompt_can_request_french_narrative_fields(self) -> None:
        self.config["codex_analysis"]["language"] = "fr"
        runner = CodexAnalysisRunner(self.config, self.state)

        prompt = runner._prompt(self.finding)

        self.assertIn("Rédige tous les champs narratifs", prompt)
        self.assertIn('"response_language": "fr"', prompt)

    def test_config_accepts_french_codex_language(self) -> None:
        config = load_config(None)
        config["codex_analysis"]["language"] = "fr"

        result = validate_config(config)

        self.assertEqual(result["errors"], [])

    def test_config_rejects_unknown_codex_language(self) -> None:
        config = load_config(None)
        config["codex_analysis"]["language"] = "de"

        result = validate_config(config)

        self.assertIn("codex_analysis.language must be either 'en' or 'fr'", result["errors"])

    def test_missing_executable_is_best_effort(self) -> None:
        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=False):
            result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "unavailable")

    def test_timeout_is_reported(self) -> None:
        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["codex"], 1)):
                result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "timed_out")

    def test_non_zero_exit_is_reported(self) -> None:
        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch(
                "subprocess.run",
                return_value=subprocess.CompletedProcess(["codex"], 2, stdout="", stderr="error: model unavailable"),
            ):
                result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "non_zero_exit")
        self.assertIn("model unavailable", result["reason"])

    def test_retry_after_transient_codex_error_can_succeed(self) -> None:
        self.config["codex_analysis"]["retry_delay_seconds"] = 10
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="error: transient failure")
            result_path = Path(command[command.index("--output-last-message") + 1])
            result_path.write_text(json.dumps(valid_analysis("HIGH")), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch("subprocess.run", side_effect=fake_run):
                with patch("vhost_cve_monitor.codex_analysis.time.sleep") as sleep_mock:
                    result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "completed")
        self.assertEqual(len(calls), 2)
        sleep_mock.assert_called_once_with(10)

    def test_invalid_json_is_rejected(self) -> None:
        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch("subprocess.run", return_value=subprocess.CompletedProcess(["codex"], 0, stdout="not-json", stderr="")):
                result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "invalid_output")

    def test_schema_invalid_json_is_rejected(self) -> None:
        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch("subprocess.run", return_value=subprocess.CompletedProcess(["codex"], 0, stdout=json.dumps({"analysis_status": "completed"}), stderr="")):
                result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "schema_invalid")

    def test_oversized_output_is_rejected(self) -> None:
        self.config["codex_analysis"]["maximum_output_bytes"] = 5
        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch("subprocess.run", return_value=subprocess.CompletedProcess(["codex"], 0, stdout="123456", stderr="")):
                result = runner.analyze(self.finding)

        self.assertEqual(result["analysis_status"], "oversized_output")

    def test_sanitized_environment_excludes_secrets(self) -> None:
        captured_env = {}

        def fake_run(command, **kwargs):
            captured_env.update(kwargs["env"])
            result_path = Path(command[command.index("--output-last-message") + 1])
            result_path.write_text(json.dumps(valid_analysis("HIGH")), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        runner = CodexAnalysisRunner(self.config, self.state)
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "secret", "SSH_AUTH_SOCK": "/tmp/agent", "PATH": "/bin"}):
            with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
                with patch("subprocess.run", side_effect=fake_run):
                    runner.analyze(self.finding)

        self.assertNotIn("AWS_SECRET_ACCESS_KEY", captured_env)
        self.assertNotIn("SSH_AUTH_SOCK", captured_env)
        self.assertEqual(captured_env["PATH"], "/bin")

    def test_missing_repository_path_is_reported(self) -> None:
        self.config["codex_analysis"]["repository_path"] = str(Path(self.tmp.name) / "missing")
        runner = CodexAnalysisRunner(self.config, self.state)

        self.assertEqual(runner.analyze(self.finding)["analysis_status"], "missing_repository")

    def test_cache_prevents_repeated_invocation(self) -> None:
        def fake_run(command, **kwargs):
            result_path = Path(command[command.index("--output-last-message") + 1])
            result_path.write_text(json.dumps(valid_analysis("HIGH")), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        runner = CodexAnalysisRunner(self.config, self.state)
        with patch("vhost_cve_monitor.codex_analysis.command_exists", return_value=True):
            with patch("subprocess.run", side_effect=fake_run) as run_mock:
                first = runner.analyze(self.finding)
                second = runner.analyze(self.finding)

        self.assertEqual(first["analysis_status"], "completed")
        self.assertEqual(second["analysis_status"], "completed")
        self.assertEqual(run_mock.call_count, 1)

    def test_validation_rejects_severity_replacement(self) -> None:
        payload = valid_analysis("LOW")

        errors = validate_analysis_result(payload, expected_severity="HIGH")

        self.assertTrue(any("preserve scanner severity" in error for error in errors))

    def test_validation_rejects_invalid_operational_verdict(self) -> None:
        payload = valid_analysis("HIGH")
        payload["exposure"] = "internet_maybe"

        errors = validate_analysis_result(payload, expected_severity="HIGH")

        self.assertTrue(any("exposure must be one of" in error for error in errors))

    def test_validation_requires_human_risk_context(self) -> None:
        payload = valid_analysis("HIGH")
        payload["environment_assessment"] = ""

        errors = validate_analysis_result(payload, expected_severity="HIGH")

        self.assertIn("environment_assessment must be a non-empty string", errors)


if __name__ == "__main__":
    unittest.main()
