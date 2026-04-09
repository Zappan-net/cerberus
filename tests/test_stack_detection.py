import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.models import VhostConfig
from vhost_cve_monitor.stack_detection import _detect_root_candidates, _walk_candidates, detect_stacks


class StackDetectionTestCase(unittest.TestCase):
    def test_redirect_only_vhost_does_not_trigger_default_root_scan(self) -> None:
        vhost = VhostConfig(
            file_path="/etc/nginx/sites-enabled/redirect.conf",
            server_names=["ai-and-tech.com"],
            returns=["302 https://link.me/ai.and.tech$request_uri"],
        )
        config = {
            "scanner": {
                "default_roots": ["/home/webserv"],
                "max_directory_walk_depth": 3,
            }
        }

        stacks = detect_stacks(vhost, config)

        self.assertEqual(stacks, [])

    def test_walk_candidates_ignores_node_modules_and_vendor_dirs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app").mkdir()
            (root / "node_modules" / "pkg").mkdir(parents=True)
            (root / "vendor" / "composer").mkdir(parents=True)
            (root / ".venv" / "lib").mkdir(parents=True)

            candidates = _walk_candidates(root, max_depth=3)
            candidate_strings = {str(path) for path in candidates}

            self.assertIn(str(root / "app"), candidate_strings)
            self.assertNotIn(str(root / "node_modules"), candidate_strings)
            self.assertNotIn(str(root / "node_modules" / "pkg"), candidate_strings)
            self.assertNotIn(str(root / "vendor"), candidate_strings)
            self.assertNotIn(str(root / ".venv"), candidate_strings)

    def test_proxy_only_vhost_does_not_scan_default_roots(self) -> None:
        with TemporaryDirectory() as tmp:
            default_root = Path(tmp) / "webserv"
            default_root.mkdir()
            vhost = VhostConfig(
                file_path="/etc/nginx/sites-enabled/proxy.conf",
                server_names=["git.zap.one"],
                proxy_passes=["http://127.0.0.1:3000"],
            )
            config = {
                "scanner": {
                    "default_roots": [str(default_root)],
                    "max_directory_walk_depth": 3,
                }
            }

            candidates = _detect_root_candidates(vhost, config)

            self.assertEqual(candidates, [])

    def test_rooted_vhost_keeps_only_explicit_root(self) -> None:
        with TemporaryDirectory() as tmp:
            explicit_root = Path(tmp) / "frontend"
            explicit_root.mkdir()
            default_root = Path(tmp) / "webserv"
            default_root.mkdir()
            vhost = VhostConfig(
                file_path="/etc/nginx/sites-enabled/app.conf",
                server_names=["zap.one"],
                roots=[str(explicit_root)],
                proxy_passes=["http://127.0.0.1:3000"],
            )
            config = {
                "scanner": {
                    "default_roots": [str(default_root)],
                    "max_directory_walk_depth": 3,
                }
            }

            candidates = _detect_root_candidates(vhost, config)

            self.assertEqual(candidates, [explicit_root])

    def test_build_root_also_scans_parent_manifest_root(self) -> None:
        with TemporaryDirectory() as tmp:
            app_root = Path(tmp) / "zap-and-rok"
            build_root = app_root / "build"
            build_root.mkdir(parents=True)
            (app_root / "package.json").write_text("{}", encoding="utf-8")
            vhost = VhostConfig(
                file_path="/etc/nginx/sites-enabled/app.conf",
                server_names=["zap.one"],
                roots=[str(build_root)],
            )
            config = {
                "scanner": {
                    "default_roots": [],
                    "max_directory_walk_depth": 3,
                }
            }

            candidates = _detect_root_candidates(vhost, config)

            self.assertEqual(candidates, [build_root, app_root])


if __name__ == "__main__":
    unittest.main()
