import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vhost_cve_monitor.models import VhostConfig
from vhost_cve_monitor.stack_detection import _walk_candidates, detect_stacks


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


if __name__ == "__main__":
    unittest.main()
