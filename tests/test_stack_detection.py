import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.models import VhostConfig
from vhost_cve_monitor.stack_detection import _detect_root_candidates, _walk_candidates, detect_stacks
from vhost_cve_monitor.stack_detection import _read_mountinfo, _process_host_path


class StackDetectionTestCase(unittest.TestCase):
    def test_private_bind_mount_translates_to_host_project(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "source app"
            project.mkdir()
            (project / "package.json").write_text("{}")
            (project / "server.js").write_text("")
            proc = base / "proc"
            visible = proc / "root/run/private/app"
            visible.parent.mkdir(parents=True)
            visible.symlink_to(project, target_is_directory=True)
            mounts = [("8:1", Path("/"), Path("/")),
                      ("8:1", project, Path("/run/private/app"))]
            host = [("8:1", Path("/"), Path("/"))]
            mapped = _process_host_path(Path("/run/private/app/server.js"), proc, mounts, host)
            self.assertEqual(mapped, project / "server.js")
            vhost = VhostConfig("test", proxy_passes=["http://127.0.0.1:3002"])
            config = {"scanner": {"max_directory_walk_depth": 1, "local_proxy_root_hints": [str(base)]}}
            with patch("vhost_cve_monitor.stack_detection._listening_tcp_inode", return_value="1"), \
                 patch("vhost_cve_monitor.stack_detection._socket_inode_pid_map", return_value={"1": "42"}), \
                 patch("vhost_cve_monitor.stack_detection._process_root_candidates", return_value=[mapped.parent]):
                self.assertEqual(detect_stacks(vhost, config)[0].root_path, str(project))
                config["scanner"]["local_proxy_root_hints"] = [str(base / "other")]
                self.assertEqual(detect_stacks(vhost, config), [])

    def test_mountinfo_decodes_escaped_paths_and_ignores_malformed_lines(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "mountinfo"
            path.write_text("bad\n12 1 8:1 /srv/my\\040app /run/app ro - ext4 /dev/sda rw\n")
            self.assertEqual(_read_mountinfo(path), [("8:1", Path("/srv/my app"), Path("/run/app"))])
            self.assertEqual(_read_mountinfo(path.parent / "missing"), [])

    def test_private_mount_never_falls_back_to_shadowed_host_file(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "package.json"
            path.write_text("{}")
            mounts = [("8:1", Path("/"), Path("/")),
                      ("0:99", Path("/"), path.parent)]
            host = [("8:1", Path("/"), Path("/"))]
            self.assertIsNone(_process_host_path(path, Path(tmp) / "proc", mounts, host))

    def test_translation_requires_identical_filesystem_object(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "package.json").write_text("{}")
            visible = base / "proc/root/run/app/package.json"
            visible.parent.mkdir(parents=True)
            visible.write_text("{}")
            self.assertIsNone(_process_host_path(Path("/run/app/package.json"), base / "proc",
                [("8:1", base, Path("/run/app"))], [("8:1", Path("/"), Path("/"))]))

    def test_missing_mountinfo_keeps_ordinary_discovery(self):
        path = Path("/srv/app/server.js")
        self.assertEqual(_process_host_path(path, Path("/proc/42"), [], []), path)

    def test_redirect_only_vhost_does_not_trigger_default_root_scan(self) -> None:
        vhost = VhostConfig(
            file_path="/etc/nginx/sites-enabled/redirect.conf",
            server_names=["redirect.example.test"],
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
                server_names=["git.domain.tld"],
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

    def test_loopback_proxy_process_can_resolve_python_venv_project_root(self) -> None:
        with TemporaryDirectory() as tmp:
            app_root = Path(tmp) / "example-project"
            venv_python = app_root / ".venv" / "bin" / "python3.11"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("", encoding="utf-8")
            (app_root / "requirements.txt").write_text("fastapi==0.111.0\n", encoding="utf-8")
            vhost = VhostConfig(
                file_path="/etc/nginx/sites-enabled/app.conf",
                server_names=["domain.tld"],
                proxy_passes=["http://127.0.0.1:8787/"],
            )
            config = {
                "scanner": {
                    "default_roots": [],
                    "max_directory_walk_depth": 3,
                    "resolve_local_proxy_processes": True,
                    "local_proxy_root_hints": [str(Path(tmp))],
                }
            }

            with patch("vhost_cve_monitor.stack_detection._listening_tcp_inode", return_value="12345"):
                with patch("vhost_cve_monitor.stack_detection._socket_inode_pid_map", return_value={"12345": "30097"}):
                    with patch("vhost_cve_monitor.stack_detection._process_root_candidates", return_value=[app_root]):
                        candidates = _detect_root_candidates(vhost, config)
                        stacks = detect_stacks(vhost, config)

            self.assertEqual(candidates, [app_root])
            self.assertEqual(len(stacks), 1)
            self.assertEqual(stacks[0].stack_name, "python")
            self.assertEqual(stacks[0].root_path, str(app_root))

    def test_loopback_proxy_resolution_respects_root_hints(self) -> None:
        with TemporaryDirectory() as tmp:
            app_root = Path(tmp) / "outside" / "app"
            app_root.mkdir(parents=True)
            (app_root / "requirements.txt").write_text("fastapi==0.111.0\n", encoding="utf-8")
            allowed_root = Path(tmp) / "allowed"
            allowed_root.mkdir()
            vhost = VhostConfig(
                file_path="/etc/nginx/sites-enabled/app.conf",
                server_names=["domain.tld"],
                proxy_passes=["http://127.0.0.1:8787/"],
            )
            config = {
                "scanner": {
                    "default_roots": [],
                    "max_directory_walk_depth": 3,
                    "resolve_local_proxy_processes": True,
                    "local_proxy_root_hints": [str(allowed_root)],
                }
            }

            with patch("vhost_cve_monitor.stack_detection._listening_tcp_inode", return_value="12345"):
                with patch("vhost_cve_monitor.stack_detection._socket_inode_pid_map", return_value={"12345": "30097"}):
                    with patch("vhost_cve_monitor.stack_detection._process_root_candidates", return_value=[app_root]):
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
                server_names=["domain.tld"],
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
            app_root = Path(tmp) / "example-app"
            build_root = app_root / "build"
            build_root.mkdir(parents=True)
            (app_root / "package.json").write_text("{}", encoding="utf-8")
            vhost = VhostConfig(
                file_path="/etc/nginx/sites-enabled/app.conf",
                server_names=["domain.tld"],
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
