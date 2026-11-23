from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .models import StackMatch, VhostConfig

LOGGER = logging.getLogger(__name__)
IGNORED_DIR_NAMES = {
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".git",
}
BUILD_OUTPUT_DIR_NAMES = {"build", "dist", "public", "www", "htdocs", "html"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _exists(root: Path, relative: str) -> bool:
    return (root / relative).exists()


def _is_application_manifest_root(path: Path) -> bool:
    markers = (
        "composer.json",
        "composer.lock",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "manage.py",
        "custom/conf/app.ini",
        "VERSION",
    )
    return any(_exists(path, marker) for marker in markers)


def _is_inside_hints(path: Path, hints: List[str]) -> bool:
    if not hints:
        return True
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    for hint in hints:
        try:
            resolved.relative_to(Path(str(hint)).expanduser().resolve())
            return True
        except (OSError, ValueError):
            continue
    return False


def _root_variants(root: Path) -> List[Path]:
    candidates = [root]
    if root.name.lower() in BUILD_OUTPUT_DIR_NAMES:
        parent = root.parent
        if parent != root and _is_application_manifest_root(parent):
            candidates.append(parent)
    return candidates


def _walk_candidates(root: Path, max_depth: int) -> List[Path]:
    if not root.exists():
        return []
    candidates = [root]
    for current_root, dirs, _files in os.walk(str(root)):
        current_path = Path(current_root)
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            continue
        dirs[:] = [name for name in dirs if name not in IGNORED_DIR_NAMES]
        if depth == 0:
            for name in dirs:
                candidates.append(current_path / name)
            continue
        if depth > max_depth:
            dirs[:] = []
            continue
        for name in dirs:
            child = current_path / name
            child_depth = len(child.relative_to(root).parts)
            if child_depth <= max_depth:
                candidates.append(child)
    return candidates


def _detect_root_candidates(vhost: VhostConfig, config: Dict) -> List[Path]:
    candidates = []
    if vhost.primary_root:
        candidates.extend(_root_variants(Path(vhost.primary_root)))
    if bool(config["scanner"].get("resolve_local_proxy_processes", True)):
        candidates.extend(_local_proxy_root_candidates(vhost, config))
    should_use_default_roots = bool((not vhost.primary_root) and (vhost.fastcgi_passes or vhost.uwsgi_passes))
    if should_use_default_roots:
        for root_hint in config["scanner"].get("default_roots", []):
            hint_path = Path(root_hint)
            if hint_path.exists():
                candidates.append(hint_path)
    deduped = []
    for path in candidates:
        resolved = path.expanduser()
        if resolved not in deduped:
            deduped.append(resolved)
    return deduped


def _local_proxy_root_candidates(vhost: VhostConfig, config: Dict) -> List[Path]:
    candidates: List[Path] = []
    ports = [_loopback_proxy_port(proxy_pass) for proxy_pass in vhost.proxy_passes]
    ports = [port for port in ports if port is not None]
    if not ports:
        return []
    inode_to_pid = _socket_inode_pid_map()
    root_hints = [str(item) for item in config["scanner"].get("local_proxy_root_hints", [])]
    for port in ports:
        inode = _listening_tcp_inode(port)
        if not inode:
            continue
        pid = inode_to_pid.get(inode)
        if not pid:
            continue
        for root in _process_root_candidates(pid):
            if _is_inside_hints(root, root_hints):
                LOGGER.info("Resolved local proxy port %s to project root candidate %s via pid %s", port, root, pid)
                candidates.append(root)
    return candidates


def _loopback_proxy_port(proxy_pass: str) -> Optional[int]:
    parsed = urlparse(str(proxy_pass or ""))
    if parsed.scheme not in {"http", "https"}:
        return None
    host = parsed.hostname or ""
    if host not in LOOPBACK_HOSTS:
        return None
    return parsed.port


def _listening_tcp_inode(port: int) -> Optional[str]:
    port_hex = format(port, "04X")
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(proc_file).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10:
                continue
            local_address = fields[1]
            state = fields[3]
            inode = fields[9]
            if state != "0A":
                continue
            if not local_address.upper().endswith(":{}".format(port_hex)):
                continue
            return inode
    return None


def _socket_inode_pid_map() -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    socket_re = re.compile(r"socket:\[(\d+)\]")
    proc = Path("/proc")
    for pid_dir in proc.iterdir() if proc.exists() else []:
        if not pid_dir.name.isdigit():
            continue
        fd_dir = pid_dir / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd in entries:
            try:
                target = os.readlink(str(fd))
            except OSError:
                continue
            match = socket_re.match(target)
            if match:
                mapping.setdefault(match.group(1), pid_dir.name)
    return mapping


def _process_root_candidates(pid: str) -> List[Path]:
    candidates: List[Path] = []
    proc = Path("/proc") / str(pid)
    process_mounts = _read_mountinfo(proc / "mountinfo")
    host_mounts = _read_mountinfo(Path("/proc/self/mountinfo"))
    for path in (_process_cwd(proc), _process_executable_project_root(proc)):
        path = _process_host_path(path, proc, process_mounts, host_mounts)
        if path and _is_application_manifest_root(path):
            candidates.append(path)
    for arg_path in _process_argument_paths(proc):
        arg_path = _process_host_path(arg_path, proc, process_mounts, host_mounts)
        if arg_path is None:
            continue
        for path in [arg_path, *arg_path.parents]:
            if _is_application_manifest_root(path):
                candidates.append(path)
                break
    deduped: List[Path] = []
    for candidate in candidates:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped


def _read_mountinfo(path: Path) -> List[tuple]:
    """Return device, filesystem root and mountpoint without entering a namespace."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    mounts = []
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or "-" not in fields[6:]:
            continue
        # mountinfo escapes spaces, tabs, newlines and backslashes as octal.
        root, mountpoint = [re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)
                            for value in fields[3:5]]
        if root.startswith("/") and mountpoint.startswith("/"):
            mounts.append((fields[2], Path(root), Path(mountpoint)))
    return mounts


def _process_host_path(path: Optional[Path], proc: Path, process_mounts: List[tuple],
                       host_mounts: List[tuple]) -> Optional[Path]:
    if path is None:
        return None
    if not process_mounts or not host_mounts:
        # Preserve ordinary process discovery when mount metadata is unavailable.
        return path
    path = Path(os.path.normpath(str(path)))
    matching = []
    for device, root, mountpoint in process_mounts:
        try:
            relative = path.relative_to(mountpoint)
        except ValueError:
            continue
        matching.append((len(mountpoint.parts), device, root / relative))
    if not matching:
        return None
    # A nested mount shadows its parent; never fall back to a different host tree.
    depth = max(item[0] for item in matching)
    visible = proc / "root" / str(path).lstrip("/")
    for current_depth, device, filesystem_path in matching:
        if current_depth != depth:
            continue
        for host_device, host_root, host_mountpoint in host_mounts:
            if device != host_device:
                continue
            try:
                candidate = host_mountpoint / filesystem_path.relative_to(host_root)
                # Mount aliases and symlinks are accepted only for the same object.
                if candidate.samefile(visible):
                    return candidate
            except (OSError, ValueError):
                continue
    return None


def _process_cwd(proc: Path) -> Optional[Path]:
    try:
        return Path(os.readlink(str(proc / "cwd")))
    except OSError:
        return None


def _process_executable_project_root(proc: Path) -> Optional[Path]:
    try:
        executable = Path(os.readlink(str(proc / "exe")))
    except OSError:
        return None
    parts = executable.parts
    for marker in (".venv", "venv"):
        if marker in parts:
            index = parts.index(marker)
            if index > 0:
                return Path(*parts[:index])
    return None


def _process_argument_paths(proc: Path) -> List[Path]:
    try:
        raw = (proc / "cmdline").read_bytes()
    except OSError:
        return []
    paths = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        text = item.decode("utf-8", errors="ignore")
        if text.startswith("/"):
            paths.append(Path(text))
    return paths


def detect_stacks(vhost: VhostConfig, config: Dict) -> List[StackMatch]:
    if vhost.is_redirect_only:
        LOGGER.info("Skipping stack detection for redirect-only vhost %s", vhost.primary_server_name)
        return []
    stacks = []
    max_depth = int(config["scanner"]["max_directory_walk_depth"])
    inspected_paths = _detect_root_candidates(vhost, config)
    for root in inspected_paths:
        for candidate in _walk_candidates(root, max_depth):
            if _exists(candidate, "composer.lock") or _exists(candidate, "composer.json"):
                stacks.append(
                    StackMatch(
                        stack_name="php-composer",
                        confidence="high",
                        reasons=["composer.json or composer.lock detected"],
                        root_path=str(candidate),
                    )
                )
            if any(_exists(candidate, name) for name in ("package-lock.json", "npm-shrinkwrap.json", "package.json")):
                stacks.append(
                    StackMatch(
                        stack_name="nodejs",
                        confidence="high",
                        reasons=["npm manifest or lockfile detected"],
                        root_path=str(candidate),
                    )
                )
            if any(_exists(candidate, name) for name in ("requirements.txt", "pyproject.toml", "poetry.lock", "manage.py")):
                reason = "Python dependency file detected"
                if _exists(candidate, "manage.py"):
                    reason = "Django manage.py detected"
                stacks.append(
                    StackMatch(
                        stack_name="python",
                        confidence="high",
                        reasons=[reason],
                        root_path=str(candidate),
                    )
                )
            if _exists(candidate, "custom/conf/app.ini") or _exists(candidate, "gitea") or _exists(candidate, "VERSION"):
                stacks.append(
                    StackMatch(
                        stack_name="gitea",
                        confidence="medium",
                        reasons=["Gitea-like filesystem markers detected"],
                        root_path=str(candidate),
                    )
                )
    proxy_text = " ".join(vhost.proxy_passes + vhost.fastcgi_passes + vhost.uwsgi_passes).lower()
    if "gitea" in proxy_text:
        stacks.append(
            StackMatch(
                stack_name="gitea",
                confidence="high",
                reasons=["proxy_pass or upstream references gitea"],
                root_path=vhost.primary_root,
            )
        )
    deduped = {}
    for stack in stacks:
        key = (stack.stack_name, stack.root_path)
        if key not in deduped:
            deduped[key] = stack
    return list(deduped.values())
