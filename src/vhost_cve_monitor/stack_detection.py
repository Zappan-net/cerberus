from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List

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
