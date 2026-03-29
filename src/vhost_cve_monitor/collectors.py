from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from .models import Dependency, ScanFailure, StackMatch
from .subprocess_utils import command_exists, run_command

LOGGER = logging.getLogger(__name__)


def _load_json(path: Path) -> Optional[Union[Dict, List]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _find_line_number(path: Path, patterns: List[str]) -> Optional[int]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    for index, line in enumerate(lines, start=1):
        if all(pattern in line for pattern in patterns):
            return index
    for index, line in enumerate(lines, start=1):
        if any(pattern in line for pattern in patterns):
            return index
    return None


def collect_node_dependencies(stack: StackMatch) -> Tuple[List[Dependency], List[ScanFailure]]:
    dependencies = []
    failures = []
    if not stack.root_path:
        return dependencies, [ScanFailure(scope="nodejs", reason="missing_root_path")]
    root = Path(stack.root_path)
    lock_path = root / "package-lock.json"
    shrinkwrap_path = root / "npm-shrinkwrap.json"
    package_json_path = root / "package.json"
    manifest = lock_path if lock_path.exists() else shrinkwrap_path if shrinkwrap_path.exists() else None
    if manifest:
        data = _load_json(manifest)
        if isinstance(data, dict):
            packages = data.get("packages")
            if isinstance(packages, dict):
                for package_path, metadata in packages.items():
                    if not package_path:
                        continue
                    name = package_path.split("node_modules/")[-1]
                    version = metadata.get("version")
                    if name and version:
                        dependencies.append(
                            Dependency(
                                ecosystem="npm",
                                name=name,
                                version=str(version),
                                source=str(manifest),
                                source_line=_find_line_number(manifest, ['"{}"'.format(name), str(version)]),
                                locations=[package_path],
                            )
                        )
            else:
                for name, metadata in (data.get("dependencies") or {}).items():
                    version = metadata.get("version") if isinstance(metadata, dict) else None
                    if version:
                        dependencies.append(
                            Dependency(
                                ecosystem="npm",
                                name=name,
                                version=str(version),
                                source=str(manifest),
                                source_line=_find_line_number(manifest, ['"{}"'.format(name), str(version)]),
                            )
                        )
    elif package_json_path.exists():
        data = _load_json(package_json_path)
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies"):
                for name, version in (data.get(section) or {}).items():
                    if isinstance(version, str):
                        dependencies.append(
                            Dependency(
                                ecosystem="npm",
                                name=name,
                                version=version.lstrip("^~<>= "),
                                source=str(package_json_path),
                                source_line=_find_line_number(package_json_path, ['"{}"'.format(name)]),
                            )
                        )
    else:
        failures.append(ScanFailure(scope="nodejs", reason="missing_manifest", detail=stack.root_path))
    return _dedupe_dependencies(dependencies), failures


def collect_composer_dependencies(stack: StackMatch) -> Tuple[List[Dependency], List[ScanFailure]]:
    dependencies = []
    failures = []
    if not stack.root_path:
        return dependencies, [ScanFailure(scope="php-composer", reason="missing_root_path")]
    root = Path(stack.root_path)
    lock_path = root / "composer.lock"
    json_path = root / "composer.json"
    if lock_path.exists():
        data = _load_json(lock_path)
        if isinstance(data, dict):
            for section in ("packages", "packages-dev"):
                for package in data.get(section, []):
                    name = package.get("name")
                    version = package.get("version")
                    if name and version:
                        dependencies.append(
                            Dependency(
                                ecosystem="Packagist",
                                name=name,
                                version=str(version).lstrip("v"),
                                source=str(lock_path),
                                source_line=_find_line_number(lock_path, ['"{}"'.format(name), str(version)]),
                            )
                        )
    elif json_path.exists():
        data = _load_json(json_path)
        if isinstance(data, dict):
            for section in ("require", "require-dev"):
                for name, version in (data.get(section) or {}).items():
                    if name == "php":
                        continue
                    dependencies.append(
                        Dependency(
                            ecosystem="Packagist",
                            name=name,
                            version=str(version).lstrip("^~v"),
                            source=str(json_path),
                            source_line=_find_line_number(json_path, ['"{}"'.format(name)]),
                        )
                    )
    else:
        failures.append(ScanFailure(scope="php-composer", reason="missing_manifest", detail=stack.root_path))
    return _dedupe_dependencies(dependencies), failures


def _parse_requirement_line(line: str) -> Optional[Tuple[str, str]]:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    match = re.match(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line)
    if match:
        return match.group(1), match.group(2)
    return None


def collect_python_dependencies(stack: StackMatch, timeout: int) -> Tuple[List[Dependency], List[ScanFailure]]:
    dependencies = []
    failures = []
    if not stack.root_path:
        return dependencies, [ScanFailure(scope="python", reason="missing_root_path")]
    root = Path(stack.root_path)
    requirements_path = root / "requirements.txt"
    poetry_lock = root / "poetry.lock"
    if requirements_path.exists():
        for index, line in enumerate(requirements_path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            parsed = _parse_requirement_line(line)
            if parsed:
                name, version = parsed
                dependencies.append(
                    Dependency(
                        ecosystem="PyPI",
                        name=name,
                        version=version,
                        source=str(requirements_path),
                        source_line=index,
                    )
                )
    if poetry_lock.exists():
        current_name = None
        current_version = None
        current_line = None
        for index, line in enumerate(poetry_lock.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("name = "):
                current_name = stripped.split("=", 1)[1].strip().strip('"')
                current_line = index
            elif stripped.startswith("version = "):
                current_version = stripped.split("=", 1)[1].strip().strip('"')
            elif not stripped and current_name and current_version:
                dependencies.append(
                    Dependency(
                        ecosystem="PyPI",
                        name=current_name,
                        version=current_version,
                        source=str(poetry_lock),
                        source_line=current_line,
                    )
                )
                current_name = None
                current_version = None
                current_line = None
    venv_candidates = [root / ".venv/bin/python", root / "venv/bin/python"]
    for python_bin in venv_candidates:
        if python_bin.exists():
            result = run_command([str(python_bin), "-m", "pip", "freeze"], timeout=timeout, cwd=root)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parsed = _parse_requirement_line(line)
                    if parsed:
                        name, version = parsed
                        dependencies.append(
                            Dependency(
                                ecosystem="PyPI",
                                name=name,
                                version=version,
                                source=str(python_bin),
                                source_line=None,
                            )
                        )
            else:
                failures.append(ScanFailure(scope="python", reason="pip_freeze_failed", detail=result.stderr.strip()))
            break
    if not dependencies:
        failures.append(ScanFailure(scope="python", reason="no_pinned_dependencies_found", detail=stack.root_path))
    return _dedupe_dependencies(dependencies), failures


def collect_gitea_dependencies(stack: StackMatch, timeout: int) -> Tuple[List[Dependency], List[ScanFailure]]:
    dependencies = []
    failures = []
    version = None
    source = None
    root = Path(stack.root_path) if stack.root_path else None
    if command_exists("gitea"):
        result = run_command(["gitea", "--version"], timeout=timeout)
        if result.returncode == 0:
            match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
            if match:
                version = match.group(1)
                source = "gitea --version"
    if not version and root:
        version_file = root / "VERSION"
        if version_file.exists():
            content = version_file.read_text(encoding="utf-8", errors="ignore")
            match = re.search(r"(\d+\.\d+\.\d+)", content)
            if match:
                version = match.group(1)
                source = str(version_file)
    if version:
        dependencies.append(
            Dependency(
                ecosystem="Go",
                name="code.gitea.io/gitea",
                version=version,
                source=source or "unknown",
                source_line=1 if source and source.endswith("VERSION") else None,
            )
        )
    else:
        failures.append(ScanFailure(scope="gitea", reason="version_not_detected", detail=stack.root_path))
    return dependencies, failures


def _dedupe_dependencies(dependencies: List[Dependency]) -> List[Dependency]:
    deduped = {}
    for dependency in dependencies:
        key = (dependency.ecosystem, dependency.name.lower(), dependency.version)
        if key not in deduped:
            deduped[key] = dependency
    return list(deduped.values())
