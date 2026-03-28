from __future__ import annotations

import glob
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Union

from .models import NginxLocation, VhostConfig

LOGGER = logging.getLogger(__name__)


DIRECTIVES = {
    "server_name",
    "root",
    "include",
    "proxy_pass",
    "fastcgi_pass",
    "uwsgi_pass",
}


def _tokenize(content: str) -> List[str]:
    tokens = []
    current = []
    in_quote = False
    quote_char = ""
    i = 0
    while i < len(content):
        char = content[i]
        if not in_quote and char == "#":
            while i < len(content) and content[i] != "\n":
                i += 1
            continue
        if char in ('"', "'"):
            if in_quote and char == quote_char:
                in_quote = False
                quote_char = ""
            elif not in_quote:
                in_quote = True
                quote_char = char
            else:
                current.append(char)
            i += 1
            continue
        if not in_quote and char in "{};":
            if current:
                tokens.append("".join(current).strip())
                current = []
            tokens.append(char)
            i += 1
            continue
        if not in_quote and char.isspace():
            if current:
                tokens.append("".join(current).strip())
                current = []
            i += 1
            continue
        current.append(char)
        i += 1
    if current:
        tokens.append("".join(current).strip())
    return [token for token in tokens if token]


def _parse_block(tokens: List[str], index: int = 0) -> Tuple[List[Dict], int]:
    directives = []
    while index < len(tokens):
        token = tokens[index]
        if token == "}":
            return directives, index + 1
        name = token
        index += 1
        args = []
        while index < len(tokens) and tokens[index] not in {"{", ";", "}"}:
            args.append(tokens[index])
            index += 1
        if index >= len(tokens):
            directives.append({"name": name, "args": args, "children": []})
            break
        if tokens[index] == ";":
            directives.append({"name": name, "args": args, "children": []})
            index += 1
            continue
        if tokens[index] == "{":
            children, index = _parse_block(tokens, index + 1)
            directives.append({"name": name, "args": args, "children": children})
            continue
        if tokens[index] == "}":
            directives.append({"name": name, "args": args, "children": []})
            return directives, index
    return directives, index


def _resolve_include_paths(base_file: Path, pattern: str) -> List[Path]:
    if not pattern.startswith("/"):
        pattern = str((base_file.parent / pattern).resolve())
    return [Path(match) for match in glob.glob(pattern, recursive=True)]


def _collect_server_block(
    file_path: Path,
    block: dict,
    include_depth: int,
    max_include_depth: int,
    visited: Set[Path],
) -> VhostConfig:
    vhost = VhostConfig(file_path=str(file_path))
    for child in block["children"]:
        name = child["name"]
        args = child["args"]
        if name == "server_name":
            vhost.server_names.extend(args)
        elif name == "root" and args:
            vhost.roots.append(args[0])
        elif name == "return" and args:
            vhost.returns.append(" ".join(args))
        elif name == "include":
            for pattern in args:
                vhost.includes.append(pattern)
                if include_depth < max_include_depth:
                    for include_path in _resolve_include_paths(file_path, pattern):
                        _merge_include(vhost, include_path, include_depth + 1, max_include_depth, visited)
        elif name == "proxy_pass" and args:
            vhost.proxy_passes.append(args[0])
            vhost.upstream_paths.append(args[0])
        elif name == "fastcgi_pass" and args:
            vhost.fastcgi_passes.append(args[0])
            vhost.upstream_paths.append(args[0])
        elif name == "uwsgi_pass" and args:
            vhost.uwsgi_passes.append(args[0])
            vhost.upstream_paths.append(args[0])
        elif name == "location":
            location = NginxLocation(path=" ".join(args) or "/")
            for nested in child["children"]:
                if nested["name"] == "include":
                    location.includes.extend(nested["args"])
                elif nested["name"] == "proxy_pass" and nested["args"]:
                    location.proxy_pass = nested["args"][0]
                    vhost.proxy_passes.append(nested["args"][0])
                    vhost.upstream_paths.append(nested["args"][0])
                elif nested["name"] == "fastcgi_pass" and nested["args"]:
                    location.fastcgi_pass = nested["args"][0]
                    vhost.fastcgi_passes.append(nested["args"][0])
                    vhost.upstream_paths.append(nested["args"][0])
                elif nested["name"] == "uwsgi_pass" and nested["args"]:
                    location.uwsgi_pass = nested["args"][0]
                    vhost.uwsgi_passes.append(nested["args"][0])
                    vhost.upstream_paths.append(nested["args"][0])
            vhost.locations.append(location)
    return vhost


def _merge_include(
    vhost: VhostConfig,
    include_path: Path,
    include_depth: int,
    max_include_depth: int,
    visited: Set[Path],
) -> None:
    if not include_path.exists() or include_path in visited:
        return
    visited.add(include_path)
    try:
        content = include_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        LOGGER.warning("Unable to read nginx include %s: %s", include_path, exc)
        return
    directives, _ = _parse_block(_tokenize(content))
    pseudo_server = {"name": "server", "args": [], "children": directives}
    included = _collect_server_block(include_path, pseudo_server, include_depth, max_include_depth, visited)
    vhost.roots.extend([item for item in included.roots if item not in vhost.roots])
    vhost.includes.extend([item for item in included.includes if item not in vhost.includes])
    vhost.returns.extend([item for item in included.returns if item not in vhost.returns])
    vhost.proxy_passes.extend([item for item in included.proxy_passes if item not in vhost.proxy_passes])
    vhost.fastcgi_passes.extend([item for item in included.fastcgi_passes if item not in vhost.fastcgi_passes])
    vhost.uwsgi_passes.extend([item for item in included.uwsgi_passes if item not in vhost.uwsgi_passes])
    vhost.upstream_paths.extend([item for item in included.upstream_paths if item not in vhost.upstream_paths])


def parse_nginx_file(file_path: Union[str, Path], max_include_depth: int = 4) -> List[VhostConfig]:
    path = Path(file_path)
    content = path.read_text(encoding="utf-8", errors="ignore")
    directives, _ = _parse_block(_tokenize(content))
    vhosts = []
    for directive in directives:
        if directive["name"] != "server":
            continue
        vhosts.append(
            _collect_server_block(
                path,
                directive,
                include_depth=0,
                max_include_depth=max_include_depth,
                visited={path},
            )
        )
    return vhosts


def load_vhosts(config: Dict) -> List[VhostConfig]:
    directory = Path(config["nginx"]["sites_enabled_dir"])
    max_include_depth = int(config["scanner"]["max_include_depth"])
    vhosts = []
    if not directory.exists():
        LOGGER.warning("Nginx sites-enabled directory does not exist: %s", directory)
        return vhosts
    for item in sorted(directory.iterdir()):
        if not item.is_file():
            continue
        try:
            vhosts.extend(parse_nginx_file(item, max_include_depth=max_include_depth))
        except OSError as exc:
            LOGGER.warning("Failed to parse nginx file %s: %s", item, exc)
    return vhosts
