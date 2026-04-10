from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "nginx": {
        "sites_enabled_dir": "/etc/nginx/sites-enabled",
        "include_globs": ["/etc/nginx/**/*.conf"],
    },
    "scanner": {
        "default_roots": ["/home/webserv"],
        "scan_interval_minutes": 60,
        "command_timeout_seconds": 120,
        "network_timeout_seconds": 30,
        "max_include_depth": 4,
        "max_directory_walk_depth": 3,
        "repeated_failure_threshold": 3,
    },
    "notifications": {
        "email_to": ["root@localhost"],
        "email_from": "cerberus@localhost",
        "method": "sendmail",
        "sendmail_path": "/usr/sbin/sendmail",
        "smtp_host": "127.0.0.1",
        "smtp_port": 25,
        "smtp_ssl": False,
        "smtp_starttls": False,
        "smtp_username": "",
        "smtp_password": "",
        "smtp_password_env": "",
        "max_emails_per_run": 20,
        "summary_only": True,
    },
    "state": {
        "state_dir": "/var/lib/vhost-cve-monitor",
        "database_path": "/var/lib/vhost-cve-monitor/state.db",
        "cve_cache_ttl_hours": 24,
        "cache_grace_hours": 168,
    },
    "logging": {
        "level": "INFO",
        "file": "",
    },
    "filters": {
        "vhost_allowlist": [],
        "vhost_blocklist": [],
        "path_allowlist": [],
        "path_blocklist": [],
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: Optional[Union[str, Path]]) -> Dict[str, Any]:
    if not path:
        return DEFAULT_CONFIG
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping")
    return _deep_merge(DEFAULT_CONFIG, data)
