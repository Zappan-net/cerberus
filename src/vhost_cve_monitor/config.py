from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

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


def validate_config(config: Dict[str, Any]) -> Dict[str, List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    nginx = config.get("nginx") or {}
    scanner = config.get("scanner") or {}
    notifications = config.get("notifications") or {}
    state = config.get("state") or {}
    logging_config = config.get("logging") or {}

    sites_enabled_dir = str(nginx.get("sites_enabled_dir") or "").strip()
    if not sites_enabled_dir:
        errors.append("nginx.sites_enabled_dir must be set")

    include_globs = nginx.get("include_globs")
    if include_globs is not None and not isinstance(include_globs, list):
        errors.append("nginx.include_globs must be a list when provided")

    for key in (
        "scan_interval_minutes",
        "command_timeout_seconds",
        "network_timeout_seconds",
        "max_include_depth",
        "max_directory_walk_depth",
        "repeated_failure_threshold",
    ):
        value = scanner.get(key)
        if not isinstance(value, int) or value < 0:
            errors.append("scanner.{} must be an integer greater than or equal to 0".format(key))
    if isinstance(scanner.get("command_timeout_seconds"), int) and scanner.get("command_timeout_seconds", 0) <= 0:
        errors.append("scanner.command_timeout_seconds must be greater than 0")
    if isinstance(scanner.get("network_timeout_seconds"), int) and scanner.get("network_timeout_seconds", 0) <= 0:
        errors.append("scanner.network_timeout_seconds must be greater than 0")

    default_roots = scanner.get("default_roots")
    if default_roots is not None and not isinstance(default_roots, list):
        errors.append("scanner.default_roots must be a list when provided")

    email_to = notifications.get("email_to")
    if not isinstance(email_to, list) or not email_to or not all(str(item).strip() for item in email_to):
        errors.append("notifications.email_to must be a non-empty list of recipient addresses")
    if not str(notifications.get("email_from") or "").strip():
        errors.append("notifications.email_from must be set")

    method = str(notifications.get("method") or "").strip().lower()
    if method not in {"sendmail", "smtp"}:
        errors.append("notifications.method must be either 'sendmail' or 'smtp'")
    if method == "sendmail" and not str(notifications.get("sendmail_path") or "").strip():
        errors.append("notifications.sendmail_path must be set when notifications.method is sendmail")
    if method == "smtp":
        if not str(notifications.get("smtp_host") or "").strip():
            errors.append("notifications.smtp_host must be set when notifications.method is smtp")
        port = notifications.get("smtp_port")
        if not isinstance(port, int) or port <= 0 or port > 65535:
            errors.append("notifications.smtp_port must be a valid TCP port when notifications.method is smtp")
        if notifications.get("smtp_ssl") and notifications.get("smtp_starttls"):
            errors.append("notifications.smtp_ssl and notifications.smtp_starttls cannot both be enabled")
        if str(notifications.get("smtp_password") or "").strip() and str(notifications.get("smtp_password_env") or "").strip():
            warnings.append("notifications.smtp_password_env overrides notifications.smtp_password when both are set")

    value = notifications.get("max_emails_per_run")
    if not isinstance(value, int) or value <= 0:
        errors.append("notifications.max_emails_per_run must be an integer greater than 0")
    if not isinstance(notifications.get("summary_only"), bool):
        errors.append("notifications.summary_only must be a boolean")

    database_path = str(state.get("database_path") or "").strip()
    if not database_path:
        errors.append("state.database_path must be set")
    state_dir = str(state.get("state_dir") or "").strip()
    if not state_dir:
        warnings.append("state.state_dir is empty; only state.database_path will be used")
    ttl_hours = state.get("cve_cache_ttl_hours")
    if not isinstance(ttl_hours, int) or ttl_hours <= 0:
        errors.append("state.cve_cache_ttl_hours must be an integer greater than 0")

    level = str(logging_config.get("level") or "").upper()
    if level and level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        errors.append("logging.level must be one of CRITICAL, ERROR, WARNING, INFO, DEBUG")

    return {"errors": errors, "warnings": warnings}
