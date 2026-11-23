"""Install the narrowly scoped writable Codex state directory for systemd."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

from .config import load_config


def codex_home_path(config: Dict[str, Any]) -> Path:
    settings = config.get("codex_analysis") or {}
    configured = str(settings.get("codex_home") or "").strip()
    state_dir = str((config.get("state") or {}).get("state_dir") or "/var/lib/vhost-cve-monitor")
    return Path(configured or str(Path(state_dir) / "codex")).expanduser().resolve()


def install_dropin(config: Dict[str, Any], systemd_dir: Path) -> None:
    target = systemd_dir / "vhost-cve-monitor.service.d" / "30-cerberus-codex.conf"
    if not (config.get("codex_analysis") or {}).get("enabled", False):
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        return
    home = codex_home_path(config)
    # Never turn a misconfigured home into write access to a whole system tree.
    if len(home.parts) < 3 or home in {Path('/var/lib'), Path('/usr/local')}:
        raise ValueError("codex_home must be a dedicated directory, not a system root")
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    escaped = str(home).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    if any(ord(char) < 32 for char in escaped):
        raise ValueError("codex_home contains control characters")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        '# Managed by the Cerberus installer; contains no credentials.\n'
        '[Service]\nReadWritePaths="{}"\n'.format(escaped), encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--systemd-dir", default="/etc/systemd/system")
    args = parser.parse_args()
    install_dropin(load_config(args.config), Path(args.systemd_dir))


if __name__ == "__main__":
    main()
