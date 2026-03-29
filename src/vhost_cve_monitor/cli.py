from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import List, Optional

from .config import load_config
from .logging_utils import configure_logging
from .scanner import CerberusScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vhost-cve-monitor")
    parser.add_argument(
        "-c",
        "--config",
        default="/etc/vhost-cve-monitor/config.yml",
        help="Path to YAML configuration file",
    )
    parser.add_argument("--dry-run", action="store_true", help="Do not send mails")
    parser.add_argument("--offline", action="store_true", help="Do not refresh remote CVE data")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose progress logs")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("scan-once", help="Run one full scan")
    subparsers.add_parser("daemon", help="Run an internal periodic loop")
    subparsers.add_parser("sync-cve", help="Refresh cached advisories for known packages")
    test_mail_parser = subparsers.add_parser("test-mail", help="Send a test mail")
    test_mail_parser.add_argument(
        "--severity",
        default="INFO",
        choices=["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW", "INFO", "UNKNOWN"],
        type=str.upper,
        help="Severity to simulate in the test mail",
    )
    test_mail_parser.add_argument(
        "--category",
        default="test",
        choices=["test", "vulnerability", "scan-failure", "digest"],
        help="Notification category to simulate in the test mail",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)
    configure_logging(config, override_level="DEBUG" if args.verbose else None)
    scanner = CerberusScanner(config, dry_run=args.dry_run, allow_network=not args.offline)

    if args.command == "scan-once":
        results, notifications = scanner.scan_once()
        print(
            json.dumps(
                {
                    "vhosts": len(results),
                    "notifications": len(notifications),
                },
                indent=2,
            )
        )
        return 0
    if args.command == "sync-cve":
        refreshed = scanner.refresh_cve_cache()
        print(json.dumps({"refreshed_packages": refreshed}, indent=2))
        return 0
    if args.command == "test-mail":
        event = scanner.send_test_mail(severity=args.severity, category=args.category)
        print(json.dumps({"subject": event.subject}, indent=2))
        return 0
    if args.command == "daemon":
        logging.getLogger(__name__).info("Starting daemon loop")
        scanner.daemon_loop()
        return 0
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
