from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import List, Optional

from .config import load_config
from .logging_utils import configure_logging
from .notify import NotificationDeliveryError
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
    export_parser = subparsers.add_parser("export-findings", help="Export the latest materialized findings snapshot")
    export_parser.add_argument("--format", default="json", choices=["json"], help="Export format")
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
        choices=["test", "vulnerability", "scan-failure", "internal-error", "digest"],
        help="Notification category to simulate in the test mail",
    )
    test_mail_parser.add_argument("--stack", help="Stack name to simulate for vulnerability test mails")
    test_mail_parser.add_argument("--ecosystem", help="Explicit ecosystem override for vulnerability test mails")
    test_mail_parser.add_argument("--package", dest="package_name", help="Package name to simulate")
    test_mail_parser.add_argument("--installed-version", help="Installed version to simulate")
    test_mail_parser.add_argument("--fixed-version", help="Fixed version to render when known")
    test_mail_parser.add_argument("--advisory-id", help="Advisory id to render")
    test_mail_parser.add_argument("--vhost", help="Virtual host name to render")
    test_mail_parser.add_argument("--source-file", help="Evidence file path to render")
    test_mail_parser.add_argument("--source-line", type=int, help="Evidence line number to render")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)
    configure_logging(config, override_level="DEBUG" if args.verbose else None)
    scanner = CerberusScanner(config, dry_run=args.dry_run, allow_network=not args.offline)

    try:
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
        if args.command == "export-findings":
            print(json.dumps(scanner.export_findings(), indent=2))
            return 0
        if args.command == "test-mail":
            event = scanner.send_custom_test_mail(
                severity=args.severity,
                category=args.category,
                stack=args.stack,
                ecosystem=args.ecosystem,
                package_name=args.package_name,
                installed_version=args.installed_version,
                fixed_version=args.fixed_version,
                advisory_id=args.advisory_id,
                vhost=args.vhost,
                source_file=args.source_file,
                source_line=args.source_line,
            )
            print(json.dumps({"subject": event.subject}, indent=2))
            return 0
        if args.command == "daemon":
            logging.getLogger(__name__).info("Starting daemon loop")
            scanner.daemon_loop()
            return 0
    except NotificationDeliveryError as exc:
        logging.getLogger(__name__).error("Mail delivery error during %s: %s", args.command, exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        logging.getLogger(__name__).exception("Unhandled Cerberus error during %s", args.command)
        scanner.report_internal_error(args.command, exc)
        return 1
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
