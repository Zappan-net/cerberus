from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, List, Optional

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

    scan_once_parser = subparsers.add_parser("scan-once", help="Run one full scan")
    scan_once_parser.add_argument(
        "--only-vhost",
        action="append",
        help="Restrict the scan to one or more vhosts matched with fnmatch patterns",
    )
    subparsers.add_parser("daemon", help="Run an internal periodic loop")
    subparsers.add_parser("sync-cve", help="Refresh cached advisories for known packages")
    subparsers.add_parser("validate-config", help="Validate the loaded configuration")
    subparsers.add_parser("doctor", help="Run local environment diagnostics")
    subparsers.add_parser("list-vhosts", help="List parsed nginx vhosts with filter and stack context")
    explain_parser = subparsers.add_parser("explain-vhost", help="Explain how Cerberus sees a given vhost")
    explain_parser.add_argument("name", help="Vhost name or fnmatch pattern to explain")
    export_parser = subparsers.add_parser("export-findings", help="Export the latest materialized findings snapshot")
    export_parser.add_argument("--format", default="json", choices=["json"], help="Export format")
    export_parser.add_argument("--output", help="Optional output file path for the exported findings JSON")
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


def _emit_json(payload: Any, output_path: Optional[str] = None) -> None:
    rendered = json.dumps(payload, indent=2)
    if output_path:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    configure_logging(config, override_level="DEBUG" if args.verbose else None)
    scanner = CerberusScanner(config, dry_run=args.dry_run, allow_network=not args.offline)

    try:
        if args.command == "scan-once":
            results, notifications = scanner.scan_once(only_vhosts=args.only_vhost)
            _emit_json(
                {
                    "vhosts": len(results),
                    "notifications": len(notifications),
                    "only_vhost": args.only_vhost or [],
                }
            )
            return 0
        if args.command == "sync-cve":
            refreshed = scanner.refresh_cve_cache()
            _emit_json({"refreshed_packages": refreshed})
            return 0
        if args.command == "validate-config":
            validation = scanner.validate_loaded_config()
            _emit_json(validation)
            return 1 if validation["errors"] else 0
        if args.command == "doctor":
            report = scanner.doctor()
            _emit_json(report)
            return 1 if report["status"] == "error" else 0
        if args.command == "list-vhosts":
            _emit_json(scanner.list_vhosts())
            return 0
        if args.command == "explain-vhost":
            _emit_json(scanner.explain_vhost(args.name))
            return 0
        if args.command == "export-findings":
            payload = scanner.export_findings()
            _emit_json(payload, output_path=args.output)
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
            _emit_json({"subject": event.subject})
            return 0
        if args.command == "daemon":
            logging.getLogger(__name__).info("Starting daemon loop")
            scanner.daemon_loop()
            return 0
    except ValueError as exc:
        logging.getLogger(__name__).error(str(exc))
        return 2
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
