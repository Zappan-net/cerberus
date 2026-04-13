# Changelog

## Unreleased

### Added

- Normalized finding correlation that merges duplicate advisories across audit-tool and local-cache stages before rendering notifications.
- Stack-aware remediation recommendations for npm, Composer, PyPI, and Go findings.
- Fixed-version and affected-range rendering in alert emails and digests when advisory data provides it.
- Canonical advisory identifier selection, preferring `GHSA-*` or `CVE-*` when available.
- Stack-aware `test-mail` simulation with package, version, advisory, and evidence overrides for remediation previewing.
- Direct `internal-error` notifications for unhandled Cerberus execution failures, with a GitHub bug-report hint.
- Regression tests for severity precedence, fixed-version rendering, compact subjects, and infra-visible multi-vhost projection.

### Changed

- Digest subjects are shorter and operationally focused, for example `[Cerberus][MEDIUM][domain.tld] 2 alerts`.
- `UNKNOWN` no longer overrides a known severity during finding enrichment.
- OSV severity extraction now checks top-level `database_specific.severity` before matched `affected[*]` metadata and logs the candidate fields chosen during debug runs.
- When OSV only exposes CVSS scores or CVSS v3.x vectors, Cerberus now derives a canonical severity instead of falling back to `UNKNOWN`.
- SMTP delivery now supports authenticated relays with either STARTTLS or implicit TLS, in addition to local sendmail/Postfix handoff.
- Numeric npm advisory identifiers are rendered explicitly as `NPM-ADVISORY-*` when no standard public identifier is available.
- The advisory cache schema stores fixed-version and affected-range data to keep offline alert rendering actionable.
- Internal execution failures bypass digest grouping so daemon crashes are mailed directly and deduplicated by operation and payload.
- Packaging now installs Cerberus into `/opt/cerberus/.venv` and refreshes stable wrappers in `/usr/local/bin/` instead of using global `pip install` into the system interpreter.
- A minimal Debian package layout is now shipped, keeping the dedicated `/opt/cerberus/.venv` runtime model and enabling the timers from `postinst`.
- The Debian package now reuses `python3-yaml` through a venv created with `--system-site-packages`, avoiding package-install-time dependency downloads.
- Missing local mail transport binaries now surface as concise delivery errors instead of triggering recursive internal-error tracebacks.
- Digest mails now state explicitly that they cover new or changed findings, preserve advisory summaries, and render findings in per-severity blocks with exact breakdown counts.
- Cerberus now materializes the latest retained findings into SQLite and exposes them through `export-findings`, so external tools can consume current CVE state without a separate local web service.
