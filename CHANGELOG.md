# Changelog

## Unreleased

### Added

- CPython runtime coverage from PSF advisories via OSV release-commit queries, with version-keyed offline cache, CVE alias correlation and available CVSS severity; Git-only fix commits are not presented as Python release versions.
- Runtime CVE inventory for local PHP-FPM, Node.js and Python backends, independently of application manifests; explicit bindings support stopped backends. Debian source revisions/backports take precedence over upstream version matches.
- Bounded official repository advisory caching, explicit provisional distributor assessments and coverage warnings; runtime inventory is preserved in text/HTML mail, JSON exports and optional Codex context. Codex remains disabled by default.
- Additive SQLite runtime cache and current-findings context migration without rewriting notification history.

- Package-scoped fixed-version enrichment from OSV and the official GitHub advisory API, with alias-aware bounded caching, collection provenance and explicit incomplete/error/conflict states in email, export and AI context.

- Append-only SQLite notification journal and `notification-history` CLI, with per-scan/per-vhost before/after decisions and separate delivery outcomes; no historical backfill.
- Normalized finding correlation that merges duplicate advisories across audit-tool and local-cache stages before rendering notifications.
- Stack-aware remediation recommendations for npm, Composer, PyPI, and Go findings.
- Fixed-version and affected-range rendering in alert emails and digests when advisory data provides it.
- Canonical advisory identifier selection, preferring `GHSA-*` or `CVE-*` when available.
- Stack-aware `test-mail` simulation with package, version, advisory, and evidence overrides for remediation previewing.
- Direct `internal-error` notifications for unhandled Cerberus execution failures, with a GitHub bug-report hint.
- `scan-once --force-notify` for sending all current vulnerability findings without changing deduplication state.
- Optional disabled-by-default Codex CLI static analysis enrichment for vulnerability findings, with strict JSON validation, sanitized subprocess environment, timeout, output-size limit, and SQLite result caching.
- Regression tests for severity precedence, fixed-version rendering, compact subjects, and infra-visible multi-vhost projection.

### Changed

- Stop reporting redirect-only nginx blocks as missing stacks. Skip inapplicable npm dependency audits for dependency-free standalone projects and distinguish missing audit prerequisites from failed commands.

- Resolve local proxy projects behind private bind mounts using verified host filesystem mappings, without weakening service isolation. Render stack discovery failures as coverage diagnostics rather than dependency vulnerabilities.

- Stop treating npm package-level `fixAvailable` as per-advisory evidence or inclusive affected bounds as patched versions. Preserve confirmed fixes on transient source failures and journal repair enrichment without resending metadata-only alerts.

- npm advisory severity now takes precedence over package aggregate severity. Dry-run decisions no longer consume real alerts, and the installer verifies source/venv parity after installation.
- Alert deduplication now correlates explicit advisory aliases across identifier changes, ignores metadata-only changes, and preserves new-target and severity notifications. Batch normalization merges late alias bridges before per-vhost projection; existing SQLite history remains usable without a reset.
- Source and Debian installers now maintain a systemd write exception limited to the configured Codex state directory, preserving read-only source protections across reinstalls. Unwritable Codex state is detected before execution instead of repeatedly failing app-server initialization.
- Digest subjects are shorter and operationally focused, for example `[Cerberus][MEDIUM][domain.tld] 2 alerts`.
- npm scanning now runs both production/runtime audit scope and full audit scope, keeping development/build-only findings visible without inflating the primary runtime digest severity.
- Digest rendering now groups identical findings by evidence path, package, installed version, advisory, and audit scope, while listing all affected targets in one block.
- npm recommendations now distinguish runtime remediation from development/build dependency maintenance and warn when `fixAvailable` requires a semver-major change.
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
- Alert and digest emails can now include a separate AI-assisted contextual analysis section when Codex analysis is enabled and returns a validated result; official scanner severity remains authoritative.
