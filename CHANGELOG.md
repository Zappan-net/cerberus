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

- Digest subjects are shorter and operationally focused, for example `[Cerberus][MEDIUM][zap.one] 2 alerts`.
- `UNKNOWN` no longer overrides a known severity during finding enrichment.
- Numeric npm advisory identifiers are rendered explicitly as `NPM-ADVISORY-*` when no standard public identifier is available.
- The advisory cache schema stores fixed-version and affected-range data to keep offline alert rendering actionable.
- Internal execution failures bypass digest grouping so daemon crashes are mailed directly and deduplicated by operation and payload.
