# Runtime CVE coverage and optional AI triage

Cerberus audits two distinct layers: application dependencies (npm, Composer,
PyPI and the existing Gitea collector) and the PHP, Node.js or Python runtime
actually associated with a backend. Updating Composer packages does not patch
PHP-FPM. A PHP application does not need Composer to qualify for runtime checks.

## Identification

Runtime auditing is enabled by default. Local loopback HTTP backends and nginx
FastCGI Unix/TCP listeners are associated through socket inodes and `/proc`.
Nested FastCGI directives and literal absolute `SCRIPT_FILENAME` values are
recognized. The executable must match the live process and be root-owned with
non-writable parent directories. Version probes use bounded subprocesses,
argument arrays, a minimal environment, no shell, and interpreter startup flags
that avoid application configuration. No application code is executed.

The scanner never guesses an interpreter from its own PATH. Missing permissions,
stopped services, ambiguous processes, third-party inventory limitations and
unsupported version ranges are coverage diagnostics, not a declaration of safety.
Named upstreams, remote/container-only executables, variable script paths and
non-root-managed runtimes can require an explicit administrator binding:

```yaml
runtime_audit:
  enabled: true
  cache_ttl_hours: 24
  bindings:
    - vhost: app.example.test
      kind: php
      executable: /opt/php/current/sbin/php-fpm
      repository_path: /srv/example-app

codex_analysis:
  enabled: false
```

Supported kinds are `php`, `node`, and `python`. A binding is an administrator's
assertion, not evidence of a running or publicly reachable service. Restrict
configuration write access accordingly. Use `CERBERUS_RUNTIME_AUDIT_ENABLED=false`
to disable runtime checks without changing dependency audits.

## Advisory sources and limitations

Debian packages retain their source package name and full revision, queried via
OSV's Debian release ecosystem. The Debian Security Tracker supplies backport
status; comparison uses Debian's `dpkg --compare-versions`, not upstream semver.
A distributor-confirmed fixed/not-affected version is not resurrected by an
upstream advisory. Only an unmodified binary attributed to a Debian-maintained
package can use that distribution identity. Other distributions are not yet
supported by the Debian adapter.

Official repository security advisory feeds are used for `php/php-src` and
`nodejs/node`. CPython uses the [PSF advisory database](https://github.com/psf/advisory-database)
through OSV's commit query: Cerberus resolves the installed version's official
`python/cpython` release tag to a commit and queries OSV for that commit. This is
necessary because PSF advisories commonly express affected ranges as Git commits,
while the `python/cpython` GitHub security advisory list is empty. Matching PSF
records and CVE copies are merged by CVE identifier; CVSS severity from the CVE
copy is used when the PSF record has no severity. GitHub and OSV responses are
bounded and cached locally by CPython version for `cache_ttl_hours`.

The tag match means an official upstream release contains the vulnerable code.
A locally rebuilt or patched interpreter with the same version string cannot be
distinguished automatically. OSV's Git fix commits are not reported as fixed
Python release versions; `Fixed version` remains unknown unless an explicit
release-version mapping becomes available. A missing release tag, API failure,
empty PSF result or expired offline cache produces a coverage diagnostic, not a
clean result. These sources are not exhaustive CVE databases:
some projects publish security announcements elsewhere. An empty feed produces
a coverage warning. Unknown package mappings and unsupported range syntax also
produce warnings rather than silently meaning unaffected. GitHub API rate limits
and OSV availability can temporarily prevent refresh; no access token or
credentials are required.

For packaged runtimes whose distributor status is missing, an upstream match is
marked `upstream_match_distributor_status_unconfirmed`, visibly in the mail and
export. It is a candidate needing confirmation, not proof that a backport is
absent. Upstream fixed versions are not presented as fixed Debian package
revisions. The advisory severity remains the publisher's severity.

Ranges support stable numeric versions and comparator conjunctions/unions, not
arbitrary ecosystem syntax. Some PHP advisories publish parallel `< fixed`
records without lower bounds for each maintained branch. The adapter explicitly
infers branch scope for that homogeneous shape, selecting the matching branch
or the earliest newer fixed branch for an older runtime. The inference is recorded
as `range_selection`; a patched 8.2 must not be flagged merely because it is below
the 8.5 patch version. This is not evidence of a same-branch fix for EOL PHP.

Offline operation uses an unexpired local cache. Missing or expired runtime
advisory data produces an incomplete-coverage warning. Runtime auditing does not
turn on Codex, execute remediation or send mail independently of the usual
notification pipeline. Local bindings and inventory must not be committed to
public example configurations.

## Storage, notification and AI

Existing normalization, alias correlation, per-target projection and differential
notification logic are reused. Shared findings retain all affected vhosts. Runtime
facts are stored under `runtime_context` in JSON exports and shown as a separate
runtime inventory line in text and HTML alerts/digests. Recommendations distinguish
interpreter upgrades from dependency-manager upgrades.

The additive migration adds `current_findings.runtime_context_json` with an empty
object default, plus a lazily created `runtime_advisory_cache` table. Existing
current-state rows and append-only notification history are retained; no prior
runtime inventory/history is invented. Back up SQLite before updating normally.

Codex is **optional and disabled by default** in distributed configuration. When
locally enabled, it receives filtered runtime facts alongside the existing finding
and source repository. Facts include executable/version, package provenance,
association method and process state, but no process environment, credentials,
full command line or raw host configuration. Runtime facts participate in its
cache key. A runtime without an application repository is not given arbitrary
access to `/usr` or `/etc` for analysis.

The scanner does not yet certify firewall rules, live request routing, per-pool
PHP flags, extensions or end-to-end exposure. A running/listening process is not
proof of internet reachability; a configured route can still be in maintenance.
Codex must state those limitations. Its contextual risk never replaces official
severity, and failed/disabled AI does not prevent deterministic alerts.

Example (AI section exists only when a validated analysis is available):

```text
Affected targets: app.example.test, admin.example.test
Stack: php-runtime
Runtime inventory: kind=php; version=8.4.26; provenance=upstream;
  association=listening_process; process_state=running;
  assessment=upstream_version_match; reachability=not_verified
Advisory: CVE-2026-109618
Severity: CRITICAL
Fixed version: 8.4.27
Recommendation: update PHP, validate extensions/application compatibility,
  restart affected workers and verify the running binary.

AI-assisted static analysis (illustrative, not a measured verdict):
Official severity: CRITICAL
Contextual risk: UNKNOWN
Limitations: live ingress restrictions were not verified.
```

## Validation

Use `validate-config`, then `--dry-run --offline scan-once` with a copy of the
database/configuration and Codex disabled for repeatable local checks. Offline
warnings are expected until runtime feeds have been cached. Unit tests mock
processes and advisory sources; they do not invoke Codex or require network/mail.
Tests cover PHP without Composer, all three runtime adapters, real PHP advisory
branch shapes, distributor backports, cache expiry, per-vhost projection, export,
HTML/text and optional AI context. This is not exhaustive validation of every
runtime/distribution or every application's exploitability.
