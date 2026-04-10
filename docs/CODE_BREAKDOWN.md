# Cerberus Code Breakdown

This document is a full technical walkthrough of the Cerberus codebase. It explains what each module does, how data flows through the program, how the local vulnerability cache works, how notifications are deduplicated, and where the current limits are.

It is written for an operator or developer who needs to understand the actual implementation, not just the user-facing behavior.

## 1. High-level purpose

Cerberus is a Python daemon-oriented scanner for Debian servers. Its job is to:

1. inspect nginx virtual host definitions
2. infer what application stack is behind each vhost
3. collect dependency versions from local project files or runtime hints
4. run stack-specific audit tools when available
5. correlate detected versions with a local SQLite vulnerability cache
6. send email alerts only for new, changed, or repeated-failure conditions

The design goal is resilience:

- a broken project must not stop the whole scan
- a missing tool must degrade gracefully
- a vhost behind `proxy_pass` may still be partially identified
- duplicate alerts must be suppressed
- the code must remain easy to extend stack by stack

## 2. Execution model

Cerberus supports three practical execution modes:

- `scan-once`
  Runs one full scan pass, optionally refreshing missing or stale vulnerability cache entries as it goes.
- `sync-cve`
  Refreshes cached vulnerability entries for package/version tuples already known in the local database.
- `daemon`
  Runs an internal loop with sleep intervals.
- `test-mail`
  Sends a synthetic notification to validate severity rendering, headers, categories, recipients, and transport behavior.

On Debian, the recommended scheduling model is not the internal daemon loop. It is:

- `systemd` oneshot services
- `systemd` timers

That gives better observability and restart behavior than a permanent Python process.

## 3. End-to-end control flow

The normal scan path is:

1. [cli.py](../src/vhost_cve_monitor/cli.py)
   Parses arguments, loads config, configures logging, instantiates `CerberusScanner`.
2. [scanner.py](../src/vhost_cve_monitor/scanner.py)
   Calls `load_vhosts()`.
3. [nginx_parser.py](../src/vhost_cve_monitor/nginx_parser.py)
   Parses nginx files and resolves useful includes.
4. [stack_detection.py](../src/vhost_cve_monitor/stack_detection.py)
   Applies explicit heuristics to determine likely stacks.
5. [audits.py](../src/vhost_cve_monitor/audits.py)
   Dispatches each stack to the proper collector and audit logic.
6. [collectors.py](../src/vhost_cve_monitor/collectors.py)
   Extracts dependency names and versions from lockfiles, manifests, virtualenvs, or service binaries.
7. [cve_db.py](../src/vhost_cve_monitor/cve_db.py)
   Returns cached vulnerability data or refreshes it from OSV if stale and network is allowed.
8. [state_store.py](../src/vhost_cve_monitor/state_store.py)
   Decides whether an alert should be emitted or suppressed as already known.
9. [notify.py](../src/vhost_cve_monitor/notify.py)
   Sends the resulting mail or prints it in dry-run mode.

The scanner never assumes one stack per vhost. A vhost may produce multiple `StackMatch` entries if several markers are detected.

## 4. Module-by-module breakdown

### 4.1 [models.py](../src/vhost_cve_monitor/models.py)

This file defines the central data structures exchanged across the project.

Key dataclasses:

- `NginxLocation`
  Represents a `location {}` block with proxy or FastCGI/uWSGI hints.
- `VhostConfig`
  Represents one parsed nginx `server {}` block.
- `StackMatch`
  Represents one detected stack with confidence, reasons, and root path.
- `Dependency`
  Represents a resolved package name, ecosystem, version, and source.
- `Vulnerability`
  Represents one normalized advisory linked to a dependency version.
- `AuditIssue`
  Joins a `Dependency` and a `Vulnerability`.
- `ScanFailure`
  Represents a non-fatal problem during scanning.
- `StackScanResult`
  Holds dependencies, issues, failures, and executed audit commands for one stack.
- `VhostScanResult`
  Aggregates all stack results for one vhost.
- `NotificationEvent`
  Represents a fully built email alert.

This separation keeps the rest of the code explicit. Data transformation is visible instead of hidden in ad hoc dicts.

### 4.2 [config.py](../src/vhost_cve_monitor/config.py)

This module loads and merges configuration.

Responsibilities:

- define `DEFAULT_CONFIG`
- load YAML from disk
- merge user config over defaults recursively

Important configuration groups:

- `nginx`
  scan roots and include behavior
- `scanner`
  timeouts, scan interval, repeated-failure threshold, walk depth
- `notifications`
  sendmail or SMTP settings
- `state`
  SQLite path and cache TTL
- `logging`
  level and optional file path
- `filters`
  allowlist and blocklist for vhosts and paths

Design choice:

- defaults are embedded in code so the program can still run with a minimal config
- YAML is used only for human-readable operational settings

### 4.3 [logging_utils.py](../src/vhost_cve_monitor/logging_utils.py)

This configures Python logging.

Behavior:

- logs always go to stdout
- optional file logging is added if configured
- if the file cannot be opened, Cerberus falls back to stdout instead of crashing
- `--verbose` in the CLI overrides config level to `DEBUG`

This matters on real systems because a bad log path must not stop the monitor.

### 4.4 [subprocess_utils.py](../src/vhost_cve_monitor/subprocess_utils.py)

This module wraps external command execution.

Responsibilities:

- check if a binary exists with `command_exists()`
- run commands with timeout and captured output
- return a structured `CommandResult`
- parse JSON stdout when applicable

Design choice:

- all external audits are bounded by timeout
- timeout returns a structured result instead of raising through the whole program
- verbose logging shows which command is running and where

This is one of the key anti-hang layers in the system.

### 4.5 [nginx_parser.py](../src/vhost_cve_monitor/nginx_parser.py)

This module is a lightweight nginx parser, not a full nginx interpreter.

Responsibilities:

- tokenize nginx-like syntax
- ignore comments
- parse nested blocks recursively
- extract directives relevant to application discovery
- resolve `include` directives recursively up to a configured maximum depth
- produce one `VhostConfig` per `server {}` block

Extracted data:

- `server_name`
- `root`
- `include`
- `proxy_pass`
- `fastcgi_pass`
- `uwsgi_pass`
- proxy/socket/upstream strings found in locations and include files

Important implementation detail:

- includes are merged into the vhost model for useful dependency-related directives
- this is a practical parser for common layouts, not a full semantic nginx engine

Current limit:

- named `upstream {}` blocks are not resolved into target sockets or URLs yet

### 4.6 [stack_detection.py](../src/vhost_cve_monitor/stack_detection.py)

This module applies explicit filesystem and upstream heuristics.

It does not use opaque rules. Each stack is inferred from concrete markers.

Current heuristics:

- PHP / Composer
  `composer.json` or `composer.lock`
- Node.js / npm
  `package.json`, `package-lock.json`, or `npm-shrinkwrap.json`
- Python / Django
  `requirements.txt`, `pyproject.toml`, `poetry.lock`, or `manage.py`
- Gitea
  `custom/conf/app.ini`, `gitea`, `VERSION`, or an upstream/proxy reference containing `gitea`

Path resolution behavior:

- start from nginx `root` if present
- if the root points to a build output directory such as `build/` or `dist/`, also inspect the parent directory when it clearly contains application manifests
- consider fallback roots from config only for FastCGI or uWSGI style vhosts that do not expose an explicit `root`
- walk down the tree up to `max_directory_walk_depth`

Important guardrails:

- `redirect-only` vhosts are skipped entirely
- proxy-only vhosts without an explicit local root do not scan broad fallback roots such as `/home/webserv`
- ignored directories such as `node_modules`, `vendor`, `.venv`, `venv`, `__pycache__`, and `.git` are pruned from traversal

Why this is important:

- many real deployments have vhost roots pointing to `public/` or `current/public/`
- the actual application files may be one or two levels away

Current risk:

- if a default root like `/home/webserv` is large, directory walking can become expensive
- verbose mode helps reveal when time is spent here

### 4.7 [collectors.py](../src/vhost_cve_monitor/collectors.py)

This module extracts package versions from stack-specific sources.

#### Node.js collection

Supported inputs:

- `package-lock.json`
- `npm-shrinkwrap.json`
- `package.json`

Preference order:

1. lockfile with concrete resolved versions
2. package manifest if only declared versions are available

Behavior:

- if lockfile has `packages`, Cerberus iterates that structure
- otherwise it falls back to classic `dependencies`
- if only `package.json` exists, version strings are simplified by trimming common range prefixes

Limit:

- manifest-only versions may be imprecise if semver ranges are used

#### Composer collection

Supported inputs:

- `composer.lock`
- `composer.json`

Preference order:

1. `composer.lock`
2. `composer.json`

Behavior:

- `packages` and `packages-dev` are read from lockfile
- `require` and `require-dev` are read from manifest fallback
- the synthetic `php` entry is ignored

#### Python collection

Supported inputs:

- `requirements.txt`
- `poetry.lock`
- `venv/bin/python -m pip freeze`
- `.venv/bin/python -m pip freeze`

Behavior:

- pinned `requirements.txt` lines are parsed only when they look like `package==version`
- Poetry lock parsing is line-based and intentionally simple
- if a local virtualenv exists, Cerberus tries `pip freeze`

Limit:

- broad specifiers like `django>=3.2` are not treated as precise installed versions
- `pyproject.toml` is currently only a detection hint, not a full dependency parser

#### Gitea collection

Supported inputs:

- `gitea --version`
- `VERSION` file under the detected root

Behavior:

- if the `gitea` binary exists, it is preferred
- otherwise Cerberus looks for a parseable semver in `VERSION`

### 4.8 [cve_db.py](../src/vhost_cve_monitor/cve_db.py)

This module implements the local vulnerability cache in SQLite.

This is one of the most important design decisions in the project.

#### Why OSV was chosen

Cerberus needs a practical source for ecosystems like:

- npm
- PyPI
- Packagist
- Go

OSV is a good fit because it supports direct queries by:

- package name
- ecosystem
- version

That maps cleanly to Cerberus’s dependency model.

#### What is actually stored

Cerberus does not mirror the whole internet advisory set.

It stores only:

- advisories for package/version tuples it has actually seen
- query timestamps
- normalized advisory metadata

This keeps the DB small in normal deployments.

#### SQLite tables

- `advisories`
  One row per vulnerability id
- `package_findings`
  Links one dependency version to one advisory
- `package_queries`
  Tracks when a package/version was last refreshed

#### Freshness logic

`ensure_fresh()` works like this:

1. look up cached advisories
2. if the cache is fresh enough, return it
3. if offline mode is active, return cached data even if stale
4. otherwise query OSV, store results, then return them

This means a normal scan may refresh missing or old entries on demand.

#### `sync-cve`

The dedicated refresh path iterates all known package/version tuples from `package_queries` and refreshes each one.

This is what the `vhost-cve-monitor-cve-sync.timer` drives periodically.

#### Current limits

- no cache pruning policy yet
- no hybrid source selection yet
- no Debian package security source yet

### 4.9 [state_store.py](../src/vhost_cve_monitor/state_store.py)

This module is responsible for anti-spam behavior.

SQLite tables:

- `alert_state`
- `repeated_failures`

#### Alert deduplication

`should_alert()`:

1. builds a stable hash of the alert payload
2. compares it to the last stored hash for the same fingerprint
3. suppresses identical alerts
4. allows alerts when the payload changes, for example severity

This directly implements:

- send on new vulnerability
- resend when severity or other tracked fields change
- do not keep spamming unchanged alerts

#### Repeated failure tracking

`register_failure()`:

1. hashes the failure detail
2. increments the counter only if the same failure repeats
3. resets effectively when the failure changes
4. emits one alert once the threshold is crossed
5. suppresses repeated mail for the same unchanged repeated failure afterward

This is how Cerberus avoids mailing on every single transient scan problem.

### 4.10 [notify.py](../src/vhost_cve_monitor/notify.py)

This module sends notification emails.

Supported transports:

- local `sendmail`
- SMTP to localhost or another configured endpoint
- authenticated SMTP with STARTTLS
- authenticated SMTP with implicit TLS (`SMTP_SSL`)

Behavior:

- builds a standard `EmailMessage`
- includes hostname header
- adds severity-aware headers such as `X-Cerberus-Severity`, `X-Priority`, `Priority`, and `Importance`
- honors dry-run mode
- logs transport choice in verbose mode
- supports relay authentication via `smtp_username` plus either `smtp_password` or `smtp_password_env`
- rejects invalid combinations such as enabling both `smtp_ssl` and `smtp_starttls`

Dry-run mode is important because it lets you validate the full scan path without spamming real recipients.

Operational note:

- successful local submission only means Cerberus handed the message to the local MTA
- remote delivery still depends on SPF, DKIM, recipient policy, and throttling
- this was validated during live testing: once SPF, DKIM, and DMARC were aligned, delivery reached a clean `mail-tester` result

### 4.11 [audits.py](../src/vhost_cve_monitor/audits.py)

This module contains the stack-specific scanning logic.

Entry point:

- `scan_stack()`

It dispatches by `stack_name`.

#### Shared behavior

For every supported stack:

1. collect dependencies
2. correlate them against the local cache via `_local_db_issues()`
3. run native audit tooling if available
4. normalize those findings into `AuditIssue`
5. deduplicate repeated issues
6. return `StackScanResult`

#### Node.js

- collects dependencies from npm files
- runs `npm audit --json --omit=dev` if `npm` and `package-lock.json` are present
- parses `vulnerabilities` from the audit JSON
- prefers standard identifiers such as `GHSA-...` or `CVE-...` when npm exposes them
- falls back to explicit `NPM-ADVISORY-...` identifiers instead of leaving raw numeric internal IDs in alerts
- keeps the strongest known severity when npm and OSV disagree or when one source only reports `UNKNOWN`
- carries `fixAvailable` data forward so the rendered alert can mention the first known safe version

#### Composer

- collects dependencies from Composer files
- runs `composer audit --format=json --locked` when possible
- converts advisories into internal `AuditIssue`

#### Python

- collects dependencies from requirements, Poetry lock, or local virtualenv
- runs `pip-audit -r requirements.txt --format json` when possible

#### Gitea

- collects version via binary or `VERSION`
- correlates against the local vulnerability cache

Design choice:

- native ecosystem audits are additive
- the local cache correlation is always the common baseline
- if the audit binary is missing, the stack still produces useful output

### 4.12 [scanner.py](../src/vhost_cve_monitor/scanner.py)

This is the top-level orchestrator.

The main class is `CerberusScanner`.

#### Constructor responsibilities

- store config and mode flags
- initialize timeout and thresholds
- initialize `CVEDatabase`
- initialize `StateStore`
- initialize `Mailer`

#### `scan_once()`

This is the main pipeline:

1. load all nginx vhosts
2. apply allowlist/blocklist logic
3. detect stacks per vhost
4. run `scan_stack()` for each stack
5. build notification events for issues and failures
6. send notifications

Verbose logging in this module tells you exactly:

- how many vhosts were loaded
- which vhost is being processed
- how many stacks were detected
- how many dependencies, issues, and failures came out of each stack
- how many notifications were prepared and sent

#### Notification building

Two private methods create mails:

- `_build_issue_notifications()`
- `_build_failure_notifications()`

Important implementation detail:

- issue notifications are not emitted directly from raw `AuditIssue` objects anymore
- Cerberus first normalizes logical findings by advisory id, package, installed version, and evidence path
- only after that merge step does it project the finding back to each exposed vhost for rendering
- this preserves infrastructure visibility while preventing contradictory `MEDIUM` and `UNKNOWN` variants of the same security event

Issue fingerprints are built from:

- vhost
- stack
- dependency
- dependency version
- advisory id
- source file

Logical finding identity is built from:

- canonical advisory id
- package name
- installed version
- evidence path

Failure fingerprints are built from:

- vhost
- failure scope
- failure reason

#### `daemon_loop()`

This is a simple sleep loop driven by `scan_interval_minutes`.

It exists, but the recommended deployment pattern remains `systemd timer`.

Additional test-mail behavior:

- `send_test_mail()` accepts explicit severities and categories
- `send_custom_test_mail()` can simulate a concrete vulnerability with stack, package, version, fixed-version, advisory, vhost, and evidence overrides
- supported categories:
  - `test`
  - `vulnerability`
  - `scan-failure`
  - `internal-error`
  - `digest`
- supported severities:
  - `CRITICAL`
  - `HIGH`
  - `MEDIUM`
  - `WARNING`
  - `LOW`
  - `INFO`
  - `UNKNOWN`
- digest test messages include synthetic grouped alert lines
- real digest mails are rendered from the final retained finding set, then split into explicit severity blocks with per-block recommendations
- vulnerability test messages can exercise stack-aware remediation text without waiting for a real scan finding
- internal-error test messages exercise the dedicated daemon failure path and the GitHub bug-report hint
- compact subjects mirror the real mail path and no longer include redundant markers such as both `ALERT` and `in this scan`

### 4.13 [cli.py](../src/vhost_cve_monitor/cli.py)

This is the user-facing command entry point.

Supported options:

- `--config`
- `--dry-run`
- `--offline`
- `--verbose`

Supported subcommands:

- `scan-once`
- `daemon`
- `sync-cve`
- `test-mail`

Additional `test-mail` options:

- `--severity`
- `--category`
- `--stack`
- `--ecosystem`
- `--package`
- `--installed-version`
- `--fixed-version`
- `--advisory-id`
- `--vhost`
- `--source-file`
- `--source-line`

Unhandled exceptions in `scan-once`, `sync-cve`, and the internal `daemon` loop are reported through `report_internal_error()`. These notifications:

- use category `internal-error`
- keep severity `HIGH`
- are deduplicated through the state store
- bypass digest grouping so operator-facing daemon failures are mailed directly
- invite the operator to open a bug report on the Cerberus GitHub issue tracker when the issue is reproducible

The CLI does very little business logic. It mainly wires together:

- config loading
- logging setup
- scanner construction
- command dispatch

This keeps operational entry concerns separate from scanning logic.

## 5. Data flow in concrete terms

To understand the code, it helps to follow one hypothetical vhost.

Example:

- nginx vhost file points to `/home/webserv/app/current/public`
- include file references PHP FastCGI socket
- inside `/home/webserv/app/current`, Cerberus finds `composer.lock`

What happens:

1. `nginx_parser.py` creates `VhostConfig`
2. `stack_detection.py` sees Composer markers and emits `StackMatch(stack_name="php-composer")`
3. `collectors.py` parses `composer.lock` into many `Dependency` objects
4. `cve_db.py` checks whether each dependency version is fresh in SQLite
5. stale or missing entries are queried from OSV unless `--offline` is set
6. `audits.py` optionally runs `composer audit`
7. issues from OSV cache and issues from Composer are merged
   OSV severity resolution now checks top-level `database_specific.severity` before matched `affected[*]` severity fields, which helps preserve GHSA severities instead of falling back to `UNKNOWN`.
   If OSV only exposes a CVSS score or CVSS v3.x vector, Cerberus derives a canonical severity bucket from that score.
8. `scanner.py` builds alert events
9. `state_store.py` suppresses already known unchanged alerts
10. `notify.py` sends only the resulting new notifications

## 6. Database breakdown

Cerberus currently uses one SQLite file path for both alert state and advisory cache.

That means one database contains:

- advisory cache tables from [cve_db.py](../src/vhost_cve_monitor/cve_db.py)
- anti-spam state tables from [state_store.py](../src/vhost_cve_monitor/state_store.py)

This is operationally simple:

- one file to back up
- one file to inspect with `sqlite3`
- no service dependency

Current consequence:

- the DB mixes two responsibilities
- this is acceptable for a small deployment, but later versions might split cache and state into separate files

## 7. systemd integration

Relevant files:

- [vhost-cve-monitor.service](../packaging/systemd/vhost-cve-monitor.service)
- [vhost-cve-monitor.timer](../packaging/systemd/vhost-cve-monitor.timer)
- [vhost-cve-monitor-cve-sync.service](../packaging/systemd/vhost-cve-monitor-cve-sync.service)
- [vhost-cve-monitor-cve-sync.timer](../packaging/systemd/vhost-cve-monitor-cve-sync.timer)

Recommended runtime model:

- every hour, run a fresh scan
- every six hours, refresh the known cache entries

Operational note:

- restarting a `.timer` does not force an immediate service run
- after `systemctl daemon-reload`, active timers usually continue normally
- use `systemctl enable --now ...timer` to ensure a timer is enabled
- use `systemctl restart ...service` if you want to trigger an immediate scan
- the packaged services call `/opt/cerberus/.venv/bin/vhost-cve-monitor` directly instead of relying on a globally installed Python package

Why timers are preferred here:

- no permanently running Python process required
- easy status inspection with `systemctl` and `journalctl`
- persistent missed-run handling
- simpler failure semantics

Packaging note:

- Debian systems now treat the system interpreter as externally managed
- Cerberus therefore installs itself into `/opt/cerberus/.venv`
- `/usr/local/bin/vhost-cve-monitor` and `/usr/local/bin/vhost-cve-monitor-testmail` are thin wrappers for operators
- the repository also ships a minimal `debian/` packaging layout; the package installs files under `/opt/cerberus` and lets `postinst` create or refresh the venv
- the Debian package uses `--system-site-packages` plus `python3-yaml` to avoid network-dependent `pip` resolution during package installation
- the example config is shipped under `/usr/share/cerberus/config.yml` so maintainer scripts do not depend on repository-only paths during package installation
- notification transport failures such as a missing `/usr/sbin/sendmail` are treated as operational delivery errors, not as internal Cerberus crashes

## 8. Logging and observability

Current observability is centered around structured progress logs.

With `--verbose`, you will see:

- cycle start and end
- command starts
- cache refresh activity
- stack-level progress
- notification sending

This is important because Cerberus can appear blocked when it is actually:

- waiting on `npm audit`
- waiting on `composer audit`
- waiting on `pip-audit`
- waiting on OSV network I/O
- walking a large directory tree

The verbose logs are intended to make those wait points visible.

## 9. Error handling strategy

Cerberus is intentionally fault-tolerant.

Examples:

- unreadable include file
  logs a warning, continues
- missing audit binary
  creates a non-fatal `ScanFailure`, continues
- broken project tree
  affects only that stack or vhost
- OSV refresh failure
  falls back to cached data if present
- bad log file path
  falls back to stdout logging

This is central to the daemon design. On a real server, heterogeneous and partly broken projects are normal, not exceptional.

## 10. Security posture of the implementation

Positive points:

- only non-destructive commands are run
- external tools are bounded by timeouts
- no shell command strings are built dynamically for execution
- subprocesses are run as argument arrays
- state is local and explicit

Current caveats:

- Cerberus trusts local manifests and local filesystem content
- it does not sandbox external audit tools
- OSV data is trusted as an upstream advisory source

This is acceptable for the intended admin-side monitoring role.

## 11. Current known weak points in the code

These are implementation-level limits, not just user-facing caveats.

### nginx interpretation is partial

The parser is good enough for common layouts, but it does not fully evaluate:

- variable expansion
- named upstream block resolution
- all inheritance semantics across nested nginx contexts

### Python package collection is conservative

The implementation prefers precise versions and avoids guessing too much. That means it may miss:

- dependencies defined only in `pyproject.toml`
- editable installs
- unpinned constraints

### Severity normalization is basic

Different upstream tools still format severity differently, but Cerberus now applies a deterministic precedence rule and never lets `UNKNOWN` override a known severity.

### Proxy-to-backend attribution stays heuristic

Cerberus now avoids broad fallback-root scans for proxy-only vhosts, and it can walk from a static `build/` root back to an application parent. That still remains heuristic. It does not resolve arbitrary reverse-proxy targets into concrete project roots automatically.

### Cache growth is unbounded

The advisory cache grows with the number of seen package/version tuples. For most deployments that remains small, but there is no pruning strategy yet.

### One DB file for multiple concerns

This keeps deployment easy, but reduces separation between:

- advisory cache
- alert state

## 12. Extension points

The current structure is intentionally extensible.

To add a new stack cleanly:

1. add heuristics in [stack_detection.py](../src/vhost_cve_monitor/stack_detection.py)
2. add dependency collection in [collectors.py](../src/vhost_cve_monitor/collectors.py)
3. add a scan branch in [audits.py](../src/vhost_cve_monitor/audits.py)
4. map the new ecosystem naming cleanly for `cve_db.py`
5. add tests for detection and deduplication behavior

This modular split is one of the strongest parts of the design.

## 13. Operator mental model

If you need to reason about Cerberus during production use, think of it as five stacked layers:

1. nginx discovery
   What sites and roots exist?
2. stack inference
   What technology is behind each site?
3. version extraction
   What exact dependencies or service versions can be identified?
4. advisory correlation
   What does the local cache or OSV say about those versions?
5. alert policy
   Is this new, changed, or noisy and already known?

When a scan result looks wrong, the fastest way to debug is to identify which of these five layers is failing.

## 14. Practical debugging checklist

When Cerberus seems slow or blocked:

1. run with `--verbose`
2. see whether it stalls before or after vhost loading
3. if it stalls during stack processing, inspect the last stack root path
4. if it stalls on a command start log, inspect that external tool manually
5. if it stalls on OSV refresh logs, test network reachability and latency

Useful commands:

```bash
vhost-cve-monitor --verbose --config /etc/vhost-cve-monitor/config.yml --dry-run scan-once
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity HIGH
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity WARNING --category scan-failure
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity HIGH --category internal-error
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity MEDIUM --category digest
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --category vulnerability --stack nodejs --package lodash --installed-version 4.17.23 --fixed-version ">= 4.17.24" --advisory-id GHSA-35jh-r3h4-6jhm
journalctl -u vhost-cve-monitor.service -n 200 --no-pager
journalctl -u vhost-cve-monitor-cve-sync.service -n 200 --no-pager
sqlite3 /var/lib/vhost-cve-monitor/state.db '.tables'
```

If you need to inspect the normalized finding pipeline, also look at the rendered fixed version and advisory id chosen in dry-run output. This is the fastest way to confirm that OSV and runtime-audit data merged correctly.

## 15. Summary

Cerberus is implemented as a practical, modular, low-dependency scanner:

- nginx parsing is isolated
- stack heuristics are explicit
- dependency collection is per-ecosystem
- advisory correlation is locally cached in SQLite
- alerts are deduplicated and failure-aware
- scheduling is delegated to systemd

The code is already usable for real-world Debian monitoring, but the next obvious engineering steps are:

- upstream block resolution in nginx
- stronger Python dependency parsing
- cache pruning
- hybrid advisory sources beyond OSV
- broader stack-aware remediation logic for additional ecosystems
