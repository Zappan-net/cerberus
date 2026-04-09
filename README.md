# Cerberus

Cerberus is a maintainable Python 3 monitor for Debian servers that inspects nginx vhosts, detects the application stack behind each vhost, runs stack-specific security audits when possible, correlates detected versions with a local SQLite advisory cache, and sends email alerts only for new or materially changed findings.

License: MIT. See [LICENSE](LICENSE).
Author: Julien Wehrbach.

Detailed internal documentation is available in [docs/CODE_BREAKDOWN.md](docs/CODE_BREAKDOWN.md).
Architecture diagrams are available in [docs/DIAGRAMS.md](docs/DIAGRAMS.md).
An editable office export source is available in [docs/README_EXPORT.md](docs/README_EXPORT.md).

## Architecture

The project is split into explicit layers:

1. `nginx_parser.py`
   Reads files from `/etc/nginx/sites-enabled`, resolves useful `include` directives, and extracts `server_name`, `root`, `proxy_pass`, `fastcgi_pass`, `uwsgi_pass`, and upstream/socket paths.
2. `stack_detection.py`
   Applies readable heuristics on filesystem markers and upstream names. The logic is intentionally explicit, not opaque.
3. `collectors.py`
   Collects dependency versions from common manifests and environments:
   `composer.lock`, `composer.json`, `package-lock.json`, `npm-shrinkwrap.json`, `package.json`, `requirements.txt`, `poetry.lock`, `.venv/bin/python`, `venv/bin/python`, `gitea --version`, and `VERSION`.
4. `audits.py`
   Runs `npm audit`, `composer audit`, and `pip-audit` when available, under a timeout. If a tool is missing or the project is incomplete, Cerberus keeps going and falls back to the local advisory cache.
5. `cve_db.py`
   Maintains a local SQLite advisory cache. The chosen strategy is pragmatic: Cerberus does not mirror all CVEs, it normalizes and caches OSV responses only for the package/version pairs it actually sees. This keeps the local database small and useful on a simple Debian host. Between refreshes, scans can run in offline mode against the cache.
6. `state_store.py`
   Stores alert fingerprints and repeated failure counters to avoid duplicate emails.
7. `notify.py`
   Sends mail through local `sendmail` or SMTP on `localhost`.
8. `scanner.py`
   Orchestrates one full scan, cache refresh, deduplicated notification generation, and the optional internal daemon loop.

## Technical choices

- Python 3 standard library first, plus `PyYAML` for configuration parsing.
- `systemd timer` preferred over an infinite daemon loop. It is simpler, more observable, and more resilient on Debian. An internal `daemon` mode is still provided for environments that want it.
- SQLite for both state and advisory cache, to avoid extra services.
- Local CVE strategy: OSV targeted synchronization plus SQLite normalization.
  Hypothesis: internet access is available during periodic syncs. If not, Cerberus still works against the last cached data.
- External audit tools are optional, not required for the process to continue.
- All variable names, function names, and comments are in English.

## Final tree

```text
.
├── pyproject.toml
├── README.md
├── packaging
│   ├── examples
│   │   ├── config.yml
│   │   ├── sample-email.txt
│   │   └── sample-log.txt
│   ├── scripts
│   │   └── install.sh
│   └── systemd
│       ├── vhost-cve-monitor.service
│       ├── vhost-cve-monitor.timer
│       ├── vhost-cve-monitor-cve-sync.service
│       └── vhost-cve-monitor-cve-sync.timer
├── src
│   └── vhost_cve_monitor
│       ├── __init__.py
│       ├── audits.py
│       ├── cli.py
│       ├── collectors.py
│       ├── config.py
│       ├── cve_db.py
│       ├── logging_utils.py
│       ├── models.py
│       ├── nginx_parser.py
│       ├── notify.py
│       ├── scanner.py
│       ├── stack_detection.py
│       ├── state_store.py
│       └── subprocess_utils.py
└── tests
    ├── test_cli.py
    ├── test_collectors.py
    ├── test_nginx_parser.py
    ├── test_scanner_digest.py
    ├── test_scanner_test_mail.py
    ├── test_stack_detection.py
    └── test_state_store.py
```

## Installation

### Dependencies

- Python 3.7+
- `python3-pip`
- `python3-venv` recommended
- `postfix` configured locally
- Optional but recommended:
  - `npm`
  - `composer`
  - `pip-audit`

### Install

```bash
cd /opt/cerberus
python3 -m pip install .
sudo install -d /etc/vhost-cve-monitor /var/lib/vhost-cve-monitor
sudo cp packaging/examples/config.yml /etc/vhost-cve-monitor/config.yml
sudo cp packaging/systemd/*.service packaging/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vhost-cve-monitor.timer
sudo systemctl enable --now vhost-cve-monitor-cve-sync.timer
```

Or use the helper:

```bash
sudo sh packaging/scripts/install.sh
```

### Upgrade existing installations

If Cerberus is already installed on the machine, update it from the repository root:

```bash
cd /opt/cerberus
python3 -m pip install .
```

If you changed packaged files such as systemd units, reload systemd and ensure the timers are enabled:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vhost-cve-monitor.timer
sudo systemctl enable --now vhost-cve-monitor-cve-sync.timer
```

If the timers were already active, `daemon-reload` is usually enough unless the unit files changed structurally. If you want to force an immediate run, restart the associated `.service` unit instead of the `.timer`.

If you changed mail authentication or local MTA integration, also reload the relevant services:

```bash
sudo systemctl restart opendkim
sudo systemctl reload postfix
```

Recommended post-upgrade checks:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml --dry-run scan-once
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity HIGH
```

## Configuration

Example file: [packaging/examples/config.yml](packaging/examples/config.yml)

Configuration split:

- repository default example: [packaging/examples/config.yml](packaging/examples/config.yml)
- live machine configuration: `/etc/vhost-cve-monitor/config.yml`

The repository file is intentionally generic and safe to publish. The `/etc` file is the local deployment configuration and may contain real recipients, sender domains, and environment-specific tuning.

Main keys:

- `nginx.sites_enabled_dir`: nginx vhost directory to scan.
- `scanner.default_roots`: fallback roots to inspect if nginx `root` is absent or incomplete.
- `scanner.command_timeout_seconds`: timeout for `npm audit`, `composer audit`, `pip-audit`, and `pip freeze`.
- `scanner.repeated_failure_threshold`: number of identical failures before an alert is sent.
- `notifications.method`: `sendmail` or `smtp`.
- `notifications.max_emails_per_run`: hard cap per scan cycle, with overflow grouped into one digest mail.
- `notifications.summary_only`: when enabled, one scan generates one single summary mail containing every alert from that run.
- `filters.*`: allowlist/blocklist for vhosts and paths.

## CLI

Single scan:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml scan-once
```

Dry run:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml --dry-run scan-once
```

Verbose dry run:

```bash
vhost-cve-monitor --verbose --config /etc/vhost-cve-monitor/config.yml --dry-run scan-once
```

Offline scan against cached data only:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml --offline scan-once
```

Manual CVE cache refresh:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml sync-cve
```

Test mail:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail
```

Test mail with explicit severity:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity HIGH
```

Test mail with explicit severity and category:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity CRITICAL --category vulnerability
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity WARNING --category scan-failure
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity MEDIUM --category digest
```

Supported `test-mail` categories:

- `test`
- `vulnerability`
- `scan-failure`
- `digest`

Supported `test-mail` severities:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `WARNING`
- `LOW`
- `INFO`
- `UNKNOWN`

Internal daemon mode:

```bash
vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml daemon
```

## systemd

Recommended unit files:

- [vhost-cve-monitor.service](packaging/systemd/vhost-cve-monitor.service)
- [vhost-cve-monitor.timer](packaging/systemd/vhost-cve-monitor.timer)
- [vhost-cve-monitor-cve-sync.service](packaging/systemd/vhost-cve-monitor-cve-sync.service)
- [vhost-cve-monitor-cve-sync.timer](packaging/systemd/vhost-cve-monitor-cve-sync.timer)

The first timer performs scans. The second refreshes the local advisory cache for already known package/version tuples.

## Notification format

Cerberus sends a mail only when:

- a vulnerability appears for the first time
- the payload changes materially, including severity
- the same scan failure repeats enough times to cross the configured threshold

Mail body fields:

- hostname
- date
- vhost
- stack
- dependency
- detected version
- fixed version when known
- CVE or advisory id
- severity
- summary
- recommendation

Mail presentation:

- compact subject prefix with product, highest severity, host scope, and alert count
- HTML version with color-coded severity banner
- plain text fallback for minimal mail clients
- severity-aware headers such as `X-Cerberus-Severity`, `X-Priority`, `Priority`, and `Importance`
- digest items keep per-vhost visibility even when the same vulnerable project is exposed through multiple hostnames
- recommendations are stack-aware and mention fixed versions when the advisory data allows it

Operational note:

- a successful Cerberus send means local handoff to `sendmail` or SMTP completed
- final delivery still depends on remote acceptance and public mail authentication
- in the current live validation, `zap.one` and `zapandrok.com` both reached a clean `mail-tester` score after SPF, DKIM, and DMARC were aligned

Example: [packaging/examples/sample-email.txt](packaging/examples/sample-email.txt)

## Logging

By default logs go to stdout and can be collected by journald. A file path may also be configured.

Example: [packaging/examples/sample-log.txt](packaging/examples/sample-log.txt)

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Covered critical parts:

- CLI parsing for `test-mail` severity and category simulation
- advisory severity precedence and canonical advisory identifiers
- stack-aware recommendation generation
- fixed version extraction and rendering
- dependency source line preservation where available
- digest deduplication, compact subject rendering, and highest-severity rendering
- nginx config parsing
- stack detection guardrails for redirect-only vhosts, proxy-only vhosts, and build-root parent detection
- logical finding normalization across multiple pipeline stages and vhosts
- alert deduplication and repeated-failure threshold logic

## Example execution

Dry-run single scan:

```bash
$ vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml --dry-run scan-once
{
  "vhosts": 4,
  "notifications": 1
}
```

Typical flow:

1. Parse nginx vhosts and includes.
2. Detect stacks from explicit markers.
3. Collect dependency versions.
4. Run optional ecosystem audit tools.
5. Normalize advisories, severities, aliases, and fixed versions across audit-tool and local-cache sources.
6. Query or reuse the local SQLite advisory cache.
7. Project normalized findings back to the affected vhosts and emit deduplicated notifications.

## Known limits

- nginx parsing is intentionally conservative. It handles common directive layouts but is not a full nginx interpreter.
- Python dependency discovery is strongest when requirements are pinned or a local virtualenv exists.
- Composer, npm, and pip tooling can report more precise runtime findings than manifest-only parsing.
- OSV does not cover every ecosystem with equal depth. The cache is only as complete as the upstream data for the detected packages.
- Gitea version detection is heuristic unless the `gitea` binary is available or a `VERSION` file exists.
- Projects behind `proxy_pass` without a readable local filesystem tree may only yield service-level detection, not full dependency extraction.
- Fixed versions are only as accurate as the upstream advisory metadata. When Cerberus has to infer a first safe version from a range expression, it keeps the wording explicit and conservative.

## Improvement plan

1. Add support for nginx `upstream` blocks and map named upstreams to service sockets more precisely.
2. Add Debian package correlation for proxied services installed through `apt`.
3. Add better parsing for `pyproject.toml` and lockfiles from Poetry, Pipenv, and PDM.
4. Add a plugin interface for new stacks such as Ruby, Java, or generic containers.
5. Add richer remediation guidance for ecosystems beyond npm, Packagist, PyPI, and Go.
6. Add optional report-level controls such as scheduled summary digests, alert suppression windows, and richer notification routing.
