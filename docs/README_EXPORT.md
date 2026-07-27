# Cerberus

## Overview

Cerberus is a maintainable Python 3 monitor for Debian servers that inspects nginx vhosts, detects the application stack behind each vhost, runs stack-specific security audits when possible, correlates detected versions with a local SQLite advisory cache, and sends email alerts only for new or materially changed findings.

This export document is intended for editable office formats such as DOCX. It is derived from the repository README and extended with architecture diagrams.

## Architecture Summary

- nginx_parser reads `/etc/nginx/sites-enabled`, resolves useful includes, and extracts server names, roots, and upstream hints.
- stack_detection applies explicit heuristics based on files and upstream names.
- collectors reads package manifests, lockfiles, local virtualenvs, and service version markers.
- audits runs optional ecosystem-native tools such as npm audit, `composer audit`, and `pip-audit`.
- npm scans run both `npm audit --omit=dev` and full `npm audit`, allowing Cerberus to separate production/runtime exposure from development/build dependency maintenance.
- cve_db maintains a local SQLite advisory cache fed by targeted OSV queries.
- state_store prevents alert spam by tracking previously sent findings and repeated failures.
- notify delivers alerts through local sendmail, plain SMTP, STARTTLS SMTP, or authenticated SMTPS/SMTP.
- scanner orchestrates the full scan cycle.
- codex_analysis optionally enriches findings with bounded AI-assisted static triage through Codex CLI. It is disabled by default and never replaces scanner severity.

## Runtime Flow

1. A systemd timer starts the oneshot service.
2. The CLI loads the configuration and initializes logging.
3. Cerberus parses nginx vhost files.
4. Cerberus detects candidate stacks per vhost.
5. Cerberus collects dependency versions.
6. Cerberus correlates versions with the local CVE cache and optional external audit tools.
7. Cerberus deduplicates notifications.
8. Cerberus sends one digest or individual alerts according to configuration.

## Sequence Diagram

See the repository version in `docs/DIAGRAMS.md`.

```mermaid
sequenceDiagram
    autonumber
    participant T as systemd timer
    participant S as vhost-cve-monitor.service
    participant C as CLI
    participant SC as CerberusScanner
    participant N as nginx_parser
    participant D as stack_detection
    participant A as audits/collectors
    participant DB as SQLite cache/state
    participant M as Mailer/Postfix

    T->>S: trigger oneshot service
    S->>C: exec vhost-cve-monitor scan-once
    C->>SC: load config and start scan
    SC->>N: parse /etc/nginx/sites-enabled
    N-->>SC: VhostConfig[]
    loop for each vhost
        SC->>D: detect stacks and roots
        D-->>SC: StackMatch[]
        loop for each stack
            SC->>A: collect dependencies
            A->>DB: lookup cached advisories / refresh if needed
            DB-->>A: Vulnerability[]
            A-->>SC: StackScanResult
        end
        SC->>DB: deduplicate alerts / track failures
    end
    SC->>M: send notifications
```

## Functional Diagram

See the repository version in `docs/DIAGRAMS.md`.

```mermaid
flowchart TD
    A[nginx vhost files] --> B[nginx_parser]
    B --> C[VhostConfig model]
    C --> D[stack_detection]
    D --> E[Stack matches]
    E --> F[collectors]
    F --> G[Dependency inventory]
    G --> H[audits]
    H --> I[Runtime audit findings]
    G --> J[CVEDatabase]
    J --> K[Local SQLite advisory cache]
    K --> L[Correlated vulnerabilities]
    I --> M[Scanner aggregation]
    L --> M
    M --> N[StateStore deduplication]
    N --> O[NotificationEvent]
    O --> P[Mailer]
    P --> Q[sendmail / Postfix / SMTP]
```

## Deployment Model

- Recommended scheduler: systemd timers
- Scan service: `vhost-cve-monitor.service`
- Scan timer: `vhost-cve-monitor.timer`
- CVE refresh service: `vhost-cve-monitor-cve-sync.service`
- CVE refresh timer: `vhost-cve-monitor-cve-sync.timer`

## Configuration Split

- Repository default example: `packaging/examples/config.yml`
- Local machine configuration: `/etc/vhost-cve-monitor/config.yml`

The repository file is generic and safe to publish. The `/etc` file contains deployment-specific recipients, sender domains, and tuning values.

## Mail Policy

- Alerts can be sent individually or grouped.
- Current recommended mode: one digest per scan.
- Messages are handed off to local sendmail/Postfix or to a configured SMTP relay.
- SMTP mode supports both STARTTLS and implicit TLS, with optional authentication credentials.
- Prefer `smtp_password_env` over `smtp_password` when storing relay credentials outside the YAML file.
- Delivery success to the final recipient depends on DNS authentication and remote provider policy.
- Digest subjects are intentionally short and operational, keeping only product, highest severity, host scope, and alert count.
- Alerts and digests show fixed versions when upstream advisory data provides them.
- Digest mails keep the differential-alerting model, but now render retained findings by severity block and include advisory summaries when available.
- npm digest mails split production/runtime findings from full-audit-only development/build findings. Runtime findings drive the primary subject severity when both scopes exist, while development/build findings remain visible in a separate section.
- Identical digest findings sharing the same evidence file, package, installed version, advisory, and audit scope are grouped once with an `Affected targets` list instead of repeated as separate advisory blocks.
- Recommendations are stack-aware and depend on ecosystem, package manager context, and whether a fixed version is known.
- npm recommendations warn when an available fix is semver-major and avoid presenting `npm audit fix --force` as a safe default.
- `test-mail` can simulate explicit severities, categories, and stack-specific vulnerability samples.
- `validate-config` checks the loaded YAML structure and highlights obvious semantic conflicts before a scan starts.
- `doctor` runs a local diagnostic pass over config, key paths, mail transport assumptions, optional audit tools, and nginx parsing.
- `list-vhosts` shows the parsed nginx targets together with filter decisions and detected stacks.
- `explain-vhost <name>` explains how Cerberus sees one target, including candidate roots and stack matches.
- `scan-once --only-vhost ...` restricts a run to one or more selected vhosts for focused troubleshooting.
- `scan-once --force-notify` sends all current vulnerability findings for one invocation without clearing or updating alert fingerprints; it can be combined with `--only-vhost`.
- `export-findings` dumps the latest materialized findings snapshot as JSON for external consumers, and initializes that snapshot with a collection-only pass if none exists yet.
- `export-findings --output /path/file.json` writes that same JSON snapshot directly to a file for automation or a third-party application.
- Optional Codex static analysis can add a clearly separated contextual analysis block to vulnerability alerts and digests. It preserves the official advisory severity and reports contextual risk separately.
- Supported severities: `CRITICAL`, `HIGH`, `MEDIUM`, `WARNING`, `LOW`, `INFO`, `UNKNOWN`
- Supported categories: `test`, `vulnerability`, `scan-failure`, `internal-error`, `digest`
- Example commands:
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity HIGH`
  - `vhost-cve-monitor-testmail HIGH`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity CRITICAL --category vulnerability`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity WARNING --category scan-failure`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity HIGH --category internal-error`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --severity MEDIUM --category digest`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml test-mail --category vulnerability --stack nodejs --package lodash --installed-version 4.17.23 --fixed-version ">= 4.17.24" --advisory-id GHSA-35jh-r3h4-6jhm`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml validate-config`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml doctor`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml list-vhosts`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml explain-vhost app.example.net`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml scan-once --only-vhost app.example.net`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml scan-once --only-vhost app.example.net --force-notify`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml export-findings`
  - `vhost-cve-monitor --config /etc/vhost-cve-monitor/config.yml export-findings --output /var/lib/cerberus/findings.json`
- Unhandled Cerberus execution failures generate a direct `internal-error` mail with a GitHub bug-report hint and are not wrapped into digest mode.
- Live validation note:
  - delivery reached a clean `mail-tester` score after SPF, DKIM, and DMARC were aligned

## Upgrade Existing Installations

If Cerberus is already installed on a machine:

- rerun `sudo sh packaging/scripts/install.sh` from the repository root instead of using global `pip install`
- Cerberus is installed into `/opt/cerberus/.venv`
- admin-facing wrappers are refreshed in `/usr/local/bin/`
- a minimal Debian package is also available through `dpkg-buildpackage -us -uc`, with the same runtime model under `/opt/cerberus/.venv`
- the Debian package relies on `python3-yaml` and a venv created with `--system-site-packages`, so `postinst` does not need to download Python dependencies
- the Debian package ships its example config in `/usr/share/cerberus/config.yml` and only copies it into `/etc/vhost-cve-monitor/config.yml` when no local config exists
- run `systemctl daemon-reload` after changing packaged unit files
- use `systemctl enable --now ...timer` to ensure timers are enabled
- if timers were already active, `daemon-reload` is usually enough unless the unit files changed structurally
- restart the associated `.service` unit, not the `.timer`, when you want to trigger an immediate run
- reload `opendkim` and `postfix` if mail authentication or local MTA integration changed
- the scan timer keeps the materialized findings snapshot current automatically, because each `scan-once` run refreshes the SQLite export state consumed by `export-findings`

Default deployments keep using local sendmail/Postfix. If you keep the example config unchanged, ensure `/usr/sbin/sendmail` exists on the host.
If it does not, Cerberus reports a concise mail-delivery error instead of cascading through an internal Python traceback.

## Optional Codex Static Analysis

Cerberus can optionally invoke Codex CLI to perform static, contextual vulnerability triage for selected findings.

Default status:

- disabled by default
- best-effort only
- no change to existing scan, deduplication, or mail behavior when unavailable
- scanner severity remains authoritative

Typical configuration:

```yaml
codex_analysis:
  enabled: false
  executable: codex
  codex_home: ""
  timeout_seconds: 180
  maximum_output_bytes: 65536
  maximum_findings_per_run: 10
  minimum_severity: MEDIUM
  repository_path: ""
  sandbox: read-only
  network_access: false
  cache_ttl_seconds: 86400
```

Security model:

- Codex is invoked non-interactively with an output schema and `approval_policy="never"`.
- `codex_home` selects the Codex CLI account/config directory. If empty, Cerberus falls back to `<state.state_dir>/codex`.
- The subprocess receives a sanitized environment without SSH agent sockets, cloud credentials, SMTP passwords, or unrelated variables.
- The source tree is treated as untrusted evidence, not as instructions.
- Validated output is rendered as an optional `AI-assisted contextual analysis` section.
- Raw model output is never inserted directly into email.
- Cerberus requests read-only sandboxing through Codex CLI, but final OS-level isolation depends on the local Codex installation and host policy.

Example enriched section:

```text
AI-assisted contextual analysis
Official advisory severity: HIGH
Estimated contextual risk: LOW
Confidence: 82%
Analysis status: completed
Dependency scope: runtime
Reachability: not_observed
Analysis summary: The vulnerable version is present, but no attacker-controlled path was identified.
Limitations: Static analysis cannot exclude dynamically generated inputs.
```

Known limitations:

- Static analysis cannot prove absence of dynamically constructed flows.
- The feature does not update dependencies, patch source files, commit, push, deploy, or create pull requests.
- `unavailable`, `timed_out`, `invalid_output`, `schema_invalid`, and `missing_repository` statuses are diagnostic states only; alert delivery continues normally.

## Known Limits

- nginx parsing is intentionally pragmatic, not a full nginx interpreter.
- Python dependency resolution is strongest when requirements are pinned or a local virtualenv exists.
- Advisory quality depends on upstream OSV coverage and runtime audit tool availability.
- Legacy or proxied deployments can still require stricter vhost-to-backend correlation logic.
- Fixed-version accuracy depends on upstream advisory metadata. Some ecosystems expose only affected ranges, and Cerberus keeps that distinction explicit.

## Repository References

- Internal code walkthrough: `docs/CODE_BREAKDOWN.md`
- Diagrams: `docs/DIAGRAMS.md`
- Main repository README: `README.md`
