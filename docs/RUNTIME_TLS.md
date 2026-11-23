# Python runtime and TLS trust

## certifi incident GHSA-6q48-6c7w-9gw2

Absence of an independently installed `certifi` package does not establish
safety: pip includes its own vendored certificate bundle. The Python incident
announcement recommends pip >= 26.2.2 and certifi >= 2026.10.19. That pip release
requires Python >= 3.10; do not install it into Python 3.7 or replace the system
interpreter to work around this requirement.

Sources:

- [Python announcement and wheel checksum](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
- [certifi advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2)
- [Affected certificate fingerprints](https://emudhra.we-have-a-problem.com/roots.json)

## Migration procedure

Create a separate environment with a supported interpreter and `venv
--without-pip`. Verify the pip wheel SHA256 against both the announcement and
independent PyPI release metadata before executing it. Bootstrap from the
verified wheel offline; do not rely on the pip embedded in `ensurepip`.

The application uses `urllib` for advisory HTTP requests and
`ssl.create_default_context()` for SMTP TLS. These normally trust the OpenSSL
system store. Updating certifi alone does not change that store. Modern pip
also combines its certificate bundle with system trust.

Compare exact certificate fingerprints, including cross-signing trust anchors.
Do not remove every certificate with emSign in its name. Where changing system
trust would affect unrelated applications, provision a private Cerberus bundle
containing the permitted system roots and an empty CA directory. Both
`SSL_CERT_FILE` and `SSL_CERT_DIR` must be set: setting only the file can leave
the default hashed certificate directory available.

The locally hardened environment can enforce these paths using its own
`sitecustomize.py`, also setting `REQUESTS_CA_BUNDLE` and `PIP_CERT`. Such a policy
belongs only in Cerberus's virtual environment, never the global Python
installation. It must refuse startup if its trust files are missing. This is
deployment configuration, not a claim that every installation of this package
automatically has the policy. Python started with `-S`, explicitly supplied SSL
contexts, and independent external audit tools require separate consideration.

A private trust bundle is a snapshot: regenerate and validate it when the
system trust store changes. Preserve private organization roots where applicable.
Do not silently fall back to the system bundle if the private bundle disappears.

## Validation and cutover

Run the full tests under the new interpreter, `pip check`, and compare installed
Python sources with the checkout. Verify normal TLS access and rejection of
affected chains with both the application's SSL context and pip's context.

Pause both Cerberus timers and wait for scans and advisory syncs to finish.
Back up configuration, unit definitions and SQLite using SQLite's backup API.
Keep runtime backups private and excluded from Git: they contain operational
data and may contain credentials.

Retain the stable `/opt/cerberus/.venv` path used by services and wrappers;
it may be a symlink to a versioned environment under `/opt/cerberus/.venvs/`.
Keep the previous environment for rollback. Do not move a newly created venv
after installation: its executable shebangs refer to its original location.

Validate `validate-config`, `export-findings`, and the actual systemd service
with `--dry-run`, a copy of the state database, Codex disabled, and an unusable
mail transport as a second safeguard. Remove temporary unit overrides, compare
production state and export with the backup, and restore the original timers.
Do not restore an old database over newer notification history during rollback.

Archived vulnerable environments are emergency rollback artifacts, not safe
active runtimes. Keep timers stopped if rolling back to one. This remediation
does not upgrade the host's Python, OpenSSL, or unrelated applications; those
still need their own lifecycle and certificate-store review.
