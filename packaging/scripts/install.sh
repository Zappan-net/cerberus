#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vhost-cve-monitor}"
STATE_DIR="${STATE_DIR:-/var/lib/vhost-cve-monitor}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
PROJECT_DIR="${PROJECT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}"
VENV_DIR="${VENV_DIR:-${PROJECT_DIR}/.venv}"
WRAPPER_DIR="${PREFIX}/bin"
CERBERUS_BIN="${VENV_DIR}/bin/vhost-cve-monitor"
TESTMAIL_BIN="${VENV_DIR}/bin/vhost-cve-monitor-testmail"

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "python3-venv is required. Install it first, for example: apt-get install python3-venv" >&2
  exit 1
fi

install -d -m 0755 "$CONFIG_DIR"
install -d -m 0755 "$STATE_DIR"
install -d -m 0755 "$SYSTEMD_DIR"
install -d -m 0755 "$WRAPPER_DIR"

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv --system-site-packages "$VENV_DIR"
fi

"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install --upgrade "$PROJECT_DIR"

"${VENV_DIR}/bin/python" - "$PROJECT_DIR" <<'PY'
import pathlib
import sys
import vhost_cve_monitor
source = pathlib.Path(sys.argv[1]) / "src" / "vhost_cve_monitor"
installed = pathlib.Path(vhost_cve_monitor.__file__).resolve().parent
if pathlib.Path(sys.prefix).resolve() not in installed.parents:
    raise SystemExit("Cerberus import is outside its virtual environment")
for path in source.rglob("*.py"):
    target = installed / path.relative_to(source)
    if not target.is_file() or path.read_bytes() != target.read_bytes():
        raise SystemExit("Installed/source mismatch: " + str(path.relative_to(source)))
print("Installed Python modules verified against source:", installed)
PY

install -m 0755 "${PROJECT_DIR}/packaging/scripts/testmail" "$TESTMAIL_BIN"

cat > "${WRAPPER_DIR}/vhost-cve-monitor" <<EOF
#!/bin/sh
exec "${CERBERUS_BIN}" "\$@"
EOF
chmod 0755 "${WRAPPER_DIR}/vhost-cve-monitor"

cat > "${WRAPPER_DIR}/vhost-cve-monitor-testmail" <<EOF
#!/bin/sh
exec "${TESTMAIL_BIN}" "\$@"
EOF
chmod 0755 "${WRAPPER_DIR}/vhost-cve-monitor-testmail"

if [ ! -f "$CONFIG_DIR/config.yml" ]; then
  install -m 0644 "${PROJECT_DIR}/packaging/examples/config.yml" "$CONFIG_DIR/config.yml"
fi

echo "Repository default config: ${PROJECT_DIR}/packaging/examples/config.yml"
echo "Local system config: $CONFIG_DIR/config.yml"
echo "Virtual environment: $VENV_DIR"

install -m 0644 "${PROJECT_DIR}/packaging/systemd/vhost-cve-monitor.service" "$SYSTEMD_DIR/vhost-cve-monitor.service"
install -m 0644 "${PROJECT_DIR}/packaging/systemd/vhost-cve-monitor.timer" "$SYSTEMD_DIR/vhost-cve-monitor.timer"
install -m 0644 "${PROJECT_DIR}/packaging/systemd/vhost-cve-monitor-cve-sync.service" "$SYSTEMD_DIR/vhost-cve-monitor-cve-sync.service"
install -m 0644 "${PROJECT_DIR}/packaging/systemd/vhost-cve-monitor-cve-sync.timer" "$SYSTEMD_DIR/vhost-cve-monitor-cve-sync.timer"

"${VENV_DIR}/bin/python" -m vhost_cve_monitor.systemd_codex --config "$CONFIG_DIR/config.yml" --systemd-dir "$SYSTEMD_DIR"
systemctl daemon-reload
if [ "${ENABLE_TIMERS:-1}" = "1" ]; then
  systemctl enable --now vhost-cve-monitor.timer
  systemctl enable --now vhost-cve-monitor-cve-sync.timer
fi

echo "Installation completed."
