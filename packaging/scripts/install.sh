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

systemctl daemon-reload
systemctl enable --now vhost-cve-monitor.timer
systemctl enable --now vhost-cve-monitor-cve-sync.timer

echo "Installation completed."
