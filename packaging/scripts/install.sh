#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vhost-cve-monitor}"
STATE_DIR="${STATE_DIR:-/var/lib/vhost-cve-monitor}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

python3 -m pip install --upgrade "${PWD}"

install -d -m 0755 "$CONFIG_DIR"
install -d -m 0755 "$STATE_DIR"
install -d -m 0755 "$SYSTEMD_DIR"

if [ ! -f "$CONFIG_DIR/config.yml" ]; then
  install -m 0644 packaging/examples/config.yml "$CONFIG_DIR/config.yml"
fi

install -m 0644 packaging/systemd/vhost-cve-monitor.service "$SYSTEMD_DIR/vhost-cve-monitor.service"
install -m 0644 packaging/systemd/vhost-cve-monitor.timer "$SYSTEMD_DIR/vhost-cve-monitor.timer"
install -m 0644 packaging/systemd/vhost-cve-monitor-cve-sync.service "$SYSTEMD_DIR/vhost-cve-monitor-cve-sync.service"
install -m 0644 packaging/systemd/vhost-cve-monitor-cve-sync.timer "$SYSTEMD_DIR/vhost-cve-monitor-cve-sync.timer"

systemctl daemon-reload
systemctl enable --now vhost-cve-monitor.timer
systemctl enable --now vhost-cve-monitor-cve-sync.timer

echo "Installation completed."

