#!/bin/bash
set -euo pipefail

APP_NAME="graylog-dns-rpz-correlator"

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo:"
    echo "  sudo ./uninstall.sh"
    exit 1
fi

systemctl disable --now "${APP_NAME}.service" 2>/dev/null || true
rm -f "/etc/systemd/system/${APP_NAME}.service"
systemctl daemon-reload

echo "Service removed."
echo
echo "Application/config/state were intentionally left in place:"
echo "  /opt/${APP_NAME}"
echo "  /etc/${APP_NAME}"
echo "  /var/lib/${APP_NAME}"
