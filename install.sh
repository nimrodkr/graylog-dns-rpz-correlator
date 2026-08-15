#!/bin/bash
set -euo pipefail

APP_NAME="graylog-dns-rpz-correlator"
APP_USER="rpzcorrelator"
APP_GROUP="rpzcorrelator"

APP_DIR="/opt/${APP_NAME}"
CONF_DIR="/etc/${APP_NAME}"
STATE_DIR="/var/lib/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo:"
    echo "  sudo ./install.sh"
    exit 1
fi

echo "[1/8] Installing Python prerequisites..."

if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y python3 python3-venv python3-pip
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip
else
    echo "Unsupported package manager."
    echo "Install python3, python3-venv and pip manually."
    exit 1
fi

echo "[2/8] Creating service account..."

if ! getent group "${APP_GROUP}" >/dev/null; then
    groupadd --system "${APP_GROUP}"
fi

if ! id "${APP_USER}" >/dev/null 2>&1; then
    useradd \
        --system \
        --gid "${APP_GROUP}" \
        --home-dir "${APP_DIR}" \
        --shell /usr/sbin/nologin \
        "${APP_USER}"
fi

echo "[3/8] Creating directories..."

mkdir -p \
    "${APP_DIR}" \
    "${CONF_DIR}" \
    "${STATE_DIR}"

echo "[4/8] Installing application..."

install -m 0755 rpz_correlator.py "${APP_DIR}/rpz_correlator.py"
install -m 0644 requirements.txt "${APP_DIR}/requirements.txt"

if [[ ! -f "${CONF_DIR}/rpz-correlator.env" ]]; then
    install -m 0640 \
        rpz-correlator.env.example \
        "${CONF_DIR}/rpz-correlator.env"
    echo "Created ${CONF_DIR}/rpz-correlator.env"
else
    echo "Keeping existing ${CONF_DIR}/rpz-correlator.env"
fi

chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"
chown -R "${APP_USER}:${APP_GROUP}" "${STATE_DIR}"
chown root:"${APP_GROUP}" "${CONF_DIR}/rpz-correlator.env"

echo "[5/8] Creating Python virtual environment..."

python3 -m venv "${APP_DIR}/venv"

"${APP_DIR}/venv/bin/pip" install --upgrade pip
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"

echo "[6/8] Installing systemd service..."

install -m 0644 \
    graylog-dns-rpz-correlator.service \
    "${SERVICE_FILE}"

echo "[7/8] Enabling service at boot..."

systemctl daemon-reload
systemctl enable "${APP_NAME}.service"

echo "[8/8] Starting service..."

systemctl restart "${APP_NAME}.service"

echo
echo "Installation complete."
echo
echo "Service status:"
systemctl --no-pager --full status "${APP_NAME}.service" || true
echo
echo "Useful commands:"
echo "  sudo systemctl status ${APP_NAME}"
echo "  sudo systemctl restart ${APP_NAME}"
echo "  sudo systemctl stop ${APP_NAME}"
echo "  sudo journalctl -u ${APP_NAME} -f"
echo
echo "Configuration:"
echo "  ${CONF_DIR}/rpz-correlator.env"
echo
echo "SQLite state:"
echo "  ${STATE_DIR}/state.db"
