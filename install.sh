#!/usr/bin/env bash
# install.sh — Build and install the denims account manager service.
# Must be run as root on Ubuntu 24.04 (or later LTS).

set -euo pipefail

BINARY_DEST="/usr/local/bin/denims"
SERVICE_SRC="denims.service"
SERVICE_DEST="/etc/systemd/system/denims.service"
CONFIG_DIR="/var/denims/config"

# ── Checks ──────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "Error: this script must be run as root (use sudo)." >&2
  exit 1
fi

command -v go >/dev/null 2>&1 || {
  echo "Error: Go toolchain not found. Install Go 1.21+ first." >&2
  exit 1
}

# ── Build ────────────────────────────────────────────────────────────────────
echo "==> Building denims..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
(cd "$SCRIPT_DIR" && go build -o denims .)

# ── Install binary ────────────────────────────────────────────────────────────
echo "==> Installing binary to $BINARY_DEST"
install -m 0755 "$SCRIPT_DIR/denims" "$BINARY_DEST"

# ── Create config directory ───────────────────────────────────────────────────
echo "==> Creating config directory $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# ── Install systemd service ───────────────────────────────────────────────────
echo "==> Installing systemd service"
install -m 0644 "$SCRIPT_DIR/$SERVICE_SRC" "$SERVICE_DEST"
systemctl daemon-reload
systemctl enable denims.service

# ── Start the service ─────────────────────────────────────────────────────────
echo "==> Starting denims service"
systemctl start denims.service

echo ""
echo "========================================================"
echo " denims installed successfully!"
echo ""
echo " Service control:"
echo "   sudo systemctl start   denims"
echo "   sudo systemctl stop    denims"
echo "   sudo systemctl restart denims"
echo "   sudo systemctl status  denims"
echo "   sudo journalctl -u denims -f   (view logs)"
echo ""
echo " Web UI:  https://localhost:501"
echo ""
echo " Config:  $CONFIG_DIR/config.json"
echo " TLS:     $CONFIG_DIR/server.crt  /  server.key"
echo " Auth:    $CONFIG_DIR/.htaccess"
echo ""
echo " Default credentials:"
echo "   Username: admin"
echo "   Password: changeme"
echo ""
echo " IMPORTANT: Change the default password after first login!"
echo " Run:  sudo denims-passwd admin <new-password>"
echo "========================================================"
