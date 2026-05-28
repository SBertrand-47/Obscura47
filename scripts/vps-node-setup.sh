#!/usr/bin/env bash
# Obscura47 - One-time setup for a DEDICATED RELAY NODE.
# Run on the node VPS (VPS-2) as root (or with sudo):
#   bash vps-node-setup.sh
#
# This box runs only the relay node and points at the existing registry.
# It does NOT run the registry or an exit. Prerequisites: Ubuntu/Debian with
# Python 3.11+ and git installed.
set -euo pipefail

APP_DIR="/opt/obscura47"
DATA_DIR="/var/lib/obscura47"
APP_USER="obscura"
REPO_URL="https://github.com/SBertrand-47/Obscura47.git"

echo "=== Obscura47 Relay Node Setup ==="

# Create system user (no login shell). DATA_DIR is the home so expanduser("~")
# resolves to a writable path under ProtectSystem=strict.
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir "$DATA_DIR" "$APP_USER"
    echo "[+] Created user: $APP_USER"
fi

# Clone or update repo
if [ -d "$APP_DIR/.git" ]; then
    echo "[*] Repo exists, pulling latest..."
    cd "$APP_DIR" && git pull origin master
else
    echo "[+] Cloning repo..."
    git clone "$REPO_URL" "$APP_DIR" && cd "$APP_DIR"
fi

# Virtualenv + deps
if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
    echo "[+] Created virtualenv"
fi
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
echo "[+] Dependencies installed"

# Writable state dir
mkdir -p "$DATA_DIR"
chown -R "$APP_USER:$APP_USER" "$DATA_DIR" "$APP_DIR"

# Node-only .env. No registry/exit config: this box just relays and
# registers itself against the bootstrap registry below.
if [ ! -f "$APP_DIR/.env" ]; then
    cat > "$APP_DIR/.env" <<'ENVEOF'
# Obscura47 Relay Node Configuration
# Point at the bootstrap registry (same default the rest of the network uses).
OBSCURA_REGISTRY_URL=https://db.monmedjs.com

# Relay node listen ports - must be reachable from the public internet.
OBSCURA_NODE_LISTEN_PORT=5001
OBSCURA_NODE_WS_PORT=5002

# Node identity key (distinct file so this node has its own identity).
OBSCURA_NODE_KEY_PATH=/var/lib/obscura47/node_key.pem
ENVEOF
    chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
    echo "[+] Created node .env"
fi

# Install systemd service
cp "$APP_DIR/scripts/obscura47-node.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable obscura47-node
echo "[+] Systemd service installed and enabled"

echo ""
echo "=== Setup complete ==="
echo "  1. Open firewall ports so circuits can reach this relay:"
echo "       ufw allow 5001/tcp   # node TCP"
echo "       ufw allow 5002/tcp   # node WebSocket"
echo "  2. Start: systemctl start obscura47-node"
echo "  3. Logs:  journalctl -u obscura47-node -f"
echo "  4. Confirm it registered: curl -s https://db.monmedjs.com/peers | grep <this-vps-ip>"
echo ""
