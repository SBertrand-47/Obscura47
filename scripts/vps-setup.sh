#!/usr/bin/env bash
# Obscura47 — One-time VPS setup
# Run on the VPS as root (or with sudo):
#   bash vps-setup.sh
#
# Prerequisites: Ubuntu/Debian with Python 3.11+ and git installed.
set -euo pipefail

APP_DIR="/opt/obscura47"
APP_USER="obscura"
REPO_URL="https://github.com/SBertrand-47/Obscura47.git"

echo "=== Obscura47 VPS Setup ==="

# Create system user (no login shell)
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir "$APP_DIR" "$APP_USER"
    echo "[+] Created user: $APP_USER"
fi

# Clone or update repo
if [ -d "$APP_DIR/.git" ]; then
    echo "[*] Repo already exists, pulling latest..."
    cd "$APP_DIR"
    git pull origin master
else
    echo "[+] Cloning repo..."
    git clone "$REPO_URL" "$APP_DIR"
    cd "$APP_DIR"
fi

# Create virtualenv and install deps
if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
    echo "[+] Created virtualenv"
fi
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
echo "[+] Dependencies installed"

# Create data directories
mkdir -p /var/lib/obscura47
mkdir -p /home/$APP_USER/.obscura47/audit
chown -R "$APP_USER:$APP_USER" /var/lib/obscura47
chown -R "$APP_USER:$APP_USER" /home/$APP_USER/.obscura47
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# Create .env if it doesn't exist
if [ ! -f "$APP_DIR/.env" ]; then
    cat > "$APP_DIR/.env" <<'ENVEOF'
# Obscura47 VPS Server Configuration
# Registry
OBSCURA_REGISTRY_URL=https://db.monmedjs.com
OBSCURA_REGISTRY_PORT=8470
OBSCURA_REGISTRY_ADMIN_KEY=CHANGE_ME_TO_A_STRONG_SECRET

# Exit node
OBSCURA_EXIT_LISTEN_PORT=6000
OBSCURA_EXIT_WS_PORT=6001

# Security: block exit connections to private IPs
OBSCURA_EXIT_DENY_PRIVATE_IPS=true

# Audit
OBSCURA_EXIT_EGRESS_AUDIT_ENABLED=true
OBSCURA_AUDIT_RETENTION_DAYS=14

# Database
OBSCURA_REGISTRY_DB_PATH=/var/lib/obscura47/registry.db

# Key paths
OBSCURA_EXIT_KEY_PATH=/home/obscura/.obscura47/exit_key.pem

# TLS (uncomment and set paths when you have certs)
# OBSCURA_REGISTRY_TLS_CERT=/etc/letsencrypt/live/db.monmedjs.com/fullchain.pem
# OBSCURA_REGISTRY_TLS_KEY=/etc/letsencrypt/live/db.monmedjs.com/privkey.pem
# OBSCURA_WS_TLS_CERT=/etc/letsencrypt/live/db.monmedjs.com/fullchain.pem
# OBSCURA_WS_TLS_KEY=/etc/letsencrypt/live/db.monmedjs.com/privkey.pem
ENVEOF
    echo "[+] Created .env (edit OBSCURA_REGISTRY_ADMIN_KEY!)"
fi

# Install systemd service
cp "$APP_DIR/scripts/obscura47-server.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable obscura47-server
echo "[+] Systemd service installed and enabled"

echo ""
echo "=== Setup complete ==="
echo "  1. Edit $APP_DIR/.env (set OBSCURA_REGISTRY_ADMIN_KEY)"
echo "  2. Start: systemctl start obscura47-server"
echo "  3. Logs:  journalctl -u obscura47-server -f"
echo ""
