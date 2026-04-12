#!/usr/bin/env bash
# Obscura47 — Deploy latest code to VPS
# Run from your local machine:
#   bash scripts/deploy.sh user@db.monmedjs.com
#
# Pulls latest master on the VPS and restarts the service.
set -euo pipefail

VPS="${1:?Usage: deploy.sh user@hostname}"
APP_DIR="/opt/obscura47"

echo "=== Deploying Obscura47 to $VPS ==="

ssh "$VPS" bash -s <<REMOTE
set -euo pipefail
cd "$APP_DIR"
echo "[*] Pulling latest code..."
git pull origin master
echo "[*] Installing dependencies..."
./venv/bin/pip install -q -r requirements.txt
echo "[*] Restarting service..."
sudo systemctl restart obscura47-server
echo "[*] Checking status..."
sleep 2
sudo systemctl is-active obscura47-server && echo "[+] Service is running" || echo "[-] Service failed to start"
REMOTE

echo "=== Deploy complete ==="
echo "  Logs: ssh $VPS journalctl -u obscura47-server -f"
