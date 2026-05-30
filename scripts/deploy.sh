#!/usr/bin/env bash
# Obscura47 - deploy latest code to a VPS and restart its service.
# Run from your local machine:
#   bash scripts/deploy.sh user@host                 # auto-detect service + dir
#   bash scripts/deploy.sh user@host obscura47-node  # pin the service explicitly
#
# The remote install dir is derived from the *running* systemd unit
# (WorkingDirectory), so it works regardless of where the box was cloned
# (/opt, /root, ~, ...) and never assumes a hardcoded path.
set -euo pipefail

VPS="${1:?Usage: deploy.sh user@hostname [service-name]}"
SERVICE="${2:-}"

echo "=== Deploying Obscura47 to $VPS ==="

ssh "$VPS" SERVICE="$SERVICE" bash -s <<'REMOTE'
set -euo pipefail

# Pick the service: explicit arg, else the first active obscura unit.
svc="$SERVICE"
if [ -z "$svc" ]; then
    for cand in obscura47-server obscura47-node obscura-registry; do
        if systemctl is-active --quiet "$cand" 2>/dev/null; then svc="$cand"; break; fi
    done
fi
[ -n "$svc" ] || { echo "[x] No active obscura service found; pass one as the 2nd arg."; exit 1; }

# Derive the install dir from the unit itself - no hardcoded path.
app_dir="$(systemctl show -p WorkingDirectory --value "$svc" 2>/dev/null)"
[ -n "$app_dir" ] && [ -d "$app_dir/.git" ] || { echo "[x] Could not resolve a git checkout from $svc (WorkingDirectory='$app_dir')."; exit 1; }

echo "[*] Service: $svc   Dir: $app_dir"
cd "$app_dir"
echo "[*] Pulling latest code..."
sudo -n git pull origin master 2>/dev/null || git pull origin master
echo "[*] Installing dependencies..."
"$app_dir/venv/bin/pip" install -q -r "$app_dir/requirements.txt"
echo "[*] Restarting $svc..."
sudo systemctl restart "$svc"
sleep 2
if sudo systemctl is-active --quiet "$svc"; then echo "[+] $svc is running"; else echo "[-] $svc failed to start"; exit 1; fi
REMOTE

echo "=== Deploy complete ==="
echo "  Logs: ssh $VPS journalctl -u <service> -f"
