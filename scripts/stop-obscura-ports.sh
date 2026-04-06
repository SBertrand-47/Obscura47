#!/usr/bin/env bash
# Free default Obscura47 listening ports (macOS/Linux).
# Run from project root: bash scripts/stop-obscura-ports.sh
# If you changed ports in .env, add them to PORTS below.

set -euo pipefail

PORTS=(
  50000 50002 50003
  5001 5002
  6000 6001
  8470
  9047 9051 9052
)

for p in "${PORTS[@]}"; do
  pids=$(lsof -ti ":$p" 2>/dev/null || true)
  if [[ -n "${pids:-}" ]]; then
    echo "Port $p: stopping PID(s) $pids"
    kill -9 $pids 2>/dev/null || true
  fi
done

echo "Done. Obscura default ports should be free."
