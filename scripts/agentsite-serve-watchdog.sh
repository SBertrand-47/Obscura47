#!/usr/bin/env bash
# agentsite-serve-watchdog.sh - keep the public agent-operated-site demo alive.
#
# A long-running Obscura node "goes cold": intro circuits idle-close, republish
# silently fails, and the registry descriptor expires OBSCURA_DESCRIPTOR_TTL
# (24h) after the last good republish - so the site 404s while the process is
# still up. This watchdog restarts on cold detection and force-recycles well
# under the TTL. See docs/deploy-public-demo.md. Target: a Linux VM (bash +
# coreutils). Run it under systemd / tmux / nohup.
set -uo pipefail

# --- config (override via env) ---
NAME="${NAME:-the-stacks}"
MODEL="${MODEL:-claude-sonnet-4-6}"
KEY="${KEY:-${NAME}.pem}"
JSONL="${JSONL:-${NAME}-events.jsonl}"
BIND="${BIND:-127.0.0.1}"
PORT="${PORT:-0}"
LOGFILE="${LOGFILE:-${NAME}-serve.log}"
MAX_UPTIME="${MAX_UPTIME:-21600}"       # force-recycle every 6h (< 24h TTL)
COLD_THRESHOLD="${COLD_THRESHOLD:-5}"   # new cold signals in one interval -> restart
CHECK_INTERVAL="${CHECK_INTERVAL:-30}"  # seconds between health checks
PYTHON="${PYTHON:-python}"

COLD_RE='rv_ready timeout|UNREACHABLE|Bad file descriptor|Failed to send frame|established no intro points'

: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY (the operator is a real model)}"
: "${OBSCURA_MODE:?set OBSCURA_MODE=range}"

start_serve() {
  "$PYTHON" -m src.range agentsite --serve \
    --name "$NAME" --key "$KEY" --model "$MODEL" \
    --jsonl "$JSONL" --bind "$BIND" --port "$PORT" \
    >>"$LOGFILE" 2>&1 &
  echo $!
}

echo "[watchdog] supervising agentsite --serve name=$NAME model=$MODEL"
echo "[watchdog] max_uptime=${MAX_UPTIME}s cold_threshold=$COLD_THRESHOLD log=$LOGFILE"

while true; do
  : >"$LOGFILE"                          # fresh log per run -> cold counts are per-run
  pid="$(start_serve)"
  started="$(date +%s)"
  cold_baseline=0
  echo "[watchdog] started serve pid=$pid at $(date -Is)"

  while true; do
    sleep "$CHECK_INTERVAL"

    # 1) process died -> relaunch now
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[watchdog] serve pid=$pid exited; relaunching"
      break
    fi

    # 2) a burst of cold signals -> recycle early (grep -c always prints a count)
    cold_now="$(grep -Ec "$COLD_RE" "$LOGFILE" 2>/dev/null)"; cold_now="${cold_now:-0}"
    if [ "$((cold_now - cold_baseline))" -ge "$COLD_THRESHOLD" ]; then
      echo "[watchdog] cold detected (${cold_now} signals total); recycling"
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      break
    fi
    cold_baseline="$cold_now"

    # 3) force-recycle before the 24h descriptor TTL can lapse
    now="$(date +%s)"
    if [ "$((now - started))" -ge "$MAX_UPTIME" ]; then
      echo "[watchdog] max uptime reached; recycling to refresh the descriptor"
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      break
    fi
  done

  sleep 2                                # brief backoff before relaunch
done
