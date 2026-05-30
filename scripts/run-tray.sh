#!/bin/bash
# Obscura47 System Tray Launcher (macOS/Linux)
# Runs the tray application in the background

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Prefer the project venv (created by ./run.sh) so deps are guaranteed present;
# fall back to a system Python otherwise.
PY="$DIR/venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"
nohup "$PY" "$DIR/tray_app.py" "$@" &>/dev/null &
echo "Obscura47 is running in the background."
