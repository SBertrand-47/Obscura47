#!/bin/bash
# Obscura47 System Tray Launcher (macOS/Linux)
# Runs the tray application in the background

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
nohup python3 "$DIR/tray_app.py" "$@" &>/dev/null &
echo "Obscura47 is running in the background."
