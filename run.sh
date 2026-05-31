#!/usr/bin/env bash
# Obscura47 - one-command launcher (macOS / Linux).
#
# Creates an isolated virtualenv on first run, keeps dependencies in sync, and
# opens the desktop app. No manual "activate" step - it calls the venv's own
# Python directly, which is the same on every platform.
#
#   ./run.sh        then click Connect
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. find a Python 3 interpreter
PY=""
for c in python3 python; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "[x] Python 3.10+ not found. Install it from https://www.python.org/downloads/"; exit 1; }

# 2. reuse an existing venv if present, else create one. The create command is
#    the platform-specific part; afterwards we only ever call venv/bin/python,
#    never "source activate". Existing setups are never recreated or wiped.
if [ -x venv/bin/python ]; then
    echo "[*] Reusing existing virtual environment."
else
    echo "[*] Creating virtual environment (first run)..."
    "$PY" -m venv venv 2>/dev/null || {
        echo "[x] Could not create the virtualenv. On Debian/Ubuntu install it first:"
        echo "      sudo apt install -y python3-venv"
        exit 1
    }
fi
VPY="$PWD/venv/bin/python"

# 3. install/update deps only when requirements.txt changes (fast re-launches)
req_hash="$("$VPY" -c "import hashlib;print(hashlib.md5(open('requirements.txt','rb').read()).hexdigest())")"
if [ "$(cat venv/.req-hash 2>/dev/null || true)" != "$req_hash" ]; then
    echo "[*] Installing dependencies..."
    "$VPY" -m pip install --quiet --upgrade pip
    "$VPY" -m pip install --quiet -r requirements.txt
    echo "$req_hash" > venv/.req-hash
fi

# 4. the GUI is built with PySide6 (Qt 6); pip installs it in step 3, but on
#    minimal Linux it needs a few system libraries to load the Qt plugins.
if ! "$VPY" -c "import PySide6.QtWidgets" >/dev/null 2>&1; then
    echo "[!] PySide6 (the desktop GUI toolkit) could not be loaded."
    case "$(uname -s)" in
        Linux)  echo "    Install Qt's runtime libs:  sudo apt install -y libgl1 libegl1 libxkbcommon0 libdbus-1-3   (Debian/Ubuntu)";;
        Darwin) echo "    Try reinstalling it:  venv/bin/python -m pip install --force-reinstall PySide6-Essentials";;
    esac
    exit 1
fi

echo "[+] Launching Obscura47..."
exec "$VPY" app.py "$@"
