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

# 4. tkinter is the one GUI piece pip can't provide on some platforms
if ! "$VPY" -c "import tkinter" >/dev/null 2>&1; then
    echo "[!] Python 'tkinter' is missing (needed for the desktop GUI)."
    case "$(uname -s)" in
        Linux)  echo "    Install it:  sudo apt install -y python3-tk   (Debian/Ubuntu)";;
        Darwin) echo "    Reinstall Python from python.org, or:  brew install python-tk";;
    esac
    exit 1
fi

echo "[+] Launching Obscura47..."
exec "$VPY" app.py "$@"
