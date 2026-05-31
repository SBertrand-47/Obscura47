#!/usr/bin/env bash
# Obscura47 - legacy launcher name kept for compatibility.
# The real, robust launcher is run.sh: it creates or reuses the venv, calls the
# venv's own python directly (no fragile "source activate"), syncs deps, and
# opens the desktop app. This file just hands off to it.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
exec bash ./run.sh "$@"
