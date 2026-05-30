#!/usr/bin/env bash
# Obscura47 - macOS double-click launcher.
#
# Finder won't run a .sh on double-click (it opens it in an editor), but it
# runs a .command in Terminal. This just hands off to run.sh, which creates or
# REUSES the virtualenv and opens the desktop app. Terminal users on macOS or
# Linux can run ./run.sh directly instead.
#
# Double-click this file in Finder, then click Connect.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
exec bash ./run.sh "$@"
