#!/bin/bash
# Build Obscura47 into a standalone macOS app
# Requires: pip install pyinstaller

cd "$(dirname "$0")"
source venv/bin/activate
pip install pyinstaller
pyinstaller --onefile --noconsole --name Obscura47 --add-data "src:src" app.py
echo ""
echo "Done! Your binary is in the dist/ folder."
