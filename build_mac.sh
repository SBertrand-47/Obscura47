#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Obscura47 — macOS Build Script
#  Produces: dist/Obscura47.app   (GUI double-clickable app)
#            dist/Obscura47-CLI   (terminal binary)
#
#  Prerequisites:
#    pip3 install pyinstaller
#    pip3 install -r requirement.txt
# ─────────────────────────────────────────────────────────────

set -e

echo ""
echo "============================================"
echo "  Obscura47 — macOS Build"
echo "============================================"
echo ""

# Resolve script directory (works even if called from elsewhere)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.10+ from python.org or via brew."
    exit 1
fi

# Check PyInstaller
if ! python3 -c "import PyInstaller" &>/dev/null; then
    echo "[INFO] Installing PyInstaller..."
    pip3 install pyinstaller
fi

# Install dependencies
echo "[1/4] Installing dependencies..."
pip3 install -r requirement.txt --quiet

HIDDEN_IMPORTS=(
    --hidden-import "src.core.proxy"
    --hidden-import "src.core.node"
    --hidden-import "src.core.exit_node"
    --hidden-import "src.core.registry"
    --hidden-import "src.core.router"
    --hidden-import "src.core.encryptions"
    --hidden-import "src.core.discover"
    --hidden-import "src.core.internet_discovery"
    --hidden-import "src.core.ws_transport"
    --hidden-import "src.core.guards"
    --hidden-import "src.utils.config"
    --hidden-import "src.utils.logger"
    --hidden-import "src.client.obscura_client"
    --hidden-import "websockets"
    --hidden-import "websockets.asyncio.server"
    --hidden-import "websockets.asyncio.client"
    --hidden-import "fastapi"
    --hidden-import "uvicorn"
    --hidden-import "pydantic"
    --hidden-import "aiosqlite"
    --hidden-import "Crypto"
    --hidden-import "Crypto.PublicKey.ECC"
    --hidden-import "Crypto.Cipher.AES"
    --hidden-import "Crypto.Signature.DSS"
    --hidden-import "Crypto.Hash.SHA256"
    --hidden-import "Crypto.Random"
    --collect-all "websockets"
    --collect-all "uvicorn"
)

# ── Build GUI app (.app bundle) ──────────────────────────────
echo "[2/4] Building Obscura47 GUI (.app)..."

# Use icon if it exists
ICON_FLAG=""
if [ -f "assets/icon.icns" ]; then
    ICON_FLAG="--icon assets/icon.icns"
fi

python3 -m PyInstaller \
    --onefile \
    --windowed \
    --name "Obscura47" \
    $ICON_FLAG \
    --add-data "src:src" \
    --add-data ".env.example:." \
    "${HIDDEN_IMPORTS[@]}" \
    --osx-bundle-identifier "com.obscura47.app" \
    app.py

echo "[3/4] Building Obscura47 CLI..."
python3 -m PyInstaller \
    --onefile \
    --console \
    --name "Obscura47-CLI" \
    --add-data "src:src" \
    --add-data ".env.example:." \
    "${HIDDEN_IMPORTS[@]}" \
    src/main.py

echo "[4/4] Done!"
echo ""
echo "  GUI:  dist/Obscura47.app   (double-click to launch)"
echo "  CLI:  dist/Obscura47-CLI"
echo ""
echo "  Usage:"
echo "    GUI:  open dist/Obscura47.app"
echo "    CLI:  ./dist/Obscura47-CLI node"
echo "          ./dist/Obscura47-CLI exit"
echo "          ./dist/Obscura47-CLI proxy"
echo ""
