#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Obscura47 — Linux Build Script
#  Produces: dist/Obscura47-CLI   (single binary)
#
#  Prerequisites:
#    pip3 install pyinstaller
#    pip3 install -r requirement.txt
# ─────────────────────────────────────────────────────────────

set -e

echo ""
echo "============================================"
echo "  Obscura47 — Linux Build"
echo "============================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.10+."
    exit 1
fi

# Check PyInstaller
if ! python3 -c "import PyInstaller" &>/dev/null; then
    echo "[INFO] Installing PyInstaller..."
    pip3 install pyinstaller
fi

echo "[1/3] Installing dependencies..."
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

echo "[2/3] Building Obscura47-CLI..."
python3 -m PyInstaller \
    --onefile \
    --console \
    --name "Obscura47-CLI" \
    --add-data "src:src" \
    --add-data ".env.example:." \
    "${HIDDEN_IMPORTS[@]}" \
    src/main.py

echo "[3/3] Done!"
echo ""
echo "  Binary: dist/Obscura47-CLI"
echo ""
echo "  Usage:"
echo "    ./dist/Obscura47-CLI node    # Join as relay node"
echo "    ./dist/Obscura47-CLI exit    # Join as exit node"
echo "    ./dist/Obscura47-CLI proxy   # Run local proxy"
echo ""
