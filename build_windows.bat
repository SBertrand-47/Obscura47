@echo off
REM ─────────────────────────────────────────────────────────────
REM  Obscura47 — Windows Build Script
REM  Produces: dist/Obscura47.exe  (single-file, no console)
REM            dist/Obscura47-CLI.exe  (single-file, console mode)
REM
REM  Prerequisites:
REM    pip install pyinstaller
REM    pip install -r requirement.txt
REM ─────────────────────────────────────────────────────────────

echo.
echo ============================================
echo   Obscura47 — Windows Build
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from python.org
    pause
    exit /b 1
)

REM Check PyInstaller
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    pip install pyinstaller
)

REM Install dependencies
echo [1/4] Installing dependencies...
pip install -r requirement.txt --quiet

REM ── Build GUI app (windowed, no console) ────────────────────
echo [2/4] Building Obscura47 GUI (.exe)...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name "Obscura47" ^
    --icon "assets\icon.ico" ^
    --add-data "src;src" ^
    --add-data ".env.example;." ^
    --hidden-import "src.core.proxy" ^
    --hidden-import "src.core.node" ^
    --hidden-import "src.core.exit_node" ^
    --hidden-import "src.core.registry" ^
    --hidden-import "src.core.router" ^
    --hidden-import "src.core.encryptions" ^
    --hidden-import "src.core.discover" ^
    --hidden-import "src.core.internet_discovery" ^
    --hidden-import "src.core.ws_transport" ^
    --hidden-import "src.core.guards" ^
    --hidden-import "src.utils.config" ^
    --hidden-import "src.utils.logger" ^
    --hidden-import "src.client.obscura_client" ^
    --hidden-import "websockets" ^
    --hidden-import "websockets.asyncio.server" ^
    --hidden-import "websockets.asyncio.client" ^
    --hidden-import "fastapi" ^
    --hidden-import "uvicorn" ^
    --hidden-import "pydantic" ^
    --hidden-import "aiosqlite" ^
    --hidden-import "Crypto" ^
    --hidden-import "Crypto.PublicKey.ECC" ^
    --hidden-import "Crypto.Cipher.AES" ^
    --hidden-import "Crypto.Signature.DSS" ^
    --hidden-import "Crypto.Hash.SHA256" ^
    --hidden-import "Crypto.Random" ^
    --collect-all "websockets" ^
    --collect-all "uvicorn" ^
    app.py

if errorlevel 1 (
    echo [ERROR] GUI build failed.
    pause
    exit /b 1
)

REM ── Build CLI version (with console) ────────────────────────
echo [3/4] Building Obscura47 CLI (.exe)...
pyinstaller ^
    --onefile ^
    --console ^
    --name "Obscura47-CLI" ^
    --icon "assets\icon.ico" ^
    --add-data "src;src" ^
    --add-data ".env.example;." ^
    --hidden-import "src.core.proxy" ^
    --hidden-import "src.core.node" ^
    --hidden-import "src.core.exit_node" ^
    --hidden-import "src.core.registry" ^
    --hidden-import "src.core.router" ^
    --hidden-import "src.core.encryptions" ^
    --hidden-import "src.core.discover" ^
    --hidden-import "src.core.internet_discovery" ^
    --hidden-import "src.core.ws_transport" ^
    --hidden-import "src.core.guards" ^
    --hidden-import "src.utils.config" ^
    --hidden-import "src.utils.logger" ^
    --hidden-import "src.client.obscura_client" ^
    --hidden-import "websockets" ^
    --hidden-import "websockets.asyncio.server" ^
    --hidden-import "websockets.asyncio.client" ^
    --hidden-import "fastapi" ^
    --hidden-import "uvicorn" ^
    --hidden-import "pydantic" ^
    --hidden-import "aiosqlite" ^
    --hidden-import "Crypto" ^
    --hidden-import "Crypto.PublicKey.ECC" ^
    --hidden-import "Crypto.Cipher.AES" ^
    --hidden-import "Crypto.Signature.DSS" ^
    --hidden-import "Crypto.Hash.SHA256" ^
    --hidden-import "Crypto.Random" ^
    --collect-all "websockets" ^
    --collect-all "uvicorn" ^
    src/main.py

if errorlevel 1 (
    echo [ERROR] CLI build failed.
    pause
    exit /b 1
)

echo [4/4] Done!
echo.
echo   GUI:  dist\Obscura47.exe
echo   CLI:  dist\Obscura47-CLI.exe
echo.
echo   Usage:
echo     GUI:  Double-click Obscura47.exe
echo     CLI:  Obscura47-CLI.exe node
echo           Obscura47-CLI.exe exit
echo           Obscura47-CLI.exe proxy
echo.
pause
