# -*- mode: python ; coding: utf-8 -*-
"""
Obscura47 — PyInstaller Spec File (CLI)
Builds the command-line binary for running individual roles.

Usage:  pyinstaller obscura47-cli.spec

Result: dist/Obscura47-CLI  (or dist/Obscura47-CLI.exe on Windows)

Run:    ./dist/Obscura47-CLI node
        ./dist/Obscura47-CLI exit
        ./dist/Obscura47-CLI proxy
"""

import sys
import os

block_cipher = None
is_win = sys.platform == 'win32'

icon_path = None
if is_win and os.path.exists('assets/icon.ico'):
    icon_path = 'assets/icon.ico'

hidden_imports = [
    'src.core.proxy',
    'src.core.node',
    'src.core.exit_node',
    'src.core.registry',
    'src.core.router',
    'src.core.encryptions',
    'src.core.discover',
    'src.core.internet_discovery',
    'src.core.ws_transport',
    'src.core.guards',
    'src.utils.config',
    'src.utils.logger',
    'src.client.obscura_client',
    'websockets',
    'websockets.asyncio.server',
    'websockets.asyncio.client',
    'fastapi',
    'uvicorn',
    'pydantic',
    'aiosqlite',
    'Crypto',
    'Crypto.PublicKey.ECC',
    'Crypto.Cipher.AES',
    'Crypto.Signature.DSS',
    'Crypto.Hash.SHA256',
    'Crypto.Random',
]

a = Analysis(
    ['src/main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('src', 'src'),
        ('.env.example', '.'),
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Obscura47-CLI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)
