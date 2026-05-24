# -*- mode: python ; coding: utf-8 -*-
"""
Obscura47 - PyInstaller Spec File (GUI)
Builds the windowed desktop app.

Usage:  pyinstaller obscura47.spec
"""

import sys
import os

block_cipher = None
is_mac = sys.platform == 'darwin'
is_win = sys.platform == 'win32'

icon_path = None
if is_win and os.path.exists('assets/icon.ico'):
    icon_path = 'assets/icon.ico'
elif is_mac and os.path.exists('assets/icon.icns'):
    icon_path = 'assets/icon.icns'

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
    ['app.py'],
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
    name='Obscura47',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

if is_mac:
    app = BUNDLE(
        exe,
        name='Obscura47.app',
        icon=icon_path,
        bundle_identifier='com.obscura47.app',
        info_plist={
            'CFBundleDisplayName': 'Obscura47',
            'CFBundleShortVersionString': '1.0.0',
            'NSHighResolutionCapable': True,
        },
    )
