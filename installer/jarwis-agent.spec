# -*- mode: python ; coding: utf-8 -*-
"""
Jarwis Agent - PyInstaller Specification File (Standalone)

Builds the standalone Jarwis Security Agent executable.
This is for the jarwis-agent repository, NOT the main jarwis platform.

Usage:
    pyinstaller installer/jarwis-agent.spec

Build variants:
    Windows: jarwis-agent.exe
    macOS:   jarwis-agent
    Linux:   jarwis-agent
"""

import os
import sys
import platform
from pathlib import Path

# Determine platform
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'

# Project root (parent of installer directory)
PROJECT_ROOT = Path(SPECPATH).parent

# Output name
APP_NAME = 'jarwis-agent'
if IS_WINDOWS:
    APP_NAME = 'jarwis-agent.exe'

# Icon paths - check installer/assets first
ICON_DIR = PROJECT_ROOT / 'installer' / 'assets' / 'icons'
ICON_WINDOWS = str(ICON_DIR / 'jarwis-agent.ico') if (ICON_DIR / 'jarwis-agent.ico').exists() else None
ICON_MACOS = str(ICON_DIR / 'jarwis-agent.icns') if (ICON_DIR / 'jarwis-agent.icns').exists() else None

# Version info
VERSION = '2.1.0'

# Data files to include
datas = []

# Include config if it exists
config_path = PROJECT_ROOT / 'config' / 'config.yaml'
if config_path.exists():
    datas.append((str(config_path), 'config'))

# Analysis - the standalone agent
a = Analysis(
    [str(PROJECT_ROOT / 'jarwis_agent.py')],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'asyncio', 'json', 'logging', 'platform', 'socket', 
        'subprocess', 'uuid', 'pathlib',
        'aiohttp', 'websockets', 'yaml', 'psutil',
    ],
    hookspath=[str(PROJECT_ROOT / 'installer' / 'hooks')],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy', 'PIL'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_WINDOWS if IS_WINDOWS else ICON_MACOS,
)
