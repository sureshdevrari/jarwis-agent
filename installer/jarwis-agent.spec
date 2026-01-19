# -*- mode: python ; coding: utf-8 -*-
"""
Jarwis Agent - PyInstaller Specification
Builds cross-platform executable for Windows, macOS, and Linux.
"""

import os
import sys
import platform
from pathlib import Path

# Platform detection
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'

# Paths
PROJECT_ROOT = Path(SPECPATH).parent
APP_NAME = 'jarwis-agent.exe' if IS_WINDOWS else 'jarwis-agent'

# Analysis
a = Analysis(
    [str(PROJECT_ROOT / 'jarwis_agent.py')],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / 'config' / 'config.yaml'), 'config'),
    ],
    hiddenimports=[
        'websockets',
        'websockets.client',
        'aiohttp',
        'yaml',
        'cryptography',
        'ssl',
        'certifi',
        'asyncio',
        'json',
        'logging',
        'pathlib',
        'uuid',
        'socket',
        'struct',
        'subprocess',
        'threading',
        'psutil',
    ],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'scipy',
        'IPython',
        'jupyter',
        'pytest',
    ],
    hookspath=[str(PROJECT_ROOT / 'installer' / 'hooks')],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

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
    upx=True if IS_LINUX else False,
    console=True,
    icon=str(PROJECT_ROOT / 'assets' / 'jarwis-agent.ico') if IS_WINDOWS and (PROJECT_ROOT / 'assets' / 'jarwis-agent.ico').exists() else None,
)
