# -*- mode: python ; coding: utf-8 -*-
"""
Jarwis Agent System Tray - PyInstaller Specification

Builds the system tray application for Jarwis Agent.
Shows connection status and provides quick actions.

Usage:
    pyinstaller installer/jarwis-tray.spec

Output:
    Windows: dist/jarwis-tray.exe
    macOS:   dist/jarwis-tray
    Linux:   dist/jarwis-tray
"""

import os
import sys
import platform
from pathlib import Path

# Determine platform
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'

# Project paths
PROJECT_ROOT = Path(SPECPATH).parent
INSTALLER_DIR = PROJECT_ROOT / 'installer'
GUI_DIR = INSTALLER_DIR / 'gui'
ASSETS_DIR = INSTALLER_DIR / 'assets'

# Output name
APP_NAME = 'jarwis-tray'

# Icon path - use main jarwis icon
if IS_WINDOWS:
    ICON_PATH = str(ASSETS_DIR / 'jarwis.ico')
elif IS_MACOS:
    ICON_PATH = str(ASSETS_DIR / 'jarwis.ico')  # PyInstaller handles conversion
else:
    ICON_PATH = str(ASSETS_DIR / 'jarwis-icon.png') if (ASSETS_DIR / 'jarwis-icon.png').exists() else None

# Version
VERSION = '2.1.0'

# Analysis
a = Analysis(
    [str(GUI_DIR / 'system_tray.py')],
    pathex=[str(PROJECT_ROOT), str(INSTALLER_DIR)],
    binaries=[],
    datas=[
        # Include main assets (logo and icon)
        *( [(str(ASSETS_DIR / 'jarwis-logo.png'), '.')] if (ASSETS_DIR / 'jarwis-logo.png').exists() else [] ),
        *( [(str(ASSETS_DIR / 'jarwis.ico'), '.')] if (ASSETS_DIR / 'jarwis.ico').exists() else [] ),
        *( [(str(ASSETS_DIR / 'jarwis-icon.png'), '.')] if (ASSETS_DIR / 'jarwis-icon.png').exists() else [] ),
        # Include icons for tray states (only if they exist)
        *( [(str(ASSETS_DIR / 'icons'), 'assets/icons')] if (ASSETS_DIR / 'icons').exists() else [] ),
        *( [(str(ASSETS_DIR / 'logos'), 'assets/logos')] if (ASSETS_DIR / 'logos').exists() and any((ASSETS_DIR / 'logos').iterdir()) else [] ),
    ],
    hiddenimports=[
        'PyQt6',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.sip',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'tkinter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
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
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Windowed - runs in system tray
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_PATH if ICON_PATH and os.path.exists(ICON_PATH) else None,
)

# macOS App Bundle for tray
if IS_MACOS:
    app = BUNDLE(
        exe,
        name='Jarwis Tray.app',
        icon=ICON_PATH,
        bundle_identifier='io.jarwis.agent.tray',
        info_plist={
            'CFBundleName': 'Jarwis Tray',
            'CFBundleDisplayName': 'Jarwis Agent Status',
            'CFBundleVersion': VERSION,
            'CFBundleShortVersionString': VERSION,
            'NSHighResolutionCapable': True,
            'LSUIElement': True,  # Hide from dock (tray app only)
            'LSMinimumSystemVersion': '11.0',
        },
    )
