# -*- mode: python ; coding: utf-8 -*-
"""
Jarwis Agent Configuration Tool - PyInstaller Specification

Builds the post-installation configuration GUI tool.
Allows users to configure server URL, activation key, and test connection.

Usage:
    pyinstaller installer/jarwis-config.spec

Output:
    Windows: dist/jarwis-config.exe
    macOS:   dist/jarwis-config
    Linux:   dist/jarwis-config
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
APP_NAME = 'jarwis-config'

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
    [str(GUI_DIR / 'post_install_config.py')],
    pathex=[str(PROJECT_ROOT), str(INSTALLER_DIR)],
    binaries=[],
    datas=[
        # Include main assets (logo and icon)
        *( [(str(ASSETS_DIR / 'jarwis-logo.png'), '.')] if (ASSETS_DIR / 'jarwis-logo.png').exists() else [] ),
        *( [(str(ASSETS_DIR / 'jarwis.ico'), '.')] if (ASSETS_DIR / 'jarwis.ico').exists() else [] ),
        *( [(str(ASSETS_DIR / 'jarwis-icon.png'), '.')] if (ASSETS_DIR / 'jarwis-icon.png').exists() else [] ),
        # Include branding assets (only if they exist)
        *( [(str(ASSETS_DIR / 'logos'), 'assets/logos')] if (ASSETS_DIR / 'logos').exists() and any((ASSETS_DIR / 'logos').iterdir()) else [] ),
        *( [(str(ASSETS_DIR / 'icons'), 'assets/icons')] if (ASSETS_DIR / 'icons').exists() else [] ),
    ],
    hiddenimports=[
        'PyQt6',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.sip',
        'yaml',  # For config file handling
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
    console=False,  # Windowed application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_PATH if ICON_PATH and os.path.exists(ICON_PATH) else None,
)

# macOS App Bundle
if IS_MACOS:
    app = BUNDLE(
        exe,
        name='Jarwis Config.app',
        icon=ICON_PATH,
        bundle_identifier='io.jarwis.agent.config',
        info_plist={
            'CFBundleName': 'Jarwis Config',
            'CFBundleDisplayName': 'Jarwis Agent Configuration',
            'CFBundleVersion': VERSION,
            'CFBundleShortVersionString': VERSION,
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '11.0',
        },
    )
