# -*- mode: python ; coding: utf-8 -*-
"""
Jarwis Agent GUI Setup Wizard - PyInstaller Specification

Builds the professional GUI installer wizard for Jarwis Agent.
This creates a windowed (no console) application with full branding.

Usage:
    pyinstaller installer/jarwis-setup-gui.spec

Output:
    Windows: dist/JarwisAgentSetup-GUI.exe
    macOS:   dist/JarwisAgentSetup-macos
    Linux:   dist/JarwisAgentSetup-linux
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

# Output name based on platform
if IS_WINDOWS:
    APP_NAME = 'JarwisAgentSetup-GUI'
    ICON_PATH = str(ASSETS_DIR / 'jarwis.ico')
elif IS_MACOS:
    APP_NAME = 'JarwisAgentSetup-macos'
    # macOS uses .icns, but we can convert from PNG at build time
    ICON_PATH = str(ASSETS_DIR / 'jarwis.ico')  # PyInstaller handles conversion
else:
    APP_NAME = 'JarwisAgentSetup-linux'
    ICON_PATH = str(ASSETS_DIR / 'jarwis-icon.png') if (ASSETS_DIR / 'jarwis-icon.png').exists() else None

# Version
VERSION = '2.1.0'

# Analysis
a = Analysis(
    [str(GUI_DIR / 'setup_wizard.py')],
    pathex=[str(PROJECT_ROOT), str(INSTALLER_DIR)],
    binaries=[],
    datas=[
        # Include main assets (logo and icon)
        *( [(str(ASSETS_DIR / 'jarwis-logo.png'), '.')] if (ASSETS_DIR / 'jarwis-logo.png').exists() else [] ),
        *( [(str(ASSETS_DIR / 'jarwis.ico'), '.')] if (ASSETS_DIR / 'jarwis.ico').exists() else [] ),
        # Include branding assets folders (only if they exist and have content)
        *( [(str(ASSETS_DIR / 'logos'), 'assets/logos')] if (ASSETS_DIR / 'logos').exists() and any((ASSETS_DIR / 'logos').iterdir()) else [] ),
        *( [(str(ASSETS_DIR / 'bitmaps'), 'assets/bitmaps')] if (ASSETS_DIR / 'bitmaps').exists() else [] ),
        *( [(str(ASSETS_DIR / 'icons'), 'assets/icons')] if (ASSETS_DIR / 'icons').exists() else [] ),
        # Include license
        *( [(str(INSTALLER_DIR / 'LICENSE.rtf'), '.')] if (INSTALLER_DIR / 'LICENSE.rtf').exists() else [] ),
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
        'PIL',  # We use PyQt6 for images
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
    console=False,  # Windowed application - no console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_PATH if ICON_PATH and os.path.exists(ICON_PATH) else None,
    version_file=None,  # TODO: Add version info for Windows
)

# macOS App Bundle
if IS_MACOS:
    app = BUNDLE(
        exe,
        name='Jarwis Agent Setup.app',
        icon=ICON_PATH,
        bundle_identifier='io.jarwis.agent.setup',
        info_plist={
            'CFBundleName': 'Jarwis Agent Setup',
            'CFBundleDisplayName': 'Jarwis Agent Setup',
            'CFBundleVersion': VERSION,
            'CFBundleShortVersionString': VERSION,
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '11.0',
        },
    )
