# -*- mode: python ; coding: utf-8 -*-
"""
Jarwis Universal Agent - PyInstaller Specification File

Builds a single executable for the Jarwis Universal Security Testing Agent.
Supports ALL scan types: Web, Mobile, Network, Cloud, SAST
Supports Windows, macOS, and Linux.

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

# Project root
PROJECT_ROOT = Path(SPECPATH).parent
CORE_PATH = PROJECT_ROOT / 'core'
ATTACKS_PATH = PROJECT_ROOT / 'attacks'

# Output name
APP_NAME = 'jarwis-agent'
if IS_WINDOWS:
    APP_NAME = 'jarwis-agent.exe'

# Icon paths
ICON_WINDOWS = str(PROJECT_ROOT / 'assets' / 'logos' / 'jarwis-agent.ico')
ICON_MACOS = str(PROJECT_ROOT / 'assets' / 'logos' / 'jarwis-agent.icns')

# Version info for Windows
VERSION = '2.0.0'

# Analysis - collect all Python files
a = Analysis(
    # Entry point
    [str(PROJECT_ROOT / 'jarwis_agent.py')],
    
    # Additional paths to search for imports
    pathex=[str(PROJECT_ROOT)],
    
    # Binary files (native libraries)
    binaries=[],
    
    # Data files to include
    datas=[
        # Include config templates
        (str(PROJECT_ROOT / 'config' / 'config.yaml'), 'config'),
        # Include attack payloads
        (str(ATTACKS_PATH / 'payloads'), 'attacks/payloads'),
        # Include mobile agent modules
        (str(CORE_PATH / 'mobile_agent'), 'core/mobile_agent'),
    ],
    
    # Hidden imports that PyInstaller might miss
    hiddenimports=[
        # Universal agent core
        'core.universal_agent',
        
        # Mobile agent modules
        'core.mobile_agent',
        'core.mobile_agent.agent_core',
        'core.mobile_agent.agent_protocol',
        'core.mobile_agent.emulator_controller',
        'core.mobile_agent.frida_manager',
        'core.mobile_agent.local_mitm',
        'core.mobile_agent.traffic_relay',
        'core.mobile_agent.universal_scanner',
        
        # Attack modules for network scanning
        'attacks.network.port_scanner',
        'attacks.network.vuln_scanner',
        'attacks.network.credential_scanner',
        
        # Web attack modules
        'attacks.web',
        
        # SAST modules
        'attacks.sast',
        
        # Cloud modules
        'attacks.cloud',
        
        # Dependencies
        'websockets',
        'websockets.client',
        'aiohttp',
        'frida',
        'mitmproxy',
        'mitmproxy.options',
        'mitmproxy.tools.dump',
        'psutil',
        'netifaces',
        'scapy',
        'scapy.all',
        'nmap',
        'yaml',
        'pyyaml',
        'cryptography',
        'ssl',
        'certifi',
        'playwright',
        'playwright.async_api',
        
        # Standard library that might be missed
        'asyncio',
        'json',
        'logging',
        'pathlib',
        'uuid',
        'socket',
        'struct',
        'subprocess',
        'threading',
        'multiprocessing',
    ],
    
    # Modules to exclude (reduce size)
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'scipy',
        'IPython',
        'jupyter',
        'notebook',
        'pytest',
        'unittest',
    ],
    
    # Runtime hooks
    hookspath=[str(PROJECT_ROOT / 'installer' / 'hooks')],
    
    # Additional PyInstaller hooks
    hooksconfig={},
    
    # Collect all from these packages
    runtime_hooks=[],
    
    # Optimize
    noarchive=False,
    optimize=2,
)

# Remove duplicate binaries/datas
a.binaries = list(set(a.binaries))
a.datas = list(set(a.datas))

# PYZ archive - compressed Python bytecode
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=None,  # No encryption
)

# Single executable
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
    strip=False,  # Don't strip symbols (needed for signing)
    upx=True if IS_LINUX else False,  # UPX compression on Linux only
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Console application (no GUI)
    disable_windowed_traceback=False,
    
    # Windows-specific
    icon=ICON_WINDOWS if IS_WINDOWS and os.path.exists(ICON_WINDOWS) else None,
    version=str(PROJECT_ROOT / 'installer' / 'windows' / 'version_info.txt') if IS_WINDOWS else None,
    
    # macOS-specific
    codesign_identity=os.environ.get('APPLE_CODESIGN_IDENTITY', None),
    entitlements_file=str(PROJECT_ROOT / 'installer' / 'macos' / 'entitlements.plist') if IS_MACOS else None,
    
    # Target arch
    target_arch=None,  # Universal
)

# macOS app bundle (optional, we use PKG instead)
if IS_MACOS:
    app = BUNDLE(
        exe,
        name='Jarwis Agent.app',
        icon=ICON_MACOS if os.path.exists(ICON_MACOS) else None,
        bundle_identifier='com.jarwis.agent',
        version=VERSION,
        info_plist={
            'CFBundleName': 'Jarwis Agent',
            'CFBundleDisplayName': 'Jarwis Security Agent',
            'CFBundleVersion': VERSION,
            'CFBundleShortVersionString': VERSION,
            'LSBackgroundOnly': True,  # Background daemon
            'LSUIElement': True,  # No dock icon
        },
    )
