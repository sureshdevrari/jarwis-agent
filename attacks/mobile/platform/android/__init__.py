"""
Mobile Android Platform Module

Components:
- EmulatorManager: Manages Android SDK emulator setup and lifecycle
- ADBDeviceManager: Manages real device detection and configuration
- AndroidAttackScanner: Android-specific vulnerability scanning

Device Detection:
- ADBDeviceManager distinguishes real devices from emulators
- Different security behaviors (verified boot, Play Protect, etc.)
- Root detection (Magisk, SuperSU, etc.)
- Frida server management
"""

from .android_attacks import AndroidVulnerability, AndroidAttackScanner
from .emulator_manager import EmulatorConfig, EmulatorStatus, EmulatorManager
from .adb_device_manager import (
    ADBDeviceManager,
    AndroidDevice,
    DeviceType,
    RootStatus,
    SecurityLevel,
)

__all__ = [
    # Attack scanner
    'AndroidVulnerability', 
    'AndroidAttackScanner',
    
    # Emulator management
    'EmulatorConfig', 
    'EmulatorStatus', 
    'EmulatorManager',
    
    # ADB device management (NEW)
    'ADBDeviceManager',
    'AndroidDevice',
    'DeviceType',
    'RootStatus',
    'SecurityLevel',
]
