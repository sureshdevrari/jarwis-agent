"""
Mobile iOS Platform Module

Components:
- IOSSimulatorManager: Manages Xcode iOS Simulator
- IOSDeviceManager: Manages real iOS devices via libimobiledevice
- IOSAttackScanner: iOS-specific vulnerability scanning

Device Detection:
- Real device vs Simulator detection
- Jailbreak status detection (checkra1n, palera1n, etc.)
- Developer mode and trust management
- Frida server management
"""

from .ios_attacks import IOSVulnerability, IOSAttackScanner
from .ios_simulator_manager import SimulatorConfig, SimulatorDevice, SimulatorStatus, IOSSimulatorManager
from .ios_device_manager import (
    IOSDeviceManager,
    IOSDevice,
    IOSDeviceType,
    JailbreakStatus,
    SecurityLevel as IOSSecurityLevel,
)

__all__ = [
    # Attack scanner
    'IOSVulnerability', 
    'IOSAttackScanner',
    
    # Simulator management
    'SimulatorConfig', 
    'SimulatorDevice', 
    'SimulatorStatus', 
    'IOSSimulatorManager',
    
    # Device management (NEW)
    'IOSDeviceManager',
    'IOSDevice',
    'IOSDeviceType',
    'JailbreakStatus',
    'IOSSecurityLevel',
]
