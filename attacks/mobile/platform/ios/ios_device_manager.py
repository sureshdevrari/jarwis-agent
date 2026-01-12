"""
Jarwis AGI Pen Test - iOS Device Manager

Manages real iOS devices via libimobiledevice tools (idevice*).
Handles device discovery, pairing, and security testing setup.

Key Features:
- Real device vs Simulator detection
- Jailbreak status detection
- SSL Kill Switch / Frida setup
- Developer mode and trust management
- App installation and launching

Tools Required:
- libimobiledevice: idevice_id, ideviceinfo, ideviceinstaller
- ios-deploy: App installation on real devices
- Frida: Runtime instrumentation

Device Security Levels:
- JAILBROKEN: Full filesystem access, Cydia/Sileo installed
- CHECKRA1N: Hardware exploit jailbreak (semi-tethered)
- UNJAILBROKEN: Stock iOS, limited testing capabilities
- DEVELOPER: Developer mode enabled, can sideload

Usage:
    manager = IOSDeviceManager()
    devices = await manager.discover_devices()
    
    for device in devices:
        print(f"{device.display_name} - {device.jailbreak_status.value}")
        if device.is_real_device:
            await manager.prepare_device_for_testing(device.udid)

OWASP Mobile Top 10 2024:
- M1: Improper Platform Usage
- M9: Insecure Data Storage
- M5: Insecure Communication
"""

import os
import re
import json
import asyncio
import logging
import platform
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class IOSDeviceType(Enum):
    """Type of iOS device"""
    SIMULATOR = "simulator"
    REAL_DEVICE = "real_device"
    UNKNOWN = "unknown"


class JailbreakStatus(Enum):
    """Jailbreak status of iOS device"""
    JAILBROKEN = "jailbroken"           # Generic jailbreak detected
    CHECKRA1N = "checkra1n"             # checkra1n hardware exploit
    PALERA1N = "palera1n"               # palera1n (rootless/rootful)
    DOPAMINE = "dopamine"               # Dopamine jailbreak
    UNJAILBROKEN = "unjailbroken"       # Stock iOS
    UNKNOWN = "unknown"                 # Cannot determine


class SecurityLevel(Enum):
    """Security level of the device for testing"""
    DEVELOPMENT = "development"         # Developer mode, can sideload
    ENTERPRISE = "enterprise"           # Enterprise-signed apps allowed
    PRODUCTION = "production"           # App Store only
    JAILBROKEN = "jailbroken"          # Full access


@dataclass
class IOSDevice:
    """Represents an iOS device (real or simulator)"""
    # Basic info
    udid: str
    name: str
    device_type: IOSDeviceType
    model: str = ""
    product_type: str = ""       # iPhone15,2 etc
    
    # iOS version
    ios_version: str = ""
    build_version: str = ""
    
    # Security state
    jailbreak_status: JailbreakStatus = JailbreakStatus.UNKNOWN
    security_level: SecurityLevel = SecurityLevel.PRODUCTION
    
    # Device state
    is_paired: bool = False
    is_trusted: bool = False
    is_connected: bool = True
    developer_mode: bool = False
    
    # Capabilities for testing
    can_install_ipa: bool = False
    can_run_frida: bool = False
    can_bypass_ssl: bool = False
    has_cydia: bool = False
    has_sileo: bool = False
    
    # Frida
    frida_server_running: bool = False
    frida_version: str = ""
    
    # Connection
    connection_type: str = "usb"  # usb, wifi, unknown
    wifi_address: str = ""
    
    # Timestamps
    last_seen: str = ""
    
    @property
    def is_real_device(self) -> bool:
        """Check if this is a real device (not simulator)"""
        return self.device_type == IOSDeviceType.REAL_DEVICE
    
    @property
    def is_simulator(self) -> bool:
        """Check if this is a simulator"""
        return self.device_type == IOSDeviceType.SIMULATOR
    
    @property
    def is_jailbroken(self) -> bool:
        """Check if device is jailbroken"""
        return self.jailbreak_status not in [JailbreakStatus.UNJAILBROKEN, JailbreakStatus.UNKNOWN]
    
    @property
    def display_name(self) -> str:
        """Get display name for device"""
        device_type = "📱" if self.is_real_device else "📲"
        jb_indicator = "🔓" if self.is_jailbroken else ""
        return f"{device_type} {self.name} ({self.ios_version}) {jb_indicator}".strip()


# Known jailbreak indicators
JAILBREAK_APPS = [
    "com.saurik.Cydia",           # Cydia
    "org.coolstar.SileoStore",    # Sileo
    "xyz.willy.Zebra",            # Zebra
    "me.alfhaily.installer",      # Installer 5
    "com.opa334.trollstore",      # TrollStore
]

JAILBREAK_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/var/jb",                     # rootless jailbreak
    "/var/lib/dpkg",
    "/var/lib/apt",
    "/etc/apt",
    "/private/var/stash",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/bin/bash",
]


class IOSDeviceManager:
    """
    Manages iOS devices for security testing.
    
    Supports both real devices (via libimobiledevice) and simulators.
    Provides unified interface for device discovery and testing setup.
    """
    
    def __init__(
        self,
        prefer_real_device: bool = True,
        jarwis_home: Optional[str] = None
    ):
        """
        Initialize iOS device manager.
        
        Args:
            prefer_real_device: Prefer real device over simulator if both available
            jarwis_home: Path to Jarwis home directory
        """
        self.prefer_real_device = prefer_real_device
        self.jarwis_home = Path(jarwis_home or os.path.expanduser("~/.jarwis"))
        self.is_macos = platform.system() == "Darwin"
        
        # Cache
        self._devices: Dict[str, IOSDevice] = {}
        self._last_discovery: Optional[datetime] = None
        
        # Tool availability
        self._has_idevice = self._check_tool("idevice_id")
        self._has_ios_deploy = self._check_tool("ios-deploy")
        self._has_frida = self._check_tool("frida")
        self._has_xcrun = self._check_tool("xcrun")
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            cmd = ["where" if os.name == "nt" else "which", tool_name]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    async def _run_command(
        self,
        cmd: List[str],
        timeout: int = 30
    ) -> Tuple[int, str, str]:
        """Run a command asynchronously"""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            return proc.returncode or 0, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -1, "", str(e)
    
    async def discover_devices(self) -> List[IOSDevice]:
        """
        Discover all connected iOS devices and simulators.
        
        Returns:
            List of discovered IOSDevice objects
        """
        devices = []
        
        # Discover real devices via libimobiledevice
        if self._has_idevice:
            real_devices = await self._discover_real_devices()
            devices.extend(real_devices)
        
        # Discover simulators on macOS
        if self.is_macos and self._has_xcrun:
            simulators = await self._discover_simulators()
            devices.extend(simulators)
        
        # Update cache
        self._devices = {d.udid: d for d in devices}
        self._last_discovery = datetime.now()
        
        logger.info(f"Discovered {len(devices)} iOS devices ({len([d for d in devices if d.is_real_device])} real, {len([d for d in devices if d.is_simulator])} simulators)")
        
        return devices
    
    async def _discover_real_devices(self) -> List[IOSDevice]:
        """Discover real iOS devices via libimobiledevice"""
        devices = []
        
        # List device UDIDs
        code, stdout, stderr = await self._run_command(["idevice_id", "-l"])
        
        if code != 0:
            logger.debug(f"idevice_id failed: {stderr}")
            return []
        
        udids = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        
        for udid in udids:
            device = await self._get_device_info(udid)
            if device:
                devices.append(device)
        
        return devices
    
    async def _get_device_info(self, udid: str) -> Optional[IOSDevice]:
        """Get detailed info for a device"""
        # Get basic device info
        code, stdout, stderr = await self._run_command(
            ["ideviceinfo", "-u", udid, "-x"]
        )
        
        if code != 0:
            logger.debug(f"Failed to get info for {udid}: {stderr}")
            return None
        
        try:
            import plistlib
            info = plistlib.loads(stdout.encode())
        except:
            # Fallback to simple parsing
            info = self._parse_ideviceinfo_output(stdout)
        
        device = IOSDevice(
            udid=udid,
            name=info.get("DeviceName", "Unknown iPhone"),
            device_type=IOSDeviceType.REAL_DEVICE,
            model=info.get("ModelNumber", ""),
            product_type=info.get("ProductType", ""),
            ios_version=info.get("ProductVersion", ""),
            build_version=info.get("BuildVersion", ""),
            is_paired=True,
            is_trusted=True,
            is_connected=True,
            last_seen=datetime.now().isoformat()
        )
        
        # Populate additional info
        await self._populate_device_info(device)
        
        return device
    
    def _parse_ideviceinfo_output(self, output: str) -> Dict:
        """Parse ideviceinfo plain text output"""
        info = {}
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip()] = value.strip()
        return info
    
    async def _populate_device_info(self, device: IOSDevice):
        """Populate additional device information"""
        # Check jailbreak status
        device.jailbreak_status = await self._check_jailbreak_status(device.udid)
        
        if device.is_jailbroken:
            device.security_level = SecurityLevel.JAILBROKEN
            device.can_install_ipa = True
            device.can_run_frida = True
            device.can_bypass_ssl = True
        else:
            # Check developer mode
            device.developer_mode = await self._check_developer_mode(device.udid)
            if device.developer_mode:
                device.security_level = SecurityLevel.DEVELOPMENT
                device.can_install_ipa = True
        
        # Check Frida status
        if device.can_run_frida:
            device.frida_server_running = await self._check_frida_server(device.udid)
        
        # Check for Cydia/Sileo
        device.has_cydia = await self._check_app_installed(device.udid, "com.saurik.Cydia")
        device.has_sileo = await self._check_app_installed(device.udid, "org.coolstar.SileoStore")
    
    async def _check_jailbreak_status(self, udid: str) -> JailbreakStatus:
        """Check if device is jailbroken"""
        # Try to check for common jailbreak indicators
        
        # Check for jailbreak apps
        for app_id in JAILBREAK_APPS:
            if await self._check_app_installed(udid, app_id):
                # Determine jailbreak type
                if "trollstore" in app_id:
                    # TrollStore doesn't mean jailbroken
                    continue
                    
                return JailbreakStatus.JAILBROKEN
        
        # Try SSH connection (jailbroken devices often have SSH)
        code, stdout, stderr = await self._run_command(
            ["idevice_id", "-l"]  # Just check if we can communicate
        )
        
        # Check for specific jailbreak tools
        # This is limited without filesystem access
        
        return JailbreakStatus.UNJAILBROKEN
    
    async def _check_developer_mode(self, udid: str) -> bool:
        """Check if developer mode is enabled"""
        # On iOS 16+, developer mode must be enabled
        code, stdout, stderr = await self._run_command(
            ["ideviceinfo", "-u", udid, "-k", "DeveloperStatus"]
        )
        
        return "Development" in stdout
    
    async def _check_app_installed(self, udid: str, bundle_id: str) -> bool:
        """Check if an app is installed on device"""
        code, stdout, stderr = await self._run_command(
            ["ideviceinstaller", "-u", udid, "-l"]
        )
        
        return bundle_id in stdout
    
    async def _check_frida_server(self, udid: str) -> bool:
        """Check if Frida server is running on device"""
        if not self._has_frida:
            return False
        
        try:
            code, stdout, stderr = await self._run_command(
                ["frida-ps", "-U", "-D", udid],
                timeout=5
            )
            return code == 0
        except:
            return False
    
    async def _discover_simulators(self) -> List[IOSDevice]:
        """Discover iOS simulators"""
        devices = []
        
        code, stdout, stderr = await self._run_command(
            ["xcrun", "simctl", "list", "devices", "--json"]
        )
        
        if code != 0:
            return []
        
        try:
            data = json.loads(stdout)
            
            for runtime, runtime_devices in data.get("devices", {}).items():
                # Extract iOS version
                version_match = re.search(r'iOS[- ](\d+[.\-]\d+)', runtime)
                ios_version = version_match.group(1).replace('-', '.') if version_match else "Unknown"
                
                for sim in runtime_devices:
                    if not sim.get("isAvailable", False):
                        continue
                    
                    state = sim.get("state", "Shutdown")
                    
                    device = IOSDevice(
                        udid=sim.get("udid", ""),
                        name=sim.get("name", "Unknown Simulator"),
                        device_type=IOSDeviceType.SIMULATOR,
                        model=sim.get("deviceTypeIdentifier", "").split(".")[-1],
                        ios_version=ios_version,
                        jailbreak_status=JailbreakStatus.UNJAILBROKEN,
                        security_level=SecurityLevel.DEVELOPMENT,
                        is_paired=True,
                        is_trusted=True,
                        is_connected=state == "Booted",
                        developer_mode=True,
                        can_install_ipa=True,
                        can_run_frida=True,
                        can_bypass_ssl=True,
                        last_seen=datetime.now().isoformat()
                    )
                    
                    devices.append(device)
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse simulator list: {e}")
        
        return devices
    
    async def select_device(
        self,
        udid: Optional[str] = None,
        prefer_booted: bool = True
    ) -> Optional[IOSDevice]:
        """
        Select a device for testing.
        
        Priority:
        1. Specified UDID if provided
        2. Real device if prefer_real_device is True
        3. Booted simulator if prefer_booted is True
        4. Any available device
        """
        if not self._devices:
            await self.discover_devices()
        
        if not self._devices:
            return None
        
        # Return specific device if requested
        if udid and udid in self._devices:
            return self._devices[udid]
        
        devices = list(self._devices.values())
        
        # Prefer real devices
        if self.prefer_real_device:
            real_devices = [d for d in devices if d.is_real_device]
            if real_devices:
                # Prefer jailbroken for testing
                jailbroken = [d for d in real_devices if d.is_jailbroken]
                if jailbroken:
                    return jailbroken[0]
                return real_devices[0]
        
        # Prefer booted simulators
        if prefer_booted:
            booted = [d for d in devices if d.is_simulator and d.is_connected]
            if booted:
                return booted[0]
        
        # Return any available
        return devices[0] if devices else None
    
    async def prepare_device_for_testing(
        self,
        udid: str,
        install_frida: bool = True,
        configure_proxy: bool = True
    ) -> Dict:
        """
        Prepare a device for security testing.
        
        Steps:
        1. Verify device is accessible
        2. Install Frida (if jailbroken)
        3. Configure proxy settings
        4. Install CA certificate
        """
        device = self._devices.get(udid)
        if not device:
            return {"success": False, "error": "Device not found"}
        
        result = {
            "success": True,
            "device_udid": udid,
            "device_name": device.name,
            "steps_completed": []
        }
        
        try:
            # Step 1: Verify connectivity
            if device.is_real_device:
                code, _, _ = await self._run_command(["ideviceinfo", "-u", udid])
                if code != 0:
                    return {"success": False, "error": "Cannot connect to device"}
            
            result["steps_completed"].append("connectivity_verified")
            
            # Step 2: Start Frida server (jailbroken only)
            if install_frida and device.is_jailbroken and not device.frida_server_running:
                frida_started = await self._start_frida_server(udid)
                if frida_started:
                    result["steps_completed"].append("frida_started")
                    device.frida_server_running = True
            
            # Step 3: Configure proxy (for MITM)
            if configure_proxy:
                if device.is_simulator:
                    # Simulators use host network, no proxy config needed
                    result["steps_completed"].append("proxy_configured")
                elif device.is_jailbroken:
                    # On jailbroken devices, can set system proxy
                    proxy_set = await self._configure_device_proxy(udid)
                    if proxy_set:
                        result["steps_completed"].append("proxy_configured")
            
            result["device_ready"] = True
            
        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
        
        return result
    
    async def _start_frida_server(self, udid: str) -> bool:
        """Start Frida server on jailbroken device"""
        # This requires SSH access to the device
        try:
            # Try to start frida-server via SSH
            # Note: Requires proper SSH setup with the device
            logger.info(f"Starting Frida server on {udid}")
            
            # For jailbroken devices with SSH:
            # ssh mobile@<device_ip> "/usr/sbin/frida-server -D &"
            
            return False  # Would need SSH implementation
            
        except Exception as e:
            logger.error(f"Failed to start Frida: {e}")
            return False
    
    async def _configure_device_proxy(self, udid: str) -> bool:
        """Configure proxy on device for MITM"""
        # On jailbroken devices, can modify proxy settings
        # On stock devices, user must manually configure
        
        logger.info(f"Proxy configuration for {udid} - manual setup required")
        return False
    
    async def install_ipa(self, udid: str, ipa_path: str) -> bool:
        """Install IPA on device"""
        device = self._devices.get(udid)
        
        if not device:
            logger.error(f"Device {udid} not found")
            return False
        
        if not device.can_install_ipa:
            logger.error(f"Device {udid} cannot install IPAs")
            return False
        
        if device.is_simulator:
            # Use simctl for simulators (needs .app, not .ipa)
            logger.warning("Simulators require .app bundles, not .ipa files")
            return False
        
        # Use ios-deploy for real devices
        if self._has_ios_deploy:
            code, stdout, stderr = await self._run_command(
                ["ios-deploy", "--id", udid, "--bundle", ipa_path],
                timeout=120
            )
            return code == 0
        
        # Fallback to ideviceinstaller
        if self._has_idevice:
            code, stdout, stderr = await self._run_command(
                ["ideviceinstaller", "-u", udid, "-i", ipa_path],
                timeout=120
            )
            return code == 0
        
        return False
    
    async def launch_app(self, udid: str, bundle_id: str) -> bool:
        """Launch an app on device"""
        device = self._devices.get(udid)
        
        if not device:
            return False
        
        if device.is_simulator:
            code, _, _ = await self._run_command(
                ["xcrun", "simctl", "launch", udid, bundle_id]
            )
            return code == 0
        
        # Real device - use idevicedebug
        code, stdout, stderr = await self._run_command(
            ["idevicedebug", "-u", udid, "run", bundle_id],
            timeout=30
        )
        
        return code == 0
    
    async def get_installed_apps(self, udid: str) -> List[Dict]:
        """Get list of installed apps on device"""
        apps = []
        
        device = self._devices.get(udid)
        if not device:
            return apps
        
        if device.is_real_device:
            code, stdout, stderr = await self._run_command(
                ["ideviceinstaller", "-u", udid, "-l", "-o", "list_user"]
            )
            
            if code == 0:
                for line in stdout.strip().split('\n'):
                    if ' - ' in line:
                        bundle_id, name = line.split(' - ', 1)
                        apps.append({
                            "bundle_id": bundle_id.strip(),
                            "name": name.strip()
                        })
        
        return apps
    
    def get_device_security_summary(self, udid: str) -> Dict:
        """Get security-relevant summary for a device"""
        device = self._devices.get(udid)
        
        if not device:
            return {}
        
        return {
            "device_type": device.device_type.value,
            "is_jailbroken": device.is_jailbroken,
            "jailbreak_status": device.jailbreak_status.value,
            "security_level": device.security_level.value,
            "ios_version": device.ios_version,
            "can_install_ipa": device.can_install_ipa,
            "can_run_frida": device.can_run_frida,
            "can_bypass_ssl": device.can_bypass_ssl,
            "frida_running": device.frida_server_running,
            "has_cydia": device.has_cydia,
            "has_sileo": device.has_sileo,
            "testing_capabilities": self._get_testing_capabilities(device)
        }
    
    def _get_testing_capabilities(self, device: IOSDevice) -> List[str]:
        """Get list of testing capabilities for device"""
        capabilities = []
        
        if device.can_install_ipa:
            capabilities.append("IPA installation")
        
        if device.can_run_frida:
            capabilities.append("Frida instrumentation")
            capabilities.append("SSL pinning bypass")
            capabilities.append("Runtime manipulation")
        
        if device.is_jailbroken:
            capabilities.append("Filesystem access")
            capabilities.append("Keychain dumping")
            capabilities.append("Binary analysis")
            capabilities.append("Hook system calls")
        elif device.is_simulator:
            capabilities.append("Filesystem access (simulated)")
            capabilities.append("Network interception")
            capabilities.append("Debug builds")
        else:
            capabilities.append("App installation (with provisioning)")
            capabilities.append("Network traffic (manual proxy)")
        
        return capabilities


# Convenience functions
async def discover_ios_devices() -> List[IOSDevice]:
    """Discover all iOS devices"""
    manager = IOSDeviceManager()
    return await manager.discover_devices()


async def get_best_ios_device() -> Optional[IOSDevice]:
    """Get the best available iOS device for testing"""
    manager = IOSDeviceManager(prefer_real_device=True)
    await manager.discover_devices()
    return await manager.select_device()
