"""
Jarwis AGI Pen Test - ADB Device Manager

Manages both real Android devices and emulators via ADB.
Real devices often have different security behaviors:
- Production security features enabled
- Manufacturer-specific security
- Different root access patterns
- Hardware-backed keystore

Usage:
    manager = ADBDeviceManager()
    devices = await manager.discover_devices()
    
    for device in devices:
        if device.is_real_device:
            print(f"Real device: {device.model} (more realistic testing)")
        else:
            print(f"Emulator: {device.device_id} (easier root access)")
"""

import os
import re
import asyncio
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Type of Android device"""
    EMULATOR = "emulator"
    REAL_DEVICE = "real_device"
    UNKNOWN = "unknown"


class RootStatus(Enum):
    """Root access status"""
    ROOTED = "rooted"
    UNROOTED = "unrooted"
    MAGISK = "magisk"
    SUPERSU = "supersu"
    UNKNOWN = "unknown"


class SecurityLevel(Enum):
    """Device security level for testing"""
    DEBUG = "debug"           # Debug build, easy to test
    USER = "user"             # User build, more secure
    USERDEBUG = "userdebug"   # User-debug build
    PRODUCTION = "production" # Production device with full security


@dataclass
class AndroidDevice:
    """Represents a connected Android device"""
    device_id: str
    device_type: DeviceType
    
    # Device info
    model: str = ""
    manufacturer: str = ""
    product: str = ""
    device: str = ""
    
    # Android version
    sdk_version: int = 0
    android_version: str = ""
    build_type: str = ""  # user, userdebug, eng
    
    # Security info
    root_status: RootStatus = RootStatus.UNKNOWN
    security_patch: str = ""
    selinux_status: str = ""
    verified_boot: bool = True
    encryption_status: str = ""
    
    # Connection info
    transport_id: str = ""
    connection_type: str = ""  # usb, tcp
    is_online: bool = False
    is_authorized: bool = False
    
    # Frida status
    frida_server_running: bool = False
    frida_version: str = ""
    
    # Testing capabilities
    can_install_ca: bool = False
    can_modify_system: bool = False
    has_play_protect: bool = True
    
    @property
    def is_real_device(self) -> bool:
        """Check if this is a real device (not emulator)"""
        return self.device_type == DeviceType.REAL_DEVICE
    
    @property
    def security_level(self) -> SecurityLevel:
        """Determine security level"""
        if self.build_type == "eng":
            return SecurityLevel.DEBUG
        elif self.build_type == "userdebug":
            return SecurityLevel.USERDEBUG
        elif self.is_real_device and self.verified_boot:
            return SecurityLevel.PRODUCTION
        return SecurityLevel.USER
    
    @property
    def display_name(self) -> str:
        """Human-readable device name"""
        if self.is_real_device:
            return f"{self.manufacturer} {self.model} (Android {self.android_version})"
        return f"Emulator {self.device_id} (Android {self.android_version})"


@dataclass
class ADBConfig:
    """Configuration for ADB operations"""
    adb_path: str = "adb"
    timeout: int = 30
    prefer_real_device: bool = True
    auto_root: bool = True
    install_frida: bool = True


class ADBDeviceManager:
    """
    Manages Android devices via ADB for security testing.
    
    Supports both emulators and real devices with automatic detection
    of device capabilities and security features.
    """
    
    # Emulator detection patterns
    EMULATOR_INDICATORS = [
        "sdk_gphone",
        "sdk_google",
        "emulator",
        "goldfish",
        "ranchu",
        "generic",
        "vbox86",
        "genymotion",
        "android_x86"
    ]
    
    # Known root management apps
    ROOT_APPS = {
        "com.topjohnwu.magisk": RootStatus.MAGISK,
        "eu.chainfire.supersu": RootStatus.SUPERSU,
        "com.noshufou.android.su": RootStatus.ROOTED,
        "com.koushikdutta.superuser": RootStatus.ROOTED,
    }
    
    def __init__(self, config: Optional[ADBConfig] = None):
        self.config = config or ADBConfig()
        self._devices: Dict[str, AndroidDevice] = {}
        self._selected_device: Optional[str] = None
        
        # Try to find ADB in common locations
        self._adb_path = self._find_adb()
    
    def _find_adb(self) -> str:
        """Find ADB executable"""
        # Check configured path
        if self.config.adb_path and Path(self.config.adb_path).exists():
            return self.config.adb_path
        
        # Check system PATH
        try:
            result = subprocess.run(
                ["which" if os.name != "nt" else "where", "adb"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
        
        # Check common locations
        common_paths = [
            Path.home() / ".jarwis" / "android-sdk" / "platform-tools" / "adb",
            Path(os.environ.get("ANDROID_HOME", "")) / "platform-tools" / "adb",
            Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "platform-tools" / "adb",
            Path("C:/Android/sdk/platform-tools/adb.exe"),
            Path("/usr/local/android-sdk/platform-tools/adb"),
        ]
        
        for path in common_paths:
            if path.exists():
                return str(path)
            if os.name == "nt" and path.with_suffix(".exe").exists():
                return str(path.with_suffix(".exe"))
        
        return "adb"  # Hope it's in PATH
    
    async def _run_adb(
        self,
        args: List[str],
        device_id: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Tuple[int, str, str]:
        """Run ADB command"""
        cmd = [self._adb_path]
        
        if device_id:
            cmd.extend(["-s", device_id])
        
        cmd.extend(args)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout or self.config.timeout
            )
            return proc.returncode, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    async def discover_devices(self) -> List[AndroidDevice]:
        """Discover all connected Android devices (real and emulator)"""
        logger.info("Discovering Android devices...")
        
        # Start ADB server if needed
        await self._run_adb(["start-server"])
        
        # Get device list
        code, stdout, stderr = await self._run_adb(["devices", "-l"])
        
        if code != 0:
            logger.error(f"Failed to list devices: {stderr}")
            return []
        
        devices = []
        
        for line in stdout.strip().split('\n')[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            device_id = parts[0]
            status = parts[1]
            
            # Parse device info from extended output
            device_info = {}
            for part in parts[2:]:
                if ':' in part:
                    key, value = part.split(':', 1)
                    device_info[key] = value
            
            # Create device object
            device = AndroidDevice(
                device_id=device_id,
                device_type=DeviceType.UNKNOWN,
                model=device_info.get('model', ''),
                product=device_info.get('product', ''),
                device=device_info.get('device', ''),
                transport_id=device_info.get('transport_id', ''),
                is_online=status == 'device',
                is_authorized=status != 'unauthorized'
            )
            
            # Detect device type
            device.device_type = self._detect_device_type(device)
            
            # Get detailed info if online
            if device.is_online:
                await self._populate_device_info(device)
            
            devices.append(device)
            self._devices[device_id] = device
            
            logger.info(
                f"Found device: {device.display_name} "
                f"({'Real' if device.is_real_device else 'Emulator'})"
            )
        
        return devices
    
    def _detect_device_type(self, device: AndroidDevice) -> DeviceType:
        """Detect if device is real or emulator"""
        # Check device ID pattern
        if device.device_id.startswith("emulator-"):
            return DeviceType.EMULATOR
        
        # Check product/model indicators
        check_fields = [
            device.product.lower(),
            device.model.lower(),
            device.device.lower()
        ]
        
        for field in check_fields:
            for indicator in self.EMULATOR_INDICATORS:
                if indicator in field:
                    return DeviceType.EMULATOR
        
        # TCP connections are usually emulators
        if ":" in device.device_id:
            return DeviceType.EMULATOR
        
        return DeviceType.REAL_DEVICE
    
    async def _populate_device_info(self, device: AndroidDevice):
        """Get detailed device information"""
        props = await self._get_device_props(device.device_id)
        
        # Basic info
        device.manufacturer = props.get("ro.product.manufacturer", "")
        device.android_version = props.get("ro.build.version.release", "")
        device.sdk_version = int(props.get("ro.build.version.sdk", "0") or "0")
        device.build_type = props.get("ro.build.type", "")
        device.security_patch = props.get("ro.build.version.security_patch", "")
        
        # Security info
        device.verified_boot = props.get("ro.boot.verifiedbootstate", "") == "green"
        device.encryption_status = props.get("ro.crypto.state", "")
        
        # SELinux status
        code, stdout, _ = await self._run_adb(["shell", "getenforce"], device.device_id)
        if code == 0:
            device.selinux_status = stdout.strip()
        
        # Check root status
        device.root_status = await self._check_root_status(device)
        
        # Check Frida
        await self._check_frida_status(device)
        
        # Determine capabilities
        device.can_modify_system = (
            device.root_status != RootStatus.UNROOTED or
            device.build_type in ["eng", "userdebug"]
        )
        device.can_install_ca = device.can_modify_system
        
        # Check Play Protect (real devices)
        if device.is_real_device:
            code, _, _ = await self._run_adb(
                ["shell", "pm", "list", "packages", "com.google.android.gms"],
                device.device_id
            )
            device.has_play_protect = code == 0
    
    async def _get_device_props(self, device_id: str) -> Dict[str, str]:
        """Get all device properties"""
        code, stdout, _ = await self._run_adb(
            ["shell", "getprop"],
            device_id,
            timeout=10
        )
        
        props = {}
        if code == 0:
            for line in stdout.split('\n'):
                match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line)
                if match:
                    props[match.group(1)] = match.group(2)
        
        return props
    
    async def _check_root_status(self, device: AndroidDevice) -> RootStatus:
        """Check if device is rooted"""
        # Check for su binary
        code, stdout, _ = await self._run_adb(
            ["shell", "which", "su"],
            device.device_id
        )
        has_su = code == 0 and stdout.strip()
        
        # Check for root apps
        code, stdout, _ = await self._run_adb(
            ["shell", "pm", "list", "packages"],
            device.device_id
        )
        
        for package, status in self.ROOT_APPS.items():
            if package in stdout:
                return status
        
        # Try adb root
        code, _, _ = await self._run_adb(["root"], device.device_id)
        if code == 0:
            return RootStatus.ROOTED
        
        return RootStatus.ROOTED if has_su else RootStatus.UNROOTED
    
    async def _check_frida_status(self, device: AndroidDevice):
        """Check if Frida server is running"""
        code, stdout, _ = await self._run_adb(
            ["shell", "pgrep", "-f", "frida-server"],
            device.device_id
        )
        device.frida_server_running = code == 0 and stdout.strip()
        
        if device.frida_server_running:
            # Try to get version
            code, stdout, _ = await self._run_adb(
                ["shell", "/data/local/tmp/frida-server", "--version"],
                device.device_id
            )
            if code == 0:
                device.frida_version = stdout.strip()
    
    async def select_device(
        self,
        device_id: Optional[str] = None,
        prefer_real: Optional[bool] = None
    ) -> Optional[AndroidDevice]:
        """Select a device for testing"""
        if not self._devices:
            await self.discover_devices()
        
        if not self._devices:
            logger.warning("No devices found")
            return None
        
        # If specific device requested
        if device_id and device_id in self._devices:
            self._selected_device = device_id
            return self._devices[device_id]
        
        # Filter online devices
        online_devices = [
            d for d in self._devices.values()
            if d.is_online and d.is_authorized
        ]
        
        if not online_devices:
            logger.warning("No online/authorized devices")
            return None
        
        prefer_real = prefer_real if prefer_real is not None else self.config.prefer_real_device
        
        # Prefer real device if configured
        if prefer_real:
            real_devices = [d for d in online_devices if d.is_real_device]
            if real_devices:
                device = real_devices[0]
                self._selected_device = device.device_id
                logger.info(f"Selected real device: {device.display_name}")
                return device
        
        # Fall back to first available
        device = online_devices[0]
        self._selected_device = device.device_id
        logger.info(f"Selected device: {device.display_name}")
        return device
    
    async def prepare_device_for_testing(
        self,
        device_id: Optional[str] = None
    ) -> bool:
        """Prepare device for security testing"""
        device = self._devices.get(device_id or self._selected_device)
        if not device:
            logger.error("No device selected")
            return False
        
        logger.info(f"Preparing {device.display_name} for testing...")
        
        success = True
        
        # Try to get root
        if self.config.auto_root and device.root_status == RootStatus.UNROOTED:
            if device.device_type == DeviceType.EMULATOR:
                code, _, _ = await self._run_adb(["root"], device.device_id)
                if code == 0:
                    device.root_status = RootStatus.ROOTED
                    device.can_modify_system = True
                    logger.info("Root access enabled (emulator)")
            else:
                logger.warning(
                    "Real device is not rooted. Some tests may be limited. "
                    "Consider using Magisk for root access."
                )
                success = False
        
        # Disable verity on emulator (for system modification)
        if device.device_type == DeviceType.EMULATOR:
            await self._run_adb(["disable-verity"], device.device_id)
            await self._run_adb(["remount"], device.device_id)
        
        # Install Frida if configured
        if self.config.install_frida and not device.frida_server_running:
            frida_installed = await self._install_frida(device)
            if frida_installed:
                device.frida_server_running = True
                logger.info("Frida server installed and running")
        
        return success
    
    async def _install_frida(self, device: AndroidDevice) -> bool:
        """Install and start Frida server on device"""
        # This would download and install frida-server
        # Implementation depends on device architecture
        logger.info("Installing Frida server...")
        
        # Get device architecture
        code, stdout, _ = await self._run_adb(
            ["shell", "getprop", "ro.product.cpu.abi"],
            device.device_id
        )
        arch = stdout.strip()
        
        # Map to Frida architecture
        arch_map = {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86_64": "x86_64",
            "x86": "x86"
        }
        frida_arch = arch_map.get(arch, "arm64")
        
        logger.info(f"Device architecture: {arch} -> Frida {frida_arch}")
        
        # Would download from GitHub releases
        # For now, assume frida-server is pre-downloaded
        frida_path = Path.home() / ".jarwis" / "frida" / f"frida-server-{frida_arch}"
        
        if frida_path.exists():
            # Push to device
            await self._run_adb(
                ["push", str(frida_path), "/data/local/tmp/frida-server"],
                device.device_id
            )
            await self._run_adb(
                ["shell", "chmod", "755", "/data/local/tmp/frida-server"],
                device.device_id
            )
            
            # Start Frida server
            await self._run_adb(
                ["shell", "nohup", "/data/local/tmp/frida-server", "&"],
                device.device_id
            )
            
            await asyncio.sleep(1)
            
            # Verify
            code, stdout, _ = await self._run_adb(
                ["shell", "pgrep", "-f", "frida-server"],
                device.device_id
            )
            return code == 0
        
        logger.warning("Frida server binary not found. Download manually.")
        return False
    
    async def install_apk(
        self,
        apk_path: str,
        device_id: Optional[str] = None,
        grant_permissions: bool = True,
        allow_downgrade: bool = True
    ) -> bool:
        """Install APK on device"""
        device = device_id or self._selected_device
        if not device:
            logger.error("No device selected")
            return False
        
        args = ["install"]
        if grant_permissions:
            args.append("-g")
        if allow_downgrade:
            args.append("-d")
        args.append(apk_path)
        
        code, stdout, stderr = await self._run_adb(args, device, timeout=120)
        
        if code == 0 and "Success" in stdout:
            logger.info(f"APK installed successfully on {device}")
            return True
        
        logger.error(f"Failed to install APK: {stderr}")
        return False
    
    async def configure_proxy(
        self,
        host: str = "10.0.2.2",
        port: int = 8080,
        device_id: Optional[str] = None
    ) -> bool:
        """Configure device proxy for MITM"""
        device = device_id or self._selected_device
        if not device:
            return False
        
        # Set global proxy
        await self._run_adb(
            ["shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"],
            device
        )
        
        logger.info(f"Proxy configured: {host}:{port}")
        return True
    
    async def clear_proxy(self, device_id: Optional[str] = None) -> bool:
        """Clear device proxy settings"""
        device = device_id or self._selected_device
        if not device:
            return False
        
        await self._run_adb(
            ["shell", "settings", "put", "global", "http_proxy", ":0"],
            device
        )
        
        logger.info("Proxy cleared")
        return True
    
    def get_device(self, device_id: Optional[str] = None) -> Optional[AndroidDevice]:
        """Get device by ID or selected device"""
        return self._devices.get(device_id or self._selected_device)
    
    def get_all_devices(self) -> List[AndroidDevice]:
        """Get all discovered devices"""
        return list(self._devices.values())
    
    def get_real_devices(self) -> List[AndroidDevice]:
        """Get only real devices"""
        return [d for d in self._devices.values() if d.is_real_device]
    
    def get_emulators(self) -> List[AndroidDevice]:
        """Get only emulators"""
        return [d for d in self._devices.values() if not d.is_real_device]
    
    async def get_device_security_summary(
        self,
        device_id: Optional[str] = None
    ) -> Dict:
        """Get security-relevant info about device"""
        device = self.get_device(device_id)
        if not device:
            return {}
        
        return {
            "device_id": device.device_id,
            "type": "real_device" if device.is_real_device else "emulator",
            "display_name": device.display_name,
            "android_version": device.android_version,
            "sdk_version": device.sdk_version,
            "security_level": device.security_level.value,
            "root_status": device.root_status.value,
            "selinux": device.selinux_status,
            "verified_boot": device.verified_boot,
            "encryption": device.encryption_status,
            "security_patch": device.security_patch,
            "frida_running": device.frida_server_running,
            "can_modify_system": device.can_modify_system,
            "play_protect": device.has_play_protect,
            "testing_notes": self._get_testing_notes(device)
        }
    
    def _get_testing_notes(self, device: AndroidDevice) -> List[str]:
        """Get security testing notes for device"""
        notes = []
        
        if device.is_real_device:
            notes.append("Real device - more realistic testing environment")
            if device.verified_boot:
                notes.append("Verified boot enabled - tamper detection active")
            if device.has_play_protect:
                notes.append("Play Protect enabled - may detect test payloads")
        else:
            notes.append("Emulator - easier root access but may miss device-specific issues")
        
        if device.root_status == RootStatus.UNROOTED:
            notes.append("Not rooted - limited system access")
        elif device.root_status == RootStatus.MAGISK:
            notes.append("Magisk root - can hide from root detection")
        
        if device.selinux_status == "Enforcing":
            notes.append("SELinux enforcing - strict security policies")
        
        return notes


# Convenience functions
async def discover_devices() -> List[AndroidDevice]:
    """Discover all Android devices"""
    manager = ADBDeviceManager()
    return await manager.discover_devices()


async def get_best_device_for_testing() -> Optional[AndroidDevice]:
    """Get the best device for security testing"""
    manager = ADBDeviceManager()
    await manager.discover_devices()
    return await manager.select_device(prefer_real=True)
