"""
Jarwis Mobile Agent - Emulator Controller

Manages Android emulator/device lifecycle for mobile security testing.
Handles device discovery, app installation, proxy configuration.
"""

import asyncio
import logging
import os
import platform
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Information about a connected device/emulator"""
    device_id: str
    status: str                    # device, offline, unauthorized
    device_type: str               # emulator, device
    model: str = ""
    android_version: str = ""
    api_level: int = 0
    is_rooted: bool = False
    frida_running: bool = False
    
    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "status": self.status,
            "device_type": self.device_type,
            "model": self.model,
            "android_version": self.android_version,
            "api_level": self.api_level,
            "is_rooted": self.is_rooted,
            "frida_running": self.frida_running
        }


class EmulatorController:
    """
    Controls Android emulator/device for mobile testing.
    
    Responsibilities:
    - Device/emulator discovery
    - Emulator startup/shutdown
    - App installation and launch
    - Proxy configuration on device
    - Root/Frida server management
    """
    
    AVD_NAME = "jarwis_test_device"
    
    def __init__(self, sdk_path: Optional[str] = None):
        self.sdk_path = self._find_sdk_path(sdk_path)
        self._current_device_id: Optional[str] = None
        self._emulator_process: Optional[asyncio.subprocess.Process] = None
        self._is_running = False
        
        logger.info(f"EmulatorController initialized with SDK: {self.sdk_path}")
    
    @property
    def current_device_id(self) -> str:
        return self._current_device_id or ""
    
    @property
    def is_running(self) -> bool:
        return self._is_running
    
    def _find_sdk_path(self, provided_path: Optional[str]) -> Optional[str]:
        """Find Android SDK path"""
        if provided_path and Path(provided_path).exists():
            return provided_path
        
        # Check environment variables
        for var in ["ANDROID_HOME", "ANDROID_SDK_ROOT"]:
            path = os.environ.get(var)
            if path and Path(path).exists():
                return path
        
        # Common locations
        home = Path.home()
        common_paths = [
            home / "AppData" / "Local" / "Android" / "Sdk",  # Windows
            home / ".jarwis" / "android-sdk",                 # Jarwis custom
            home / "Android" / "Sdk",                         # Linux
            Path("/usr/local/android-sdk"),                   # Linux global
        ]
        
        for path in common_paths:
            if path.exists():
                return str(path)
        
        return None
    
    def _get_adb_path(self) -> str:
        """Get path to adb executable"""
        if not self.sdk_path:
            return "adb"
        
        exe = "adb.exe" if platform.system() == "Windows" else "adb"
        adb_path = Path(self.sdk_path) / "platform-tools" / exe
        return str(adb_path) if adb_path.exists() else "adb"
    
    def _get_emulator_path(self) -> str:
        """Get path to emulator executable"""
        if not self.sdk_path:
            return "emulator"
        
        exe = "emulator.exe" if platform.system() == "Windows" else "emulator"
        emulator_path = Path(self.sdk_path) / "emulator" / exe
        return str(emulator_path) if emulator_path.exists() else "emulator"
    
    async def _run_adb(self, *args, device_id: Optional[str] = None, timeout: int = 30) -> tuple:
        """Run ADB command and return (stdout, stderr, returncode)"""
        cmd = [self._get_adb_path()]
        
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
                timeout=timeout
            )
            return stdout.decode(), stderr.decode(), proc.returncode
            
        except asyncio.TimeoutError:
            logger.error(f"ADB command timeout: {' '.join(cmd)}")
            return "", "timeout", -1
        except Exception as e:
            logger.error(f"ADB command failed: {e}")
            return "", str(e), -1
    
    async def list_devices(self) -> List[DeviceInfo]:
        """List connected devices and emulators"""
        stdout, stderr, rc = await self._run_adb("devices", "-l")
        
        if rc != 0:
            logger.error(f"Failed to list devices: {stderr}")
            return []
        
        devices = []
        for line in stdout.strip().split("\n")[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            device_id = parts[0]
            status = parts[1]
            
            device_type = "emulator" if device_id.startswith("emulator") else "device"
            
            # Get more details if device is online
            model = ""
            android_version = ""
            api_level = 0
            
            if status == "device":
                # Get model
                model_out, _, _ = await self._run_adb(
                    "shell", "getprop", "ro.product.model",
                    device_id=device_id
                )
                model = model_out.strip()
                
                # Get Android version
                ver_out, _, _ = await self._run_adb(
                    "shell", "getprop", "ro.build.version.release",
                    device_id=device_id
                )
                android_version = ver_out.strip()
                
                # Get API level
                api_out, _, _ = await self._run_adb(
                    "shell", "getprop", "ro.build.version.sdk",
                    device_id=device_id
                )
                try:
                    api_level = int(api_out.strip())
                except ValueError:
                    pass
            
            devices.append(DeviceInfo(
                device_id=device_id,
                status=status,
                device_type=device_type,
                model=model,
                android_version=android_version,
                api_level=api_level
            ))
        
        return devices
    
    async def ensure_device_ready(self) -> Optional[str]:
        """
        Ensure a device/emulator is available.
        Prefers real devices, falls back to starting emulator.
        
        Returns device ID if available, None otherwise.
        """
        devices = await self.list_devices()
        
        # Prefer real devices
        for device in devices:
            if device.status == "device" and device.device_type == "device":
                self._current_device_id = device.device_id
                self._is_running = True
                logger.info(f"Using real device: {device.device_id} ({device.model})")
                return device.device_id
        
        # Use existing emulator
        for device in devices:
            if device.status == "device" and device.device_type == "emulator":
                self._current_device_id = device.device_id
                self._is_running = True
                logger.info(f"Using running emulator: {device.device_id}")
                return device.device_id
        
        # Start new emulator
        logger.info("No device available, starting emulator...")
        return await self.start_emulator()
    
    async def start_emulator(self, avd_name: Optional[str] = None) -> Optional[str]:
        """Start Android emulator"""
        avd = avd_name or self.AVD_NAME
        
        # Check if AVD exists
        avds = await self._list_avds()
        if avd not in avds:
            logger.error(f"AVD '{avd}' not found. Available: {avds}")
            logger.info("Run SETUP_ANDROID_EMULATOR.bat to create the AVD")
            return None
        
        logger.info(f"Starting emulator: {avd}")
        
        try:
            # Start emulator process
            cmd = [
                self._get_emulator_path(),
                "-avd", avd,
                "-no-snapshot-save",
                "-no-audio",
                "-gpu", "swiftshader_indirect"
            ]
            
            # Add headless mode if available
            # cmd.append("-no-window")  # Uncomment for headless
            
            self._emulator_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            # Wait for device to be ready
            logger.info("Waiting for emulator to boot...")
            device_id = await self._wait_for_device(timeout=120)
            
            if device_id:
                self._current_device_id = device_id
                self._is_running = True
                logger.info(f"Emulator ready: {device_id}")
                return device_id
            else:
                logger.error("Emulator failed to start")
                await self.stop_emulator()
                return None
                
        except Exception as e:
            logger.error(f"Failed to start emulator: {e}")
            return None
    
    async def _list_avds(self) -> List[str]:
        """List available AVDs"""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._get_emulator_path(), "-list-avds",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return [line.strip() for line in stdout.decode().split("\n") if line.strip()]
        except Exception:
            return []
    
    async def _wait_for_device(self, timeout: int = 120) -> Optional[str]:
        """Wait for device to be ready"""
        import time
        start = time.time()
        
        while time.time() - start < timeout:
            devices = await self.list_devices()
            
            for device in devices:
                if device.device_type == "emulator" and device.status == "device":
                    # Check if boot completed
                    out, _, rc = await self._run_adb(
                        "shell", "getprop", "sys.boot_completed",
                        device_id=device.device_id
                    )
                    if out.strip() == "1":
                        return device.device_id
            
            await asyncio.sleep(2)
        
        return None
    
    async def stop_emulator(self):
        """Stop the emulator"""
        if self._emulator_process:
            logger.info("Stopping emulator...")
            self._emulator_process.terminate()
            try:
                await asyncio.wait_for(self._emulator_process.wait(), timeout=10)
            except asyncio.TimeoutError:
                self._emulator_process.kill()
            self._emulator_process = None
        
        self._is_running = False
        self._current_device_id = None
    
    async def install_app(self, device_id: str, apk_path: str) -> bool:
        """Install APK on device"""
        logger.info(f"Installing app: {apk_path}")
        
        if not Path(apk_path).exists():
            logger.error(f"APK not found: {apk_path}")
            return False
        
        stdout, stderr, rc = await self._run_adb(
            "install", "-r", "-g", apk_path,
            device_id=device_id,
            timeout=120
        )
        
        if rc != 0 or "Failure" in stdout + stderr:
            logger.error(f"Failed to install app: {stderr or stdout}")
            return False
        
        logger.info("App installed successfully")
        return True
    
    async def uninstall_app(self, device_id: str, package: str) -> bool:
        """Uninstall app from device"""
        stdout, stderr, rc = await self._run_adb(
            "uninstall", package,
            device_id=device_id
        )
        return rc == 0
    
    async def launch_app(self, device_id: str, package: str, activity: str = "") -> bool:
        """Launch app on device"""
        logger.info(f"Launching app: {package}")
        
        if activity:
            # Launch specific activity
            cmd = ["shell", "am", "start", "-n", f"{package}/{activity}"]
        else:
            # Launch main activity
            cmd = ["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"]
        
        stdout, stderr, rc = await self._run_adb(*cmd, device_id=device_id)
        
        if rc != 0:
            logger.error(f"Failed to launch app: {stderr}")
            return False
        
        logger.info("App launched")
        return True
    
    async def stop_app(self, device_id: str, package: str) -> bool:
        """Force stop app"""
        _, _, rc = await self._run_adb(
            "shell", "am", "force-stop", package,
            device_id=device_id
        )
        return rc == 0
    
    async def set_proxy(self, device_id: str, host: str, port: int) -> bool:
        """Configure HTTP proxy on device"""
        logger.info(f"Setting proxy: {host}:{port}")
        
        # For emulator, host should be 10.0.2.2 (host machine)
        if device_id.startswith("emulator") and host == "127.0.0.1":
            host = "10.0.2.2"
        
        # Set global proxy
        _, _, rc = await self._run_adb(
            "shell", "settings", "put", "global",
            "http_proxy", f"{host}:{port}",
            device_id=device_id
        )
        
        if rc != 0:
            logger.warning("Failed to set global proxy, trying alternative method...")
            # Alternative for older Android versions
            await self._run_adb(
                "shell", "setprop", "net.gprs.http-proxy", f"{host}:{port}",
                device_id=device_id
            )
        
        logger.info("Proxy configured")
        return True
    
    async def clear_proxy(self, device_id: str) -> bool:
        """Clear HTTP proxy on device"""
        _, _, rc = await self._run_adb(
            "shell", "settings", "put", "global",
            "http_proxy", ":0",
            device_id=device_id
        )
        return rc == 0
    
    async def install_ca_certificate(self, device_id: str, cert_path: str) -> bool:
        """
        Install CA certificate on device for MITM.
        Requires root on Android 7+.
        """
        logger.info("Installing CA certificate...")
        
        if not Path(cert_path).exists():
            logger.error(f"Certificate not found: {cert_path}")
            return False
        
        # Push certificate to device
        remote_path = "/sdcard/Download/jarwis-ca.pem"
        _, _, rc = await self._run_adb(
            "push", cert_path, remote_path,
            device_id=device_id
        )
        
        if rc != 0:
            logger.error("Failed to push certificate")
            return False
        
        # Try to install as system cert (requires root)
        # For non-rooted devices, user must install manually
        logger.info(f"Certificate pushed to {remote_path}")
        logger.info("For non-rooted devices, install via Settings > Security > Install from storage")
        
        return True
    
    async def check_root(self, device_id: str) -> bool:
        """Check if device is rooted"""
        stdout, _, rc = await self._run_adb(
            "shell", "su", "-c", "id",
            device_id=device_id
        )
        return rc == 0 and "uid=0" in stdout
    
    async def take_screenshot(self, device_id: str, local_path: str) -> bool:
        """Take screenshot from device"""
        remote_path = "/sdcard/screenshot.png"
        
        # Capture screenshot
        _, _, rc = await self._run_adb(
            "shell", "screencap", "-p", remote_path,
            device_id=device_id
        )
        
        if rc != 0:
            return False
        
        # Pull to local
        _, _, rc = await self._run_adb(
            "pull", remote_path, local_path,
            device_id=device_id
        )
        
        # Clean up
        await self._run_adb("shell", "rm", remote_path, device_id=device_id)
        
        return rc == 0
    
    async def get_logcat(self, device_id: str, lines: int = 100) -> str:
        """Get device logs"""
        stdout, _, _ = await self._run_adb(
            "logcat", "-d", "-t", str(lines),
            device_id=device_id,
            timeout=10
        )
        return stdout
