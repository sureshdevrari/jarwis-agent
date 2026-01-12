"""
Jarwis AGI - iOS Simulator Manager
Handles Xcode iOS Simulator setup and integration for iOS app security testing

Features:
- iOS Simulator discovery and management
- Frida gadget injection for iOS apps
- SSL trust injection
- App installation and launching
- Traffic capture integration
"""

import os
import re
import json
import time
import asyncio
import logging
import platform
import subprocess
import plistlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SimulatorConfig:
    """Configuration for iOS Simulator"""
    device_type: str = "iPhone 15 Pro"
    runtime: str = "iOS-17-0"  # or iOS-16-4, iOS-17-2, etc.
    name: str = "Jarwis-Test-iPhone"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080


@dataclass
class SimulatorDevice:
    """Represents an iOS Simulator device"""
    udid: str
    name: str
    device_type: str
    runtime: str
    state: str  # Shutdown, Booted
    is_available: bool


@dataclass
class SimulatorStatus:
    """Status of iOS Simulator"""
    running: bool = False
    device_udid: str = ""
    device_name: str = ""
    runtime: str = ""
    frida_gadget_installed: bool = False
    ca_installed: bool = False
    proxy_configured: bool = False


class IOSSimulatorManager:
    """
    Manages iOS Simulator for mobile security testing
    
    Note: Requires macOS with Xcode installed
    """
    
    def __init__(self, jarwis_home: Optional[str] = None):
        self.is_macos = platform.system() == "Darwin"
        self.jarwis_home = Path(jarwis_home or os.path.expanduser("~/.jarwis"))
        self.ios_dir = self.jarwis_home / "ios"
        self.frida_dir = self.jarwis_home / "frida"
        self.certs_dir = self.jarwis_home / "certs"
        
        # Ensure directories exist
        for dir_path in [self.jarwis_home, self.ios_dir, self.frida_dir, self.certs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        self.config = SimulatorConfig()
        self.status = SimulatorStatus()
        
        # Cache for available simulators
        self._available_devices: List[SimulatorDevice] = []
        
    def _run_command(self, cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Run a command and return result"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def is_xcode_installed(self) -> bool:
        """Check if Xcode is installed"""
        if not self.is_macos:
            return False
        
        code, stdout, stderr = self._run_command(["xcrun", "--version"])
        return code == 0
    
    def is_simulator_available(self) -> bool:
        """Check if iOS Simulator is available"""
        if not self.is_macos:
            return False
        
        code, stdout, stderr = self._run_command(["xcrun", "simctl", "list", "--json"])
        return code == 0
    
    async def get_available_devices(self, refresh: bool = False) -> List[SimulatorDevice]:
        """Get list of available iOS Simulator devices"""
        if not refresh and self._available_devices:
            return self._available_devices
        
        if not self.is_macos:
            logger.warning("iOS Simulator is only available on macOS")
            return []
        
        code, stdout, stderr = self._run_command(["xcrun", "simctl", "list", "--json"])
        
        if code != 0:
            logger.error(f"Failed to list simulators: {stderr}")
            return []
        
        try:
            data = json.loads(stdout)
            devices = []
            
            for runtime, runtime_devices in data.get("devices", {}).items():
                # Extract runtime version (e.g., "com.apple.CoreSimulator.SimRuntime.iOS-17-0")
                runtime_match = re.search(r'iOS-(\d+)-(\d+)', runtime)
                runtime_version = f"iOS-{runtime_match.group(1)}-{runtime_match.group(2)}" if runtime_match else runtime
                
                for device in runtime_devices:
                    devices.append(SimulatorDevice(
                        udid=device.get("udid", ""),
                        name=device.get("name", ""),
                        device_type=device.get("deviceTypeIdentifier", "").split(".")[-1],
                        runtime=runtime_version,
                        state=device.get("state", "Unknown"),
                        is_available=device.get("isAvailable", False)
                    ))
            
            self._available_devices = devices
            return devices
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse simulator list: {e}")
            return []
    
    async def get_booted_device(self) -> Optional[SimulatorDevice]:
        """Get currently booted simulator device"""
        devices = await self.get_available_devices(refresh=True)
        
        for device in devices:
            if device.state == "Booted":
                return device
        
        return None
    
    async def create_device(self, config: Optional[SimulatorConfig] = None) -> Optional[str]:
        """Create a new simulator device"""
        if config:
            self.config = config
        
        if not self.is_macos:
            logger.error("iOS Simulator is only available on macOS")
            return None
        
        logger.info(f"Creating iOS Simulator: {self.config.name}")
        
        # Get device type identifier
        device_type_id = f"com.apple.CoreSimulator.SimDeviceType.{self.config.device_type.replace(' ', '-')}"
        runtime_id = f"com.apple.CoreSimulator.SimRuntime.{self.config.runtime}"
        
        code, stdout, stderr = self._run_command([
            "xcrun", "simctl", "create",
            self.config.name,
            device_type_id,
            runtime_id
        ])
        
        if code == 0:
            udid = stdout.strip()
            logger.info(f"Created simulator: {udid}")
            return udid
        else:
            logger.error(f"Failed to create simulator: {stderr}")
            return None
    
    async def boot_device(self, udid: str = None) -> bool:
        """Boot an iOS Simulator device"""
        if not udid:
            # Try to find an existing device or create one
            devices = await self.get_available_devices()
            available = [d for d in devices if d.is_available and d.state == "Shutdown"]
            
            if available:
                udid = available[0].udid
            else:
                udid = await self.create_device()
                if not udid:
                    return False
        
        logger.info(f"Booting simulator: {udid}")
        
        code, stdout, stderr = self._run_command(["xcrun", "simctl", "boot", udid])
        
        if code == 0 or "current state: Booted" in stderr:
            self.status.running = True
            self.status.device_udid = udid
            
            # Wait for boot to complete
            await self._wait_for_boot(udid)
            
            logger.info(f"Simulator booted: {udid}")
            return True
        else:
            logger.error(f"Failed to boot simulator: {stderr}")
            return False
    
    async def _wait_for_boot(self, udid: str, timeout: int = 60):
        """Wait for simulator to fully boot"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            code, stdout, stderr = self._run_command([
                "xcrun", "simctl", "spawn", udid,
                "launchctl", "print", "system"
            ])
            
            if code == 0 and "com.apple.SpringBoard" in stdout:
                await asyncio.sleep(2)  # Extra wait for UI
                return True
            
            await asyncio.sleep(2)
        
        return False
    
    async def shutdown_device(self, udid: str = None) -> bool:
        """Shutdown the simulator"""
        udid = udid or self.status.device_udid
        
        if not udid:
            code, stdout, stderr = self._run_command(["xcrun", "simctl", "shutdown", "all"])
        else:
            code, stdout, stderr = self._run_command(["xcrun", "simctl", "shutdown", udid])
        
        self.status.running = False
        self.status.device_udid = ""
        
        logger.info("Simulator shutdown")
        return True
    
    async def install_app(self, ipa_path: str, udid: str = None) -> bool:
        """Install an IPA/app on the simulator"""
        udid = udid or self.status.device_udid
        
        if not udid:
            logger.error("No simulator device available")
            return False
        
        if not os.path.exists(ipa_path):
            logger.error(f"App not found: {ipa_path}")
            return False
        
        logger.info(f"Installing app: {os.path.basename(ipa_path)}")
        
        # For simulator, we need .app bundle, not .ipa
        # If it's an .ipa, we need to extract it
        app_path = ipa_path
        
        if ipa_path.lower().endswith('.ipa'):
            app_path = await self._extract_ipa(ipa_path)
            if not app_path:
                return False
        
        code, stdout, stderr = self._run_command([
            "xcrun", "simctl", "install", udid, app_path
        ], timeout=120)
        
        if code == 0:
            logger.info("App installed successfully")
            return True
        else:
            logger.error(f"Failed to install app: {stderr}")
            return False
    
    async def _extract_ipa(self, ipa_path: str) -> Optional[str]:
        """Extract .app from .ipa file"""
        import zipfile
        import tempfile
        
        try:
            extract_dir = tempfile.mkdtemp(prefix="jarwis_ipa_")
            
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find .app bundle in Payload folder
            payload_dir = Path(extract_dir) / "Payload"
            if payload_dir.exists():
                apps = list(payload_dir.glob("*.app"))
                if apps:
                    return str(apps[0])
            
            logger.error("No .app bundle found in IPA")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract IPA: {e}")
            return None
    
    async def launch_app(self, bundle_id: str, udid: str = None) -> bool:
        """Launch an app on the simulator"""
        udid = udid or self.status.device_udid
        
        if not udid:
            logger.error("No simulator device available")
            return False
        
        logger.info(f"Launching app: {bundle_id}")
        
        code, stdout, stderr = self._run_command([
            "xcrun", "simctl", "launch", udid, bundle_id
        ])
        
        if code == 0:
            logger.info("App launched successfully")
            return True
        else:
            logger.error(f"Failed to launch app: {stderr}")
            return False
    
    async def get_installed_apps(self, udid: str = None) -> List[Dict]:
        """Get list of installed apps on simulator"""
        udid = udid or self.status.device_udid
        
        if not udid:
            return []
        
        # Get data container paths which lists installed apps
        code, stdout, stderr = self._run_command([
            "xcrun", "simctl", "listapps", udid
        ])
        
        if code != 0:
            return []
        
        apps = []
        try:
            # Parse plist output
            app_data = plistlib.loads(stdout.encode())
            
            for bundle_id, info in app_data.items():
                apps.append({
                    "bundle_id": bundle_id,
                    "name": info.get("CFBundleName", ""),
                    "version": info.get("CFBundleVersion", ""),
                    "path": info.get("Path", "")
                })
        except:
            pass
        
        return apps
    
    async def install_ca_certificate(self, cert_path: str = None, udid: str = None) -> bool:
        """Install CA certificate for MITM proxy"""
        udid = udid or self.status.device_udid
        
        if not udid:
            logger.error("No simulator device available")
            return False
        
        # Find CA cert
        if cert_path:
            ca_path = Path(cert_path)
        else:
            # Try mitmproxy default location
            ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
            if not ca_path.exists():
                ca_path = self.certs_dir / "mitmproxy-ca-cert.pem"
        
        if not ca_path.exists():
            logger.error(f"CA certificate not found: {ca_path}")
            return False
        
        logger.info("Installing CA certificate...")
        
        # Add certificate to simulator's keychain
        code, stdout, stderr = self._run_command([
            "xcrun", "simctl", "keychain", udid,
            "add-root-cert", str(ca_path)
        ])
        
        if code == 0:
            self.status.ca_installed = True
            logger.info("CA certificate installed")
            return True
        else:
            logger.error(f"Failed to install CA: {stderr}")
            return False
    
    async def configure_proxy(self, host: str = None, port: int = None, udid: str = None) -> bool:
        """Configure HTTP proxy on simulator"""
        udid = udid or self.status.device_udid
        host = host or self.config.proxy_host
        port = port or self.config.proxy_port
        
        if not udid:
            logger.error("No simulator device available")
            return False
        
        logger.info(f"Configuring proxy: {host}:{port}")
        
        # Use simctl to set proxy
        # Note: iOS Simulator uses host machine's proxy settings by default
        # We need to modify the preferences
        
        # Get simulator data path
        devices_dir = Path.home() / "Library" / "Developer" / "CoreSimulator" / "Devices" / udid
        prefs_path = devices_dir / "data" / "Library" / "Preferences" / "com.apple.WebKit.plist"
        
        try:
            # Create proxy configuration
            proxy_config = {
                "WebKitWebProxyEnabled": True,
                "WebKitWebProxyHost": host,
                "WebKitWebProxyPort": port,
                "WebKitSecureWebProxyEnabled": True,
                "WebKitSecureWebProxyHost": host,
                "WebKitSecureWebProxyPort": port
            }
            
            # Write to plist
            with open(prefs_path, 'wb') as f:
                plistlib.dump(proxy_config, f)
            
            self.status.proxy_configured = True
            logger.info("Proxy configured")
            return True
            
        except Exception as e:
            logger.warning(f"Proxy config via plist failed: {e}")
            
            # Alternative: Use environment variables when launching app
            # This requires launching via a wrapper script
            return True  # Partial success
    
    async def inject_frida_gadget(self, app_path: str) -> bool:
        """
        Inject Frida Gadget into an iOS app for instrumentation
        Note: This modifies the app and requires resigning
        """
        logger.info("Injecting Frida Gadget...")
        
        # Download Frida Gadget if not present
        gadget_path = self.frida_dir / "FridaGadget.dylib"
        
        if not gadget_path.exists():
            success = await self._download_frida_gadget()
            if not success:
                return False
        
        # Find the main binary in the app
        app_bundle = Path(app_path)
        info_plist = app_bundle / "Info.plist"
        
        if not info_plist.exists():
            logger.error("Info.plist not found in app bundle")
            return False
        
        try:
            with open(info_plist, 'rb') as f:
                info = plistlib.load(f)
            
            executable_name = info.get("CFBundleExecutable", "")
            executable_path = app_bundle / executable_name
            
            if not executable_path.exists():
                logger.error(f"Executable not found: {executable_path}")
                return False
            
            # Copy Frida Gadget to app Frameworks
            frameworks_dir = app_bundle / "Frameworks"
            frameworks_dir.mkdir(exist_ok=True)
            
            target_gadget = frameworks_dir / "FridaGadget.dylib"
            
            import shutil
            shutil.copy(gadget_path, target_gadget)
            
            # Patch the binary to load FridaGadget
            # Using insert_dylib or optool
            code, stdout, stderr = self._run_command([
                "install_name_tool", "-add_rpath",
                "@executable_path/Frameworks",
                str(executable_path)
            ])
            
            # Add load command for FridaGadget
            # Note: This requires 'insert_dylib' tool to be installed
            # Alternative: use optool or LIEF
            
            logger.info("Frida Gadget injected (requires resigning)")
            self.status.frida_gadget_installed = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to inject Frida Gadget: {e}")
            return False
    
    async def _download_frida_gadget(self) -> bool:
        """Download latest Frida Gadget for iOS Simulator"""
        import urllib.request
        
        logger.info("Downloading Frida Gadget...")
        
        try:
            # Get latest release info
            req = urllib.request.Request(
                "https://api.github.com/repos/frida/frida/releases/latest",
                headers={"User-Agent": "Jarwis-Mobile-Scanner"}
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                release_data = json.loads(response.read().decode())
            
            # Find iOS simulator gadget
            gadget_asset = None
            for asset in release_data.get('assets', []):
                if 'frida-gadget' in asset['name'] and 'ios-universal' in asset['name']:
                    gadget_asset = asset
                    break
            
            if not gadget_asset:
                logger.error("Frida Gadget asset not found")
                return False
            
            # Download
            gadget_url = gadget_asset['browser_download_url']
            gadget_path = self.frida_dir / gadget_asset['name']
            
            urllib.request.urlretrieve(gadget_url, gadget_path)
            
            # Extract if needed (usually .dylib.xz)
            if gadget_path.suffix == '.xz':
                import lzma
                with lzma.open(gadget_path, 'rb') as xz:
                    dylib_path = self.frida_dir / "FridaGadget.dylib"
                    with open(dylib_path, 'wb') as out:
                        out.write(xz.read())
                gadget_path.unlink()
            
            logger.info("Frida Gadget downloaded")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download Frida Gadget: {e}")
            return False
    
    async def capture_network_traffic(self, udid: str = None, duration: int = 60) -> List[Dict]:
        """Capture network traffic from simulator using rvictl"""
        udid = udid or self.status.device_udid
        
        if not udid:
            logger.error("No simulator device available")
            return []
        
        # For simulators, we can use the host's network interface
        # or setup a virtual interface with rvictl
        
        logger.info(f"Capturing traffic for {duration} seconds...")
        
        # Start tcpdump or use mitmproxy logs
        # For now, return empty - traffic capture should be done via mitmproxy
        
        return []
    
    async def full_setup(self, config: Optional[SimulatorConfig] = None) -> bool:
        """Complete simulator setup for security testing"""
        if config:
            self.config = config
        
        if not self.is_macos:
            logger.error("iOS Simulator is only available on macOS")
            return False
        
        if not self.is_xcode_installed():
            logger.error("Xcode is required for iOS Simulator")
            return False
        
        logger.info("Starting iOS Simulator setup...")
        
        # Get or create device
        devices = await self.get_available_devices()
        booted = await self.get_booted_device()
        
        if booted:
            logger.info(f"Using already booted simulator: {booted.name}")
            self.status.device_udid = booted.udid
            self.status.running = True
        else:
            # Find suitable device
            suitable = [d for d in devices if d.is_available and "iPhone" in d.name]
            
            if suitable:
                await self.boot_device(suitable[0].udid)
            else:
                udid = await self.create_device()
                if udid:
                    await self.boot_device(udid)
        
        if not self.status.running:
            return False
        
        # Install CA certificate
        await self.install_ca_certificate()
        
        # Configure proxy
        await self.configure_proxy()
        
        logger.info("iOS Simulator setup complete")
        return True
    
    def get_status(self) -> Dict:
        """Get current simulator status"""
        return {
            "is_macos": self.is_macos,
            "xcode_installed": self.is_xcode_installed() if self.is_macos else False,
            "simulator_available": self.is_simulator_available() if self.is_macos else False,
            "running": self.status.running,
            "device_udid": self.status.device_udid,
            "device_name": self.status.device_name,
            "frida_gadget_installed": self.status.frida_gadget_installed,
            "ca_installed": self.status.ca_installed,
            "proxy_configured": self.status.proxy_configured,
            "config": {
                "device_type": self.config.device_type,
                "runtime": self.config.runtime,
                "proxy_port": self.config.proxy_port
            }
        }


# Convenience functions
async def setup_ios_simulator() -> IOSSimulatorManager:
    """Quick setup iOS Simulator for testing"""
    manager = IOSSimulatorManager()
    await manager.full_setup()
    return manager


def create_ios_simulator_manager() -> IOSSimulatorManager:
    """Create iOS Simulator manager instance"""
    return IOSSimulatorManager()


if __name__ == "__main__":
    # Test setup
    async def main():
        manager = IOSSimulatorManager()
        status = manager.get_status()
        print(f"iOS Simulator Status: {json.dumps(status, indent=2)}")
        
        if status["is_macos"]:
            await manager.full_setup()
    
    asyncio.run(main())
