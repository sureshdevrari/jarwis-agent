"""
Jarwis Android Emulator Manager
Handles emulator download, setup, and integration for mobile security testing
"""

import os
import sys
import json
import time
import shutil
import zipfile
import hashlib
import asyncio
import platform
import subprocess
import urllib.request
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn

console = Console()

# Android SDK URLs
SDK_URLS = {
    "windows": "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip",
    "linux": "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip",
    "darwin": "https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip"
}

# System images for different API levels
SYSTEM_IMAGES = {
    "android-30": "system-images;android-30;google_apis;x86_64",  # Android 11
    "android-31": "system-images;android-31;google_apis;x86_64",  # Android 12
    "android-33": "system-images;android-33;google_apis;x86_64",  # Android 13
    "android-34": "system-images;android-34;google_apis;x86_64",  # Android 14
}

# Frida server releases
FRIDA_RELEASES_URL = "https://api.github.com/repos/frida/frida/releases/latest"


@dataclass
class EmulatorConfig:
    """Configuration for Android emulator"""
    name: str = "jarwis_test_device"
    api_level: str = "android-33"
    device_type: str = "pixel_6"
    ram_mb: int = 4096
    heap_mb: int = 576
    disk_size: str = "8G"
    gpu_mode: str = "auto"  # auto, host, swiftshader_indirect, off
    proxy_host: str = "10.0.2.2"  # Host machine from emulator's perspective
    proxy_port: int = 8080
    headless: bool = False
    writable_system: bool = True  # Required for Frida


@dataclass
class EmulatorStatus:
    """Status of emulator"""
    running: bool = False
    device_id: str = ""
    api_level: str = ""
    frida_installed: bool = False
    proxy_configured: bool = False
    ca_installed: bool = False
    adb_root: bool = False
    emulator_pid: int = 0  # PID of emulator process for cleanup


class EmulatorManager:
    """Manages Android emulator for mobile security testing"""
    
    def __init__(self, jarwis_home: Optional[str] = None):
        self.jarwis_home = Path(jarwis_home or os.path.expanduser("~/.jarwis"))
        self.sdk_root = self.jarwis_home / "android-sdk"
        self.avd_home = self.jarwis_home / "avd"
        self.frida_dir = self.jarwis_home / "frida"
        self.certs_dir = self.jarwis_home / "certs"
        
        # Ensure directories exist
        for dir_path in [self.jarwis_home, self.sdk_root, self.avd_home, self.frida_dir, self.certs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # SDK tools paths
        self.cmdline_tools = self.sdk_root / "cmdline-tools" / "latest" / "bin"
        self.platform_tools = self.sdk_root / "platform-tools"
        self.emulator_path = self.sdk_root / "emulator"
        
        # Executables
        self.is_windows = platform.system() == "Windows"
        self.exe_ext = ".exe" if self.is_windows else ""
        self.bat_ext = ".bat" if self.is_windows else ""
        
        self.config = EmulatorConfig()
        self.status = EmulatorStatus()
        
    def _get_adb_path(self) -> str:
        """Get path to adb executable"""
        return str(self.platform_tools / f"adb{self.exe_ext}")
    
    def _get_emulator_path(self) -> str:
        """Get path to emulator executable"""
        return str(self.emulator_path / f"emulator{self.exe_ext}")
    
    def _get_sdkmanager_path(self) -> str:
        """Get path to sdkmanager"""
        return str(self.cmdline_tools / f"sdkmanager{self.bat_ext}")
    
    def _get_avdmanager_path(self) -> str:
        """Get path to avdmanager"""
        return str(self.cmdline_tools / f"avdmanager{self.bat_ext}")
    
    def _run_command(self, cmd: List[str], env: Optional[Dict] = None, 
                     capture_output: bool = True, timeout: int = 300) -> Tuple[int, str, str]:
        """Run a command and return result"""
        try:
            full_env = os.environ.copy()
            full_env["ANDROID_SDK_ROOT"] = str(self.sdk_root)
            full_env["ANDROID_AVD_HOME"] = str(self.avd_home)
            if env:
                full_env.update(env)
            
            if capture_output:
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    env=full_env,
                    timeout=timeout
                )
                return result.returncode, result.stdout, result.stderr
            else:
                result = subprocess.Popen(cmd, env=full_env)
                return 0, "", ""
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def is_sdk_installed(self) -> bool:
        """Check if Android SDK is installed"""
        return (
            self.cmdline_tools.exists() and
            (self.cmdline_tools / f"sdkmanager{self.bat_ext}").exists()
        )
    
    def is_emulator_installed(self) -> bool:
        """Check if emulator is installed"""
        return (
            self.emulator_path.exists() and
            (self.emulator_path / f"emulator{self.exe_ext}").exists()
        )
    
    def is_platform_tools_installed(self) -> bool:
        """Check if platform-tools (adb) is installed"""
        return (
            self.platform_tools.exists() and
            (self.platform_tools / f"adb{self.exe_ext}").exists()
        )
    
    async def download_sdk(self, progress_callback=None) -> bool:
        """Download Android SDK command-line tools"""
        console.print("[info] Downloading Android SDK command-line tools...", style="cyan")
        
        system = platform.system().lower()
        if system == "darwin":
            system = "darwin"
        elif system != "linux":
            system = "windows"
        
        url = SDK_URLS[system]
        zip_path = self.jarwis_home / "cmdline-tools.zip"
        
        try:
            # Download with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Downloading SDK...", total=None)
                
                def reporthook(count, block_size, total_size):
                    if total_size > 0:
                        progress.update(task, total=total_size, completed=count * block_size)
                
                urllib.request.urlretrieve(url, zip_path, reporthook)
            
            console.print("[success] [OK] Download complete", style="green")
            
            # Extract
            console.print("[info] Extracting SDK tools...", style="cyan")
            extract_dir = self.sdk_root / "cmdline-tools"
            extract_dir.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Rename to 'latest' as expected by sdkmanager
            extracted_folder = extract_dir / "cmdline-tools"
            latest_folder = extract_dir / "latest"
            
            if latest_folder.exists():
                shutil.rmtree(latest_folder)
            
            if extracted_folder.exists():
                shutil.move(str(extracted_folder), str(latest_folder))
            
            # Cleanup
            zip_path.unlink()
            
            console.print("[success] [OK] SDK tools extracted", style="green")
            return True
            
        except Exception as e:
            console.print(f"[error] [X] Failed to download SDK: {e}", style="red")
            return False
    
    async def install_sdk_components(self) -> bool:
        """Install required SDK components (emulator, platform-tools, system image)"""
        if not self.is_sdk_installed():
            console.print("[error] [X] SDK not installed. Run download_sdk() first.", style="red")
            return False
        
        sdkmanager = self._get_sdkmanager_path()
        
        # Accept licenses first
        console.print("[info] Accepting SDK licenses...", style="cyan")
        
        if self.is_windows:
            # On Windows, use echo y to accept
            cmd = f'echo y | "{sdkmanager}" --licenses'
            os.system(cmd)
        else:
            cmd = f'yes | "{sdkmanager}" --licenses'
            os.system(cmd)
        
        # Components to install
        components = [
            "platform-tools",
            "emulator",
            f"platforms;{self.config.api_level}",
            SYSTEM_IMAGES.get(self.config.api_level, SYSTEM_IMAGES["android-33"])
        ]
        
        for component in components:
            console.print(f"[info] Installing {component}...", style="cyan")
            
            code, stdout, stderr = self._run_command(
                [sdkmanager, "--install", component],
                timeout=600
            )
            
            if code != 0 and "already" not in stderr.lower():
                console.print(f"[warning] [!] Issue installing {component}: {stderr}", style="yellow")
            else:
                console.print(f"[success] [OK] {component} installed", style="green")
        
        return True
    
    async def create_avd(self, config: Optional[EmulatorConfig] = None) -> bool:
        """Create Android Virtual Device"""
        if config:
            self.config = config
        
        if not self.is_sdk_installed():
            console.print("[error] [X] SDK not installed", style="red")
            return False
        
        avdmanager = self._get_avdmanager_path()
        system_image = SYSTEM_IMAGES.get(self.config.api_level, SYSTEM_IMAGES["android-33"])
        
        console.print(f"[info] Creating AVD '{self.config.name}'...", style="cyan")
        
        # Check if AVD already exists
        code, stdout, stderr = self._run_command([avdmanager, "list", "avd"])
        if self.config.name in stdout:
            console.print(f"[info] AVD '{self.config.name}' already exists", style="yellow")
            return True
        
        # Create AVD
        cmd = [
            avdmanager, "create", "avd",
            "--name", self.config.name,
            "--package", system_image,
            "--device", self.config.device_type,
            "--force"
        ]
        
        # Auto-accept with echo
        if self.is_windows:
            full_cmd = f'echo no | "{avdmanager}" create avd --name {self.config.name} --package "{system_image}" --device "{self.config.device_type}" --force'
            result = os.system(full_cmd)
            code = result
        else:
            code, stdout, stderr = self._run_command(cmd)
        
        if code == 0:
            console.print(f"[success] [OK] AVD '{self.config.name}' created", style="green")
            
            # Configure AVD hardware
            await self._configure_avd_hardware()
            return True
        else:
            console.print(f"[error] [X] Failed to create AVD: {stderr}", style="red")
            return False
    
    async def _configure_avd_hardware(self):
        """Configure AVD hardware settings"""
        config_file = self.avd_home / f"{self.config.name}.avd" / "config.ini"
        
        if not config_file.exists():
            console.print("[warning] [!] AVD config not found, skipping hardware config", style="yellow")
            return
        
        # Read existing config
        with open(config_file, 'r') as f:
            lines = f.readlines()
        
        # Settings to update
        settings = {
            "hw.ramSize": str(self.config.ram_mb),
            "vm.heapSize": str(self.config.heap_mb),
            "disk.dataPartition.size": self.config.disk_size,
            "hw.gpu.enabled": "yes",
            "hw.gpu.mode": self.config.gpu_mode,
            "hw.keyboard": "yes",
            "hw.lcd.density": "440",
            "hw.lcd.width": "1080",
            "hw.lcd.height": "2340",
        }
        
        # Update settings
        updated_lines = []
        updated_keys = set()
        
        for line in lines:
            key = line.split('=')[0].strip() if '=' in line else None
            if key and key in settings:
                updated_lines.append(f"{key}={settings[key]}\n")
                updated_keys.add(key)
            else:
                updated_lines.append(line)
        
        # Add missing settings
        for key, value in settings.items():
            if key not in updated_keys:
                updated_lines.append(f"{key}={value}\n")
        
        # Write back
        with open(config_file, 'w') as f:
            f.writelines(updated_lines)
        
        console.print("[success] [OK] AVD hardware configured", style="green")
    
    async def start_emulator(self, headless: bool = False, wait: bool = True) -> bool:
        """Start the Android emulator"""
        if not self.is_emulator_installed():
            console.print("[error] [X] Emulator not installed", style="red")
            return False
        
        emulator = self._get_emulator_path()
        
        console.print(f"[info] Starting emulator '{self.config.name}'...", style="cyan")
        
        # Build command
        cmd = [
            emulator,
            "-avd", self.config.name,
            "-writable-system",  # Required for Frida
            "-gpu", self.config.gpu_mode,
            "-memory", str(self.config.ram_mb),
        ]
        
        if headless or self.config.headless:
            cmd.extend(["-no-window", "-no-audio"])
        
        # Set proxy
        cmd.extend([
            "-http-proxy", f"{self.config.proxy_host}:{self.config.proxy_port}"
        ])
        
        # Start emulator in background
        env = os.environ.copy()
        env["ANDROID_SDK_ROOT"] = str(self.sdk_root)
        env["ANDROID_AVD_HOME"] = str(self.avd_home)
        
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Save PID for cleanup
        self.status.emulator_pid = proc.pid
        console.print(f"[info] Emulator process started with PID: {proc.pid}", style="cyan")
        
        if wait:
            console.print("[info] Waiting for emulator to boot...", style="cyan")
            if await self._wait_for_boot(timeout=180):
                self.status.running = True
                self.status.device_id = await self._get_device_id()
                console.print(f"[success] [OK] Emulator running: {self.status.device_id}", style="green")
                return True
            else:
                console.print("[error] [X] Emulator boot timeout", style="red")
                return False
        
        return True
    
    async def _wait_for_boot(self, timeout: int = 180) -> bool:
        """Wait for emulator to fully boot"""
        adb = self._get_adb_path()
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check if device is online
            code, stdout, stderr = self._run_command([adb, "devices"])
            if "emulator-" in stdout and "device" in stdout:
                # Check if boot completed
                code, stdout, stderr = self._run_command([
                    adb, "shell", "getprop", "sys.boot_completed"
                ])
                if stdout.strip() == "1":
                    await asyncio.sleep(5)  # Extra wait for services
                    return True
            
            await asyncio.sleep(2)
        
        return False
    
    async def _get_device_id(self) -> str:
        """Get emulator device ID"""
        adb = self._get_adb_path()
        code, stdout, stderr = self._run_command([adb, "devices"])
        
        for line in stdout.split('\n'):
            if "emulator-" in line and "device" in line:
                return line.split()[0]
        
        return ""
    
    async def stop_emulator(self) -> bool:
        """Stop the running emulator"""
        adb = self._get_adb_path()
        
        console.print("[info] Stopping emulator...", style="cyan")
        
        # Method 1: Try graceful ADB shutdown
        try:
            code, stdout, stderr = self._run_command([adb, "emu", "kill"])
            await asyncio.sleep(3)
        except Exception as e:
            console.print(f"[warning] ADB emu kill failed: {e}", style="yellow")
        
        # Method 2: Kill by PID if we have one
        if self.status.emulator_pid:
            try:
                import platform as plat
                if plat.system() == "Windows":
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(self.status.emulator_pid)],
                        capture_output=True,
                        timeout=10
                    )
                else:
                    subprocess.run(
                        ["kill", "-9", str(self.status.emulator_pid)],
                        capture_output=True,
                        timeout=10
                    )
                console.print(f"[info] Killed emulator process PID: {self.status.emulator_pid}", style="cyan")
            except Exception as e:
                console.print(f"[warning] Failed to kill by PID: {e}", style="yellow")
        
        self.status.running = False
        self.status.device_id = ""
        self.status.emulator_pid = 0
        
        console.print("[success] [OK] Emulator stopped", style="green")
        return True
    
    async def install_frida_server(self) -> bool:
        """Download and install Frida server on emulator"""
        if not self.status.running:
            console.print("[error] [X] Emulator not running", style="red")
            return False
        
        adb = self._get_adb_path()
        
        console.print("[info] Installing Frida server...", style="cyan")
        
        try:
            # Get latest Frida release
            console.print("[info] Fetching latest Frida release...", style="cyan")
            
            req = urllib.request.Request(FRIDA_RELEASES_URL)
            req.add_header('User-Agent', 'Jarwis-Mobile-Scanner')
            
            with urllib.request.urlopen(req, timeout=30) as response:
                release_data = json.loads(response.read().decode())
            
            # Find x86_64 Android server
            frida_asset = None
            for asset in release_data.get('assets', []):
                if 'frida-server' in asset['name'] and 'android-x86_64' in asset['name']:
                    frida_asset = asset
                    break
            
            if not frida_asset:
                console.print("[error] [X] Frida server asset not found", style="red")
                return False
            
            # Download Frida server
            frida_url = frida_asset['browser_download_url']
            frida_xz_path = self.frida_dir / frida_asset['name']
            frida_path = self.frida_dir / "frida-server"
            
            if not frida_path.exists():
                console.print(f"[info] Downloading {frida_asset['name']}...", style="cyan")
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                ) as progress:
                    task = progress.add_task("[cyan]Downloading Frida...", total=frida_asset['size'])
                    
                    def reporthook(count, block_size, total_size):
                        progress.update(task, completed=count * block_size)
                    
                    urllib.request.urlretrieve(frida_url, frida_xz_path, reporthook)
                
                # Extract xz file
                console.print("[info] Extracting Frida server...", style="cyan")
                import lzma
                
                with lzma.open(frida_xz_path, 'rb') as xz_file:
                    with open(frida_path, 'wb') as out_file:
                        out_file.write(xz_file.read())
                
                frida_xz_path.unlink()
            
            # Root the emulator
            console.print("[info] Getting root access...", style="cyan")
            self._run_command([adb, "root"])
            await asyncio.sleep(2)
            self._run_command([adb, "remount"])
            await asyncio.sleep(2)
            
            # Push Frida server
            console.print("[info] Pushing Frida server to device...", style="cyan")
            code, stdout, stderr = self._run_command([
                adb, "push", str(frida_path), "/data/local/tmp/frida-server"
            ])
            
            # Make executable
            self._run_command([adb, "shell", "chmod", "755", "/data/local/tmp/frida-server"])
            
            self.status.frida_installed = True
            self.status.adb_root = True
            
            console.print("[success] [OK] Frida server installed", style="green")
            return True
            
        except Exception as e:
            console.print(f"[error] [X] Failed to install Frida: {e}", style="red")
            return False
    
    async def start_frida_server(self) -> bool:
        """Start Frida server on the emulator"""
        if not self.status.frida_installed:
            console.print("[error] [X] Frida not installed. Run install_frida_server() first.", style="red")
            return False
        
        adb = self._get_adb_path()
        
        console.print("[info] Starting Frida server...", style="cyan")
        
        # Kill any existing frida-server
        self._run_command([adb, "shell", "pkill", "-f", "frida-server"])
        await asyncio.sleep(1)
        
        # Start frida-server in background
        subprocess.Popen(
            [adb, "shell", "/data/local/tmp/frida-server", "&"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        await asyncio.sleep(3)
        
        # Verify running
        code, stdout, stderr = self._run_command([adb, "shell", "ps", "-A"])
        if "frida-server" in stdout:
            console.print("[success] [OK] Frida server running", style="green")
            return True
        else:
            console.print("[error] [X] Frida server failed to start", style="red")
            return False
    
    async def install_ca_certificate(self, ca_cert_path: Optional[str] = None) -> bool:
        """Install CA certificate for MITM proxy"""
        if not self.status.running:
            console.print("[error] [X] Emulator not running", style="red")
            return False
        
        adb = self._get_adb_path()
        
        # Find CA cert
        if ca_cert_path:
            cert_path = Path(ca_cert_path)
        else:
            # Try to find mitmproxy CA
            cert_path = self.certs_dir / "mitmproxy-ca-cert.pem"
            if not cert_path.exists():
                # Check default mitmproxy location
                default_mitm = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
                if default_mitm.exists():
                    cert_path = default_mitm
        
        if not cert_path.exists():
            console.print(f"[error] [X] CA certificate not found at {cert_path}", style="red")
            return False
        
        console.print("[info] Installing CA certificate...", style="cyan")
        
        try:
            # Calculate hash for Android's cert store
            import hashlib
            import subprocess
            
            # Get subject hash using openssl
            try:
                result = subprocess.run(
                    ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path)],
                    capture_output=True,
                    text=True
                )
                cert_hash = result.stdout.split('\n')[0]
            except:
                # Fallback: use simple hash
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                cert_hash = hashlib.md5(cert_data).hexdigest()[:8]
            
            cert_name = f"{cert_hash}.0"
            
            # Root access
            self._run_command([adb, "root"])
            await asyncio.sleep(2)
            self._run_command([adb, "remount"])
            await asyncio.sleep(2)
            
            # Push certificate
            self._run_command([
                adb, "push", str(cert_path), f"/data/local/tmp/{cert_name}"
            ])
            
            # Install to system certs
            self._run_command([
                adb, "shell", "mv", f"/data/local/tmp/{cert_name}", 
                f"/system/etc/security/cacerts/{cert_name}"
            ])
            
            # Set permissions
            self._run_command([
                adb, "shell", "chmod", "644", 
                f"/system/etc/security/cacerts/{cert_name}"
            ])
            
            self.status.ca_installed = True
            console.print("[success] [OK] CA certificate installed", style="green")
            return True
            
        except Exception as e:
            console.print(f"[error] [X] Failed to install CA: {e}", style="red")
            return False
    
    async def configure_proxy(self, host: str = "10.0.2.2", port: int = 8080) -> bool:
        """Configure proxy settings on emulator"""
        if not self.status.running:
            console.print("[error] [X] Emulator not running", style="red")
            return False
        
        adb = self._get_adb_path()
        
        console.print(f"[info] Configuring proxy {host}:{port}...", style="cyan")
        
        # Set global proxy
        self._run_command([
            adb, "shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"
        ])
        
        self.status.proxy_configured = True
        console.print("[success] [OK] Proxy configured", style="green")
        return True
    
    async def install_apk(self, apk_path: str) -> bool:
        """Install APK on emulator"""
        if not self.status.running:
            console.print("[error] [X] Emulator not running", style="red")
            return False
        
        if not os.path.exists(apk_path):
            console.print(f"[error] [X] APK not found: {apk_path}", style="red")
            return False
        
        adb = self._get_adb_path()
        
        console.print(f"[info] Installing APK: {os.path.basename(apk_path)}...", style="cyan")
        
        code, stdout, stderr = self._run_command([adb, "install", "-r", apk_path], timeout=120)
        
        if "Success" in stdout:
            console.print("[success] [OK] APK installed", style="green")
            return True
        else:
            console.print(f"[error] [X] Failed to install APK: {stderr}", style="red")
            return False
    
    async def launch_app(self, package_name: str, activity: Optional[str] = None) -> bool:
        """Launch an app on the emulator"""
        if not self.status.running:
            console.print("[error] [X] Emulator not running", style="red")
            return False
        
        adb = self._get_adb_path()
        
        console.print(f"[info] Launching {package_name}...", style="cyan")
        
        if activity:
            cmd = [adb, "shell", "am", "start", "-n", f"{package_name}/{activity}"]
        else:
            # Use monkey to start main activity
            cmd = [adb, "shell", "monkey", "-p", package_name, "-c", 
                   "android.intent.category.LAUNCHER", "1"]
        
        code, stdout, stderr = self._run_command(cmd)
        
        if code == 0:
            console.print("[success] [OK] App launched", style="green")
            return True
        else:
            console.print(f"[warning] [!] Launch issue: {stderr}", style="yellow")
            return True  # May still work
    
    async def get_installed_packages(self) -> List[str]:
        """Get list of installed packages"""
        if not self.status.running:
            return []
        
        adb = self._get_adb_path()
        code, stdout, stderr = self._run_command([adb, "shell", "pm", "list", "packages", "-3"])
        
        packages = []
        for line in stdout.split('\n'):
            if line.startswith('package:'):
                packages.append(line.replace('package:', '').strip())
        
        return packages
    
    async def full_setup(self, config: Optional[EmulatorConfig] = None) -> bool:
        """Complete emulator setup: download, install, create, start, configure"""
        if config:
            self.config = config
        
        console.print("\n[bold cyan][LAUNCH] Jarwis Android Emulator Setup[/bold cyan]\n")
        
        steps = [
            ("Download SDK", self.download_sdk, self.is_sdk_installed()),
            ("Install SDK Components", self.install_sdk_components, self.is_emulator_installed()),
            ("Create AVD", self.create_avd, False),
            ("Start Emulator", self.start_emulator, False),
            ("Install Frida Server", self.install_frida_server, False),
            ("Start Frida Server", self.start_frida_server, False),
            ("Install CA Certificate", self.install_ca_certificate, False),
            ("Configure Proxy", self.configure_proxy, False),
        ]
        
        for step_name, step_func, skip_if_done in steps:
            if skip_if_done:
                console.print(f"[skip] ⏭ {step_name} (already done)", style="dim")
                continue
            
            console.print(f"\n[step] 📍 {step_name}", style="bold blue")
            success = await step_func()
            
            if not success:
                console.print(f"\n[error] [X] Setup failed at: {step_name}", style="red")
                return False
        
        console.print("\n[success] [OK] Emulator setup complete!", style="bold green")
        console.print(f"[info] Device ID: {self.status.device_id}", style="cyan")
        console.print("[info] Ready for mobile security testing with Frida SSL bypass", style="cyan")
        
        return True
    
    def get_status(self) -> Dict:
        """Get current emulator status"""
        return {
            "sdk_installed": self.is_sdk_installed(),
            "emulator_installed": self.is_emulator_installed(),
            "platform_tools_installed": self.is_platform_tools_installed(),
            "running": self.status.running,
            "device_id": self.status.device_id,
            "frida_installed": self.status.frida_installed,
            "proxy_configured": self.status.proxy_configured,
            "ca_installed": self.status.ca_installed,
            "adb_root": self.status.adb_root,
            "config": {
                "name": self.config.name,
                "api_level": self.config.api_level,
                "ram_mb": self.config.ram_mb,
                "proxy_port": self.config.proxy_port
            }
        }


# Convenience functions
async def setup_emulator(headless: bool = False) -> EmulatorManager:
    """Quick setup: download and configure emulator"""
    manager = EmulatorManager()
    config = EmulatorConfig(headless=headless)
    await manager.full_setup(config)
    return manager


def create_emulator_manager() -> EmulatorManager:
    """Create emulator manager instance"""
    return EmulatorManager()


if __name__ == "__main__":
    # Test setup
    async def main():
        manager = EmulatorManager()
        await manager.full_setup()
    
    asyncio.run(main())
