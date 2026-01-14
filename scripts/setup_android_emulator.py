"""
Android Emulator Setup for Jarwis Mobile Testing (Windows)

This script automates the complete setup of:
1. Android SDK Command-line Tools
2. Android Emulator with system image
3. Frida for SSL pinning bypass
4. Environment variables

Run with admin privileges for best results.
"""

import os
import sys
import subprocess
import shutil
import zipfile
import urllib.request
import tempfile
import time
from pathlib import Path

# Configuration
ANDROID_SDK_ROOT = Path("C:/Android/Sdk")
CMDLINE_TOOLS_URL = "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
FRIDA_VERSION = "16.1.4"
AVD_NAME = "jarwis_test_device"
SYSTEM_IMAGE = "system-images;android-33;google_apis;x86_64"
PLATFORM_VERSION = "33"


def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


def print_step(step, text):
    print(f"[{step}] {text}")


def print_ok(text):
    print(f"  ✓ {text}")


def print_error(text):
    print(f"  ✗ {text}")


def print_info(text):
    print(f"  → {text}")


def run_cmd(cmd, check=True, capture=True):
    """Run a command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=capture,
            text=True,
            check=check
        )
        return result.stdout if capture else ""
    except subprocess.CalledProcessError as e:
        if capture:
            print_error(f"Command failed: {e.stderr}")
        raise


def check_prerequisites():
    """Check system prerequisites"""
    print_header("Checking Prerequisites")
    
    issues = []
    
    # Check Java
    java = shutil.which("java")
    if java:
        print_ok(f"Java found: {java}")
        # Check version
        result = run_cmd("java -version 2>&1")
        print_info(result.split('\n')[0] if result else "Version unknown")
    else:
        print_error("Java not found - required for Android SDK")
        issues.append("Install Java JDK 17+ from https://adoptium.net/")
    
    # Check available disk space
    import ctypes
    free_bytes = ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p("C:\\"), None, None, ctypes.pointer(free_bytes)
    )
    free_gb = free_bytes.value / (1024**3)
    if free_gb >= 15:
        print_ok(f"Disk space: {free_gb:.1f} GB available")
    else:
        print_error(f"Low disk space: {free_gb:.1f} GB (need 15+ GB)")
        issues.append("Free up disk space (need 15+ GB for emulator)")
    
    # Check if virtualization is enabled (for emulator)
    print_info("Checking virtualization support...")
    try:
        result = run_cmd('systeminfo | findstr /i "Hyper-V"', check=False)
        if "Hyper-V" in result:
            print_ok("Hyper-V detected")
        else:
            # Check HAXM alternative
            print_info("Hyper-V not detected. Will use software emulation (slower)")
    except:
        print_info("Could not verify virtualization status")
    
    # Check ADB
    adb = shutil.which("adb")
    if adb:
        print_ok(f"ADB already installed: {adb}")
    else:
        print_info("ADB will be installed with SDK")
    
    return issues


def download_file(url, dest_path, desc="file"):
    """Download a file with progress"""
    print_info(f"Downloading {desc}...")
    
    def progress_hook(count, block_size, total_size):
        percent = int(count * block_size * 100 / total_size)
        sys.stdout.write(f"\r  → Progress: {percent}%")
        sys.stdout.flush()
    
    urllib.request.urlretrieve(url, dest_path, progress_hook)
    print()  # newline after progress


def setup_android_sdk():
    """Download and setup Android SDK command-line tools"""
    print_header("Setting up Android SDK")
    
    # Create SDK directory
    ANDROID_SDK_ROOT.mkdir(parents=True, exist_ok=True)
    cmdline_tools_dir = ANDROID_SDK_ROOT / "cmdline-tools"
    
    # Check if already installed
    sdkmanager = ANDROID_SDK_ROOT / "cmdline-tools" / "latest" / "bin" / "sdkmanager.bat"
    if sdkmanager.exists():
        print_ok("Android SDK command-line tools already installed")
        return True
    
    print_step("1", "Downloading Android SDK command-line tools...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / "cmdline-tools.zip"
        
        try:
            download_file(CMDLINE_TOOLS_URL, zip_path, "SDK tools")
        except Exception as e:
            print_error(f"Download failed: {e}")
            print_info("Manual download: https://developer.android.com/studio#command-tools")
            return False
        
        print_step("2", "Extracting SDK tools...")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(tmpdir)
        
        # Move to correct location (cmdline-tools/latest)
        src = Path(tmpdir) / "cmdline-tools"
        dest = cmdline_tools_dir / "latest"
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(src), str(dest))
    
    print_ok("SDK command-line tools installed")
    return True


def accept_licenses():
    """Accept Android SDK licenses"""
    print_step("3", "Accepting SDK licenses...")
    
    sdkmanager = ANDROID_SDK_ROOT / "cmdline-tools" / "latest" / "bin" / "sdkmanager.bat"
    
    # Auto-accept licenses
    try:
        process = subprocess.Popen(
            f'echo y | "{sdkmanager}" --licenses',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        # Send 'y' multiple times for all licenses
        for _ in range(10):
            try:
                process.stdin.write(b'y\n')
                process.stdin.flush()
            except:
                break
        process.wait(timeout=60)
        print_ok("Licenses accepted")
        return True
    except Exception as e:
        print_error(f"License acceptance failed: {e}")
        return False


def install_sdk_packages():
    """Install required SDK packages"""
    print_header("Installing SDK Packages")
    
    sdkmanager = ANDROID_SDK_ROOT / "cmdline-tools" / "latest" / "bin" / "sdkmanager.bat"
    
    packages = [
        ("platform-tools", "ADB and Fastboot"),
        ("emulator", "Android Emulator"),
        (f"platforms;android-{PLATFORM_VERSION}", f"Android {PLATFORM_VERSION} Platform"),
        (SYSTEM_IMAGE, "System Image (x86_64 with Google APIs)"),
    ]
    
    for i, (package, desc) in enumerate(packages, 1):
        print_step(str(i), f"Installing {desc}...")
        try:
            # Use echo y to auto-accept
            cmd = f'echo y | "{sdkmanager}" "{package}"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout for large downloads
            )
            if result.returncode == 0:
                print_ok(f"{desc} installed")
            else:
                print_error(f"Failed: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            print_error(f"Timeout installing {desc}")
        except Exception as e:
            print_error(f"Error: {e}")
    
    return True


def create_avd():
    """Create Android Virtual Device"""
    print_header("Creating Android Virtual Device")
    
    avdmanager = ANDROID_SDK_ROOT / "cmdline-tools" / "latest" / "bin" / "avdmanager.bat"
    
    # Check if AVD already exists
    result = run_cmd(f'"{avdmanager}" list avd', check=False)
    if AVD_NAME in result:
        print_ok(f"AVD '{AVD_NAME}' already exists")
        return True
    
    print_step("1", f"Creating AVD '{AVD_NAME}'...")
    
    try:
        # Create AVD with default settings
        cmd = f'echo no | "{avdmanager}" create avd -n {AVD_NAME} -k "{SYSTEM_IMAGE}" -d pixel_6'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0 or "already exists" in result.stderr:
            print_ok(f"AVD '{AVD_NAME}' created")
            
            # Configure AVD for better performance
            avd_ini = Path.home() / ".android" / "avd" / f"{AVD_NAME}.avd" / "config.ini"
            if avd_ini.exists():
                print_step("2", "Optimizing AVD settings...")
                with open(avd_ini, 'a') as f:
                    f.write("\nhw.ramSize=4096\n")
                    f.write("hw.gpu.enabled=yes\n")
                    f.write("hw.gpu.mode=auto\n")
                    f.write("disk.dataPartition.size=8G\n")
                print_ok("AVD optimized")
            
            return True
        else:
            print_error(f"Failed to create AVD: {result.stderr[:200]}")
            return False
    except Exception as e:
        print_error(f"Error creating AVD: {e}")
        return False


def install_frida():
    """Install Frida tools"""
    print_header("Installing Frida")
    
    print_step("1", "Installing Frida Python package...")
    try:
        run_cmd(f'"{sys.executable}" -m pip install frida-tools frida --upgrade')
        print_ok("Frida Python tools installed")
    except Exception as e:
        print_error(f"Failed to install Frida: {e}")
        return False
    
    print_step("2", "Downloading Frida server for Android...")
    
    # Determine architecture (x86_64 for emulator)
    frida_arch = "x86_64"
    frida_url = f"https://github.com/frida/frida/releases/download/{FRIDA_VERSION}/frida-server-{FRIDA_VERSION}-android-{frida_arch}.xz"
    
    frida_dir = ANDROID_SDK_ROOT / "frida"
    frida_dir.mkdir(parents=True, exist_ok=True)
    frida_server = frida_dir / f"frida-server-{frida_arch}"
    
    if frida_server.exists():
        print_ok(f"Frida server already downloaded: {frida_server}")
        return True
    
    try:
        import lzma
        
        with tempfile.TemporaryDirectory() as tmpdir:
            xz_path = Path(tmpdir) / "frida-server.xz"
            download_file(frida_url, xz_path, "Frida server")
            
            print_info("Extracting Frida server...")
            with lzma.open(xz_path, 'rb') as f_in:
                with open(frida_server, 'wb') as f_out:
                    f_out.write(f_in.read())
        
        print_ok(f"Frida server ready: {frida_server}")
        return True
    except Exception as e:
        print_error(f"Failed to download Frida server: {e}")
        print_info(f"Manual download: {frida_url}")
        return False


def setup_environment_variables():
    """Set up environment variables"""
    print_header("Setting Environment Variables")
    
    env_vars = {
        "ANDROID_HOME": str(ANDROID_SDK_ROOT),
        "ANDROID_SDK_ROOT": str(ANDROID_SDK_ROOT),
    }
    
    paths_to_add = [
        str(ANDROID_SDK_ROOT / "platform-tools"),
        str(ANDROID_SDK_ROOT / "emulator"),
        str(ANDROID_SDK_ROOT / "cmdline-tools" / "latest" / "bin"),
    ]
    
    print_step("1", "Setting ANDROID_HOME and ANDROID_SDK_ROOT...")
    
    for var, value in env_vars.items():
        try:
            run_cmd(f'setx {var} "{value}"', check=False)
            os.environ[var] = value
            print_ok(f"{var} = {value}")
        except Exception as e:
            print_error(f"Failed to set {var}: {e}")
    
    print_step("2", "Adding SDK tools to PATH...")
    
    current_path = os.environ.get("PATH", "")
    new_paths = [p for p in paths_to_add if p not in current_path]
    
    if new_paths:
        # Add to user PATH
        for p in new_paths:
            print_info(f"Adding: {p}")
        
        # Note: This requires admin or user to restart terminal
        path_addition = ";".join(new_paths)
        print_info("Run this command in an admin PowerShell to add to PATH permanently:")
        print(f'\n  $env:Path += ";{path_addition}"\n')
    else:
        print_ok("SDK paths already in PATH")
    
    return True


def verify_installation():
    """Verify the installation"""
    print_header("Verifying Installation")
    
    checks = []
    
    # Check ADB
    adb = ANDROID_SDK_ROOT / "platform-tools" / "adb.exe"
    if adb.exists():
        print_ok(f"ADB: {adb}")
        checks.append(True)
    else:
        print_error("ADB not found")
        checks.append(False)
    
    # Check emulator
    emulator = ANDROID_SDK_ROOT / "emulator" / "emulator.exe"
    if emulator.exists():
        print_ok(f"Emulator: {emulator}")
        checks.append(True)
    else:
        print_error("Emulator not found")
        checks.append(False)
    
    # Check AVD
    avd_dir = Path.home() / ".android" / "avd" / f"{AVD_NAME}.avd"
    if avd_dir.exists():
        print_ok(f"AVD: {AVD_NAME}")
        checks.append(True)
    else:
        print_error(f"AVD '{AVD_NAME}' not found")
        checks.append(False)
    
    # Check Frida
    frida = shutil.which("frida")
    if frida:
        print_ok(f"Frida CLI: {frida}")
        checks.append(True)
    else:
        # Check in venv
        try:
            result = run_cmd(f'"{sys.executable}" -c "import frida; print(frida.__version__)"', check=False)
            if result.strip():
                print_ok(f"Frida Python: v{result.strip()}")
                checks.append(True)
            else:
                print_error("Frida not installed")
                checks.append(False)
        except:
            print_error("Frida not installed")
            checks.append(False)
    
    return all(checks)


def create_start_script():
    """Create a convenience script to start the emulator"""
    print_header("Creating Start Scripts")
    
    scripts_dir = Path(__file__).parent
    
    # PowerShell script
    ps_script = scripts_dir / "start_emulator.ps1"
    ps_content = f'''# Start Jarwis Android Emulator
$env:ANDROID_HOME = "{ANDROID_SDK_ROOT}"
$env:ANDROID_SDK_ROOT = "{ANDROID_SDK_ROOT}"

Write-Host "Starting Android Emulator ({AVD_NAME})..." -ForegroundColor Green

# Start emulator
$emulator = "{ANDROID_SDK_ROOT}\\emulator\\emulator.exe"
Start-Process -FilePath $emulator -ArgumentList "-avd", "{AVD_NAME}", "-gpu", "auto", "-no-snapshot-load" -NoNewWindow

Write-Host "Waiting for emulator to boot..." -ForegroundColor Yellow

# Wait for device
$adb = "{ANDROID_SDK_ROOT}\\platform-tools\\adb.exe"
& $adb wait-for-device

# Wait for boot complete
do {{
    Start-Sleep -Seconds 2
    $bootComplete = & $adb shell getprop sys.boot_completed 2>$null
}} while ($bootComplete -ne "1")

Write-Host "Emulator ready!" -ForegroundColor Green

# Push Frida server
$fridaServer = "{ANDROID_SDK_ROOT}\\frida\\frida-server-x86_64"
if (Test-Path $fridaServer) {{
    Write-Host "Installing Frida server..." -ForegroundColor Yellow
    & $adb push $fridaServer /data/local/tmp/frida-server
    & $adb shell "chmod 755 /data/local/tmp/frida-server"
    
    # Start Frida in background
    Start-Process -FilePath $adb -ArgumentList "shell", "/data/local/tmp/frida-server", "-D" -NoNewWindow
    Write-Host "Frida server started!" -ForegroundColor Green
}}

Write-Host "`nEmulator is ready for mobile testing!" -ForegroundColor Cyan
Write-Host "You can now start a mobile scan in Jarwis with FULL mode." -ForegroundColor Cyan
'''
    
    with open(ps_script, 'w') as f:
        f.write(ps_content)
    print_ok(f"Created: {ps_script}")
    
    # Batch script
    bat_script = scripts_dir.parent / "START_EMULATOR.bat"
    bat_content = f'''@echo off
echo Starting Jarwis Android Emulator...
powershell -ExecutionPolicy Bypass -File "{ps_script}"
pause
'''
    
    with open(bat_script, 'w') as f:
        f.write(bat_content)
    print_ok(f"Created: {bat_script}")
    
    return True


def main():
    print("\n" + "="*60)
    print("   JARWIS ANDROID EMULATOR SETUP")
    print("   Mobile Dynamic Testing Environment for Windows")
    print("="*60)
    
    # Check prerequisites
    issues = check_prerequisites()
    if issues:
        print("\n⚠️  Prerequisites not met:")
        for issue in issues:
            print(f"   • {issue}")
        
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Setup cancelled.")
            return False
    
    # Setup Android SDK
    if not setup_android_sdk():
        print_error("SDK setup failed. Please install manually.")
        return False
    
    # Accept licenses
    accept_licenses()
    
    # Install packages
    install_sdk_packages()
    
    # Create AVD
    create_avd()
    
    # Install Frida
    install_frida()
    
    # Setup environment
    setup_environment_variables()
    
    # Create convenience scripts
    create_start_script()
    
    # Verify
    success = verify_installation()
    
    # Summary
    print_header("Setup Complete!")
    
    if success:
        print("✓ Android Emulator environment is ready!")
        print("\nNext steps:")
        print("  1. Run START_EMULATOR.bat to launch the emulator")
        print("  2. Wait for the emulator to fully boot")
        print("  3. Start a mobile scan in Jarwis with 'FULL' mode")
        print("  4. Enter your Instagram credentials when prompted")
        print("  5. The OTP will be requested via the Jarwis UI")
    else:
        print("⚠️  Some components may need manual installation.")
        print("Check the errors above and try again.")
    
    return success


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
