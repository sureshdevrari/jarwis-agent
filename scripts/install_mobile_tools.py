"""
Jarwis AGI Pen Test - Mobile Tool Installer

Installs mobile reverse engineering tools for deep code analysis:

Android Tools:
- Jadx: Java/Kotlin decompiler for APK analysis
- APKTool: Resource extraction and smali decompilation

iOS Tools (macOS only):
- libimobiledevice: iOS device communication
- ios-deploy: App installation on real devices
- class-dump: Objective-C header extraction

Usage:
    python scripts/install_mobile_tools.py
    python scripts/install_mobile_tools.py --jadx-only
    python scripts/install_mobile_tools.py --apktool-only
    python scripts/install_mobile_tools.py --ios-only
"""

import os
import sys
import json
import shutil
import zipfile
import tarfile
import argparse
import platform
import tempfile
import urllib.request
from pathlib import Path

# Tool versions and download URLs
TOOLS = {
    "jadx": {
        "version": "1.5.0",
        "windows": "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
        "linux": "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
        "darwin": "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
        "executable": "jadx" if os.name != "nt" else "jadx.bat",
        "description": "Dex to Java decompiler",
        "platforms": ["windows", "linux", "darwin"]
    },
    "apktool": {
        "version": "2.9.3",
        "jar_url": "https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar",
        "wrapper_url": "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat" if os.name == "nt" else "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool",
        "executable": "apktool.bat" if os.name == "nt" else "apktool",
        "description": "APK resource extractor and smali decompiler",
        "platforms": ["windows", "linux", "darwin"]
    }
}

# iOS tools (macOS only, via Homebrew)
IOS_TOOLS = {
    "libimobiledevice": {
        "brew": "libimobiledevice",
        "description": "iOS device communication library",
        "executables": ["idevice_id", "ideviceinfo", "ideviceinstaller"]
    },
    "ios-deploy": {
        "brew": "ios-deploy",
        "description": "Install and debug iOS apps",
        "executables": ["ios-deploy"]
    },
    "class-dump": {
        "brew": "class-dump",
        "description": "Objective-C class header extraction",
        "executables": ["class-dump"]
    }
}

def get_tools_dir() -> Path:
    """Get the tools installation directory"""
    # Use ~/.jarwis/tools for tool installations
    tools_dir = Path.home() / ".jarwis" / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    return tools_dir

def download_file(url: str, dest: Path, desc: str = "") -> bool:
    """Download a file with progress indicator"""
    print(f"  Downloading: {desc or url.split('/')[-1]}...")
    
    try:
        # Custom progress handler
        def progress_hook(block_num, block_size, total_size):
            if total_size > 0:
                percent = min(100, int(block_num * block_size / total_size * 100))
                print(f"\r  Progress: {percent}%", end="", flush=True)
        
        urllib.request.urlretrieve(url, dest, reporthook=progress_hook)
        print()  # Newline after progress
        return True
        
    except Exception as e:
        print(f"\n  Error downloading: {e}")
        return False

def install_jadx(tools_dir: Path) -> bool:
    """Install Jadx decompiler"""
    print("\n[Jadx] Installing...")
    
    jadx_dir = tools_dir / "jadx"
    jadx_info = TOOLS["jadx"]
    
    # Check if already installed
    jadx_bin = jadx_dir / "bin" / jadx_info["executable"]
    if jadx_bin.exists():
        print(f"  Already installed at: {jadx_bin}")
        return True
    
    # Download
    system = platform.system().lower()
    if system == "windows":
        system = "windows"
    elif system == "darwin":
        system = "darwin"
    else:
        system = "linux"
    
    url = jadx_info[system]
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = Path(tmp_dir) / "jadx.zip"
        
        if not download_file(url, zip_path, f"Jadx v{jadx_info['version']}"):
            return False
        
        # Extract
        print("  Extracting...")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(jadx_dir)
    
    # Make executable
    if os.name != "nt":
        jadx_bin.chmod(0o755)
        (jadx_dir / "bin" / "jadx-gui").chmod(0o755)
    
    print(f"  Installed: {jadx_bin}")
    return True

def install_apktool(tools_dir: Path) -> bool:
    """Install APKTool"""
    print("\n[APKTool] Installing...")
    
    apktool_dir = tools_dir / "apktool"
    apktool_dir.mkdir(parents=True, exist_ok=True)
    
    apktool_info = TOOLS["apktool"]
    apktool_jar = apktool_dir / "apktool.jar"
    apktool_bin = apktool_dir / apktool_info["executable"]
    
    # Check if already installed
    if apktool_jar.exists() and apktool_bin.exists():
        print(f"  Already installed at: {apktool_bin}")
        return True
    
    # Download JAR
    if not download_file(apktool_info["jar_url"], apktool_jar, f"apktool.jar v{apktool_info['version']}"):
        return False
    
    # Download or create wrapper script
    if os.name == "nt":
        # Windows batch script
        wrapper_content = f'''@echo off
setlocal
set BASENAME=apktool
chcp 65001 2>nul >nul
java -jar -Duser.language=en -Dfile.encoding=UTF8 "{apktool_jar}" %*
'''
        apktool_bin.write_text(wrapper_content)
    else:
        # Unix shell script
        wrapper_content = f'''#!/bin/bash
java -jar -Duser.language=en -Dfile.encoding=UTF8 "{apktool_jar}" "$@"
'''
        apktool_bin.write_text(wrapper_content)
        apktool_bin.chmod(0o755)
    
    print(f"  Installed: {apktool_bin}")
    return True

def check_java() -> bool:
    """Check if Java is installed"""
    try:
        import subprocess
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        # Java prints version to stderr
        version_output = result.stderr or result.stdout
        print(f"  Java found: {version_output.split(chr(10))[0]}")
        return True
    except:
        return False

def check_homebrew() -> bool:
    """Check if Homebrew is installed (macOS)"""
    try:
        import subprocess
        result = subprocess.run(
            ["brew", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"  Homebrew found: {result.stdout.split(chr(10))[0]}")
            return True
        return False
    except:
        return False

def install_ios_tools() -> bool:
    """Install iOS tools via Homebrew (macOS only)"""
    if platform.system() != "Darwin":
        print("\n[iOS Tools] Skipping - macOS required")
        return True
    
    print("\n[iOS Tools] Installing via Homebrew...")
    
    if not check_homebrew():
        print("  ERROR: Homebrew not found. Install from: https://brew.sh")
        return False
    
    import subprocess
    success = True
    
    for tool_name, tool_info in IOS_TOOLS.items():
        print(f"\n  Installing {tool_name}...")
        
        # Check if already installed
        try:
            result = subprocess.run(
                ["which", tool_info["executables"][0]],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"    Already installed: {result.stdout.decode().strip()}")
                continue
        except:
            pass
        
        # Install via Homebrew
        try:
            result = subprocess.run(
                ["brew", "install", tool_info["brew"]],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                print(f"    Installed: {tool_info['description']}")
            else:
                print(f"    Failed: {result.stderr[:200]}")
                success = False
        except Exception as e:
            print(f"    Error: {e}")
            success = False
    
    return success

def update_path_config(tools_dir: Path, include_ios: bool = False):
    """Update config to include tool paths"""
    config_file = Path(__file__).parent.parent / "config" / "config.local.yaml"
    
    # Just print instructions for now
    print("\n" + "="*60)
    print("INSTALLATION COMPLETE")
    print("="*60)
    print("\nTools installed to:", tools_dir)
    print("\nTo use these tools, add to your PATH or update config/config.local.yaml:")
    print(f'''
mobile:
  tools:
    jadx_path: "{tools_dir / 'jadx' / 'bin' / TOOLS['jadx']['executable']}"
    apktool_path: "{tools_dir / 'apktool' / TOOLS['apktool']['executable']}"
''')
    
    if include_ios and platform.system() == "Darwin":
        print("\niOS tools installed via Homebrew (already in PATH):")
        for tool_name, tool_info in IOS_TOOLS.items():
            print(f"  - {tool_name}: {tool_info['description']}")

def main():
    parser = argparse.ArgumentParser(
        description="Install mobile reverse engineering tools for Jarwis"
    )
    parser.add_argument("--jadx-only", action="store_true", help="Install only Jadx")
    parser.add_argument("--apktool-only", action="store_true", help="Install only APKTool")
    parser.add_argument("--ios-only", action="store_true", help="Install only iOS tools (macOS)")
    parser.add_argument("--android-only", action="store_true", help="Install only Android tools")
    parser.add_argument("--tools-dir", type=str, help="Custom tools directory")
    
    args = parser.parse_args()
    
    print("="*60)
    print("Jarwis Mobile Tool Installer")
    print("="*60)
    
    # Check Java
    print("\n[Prerequisites]")
    if not args.ios_only:
        if not check_java():
            print("  WARNING: Java not found. APKTool and Jadx require Java 11+")
            print("  Install from: https://adoptium.net/")
    
    # Get tools directory
    if args.tools_dir:
        tools_dir = Path(args.tools_dir)
    else:
        tools_dir = get_tools_dir()
    
    print(f"\n[Tools Directory] {tools_dir}")
    
    success = True
    install_ios = False
    
    # Install Android tools
    if not args.ios_only:
        if not args.apktool_only:
            if not install_jadx(tools_dir):
                success = False
        
        if not args.jadx_only:
            if not install_apktool(tools_dir):
                success = False
    
    # Install iOS tools (macOS only)
    if not args.android_only and not args.jadx_only and not args.apktool_only:
        if platform.system() == "Darwin":
            install_ios = True
            if not install_ios_tools():
                success = False
    
    # Update config
    update_path_config(tools_dir, include_ios=install_ios)
    
    if success:
        print("\n✓ All tools installed successfully!")
        return 0
    else:
        print("\n✗ Some tools failed to install")
        return 1

if __name__ == "__main__":
    sys.exit(main())
