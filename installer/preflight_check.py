#!/usr/bin/env python3
"""
Jarwis Agent Installer - Pre-flight Validation Script

Cross-platform script to verify all required files and dependencies exist
before building the installer. Run this before any build to catch issues early.

Usage:
    python preflight_check.py [--platform windows|macos|linux|all] [--fix]

Exit codes:
    0 - All checks passed
    1 - Critical errors (build will fail)
    2 - Warnings only (build may succeed but have issues)
"""

import os
import sys
import platform
import shutil
import argparse
from pathlib import Path
from typing import List, Tuple, Optional

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Disable colors on Windows if not supported
if platform.system() == 'Windows':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = Colors.RESET = Colors.BOLD = ''

def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.resolve()

def print_header(title: str):
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}  {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

def print_check(name: str, passed: bool, message: str = ""):
    """Print a check result."""
    if passed:
        status = f"{Colors.GREEN}✓ PASS{Colors.RESET}"
    else:
        status = f"{Colors.RED}✗ FAIL{Colors.RESET}"
    
    print(f"  [{status}] {name}")
    if message:
        print(f"          {Colors.YELLOW}{message}{Colors.RESET}")

def print_warning(message: str):
    """Print a warning message."""
    print(f"  [{Colors.YELLOW}! WARN{Colors.RESET}] {message}")

def check_file_exists(path: Path, description: str) -> Tuple[bool, str]:
    """Check if a required file exists."""
    if path.exists():
        return True, ""
    return False, f"Missing: {path}"

def check_directory_exists(path: Path, description: str) -> Tuple[bool, str]:
    """Check if a required directory exists."""
    if path.is_dir():
        return True, ""
    return False, f"Missing directory: {path}"

def check_command_exists(command: str) -> bool:
    """Check if a command is available in PATH."""
    return shutil.which(command) is not None

class PreflightChecker:
    """Pre-flight validation checker."""
    
    def __init__(self, project_root: Path, target_platform: str = "all", auto_fix: bool = False):
        self.root = project_root
        self.platform = target_platform
        self.auto_fix = auto_fix
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def run_all_checks(self) -> int:
        """Run all pre-flight checks. Returns exit code."""
        print_header("Jarwis Agent Installer - Pre-flight Check")
        print(f"Project Root: {self.root}")
        print(f"Target Platform: {self.platform}")
        print(f"Current Platform: {platform.system()}")
        
        # Core checks (all platforms)
        self.check_core_files()
        self.check_python_dependencies()
        
        # Platform-specific checks
        if self.platform in ("windows", "all"):
            self.check_windows_requirements()
        
        if self.platform in ("macos", "all"):
            self.check_macos_requirements()
        
        if self.platform in ("linux", "all"):
            self.check_linux_requirements()
        
        # Runtime dependencies check
        self.check_runtime_dependencies()
        
        # Print summary
        return self.print_summary()
    
    def check_core_files(self):
        """Check core files required for all platforms."""
        print_header("Core Files")
        
        core_files = [
            (self.root / "jarwis_agent.py", "Main agent entry point"),
            (self.root / "config" / "config.yaml", "Configuration template"),
            (self.root / "installer" / "jarwis-agent.spec", "PyInstaller spec file"),
            (self.root / "installer" / "LICENSE.rtf", "License file for installers"),
        ]
        
        for path, desc in core_files:
            passed, msg = check_file_exists(path, desc)
            print_check(desc, passed, msg)
            if not passed:
                self.errors.append(f"Missing core file: {path}")
        
        # Check core directories
        core_dirs = [
            (self.root / "core", "Core module"),
            (self.root / "attacks", "Attack modules"),
            (self.root / "installer" / "hooks", "PyInstaller hooks"),
        ]
        
        for path, desc in core_dirs:
            passed, msg = check_directory_exists(path, desc)
            print_check(desc, passed, msg)
            if not passed:
                self.errors.append(f"Missing core directory: {path}")
    
    def check_python_dependencies(self):
        """Check Python dependencies."""
        print_header("Python Environment")
        
        # Check Python version
        py_version = sys.version_info
        py_ok = py_version >= (3, 10)
        print_check(
            f"Python {py_version.major}.{py_version.minor}.{py_version.micro}",
            py_ok,
            "" if py_ok else "Python 3.10+ required"
        )
        if not py_ok:
            self.errors.append("Python 3.10 or higher is required")
        
        # Check required packages
        required_packages = [
            ("pyinstaller", "PyInstaller"),
            ("PIL", "Pillow (for asset generation)"),
        ]
        
        for module, name in required_packages:
            try:
                __import__(module)
                print_check(name, True)
            except ImportError:
                print_check(name, False, f"pip install {module.lower()}")
                self.warnings.append(f"Missing package: {name}")
    
    def check_windows_requirements(self):
        """Check Windows-specific requirements."""
        print_header("Windows Requirements")
        
        if platform.system() != "Windows":
            print_warning("Skipping Windows build tool checks (not on Windows)")
            return
        
        # Check for WiX Toolset
        wix_found = check_command_exists("candle") and check_command_exists("light")
        print_check("WiX Toolset", wix_found, 
                   "" if wix_found else "Download from https://wixtoolset.org")
        if not wix_found:
            self.warnings.append("WiX Toolset not found - MSI builds will fail")
        
        # Check for Inno Setup
        iscc_found = check_command_exists("iscc")
        if not iscc_found:
            # Check common install locations
            inno_paths = [
                Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
                Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
            ]
            for p in inno_paths:
                if p.exists():
                    iscc_found = True
                    break
        
        print_check("Inno Setup", iscc_found,
                   "" if iscc_found else "Download from https://jrsoftware.org/isinfo.php")
        if not iscc_found:
            self.warnings.append("Inno Setup not found - EXE installer builds will fail")
        
        # Check Windows-specific files
        win_files = [
            (self.root / "installer" / "inno" / "jarwis-agent.iss", "Inno Setup script"),
            (self.root / "installer" / "windows" / "jarwis-agent.wxs", "WiX configuration"),
            (self.root / "installer" / "windows" / "build.bat", "Build script"),
        ]
        
        for path, desc in win_files:
            passed, msg = check_file_exists(path, desc)
            print_check(desc, passed, msg)
            if not passed:
                self.errors.append(f"Missing Windows file: {path}")
        
        # Check branding assets
        self.check_branding_assets("windows")
    
    def check_macos_requirements(self):
        """Check macOS-specific requirements."""
        print_header("macOS Requirements")
        
        if platform.system() != "Darwin":
            print_warning("Skipping macOS build tool checks (not on macOS)")
            # Still check file existence
            mac_files = [
                (self.root / "installer" / "macos" / "build.sh", "Build script"),
                (self.root / "installer" / "macos" / "com.jarwis.agent.plist", "LaunchDaemon plist"),
                (self.root / "installer" / "macos" / "entitlements.plist", "Entitlements"),
            ]
            for path, desc in mac_files:
                passed, msg = check_file_exists(path, desc)
                print_check(desc, passed, msg)
                if not passed:
                    self.errors.append(f"Missing macOS file: {path}")
            return
        
        # Check Xcode Command Line Tools
        xcode_found = check_command_exists("pkgbuild") and check_command_exists("productbuild")
        print_check("Xcode Command Line Tools", xcode_found,
                   "" if xcode_found else "Run: xcode-select --install")
        if not xcode_found:
            self.errors.append("Xcode Command Line Tools required for macOS builds")
        
        # Check iconutil
        iconutil_found = check_command_exists("iconutil")
        print_check("iconutil", iconutil_found)
        if not iconutil_found:
            self.warnings.append("iconutil not found - icon generation may fail")
        
        # Check for Apple Silicon support
        if platform.machine() == "arm64":
            print_check("Apple Silicon (arm64)", True, "Building for Apple Silicon")
        else:
            print_check("Intel (x86_64)", True, "Building for Intel")
    
    def check_linux_requirements(self):
        """Check Linux-specific requirements."""
        print_header("Linux Requirements")
        
        if platform.system() != "Linux":
            print_warning("Skipping Linux build tool checks (not on Linux)")
            # Still check file existence
            linux_files = [
                (self.root / "installer" / "linux" / "build.sh", "Build script"),
                (self.root / "installer" / "linux" / "jarwis-agent.service", "systemd service"),
                (self.root / "installer" / "linux" / "postinstall.sh", "Post-install script"),
            ]
            for path, desc in linux_files:
                passed, msg = check_file_exists(path, desc)
                print_check(desc, passed, msg)
                if not passed:
                    self.errors.append(f"Missing Linux file: {path}")
            return
        
        # Check for fpm
        fpm_found = check_command_exists("fpm")
        print_check("fpm (Effing Package Management)", fpm_found,
                   "" if fpm_found else "gem install fpm")
        if not fpm_found:
            self.warnings.append("fpm not found - DEB/RPM builds will fail")
        
        # Check architecture
        arch = platform.machine()
        print_check(f"Architecture: {arch}", True)
        
        if arch == "aarch64":
            print_warning("ARM64 builds are supported but may require cross-compilation testing")
    
    def check_branding_assets(self, target_platform: str):
        """Check branding assets exist."""
        print_header("Branding Assets")
        
        assets = {
            "windows": [
                (self.root / "installer" / "assets" / "icons" / "jarwis-agent.ico", "Windows icon (.ico)"),
                (self.root / "installer" / "assets" / "bitmaps" / "banner.bmp", "Installer banner (493x58)"),
                (self.root / "installer" / "assets" / "bitmaps" / "dialog.bmp", "Installer dialog (493x312)"),
                (self.root / "installer" / "assets" / "bitmaps" / "wizard_large.bmp", "Inno wizard large (164x314)"),
                (self.root / "installer" / "assets" / "bitmaps" / "wizard_small.bmp", "Inno wizard small (55x55)"),
            ],
            "macos": [
                (self.root / "installer" / "assets" / "icons" / "jarwis-agent.icns", "macOS icon (.icns)"),
            ],
            "linux": [],  # Linux typically doesn't need special assets
        }
        
        platform_assets = assets.get(target_platform, [])
        
        for path, desc in platform_assets:
            passed, msg = check_file_exists(path, desc)
            print_check(desc, passed, msg)
            if not passed:
                self.warnings.append(f"Missing branding asset: {path}")
                if self.auto_fix:
                    print(f"          {Colors.BLUE}TIP: Run 'python installer/assets/create_icons.py' to generate{Colors.RESET}")
    
    def check_runtime_dependencies(self):
        """Check runtime dependencies that users will need."""
        print_header("Runtime Dependencies (User Requirements)")
        
        print_warning("The following tools are required at runtime by end users:")
        
        runtime_deps = [
            ("nmap", "Network scanning", "https://nmap.org/download.html"),
            ("adb", "Android mobile testing", "Android SDK Platform Tools"),
            ("aws", "AWS cloud scanning", "https://aws.amazon.com/cli/"),
            ("gcloud", "GCP cloud scanning", "https://cloud.google.com/sdk/docs/install"),
            ("az", "Azure cloud scanning", "https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"),
        ]
        
        for cmd, desc, install_info in runtime_deps:
            found = check_command_exists(cmd)
            status = "available" if found else "NOT FOUND"
            color = Colors.GREEN if found else Colors.YELLOW
            print(f"    {color}• {cmd}: {desc} - {status}{Colors.RESET}")
        
        print(f"\n    {Colors.BLUE}Note: These are user requirements, not build requirements.{Colors.RESET}")
        print(f"    {Colors.BLUE}Document these in user installation guide.{Colors.RESET}")
    
    def print_summary(self) -> int:
        """Print summary and return exit code."""
        print_header("Summary")
        
        if self.errors:
            print(f"{Colors.RED}CRITICAL ERRORS ({len(self.errors)}):{Colors.RESET}")
            for err in self.errors:
                print(f"  {Colors.RED}• {err}{Colors.RESET}")
            print()
        
        if self.warnings:
            print(f"{Colors.YELLOW}WARNINGS ({len(self.warnings)}):{Colors.RESET}")
            for warn in self.warnings:
                print(f"  {Colors.YELLOW}• {warn}{Colors.RESET}")
            print()
        
        if not self.errors and not self.warnings:
            print(f"{Colors.GREEN}All checks passed! Ready to build.{Colors.RESET}\n")
            return 0
        elif not self.errors:
            print(f"{Colors.YELLOW}Pre-flight completed with warnings. Build may succeed.{Colors.RESET}\n")
            return 2
        else:
            print(f"{Colors.RED}Pre-flight FAILED. Fix critical errors before building.{Colors.RESET}\n")
            return 1


def main():
    parser = argparse.ArgumentParser(
        description="Pre-flight validation for Jarwis Agent installer builds",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python preflight_check.py                    # Check all platforms
    python preflight_check.py --platform windows # Check Windows only
    python preflight_check.py --fix              # Auto-fix simple issues
        """
    )
    parser.add_argument(
        "--platform", "-p",
        choices=["windows", "macos", "linux", "all"],
        default="all",
        help="Target platform to check (default: all)"
    )
    parser.add_argument(
        "--fix", "-f",
        action="store_true",
        help="Attempt to auto-fix simple issues"
    )
    
    args = parser.parse_args()
    
    project_root = get_project_root()
    checker = PreflightChecker(project_root, args.platform, args.fix)
    exit_code = checker.run_all_checks()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
