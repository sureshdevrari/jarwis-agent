#!/usr/bin/env python3
"""
Jarwis Agent - Runtime Dependency Checker

This module checks for optional runtime dependencies and provides
installation guidance. It's integrated into the agent startup and
can also be run standalone.

Usage:
    python runtime_deps.py                    # Check all dependencies
    python runtime_deps.py --install          # Auto-install what's possible
    python runtime_deps.py --json             # Output as JSON
    python runtime_deps.py --category network # Check only network deps
"""

import os
import sys
import json
import shutil
import platform
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Callable
from enum import Enum


class DependencyStatus(Enum):
    INSTALLED = "installed"
    MISSING = "missing"
    OUTDATED = "outdated"
    OPTIONAL = "optional"


class DependencyCategory(Enum):
    NETWORK = "network"
    MOBILE = "mobile"
    CLOUD_AWS = "cloud_aws"
    CLOUD_GCP = "cloud_gcp"
    CLOUD_AZURE = "cloud_azure"
    WEB = "web"
    SAST = "sast"


@dataclass
class Dependency:
    """Represents a runtime dependency."""
    name: str
    category: DependencyCategory
    command: str
    description: str
    install_windows: str
    install_macos: str
    install_linux: str
    version_flag: str = "--version"
    required: bool = False
    min_version: Optional[str] = None


@dataclass
class DependencyResult:
    """Result of checking a dependency."""
    name: str
    category: str
    status: str
    version: Optional[str]
    description: str
    install_instructions: str


# Define all runtime dependencies
DEPENDENCIES: List[Dependency] = [
    # Network scanning
    Dependency(
        name="Nmap",
        category=DependencyCategory.NETWORK,
        command="nmap",
        description="Network exploration and security auditing tool",
        install_windows="Download from https://nmap.org/download.html",
        install_macos="brew install nmap",
        install_linux="sudo apt install nmap  # or: sudo yum install nmap",
        min_version="7.0",
    ),
    Dependency(
        name="Masscan",
        category=DependencyCategory.NETWORK,
        command="masscan",
        description="Fast port scanner (optional, enhances network scanning speed)",
        install_windows="Download from https://github.com/robertdavidgraham/masscan",
        install_macos="brew install masscan",
        install_linux="sudo apt install masscan",
    ),
    
    # Mobile testing
    Dependency(
        name="Android Debug Bridge (ADB)",
        category=DependencyCategory.MOBILE,
        command="adb",
        description="Required for Android mobile application testing",
        install_windows="Download Android SDK Platform Tools",
        install_macos="brew install android-platform-tools",
        install_linux="sudo apt install android-tools-adb",
        version_flag="version",
    ),
    Dependency(
        name="Java Runtime",
        category=DependencyCategory.MOBILE,
        command="java",
        description="Required for APK analysis tools",
        install_windows="Download from https://adoptium.net/",
        install_macos="brew install openjdk",
        install_linux="sudo apt install default-jre",
        min_version="11",
    ),
    
    # Cloud - AWS
    Dependency(
        name="AWS CLI",
        category=DependencyCategory.CLOUD_AWS,
        command="aws",
        description="Required for AWS cloud security scanning",
        install_windows="Download from https://aws.amazon.com/cli/",
        install_macos="brew install awscli",
        install_linux="pip install awscli",
    ),
    
    # Cloud - GCP
    Dependency(
        name="Google Cloud SDK",
        category=DependencyCategory.CLOUD_GCP,
        command="gcloud",
        description="Required for GCP cloud security scanning",
        install_windows="Download from https://cloud.google.com/sdk/docs/install",
        install_macos="brew install google-cloud-sdk",
        install_linux="snap install google-cloud-sdk --classic",
    ),
    
    # Cloud - Azure
    Dependency(
        name="Azure CLI",
        category=DependencyCategory.CLOUD_AZURE,
        command="az",
        description="Required for Azure cloud security scanning",
        install_windows="Download from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli",
        install_macos="brew install azure-cli",
        install_linux="curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash",
    ),
    
    # Web testing
    Dependency(
        name="Chrome/Chromium",
        category=DependencyCategory.WEB,
        command="chromium" if platform.system() != "Windows" else "chrome",
        description="Required for web application crawling and testing",
        install_windows="Download from https://www.google.com/chrome/",
        install_macos="brew install chromium",
        install_linux="sudo apt install chromium-browser",
    ),
    
    # SAST
    Dependency(
        name="Git",
        category=DependencyCategory.SAST,
        command="git",
        description="Required for repository cloning in SAST scanning",
        install_windows="Download from https://git-scm.com/download/win",
        install_macos="xcode-select --install",
        install_linux="sudo apt install git",
    ),
]


def get_platform() -> str:
    """Get the current platform name."""
    system = platform.system()
    if system == "Darwin":
        return "macos"
    return system.lower()


def check_command_exists(command: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(command) is not None


def get_command_version(command: str, version_flag: str = "--version") -> Optional[str]:
    """Get the version of an installed command."""
    try:
        result = subprocess.run(
            [command, version_flag],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout or result.stderr
        # Extract version number from output
        import re
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', output)
        if version_match:
            return version_match.group(1)
        return output.strip().split('\n')[0][:50]  # First line, truncated
    except Exception:
        return None


def get_install_instructions(dep: Dependency) -> str:
    """Get platform-specific installation instructions."""
    current_platform = get_platform()
    if current_platform == "windows":
        return dep.install_windows
    elif current_platform == "macos":
        return dep.install_macos
    else:
        return dep.install_linux


def check_dependency(dep: Dependency) -> DependencyResult:
    """Check a single dependency and return the result."""
    exists = check_command_exists(dep.command)
    version = None
    status = DependencyStatus.MISSING
    
    if exists:
        version = get_command_version(dep.command, dep.version_flag)
        status = DependencyStatus.INSTALLED
        
        # Check version if minimum is specified
        if dep.min_version and version:
            try:
                from packaging import version as pkg_version
                if pkg_version.parse(version) < pkg_version.parse(dep.min_version):
                    status = DependencyStatus.OUTDATED
            except Exception:
                pass  # Skip version comparison if parsing fails
    
    return DependencyResult(
        name=dep.name,
        category=dep.category.value,
        status=status.value,
        version=version,
        description=dep.description,
        install_instructions=get_install_instructions(dep),
    )


def check_all_dependencies(
    categories: Optional[List[DependencyCategory]] = None
) -> List[DependencyResult]:
    """Check all dependencies, optionally filtered by category."""
    results = []
    for dep in DEPENDENCIES:
        if categories is None or dep.category in categories:
            results.append(check_dependency(dep))
    return results


def check_and_report(
    categories: Optional[List[str]] = None,
    output_json: bool = False,
    verbose: bool = True
) -> Dict:
    """Check dependencies and generate a report."""
    
    # Convert string categories to enum
    cat_enums = None
    if categories:
        cat_enums = [DependencyCategory(c) for c in categories if c in [e.value for e in DependencyCategory]]
    
    results = check_all_dependencies(cat_enums)
    
    # Group by category
    by_category: Dict[str, List[DependencyResult]] = {}
    for r in results:
        if r.category not in by_category:
            by_category[r.category] = []
        by_category[r.category].append(r)
    
    # Count stats
    installed = sum(1 for r in results if r.status == "installed")
    missing = sum(1 for r in results if r.status == "missing")
    outdated = sum(1 for r in results if r.status == "outdated")
    
    report = {
        "platform": get_platform(),
        "total": len(results),
        "installed": installed,
        "missing": missing,
        "outdated": outdated,
        "categories": {cat: [asdict(r) for r in deps] for cat, deps in by_category.items()},
    }
    
    if output_json:
        print(json.dumps(report, indent=2))
    elif verbose:
        print_report(report, by_category)
    
    return report


def print_report(report: Dict, by_category: Dict[str, List[DependencyResult]]):
    """Print a human-readable report."""
    print("\n" + "=" * 60)
    print("  Jarwis Agent - Runtime Dependency Check")
    print("=" * 60)
    print(f"\nPlatform: {report['platform'].title()}")
    print(f"Total dependencies: {report['total']}")
    print(f"  ✓ Installed: {report['installed']}")
    print(f"  ✗ Missing: {report['missing']}")
    print(f"  ⚠ Outdated: {report['outdated']}")
    
    for category, deps in by_category.items():
        print(f"\n--- {category.upper().replace('_', ' ')} ---")
        for dep in deps:
            if dep.status == "installed":
                status_icon = "✓"
                status_color = "\033[92m"  # Green
            elif dep.status == "outdated":
                status_icon = "⚠"
                status_color = "\033[93m"  # Yellow
            else:
                status_icon = "✗"
                status_color = "\033[91m"  # Red
            
            reset = "\033[0m"
            version_str = f" (v{dep.version})" if dep.version else ""
            print(f"  {status_color}{status_icon}{reset} {dep.name}{version_str}")
            
            if dep.status != "installed":
                print(f"      Install: {dep.install_instructions}")
    
    if report['missing'] > 0:
        print("\n" + "-" * 60)
        print("Note: Missing dependencies will limit scanning capabilities.")
        print("Install them based on which features you need.")


def get_missing_for_category(category: str) -> List[str]:
    """Get list of missing dependencies for a specific category."""
    results = check_all_dependencies([DependencyCategory(category)])
    return [r.name for r in results if r.status == "missing"]


def auto_install_dependency(dep: Dependency) -> bool:
    """Attempt to auto-install a dependency using package manager."""
    current_platform = get_platform()
    
    try:
        if current_platform == "macos":
            # Try Homebrew
            if check_command_exists("brew"):
                # Extract package name from install command
                install_cmd = dep.install_macos
                if install_cmd.startswith("brew install"):
                    pkg = install_cmd.replace("brew install ", "")
                    subprocess.run(["brew", "install", pkg], check=True)
                    return True
        
        elif current_platform == "linux":
            # Try apt
            if check_command_exists("apt"):
                install_cmd = dep.install_linux
                if "apt install" in install_cmd:
                    pkg = install_cmd.split("apt install ")[-1].split()[0]
                    subprocess.run(["sudo", "apt", "install", "-y", pkg], check=True)
                    return True
        
        # Windows and other cases require manual installation
        return False
        
    except Exception as e:
        print(f"Auto-install failed for {dep.name}: {e}")
        return False


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Check Jarwis Agent runtime dependencies"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--category", "-c",
        choices=[e.value for e in DependencyCategory],
        action="append",
        help="Check only specific category"
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Attempt to auto-install missing dependencies"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only output if there are missing dependencies"
    )
    
    args = parser.parse_args()
    
    if args.install:
        print("Auto-installing missing dependencies...")
        for dep in DEPENDENCIES:
            if args.category and dep.category.value not in args.category:
                continue
            if not check_command_exists(dep.command):
                print(f"  Installing {dep.name}...")
                success = auto_install_dependency(dep)
                if success:
                    print(f"    ✓ Installed successfully")
                else:
                    print(f"    ✗ Auto-install not available. Manual install:")
                    print(f"      {get_install_instructions(dep)}")
        print()
    
    report = check_and_report(
        categories=args.category,
        output_json=args.json,
        verbose=not args.quiet and not args.json
    )
    
    # Exit with error code if missing critical dependencies
    if report['missing'] > 0:
        sys.exit(1)
    sys.exit(0)


# Export for use as a module
__all__ = [
    'check_all_dependencies',
    'check_and_report',
    'get_missing_for_category',
    'DependencyCategory',
    'DependencyStatus',
]


if __name__ == "__main__":
    main()
