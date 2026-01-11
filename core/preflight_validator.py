"""
Jarwis AGI Pen Test - Preflight Validator

Validates all dependencies and requirements BEFORE scan starts.
Prevents scans from failing mid-way due to missing tools.

Usage:
    validator = PreflightValidator(config)
    result = await validator.validate_all()
    if not result.passed:
        for issue in result.issues:
            print(f"[{issue.severity}] {issue.component}: {issue.message}")
"""

import asyncio
import logging
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import importlib
import os

logger = logging.getLogger(__name__)


class IssueSeverity(Enum):
    """Severity levels for validation issues"""
    CRITICAL = "critical"  # Scan cannot proceed
    WARNING = "warning"    # Scan can proceed with reduced capability
    INFO = "info"          # Informational only


@dataclass
class ValidationIssue:
    """A single validation issue"""
    component: str
    message: str
    severity: IssueSeverity
    fix_suggestion: str = ""
    auto_fixable: bool = False
    fix_command: str = ""


@dataclass
class ValidationResult:
    """Result of preflight validation"""
    passed: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    checks_run: int = 0
    checks_passed: int = 0
    duration_seconds: float = 0.0
    
    def add_issue(self, issue: ValidationIssue):
        self.issues.append(issue)
        if issue.severity == IssueSeverity.CRITICAL:
            self.passed = False
    
    def get_critical_issues(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == IssueSeverity.CRITICAL]
    
    def get_auto_fixable_issues(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.auto_fixable]


class PreflightValidator:
    """
    Validates scan requirements before execution.
    
    Checks:
    - Required Python modules
    - External tools (playwright, nmap, mitmproxy)
    - Network connectivity to target
    - Port availability for proxies
    - File system permissions
    - Browser installation
    """
    
    # Required Python modules for scanning
    REQUIRED_MODULES = [
        ("aiohttp", "pip install aiohttp"),
        ("playwright", "pip install playwright"),
        ("bs4", "pip install beautifulsoup4"),
        ("rich", "pip install rich"),
    ]
    
    # Optional modules (warning if missing)
    OPTIONAL_MODULES = [
        ("mitmproxy", "pip install mitmproxy"),
        ("frida", "pip install frida-tools"),
        ("nmap", "pip install python-nmap"),
    ]
    
    # External CLI tools
    EXTERNAL_TOOLS = {
        "nmap": {
            "check_cmd": ["nmap", "--version"],
            "install_hint": "Download from https://nmap.org/download.html",
            "required": False
        },
        "mitmproxy": {
            "check_cmd": ["mitmdump", "--version"],
            "install_hint": "pip install mitmproxy",
            "required": False
        }
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.target_url = config.get('target', {}).get('url', '') if config else ''
        self.result = ValidationResult(passed=True)
    
    async def validate_all(self) -> ValidationResult:
        """Run all validation checks"""
        import time
        start = time.time()
        
        checks = [
            ("Python Modules", self._check_python_modules),
            ("External Tools", self._check_external_tools),
            ("Playwright Browsers", self._check_playwright_browsers),
            ("Target Connectivity", self._check_target_connectivity),
            ("Proxy Ports", self._check_proxy_ports),
            ("File System", self._check_file_system),
            ("Scanner Registry", self._check_scanner_registry),
        ]
        
        for name, check_fn in checks:
            self.result.checks_run += 1
            try:
                logger.debug(f"Running preflight check: {name}")
                await check_fn()
                self.result.checks_passed += 1
            except Exception as e:
                logger.error(f"Preflight check '{name}' failed: {e}")
                self.result.add_issue(ValidationIssue(
                    component=name,
                    message=f"Check failed with error: {str(e)}",
                    severity=IssueSeverity.WARNING
                ))
        
        self.result.duration_seconds = time.time() - start
        
        # Log summary
        critical = len(self.result.get_critical_issues())
        warnings = len([i for i in self.result.issues if i.severity == IssueSeverity.WARNING])
        
        if critical > 0:
            logger.error(f"Preflight validation FAILED: {critical} critical issues")
        elif warnings > 0:
            logger.warning(f"Preflight validation passed with {warnings} warnings")
        else:
            logger.info("Preflight validation passed - all checks OK")
        
        return self.result
    
    async def _check_python_modules(self):
        """Check required Python modules are installed"""
        for module_name, install_cmd in self.REQUIRED_MODULES:
            try:
                importlib.import_module(module_name)
            except ImportError:
                self.result.add_issue(ValidationIssue(
                    component="Python Module",
                    message=f"Required module '{module_name}' is not installed",
                    severity=IssueSeverity.CRITICAL,
                    fix_suggestion=f"Run: {install_cmd}",
                    auto_fixable=True,
                    fix_command=install_cmd
                ))
        
        # Check optional modules
        for module_name, install_cmd in self.OPTIONAL_MODULES:
            try:
                importlib.import_module(module_name)
            except ImportError:
                self.result.add_issue(ValidationIssue(
                    component="Python Module",
                    message=f"Optional module '{module_name}' is not installed (some features disabled)",
                    severity=IssueSeverity.WARNING,
                    fix_suggestion=f"Run: {install_cmd}",
                    auto_fixable=True,
                    fix_command=install_cmd
                ))
    
    async def _check_external_tools(self):
        """Check external CLI tools are available"""
        for tool_name, tool_info in self.EXTERNAL_TOOLS.items():
            try:
                result = subprocess.run(
                    tool_info["check_cmd"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode != 0:
                    raise FileNotFoundError(f"{tool_name} returned error")
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                severity = IssueSeverity.CRITICAL if tool_info["required"] else IssueSeverity.WARNING
                self.result.add_issue(ValidationIssue(
                    component="External Tool",
                    message=f"Tool '{tool_name}' is not available: {e}",
                    severity=severity,
                    fix_suggestion=tool_info["install_hint"]
                ))
    
    async def _check_playwright_browsers(self):
        """Check Playwright browsers are installed"""
        try:
            from playwright.sync_api import sync_playwright
            
            # Check if browser binaries exist
            # Playwright stores browsers in a specific location
            home = Path.home()
            playwright_browsers = home / ".cache" / "ms-playwright"
            
            # On Windows
            if sys.platform == "win32":
                playwright_browsers = home / "AppData" / "Local" / "ms-playwright"
            
            if not playwright_browsers.exists():
                self.result.add_issue(ValidationIssue(
                    component="Playwright",
                    message="Playwright browsers not installed",
                    severity=IssueSeverity.CRITICAL,
                    fix_suggestion="Run: playwright install chromium",
                    auto_fixable=True,
                    fix_command="playwright install chromium"
                ))
                return
            
            # Check for chromium specifically
            chromium_dirs = list(playwright_browsers.glob("chromium-*"))
            if not chromium_dirs:
                self.result.add_issue(ValidationIssue(
                    component="Playwright",
                    message="Chromium browser not installed for Playwright",
                    severity=IssueSeverity.CRITICAL,
                    fix_suggestion="Run: playwright install chromium",
                    auto_fixable=True,
                    fix_command="playwright install chromium"
                ))
                
        except ImportError:
            self.result.add_issue(ValidationIssue(
                component="Playwright",
                message="Playwright module not installed",
                severity=IssueSeverity.CRITICAL,
                fix_suggestion="Run: pip install playwright && playwright install chromium",
                auto_fixable=True,
                fix_command="pip install playwright"
            ))
    
    async def _check_target_connectivity(self):
        """Check if target URL is reachable"""
        if not self.target_url:
            return  # No target specified yet
        
        try:
            parsed = urlparse(self.target_url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if not host:
                self.result.add_issue(ValidationIssue(
                    component="Target",
                    message=f"Invalid target URL: {self.target_url}",
                    severity=IssueSeverity.CRITICAL,
                    fix_suggestion="Provide a valid URL with scheme (http:// or https://)"
                ))
                return
            
            # Try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                result = sock.connect_ex((host, port))
                if result != 0:
                    self.result.add_issue(ValidationIssue(
                        component="Target",
                        message=f"Cannot connect to {host}:{port}",
                        severity=IssueSeverity.CRITICAL,
                        fix_suggestion="Check if target is online and accessible"
                    ))
            finally:
                sock.close()
                
        except socket.gaierror as e:
            self.result.add_issue(ValidationIssue(
                component="Target",
                message=f"Cannot resolve hostname: {e}",
                severity=IssueSeverity.CRITICAL,
                fix_suggestion="Check DNS resolution and hostname spelling"
            ))
        except Exception as e:
            self.result.add_issue(ValidationIssue(
                component="Target",
                message=f"Connectivity check failed: {e}",
                severity=IssueSeverity.WARNING
            ))
    
    async def _check_proxy_ports(self):
        """Check if required ports are available for MITM proxy"""
        ports_to_check = [
            (8080, "MITM Proxy"),
            (8081, "MITM Proxy (alternate)"),
        ]
        
        for port, name in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    # Port is in use
                    self.result.add_issue(ValidationIssue(
                        component="Network",
                        message=f"Port {port} ({name}) is already in use",
                        severity=IssueSeverity.WARNING,
                        fix_suggestion=f"Kill the process using port {port} or use a different port"
                    ))
            finally:
                sock.close()
    
    async def _check_file_system(self):
        """Check file system permissions and directories"""
        required_dirs = [
            Path("temp/scans"),
            Path("reports"),
            Path("uploads"),
            Path("logs"),
        ]
        
        for dir_path in required_dirs:
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                
                # Test write permission
                test_file = dir_path / ".write_test"
                test_file.write_text("test")
                test_file.unlink()
                
            except PermissionError:
                self.result.add_issue(ValidationIssue(
                    component="File System",
                    message=f"No write permission for directory: {dir_path}",
                    severity=IssueSeverity.CRITICAL,
                    fix_suggestion=f"Grant write permissions to {dir_path}"
                ))
            except Exception as e:
                self.result.add_issue(ValidationIssue(
                    component="File System",
                    message=f"Cannot access directory {dir_path}: {e}",
                    severity=IssueSeverity.WARNING
                ))
    
    async def _check_scanner_registry(self):
        """Check if scanner registry loads correctly"""
        try:
            from core.scanner_registry import ScannerRegistry
            
            registry = ScannerRegistry()
            scanner_count = len(registry._scanners)
            
            if scanner_count == 0:
                self.result.add_issue(ValidationIssue(
                    component="Scanner Registry",
                    message="No scanners registered",
                    severity=IssueSeverity.CRITICAL,
                    fix_suggestion="Check attacks/ directory for scanner modules"
                ))
            elif scanner_count < 50:
                self.result.add_issue(ValidationIssue(
                    component="Scanner Registry",
                    message=f"Only {scanner_count} scanners loaded (expected 100+)",
                    severity=IssueSeverity.WARNING,
                    fix_suggestion="Some scanner imports may be failing"
                ))
            else:
                logger.info(f"Scanner registry OK: {scanner_count} scanners loaded")
                
        except Exception as e:
            self.result.add_issue(ValidationIssue(
                component="Scanner Registry",
                message=f"Failed to load scanner registry: {e}",
                severity=IssueSeverity.CRITICAL
            ))
    
    async def auto_fix(self, issue: ValidationIssue) -> bool:
        """Attempt to automatically fix an issue"""
        if not issue.auto_fixable or not issue.fix_command:
            return False
        
        try:
            logger.info(f"Attempting auto-fix: {issue.fix_command}")
            
            # Run the fix command
            result = subprocess.run(
                issue.fix_command.split(),
                capture_output=True,
                timeout=120
            )
            
            if result.returncode == 0:
                logger.info(f"Auto-fix successful: {issue.component}")
                return True
            else:
                logger.error(f"Auto-fix failed: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Auto-fix error: {e}")
            return False
    
    async def fix_all_auto_fixable(self) -> int:
        """Attempt to fix all auto-fixable issues"""
        fixed_count = 0
        
        for issue in self.result.get_auto_fixable_issues():
            if await self.auto_fix(issue):
                fixed_count += 1
        
        return fixed_count
    
    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary"""
        return {
            "passed": self.result.passed,
            "checks_run": self.result.checks_run,
            "checks_passed": self.result.checks_passed,
            "critical_issues": len(self.result.get_critical_issues()),
            "warnings": len([i for i in self.result.issues if i.severity == IssueSeverity.WARNING]),
            "auto_fixable": len(self.result.get_auto_fixable_issues()),
            "duration_seconds": self.result.duration_seconds,
            "issues": [
                {
                    "component": i.component,
                    "message": i.message,
                    "severity": i.severity.value,
                    "fix_suggestion": i.fix_suggestion
                }
                for i in self.result.issues
            ]
        }


async def run_preflight_check(config: Dict[str, Any] = None) -> ValidationResult:
    """Convenience function to run all preflight checks"""
    validator = PreflightValidator(config)
    return await validator.validate_all()
