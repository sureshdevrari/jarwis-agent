"""
Jarwis Network Security Scanner - Base Classes and Utilities

This module provides the foundation for all network security scanning tools.
All scanners inherit from BaseScanner and follow a consistent output format.

Output Standard (Mandatory):
{
    "tool": "tool_name",
    "target": "1.2.3.4",
    "findings": [...],
    "severity": "high|medium|low|info",
    "confidence": 0.92
}
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanPhase(Enum):
    """Network scanning phases"""
    DISCOVERY = "discovery"          # Host discovery
    PORT_SCAN = "port_scan"          # Port scanning
    SERVICE_ENUM = "service_enum"    # Service enumeration
    VULN_SCAN = "vuln_scan"          # Vulnerability scanning
    SSL_AUDIT = "ssl_audit"          # SSL/TLS checks
    CREDENTIAL = "credential"         # Authenticated scanning
    EXPLOITATION = "exploitation"     # Optional exploitation validation
    TRAFFIC_ANALYSIS = "traffic_analysis"  # Passive traffic analysis


class ScanMode(Enum):
    """Scan aggressiveness modes"""
    SAFE = "safe"           # Read-only, non-intrusive
    NORMAL = "normal"       # Standard scanning
    AGGRESSIVE = "aggressive"  # Deep scanning, may trigger IDS


@dataclass
class Finding:
    """Represents a single security finding"""
    id: str
    tool: str
    category: str
    severity: str
    title: str
    description: str
    target: str
    port: Optional[int] = None
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    cve_id: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.0
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    raw_output: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Standard output format for all scanners"""
    tool: str
    target: str
    phase: str
    findings: List[Finding] = field(default_factory=list)
    hosts_discovered: List[Dict] = field(default_factory=list)
    ports_discovered: List[Dict] = field(default_factory=list)
    services_discovered: List[Dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    scan_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['findings'] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ToolInstaller:
    """Manages installation and availability of network tools"""
    
    # Tool installation commands by OS
    INSTALL_COMMANDS = {
        'nmap': {
            'linux': 'sudo apt install -y nmap',
            'darwin': 'brew install nmap',
            'windows': 'choco install nmap -y'
        },
        'masscan': {
            'linux': 'sudo apt install -y masscan',
            'darwin': 'brew install masscan',
            'windows': 'echo "Download from https://github.com/robertdavidgraham/masscan"'
        },
        'rustscan': {
            'linux': 'cargo install rustscan',
            'darwin': 'brew install rustscan',
            'windows': 'cargo install rustscan'
        },
        'nuclei': {
            'linux': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'darwin': 'brew install nuclei',
            'windows': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
        },
        'sslscan': {
            'linux': 'sudo apt install -y sslscan',
            'darwin': 'brew install sslscan',
            'windows': 'choco install sslscan -y'
        },
        'testssl': {
            'linux': 'git clone https://github.com/drwetter/testssl.sh.git',
            'darwin': 'brew install testssl',
            'windows': 'git clone https://github.com/drwetter/testssl.sh.git'
        },
        'snmpwalk': {
            'linux': 'sudo apt install -y snmp',
            'darwin': 'brew install net-snmp',
            'windows': 'choco install net-snmp -y'
        },
        'dnsrecon': {
            'linux': 'pip install dnsrecon',
            'darwin': 'pip install dnsrecon',
            'windows': 'pip install dnsrecon'
        },
        'crackmapexec': {
            'linux': 'pip install crackmapexec',
            'darwin': 'pip install crackmapexec',
            'windows': 'pip install crackmapexec'
        },
    }
    
    # Python packages required
    PYTHON_PACKAGES = [
        'python-nmap',
        'sslyze',
        'impacket',
        'gvm-tools',
        'pysnmp',
        'dnspython',
        'scapy',
    ]

    @staticmethod
    def is_tool_available(tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        return shutil.which(tool_name) is not None

    @staticmethod
    def get_tool_version(tool_name: str) -> Optional[str]:
        """Get version of installed tool"""
        try:
            if tool_name == 'nmap':
                result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
                return result.stdout.split('\n')[0] if result.returncode == 0 else None
            elif tool_name == 'nuclei':
                result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
                return result.stdout.strip() if result.returncode == 0 else None
            # Add more tools as needed
        except Exception:
            return None
        return None

    @classmethod
    def check_all_tools(cls) -> Dict[str, bool]:
        """Check availability of all tools"""
        tools = ['nmap', 'masscan', 'rustscan', 'nuclei', 'sslscan', 
                 'snmpwalk', 'crackmapexec', 'dnsrecon']
        return {tool: cls.is_tool_available(tool) for tool in tools}

    @classmethod
    def get_install_instructions(cls) -> str:
        """Get installation instructions for all tools"""
        import platform
        os_type = platform.system().lower()
        
        instructions = ["# Jarwis Network Security Tools Installation\n"]
        
        # Python packages
        instructions.append("## Python Packages")
        instructions.append(f"pip install {' '.join(cls.PYTHON_PACKAGES)}\n")
        
        # System tools
        instructions.append("## System Tools")
        for tool, commands in cls.INSTALL_COMMANDS.items():
            cmd = commands.get(os_type, commands.get('linux', 'N/A'))
            instructions.append(f"# {tool}")
            instructions.append(cmd)
        
        return '\n'.join(instructions)


class BaseScanner(ABC):
    """
    Abstract base class for all network security scanners.
    
    All tool-specific scanners must inherit from this class and implement:
    - run(): Execute the scan
    - parse_output(): Parse raw output into findings
    """
    
    TOOL_NAME: str = "base"
    PHASE: ScanPhase = ScanPhase.DISCOVERY
    REQUIRES_ROOT: bool = False
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 300)
        self.rate_limit = self.config.get('rate_limit', 100)
        self.mode = ScanMode(self.config.get('mode', 'safe'))
        self._finding_counter = 0
    
    def _generate_id(self) -> str:
        """Generate unique finding ID"""
        self._finding_counter += 1
        return f"{self.TOOL_NAME.upper()}-{self._finding_counter:04d}"
    
    @abstractmethod
    async def run(self, target: str, **kwargs) -> ScanResult:
        """
        Execute the scan against the target.
        
        Args:
            target: IP address, CIDR range, or hostname
            **kwargs: Tool-specific options
        
        Returns:
            ScanResult with findings
        """
        raise NotImplementedError
    
    @abstractmethod
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """
        Parse raw tool output into structured findings.
        
        Args:
            raw_output: Raw output from the tool
            target: Original target specification
        
        Returns:
            List of Finding objects
        """
        raise NotImplementedError
    
    def is_available(self) -> bool:
        """Check if the tool is installed and available"""
        return ToolInstaller.is_tool_available(self.TOOL_NAME)
    
    async def _run_command(
        self, 
        cmd: List[str], 
        timeout: int = None,
        input_data: str = None
    ) -> Tuple[str, str, int]:
        """
        Run a shell command asynchronously.
        
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        timeout = timeout or self.timeout
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_data.encode() if input_data else None),
                timeout=timeout
            )
            
            return (
                stdout.decode('utf-8', errors='ignore'),
                stderr.decode('utf-8', errors='ignore'),
                process.returncode
            )
            
        except asyncio.TimeoutError:
            process.kill()
            return "", f"Command timed out after {timeout}s", -1
        except FileNotFoundError:
            return "", f"Tool '{cmd[0]}' not found", -1
        except Exception as e:
            return "", str(e), -1
    
    def _severity_from_cvss(self, cvss: float) -> str:
        """Convert CVSS score to severity string"""
        if cvss >= 9.0:
            return Severity.CRITICAL.value
        elif cvss >= 7.0:
            return Severity.HIGH.value
        elif cvss >= 4.0:
            return Severity.MEDIUM.value
        elif cvss > 0:
            return Severity.LOW.value
        return Severity.INFO.value


class ScannerRegistry:
    """Registry of available scanners by phase"""
    
    _scanners: Dict[ScanPhase, List[type]] = {
        ScanPhase.DISCOVERY: [],
        ScanPhase.PORT_SCAN: [],
        ScanPhase.SERVICE_ENUM: [],
        ScanPhase.VULN_SCAN: [],
        ScanPhase.SSL_AUDIT: [],
        ScanPhase.CREDENTIAL: [],
        ScanPhase.EXPLOITATION: [],
        ScanPhase.TRAFFIC_ANALYSIS: [],
    }
    
    @classmethod
    def register(cls, scanner_class: type):
        """Register a scanner class"""
        phase = scanner_class.PHASE
        if scanner_class not in cls._scanners[phase]:
            cls._scanners[phase].append(scanner_class)
        return scanner_class
    
    @classmethod
    def get_scanners(cls, phase: ScanPhase) -> List[type]:
        """Get all scanners for a phase"""
        return cls._scanners[phase]
    
    @classmethod
    def get_all_scanners(cls) -> Dict[ScanPhase, List[type]]:
        """Get all registered scanners"""
        return cls._scanners
