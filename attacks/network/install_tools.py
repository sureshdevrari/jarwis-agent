#!/usr/bin/env python3
"""
Jarwis Network Security - Tool Installer

Installs network security tools for the Jarwis framework.
Supports Windows, Linux (Debian/RHEL), and macOS.

Usage:
    python install_tools.py --all          # Install everything
    python install_tools.py --category port  # Install port scanners only
    python install_tools.py --tool nmap    # Install specific tool
    python install_tools.py --check        # Check what's installed
"""

import os
import sys
import shutil
import subprocess
import platform
import argparse
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class Tool:
    """Tool definition with installation methods"""
    name: str
    description: str
    category: str
    executable: str  # Name of executable to check
    install_apt: Optional[str] = None      # Debian/Ubuntu
    install_yum: Optional[str] = None      # RHEL/CentOS
    install_brew: Optional[str] = None     # macOS
    install_choco: Optional[str] = None    # Windows Chocolatey
    install_pip: Optional[str] = None      # Python pip
    install_cargo: Optional[str] = None    # Rust cargo
    install_go: Optional[str] = None       # Go
    install_manual: Optional[str] = None   # Manual install URL
    requires_root: bool = False
    notes: Optional[str] = None


# All tools definition
TOOLS = [
    # Port Scanners
    Tool(
        name="nmap",
        description="Network exploration and security auditing",
        category="port",
        executable="nmap",
        install_apt="apt-get install -y nmap",
        install_yum="yum install -y nmap",
        install_brew="brew install nmap",
        install_choco="choco install nmap -y",
        requires_root=True,
    ),
    Tool(
        name="masscan",
        description="Fast TCP port scanner",
        category="port",
        executable="masscan",
        install_apt="apt-get install -y masscan",
        install_yum="yum install -y masscan",
        install_brew="brew install masscan",
        install_choco="choco install masscan -y",
        requires_root=True,
    ),
    Tool(
        name="rustscan",
        description="Modern fast port scanner",
        category="port",
        executable="rustscan",
        install_cargo="cargo install rustscan",
        install_brew="brew install rustscan",
        install_choco="choco install rustscan -y",
        install_manual="https://github.com/RustScan/RustScan/releases",
    ),
    
    # Vulnerability Scanners
    Tool(
        name="nuclei",
        description="Template-based vulnerability scanner",
        category="vuln",
        executable="nuclei",
        install_go="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        install_brew="brew install nuclei",
        install_manual="https://github.com/projectdiscovery/nuclei/releases",
        notes="Run 'nuclei -ut' after install to download templates",
    ),
    Tool(
        name="openvas",
        description="Greenbone Vulnerability Scanner",
        category="vuln",
        executable="gvm-cli",
        install_apt="apt-get install -y gvm",
        install_manual="https://greenbone.github.io/docs/",
        install_pip="pip install gvm-tools",
        requires_root=True,
        notes="Requires complex setup. See Greenbone docs.",
    ),
    
    # Enumeration
    Tool(
        name="netdiscover",
        description="ARP network discovery",
        category="enum",
        executable="netdiscover",
        install_apt="apt-get install -y netdiscover",
        install_yum="yum install -y netdiscover",
        requires_root=True,
    ),
    Tool(
        name="snmpwalk",
        description="SNMP enumeration tool",
        category="enum",
        executable="snmpwalk",
        install_apt="apt-get install -y snmp",
        install_yum="yum install -y net-snmp-utils",
        install_brew="brew install net-snmp",
    ),
    Tool(
        name="dnsrecon",
        description="DNS reconnaissance tool",
        category="enum",
        executable="dnsrecon",
        install_pip="pip install dnsrecon",
        install_apt="apt-get install -y dnsrecon",
    ),
    Tool(
        name="arp-scan",
        description="ARP host discovery",
        category="enum",
        executable="arp-scan",
        install_apt="apt-get install -y arp-scan",
        install_yum="yum install -y arp-scan",
        install_brew="brew install arp-scan",
        requires_root=True,
    ),
    
    # SSL/TLS
    Tool(
        name="sslscan",
        description="SSL/TLS configuration scanner",
        category="ssl",
        executable="sslscan",
        install_apt="apt-get install -y sslscan",
        install_yum="yum install -y sslscan",
        install_brew="brew install sslscan",
        install_choco="choco install sslscan -y",
    ),
    Tool(
        name="testssl",
        description="Comprehensive TLS testing script",
        category="ssl",
        executable="testssl.sh",
        install_apt="apt-get install -y testssl.sh",
        install_brew="brew install testssl",
        install_manual="https://github.com/drwetter/testssl.sh",
    ),
    Tool(
        name="sslyze",
        description="Python SSL/TLS analyzer",
        category="ssl",
        executable="sslyze",
        install_pip="pip install sslyze",
    ),
    
    # Exploitation
    Tool(
        name="crackmapexec",
        description="Swiss army knife for AD/networks",
        category="exploit",
        executable="crackmapexec",
        install_pip="pip install crackmapexec",
        install_apt="apt-get install -y crackmapexec",
        notes="NetExec is the successor (pip install netexec)",
    ),
    Tool(
        name="netexec",
        description="CrackMapExec successor",
        category="exploit",
        executable="netexec",
        install_pip="pip install netexec",
    ),
    Tool(
        name="impacket",
        description="Windows protocol implementation",
        category="exploit",
        executable="impacket-secretsdump",
        install_pip="pip install impacket",
    ),
    Tool(
        name="metasploit",
        description="Exploitation framework",
        category="exploit",
        executable="msfconsole",
        install_apt="apt-get install -y metasploit-framework",
        install_manual="https://www.metasploit.com/download",
        requires_root=True,
    ),
    
    # Traffic Analysis
    Tool(
        name="zeek",
        description="Network analysis framework",
        category="traffic",
        executable="zeek",
        install_apt="apt-get install -y zeek",
        install_brew="brew install zeek",
        requires_root=True,
    ),
    Tool(
        name="suricata",
        description="Network IDS/IPS",
        category="traffic",
        executable="suricata",
        install_apt="apt-get install -y suricata",
        install_yum="yum install -y suricata",
        install_brew="brew install suricata",
        requires_root=True,
    ),
    Tool(
        name="snort",
        description="Network IDS",
        category="traffic",
        executable="snort",
        install_apt="apt-get install -y snort",
        install_yum="yum install -y snort",
        requires_root=True,
    ),
    Tool(
        name="tshark",
        description="Wireshark CLI",
        category="traffic",
        executable="tshark",
        install_apt="apt-get install -y tshark",
        install_yum="yum install -y wireshark-cli",
        install_brew="brew install wireshark",
        install_choco="choco install wireshark -y",
    ),
]

# Category descriptions
CATEGORIES = {
    "port": "Port Scanners (Nmap, Masscan, RustScan)",
    "vuln": "Vulnerability Scanners (Nuclei, OpenVAS)",
    "enum": "Enumeration Tools (SNMP, DNS, ARP)",
    "ssl": "SSL/TLS Scanners (SSLScan, testssl, SSLyze)",
    "exploit": "Exploitation Tools (CME, Impacket, Metasploit)",
    "traffic": "Traffic Analysis (Zeek, Suricata, Snort)",
}


class ToolInstaller:
    """Handles tool installation across platforms"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        self._detect_package_manager()
    
    def _detect_package_manager(self):
        """Detect available package manager"""
        self.pkg_manager = None
        
        if self.system == 'linux':
            if shutil.which('apt-get'):
                self.pkg_manager = 'apt'
            elif shutil.which('yum'):
                self.pkg_manager = 'yum'
            elif shutil.which('dnf'):
                self.pkg_manager = 'dnf'
        elif self.system == 'darwin':
            if shutil.which('brew'):
                self.pkg_manager = 'brew'
        elif self.system == 'windows':
            if shutil.which('choco'):
                self.pkg_manager = 'choco'
    
    def is_installed(self, tool: Tool) -> bool:
        """Check if tool is installed"""
        return shutil.which(tool.executable) is not None
    
    def check_all(self) -> Dict[str, bool]:
        """Check installation status of all tools"""
        return {tool.name: self.is_installed(tool) for tool in TOOLS}
    
    def install(self, tool: Tool, force: bool = False) -> bool:
        """Install a tool"""
        if self.is_installed(tool) and not force:
            logger.info(f"[OK] {tool.name} already installed")
            return True
        
        if tool.requires_root and not self.is_root and self.system != 'windows':
            logger.warning(f"[!] {tool.name} requires root. Run with sudo.")
        
        # Try installation methods in order
        install_cmd = None
        
        # First try pip (most portable)
        if tool.install_pip and shutil.which('pip'):
            install_cmd = tool.install_pip
        
        # Then try cargo
        elif tool.install_cargo and shutil.which('cargo'):
            install_cmd = tool.install_cargo
        
        # Then try go
        elif tool.install_go and shutil.which('go'):
            install_cmd = tool.install_go
        
        # Then try system package manager
        elif self.pkg_manager == 'apt' and tool.install_apt:
            install_cmd = tool.install_apt
        elif self.pkg_manager == 'yum' and tool.install_yum:
            install_cmd = tool.install_yum
        elif self.pkg_manager == 'brew' and tool.install_brew:
            install_cmd = tool.install_brew
        elif self.pkg_manager == 'choco' and tool.install_choco:
            install_cmd = tool.install_choco
        
        if install_cmd:
            logger.info(f"Installing {tool.name}: {install_cmd}")
            try:
                result = subprocess.run(
                    install_cmd,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    logger.info(f"[OK] {tool.name} installed successfully")
                    if tool.notes:
                        logger.info(f"  Note: {tool.notes}")
                    return True
                else:
                    logger.error(f"[X] {tool.name} installation failed: {result.stderr}")
                    return False
            except Exception as e:
                logger.error(f"[X] {tool.name} installation error: {e}")
                return False
        else:
            logger.warning(f"[!] No install method for {tool.name} on {self.system}")
            if tool.install_manual:
                logger.info(f"  Manual install: {tool.install_manual}")
            return False
    
    def install_category(self, category: str) -> Dict[str, bool]:
        """Install all tools in a category"""
        results = {}
        for tool in TOOLS:
            if tool.category == category:
                results[tool.name] = self.install(tool)
        return results
    
    def install_all(self) -> Dict[str, bool]:
        """Install all tools"""
        results = {}
        for tool in TOOLS:
            results[tool.name] = self.install(tool)
        return results


def print_status(installer: ToolInstaller):
    """Print installation status"""
    status = installer.check_all()
    
    print("\n" + "=" * 60)
    print("Jarwis Network Security Tools Status")
    print("=" * 60)
    
    for category, desc in CATEGORIES.items():
        print(f"\n{desc}")
        print("-" * 40)
        
        for tool in TOOLS:
            if tool.category == category:
                installed = status[tool.name]
                mark = "[OK]" if installed else "[X]"
                color_start = "\033[92m" if installed else "\033[91m"
                color_end = "\033[0m"
                print(f"  {color_start}{mark}{color_end} {tool.name}: {tool.description}")
    
    installed_count = sum(1 for v in status.values() if v)
    total = len(status)
    print(f"\nTotal: {installed_count}/{total} tools installed")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Install Jarwis Network Security Tools"
    )
    parser.add_argument(
        '--all', '-a',
        action='store_true',
        help='Install all tools'
    )
    parser.add_argument(
        '--category', '-c',
        choices=list(CATEGORIES.keys()),
        help='Install tools by category'
    )
    parser.add_argument(
        '--tool', '-t',
        help='Install specific tool by name'
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check installed tools'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Force reinstall'
    )
    
    args = parser.parse_args()
    
    installer = ToolInstaller()
    
    if args.check or (not args.all and not args.category and not args.tool):
        print_status(installer)
        return
    
    if args.tool:
        tool = next((t for t in TOOLS if t.name == args.tool), None)
        if tool:
            installer.install(tool, force=args.force)
        else:
            logger.error(f"Unknown tool: {args.tool}")
            logger.info(f"Available: {', '.join(t.name for t in TOOLS)}")
    
    elif args.category:
        logger.info(f"Installing {CATEGORIES[args.category]}")
        results = installer.install_category(args.category)
        success = sum(1 for v in results.values() if v)
        logger.info(f"Installed {success}/{len(results)} tools")
    
    elif args.all:
        logger.info("Installing all tools...")
        results = installer.install_all()
        success = sum(1 for v in results.values() if v)
        logger.info(f"Installed {success}/{len(results)} tools")
        print_status(installer)


if __name__ == '__main__':
    main()
