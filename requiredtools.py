#!/usr/bin/env python3
"""
JARWIS AGI PEN TEST - Required Tools Installer
==============================================

This script installs all network security tools required for Jarwis.
Run with sudo/root on Linux for full installation.

Usage:
    python requiredtools.py --check          # Check installed tools
    python requiredtools.py --install        # Install all tools
    python requiredtools.py --install-python # Install Python packages only
    python requiredtools.py --install-system # Install system tools only
    python requiredtools.py --category port  # Install specific category

Categories: port, vuln, enum, ssl, exploit, traffic, all
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Category(Enum):
    PORT_SCANNERS = "port"
    VULN_SCANNERS = "vuln"
    ENUMERATION = "enum"
    SSL_SCANNERS = "ssl"
    EXPLOITATION = "exploit"
    TRAFFIC_ANALYSIS = "traffic"
    MOBILE = "mobile"
    WEB = "web"
    BROWSER = "browser"


@dataclass
class Tool:
    """Represents a security tool"""
    name: str
    description: str
    category: Category
    check_command: str  # Command to check if installed
    install_linux: str  # Linux install command
    install_macos: str  # macOS install command
    install_windows: str  # Windows install command
    python_package: Optional[str] = None  # If it's also a Python package
    go_package: Optional[str] = None  # If installable via go install
    requires_root: bool = True
    priority: int = 1  # 1 = essential, 2 = recommended, 3 = optional


# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

TOOLS: List[Tool] = [
    # -------------------------------------------------------------------------
    # PORT SCANNERS
    # -------------------------------------------------------------------------
    Tool(
        name="nmap",
        description="Network exploration and security auditing",
        category=Category.PORT_SCANNERS,
        check_command="nmap",
        install_linux="apt install -y nmap",
        install_macos="brew install nmap",
        install_windows="choco install nmap -y",
        priority=1,
    ),
    Tool(
        name="masscan",
        description="Ultra-fast TCP port scanner",
        category=Category.PORT_SCANNERS,
        check_command="masscan",
        install_linux="apt install -y masscan",
        install_macos="brew install masscan",
        install_windows="echo 'Download from https://github.com/robertdavidgraham/masscan'",
        priority=1,
    ),
    Tool(
        name="rustscan",
        description="Fast Rust-based port scanner",
        category=Category.PORT_SCANNERS,
        check_command="rustscan",
        install_linux="cargo install rustscan || wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb && dpkg -i rustscan_2.1.1_amd64.deb",
        install_macos="brew install rustscan",
        install_windows="cargo install rustscan",
        priority=2,
    ),
    
    # -------------------------------------------------------------------------
    # VULNERABILITY SCANNERS
    # -------------------------------------------------------------------------
    Tool(
        name="nuclei",
        description="Template-based vulnerability scanner",
        category=Category.VULN_SCANNERS,
        check_command="nuclei",
        install_linux="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        install_macos="brew install nuclei",
        install_windows="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        go_package="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        priority=1,
    ),
    Tool(
        name="openvas",
        description="Greenbone Vulnerability Scanner",
        category=Category.VULN_SCANNERS,
        check_command="gvm-cli",
        install_linux="apt install -y openvas gvm || docker run -d -p 443:443 --name openvas greenbone/openvas",
        install_macos="docker run -d -p 443:443 --name openvas greenbone/openvas",
        install_windows="docker run -d -p 443:443 --name openvas greenbone/openvas",
        python_package="gvm-tools",
        priority=3,
    ),
    Tool(
        name="nikto",
        description="Web server scanner",
        category=Category.VULN_SCANNERS,
        check_command="nikto",
        install_linux="apt install -y nikto",
        install_macos="brew install nikto",
        install_windows="echo 'Download from https://github.com/sullo/nikto'",
        priority=2,
    ),
    
    # -------------------------------------------------------------------------
    # ENUMERATION TOOLS
    # -------------------------------------------------------------------------
    Tool(
        name="netdiscover",
        description="ARP-based network discovery",
        category=Category.ENUMERATION,
        check_command="netdiscover",
        install_linux="apt install -y netdiscover",
        install_macos="brew install netdiscover",
        install_windows="echo 'Linux only - use WSL'",
        priority=1,
    ),
    Tool(
        name="arp-scan",
        description="Fast ARP host discovery",
        category=Category.ENUMERATION,
        check_command="arp-scan",
        install_linux="apt install -y arp-scan",
        install_macos="brew install arp-scan",
        install_windows="echo 'Linux only - use WSL'",
        priority=1,
    ),
    Tool(
        name="snmpwalk",
        description="SNMP enumeration tool",
        category=Category.ENUMERATION,
        check_command="snmpwalk",
        install_linux="apt install -y snmp snmp-mibs-downloader",
        install_macos="brew install net-snmp",
        install_windows="choco install net-snmp -y",
        priority=1,
    ),
    Tool(
        name="dnsrecon",
        description="DNS reconnaissance tool",
        category=Category.ENUMERATION,
        check_command="dnsrecon",
        install_linux="apt install -y dnsrecon || pip3 install dnsrecon",
        install_macos="pip3 install dnsrecon",
        install_windows="pip install dnsrecon",
        python_package="dnsrecon",
        priority=1,
    ),
    Tool(
        name="enum4linux",
        description="SMB/Samba enumeration",
        category=Category.ENUMERATION,
        check_command="enum4linux",
        install_linux="apt install -y enum4linux",
        install_macos="echo 'Linux only'",
        install_windows="echo 'Linux only - use WSL'",
        priority=2,
    ),
    Tool(
        name="nbtscan",
        description="NetBIOS scanner",
        category=Category.ENUMERATION,
        check_command="nbtscan",
        install_linux="apt install -y nbtscan",
        install_macos="brew install nbtscan",
        install_windows="echo 'Linux only - use WSL'",
        priority=2,
    ),
    
    # -------------------------------------------------------------------------
    # SSL/TLS SCANNERS
    # -------------------------------------------------------------------------
    Tool(
        name="sslscan",
        description="SSL/TLS configuration scanner",
        category=Category.SSL_SCANNERS,
        check_command="sslscan",
        install_linux="apt install -y sslscan",
        install_macos="brew install sslscan",
        install_windows="choco install sslscan -y",
        priority=1,
    ),
    Tool(
        name="testssl.sh",
        description="Comprehensive TLS testing script",
        category=Category.SSL_SCANNERS,
        check_command="testssl.sh",
        install_linux="git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh",
        install_macos="brew install testssl",
        install_windows="git clone https://github.com/drwetter/testssl.sh.git",
        priority=1,
    ),
    Tool(
        name="sslyze",
        description="Python-native SSL/TLS analyzer",
        category=Category.SSL_SCANNERS,
        check_command="sslyze",
        install_linux="pip3 install sslyze",
        install_macos="pip3 install sslyze",
        install_windows="pip install sslyze",
        python_package="sslyze",
        requires_root=False,
        priority=1,
    ),
    
    # -------------------------------------------------------------------------
    # EXPLOITATION TOOLS
    # -------------------------------------------------------------------------
    Tool(
        name="crackmapexec",
        description="Swiss army knife for AD/networks",
        category=Category.EXPLOITATION,
        check_command="crackmapexec",
        install_linux="pip3 install crackmapexec || pipx install crackmapexec",
        install_macos="pip3 install crackmapexec",
        install_windows="pip install crackmapexec",
        python_package="crackmapexec",
        priority=1,
    ),
    Tool(
        name="netexec",
        description="CrackMapExec successor",
        category=Category.EXPLOITATION,
        check_command="netexec",
        install_linux="pip3 install netexec || pipx install netexec",
        install_macos="pip3 install netexec",
        install_windows="pip install netexec",
        priority=1,
    ),
    Tool(
        name="impacket",
        description="Windows protocol implementation",
        category=Category.EXPLOITATION,
        check_command="impacket-secretsdump",
        install_linux="pip3 install impacket",
        install_macos="pip3 install impacket",
        install_windows="pip install impacket",
        python_package="impacket",
        priority=1,
    ),
    Tool(
        name="hydra",
        description="Network login cracker",
        category=Category.EXPLOITATION,
        check_command="hydra",
        install_linux="apt install -y hydra",
        install_macos="brew install hydra",
        install_windows="echo 'Linux only - use WSL'",
        priority=2,
    ),
    Tool(
        name="metasploit",
        description="Exploitation framework",
        category=Category.EXPLOITATION,
        check_command="msfconsole",
        install_linux="curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall",
        install_macos="brew install metasploit",
        install_windows="echo 'Download installer from https://www.metasploit.com/download'",
        priority=3,
    ),
    
    # -------------------------------------------------------------------------
    # TRAFFIC ANALYSIS
    # -------------------------------------------------------------------------
    Tool(
        name="zeek",
        description="Network traffic analysis framework",
        category=Category.TRAFFIC_ANALYSIS,
        check_command="zeek",
        install_linux="apt install -y zeek || echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/zeek.list && apt update && apt install -y zeek",
        install_macos="brew install zeek",
        install_windows="echo 'Linux only - use WSL'",
        priority=2,
    ),
    Tool(
        name="suricata",
        description="Network IDS/IPS",
        category=Category.TRAFFIC_ANALYSIS,
        check_command="suricata",
        install_linux="apt install -y suricata",
        install_macos="brew install suricata",
        install_windows="echo 'Linux only - use WSL'",
        priority=2,
    ),
    Tool(
        name="snort",
        description="Network IDS",
        category=Category.TRAFFIC_ANALYSIS,
        check_command="snort",
        install_linux="apt install -y snort",
        install_macos="brew install snort",
        install_windows="echo 'Download from https://www.snort.org/downloads'",
        priority=3,
    ),
    Tool(
        name="tshark",
        description="Wireshark CLI",
        category=Category.TRAFFIC_ANALYSIS,
        check_command="tshark",
        install_linux="apt install -y tshark wireshark-common",
        install_macos="brew install wireshark",
        install_windows="choco install wireshark -y",
        priority=1,
    ),
    Tool(
        name="tcpdump",
        description="Packet analyzer",
        category=Category.TRAFFIC_ANALYSIS,
        check_command="tcpdump",
        install_linux="apt install -y tcpdump",
        install_macos="brew install tcpdump",
        install_windows="echo 'Use Wireshark on Windows'",
        priority=1,
    ),
    
    # -------------------------------------------------------------------------
    # MOBILE SECURITY TOOLS
    # -------------------------------------------------------------------------
    Tool(
        name="adb",
        description="Android Debug Bridge",
        category=Category.MOBILE,
        check_command="adb",
        install_linux="apt install -y android-tools-adb || sdkmanager platform-tools",
        install_macos="brew install android-platform-tools",
        install_windows="choco install adb -y",
        priority=1,
    ),
    Tool(
        name="frida",
        description="Dynamic instrumentation toolkit",
        category=Category.MOBILE,
        check_command="frida",
        install_linux="pip3 install frida-tools",
        install_macos="pip3 install frida-tools",
        install_windows="pip install frida-tools",
        python_package="frida",
        requires_root=False,
        priority=1,
    ),
    Tool(
        name="objection",
        description="Mobile exploration toolkit",
        category=Category.MOBILE,
        check_command="objection",
        install_linux="pip3 install objection",
        install_macos="pip3 install objection",
        install_windows="pip install objection",
        python_package="objection",
        requires_root=False,
        priority=1,
    ),
    Tool(
        name="apktool",
        description="APK reverse engineering",
        category=Category.MOBILE,
        check_command="apktool",
        install_linux="apt install -y apktool",
        install_macos="brew install apktool",
        install_windows="choco install apktool -y",
        priority=1,
    ),
    Tool(
        name="jadx",
        description="Dex to Java decompiler",
        category=Category.MOBILE,
        check_command="jadx",
        install_linux="wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O /tmp/jadx.zip && unzip /tmp/jadx.zip -d /opt/jadx && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx",
        install_macos="brew install jadx",
        install_windows="choco install jadx -y",
        priority=2,
    ),
    Tool(
        name="emulator",
        description="Android Emulator",
        category=Category.MOBILE,
        check_command="emulator",
        install_linux="sdkmanager emulator",
        install_macos="sdkmanager emulator",
        install_windows="sdkmanager emulator",
        priority=2,
    ),
    
    # -------------------------------------------------------------------------
    # WEB SECURITY TOOLS
    # -------------------------------------------------------------------------
    Tool(
        name="mitmproxy",
        description="HTTPS interception proxy",
        category=Category.WEB,
        check_command="mitmproxy",
        install_linux="pip3 install mitmproxy",
        install_macos="brew install mitmproxy",
        install_windows="pip install mitmproxy",
        python_package="mitmproxy",
        requires_root=False,
        priority=1,
    ),
    Tool(
        name="nikto",
        description="Web server scanner",
        category=Category.WEB,
        check_command="nikto",
        install_linux="apt install -y nikto",
        install_macos="brew install nikto",
        install_windows="echo 'Linux only - use WSL'",
        priority=1,
    ),
    Tool(
        name="sqlmap",
        description="SQL injection tool",
        category=Category.WEB,
        check_command="sqlmap",
        install_linux="apt install -y sqlmap",
        install_macos="brew install sqlmap",
        install_windows="pip install sqlmap",
        priority=1,
    ),
    Tool(
        name="gobuster",
        description="Directory/DNS brute-forcer",
        category=Category.WEB,
        check_command="gobuster",
        install_linux="apt install -y gobuster",
        install_macos="brew install gobuster",
        install_windows="go install github.com/OJ/gobuster/v3@latest",
        priority=1,
    ),
    Tool(
        name="ffuf",
        description="Fast web fuzzer",
        category=Category.WEB,
        check_command="ffuf",
        install_linux="go install github.com/ffuf/ffuf/v2@latest",
        install_macos="brew install ffuf",
        install_windows="go install github.com/ffuf/ffuf/v2@latest",
        go_package="github.com/ffuf/ffuf/v2@latest",
        priority=1,
    ),
    Tool(
        name="zap",
        description="OWASP ZAP proxy",
        category=Category.WEB,
        check_command="zap",
        install_linux="wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz -O /tmp/zap.tar.gz && tar -xzf /tmp/zap.tar.gz -C /opt/ && ln -sf /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zap",
        install_macos="brew install owasp-zap",
        install_windows="choco install owasp-zap -y",
        priority=2,
    ),
    Tool(
        name="wpscan",
        description="WordPress vulnerability scanner",
        category=Category.WEB,
        check_command="wpscan",
        install_linux="gem install wpscan",
        install_macos="brew install wpscan",
        install_windows="gem install wpscan",
        priority=2,
    ),
    
    # -------------------------------------------------------------------------
    # BROWSER AUTOMATION
    # -------------------------------------------------------------------------
    Tool(
        name="chromium-browser",
        description="Chromium browser",
        category=Category.BROWSER,
        check_command="chromium-browser",
        install_linux="apt install -y chromium-browser",
        install_macos="brew install chromium",
        install_windows="choco install chromium -y",
        priority=1,
    ),
    Tool(
        name="firefox",
        description="Firefox browser",
        category=Category.BROWSER,
        check_command="firefox",
        install_linux="apt install -y firefox",
        install_macos="brew install firefox",
        install_windows="choco install firefox -y",
        priority=2,
    ),
    Tool(
        name="playwright",
        description="Browser automation",
        category=Category.BROWSER,
        check_command="playwright",
        install_linux="pip3 install playwright && playwright install",
        install_macos="pip3 install playwright && playwright install",
        install_windows="pip install playwright && playwright install",
        python_package="playwright",
        requires_root=False,
        priority=1,
    ),
]

# ============================================================================
# PYTHON PACKAGES (pip install)
# ============================================================================

PYTHON_PACKAGES = [
    # Core scanning
    "python-nmap",       # Nmap Python wrapper
    "sslyze",            # SSL/TLS analysis
    "impacket",          # Windows protocols
    
    # DNS/Network
    "dnspython",         # DNS toolkit
    "dnsrecon",          # DNS reconnaissance
    "pysnmp",            # SNMP library
    
    # Packet manipulation
    "scapy",             # Packet crafting
    
    # OpenVAS integration
    "gvm-tools",         # Greenbone VM tools
    
    # Async HTTP
    "aiohttp",           # Async HTTP client
    "httpx",             # Modern HTTP client
    
    # Parsing
    "lxml",              # XML parsing
    "beautifulsoup4",    # HTML parsing
    
    # Mobile Security
    "frida-tools",       # Frida instrumentation
    "objection",         # Mobile exploration
    "androguard",        # Android analysis
    
    # Web Proxying
    "mitmproxy",         # HTTPS interception proxy
    
    # Browser Automation
    "playwright",        # Browser automation
    "selenium",          # Browser automation (legacy)
    
    # Web Framework
    "fastapi",           # API framework
    "uvicorn",           # ASGI server
    "flask",             # Web framework
    "flask-cors",        # CORS support
    
    # Database
    "asyncpg",           # PostgreSQL async driver
    "sqlalchemy",        # ORM
    "alembic",           # Database migrations
    "psycopg2-binary",   # PostgreSQL driver
    
    # Security
    "pyjwt",             # JWT handling
    "passlib",           # Password hashing
    "bcrypt",            # Password hashing
    "cryptography",      # Crypto primitives
    "pyotp",             # OTP generation
    
    # AI/LLM
    "openai",            # OpenAI API
    "langchain",         # LLM framework
    
    # Utilities
    "rich",              # Console formatting
    "pyyaml",            # YAML parsing
    "python-dotenv",     # Environment variables
    "pydantic",          # Data validation
    "requests",          # HTTP client
    "aiofiles",          # Async file I/O
]

# ============================================================================
# GO PACKAGES (go install)
# ============================================================================

GO_PACKAGES = [
    # ProjectDiscovery tools
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    
    # Web tools
    "github.com/tomnomnom/assetfinder@latest",
    "github.com/ffuf/ffuf/v2@latest",
    "github.com/OJ/gobuster/v3@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_os() -> str:
    """Get current OS type"""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "windows":
        return "windows"
    return "linux"


def is_root() -> bool:
    """Check if running as root/admin"""
    if get_os() == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return os.geteuid() == 0


def run_command(cmd: str, check: bool = False) -> Tuple[bool, str]:
    """Run a shell command and return (success, output)"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def is_tool_installed(tool: Tool) -> bool:
    """Check if a tool is installed"""
    return shutil.which(tool.check_command) is not None


def get_install_command(tool: Tool) -> str:
    """Get the install command for current OS"""
    os_type = get_os()
    if os_type == "linux":
        return tool.install_linux
    elif os_type == "macos":
        return tool.install_macos
    return tool.install_windows


# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

def check_tools() -> Dict[Category, List[Tuple[Tool, bool]]]:
    """Check all tools and return status by category"""
    results = {cat: [] for cat in Category}
    
    for tool in TOOLS:
        installed = is_tool_installed(tool)
        results[tool.category].append((tool, installed))
    
    return results


def print_status():
    """Print tool installation status"""
    results = check_tools()
    
    print("=" * 60)
    print("JARWIS NETWORK SECURITY TOOLS STATUS")
    print(f"Operating System: {get_os().upper()}")
    print(f"Running as root: {is_root()}")
    print("=" * 60)
    
    total = 0
    installed = 0
    
    category_names = {
        Category.PORT_SCANNERS: "Port Scanners",
        Category.VULN_SCANNERS: "Vulnerability Scanners",
        Category.ENUMERATION: "Enumeration Tools",
        Category.SSL_SCANNERS: "SSL/TLS Scanners",
        Category.EXPLOITATION: "Exploitation Tools",
        Category.TRAFFIC_ANALYSIS: "Traffic Analysis",
    }
    
    for category, tools in results.items():
        print(f"\n{category_names.get(category, category.value)}")
        print("-" * 40)
        
        for tool, is_installed in tools:
            total += 1
            status = "âœ..." if is_installed else "âŒ"
            priority = "â­" * tool.priority
            if is_installed:
                installed += 1
            print(f"  {status} {tool.name}: {tool.description} {priority}")
    
    print("\n" + "=" * 60)
    print(f"TOTAL: {installed}/{total} tools installed")
    print("=" * 60)
    
    # Check Python packages
    print("\nPython Packages:")
    print("-" * 40)
    
    # Map pip package names to import names
    pkg_import_map = {
        "python-nmap": "nmap",
        "dnspython": "dns",
        "gvm-tools": "gvm",
        "beautifulsoup4": "bs4",
        "dnsrecon": "dnsrecon",
        "sslyze": "sslyze",
        "impacket": "impacket",
        "pysnmp": "pysnmp",
        "scapy": "scapy",
        "aiohttp": "aiohttp",
        "httpx": "httpx",
        "lxml": "lxml",
    }
    
    for pkg in PYTHON_PACKAGES:
        import_name = pkg_import_map.get(pkg, pkg.replace("-", "_").split("[")[0])
        try:
            __import__(import_name)
            print(f"  âœ... {pkg}")
        except ImportError:
            print(f"  âŒ {pkg}")
    
    return installed, total


def install_python_packages():
    """Install Python packages"""
    print("\nInstalling Python packages...")
    print("-" * 40)
    
    for pkg in PYTHON_PACKAGES:
        print(f"  Installing {pkg}...")
        success, output = run_command(f"{sys.executable} -m pip install {pkg} --quiet")
        status = "âœ..." if success else "âŒ"
        print(f"  {status} {pkg}")


def install_go_packages():
    """Install Go packages"""
    if not shutil.which("go"):
        print("âŒ Go is not installed. Skipping Go packages.")
        print("   Install Go first: https://golang.org/dl/")
        return
    
    print("\n¹ Installing Go packages...")
    print("-" * 40)
    
    for pkg in GO_PACKAGES:
        name = pkg.split("/")[-1].split("@")[0]
        print(f"  Installing {name}...")
        success, output = run_command(f"go install -v {pkg}")
        status = "âœ..." if success else "âŒ"
        print(f"  {status} {name}")


def install_system_tools(category: Optional[Category] = None, priority: int = 3):
    """Install system tools"""
    os_type = get_os()
    
    if os_type == "linux" and not is_root():
        print("âš ï¸  Warning: Not running as root. Some installations may fail.")
        print("   Run with: sudo python requiredtools.py --install-system")
    
    print(f"\nInstalling system tools for {os_type.upper()}...")
    print("-" * 40)
    
    # Update package manager first on Linux
    if os_type == "linux":
        print("  Updating package manager...")
        run_command("apt update")
    
    tools_to_install = TOOLS
    if category:
        tools_to_install = [t for t in TOOLS if t.category == category]
    
    tools_to_install = [t for t in tools_to_install if t.priority <= priority]
    
    for tool in tools_to_install:
        if is_tool_installed(tool):
            print(f"  â­ï¸  {tool.name} already installed")
            continue
        
        cmd = get_install_command(tool)
        print(f"  Installing {tool.name}...")
        
        # Add sudo for Linux if needed
        if os_type == "linux" and tool.requires_root and not is_root():
            cmd = f"sudo {cmd}"
        
        success, output = run_command(cmd)
        status = "âœ..." if success else "âŒ"
        print(f"  {status} {tool.name}")
        
        if not success and "echo" not in cmd:
            print(f"      Error: {output[:100]}...")


def install_all():
    """Install everything"""
    print("\n" + "=" * 60)
    print("JARWIS FULL TOOL INSTALLATION")
    print("=" * 60)
    
    install_python_packages()
    install_go_packages()
    install_system_tools()
    
    print("\n" + "=" * 60)
    print("Installation complete! Run --check to verify.")
    print("=" * 60)


def generate_install_script() -> str:
    """Generate a bash install script for Linux"""
    script = """#!/bin/bash
# ============================================================================
# JARWIS AGI PEN TEST - Linux Tool Installation Script
# Generated by requiredtools.py
# ============================================================================
# Usage: chmod +x install_jarwis_tools.sh && sudo ./install_jarwis_tools.sh
# ============================================================================

set -e

echo "======================================"
echo "Jarwis Network Security Tools Installer"
echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

# Update system
echo "[*] Updating package manager..."
apt update && apt upgrade -y

# Install prerequisites
echo "[*] Installing prerequisites..."
apt install -y git curl wget python3 python3-pip golang-go cargo

# ============================================================================
# SYSTEM TOOLS
# ============================================================================

echo ""
echo "[*] Installing Port Scanners..."
apt install -y nmap masscan

echo "[*] Installing RustScan..."
wget -q https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb -O /tmp/rustscan.deb
dpkg -i /tmp/rustscan.deb || apt install -f -y

echo ""
echo "[*] Installing Enumeration Tools..."
apt install -y netdiscover arp-scan snmp snmp-mibs-downloader nbtscan enum4linux

echo ""
echo "[*] Installing SSL/TLS Scanners..."
apt install -y sslscan
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl 2>/dev/null || true
ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

echo ""
echo "[*] Installing Traffic Analysis Tools..."
apt install -y tshark tcpdump wireshark-common
apt install -y suricata || echo "Suricata install failed, continuing..."
apt install -y zeek || echo "Zeek install failed, continuing..."

echo ""
echo "[*] Installing Exploitation Tools..."
apt install -y hydra
# Metasploit (optional - large download)
# curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
# chmod 755 /tmp/msfinstall && /tmp/msfinstall

# ============================================================================
# PYTHON PACKAGES
# ============================================================================

echo ""
echo "[*] Installing Python packages..."
pip3 install --upgrade pip
pip3 install python-nmap sslyze impacket dnspython dnsrecon pysnmp scapy
pip3 install gvm-tools aiohttp httpx lxml beautifulsoup4
pip3 install crackmapexec || echo "CrackMapExec install failed, trying pipx..."
pip3 install pipx && pipx install crackmapexec || true

# ============================================================================
# GO PACKAGES
# ============================================================================

echo ""
echo "[*] Installing Go packages..."
export GOPATH=/opt/go
export PATH=$PATH:/opt/go/bin

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/ffuf/ffuf@latest

# Add Go bin to PATH permanently
echo 'export PATH=$PATH:/opt/go/bin' >> /etc/profile.d/go.sh

# ============================================================================
# VERIFICATION
# ============================================================================

echo ""
echo "======================================"
echo "Installation Complete!"
echo "======================================"
echo ""
echo "Installed tools:"
for tool in nmap masscan rustscan nuclei netdiscover arp-scan snmpwalk sslscan testssl.sh tshark tcpdump suricata hydra; do
    if command -v $tool &> /dev/null; then
        echo "  âœ... $tool"
    else
        echo "  âŒ $tool"
    fi
done

echo ""
echo "Python packages:"
python3 -c "import nmap; print('  âœ... python-nmap')" 2>/dev/null || echo "  âŒ python-nmap"
python3 -c "import sslyze; print('  âœ... sslyze')" 2>/dev/null || echo "  âŒ sslyze"
python3 -c "import impacket; print('  âœ... impacket')" 2>/dev/null || echo "  âŒ impacket"

echo ""
echo "Restart your shell or run: source /etc/profile.d/go.sh"
"""
    return script


def main():
    parser = argparse.ArgumentParser(
        description="Jarwis Network Security Tools Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python requiredtools.py --check              Check installed tools
  python requiredtools.py --install            Install everything
  python requiredtools.py --install-python     Install Python packages only
  python requiredtools.py --install-system     Install system tools only
  python requiredtools.py --category port      Install port scanners only
  python requiredtools.py --generate-script    Generate Linux install script
        """
    )
    
    parser.add_argument("--check", action="store_true", help="Check installed tools")
    parser.add_argument("--install", action="store_true", help="Install all tools")
    parser.add_argument("--install-python", action="store_true", help="Install Python packages")
    parser.add_argument("--install-system", action="store_true", help="Install system tools")
    parser.add_argument("--install-go", action="store_true", help="Install Go packages")
    parser.add_argument("--category", choices=["port", "vuln", "enum", "ssl", "exploit", "traffic"],
                        help="Install specific category")
    parser.add_argument("--priority", type=int, default=2, choices=[1, 2, 3],
                        help="Install tools up to priority level (1=essential, 2=recommended, 3=all)")
    parser.add_argument("--generate-script", action="store_true", 
                        help="Generate Linux install bash script")
    
    args = parser.parse_args()
    
    if args.generate_script:
        script = generate_install_script()
        script_path = "install_jarwis_tools.sh"
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        print(f"âœ... Generated {script_path}")
        print(f"   Copy to Linux server and run: chmod +x {script_path} && sudo ./{script_path}")
        return
    
    if args.check:
        print_status()
        return
    
    if args.install_python:
        install_python_packages()
        return
    
    if args.install_go:
        install_go_packages()
        return
    
    if args.install_system:
        category = None
        if args.category:
            category = Category(args.category)
        install_system_tools(category=category, priority=args.priority)
        return
    
    if args.category:
        category = Category(args.category)
        install_system_tools(category=category, priority=args.priority)
        return
    
    if args.install:
        install_all()
        return
    
    # Default: show status
    print_status()
    print("\nRun with --help for installation options")


if __name__ == "__main__":
    main()
