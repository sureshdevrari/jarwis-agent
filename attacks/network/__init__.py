"""
Jarwis AGI Pen Test - Network Security Scanning Module

Comprehensive network vulnerability assessment with enterprise-grade tools:

Tools Integrated:
- Port Scanning: Nmap, Masscan, RustScan
- Vulnerability: Nuclei, OpenVAS, Vulners
- Enumeration: Netdiscover, SNMPwalk, DNSRecon, ARP-scan
- SSL/TLS: SSLScan, testssl.sh, SSLyze
- Exploitation: CrackMapExec, Impacket, Metasploit
- Traffic Analysis: Zeek, Suricata, Snort, TShark

Scan Phases:
1. DISCOVERY - Find live hosts
2. PORT_SCAN - Find open ports  
3. SERVICE_ENUM - Identify services
4. VULN_SCAN - Find vulnerabilities
5. SSL_AUDIT - TLS configuration
6. CREDENTIAL - Authenticated testing
7. EXPLOITATION - Verification
8. TRAFFIC_ANALYSIS - Passive analysis

OWASP/CWE Mappings:
- CWE-16: Configuration
- CWE-200: Information Exposure
- CWE-284: Improper Access Control
- CWE-311: Missing Encryption
- CWE-326: Inadequate Encryption Strength
"""

# Base components
from .base import (
    ScanPhase,
    ScanResult,
    Finding,
    Severity,
    ScannerRegistry,
    BaseScanner,
    ToolInstaller,
)

# Original scanners (legacy)
from .network_scanner import NetworkSecurityScanner
from .port_scanner import PortScanner
from .service_detector import ServiceDetector
from .vuln_scanner import VulnerabilityScanner
from .credential_scanner import CredentialScanner

# Orchestrator
from .orchestrator import (
    NetworkOrchestrator,
    ScanProfile,
    ScanState,
    PhaseConfig,
)

# Individual scanners
from .scanners import (
    # Port
    NmapScanner,
    MasscanScanner,
    RustScanScanner,
    # Vuln
    NucleiScanner,
    OpenVASScanner,
    VulnersNmapScanner,
    # Enum
    NetdiscoverScanner,
    SNMPScanner,
    DNSReconScanner,
    ARPScanScanner,
    # SSL
    SSLScanScanner,
    TestSSLScanner,
    SSLyzeScanner,
    # Exploit
    CrackMapExecScanner,
    ImpacketScanner,
    MetasploitScanner,
    # Traffic
    ZeekScanner,
    SuricataScanner,
    SnortScanner,
    TSharkScanner,
    # Categories
    PORT_SCANNERS,
    VULN_SCANNERS,
    ENUM_SCANNERS,
    SSL_SCANNERS,
    EXPLOIT_SCANNERS,
    TRAFFIC_SCANNERS,
    ALL_SCANNERS,
)

__all__ = [
    # Base
    'ScanPhase',
    'ScanResult',
    'Finding',
    'Severity',
    'ScannerRegistry',
    'BaseScanner',
    'ToolInstaller',
    # Orchestrator
    'NetworkOrchestrator',
    'ScanProfile',
    'ScanState',
    'PhaseConfig',
    # Legacy
    'NetworkSecurityScanner',
    'PortScanner',
    'ServiceDetector', 
    'VulnerabilityScanner',
    'CredentialScanner',
    # Port Scanners
    'NmapScanner',
    'MasscanScanner',
    'RustScanScanner',
    # Vuln Scanners
    'NucleiScanner',
    'OpenVASScanner',
    'VulnersNmapScanner',
    # Enum Scanners
    'NetdiscoverScanner',
    'SNMPScanner',
    'DNSReconScanner',
    'ARPScanScanner',
    # SSL Scanners
    'SSLScanScanner',
    'TestSSLScanner',
    'SSLyzeScanner',
    # Exploit Scanners
    'CrackMapExecScanner',
    'ImpacketScanner',
    'MetasploitScanner',
    # Traffic Scanners
    'ZeekScanner',
    'SuricataScanner',
    'SnortScanner',
    'TSharkScanner',
    # Categories
    'PORT_SCANNERS',
    'VULN_SCANNERS',
    'ENUM_SCANNERS',
    'SSL_SCANNERS',
    'EXPLOIT_SCANNERS',
    'TRAFFIC_SCANNERS',
    'ALL_SCANNERS',
]
