"""
Jarwis AGI Pen Test - Network Security Scanning Module
Central Network Attack Module - Aggregates ALL network security scanners

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

from typing import List, Any
import logging

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

logger = logging.getLogger(__name__)


class NetworkAttacks:
    """
    Aggregates ALL network security scanners.
    
    Orchestrates network security testing including:
    - Port scanning and service detection
    - Vulnerability scanning
    - SSL/TLS configuration auditing
    - Credential testing
    - Traffic analysis
    
    Usage:
        network = NetworkAttacks(config, context)
        findings = await network.run()
    """
    
    def __init__(self, config: dict, context):
        """
        Initialize network attack module.
        
        Args:
            config: Scan configuration with target IPs, ports, etc.
            context: NetworkScanContext with discovered hosts
        """
        self.config = config
        self.context = context
        self.target = config.get('target', '')
        
        # Initialize scanners based on config
        self.scanners = self._init_scanners()
    
    def _init_scanners(self) -> List[Any]:
        """Initialize network scanners based on configuration"""
        scanners = []
        network_config = self.config.get('network', {})
        
        # Port Scanning (always enabled)
        if network_config.get('port_scanning', {}).get('enabled', True):
            scanners.append(PortScanner(self.config, self.context))
        
        # Service Detection
        if network_config.get('service_detection', {}).get('enabled', True):
            scanners.append(ServiceDetector(self.config, self.context))
        
        # Vulnerability Scanning
        if network_config.get('vuln_scanning', {}).get('enabled', True):
            scanners.append(VulnerabilityScanner(self.config, self.context))
        
        # SSL/TLS Auditing
        if network_config.get('ssl_audit', {}).get('enabled', True):
            try:
                scanners.append(SSLScanScanner(self.config, self.context))
            except Exception as e:
                logger.warning(f"SSL scanner unavailable: {e}")
        
        # Credential Testing (if enabled - requires authentication)
        if network_config.get('credential_testing', {}).get('enabled', False):
            scanners.append(CredentialScanner(self.config, self.context))
        
        return scanners
    
    async def run(self) -> List[Any]:
        """
        Run all network security scanners.
        
        Returns:
            List of all network security findings
        """
        results = []
        
        logger.info(f"Starting network security scan for {self.target}...")
        logger.info(f"Loaded {len(self.scanners)} network scanners")
        
        for scanner in self.scanners:
            scanner_name = scanner.__class__.__name__
            logger.info(f"Running {scanner_name}...")
            
            try:
                if hasattr(scanner, 'scan'):
                    scanner_results = await scanner.scan()
                elif hasattr(scanner, 'run'):
                    scanner_results = await scanner.run()
                else:
                    logger.warning(f"{scanner_name} has no scan/run method")
                    continue
                
                if scanner_results:
                    results.extend(scanner_results)
                    logger.info(f"{scanner_name}: {len(scanner_results)} findings")
                    
            except Exception as e:
                logger.error(f"{scanner_name} failed: {e}")
                continue
        
        logger.info(f"Network scan complete: {len(results)} total findings")
        return results
    
    async def run_discovery(self) -> List[Any]:
        """Run only host discovery phase"""
        scanner = PortScanner(self.config, self.context)
        return await scanner.discover_hosts()
    
    async def run_port_scan(self) -> List[Any]:
        """Run only port scanning phase"""
        scanner = PortScanner(self.config, self.context)
        return await scanner.scan()
    
    async def run_vuln_scan(self) -> List[Any]:
        """Run only vulnerability scanning phase"""
        scanner = VulnerabilityScanner(self.config, self.context)
        return await scanner.scan()
    
    async def run_full_orchestrated(self) -> List[Any]:
        """Run full orchestrated scan with all phases"""
        orchestrator = NetworkOrchestrator(self.config, self.context)
        return await orchestrator.run()
    
    def get_scanner_count(self) -> int:
        """Get count of available scanners"""
        return len(self.scanners)
    
    def get_available_attacks(self) -> List[str]:
        """Get list of available attack categories"""
        return [
            "Port Scanning (TCP/UDP)",
            "Service Version Detection",
            "OS Fingerprinting",
            "Vulnerability Scanning",
            "SSL/TLS Configuration Audit",
            "Certificate Validation",
            "SNMP Enumeration",
            "DNS Reconnaissance",
            "SMB Enumeration",
            "Default Credential Testing",
            "Banner Grabbing",
            "Network Traffic Analysis",
        ]

__all__ = [
    # Main aggregator
    'NetworkAttacks',
    
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
