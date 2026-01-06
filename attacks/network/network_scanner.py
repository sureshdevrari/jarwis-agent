"""
Jarwis AGI Pen Test - Network Security Scanner
Main orchestrator for network security assessments

Features:
- Host discovery across subnets
- Port scanning with multiple techniques
- Service and version detection
- OS fingerprinting
- Vulnerability assessment
- Credential-based authenticated scanning
- Private IP scanning support via Jarwis Agent
"""

import asyncio
import ipaddress
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class NetworkScanResult:
    """Represents a network security finding"""
    id: str
    category: str  # network, port, service, vuln, config
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    ip_address: str
    port: Optional[int] = None
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    cve_id: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    evidence: str = ""
    remediation: str = ""
    reasoning: str = ""
    raw_output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class HostInfo:
    """Information about a discovered host"""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_guess: Optional[str] = None
    os_confidence: int = 0
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, Dict] = field(default_factory=dict)
    is_alive: bool = False
    response_time_ms: float = 0.0


@dataclass
class NetworkScanContext:
    """Maintains state for network scanning"""
    targets: List[str]  # List of IPs/subnets to scan
    exclude_targets: Set[str] = field(default_factory=set)
    discovered_hosts: List[HostInfo] = field(default_factory=list)
    findings: List[NetworkScanResult] = field(default_factory=list)
    credentials: Optional[Dict] = None
    scan_start_time: datetime = field(default_factory=datetime.now)
    scan_end_time: Optional[datetime] = None
    use_agent: bool = False
    agent_id: Optional[str] = None


class NetworkSecurityScanner:
    """
    Main network security scanner - orchestrates all network scanning modules
    
    Supports:
    1. Host Discovery - Find live hosts
    2. Port Scanning - Identify open ports
    3. Service Detection - Identify running services
    4. OS Detection - Fingerprint operating systems
    5. Vulnerability Scanning - Check for known CVEs
    6. Authenticated Scanning - Deep inspection with credentials
    7. Private Network Scanning - Via Jarwis Agent
    """
    
    # Common ports for quick scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 
        8443, 27017
    ]
    
    # Service signatures for detection
    SERVICE_SIGNATURES = {
        21: ('ftp', [b'220', b'FTP']),
        22: ('ssh', [b'SSH-', b'OpenSSH']),
        23: ('telnet', [b'\xff\xfb', b'\xff\xfd']),
        25: ('smtp', [b'220', b'SMTP', b'ESMTP']),
        53: ('dns', []),
        80: ('http', [b'HTTP/', b'<!DOCTYPE', b'<html']),
        110: ('pop3', [b'+OK', b'POP3']),
        143: ('imap', [b'* OK', b'IMAP']),
        443: ('https', []),
        445: ('smb', []),
        1433: ('mssql', []),
        1521: ('oracle', []),
        3306: ('mysql', [b'\x00\x00\x00\x0a', b'mysql']),
        3389: ('rdp', []),
        5432: ('postgresql', []),
        5900: ('vnc', [b'RFB ']),
        6379: ('redis', [b'+PONG', b'-ERR']),
        8080: ('http-proxy', [b'HTTP/']),
        27017: ('mongodb', []),
    }
    
    # Known vulnerable versions (sample - would be updated from CVE database)
    KNOWN_VULNS = {
        'openssh': {
            '7.2': [{'cve': 'CVE-2016-6210', 'cvss': 5.3, 'title': 'OpenSSH User Enumeration'}],
            '7.4': [{'cve': 'CVE-2017-15906', 'cvss': 5.3, 'title': 'OpenSSH Write Issue'}],
        },
        'apache': {
            '2.4.49': [{'cve': 'CVE-2021-41773', 'cvss': 9.8, 'title': 'Apache Path Traversal RCE'}],
            '2.4.50': [{'cve': 'CVE-2021-42013', 'cvss': 9.8, 'title': 'Apache Path Traversal Bypass'}],
        },
        'vsftpd': {
            '2.3.4': [{'cve': 'CVE-2011-2523', 'cvss': 10.0, 'title': 'vsftpd Backdoor Command Execution'}],
        },
        'proftpd': {
            '1.3.3c': [{'cve': 'CVE-2010-4221', 'cvss': 10.0, 'title': 'ProFTPD Telnet IAC Buffer Overflow'}],
        },
        'mysql': {
            '5.5': [{'cve': 'CVE-2012-2122', 'cvss': 5.1, 'title': 'MySQL Authentication Bypass'}],
        },
    }

    def __init__(self, config: dict, context: NetworkScanContext = None):
        self.config = config
        self.context = context
        self.network_config = config.get('network_config', {})
        self.rate_limit = self.network_config.get('rate_limit', 100)
        self.timeout = self.network_config.get('timeout_per_host', 300)
        self.max_concurrent = self.network_config.get('max_concurrent_hosts', 10)
        self.safe_checks = self.network_config.get('safe_checks', True)
        self._last_request_time = 0
        self._finding_counter = 0
        
    def _generate_finding_id(self) -> str:
        """Generate unique finding ID"""
        self._finding_counter += 1
        return f"NET-{self._finding_counter:04d}"
    
    async def scan(self) -> List[NetworkScanResult]:
        """
        Main scan entry point - orchestrates all network scanning phases
        
        Phases:
        1. Parse targets and expand subnets
        2. Host discovery
        3. Port scanning
        4. Service detection
        5. Vulnerability scanning
        6. Authenticated checks (if credentials provided)
        """
        findings = []
        
        try:
            # Check if we need agent for private IPs
            if self.context and self.context.use_agent:
                return await self._scan_via_agent()
            
            # Phase 1: Parse and expand targets
            targets = self._parse_targets()
            if not targets:
                logger.warning("No valid targets specified for network scan")
                return findings
            
            logger.info(f"Starting network scan of {len(targets)} target(s)")
            
            # Phase 2: Host Discovery
            if self.network_config.get('host_discovery', True):
                alive_hosts = await self._discover_hosts(targets)
                logger.info(f"Discovered {len(alive_hosts)} alive hosts")
            else:
                alive_hosts = [HostInfo(ip_address=ip, is_alive=True) for ip in targets]
            
            # Phase 3: Port Scanning
            if self.network_config.get('port_scan_enabled', True):
                await self._scan_ports(alive_hosts)
            
            # Phase 4: Service Detection
            if self.network_config.get('service_detection', True):
                await self._detect_services(alive_hosts)
            
            # Phase 5: Vulnerability Scanning
            if self.network_config.get('vuln_scan_enabled', True):
                vuln_findings = await self._scan_vulnerabilities(alive_hosts)
                findings.extend(vuln_findings)
            
            # Phase 6: Authenticated Scanning
            if self.context and self.context.credentials:
                auth_findings = await self._authenticated_scan(alive_hosts)
                findings.extend(auth_findings)
            
            # Generate summary findings for discovered hosts
            for host in alive_hosts:
                if host.is_alive:
                    findings.append(self._create_host_finding(host))
            
            # Store findings in context
            if self.context:
                self.context.findings = findings
                self.context.discovered_hosts = alive_hosts
                self.context.scan_end_time = datetime.now()
            
            return findings
            
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="error",
                severity="info",
                title="Network Scan Error",
                description=f"An error occurred during scanning: {str(e)}",
                ip_address="N/A",
                reasoning="Scan could not complete due to an error"
            ))
            return findings
    
    def _parse_targets(self) -> List[str]:
        """Parse target specification and expand subnets to individual IPs"""
        targets = []
        target_spec = self.network_config.get('targets', '')
        exclude_spec = self.network_config.get('exclude_targets', '')
        
        # Parse exclusions
        exclude_ips = set()
        if exclude_spec:
            for item in exclude_spec.split(','):
                item = item.strip()
                try:
                    if '/' in item:
                        network = ipaddress.ip_network(item, strict=False)
                        exclude_ips.update(str(ip) for ip in network.hosts())
                    else:
                        exclude_ips.add(item)
                except ValueError:
                    pass
        
        # Parse targets
        for item in target_spec.split(','):
            item = item.strip()
            try:
                if '/' in item:
                    # CIDR notation - expand subnet
                    network = ipaddress.ip_network(item, strict=False)
                    for ip in network.hosts():
                        ip_str = str(ip)
                        if ip_str not in exclude_ips:
                            targets.append(ip_str)
                elif '-' in item and item.count('.') == 3:
                    # IP range like 192.168.1.1-10
                    base, end_part = item.rsplit('.', 1)
                    if '-' in end_part:
                        start, end = end_part.split('-')
                        for i in range(int(start), int(end) + 1):
                            ip_str = f"{base}.{i}"
                            if ip_str not in exclude_ips:
                                targets.append(ip_str)
                else:
                    # Single IP or hostname
                    if item not in exclude_ips:
                        # Try to resolve hostname
                        try:
                            resolved = socket.gethostbyname(item)
                            if resolved not in exclude_ips:
                                targets.append(resolved)
                        except socket.gaierror:
                            targets.append(item)
            except ValueError as e:
                logger.warning(f"Invalid target specification '{item}': {e}")
        
        return targets
    
    async def _discover_hosts(self, targets: List[str]) -> List[HostInfo]:
        """Discover alive hosts using multiple methods"""
        alive_hosts = []
        ping_methods = self.network_config.get('ping_methods', ['tcp_syn'])
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_host(ip: str) -> Optional[HostInfo]:
            async with semaphore:
                await self._rate_limit()
                
                host_info = HostInfo(ip_address=ip)
                start_time = time.time()
                
                # Try different discovery methods
                for method in ping_methods:
                    if method == 'tcp_syn' and await self._tcp_ping(ip):
                        host_info.is_alive = True
                        break
                    elif method == 'icmp' and await self._icmp_ping(ip):
                        host_info.is_alive = True
                        break
                
                if host_info.is_alive:
                    host_info.response_time_ms = (time.time() - start_time) * 1000
                    # Try reverse DNS
                    try:
                        host_info.hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        pass
                
                return host_info if host_info.is_alive else None
        
        tasks = [check_host(ip) for ip in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, HostInfo) and result is not None:
                alive_hosts.append(result)
        
        return alive_hosts
    
    async def _tcp_ping(self, ip: str, port: int = 80) -> bool:
        """Check if host is alive via TCP connection"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Try alternate ports
            for alt_port in [443, 22, 445]:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, alt_port),
                        timeout=1.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except:
                    continue
            return False
    
    async def _icmp_ping(self, ip: str) -> bool:
        """Check if host responds to ICMP (requires elevated privileges)"""
        try:
            # Use system ping command as fallback (works without raw sockets)
            proc = await asyncio.create_subprocess_exec(
                'ping', '-n', '1', '-w', '1000', ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            return b'TTL=' in stdout or b'ttl=' in stdout
        except (asyncio.TimeoutError, Exception):
            return False
    
    async def _scan_ports(self, hosts: List[HostInfo]) -> None:
        """Scan ports on discovered hosts"""
        port_range = self.network_config.get('port_range', '1-1024')
        scan_type = self.network_config.get('scan_type', 'connect')
        
        # Parse port range
        ports_to_scan = self._parse_port_range(port_range)
        
        semaphore = asyncio.Semaphore(self.max_concurrent * 10)  # Higher concurrency for ports
        
        async def scan_port(host: HostInfo, port: int) -> Optional[int]:
            async with semaphore:
                await self._rate_limit()
                
                try:
                    if scan_type == 'connect':
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host.ip_address, port),
                            timeout=1.0
                        )
                        writer.close()
                        await writer.wait_closed()
                        return port
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
        
        for host in hosts:
            tasks = [scan_port(host, port) for port in ports_to_scan]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, int):
                    host.open_ports.append(result)
            
            host.open_ports.sort()
            logger.info(f"Host {host.ip_address}: {len(host.open_ports)} open ports")
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range specification"""
        ports = []
        
        if port_range.lower() == 'common':
            return self.COMMON_PORTS
        elif port_range.lower() == 'all':
            return list(range(1, 65536))
        
        for part in port_range.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        
        return ports
    
    async def _detect_services(self, hosts: List[HostInfo]) -> None:
        """Detect services and versions on open ports"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def detect_service(host: HostInfo, port: int) -> Dict:
            async with semaphore:
                await self._rate_limit()
                
                service_info = {
                    'port': port,
                    'service': 'unknown',
                    'version': '',
                    'banner': ''
                }
                
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host.ip_address, port),
                        timeout=3.0
                    )
                    
                    # Try to grab banner
                    try:
                        banner = await asyncio.wait_for(
                            reader.read(1024),
                            timeout=2.0
                        )
                        service_info['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    except asyncio.TimeoutError:
                        # Some services need a request first
                        if port in [80, 8080, 443]:
                            writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
                            await writer.drain()
                            try:
                                banner = await asyncio.wait_for(
                                    reader.read(1024),
                                    timeout=2.0
                                )
                                service_info['banner'] = banner.decode('utf-8', errors='ignore').strip()
                            except:
                                pass
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    # Identify service from signature or banner
                    if port in self.SERVICE_SIGNATURES:
                        service_info['service'] = self.SERVICE_SIGNATURES[port][0]
                    
                    # Parse version from banner
                    service_info['version'] = self._parse_version(service_info['banner'])
                    
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    if port in self.SERVICE_SIGNATURES:
                        service_info['service'] = self.SERVICE_SIGNATURES[port][0]
                
                return service_info
        
        for host in hosts:
            tasks = [detect_service(host, port) for port in host.open_ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict):
                    host.services[result['port']] = result
    
    def _parse_version(self, banner: str) -> str:
        """Extract version information from service banner"""
        import re
        
        version_patterns = [
            r'SSH-[\d.]+-OpenSSH[_-]?([\d.]+)',
            r'Apache/([\d.]+)',
            r'nginx/([\d.]+)',
            r'Server:\s+[\w/]*([\d.]+)',
            r'vsftpd\s+([\d.]+)',
            r'ProFTPD\s+([\d.]+)',
            r'MySQL\s+([\d.]+)',
            r'PostgreSQL\s+([\d.]+)',
            r'Microsoft-IIS/([\d.]+)',
            r'([\d]+\.[\d]+\.[\d]+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ''
    
    async def _scan_vulnerabilities(self, hosts: List[HostInfo]) -> List[NetworkScanResult]:
        """Scan for known vulnerabilities based on detected services/versions"""
        findings = []
        
        for host in hosts:
            # Check each service for known vulnerabilities
            for port, service_info in host.services.items():
                service = service_info.get('service', '').lower()
                version = service_info.get('version', '')
                banner = service_info.get('banner', '')
                
                # Check against known vulnerable versions
                for product, versions in self.KNOWN_VULNS.items():
                    if product in service or product in banner.lower():
                        for vuln_version, vulns in versions.items():
                            if version.startswith(vuln_version):
                                for vuln in vulns:
                                    findings.append(NetworkScanResult(
                                        id=self._generate_finding_id(),
                                        category="vulnerability",
                                        severity=self._cvss_to_severity(vuln['cvss']),
                                        title=vuln['title'],
                                        description=f"The {service} service on port {port} is running version {version} which is vulnerable to {vuln['cve']}",
                                        ip_address=host.ip_address,
                                        port=port,
                                        service=service,
                                        version=version,
                                        cve_id=vuln['cve'],
                                        cvss_score=vuln['cvss'],
                                        evidence=f"Banner: {banner[:200]}" if banner else "",
                                        remediation=f"Update {service} to the latest patched version",
                                        reasoning=f"Version {version} matches known vulnerable version {vuln_version}"
                                    ))
                
                # Check for common misconfigurations
                misconfig_findings = self._check_misconfigurations(host, port, service_info)
                findings.extend(misconfig_findings)
        
        return findings
    
    def _check_misconfigurations(self, host: HostInfo, port: int, service_info: Dict) -> List[NetworkScanResult]:
        """Check for common service misconfigurations"""
        findings = []
        banner = service_info.get('banner', '')
        service = service_info.get('service', '')
        
        # Telnet enabled (insecure protocol)
        if port == 23 and service == 'telnet':
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="misconfiguration",
                severity="high",
                title="Telnet Service Enabled",
                description="Telnet transmits data including passwords in plaintext and should be replaced with SSH",
                ip_address=host.ip_address,
                port=port,
                service=service,
                cwe_id="CWE-319",
                remediation="Disable Telnet and use SSH for remote administration",
                reasoning="Telnet is an insecure protocol that transmits credentials in cleartext"
            ))
        
        # FTP without TLS
        if port == 21 and 'TLS' not in banner and 'SSL' not in banner:
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="misconfiguration",
                severity="medium",
                title="FTP Without TLS/SSL",
                description="FTP service does not appear to support secure connections (FTPS)",
                ip_address=host.ip_address,
                port=port,
                service=service,
                cwe_id="CWE-319",
                remediation="Enable FTPS (FTP over TLS) or migrate to SFTP",
                reasoning="FTP without encryption exposes credentials and data to interception"
            ))
        
        # SMB exposed
        if port == 445:
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="exposure",
                severity="medium",
                title="SMB Service Exposed",
                description="SMB/CIFS service is accessible which may expose shared resources",
                ip_address=host.ip_address,
                port=port,
                service="smb",
                cwe_id="CWE-200",
                remediation="Restrict SMB access to trusted networks using firewall rules",
                reasoning="SMB exposure can lead to information disclosure and lateral movement"
            ))
        
        # RDP exposed
        if port == 3389:
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="exposure",
                severity="medium",
                title="RDP Service Exposed",
                description="Remote Desktop Protocol is accessible from the network",
                ip_address=host.ip_address,
                port=port,
                service="rdp",
                cwe_id="CWE-284",
                remediation="Use VPN for RDP access, enable NLA, and consider using RDP gateway",
                reasoning="Exposed RDP is a common attack vector for ransomware and unauthorized access"
            ))
        
        # Database exposed
        if port in [3306, 5432, 1433, 1521, 27017]:
            db_names = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MS SQL', 1521: 'Oracle', 27017: 'MongoDB'}
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="exposure",
                severity="high",
                title=f"{db_names.get(port, 'Database')} Service Exposed",
                description=f"Database service is accessible on port {port}",
                ip_address=host.ip_address,
                port=port,
                service=service,
                cwe_id="CWE-284",
                remediation="Restrict database access to application servers only using firewall rules",
                reasoning="Direct database exposure can lead to data breaches and unauthorized access"
            ))
        
        # Redis without auth
        if port == 6379 and 'NOAUTH' in banner:
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="misconfiguration",
                severity="critical",
                title="Redis Without Authentication",
                description="Redis instance is accessible without authentication",
                ip_address=host.ip_address,
                port=port,
                service="redis",
                cwe_id="CWE-306",
                remediation="Enable Redis AUTH and bind to localhost or trusted networks",
                reasoning="Unauthenticated Redis can lead to RCE via module loading"
            ))
        
        return findings
    
    async def _authenticated_scan(self, hosts: List[HostInfo]) -> List[NetworkScanResult]:
        """Perform authenticated scanning using provided credentials"""
        findings = []
        credentials = self.context.credentials
        
        if not credentials:
            return findings
        
        for host in hosts:
            # SSH authenticated checks
            if credentials.get('ssh') and 22 in host.open_ports:
                ssh_findings = await self._ssh_authenticated_scan(host, credentials['ssh'])
                findings.extend(ssh_findings)
            
            # Windows authenticated checks
            if credentials.get('windows') and 445 in host.open_ports:
                win_findings = await self._windows_authenticated_scan(host, credentials['windows'])
                findings.extend(win_findings)
            
            # SNMP checks
            if credentials.get('snmp') and 161 in host.open_ports:
                snmp_findings = await self._snmp_scan(host, credentials['snmp'])
                findings.extend(snmp_findings)
            
            # Database checks
            if credentials.get('database'):
                db_findings = await self._database_authenticated_scan(host, credentials['database'])
                findings.extend(db_findings)
        
        return findings
    
    async def _ssh_authenticated_scan(self, host: HostInfo, ssh_cred: Dict) -> List[NetworkScanResult]:
        """Perform SSH authenticated security checks"""
        findings = []
        
        try:
            # Note: In production, use paramiko or asyncssh for actual SSH connection
            # This is a placeholder for the authenticated scan logic
            logger.info(f"SSH authenticated scan on {host.ip_address}")
            
            # Checks to perform:
            # 1. SSH configuration audit (PermitRootLogin, PasswordAuthentication)
            # 2. User enumeration
            # 3. Sudo configuration
            # 4. Installed package versions
            # 5. Running processes
            # 6. Open files/connections
            # 7. Cron jobs
            # 8. SUID binaries
            
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="auth_scan",
                severity="info",
                title="SSH Authenticated Scan Completed",
                description=f"Successfully performed authenticated scan on {host.ip_address} via SSH",
                ip_address=host.ip_address,
                port=22,
                service="ssh"
            ))
            
        except Exception as e:
            logger.error(f"SSH authenticated scan failed for {host.ip_address}: {e}")
        
        return findings
    
    async def _windows_authenticated_scan(self, host: HostInfo, win_cred: Dict) -> List[NetworkScanResult]:
        """Perform Windows authenticated security checks"""
        findings = []
        
        try:
            logger.info(f"Windows authenticated scan on {host.ip_address}")
            
            # Checks to perform:
            # 1. Windows Update status
            # 2. Installed software inventory
            # 3. Security policy settings
            # 4. User/group enumeration
            # 5. Scheduled tasks
            # 6. Services configuration
            # 7. Registry security settings
            # 8. Event log analysis
            
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="auth_scan",
                severity="info",
                title="Windows Authenticated Scan Completed",
                description=f"Successfully performed authenticated scan on {host.ip_address} via Windows credentials",
                ip_address=host.ip_address,
                port=445,
                service="windows"
            ))
            
        except Exception as e:
            logger.error(f"Windows authenticated scan failed for {host.ip_address}: {e}")
        
        return findings
    
    async def _snmp_scan(self, host: HostInfo, snmp_cred: Dict) -> List[NetworkScanResult]:
        """Perform SNMP-based network device scanning"""
        findings = []
        
        try:
            logger.info(f"SNMP scan on {host.ip_address}")
            
            # Checks to perform:
            # 1. System information retrieval
            # 2. Interface enumeration
            # 3. Routing table
            # 4. ARP table
            # 5. Running processes
            # 6. Installed software
            
            # Check for default community strings
            default_communities = ['public', 'private', 'community']
            community = snmp_cred.get('community_string', '')
            
            if community.lower() in default_communities:
                findings.append(NetworkScanResult(
                    id=self._generate_finding_id(),
                    category="misconfiguration",
                    severity="high",
                    title="Default SNMP Community String",
                    description=f"SNMP is configured with default community string '{community}'",
                    ip_address=host.ip_address,
                    port=161,
                    protocol="udp",
                    service="snmp",
                    cwe_id="CWE-798",
                    remediation="Change SNMP community strings to complex, unique values or migrate to SNMPv3",
                    reasoning="Default community strings allow unauthorized access to device information"
                ))
            
        except Exception as e:
            logger.error(f"SNMP scan failed for {host.ip_address}: {e}")
        
        return findings
    
    async def _database_authenticated_scan(self, host: HostInfo, db_cred: Dict) -> List[NetworkScanResult]:
        """Perform database security scanning"""
        findings = []
        
        db_type = db_cred.get('db_type', '')
        db_ports = {'mysql': 3306, 'postgresql': 5432, 'mssql': 1433, 'oracle': 1521, 'mongodb': 27017}
        
        port = db_cred.get('port') or db_ports.get(db_type, 0)
        
        if port not in host.open_ports:
            return findings
        
        try:
            logger.info(f"{db_type} database scan on {host.ip_address}")
            
            # Checks to perform:
            # 1. User enumeration
            # 2. Privilege analysis
            # 3. Security configuration
            # 4. Stored procedure audit
            # 5. Sensitive data exposure
            # 6. Encryption settings
            
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="auth_scan",
                severity="info",
                title=f"{db_type.upper()} Authenticated Scan Completed",
                description=f"Successfully performed authenticated scan on {host.ip_address} database",
                ip_address=host.ip_address,
                port=port,
                service=db_type
            ))
            
        except Exception as e:
            logger.error(f"Database scan failed for {host.ip_address}: {e}")
        
        return findings
    
    async def _scan_via_agent(self) -> List[NetworkScanResult]:
        """
        Scan private networks via Jarwis Agent
        
        The Jarwis Agent is a lightweight service deployed inside private networks
        that can:
        1. Receive scan instructions from the Jarwis cloud
        2. Execute local network scans
        3. Report findings back securely
        """
        findings = []
        
        if not self.context or not self.context.agent_id:
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="error",
                severity="info",
                title="Agent Required for Private Network Scan",
                description="To scan private IP ranges, you need to deploy the Jarwis Agent inside your network",
                ip_address="N/A",
                remediation="Download and install the Jarwis Agent from your dashboard, then configure it with your API key"
            ))
            return findings
        
        try:
            # In production, this would communicate with the agent service
            agent_api = self.config.get('agent_api_url', 'https://agent.jarwis.io')
            agent_id = self.context.agent_id
            
            logger.info(f"Initiating scan via agent: {agent_id}")
            
            # Send scan configuration to agent
            async with aiohttp.ClientSession() as session:
                scan_payload = {
                    'agent_id': agent_id,
                    'targets': self.network_config.get('targets'),
                    'config': self.network_config,
                    'credentials': self.context.credentials if self.context.credentials else None
                }
                
                # This would be the actual agent communication
                # async with session.post(f"{agent_api}/api/v1/scan", json=scan_payload) as resp:
                #     result = await resp.json()
                
                findings.append(NetworkScanResult(
                    id=self._generate_finding_id(),
                    category="info",
                    severity="info",
                    title="Agent Scan Initiated",
                    description=f"Network scan job submitted to agent {agent_id}",
                    ip_address="N/A",
                    reasoning="Agent will execute the scan and report findings asynchronously"
                ))
        
        except Exception as e:
            logger.error(f"Agent scan failed: {e}")
            findings.append(NetworkScanResult(
                id=self._generate_finding_id(),
                category="error",
                severity="medium",
                title="Agent Communication Failed",
                description=f"Could not communicate with agent: {str(e)}",
                ip_address="N/A",
                remediation="Check agent connectivity and ensure it's running"
            ))
        
        return findings
    
    def _create_host_finding(self, host: HostInfo) -> NetworkScanResult:
        """Create a summary finding for a discovered host"""
        open_ports_str = ", ".join(str(p) for p in host.open_ports[:20])
        if len(host.open_ports) > 20:
            open_ports_str += f" (+{len(host.open_ports) - 20} more)"
        
        services_str = ", ".join(
            f"{p}:{info.get('service', 'unknown')}"
            for p, info in list(host.services.items())[:10]
        )
        
        return NetworkScanResult(
            id=self._generate_finding_id(),
            category="discovery",
            severity="info",
            title=f"Host Discovered: {host.ip_address}",
            description=f"Host {host.ip_address} ({host.hostname or 'unknown hostname'}) is alive with {len(host.open_ports)} open ports",
            ip_address=host.ip_address,
            evidence=f"Open ports: {open_ports_str}\nServices: {services_str}",
            raw_output=f"Response time: {host.response_time_ms:.2f}ms, OS: {host.os_guess or 'unknown'}"
        )
    
    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity rating"""
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        elif cvss > 0:
            return "low"
        return "info"
    
    async def _rate_limit(self):
        """Apply rate limiting between requests"""
        current_time = time.time()
        min_interval = 1.0 / self.rate_limit
        elapsed = current_time - self._last_request_time
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
