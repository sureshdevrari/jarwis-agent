"""
Jarwis Network Security - Port & Service Discovery Scanners

Tools:
- Nmap: Comprehensive port scanning, service detection, OS fingerprinting
- Masscan: Ultra-fast port scanning for large networks
- RustScan: Fast port discovery with Nmap integration
"""

import asyncio
import json
import re
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

from .base import (
    BaseScanner, ScanResult, Finding, ScanPhase, 
    ScannerRegistry, Severity
)

logger = logging.getLogger(__name__)


@ScannerRegistry.register
class NmapScanner(BaseScanner):
    """
    Nmap - The Network Mapper
    
    Capabilities:
    - Port scanning (TCP/UDP)
    - Service/version detection
    - OS fingerprinting
    - NSE vulnerability scripts
    - CVE detection via vulners script
    """
    
    TOOL_NAME = "nmap"
    PHASE = ScanPhase.PORT_SCAN
    REQUIRES_ROOT = True  # For SYN scans
    
    # Nmap scan profiles
    PROFILES = {
        'quick': '-sT -T4 --top-ports 100',
        'standard': '-sT -sV -T4 --top-ports 1000',
        'comprehensive': '-sT -sV -sC -O -T4 -p-',
        'vuln': '-sT -sV --script vuln,vulners -T4',
        'stealth': '-sS -sV -T2 -f',
        'udp': '-sU -sV --top-ports 100',
        'aggressive': '-A -T4 -p-',
    }
    
    # NSE scripts for vulnerability detection
    VULN_SCRIPTS = [
        'vuln', 'vulners', 'vulscan', 'exploit',
        'ssl-heartbleed', 'smb-vuln*', 'http-vuln*',
    ]

    async def run(self, target: str, profile: str = 'standard', 
                  ports: str = None, scripts: List[str] = None,
                  **kwargs) -> ScanResult:
        """
        Run Nmap scan against target.
        
        Args:
            target: IP/hostname/CIDR
            profile: Scan profile (quick, standard, comprehensive, vuln)
            ports: Custom port specification
            scripts: Additional NSE scripts to run
        """
        start_time = asyncio.get_event_loop().time()
        
        # Build command
        args = self.PROFILES.get(profile, self.PROFILES['standard'])
        
        if ports:
            args = re.sub(r'-p\S*|--top-ports\s+\d+', '', args)
            args += f' -p {ports}'
        
        if scripts:
            args += f' --script {",".join(scripts)}'
        
        # Add output format
        args += ' -oX -'  # XML output to stdout
        
        cmd = ['nmap'] + args.split() + [target]
        
        stdout, stderr, returncode = await self._run_command(cmd)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if returncode == 0 and stdout:
            result.findings = self.parse_output(stdout, target)
            result.hosts_discovered = self._extract_hosts(stdout)
            result.ports_discovered = self._extract_ports(stdout)
            result.services_discovered = self._extract_services(stdout)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse Nmap XML output into findings"""
        findings = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_output)
            
            for host in root.findall('.//host'):
                ip = host.find('.//address[@addrtype="ipv4"]')
                ip_addr = ip.get('addr') if ip is not None else target
                
                # Parse scripts results for vulnerabilities
                for script in host.findall('.//script'):
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    
                    # Check for vulnerability indicators
                    if 'VULNERABLE' in output or 'CVE-' in output:
                        cve_matches = re.findall(r'CVE-\d{4}-\d+', output)
                        cvss_match = re.search(r'CVSS[:\s]*([\d.]+)', output)
                        
                        for cve in cve_matches or ['N/A']:
                            findings.append(Finding(
                                id=self._generate_id(),
                                tool=self.TOOL_NAME,
                                category="vulnerability",
                                severity=self._severity_from_cvss(
                                    float(cvss_match.group(1)) if cvss_match else 5.0
                                ),
                                title=f"Nmap: {script_id} - {cve}",
                                description=output[:500],
                                target=ip_addr,
                                cve_id=cve if cve != 'N/A' else '',
                                cvss_score=float(cvss_match.group(1)) if cvss_match else 0,
                                confidence=0.85,
                                evidence=output,
                                raw_output=output
                            ))
                
                # Parse port findings
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol', 'tcp')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') == 'open':
                        svc_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        svc_version = service.get('version', '') if service is not None else ''
                        svc_product = service.get('product', '') if service is not None else ''
                        
                        # Check for risky services
                        risky_services = {
                            'telnet': ('high', 'Telnet transmits data in cleartext'),
                            'ftp': ('medium', 'FTP may transmit credentials in cleartext'),
                            'rexec': ('high', 'Remote execution service is dangerous'),
                            'rlogin': ('high', 'rlogin is insecure'),
                            'finger': ('medium', 'Finger exposes user information'),
                            'netbios-ssn': ('medium', 'NetBIOS may expose system information'),
                            'ms-wbt-server': ('medium', 'RDP exposed to network'),
                        }
                        
                        if svc_name in risky_services:
                            severity, desc = risky_services[svc_name]
                            findings.append(Finding(
                                id=self._generate_id(),
                                tool=self.TOOL_NAME,
                                category="exposure",
                                severity=severity,
                                title=f"Risky Service: {svc_name} on port {port_id}",
                                description=desc,
                                target=ip_addr,
                                port=int(port_id),
                                protocol=protocol,
                                service=svc_name,
                                version=f"{svc_product} {svc_version}".strip(),
                                confidence=0.90,
                                remediation=f"Consider disabling {svc_name} or restricting access"
                            ))
        
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
        except Exception as e:
            logger.error(f"Error parsing Nmap output: {e}")
        
        return findings
    
    def _extract_hosts(self, xml_output: str) -> List[Dict]:
        """Extract discovered hosts from Nmap output"""
        hosts = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            
            for host in root.findall('.//host'):
                ip = host.find('.//address[@addrtype="ipv4"]')
                mac = host.find('.//address[@addrtype="mac"]')
                hostname = host.find('.//hostname')
                status = host.find('.//status')
                os_match = host.find('.//osmatch')
                
                hosts.append({
                    'ip': ip.get('addr') if ip is not None else '',
                    'mac': mac.get('addr') if mac is not None else '',
                    'hostname': hostname.get('name') if hostname is not None else '',
                    'status': status.get('state') if status is not None else '',
                    'os': os_match.get('name') if os_match is not None else '',
                    'os_accuracy': os_match.get('accuracy') if os_match is not None else 0,
                })
        except Exception as e:
            logger.error(f"Error extracting hosts: {e}")
        return hosts
    
    def _extract_ports(self, xml_output: str) -> List[Dict]:
        """Extract open ports from Nmap output"""
        ports = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            
            for host in root.findall('.//host'):
                ip = host.find('.//address[@addrtype="ipv4"]')
                ip_addr = ip.get('addr') if ip is not None else ''
                
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        ports.append({
                            'ip': ip_addr,
                            'port': int(port.get('portid', 0)),
                            'protocol': port.get('protocol', 'tcp'),
                            'state': state.get('state'),
                            'reason': state.get('reason', ''),
                        })
        except Exception as e:
            logger.error(f"Error extracting ports: {e}")
        return ports
    
    def _extract_services(self, xml_output: str) -> List[Dict]:
        """Extract service information from Nmap output"""
        services = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            
            for host in root.findall('.//host'):
                ip = host.find('.//address[@addrtype="ipv4"]')
                ip_addr = ip.get('addr') if ip is not None else ''
                
                for port in host.findall('.//port'):
                    service = port.find('service')
                    state = port.find('state')
                    
                    if state is not None and state.get('state') == 'open' and service is not None:
                        services.append({
                            'ip': ip_addr,
                            'port': int(port.get('portid', 0)),
                            'protocol': port.get('protocol', 'tcp'),
                            'name': service.get('name', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                            'cpe': service.get('cpe', ''),
                        })
        except Exception as e:
            logger.error(f"Error extracting services: {e}")
        return services


@ScannerRegistry.register
class MasscanScanner(BaseScanner):
    """
    Masscan - Ultra-fast port scanner
    
    Can scan the entire Internet in under 6 minutes.
    Best for large network discovery before detailed Nmap scans.
    """
    
    TOOL_NAME = "masscan"
    PHASE = ScanPhase.PORT_SCAN
    REQUIRES_ROOT = True
    
    async def run(self, target: str, ports: str = "1-65535",
                  rate: int = 10000, **kwargs) -> ScanResult:
        """
        Run Masscan against target.
        
        Args:
            target: IP/CIDR range
            ports: Port specification (default: all ports)
            rate: Packets per second (default: 10000)
        """
        start_time = asyncio.get_event_loop().time()
        
        # Respect configured rate limit
        rate = min(rate, self.rate_limit * 100)
        
        cmd = [
            'masscan', target,
            '-p', ports,
            '--rate', str(rate),
            '-oJ', '-',  # JSON output
        ]
        
        stdout, stderr, returncode = await self._run_command(cmd)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target)
            result.ports_discovered = self._extract_ports(stdout)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse Masscan JSON output"""
        findings = []
        
        # Masscan JSON is line-delimited
        for line in raw_output.strip().split('\n'):
            line = line.strip().rstrip(',')
            if not line or line in ['[', ']', '{', '}']:
                continue
            
            try:
                entry = json.loads(line)
                ip = entry.get('ip', target)
                
                for port_info in entry.get('ports', []):
                    port = port_info.get('port', 0)
                    protocol = port_info.get('proto', 'tcp')
                    
                    findings.append(Finding(
                        id=self._generate_id(),
                        tool=self.TOOL_NAME,
                        category="discovery",
                        severity="info",
                        title=f"Open Port: {port}/{protocol}",
                        description=f"Port {port}/{protocol} is open on {ip}",
                        target=ip,
                        port=port,
                        protocol=protocol,
                        confidence=0.99
                    ))
            except json.JSONDecodeError:
                continue
        
        return findings
    
    def _extract_ports(self, raw_output: str) -> List[Dict]:
        """Extract port information from Masscan output"""
        ports = []
        
        for line in raw_output.strip().split('\n'):
            line = line.strip().rstrip(',')
            if not line or line in ['[', ']']:
                continue
            
            try:
                entry = json.loads(line)
                ip = entry.get('ip', '')
                
                for port_info in entry.get('ports', []):
                    ports.append({
                        'ip': ip,
                        'port': port_info.get('port', 0),
                        'protocol': port_info.get('proto', 'tcp'),
                        'state': 'open',
                        'ttl': port_info.get('ttl', 0),
                    })
            except json.JSONDecodeError:
                continue
        
        return ports


@ScannerRegistry.register
class RustScanScanner(BaseScanner):
    """
    RustScan - The Modern Port Scanner
    
    Fast Rust-based port scanner that integrates with Nmap.
    Discovers open ports quickly, then hands off to Nmap for details.
    """
    
    TOOL_NAME = "rustscan"
    PHASE = ScanPhase.PORT_SCAN
    REQUIRES_ROOT = False
    
    async def run(self, target: str, batch_size: int = 4500,
                  timeout: int = 1500, **kwargs) -> ScanResult:
        """
        Run RustScan against target.
        
        Args:
            target: IP/hostname
            batch_size: Number of ports to scan at once
            timeout: Timeout in milliseconds
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = [
            'rustscan',
            '-a', target,
            '-b', str(batch_size),
            '-t', str(timeout),
            '--greppable',
        ]
        
        stdout, stderr, returncode = await self._run_command(cmd)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target)
            result.ports_discovered = self._extract_ports(stdout)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse RustScan output"""
        findings = []
        
        # Parse greppable format: Open IP:PORT
        port_pattern = re.compile(r'Open\s+(\d+\.\d+\.\d+\.\d+):(\d+)')
        
        for match in port_pattern.finditer(raw_output):
            ip = match.group(1)
            port = int(match.group(2))
            
            findings.append(Finding(
                id=self._generate_id(),
                tool=self.TOOL_NAME,
                category="discovery",
                severity="info",
                title=f"Open Port: {port}/tcp",
                description=f"Port {port}/tcp is open on {ip}",
                target=ip,
                port=port,
                protocol="tcp",
                confidence=0.99
            ))
        
        return findings
    
    def _extract_ports(self, raw_output: str) -> List[Dict]:
        """Extract ports from RustScan output"""
        ports = []
        port_pattern = re.compile(r'Open\s+(\d+\.\d+\.\d+\.\d+):(\d+)')
        
        for match in port_pattern.finditer(raw_output):
            ports.append({
                'ip': match.group(1),
                'port': int(match.group(2)),
                'protocol': 'tcp',
                'state': 'open',
            })
        
        return ports
