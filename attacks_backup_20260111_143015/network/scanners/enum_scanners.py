"""
Jarwis Network Security - Enumeration Scanners

Tools:
- Netdiscover: ARP-based host discovery
- SNMPwalk: SNMP enumeration
- DNSRecon: DNS reconnaissance
"""

import asyncio
import json
import re
import logging
from typing import Dict, List, Optional

from .base import (
    BaseScanner, ScanResult, Finding, ScanPhase,
    ScannerRegistry, Severity
)

logger = logging.getLogger(__name__)


@ScannerRegistry.register
class NetdiscoverScanner(BaseScanner):
    """
    Netdiscover - ARP-based network discovery
    
    Discovers live hosts on local network using ARP.
    Essential for internal network mapping.
    """
    
    TOOL_NAME = "netdiscover"
    PHASE = ScanPhase.DISCOVERY
    REQUIRES_ROOT = True
    
    async def run(self, target: str, interface: str = None,
                  passive: bool = False, **kwargs) -> ScanResult:
        """
        Run netdiscover for ARP-based host discovery.
        
        Args:
            target: IP range (e.g., 192.168.1.0/24)
            interface: Network interface
            passive: Use passive mode (listen only)
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = ['netdiscover', '-P', '-N']  # Passive print, No header
        
        if passive:
            cmd.append('-p')
        else:
            cmd.extend(['-r', target])
        
        if interface:
            cmd.extend(['-i', interface])
        
        # Limit scan time
        cmd.extend(['-c', '3'])  # 3 ARP requests per IP
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=300)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 and not stdout else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse netdiscover output"""
        findings = []
        
        # Format: IP   MAC   Count   Len   Vendor
        pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+)\s+'  # IP
            r'([0-9a-fA-F:]{17})\s+'     # MAC
            r'(\d+)\s+'                   # Count
            r'(\d+)\s+'                   # Len
            r'(.+)?'                      # Vendor (optional)
        )
        
        for line in raw_output.strip().split('\n'):
            match = pattern.match(line.strip())
            if match:
                ip, mac, count, length, vendor = match.groups()
                
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="discovery",
                    severity=Severity.INFO.value,
                    title=f"Host discovered: {ip}",
                    description=f"Live host detected via ARP",
                    target=ip,
                    evidence=f"MAC: {mac}\nVendor: {vendor or 'Unknown'}",
                    confidence=0.99,
                    metadata={
                        'mac_address': mac,
                        'vendor': vendor.strip() if vendor else 'Unknown',
                        'arp_count': int(count),
                    }
                ))
        
        return findings


@ScannerRegistry.register
class SNMPScanner(BaseScanner):
    """
    SNMPwalk - SNMP Enumeration
    
    Enumerates SNMP-enabled devices for:
    - System information
    - Network interfaces
    - Routing tables
    - Running processes
    - Installed software
    
    Requires community strings or SNMPv3 credentials.
    """
    
    TOOL_NAME = "snmpwalk"
    PHASE = ScanPhase.SERVICE_ENUM
    REQUIRES_ROOT = False
    
    # Common OIDs for enumeration
    OIDS = {
        'system': '1.3.6.1.2.1.1',
        'interfaces': '1.3.6.1.2.1.2',
        'ip_addresses': '1.3.6.1.2.1.4.20',
        'routes': '1.3.6.1.2.1.4.21',
        'tcp_connections': '1.3.6.1.2.1.6.13',
        'processes': '1.3.6.1.2.1.25.4.2',
        'storage': '1.3.6.1.2.1.25.2',
        'software': '1.3.6.1.2.1.25.6.3',
    }
    
    async def run(self, target: str, community: str = 'public',
                  version: str = '2c', port: int = 161,
                  oids: List[str] = None,
                  v3_user: str = None, v3_auth: str = None,
                  v3_priv: str = None, **kwargs) -> ScanResult:
        """
        Run SNMP enumeration.
        
        Args:
            target: IP/hostname
            community: SNMP community string (v1/v2c)
            version: SNMP version (1, 2c, 3)
            port: SNMP port
            oids: Specific OIDs to query
            v3_user: SNMPv3 username
            v3_auth: SNMPv3 auth password
            v3_priv: SNMPv3 privacy password
        """
        start_time = asyncio.get_event_loop().time()
        
        all_findings = []
        full_output = []
        errors = []
        
        # Determine which OIDs to enumerate
        target_oids = oids or list(self.OIDS.values())
        
        for oid in target_oids:
            cmd = self._build_command(
                target, oid, community, version, port,
                v3_user, v3_auth, v3_priv
            )
            
            stdout, stderr, returncode = await self._run_command(cmd, timeout=60)
            
            if stdout:
                full_output.append(f"=== OID: {oid} ===\n{stdout}")
                findings = self.parse_output(stdout, target)
                all_findings.extend(findings)
            
            if stderr and 'Timeout' in stderr:
                errors.append(f"OID {oid}: Timeout")
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output='\n'.join(full_output),
            error='; '.join(errors) if errors else "",
            findings=all_findings,
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        return result
    
    def _build_command(self, target: str, oid: str, community: str,
                       version: str, port: int, v3_user: str = None,
                       v3_auth: str = None, v3_priv: str = None) -> List[str]:
        """Build snmpwalk command"""
        cmd = ['snmpwalk', '-On']  # Numeric OIDs
        
        if version == '3' and v3_user:
            cmd.extend(['-v3', '-u', v3_user])
            if v3_auth:
                cmd.extend(['-l', 'authPriv' if v3_priv else 'authNoPriv'])
                cmd.extend(['-a', 'SHA', '-A', v3_auth])
                if v3_priv:
                    cmd.extend(['-x', 'AES', '-X', v3_priv])
            else:
                cmd.extend(['-l', 'noAuthNoPriv'])
        else:
            cmd.extend(['-v', version, '-c', community])
        
        cmd.extend([f'{target}:{port}', oid])
        
        return cmd
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse SNMP walk output"""
        findings = []
        
        # Detect sensitive information
        sensitive_patterns = {
            'system_name': (r'\.1\.3\.6\.1\.2\.1\.1\.5\.0\s+=\s+STRING:\s+"?([^"]+)"?', 'System name'),
            'system_desc': (r'\.1\.3\.6\.1\.2\.1\.1\.1\.0\s+=\s+STRING:\s+"?([^"]+)"?', 'System description'),
            'contact': (r'\.1\.3\.6\.1\.2\.1\.1\.4\.0\s+=\s+STRING:\s+"?([^"]+)"?', 'Contact'),
            'location': (r'\.1\.3\.6\.1\.2\.1\.1\.6\.0\s+=\s+STRING:\s+"?([^"]+)"?', 'Location'),
        }
        
        # System information finding
        system_info = {}
        for key, (pattern, label) in sensitive_patterns.items():
            match = re.search(pattern, raw_output)
            if match:
                system_info[label] = match.group(1)
        
        if system_info:
            findings.append(Finding(
                id=self._generate_id(),
                tool=self.TOOL_NAME,
                category="enumeration",
                severity=Severity.MEDIUM.value,
                title=f"SNMP Information Disclosure on {target}",
                description="SNMP service exposed system information",
                target=target,
                port=161,
                service='snmp',
                evidence=json.dumps(system_info, indent=2),
                confidence=0.95,
                metadata=system_info
            ))
        
        # Check for writable community strings
        if 'No Such Object' not in raw_output and raw_output.strip():
            findings.append(Finding(
                id=self._generate_id(),
                tool=self.TOOL_NAME,
                category="misconfiguration",
                severity=Severity.LOW.value,
                title=f"SNMP service accessible on {target}",
                description="SNMP service responds to queries",
                target=target,
                port=161,
                service='snmp',
                confidence=0.90,
            ))
        
        return findings


@ScannerRegistry.register
class DNSReconScanner(BaseScanner):
    """
    DNSRecon - DNS Reconnaissance
    
    Performs comprehensive DNS enumeration:
    - Standard record enumeration
    - Zone transfer attempts
    - Subdomain brute-forcing
    - Cache snooping
    - Google dorks for subdomains
    """
    
    TOOL_NAME = "dnsrecon"
    PHASE = ScanPhase.DISCOVERY
    REQUIRES_ROOT = False
    
    async def run(self, target: str, record_types: List[str] = None,
                  zone_transfer: bool = True, brute_force: bool = False,
                  wordlist: str = None, **kwargs) -> ScanResult:
        """
        Run DNS reconnaissance.
        
        Args:
            target: Domain to enumerate
            record_types: Record types to query (A, AAAA, MX, NS, etc.)
            zone_transfer: Attempt zone transfer
            brute_force: Brute force subdomains
            wordlist: Path to subdomain wordlist
        """
        start_time = asyncio.get_event_loop().time()
        
        all_findings = []
        full_output = []
        errors = []
        
        # Standard enumeration
        cmd = ['dnsrecon', '-d', target, '-j', '-']
        
        if record_types:
            cmd.extend(['-t', 'std', '-a'])
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=120)
        
        if stdout:
            full_output.append(stdout)
            findings = self.parse_output(stdout, target)
            all_findings.extend(findings)
        
        # Zone transfer attempt
        if zone_transfer:
            axfr_cmd = ['dnsrecon', '-d', target, '-t', 'axfr', '-j', '-']
            stdout, stderr, returncode = await self._run_command(axfr_cmd, timeout=60)
            
            if stdout and 'Zone Transfer' in stdout:
                full_output.append(f"=== Zone Transfer ===\n{stdout}")
                all_findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="misconfiguration",
                    severity=Severity.HIGH.value,
                    title=f"DNS Zone Transfer Enabled for {target}",
                    description="DNS server allows zone transfers, exposing all DNS records",
                    target=target,
                    port=53,
                    service='dns',
                    evidence=stdout[:1000],
                    confidence=0.99,
                    remediation="Restrict zone transfers to authorized secondary nameservers only",
                ))
        
        # Subdomain brute force
        if brute_force:
            brute_cmd = ['dnsrecon', '-d', target, '-t', 'brt']
            if wordlist:
                brute_cmd.extend(['-D', wordlist])
            brute_cmd.extend(['-j', '-'])
            
            stdout, stderr, returncode = await self._run_command(brute_cmd, timeout=600)
            
            if stdout:
                full_output.append(f"=== Subdomain Brute Force ===\n{stdout}")
                findings = self.parse_output(stdout, target)
                all_findings.extend(findings)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output='\n'.join(full_output),
            error='; '.join(errors) if errors else "",
            findings=all_findings,
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse DNSRecon JSON output"""
        findings = []
        
        try:
            # Parse JSON lines
            for line in raw_output.strip().split('\n'):
                if not line.strip() or not line.startswith('{'):
                    continue
                
                try:
                    data = json.loads(line)
                    records = data if isinstance(data, list) else [data]
                    
                    for record in records:
                        record_type = record.get('type', 'A')
                        name = record.get('name', '')
                        address = record.get('address', record.get('target', ''))
                        
                        if not name:
                            continue
                        
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="discovery",
                            severity=Severity.INFO.value,
                            title=f"DNS {record_type} Record: {name}",
                            description=f"DNS record discovered during enumeration",
                            target=target,
                            port=53,
                            service='dns',
                            evidence=f"{record_type} {name} -> {address}",
                            confidence=0.99,
                            metadata={
                                'record_type': record_type,
                                'name': name,
                                'address': address,
                            }
                        ))
                        
                except json.JSONDecodeError:
                    continue
                    
        except Exception as e:
            logger.error(f"Error parsing DNSRecon output: {e}")
            
            # Fallback to text parsing
            for line in raw_output.strip().split('\n'):
                if 'A ' in line or 'MX ' in line or 'NS ' in line:
                    findings.append(Finding(
                        id=self._generate_id(),
                        tool=self.TOOL_NAME,
                        category="discovery",
                        severity=Severity.INFO.value,
                        title=f"DNS Record Found",
                        description=line.strip(),
                        target=target,
                        port=53,
                        service='dns',
                        confidence=0.90,
                    ))
        
        return findings


@ScannerRegistry.register
class ARPScanScanner(BaseScanner):
    """
    ARP-Scan - Fast ARP host discovery
    
    Alternative to netdiscover for fast local network scanning.
    """
    
    TOOL_NAME = "arp-scan"
    PHASE = ScanPhase.DISCOVERY
    REQUIRES_ROOT = True
    
    async def run(self, target: str, interface: str = None, **kwargs) -> ScanResult:
        """
        Run arp-scan for host discovery.
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = ['arp-scan']
        
        if interface:
            cmd.extend(['-I', interface])
        
        cmd.append(target)
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=120)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 and not stdout else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse arp-scan output"""
        findings = []
        
        # Format: IP   MAC   Vendor
        pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+)\s+'  # IP
            r'([0-9a-fA-F:]{17})\s+'     # MAC
            r'(.+)?'                      # Vendor
        )
        
        for line in raw_output.strip().split('\n'):
            match = pattern.match(line.strip())
            if match:
                ip, mac, vendor = match.groups()
                
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="discovery",
                    severity=Severity.INFO.value,
                    title=f"Host discovered: {ip}",
                    description=f"Live host detected via ARP scan",
                    target=ip,
                    evidence=f"MAC: {mac}\nVendor: {vendor or 'Unknown'}",
                    confidence=0.99,
                    metadata={
                        'mac_address': mac,
                        'vendor': vendor.strip() if vendor else 'Unknown',
                    }
                ))
        
        return findings
