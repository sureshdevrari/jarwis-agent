"""
Jarwis AGI Pen Test - Port Scanner Module
Provides various port scanning techniques

Scan Types:
- TCP Connect Scan: Full TCP handshake (reliable, but logged)
- SYN Scan: Half-open scan (stealthy, requires root)
- UDP Scan: For UDP services
- Comprehensive: All of the above
"""

import asyncio
import logging
import socket
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class PortScanResult:
    """Result of a port scan"""
    port: int
    protocol: str  # tcp, udp
    state: str  # open, closed, filtered
    service: str = ""
    reason: str = ""  # Why we think it's in this state


class PortScanner:
    """
    Port scanning module with multiple scan techniques
    """
    
    # Well-known port to service mapping
    PORT_SERVICES = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp',
        69: 'tftp', 80: 'http', 110: 'pop3', 111: 'rpcbind',
        119: 'nntp', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns',
        138: 'netbios-dgm', 139: 'netbios-ssn', 143: 'imap',
        161: 'snmp', 162: 'snmptrap', 179: 'bgp', 389: 'ldap',
        443: 'https', 445: 'microsoft-ds', 465: 'smtps',
        500: 'isakmp', 514: 'syslog', 515: 'printer',
        520: 'rip', 543: 'klogin', 544: 'kshell', 548: 'afp',
        554: 'rtsp', 587: 'submission', 631: 'ipp', 636: 'ldaps',
        873: 'rsync', 993: 'imaps', 995: 'pop3s', 1080: 'socks',
        1194: 'openvpn', 1433: 'mssql', 1434: 'mssql-m',
        1521: 'oracle', 1701: 'l2tp', 1723: 'pptp', 1883: 'mqtt',
        2049: 'nfs', 2082: 'cpanel', 2083: 'cpanel-ssl',
        2181: 'zookeeper', 2222: 'ssh-alt', 3000: 'ppp',
        3306: 'mysql', 3389: 'rdp', 3690: 'svn', 4369: 'epmd',
        5000: 'upnp', 5060: 'sip', 5432: 'postgresql',
        5672: 'amqp', 5900: 'vnc', 5984: 'couchdb', 6379: 'redis',
        6443: 'kubernetes', 6667: 'irc', 7001: 'weblogic',
        8000: 'http-alt', 8008: 'http-alt', 8080: 'http-proxy',
        8443: 'https-alt', 8883: 'mqtt-ssl', 9000: 'cslistener',
        9042: 'cassandra', 9092: 'kafka', 9200: 'elasticsearch',
        9300: 'elasticsearch', 11211: 'memcached', 15672: 'rabbitmq-mgmt',
        27017: 'mongodb', 27018: 'mongodb', 50000: 'sap',
    }

    def __init__(self, config: dict):
        self.config = config
        self.timeout = config.get('timeout', 2.0)
        self.rate_limit = config.get('rate_limit', 100)
        self.scan_type = config.get('scan_type', 'connect')
        self._last_scan_time = 0
    
    async def scan_host(self, ip: str, ports: List[int], protocol: str = 'tcp') -> List[PortScanResult]:
        """Scan multiple ports on a single host"""
        results = []
        
        if protocol == 'tcp':
            if self.scan_type == 'connect':
                results = await self._tcp_connect_scan(ip, ports)
            elif self.scan_type == 'syn':
                results = await self._tcp_syn_scan(ip, ports)
            else:
                results = await self._tcp_connect_scan(ip, ports)
        elif protocol == 'udp':
            results = await self._udp_scan(ip, ports)
        
        return results
    
    async def _tcp_connect_scan(self, ip: str, ports: List[int]) -> List[PortScanResult]:
        """Perform TCP connect scan (full handshake)"""
        results = []
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        
        async def scan_port(port: int) -> PortScanResult:
            async with semaphore:
                await self._rate_limit_wait()
                
                result = PortScanResult(
                    port=port,
                    protocol='tcp',
                    state='closed',
                    service=self.PORT_SERVICES.get(port, 'unknown')
                )
                
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )
                    result.state = 'open'
                    result.reason = 'syn-ack'
                    writer.close()
                    await writer.wait_closed()
                except asyncio.TimeoutError:
                    result.state = 'filtered'
                    result.reason = 'no-response'
                except ConnectionRefusedError:
                    result.state = 'closed'
                    result.reason = 'reset'
                except OSError as e:
                    if 'Network is unreachable' in str(e):
                        result.state = 'filtered'
                        result.reason = 'host-unreachable'
                    else:
                        result.state = 'closed'
                        result.reason = str(e)
                
                return result
        
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        return list(results)
    
    async def _tcp_syn_scan(self, ip: str, ports: List[int]) -> List[PortScanResult]:
        """
        Perform TCP SYN scan (half-open scan)
        Note: Requires raw socket privileges (root/admin)
        Falls back to connect scan if not available
        """
        # SYN scan requires raw sockets which need elevated privileges
        # For now, fall back to connect scan
        logger.warning("SYN scan requires elevated privileges, falling back to connect scan")
        return await self._tcp_connect_scan(ip, ports)
    
    async def _udp_scan(self, ip: str, ports: List[int]) -> List[PortScanResult]:
        """Perform UDP port scan"""
        results = []
        semaphore = asyncio.Semaphore(20)  # Lower concurrency for UDP
        
        async def scan_port(port: int) -> PortScanResult:
            async with semaphore:
                await self._rate_limit_wait()
                
                result = PortScanResult(
                    port=port,
                    protocol='udp',
                    state='open|filtered',  # UDP is tricky - no response could mean open
                    service=self.PORT_SERVICES.get(port, 'unknown')
                )
                
                try:
                    # Create UDP socket
                    loop = asyncio.get_event_loop()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setblocking(False)
                    sock.settimeout(self.timeout)
                    
                    # Send empty packet or service-specific probe
                    probe = self._get_udp_probe(port)
                    await loop.sock_sendto(sock, probe, (ip, port))
                    
                    try:
                        # Wait for response
                        data = await asyncio.wait_for(
                            loop.sock_recv(sock, 1024),
                            timeout=self.timeout
                        )
                        result.state = 'open'
                        result.reason = 'udp-response'
                    except asyncio.TimeoutError:
                        result.state = 'open|filtered'
                        result.reason = 'no-response'
                    
                    sock.close()
                    
                except Exception as e:
                    result.state = 'closed'
                    result.reason = str(e)
                
                return result
        
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        return list(results)
    
    def _get_udp_probe(self, port: int) -> bytes:
        """Get appropriate UDP probe for specific services"""
        probes = {
            53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS
            123: b'\x1b' + b'\x00' * 47,  # NTP
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05+\x06\x01\x02\x01\x05\x00',  # SNMP
            500: b'\x00' * 28,  # ISAKMP
        }
        return probes.get(port, b'\x00')
    
    async def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        current_time = time.time()
        min_interval = 1.0 / self.rate_limit
        elapsed = current_time - self._last_scan_time
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_scan_time = time.time()
    
    def get_common_ports(self) -> List[int]:
        """Return list of commonly scanned ports"""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
            8443, 27017
        ]
    
    def get_all_ports(self) -> List[int]:
        """Return all TCP ports"""
        return list(range(1, 65536))
