"""
Jarwis AGI Pen Test - Service Detection Module
Identifies services and versions running on open ports
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Information about a detected service"""
    port: int
    protocol: str
    service: str
    version: str = ""
    product: str = ""
    extra_info: str = ""
    banner: str = ""
    cpe: str = ""  # Common Platform Enumeration
    confidence: int = 0  # 0-100


class ServiceDetector:
    """
    Detects services and versions on open ports
    Uses banner grabbing and protocol-specific probes
    """
    
    # Service probes - send these to elicit responses
    SERVICE_PROBES = {
        'http': b'HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n',
        'ftp': b'',  # FTP sends banner on connect
        'ssh': b'',  # SSH sends banner on connect
        'smtp': b'EHLO jarwis\r\n',
        'pop3': b'',  # POP3 sends banner on connect
        'imap': b'',  # IMAP sends banner on connect
        'redis': b'INFO\r\n',
        'mysql': b'',  # MySQL sends greeting on connect
        'mongodb': b'\x3a\x00\x00\x00\xa7\x41\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00',
    }
    
    # Version extraction patterns
    VERSION_PATTERNS = {
        'openssh': [
            r'SSH-[\d.]+-OpenSSH[_-]?([\d.p]+)',
            r'OpenSSH[_-]?([\d.p]+)',
        ],
        'apache': [
            r'Apache/([\d.]+)',
            r'Server:\s*Apache/([\d.]+)',
        ],
        'nginx': [
            r'nginx/([\d.]+)',
            r'Server:\s*nginx/([\d.]+)',
        ],
        'microsoft-iis': [
            r'Microsoft-IIS/([\d.]+)',
            r'Server:\s*Microsoft-IIS/([\d.]+)',
        ],
        'vsftpd': [
            r'vsftpd\s+([\d.]+)',
        ],
        'proftpd': [
            r'ProFTPD\s+([\d.]+)',
        ],
        'pure-ftpd': [
            r'Pure-FTPd',
        ],
        'mysql': [
            r'^.\x00\x00\x00\x0a([\d.]+)',
            r'mysql[_-]?([\d.]+)',
        ],
        'postgresql': [
            r'PostgreSQL\s+([\d.]+)',
        ],
        'redis': [
            r'redis_version:([\d.]+)',
        ],
        'mongodb': [
            r'MongoDB\s+([\d.]+)',
            r'"version"\s*:\s*"([\d.]+)"',
        ],
        'tomcat': [
            r'Apache-Coyote/([\d.]+)',
            r'Apache Tomcat/([\d.]+)',
        ],
    }
    
    def __init__(self, config: dict):
        self.config = config
        self.timeout = config.get('timeout', 5.0)
    
    async def detect_services(self, ip: str, open_ports: List[int]) -> Dict[int, ServiceInfo]:
        """Detect services on all open ports"""
        results = {}
        
        tasks = [self.detect_service(ip, port) for port in open_ports]
        service_infos = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, info in zip(open_ports, service_infos):
            if isinstance(info, ServiceInfo):
                results[port] = info
            else:
                results[port] = ServiceInfo(
                    port=port,
                    protocol='tcp',
                    service='unknown',
                    confidence=0
                )
        
        return results
    
    async def detect_service(self, ip: str, port: int) -> ServiceInfo:
        """Detect service on a specific port"""
        service_info = ServiceInfo(
            port=port,
            protocol='tcp',
            service=self._guess_service_by_port(port),
            confidence=30
        )
        
        try:
            # Connect and grab banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # Try to read initial banner (some services send on connect)
            try:
                banner = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=2.0
                )
                service_info.banner = banner.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                # Need to send probe
                probe = self._get_probe_for_port(port)
                if probe:
                    writer.write(probe)
                    await writer.drain()
                    try:
                        banner = await asyncio.wait_for(
                            reader.read(4096),
                            timeout=3.0
                        )
                        service_info.banner = banner.decode('utf-8', errors='ignore').strip()
                    except asyncio.TimeoutError:
                        pass
            
            writer.close()
            await writer.wait_closed()
            
            # Parse banner for service and version
            if service_info.banner:
                parsed = self._parse_banner(service_info.banner, port)
                service_info.service = parsed.get('service', service_info.service)
                service_info.version = parsed.get('version', '')
                service_info.product = parsed.get('product', '')
                service_info.extra_info = parsed.get('extra_info', '')
                service_info.cpe = self._generate_cpe(parsed)
                service_info.confidence = parsed.get('confidence', 70)
            
        except Exception as e:
            logger.debug(f"Service detection failed for {ip}:{port}: {e}")
        
        return service_info
    
    def _guess_service_by_port(self, port: int) -> str:
        """Guess service name based on port number"""
        port_services = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 445: 'smb', 993: 'imaps',
            995: 'pop3s', 1433: 'mssql', 1521: 'oracle', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
            8080: 'http-proxy', 27017: 'mongodb'
        }
        return port_services.get(port, 'unknown')
    
    def _get_probe_for_port(self, port: int) -> Optional[bytes]:
        """Get appropriate probe for port"""
        if port in [80, 8080, 8000, 8443, 443]:
            return self.SERVICE_PROBES['http']
        elif port == 25:
            return self.SERVICE_PROBES['smtp']
        elif port == 6379:
            return self.SERVICE_PROBES['redis']
        return None
    
    def _parse_banner(self, banner: str, port: int) -> Dict:
        """Parse banner to extract service information"""
        result = {
            'service': self._guess_service_by_port(port),
            'version': '',
            'product': '',
            'extra_info': '',
            'confidence': 50
        }
        
        banner_lower = banner.lower()
        
        # Check for common products/services
        for product, patterns in self.VERSION_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result['product'] = product
                    result['version'] = match.group(1) if match.groups() else ''
                    result['confidence'] = 90
                    break
            if result['version']:
                break
        
        # Service-specific detection
        if 'SSH-' in banner:
            result['service'] = 'ssh'
            result['confidence'] = 95
        elif 'HTTP/' in banner:
            result['service'] = 'https' if port == 443 else 'http'
            result['confidence'] = 95
        elif '+OK' in banner or 'POP3' in banner.upper():
            result['service'] = 'pop3'
            result['confidence'] = 90
        elif '* OK' in banner or 'IMAP' in banner.upper():
            result['service'] = 'imap'
            result['confidence'] = 90
        elif 'FTP' in banner.upper() or '220 ' in banner:
            result['service'] = 'ftp'
            result['confidence'] = 85
        elif 'SMTP' in banner.upper() or 'ESMTP' in banner.upper():
            result['service'] = 'smtp'
            result['confidence'] = 90
        elif 'redis_version' in banner_lower:
            result['service'] = 'redis'
            result['confidence'] = 95
        elif 'mysql' in banner_lower:
            result['service'] = 'mysql'
            result['confidence'] = 90
        elif 'postgresql' in banner_lower:
            result['service'] = 'postgresql'
            result['confidence'] = 90
        
        return result
    
    def _generate_cpe(self, parsed: Dict) -> str:
        """Generate CPE (Common Platform Enumeration) string"""
        if not parsed.get('product') or not parsed.get('version'):
            return ''
        
        product = parsed['product'].lower().replace(' ', '_')
        version = parsed['version']
        
        return f"cpe:/a:{product}:{product}:{version}"
