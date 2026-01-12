"""
Jarwis AGI Pen Test - HTTP Request Smuggling Scanner
Detects HTTP Request Smuggling vulnerabilities (A05:2021 - Security Misconfiguration)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import socket
import ssl as ssl_module
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
import time

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


class HTTPSmugglingScanner:
    """
    Scans for HTTP Request Smuggling vulnerabilities
    OWASP A05:2021 - Security Misconfiguration
    CWE-444: Inconsistent Interpretation of HTTP Requests
    
    Attack vectors:
    - CL.TE (Content-Length vs Transfer-Encoding)
    - TE.CL (Transfer-Encoding vs Content-Length)
    - TE.TE (Transfer-Encoding obfuscation)
    - HTTP/2 Downgrade attacks
    - HTTP/0.9 desync
    """
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting HTTP Request Smuggling scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        parsed = urlparse(base_url)
        host = parsed.netloc
        port = 443 if parsed.scheme == 'https' else 80
        use_ssl = parsed.scheme == 'https'
        
        # Extract just host without port
        if ':' in host:
            host, port_str = host.split(':')
            port = int(port_str)
        
        # Test for various smuggling techniques
        await self._test_cl_te(host, port, use_ssl, parsed.path or '/')
        await self._test_te_cl(host, port, use_ssl, parsed.path or '/')
        await self._test_te_te(host, port, use_ssl, parsed.path or '/')
        await self._test_h2c_smuggling(host, port, use_ssl, parsed.path or '/')
        
        logger.info(f"HTTP Smuggling scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _send_raw_request(self, host: str, port: int, use_ssl: bool, request: bytes, timeout: float = 10) -> tuple:
        """Send raw HTTP request and get response"""
        response = b""
        response_time = 0
        
        try:
            # Run in thread to avoid blocking
            loop = asyncio.get_event_loop()
            response, response_time = await asyncio.wait_for(
                loop.run_in_executor(
                    None, 
                    self._sync_send_request, 
                    host, port, use_ssl, request, timeout
                ),
                timeout=timeout + 2
            )
        except asyncio.TimeoutError:
            response_time = timeout
        except Exception as e:
            logger.debug(f"Request error: {e}")
        
        return response, response_time
    
    def _sync_send_request(self, host: str, port: int, use_ssl: bool, request: bytes, timeout: float) -> tuple:
        """Synchronous request sender"""
        response = b""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            if use_ssl:
                context = ssl_module.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl_module.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.sendall(request)
            
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            
            sock.close()
            
        except Exception as e:
            logger.debug(f"Socket error: {e}")
        
        return response, time.time() - start_time
    
    async def _test_cl_te(self, host: str, port: int, use_ssl: bool, path: str):
        """Test for CL.TE smuggling"""
        # CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
        
        # Timing-based detection
        # The back-end will wait for chunked data that never comes
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        ).encode()
        
        await asyncio.sleep(1 / self.rate_limit)
        response, response_time = await self._send_raw_request(host, port, use_ssl, request, timeout=5)
        
        # If response takes significantly longer, might be vulnerable
        if response_time >= 5:
            result = ScanResult(
                id=f"SMUGGLE-CLTE-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="critical",
                title="HTTP Request Smuggling (CL.TE) - Timing Based",
                description="Potential CL.TE HTTP request smuggling detected via timing. Front-end uses Content-Length, back-end uses Transfer-Encoding.",
                url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                method="POST",
                evidence=f"Response took {response_time:.2f}s (expected timeout)",
                remediation="Configure front-end to reject ambiguous requests. Use HTTP/2 end-to-end.",
                cwe_id="CWE-444",
                poc=request.decode('utf-8', errors='replace'),
                reasoning="Response delay indicates backend waiting for chunked data"
            )
            self.results.append(result)
            return
        
        # Differential response test
        # Send a smuggled request that affects subsequent requests
        smuggle_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()
        
        await asyncio.sleep(1 / self.rate_limit)
        response, _ = await self._send_raw_request(host, port, use_ssl, smuggle_request)
        
        # Check if we got multiple responses
        if response.count(b"HTTP/1.") >= 2:
            result = ScanResult(
                id=f"SMUGGLE-CLTE-DIFF-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="critical",
                title="HTTP Request Smuggling (CL.TE) Confirmed",
                description="CL.TE HTTP request smuggling confirmed. Attacker can inject malicious requests.",
                url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                method="POST",
                evidence="Multiple HTTP responses received from single request",
                remediation="Configure servers consistently. Reject ambiguous requests.",
                cwe_id="CWE-444",
                poc=smuggle_request.decode('utf-8', errors='replace'),
                reasoning="Multiple responses indicate request smuggling success"
            )
            self.results.append(result)
    
    async def _test_te_cl(self, host: str, port: int, use_ssl: bool, path: str):
        """Test for TE.CL smuggling"""
        # TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
        
        # Timing-based detection
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()
        
        await asyncio.sleep(1 / self.rate_limit)
        response, response_time = await self._send_raw_request(host, port, use_ssl, request, timeout=5)
        
        if response_time >= 5:
            result = ScanResult(
                id=f"SMUGGLE-TECL-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="critical",
                title="HTTP Request Smuggling (TE.CL) - Timing Based",
                description="Potential TE.CL HTTP request smuggling detected. Front-end uses Transfer-Encoding, back-end uses Content-Length.",
                url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                method="POST",
                evidence=f"Response took {response_time:.2f}s",
                remediation="Configure all servers to use same header parsing. Reject ambiguous requests.",
                cwe_id="CWE-444",
                poc=request.decode('utf-8', errors='replace'),
                reasoning="Response delay indicates content-length/chunked mismatch"
            )
            self.results.append(result)
    
    async def _test_te_te(self, host: str, port: int, use_ssl: bool, path: str):
        """Test for TE.TE smuggling with obfuscation"""
        # Try various Transfer-Encoding obfuscation techniques
        
        te_obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked ",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: chunked\nX: X",
            "Transfer-encoding: chunked",
            "TRANSFER-ENCODING: chunked",
            "Transfer-Encoding: \nchunked",
            "X: X\nTransfer-Encoding: chunked",
            "Transfer-Encoding\n: chunked",
        ]
        
        for te_header in te_obfuscations:
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST {path} HTTP/1.1\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()
            
            await asyncio.sleep(1 / self.rate_limit)
            response, _ = await self._send_raw_request(host, port, use_ssl, request)
            
            # Check for signs of smuggling
            if b"Method Not Allowed" in response or b"Unknown method" in response:
                result = ScanResult(
                    id=f"SMUGGLE-TETE-{len(self.results)+1}",
                    category="A05:2021 - Security Misconfiguration",
                    severity="critical",
                    title="HTTP Request Smuggling (TE.TE) with Obfuscation",
                    description=f"TE.TE smuggling via obfuscated Transfer-Encoding header. Obfuscation: {te_header}",
                    url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                    method="POST",
                    evidence=response[:200].decode('utf-8', errors='replace'),
                    remediation="Normalize and validate Transfer-Encoding headers strictly.",
                    cwe_id="CWE-444",
                    poc=request.decode('utf-8', errors='replace'),
                    reasoning="Obfuscated TE header caused request interpretation difference"
                )
                self.results.append(result)
                return
    
    async def _test_h2c_smuggling(self, host: str, port: int, use_ssl: bool, path: str):
        """Test for HTTP/2 cleartext (h2c) smuggling"""
        # H2C smuggling via Upgrade header
        
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"\r\n"
        ).encode()
        
        await asyncio.sleep(1 / self.rate_limit)
        response, _ = await self._send_raw_request(host, port, use_ssl, request)
        
        if b"101 Switching Protocols" in response or b"upgrade" in response.lower():
            result = ScanResult(
                id=f"SMUGGLE-H2C-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="high",
                title="HTTP/2 Cleartext (h2c) Upgrade Allowed",
                description="Server accepts h2c upgrade requests, which may enable request smuggling attacks.",
                url=f"{'https' if use_ssl else 'http'}://{host}:{port}{path}",
                method="GET",
                evidence=response[:200].decode('utf-8', errors='replace'),
                remediation="Disable h2c upgrades on external-facing servers.",
                cwe_id="CWE-444",
                poc=request.decode('utf-8', errors='replace'),
                reasoning="Server accepted h2c upgrade header"
            )
            self.results.append(result)


class CachePoisoningScanner:
    """
    Scans for HTTP Cache Poisoning vulnerabilities
    OWASP A05:2021 - Security Misconfiguration
    
    Attack vectors:
    - Unkeyed headers
    - Unkeyed query parameters
    - Host header manipulation
    - X-Forwarded-* poisoning
    """
    
    # Headers that might be unkeyed but reflected
    UNKEYED_HEADERS = [
        ('X-Forwarded-Host', 'evil.com'),
        ('X-Forwarded-Server', 'evil.com'),
        ('X-Forwarded-Scheme', 'nothttps'),
        ('X-Original-URL', '/admin'),
        ('X-Rewrite-URL', '/admin'),
        ('X-Host', 'evil.com'),
        ('X-Forwarded-Port', '1337'),
        ('X-Forwarded-Prefix', '/prefix'),
        ('X-Forwarded-Proto', 'http'),
        ('X-Original-Host', 'evil.com'),
        ('X-HTTP-Method-Override', 'POST'),
        ('X-Custom-Header', '<script>alert(1)</script>'),
        ('True-Client-IP', '127.0.0.1'),
        ('X-Client-IP', '127.0.0.1'),
        ('X-Real-IP', '127.0.0.1'),
        ('CF-Connecting-IP', '127.0.0.1'),
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl_module.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl_module.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting HTTP Cache Poisoning scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        import aiohttp
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            await self._test_unkeyed_headers(session, base_url)
            await self._test_parameter_cloaking(session, base_url)
        
        logger.info(f"Cache poisoning scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_unkeyed_headers(self, session, base_url: str):
        """Test for unkeyed headers that are reflected"""
        import aiohttp
        
        cache_buster = f"cachebust{int(time.time())}"
        
        for header_name, header_value in self.UNKEYED_HEADERS:
            test_url = f"{base_url}?cb={cache_buster}"
            cache_buster = f"cb{int(time.time() * 1000)}"  # New cache buster each time
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                headers = {
                    header_name: header_value,
                    'User-Agent': 'Mozilla/5.0'
                }
                
                async with session.get(test_url, headers=headers) as response:
                    body = await response.text()
                    cache_control = response.headers.get('Cache-Control', '')
                    x_cache = response.headers.get('X-Cache', '')
                    
                    # Check if header value is reflected
                    if header_value in body:
                        # Check if response is cached
                        is_cacheable = any([
                            'max-age' in cache_control and 'no-cache' not in cache_control,
                            'public' in cache_control,
                            'HIT' in x_cache.upper(),
                        ])
                        
                        severity = 'critical' if is_cacheable else 'medium'
                        
                        result = ScanResult(
                            id=f"CACHE-POISON-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity=severity,
                            title=f"Cache Poisoning via {header_name}",
                            description=f"The {header_name} header is reflected in the response and may be unkeyed by the cache.",
                            url=base_url,
                            method="GET",
                            parameter=header_name,
                            evidence=f"{header_name}: {header_value} reflected in response",
                            remediation="Include security-relevant headers in cache key or don't reflect them.",
                            cwe_id="CWE-349",
                            poc=f"curl -H '{header_name}: {header_value}' '{base_url}'",
                            reasoning="Unkeyed header reflected in cached response"
                        )
                        self.results.append(result)
                        
            except Exception as e:
                logger.debug(f"Cache poison test error: {e}")
    
    async def _test_parameter_cloaking(self, session, base_url: str):
        """Test for parameter cloaking/pollution in cache"""
        import aiohttp
        
        # Test various parameter delimiters
        tests = [
            # Semicolon delimiter
            f"{base_url}?a=1;b=2",
            # Null byte
            f"{base_url}?a=1%00b=2",
            # Line break
            f"{base_url}?a=1%0d%0ab=2",
            # URL encoding variations
            f"{base_url}?a=1%26b=2",
        ]
        
        for test_url in tests:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                async with session.get(test_url) as response:
                    cache_control = response.headers.get('Cache-Control', '')
                    
                    if 'max-age' in cache_control or 'public' in cache_control:
                        result = ScanResult(
                            id=f"CACHE-PARAM-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity="low",
                            title="Potential Parameter Cloaking in Cache",
                            description="Response with unusual parameter delimiters is cacheable.",
                            url=test_url,
                            method="GET",
                            evidence=f"Cache-Control: {cache_control}",
                            remediation="Normalize query parameters before caching.",
                            cwe_id="CWE-349",
                            reasoning="Unusual parameter syntax accepted and cached"
                        )
                        self.results.append(result)
                        break
                        
            except Exception:
                pass
