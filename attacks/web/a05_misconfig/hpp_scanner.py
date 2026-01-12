"""
Jarwis AGI Pen Test - HTTP Parameter Pollution Scanner
Detects HPP vulnerabilities (A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin
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


class HTTPParameterPollutionScanner:
    """
    Scans for HTTP Parameter Pollution vulnerabilities
    OWASP A03:2021 - Injection
    CWE-235: Improper Handling of Extra Parameters
    
    Based on Web Hacking 101 HPP techniques:
    - HackerOne Social Sharing HPP
    - Twitter unsubscribe notification bypass
    """
    
    # Sensitive parameters that might be exploitable via HPP
    SENSITIVE_PARAMS = [
        # Auth-related
        'user', 'user_id', 'userid', 'uid', 'id', 'account', 'account_id',
        'email', 'username', 'login', 'password', 'pass', 'pwd',
        'token', 'access_token', 'auth', 'auth_token', 'api_key', 'apikey',
        'session', 'session_id', 'sessionid', 'sid',
        
        # Transaction-related
        'amount', 'price', 'cost', 'total', 'value', 'quantity', 'qty',
        'from', 'to', 'sender', 'receiver', 'source', 'destination',
        'account_number', 'card', 'card_number', 'cvv',
        
        # Access control
        'role', 'admin', 'privilege', 'permission', 'access', 'level',
        'group', 'type', 'status', 'approved', 'verified', 'active',
        
        # Actions
        'action', 'cmd', 'command', 'do', 'func', 'function', 'method',
        'mode', 'operation', 'op', 'task', 'step',
        
        # Redirect/URL
        'url', 'redirect', 'next', 'return', 'callback', 'goto', 'link',
        
        # File operations
        'file', 'filename', 'path', 'folder', 'dir', 'directory',
        
        # Search/Filter
        'search', 'query', 'q', 'filter', 'sort', 'order', 'limit', 'offset',
        
        # Social
        'share', 'post', 'tweet', 'message', 'comment', 'content',
        
        # API
        'api_version', 'version', 'v', 'format', 'output', 'response_type',
    ]
    
    # HPP test strategies
    HPP_STRATEGIES = [
        ('duplicate', 'Duplicate parameter with different value'),
        ('array', 'Array notation parameter'),
        ('encoded', 'URL-encoded duplicate'),
        ('mixed_case', 'Mixed case parameter name'),
        ('null_byte', 'Null byte injection'),
        ('bracket', 'Bracket notation'),
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.browser = None
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method - tests for HTTP Parameter Pollution"""
        logger.info("Starting HTTP Parameter Pollution scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            logger.warning("No target URL configured for HPP scan")
            return self.results
        
        # Collect URLs with parameters
        urls_to_test = []
        
        # From crawler endpoints
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if url and '?' in url:
                    urls_to_test.append(url)
        
        # Also test base URL with common params
        urls_to_test.append(base_url)
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            headers=self.DEFAULT_HEADERS,
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url in urls_to_test[:50]:  # Limit URLs
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    await self._test_hpp(session, url)
                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")
        
        logger.info(f"HPP scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_hpp(self, session: aiohttp.ClientSession, url: str):
        """Test URL for HTTP Parameter Pollution"""
        parsed = urlparse(url)
        
        # Get existing parameters
        params = parse_qs(parsed.query) if parsed.query else {}
        
        # Test existing params and sensitive params
        params_to_test = list(params.keys()) + self.SENSITIVE_PARAMS[:10]
        
        for param in set(params_to_test):
            await self._test_parameter_pollution(session, url, param, params)
    
    async def _test_parameter_pollution(self, session: aiohttp.ClientSession, url: str, 
                                         param: str, existing_params: dict):
        """Test specific parameter for pollution vulnerability"""
        parsed = urlparse(url)
        original_value = existing_params.get(param, ['test'])[0]
        polluted_value = 'JARWIS_HPP_TEST'
        
        # Strategy 1: Duplicate parameter (most common HPP)
        # Some backends take first, some take last, some concatenate
        test_queries = [
            # First value - second value
            f"{param}={original_value}&{param}={polluted_value}",
            # Second value - first value  
            f"{param}={polluted_value}&{param}={original_value}",
            # Array notation
            f"{param}[]={original_value}&{param}[]={polluted_value}",
            # Bracket with index
            f"{param}[0]={original_value}&{param}[1]={polluted_value}",
        ]
        
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        
        # First get baseline response
        try:
            baseline_query = f"{param}={original_value}"
            async with session.get(f"{base_url}?{baseline_query}") as baseline_resp:
                baseline_status = baseline_resp.status
                baseline_body = await baseline_resp.text()
                baseline_length = len(baseline_body)
        except Exception:
            return
        
        # Test each pollution strategy
        for i, test_query in enumerate(test_queries):
            try:
                test_url = f"{base_url}?{test_query}"
                
                async with session.get(test_url) as response:
                    status = response.status
                    body = await response.text()
                    
                    # Check if polluted value appears in response
                    if polluted_value in body:
                        result = ScanResult(
                            id=f"HPP-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="medium",
                            title=f"HTTP Parameter Pollution in {param}",
                            description=f"The application accepts duplicate {param} parameters and the polluted value appears in the response. This may allow bypassing security filters or modifying application logic.",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence=f"Polluted value '{polluted_value}' reflected in response",
                            remediation="Explicitly handle duplicate parameters. Use the first occurrence only or reject requests with duplicate parameters.",
                            cwe_id="CWE-235",
                            poc=f"curl '{test_url}'",
                            reasoning=f"Parameter pollution accepted. Strategy: {self.HPP_STRATEGIES[i][1]}"
                        )
                        self.results.append(result)
                        return
                    
                    # Check for significant behavior change
                    if abs(len(body) - baseline_length) > 100 or status != baseline_status:
                        result = ScanResult(
                            id=f"HPP-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="low",
                            title=f"Potential HPP Behavior Change in {param}",
                            description=f"The application shows different behavior when {param} is duplicated.",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence=f"Status: {baseline_status} -> {status}, Length: {baseline_length} -> {len(body)}",
                            remediation="Review how duplicate parameters are handled.",
                            cwe_id="CWE-235",
                            poc=f"curl '{test_url}'",
                            reasoning=f"Different response detected with duplicate parameters"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"HPP test error: {e}")
    
    async def _test_post_hpp(self, session: aiohttp.ClientSession, url: str, 
                             form_data: dict, param: str):
        """Test POST parameter pollution"""
        original_value = form_data.get(param, 'test')
        polluted_value = 'JARWIS_HPP_POST'
        
        # Create polluted form data with duplicate keys
        # Using aiohttp FormData for proper multivalue support
        form = aiohttp.FormData()
        
        for key, value in form_data.items():
            if key == param:
                form.add_field(key, original_value)
                form.add_field(key, polluted_value)  # Duplicate
            else:
                form.add_field(key, value)
        
        try:
            async with session.post(url, data=form) as response:
                body = await response.text()
                
                if polluted_value in body:
                    result = ScanResult(
                        id=f"HPP-POST-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="medium",
                        title=f"POST HTTP Parameter Pollution in {param}",
                        description=f"POST parameter {param} can be polluted with duplicate values.",
                        url=url,
                        method="POST",
                        parameter=param,
                        evidence=f"Polluted value reflected in response",
                        remediation="Handle duplicate POST parameters explicitly.",
                        cwe_id="CWE-235",
                        poc=f"POST {url} with duplicate {param} values"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"POST HPP test error: {e}")
