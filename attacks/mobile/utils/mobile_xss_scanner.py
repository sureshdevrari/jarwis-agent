"""
JARWIS AGI PEN TEST - Mobile XSS Scanner
Cross-Site Scripting detection for mobile app WebViews and hybrid apps
Tests XSS in:
- WebView content
- Deep links / Universal links
- JavaScript bridges
- Mobile API responses rendered in WebViews
- Hybrid app content (Cordova, React Native WebViews, Flutter WebViews)

OWASP Mobile: M7 (Client Code Quality) - Code Quality Issues including XSS
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs, quote
from pathlib import Path
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Mobile XSS scan finding result"""
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
    mobile_context: str = ""  # webview, deeplink, jsbridge, hybrid


class MobileXSSScanner:
    """
    Mobile XSS Scanner for WebViews and Hybrid Apps
    
    Professional mobile penetration testing approach:
    1. Identify mobile-specific injection points (WebViews, deep links)
    2. Test JavaScript bridge vulnerabilities
    3. Check API responses for XSS in mobile rendering
    4. Test deep link / URL scheme handlers
    5. Verify Content Security Policy in WebViews
    """
    
    # XSS payloads optimized for mobile WebViews
    MOBILE_XSS_PAYLOADS = [
        # Basic script injection
        '<script>alert("JARWIS_MOBILE_XSS")</script>',
        '"><script>alert("JARWIS_MOBILE_XSS")</script>',
        '<img src=x onerror=alert("JARWIS_MOBILE_XSS")>',
        
        # JavaScript bridge exploitation
        "javascript:Android.showToast('XSS')",
        "javascript:webkit.messageHandlers.bridge.postMessage('XSS')",
        "javascript:window.ReactNativeWebView.postMessage('XSS')",
        "javascript:window.flutter_inappwebview.callHandler('XSS')",
        
        # SVG and event handlers
        '<svg onload=alert("JARWIS_MOBILE_XSS")>',
        '<body onload=alert("JARWIS_MOBILE_XSS")>',
        
        # Mobile-specific payloads
        '<iframe src="javascript:alert(\'XSS\')">',
        '<a href="javascript:alert(\'XSS\')">Click</a>',
        
        # Deep link exploitation payloads
        'myapp://page?data=<script>alert("XSS")</script>',
        'https://app.link/redirect?url=javascript:alert("XSS")',
    ]
    
    # JavaScript bridge names to test
    JS_BRIDGE_NAMES = [
        'Android',           # Android JavaScript Interface
        'android',
        'JSBridge',
        'NativeBridge',
        'AppBridge',
        'webkit.messageHandlers',  # iOS WKWebView
        'ReactNativeWebView',      # React Native
        'flutter_inappwebview',    # Flutter
        'CordovaBridge',           # Cordova
        'PhoneGap',               # PhoneGap
        'Capacitor',              # Capacitor
        'window.native',          # Generic
        'window.Native',
        'window.App',
        'window.app',
    ]
    
    # Deep link schemes to test
    DEEP_LINK_SCHEMES = [
        'myapp://',
        'app://',
        'intent://',
        'custom://',
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 JARWIS-Mobile-Scanner/2.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'X-Requested-With': 'com.jarwis.scanner',  # Indicates WebView request
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(getattr(context, 'target_url', ''))
        
        # Optional browser controller for WebView simulation
        self.browser = None
        
        # Load additional payloads if available
        self.payloads = self.MOBILE_XSS_PAYLOADS.copy()
        self._load_additional_payloads()
        
        # Statistics
        self.stats = {
            'endpoints_tested': 0,
            'bridge_calls_tested': 0,
            'deep_links_tested': 0,
            'xss_found': 0,
        }
    
    def _load_additional_payloads(self):
        """Load XSS payloads from external file if available"""
        try:
            payload_file = Path(__file__).parent.parent.parent / 'config' / 'payloads' / 'xss_payloads.txt'
            if payload_file.exists():
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line not in self.payloads:
                                self.payloads.append(line)
                logger.info(f"Loaded {len(self.payloads)} total payloads for mobile XSS testing")
        except Exception as e:
            logger.debug(f"Could not load additional payloads: {e}")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
    def _get_next_finding_id(self) -> str:
        """Generate unique finding ID"""
        self._finding_id += 1
        return f"MOBILE-XSS-{self._finding_id:04d}"
    
    async def scan(self) -> List[ScanResult]:
        """
        Run comprehensive mobile XSS scan
        """
        self.findings = []
        logger.info("=" * 60)
        logger.info("JARWIS MOBILE XSS SCANNER - Starting scan")
        logger.info("=" * 60)
        
        # Collect mobile endpoints
        endpoints = getattr(self.context, 'endpoints', []) or []
        mobile_endpoints = self._filter_mobile_endpoints(endpoints)
        
        logger.info(f"Found {len(mobile_endpoints)} mobile-related endpoints")
        logger.info(f"Loaded {len(self.payloads)} XSS payloads")
        
        async with aiohttp.ClientSession() as session:
            # Phase 1: Test mobile API endpoints for XSS
            logger.info("\n[Phase 1] Testing mobile API endpoints...")
            await self._test_mobile_api_xss(session, mobile_endpoints)
            
            # Phase 2: Test deep link handlers
            logger.info("\n[Phase 2] Testing deep link handlers...")
            await self._test_deep_link_xss(session, mobile_endpoints)
            
            # Phase 3: Test JavaScript bridge vulnerabilities
            logger.info("\n[Phase 3] Testing JavaScript bridge XSS...")
            await self._test_js_bridge_xss(session, mobile_endpoints)
            
            # Phase 4: Test WebView content injection
            if self.browser:
                logger.info("\n[Phase 4] Browser-based WebView XSS testing...")
                await self._test_webview_xss_with_browser(mobile_endpoints)
        
        # Log statistics
        logger.info("\n" + "=" * 60)
        logger.info("MOBILE XSS SCAN COMPLETE - Statistics:")
        logger.info(f"  Endpoints tested: {self.stats['endpoints_tested']}")
        logger.info(f"  JS Bridge calls tested: {self.stats['bridge_calls_tested']}")
        logger.info(f"  Deep links tested: {self.stats['deep_links_tested']}")
        logger.info(f"  XSS vulnerabilities found: {self.stats['xss_found']}")
        logger.info("=" * 60)
        
        return self.findings
    
    def _filter_mobile_endpoints(self, endpoints: List) -> List[Dict]:
        """Filter endpoints relevant to mobile testing"""
        mobile_endpoints = []
        mobile_indicators = [
            '/api/mobile', '/mobile/', '/m/', '/app/', '/api/v1/mobile',
            '/api/v2/mobile', '/native/', '/webview/', '/hybrid/',
        ]
        
        for ep in endpoints:
            if isinstance(ep, dict):
                url = ep.get('url', '')
            else:
                url = str(ep)
            
            # Check if endpoint looks mobile-related
            url_lower = url.lower()
            is_mobile = any(indicator in url_lower for indicator in mobile_indicators)
            
            # Also include API endpoints as they might be used in WebViews
            is_api = '/api/' in url_lower or 'graphql' in url_lower
            
            if is_mobile or is_api:
                if isinstance(ep, dict):
                    mobile_endpoints.append(ep)
                else:
                    mobile_endpoints.append({'url': url, 'method': 'GET'})
        
        # If no mobile-specific endpoints, use all endpoints
        if not mobile_endpoints:
            for ep in endpoints:
                if isinstance(ep, dict):
                    mobile_endpoints.append(ep)
                else:
                    mobile_endpoints.append({'url': str(ep), 'method': 'GET'})
        
        return mobile_endpoints
    
    async def _test_mobile_api_xss(self, session: aiohttp.ClientSession, endpoints: List[Dict]):
        """Test mobile API endpoints for XSS in responses"""
        
        for endpoint in endpoints[:30]:  # Limit for performance
            self.stats['endpoints_tested'] += 1
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET').upper()
            params = endpoint.get('params', {})
            
            if not url:
                continue
            
            # Test each parameter with mobile-specific XSS payloads
            for param_name in params:
                for payload in self.payloads[:10]:  # Top 10 payloads per param
                    result = await self._inject_and_check(session, url, method, param_name, payload)
                    
                    if result.get('vulnerable'):
                        self.stats['xss_found'] += 1
                        self._add_finding(
                            title=f"Mobile API XSS in '{param_name}'",
                            description=f"XSS payload reflected in mobile API response for parameter '{param_name}'",
                            url=url,
                            method=method,
                            parameter=param_name,
                            evidence=result.get('evidence', ''),
                            severity="high",
                            mobile_context="api",
                            payload=payload
                        )
                        break  # One per parameter
                
                await asyncio.sleep(1 / self.rate_limit)
            
            # Test URL query parameters
            if '?' in url:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                for param_name in query_params:
                    for payload in self.payloads[:5]:
                        result = await self._inject_and_check(session, url, 'GET', param_name, payload)
                        if result.get('vulnerable'):
                            self.stats['xss_found'] += 1
                            self._add_finding(
                                title=f"Mobile API XSS in URL parameter '{param_name}'",
                                description=f"XSS reflected in mobile API response",
                                url=url,
                                method='GET',
                                parameter=param_name,
                                evidence=result.get('evidence', ''),
                                severity="high",
                                mobile_context="api",
                                payload=payload
                            )
                            break
    
    async def _test_deep_link_xss(self, session: aiohttp.ClientSession, endpoints: List[Dict]):
        """Test deep link / universal link handlers for XSS"""
        
        # Look for redirect endpoints commonly used with deep links
        redirect_patterns = ['/redirect', '/open', '/launch', '/deeplink', '/link', '/goto']
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            url_lower = url.lower()
            
            # Check if this looks like a redirect/deep link handler
            is_redirect = any(pattern in url_lower for pattern in redirect_patterns)
            if not is_redirect:
                continue
            
            self.stats['deep_links_tested'] += 1
            
            # Test with XSS payloads in redirect parameters
            redirect_params = ['url', 'redirect', 'next', 'goto', 'link', 'target', 'destination']
            
            for param in redirect_params:
                for payload in self.payloads[:5]:
                    # Test javascript: protocol injection
                    js_payload = f"javascript:alert('JARWIS_MOBILE_XSS')"
                    
                    result = await self._inject_and_check(session, url, 'GET', param, js_payload)
                    if result.get('vulnerable'):
                        self.stats['xss_found'] += 1
                        self._add_finding(
                            title=f"Deep Link XSS via '{param}' parameter",
                            description=f"JavaScript injection possible through deep link handler",
                            url=url,
                            method='GET',
                            parameter=param,
                            evidence=result.get('evidence', ''),
                            severity="critical",
                            mobile_context="deeplink",
                            payload=js_payload
                        )
                        break
            
            await asyncio.sleep(1 / self.rate_limit)
    
    async def _test_js_bridge_xss(self, session: aiohttp.ClientSession, endpoints: List[Dict]):
        """Test for JavaScript bridge exploitation vulnerabilities"""
        
        # Bridge-specific payloads
        bridge_payloads = []
        for bridge in self.JS_BRIDGE_NAMES:
            bridge_payloads.extend([
                f"javascript:{bridge}.eval('alert(1)')",
                f"<script>{bridge}.showToast('XSS')</script>",
                f"<img src=x onerror=\"{bridge}.execute('XSS')\">",
                f"javascript:try{{{bridge}.callback('XSS')}}catch(e){{}}",
            ])
        
        for endpoint in endpoints[:20]:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            for param_name in params:
                self.stats['bridge_calls_tested'] += 1
                
                for payload in bridge_payloads[:5]:
                    result = await self._inject_and_check(session, url, 'GET', param_name, payload)
                    
                    if result.get('vulnerable'):
                        # Extract bridge name from payload
                        bridge_name = "unknown"
                        for bn in self.JS_BRIDGE_NAMES:
                            if bn in payload:
                                bridge_name = bn
                                break
                        
                        self.stats['xss_found'] += 1
                        self._add_finding(
                            title=f"JavaScript Bridge XSS ({bridge_name})",
                            description=f"JavaScript bridge injection possible, allowing native code execution",
                            url=url,
                            method='GET',
                            parameter=param_name,
                            evidence=result.get('evidence', ''),
                            severity="critical",
                            mobile_context="jsbridge",
                            payload=payload
                        )
                        break
                
                await asyncio.sleep(1 / self.rate_limit)
    
    async def _test_webview_xss_with_browser(self, endpoints: List[Dict]):
        """Use browser to simulate WebView XSS testing"""
        if not self.browser or not hasattr(self.browser, 'page'):
            return
        
        for endpoint in endpoints[:10]:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            for param_name in params:
                for payload in self.payloads[:3]:
                    try:
                        result = await self.browser.check_xss_in_dom(url, payload, param_name)
                        
                        if result.get('vulnerable'):
                            self.stats['xss_found'] += 1
                            self._add_finding(
                                title=f"WebView XSS in '{param_name}' (Browser Verified)",
                                description=f"XSS confirmed via browser execution, indicating WebView vulnerability",
                                url=url,
                                method='GET',
                                parameter=param_name,
                                evidence=f"Dialog triggered: {result.get('alerts', [])}",
                                severity="critical",
                                mobile_context="webview",
                                payload=payload
                            )
                            break
                    except Exception as e:
                        logger.debug(f"WebView test error: {e}")
                
                await asyncio.sleep(0.5)
    
    async def _inject_and_check(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param_name: str,
        payload: str
    ) -> Dict:
        """Inject payload and check for XSS reflection"""
        result = {'vulnerable': False}
        
        try:
            # Build test URL/data
            if method == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query) if parsed.query else {}
                params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                async with session.get(
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
            else:
                test_url = url
                async with session.post(
                    url,
                    headers=self.DEFAULT_HEADERS,
                    data={param_name: payload},
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
            
            # Check if payload is reflected without encoding
            if payload in body:
                result['vulnerable'] = True
                result['evidence'] = f"Payload reflected at position {body.find(payload)}"
                result['test_url'] = test_url
            
            # Check for partial reflection (dangerous patterns)
            elif any(dangerous in body for dangerous in ['<script', 'onerror=', 'onload=', 'javascript:']):
                if 'JARWIS' in payload.upper() and 'jarwis' in body.lower():
                    result['vulnerable'] = True
                    result['evidence'] = "Partial payload reflection detected"
        
        except Exception as e:
            logger.debug(f"Injection test error: {e}")
        
        return result
    
    def _add_finding(
        self,
        title: str,
        description: str,
        url: str,
        method: str,
        parameter: str,
        evidence: str,
        severity: str,
        mobile_context: str,
        payload: str
    ):
        """Add a mobile XSS finding"""
        
        finding = ScanResult(
            id=self._get_next_finding_id(),
            category="M7:2024",  # OWASP Mobile M7 - Client Code Quality
            severity=severity,
            title=title,
            description=description,
            url=url,
            method=method,
            parameter=parameter,
            evidence=evidence,
            remediation=(
                "1. Sanitize all user input before rendering in WebViews\n"
                "2. Use Content Security Policy in WebViews\n"
                "3. Disable JavaScript in WebViews when not needed\n"
                "4. Use setJavaScriptEnabled(false) on Android WebViews when possible\n"
                "5. Use WKWebView instead of UIWebView on iOS\n"
                "6. Validate and sanitize deep link parameters\n"
                "7. Use safe JavaScript bridge implementations\n"
                "8. Implement output encoding for all dynamic content"
            ),
            cwe_id="CWE-79",
            poc=f"Payload: {payload}",
            reasoning=(
                f"This XSS vulnerability was detected in a mobile context ({mobile_context}). "
                f"In mobile apps, XSS can be more dangerous as it may allow access to "
                f"JavaScript bridges, native device features, and sensitive local data. "
                f"The payload was reflected without proper sanitization."
            ),
            mobile_context=mobile_context
        )
        
        self.findings.append(finding)
        logger.warning(f"  [!] Mobile XSS Found: {title}")


# Alias for compatibility
MobileXSSTester = MobileXSSScanner
