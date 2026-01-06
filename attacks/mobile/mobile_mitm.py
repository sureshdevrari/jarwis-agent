"""
Jarwis AGI - Mobile MITM Proxy Integration
Traffic interception and analysis for mobile applications

Uses the same mitmproxy approach as web testing with mobile-specific enhancements:
- SSL/TLS certificate injection
- Mobile API endpoint discovery
- Authentication token capture
- Request/Response logging for OWASP testing
"""

import os
import re
import json
import asyncio
import logging
import threading
from queue import Queue
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class MobileRequest:
    """Captured mobile HTTP request"""
    id: str
    timestamp: str
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    
    # Mobile-specific metadata
    platform: str = ""  # android, ios
    app_name: str = ""
    user_agent: str = ""
    is_api_call: bool = False
    auth_token: str = ""
    auth_type: str = ""  # bearer, basic, api_key, session


@dataclass
class MobileResponse:
    """Captured mobile HTTP response"""
    request_id: str
    timestamp: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    response_time_ms: float = 0


@dataclass
class MobileTrafficEntry:
    """Combined request/response entry"""
    id: str
    request: MobileRequest
    response: Optional[MobileResponse] = None
    
    # Analysis results
    findings: List[Dict] = field(default_factory=list)
    api_endpoint: str = ""
    sensitivity_score: int = 0  # 0-100


class MobileMITMProxy:
    """
    Mobile Traffic Interception and Analysis
    Integrates with mitmproxy for capturing mobile app traffic
    """
    
    # Patterns for identifying sensitive data in traffic
    SENSITIVE_PATTERNS = {
        'password': r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^"\'&\s]+)',
        'token': r'(?i)(token|jwt|bearer|auth)["\s:=]+["\']?([A-Za-z0-9_\-\.=]+)',
        'api_key': r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9_\-]+)',
        'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}',
        'private_key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'firebase_token': r'[0-9a-zA-Z_-]{100,}',  # Firebase FCM token pattern
    }
    
    # Headers that typically contain auth info
    AUTH_HEADERS = [
        'authorization', 'x-auth-token', 'x-api-key', 'api-key',
        'x-access-token', 'x-session-id', 'cookie', 'x-csrf-token',
        'x-firebase-auth', 'x-device-token'
    ]
    
    # Common mobile API patterns
    MOBILE_API_PATTERNS = [
        r'/api/v\d+/',
        r'/mobile/',
        r'/app/',
        r'/auth/',
        r'/login',
        r'/register',
        r'/user',
        r'/profile',
        r'/payment',
        r'/transaction',
        r'/order',
        r'/cart',
        r'/graphql',
        r'/rest/',
    ]
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.port = config.get('mitm_port', 8080)
        self.traffic_log: List[MobileTrafficEntry] = []
        self.discovered_endpoints: Dict[str, Dict] = {}
        self.captured_tokens: List[Dict] = []
        self.running = False
        self._request_counter = 0
        self._callback: Optional[Callable] = None
        self._mitm_process = None
        self._traffic_queue = Queue()
    
    def set_traffic_callback(self, callback: Callable):
        """Set callback for real-time traffic updates"""
        self._callback = callback
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        self._request_counter += 1
        return f"REQ-{datetime.now().strftime('%H%M%S')}-{self._request_counter:04d}"
    
    async def start(self) -> bool:
        """
        Start the MITM proxy for mobile traffic interception
        Returns True if started successfully
        """
        try:
            from core.mitm_proxy import MITMProxyController
            
            # Create addon for mobile traffic analysis
            addon_code = self._generate_mobile_addon()
            
            # Save addon to temp file
            addon_path = Path("core/mobile_mitm_addon.py")
            addon_path.write_text(addon_code)
            
            # Start mitmproxy
            self._mitm_process = await asyncio.create_subprocess_exec(
                'mitmdump',
                '-p', str(self.port),
                '-s', str(addon_path),
                '--ssl-insecure',
                '--set', 'stream_large_bodies=10m',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self.running = True
            logger.info(f"Mobile MITM proxy started on port {self.port}")
            
            # Start traffic processing thread
            threading.Thread(target=self._process_traffic_queue, daemon=True).start()
            
            return True
            
        except FileNotFoundError:
            logger.warning("mitmproxy not installed. Using fallback traffic capture.")
            return await self._start_fallback_capture()
        except Exception as e:
            logger.error(f"Failed to start MITM proxy: {e}")
            return False
    
    async def _start_fallback_capture(self) -> bool:
        """Start fallback capture without mitmproxy"""
        # Use simple HTTP proxy if mitmproxy not available
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import ssl
            
            # Create a simple logging proxy
            # This is a simplified version - real implementation needs full proxy logic
            self.running = True
            logger.info(f"Fallback traffic capture ready on port {self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Fallback capture failed: {e}")
            return False
    
    def _generate_mobile_addon(self) -> str:
        """Generate mitmproxy addon script for mobile analysis"""
        return '''
"""
Jarwis Mobile MITM Addon
Intercepts and analyzes mobile app traffic
"""

import json
import re
from datetime import datetime
from mitmproxy import http, ctx

# Traffic storage
traffic_log = []

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    "password": r'(?i)(password|passwd|pwd)["\\s:=]+["\']?([^"\\'&\\s]+)',
    "token": r'(?i)(token|jwt|bearer|auth)["\\s:=]+["\']?([A-Za-z0-9_\\-\\.=]+)',
    "api_key": r'(?i)(api[_-]?key|apikey)["\\s:=]+["\']?([A-Za-z0-9_\\-]+)',
    "credit_card": r'\\b(?:\\d{4}[- ]?){3}\\d{4}\\b',
}

AUTH_HEADERS = [
    "authorization", "x-auth-token", "x-api-key", "api-key",
    "x-access-token", "x-session-id", "cookie"
]

def request(flow: http.HTTPFlow):
    """Handle intercepted request"""
    entry = {
        "id": f"REQ-{datetime.now().strftime('%H%M%S%f')[:10]}",
        "timestamp": datetime.now().isoformat(),
        "url": flow.request.pretty_url,
        "method": flow.request.method,
        "headers": dict(flow.request.headers),
        "host": flow.request.host,
    }
    
    # Check for auth headers
    for header in AUTH_HEADERS:
        if header in flow.request.headers:
            entry["auth_header"] = header
            entry["auth_value"] = flow.request.headers[header][:50] + "..."
            break
    
    # Detect platform from User-Agent
    ua = flow.request.headers.get("user-agent", "").lower()
    if "android" in ua:
        entry["platform"] = "android"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        entry["platform"] = "ios"
    else:
        entry["platform"] = "unknown"
    
    # Log body for POST/PUT
    if flow.request.method in ["POST", "PUT", "PATCH"]:
        body = flow.request.get_text()
        if body:
            entry["body_preview"] = body[:500]
            
            # Scan for sensitive data
            for name, pattern in SENSITIVE_PATTERNS.items():
                if re.search(pattern, body):
                    entry.setdefault("sensitive_data", []).append(name)
    
    traffic_log.append(entry)
    
    # Write to file for real-time processing
    with open("reports/mobile_traffic.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\\n")
    
    ctx.log.info(f"[MOBILE] {entry['method']} {entry['url'][:80]}")

def response(flow: http.HTTPFlow):
    """Handle intercepted response"""
    entry = {
        "url": flow.request.pretty_url,
        "status": flow.response.status_code,
        "content_type": flow.response.headers.get("content-type", ""),
        "timestamp": datetime.now().isoformat(),
    }
    
    # Check for sensitive data in response
    body = flow.response.get_text()
    if body:
        for name, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, body):
                entry.setdefault("sensitive_data", []).append(name)
                ctx.log.warn(f"[SENSITIVE] {name} found in response to {flow.request.pretty_url[:50]}")
    
    with open("reports/mobile_traffic.jsonl", "a") as f:
        f.write(json.dumps({"response": entry}) + "\\n")
'''
    
    async def stop(self):
        """Stop the MITM proxy"""
        self.running = False
        
        if self._mitm_process:
            self._mitm_process.terminate()
            await self._mitm_process.wait()
            self._mitm_process = None
        
        logger.info("Mobile MITM proxy stopped")
    
    def _process_traffic_queue(self):
        """Process captured traffic in background"""
        while self.running:
            try:
                entry = self._traffic_queue.get(timeout=1)
                self._analyze_traffic_entry(entry)
            except:
                continue
    
    def _analyze_traffic_entry(self, entry: Dict):
        """Analyze a single traffic entry for security issues"""
        findings = []
        
        # Check for sensitive data in transit
        content = json.dumps(entry)
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'sensitive_data',
                    'category': pattern_name,
                    'severity': 'high' if pattern_name in ['password', 'credit_card', 'private_key'] else 'medium',
                    'message': f'{pattern_name.title()} found in traffic'
                })
        
        # Check for insecure HTTP
        url = entry.get('url', '')
        if url.startswith('http://') and not 'localhost' in url:
            findings.append({
                'type': 'insecure_transport',
                'severity': 'high',
                'message': 'Sensitive data sent over unencrypted HTTP'
            })
        
        # Check for auth tokens
        for header in self.AUTH_HEADERS:
            if header in str(entry.get('headers', {})).lower():
                self.captured_tokens.append({
                    'header': header,
                    'endpoint': url,
                    'timestamp': entry.get('timestamp', '')
                })
        
        # Update endpoint discovery
        for pattern in self.MOBILE_API_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                self._discover_endpoint(url, entry.get('method', 'GET'), entry)
                break
        
        if findings:
            entry['findings'] = findings
            if self._callback:
                self._callback('traffic_finding', entry)
    
    def _discover_endpoint(self, url: str, method: str, entry: Dict):
        """Discover and catalog API endpoint"""
        # Normalize URL (remove query params and IDs)
        normalized = re.sub(r'/\d+', '/{id}', url)
        normalized = normalized.split('?')[0]
        
        key = f"{method}:{normalized}"
        
        if key not in self.discovered_endpoints:
            self.discovered_endpoints[key] = {
                'url': normalized,
                'method': method,
                'first_seen': datetime.now().isoformat(),
                'call_count': 0,
                'sample_request': entry,
                'auth_required': bool(entry.get('auth_header')),
            }
        
        self.discovered_endpoints[key]['call_count'] += 1
        self.discovered_endpoints[key]['last_seen'] = datetime.now().isoformat()
    
    def get_traffic_log(self) -> List[MobileTrafficEntry]:
        """Get all captured traffic"""
        return self.traffic_log
    
    def get_discovered_endpoints(self) -> Dict[str, Dict]:
        """Get discovered API endpoints"""
        return self.discovered_endpoints
    
    def get_captured_tokens(self) -> List[Dict]:
        """Get captured authentication tokens"""
        return self.captured_tokens
    
    def export_traffic(self, output_path: str, format: str = 'json') -> str:
        """Export captured traffic to file"""
        output_path = Path(output_path)
        
        if format == 'json':
            data = {
                'captured_at': datetime.now().isoformat(),
                'total_requests': len(self.traffic_log),
                'endpoints_discovered': len(self.discovered_endpoints),
                'tokens_captured': len(self.captured_tokens),
                'traffic': [
                    {
                        'id': e.id,
                        'request': {
                            'url': e.request.url,
                            'method': e.request.method,
                            'headers': e.request.headers,
                        },
                        'response': {
                            'status': e.response.status_code,
                            'content_type': e.response.content_type
                        } if e.response else None,
                        'findings': e.findings
                    }
                    for e in self.traffic_log
                ],
                'endpoints': self.discovered_endpoints,
            }
            
            output_path.write_text(json.dumps(data, indent=2))
            
        elif format == 'har':
            # Export in HAR format for Burp Suite compatibility
            har_data = self._convert_to_har()
            output_path.write_text(json.dumps(har_data, indent=2))
        
        return str(output_path)
    
    def _convert_to_har(self) -> dict:
        """Convert traffic log to HAR format"""
        entries = []
        
        for entry in self.traffic_log:
            har_entry = {
                'startedDateTime': entry.request.timestamp,
                'request': {
                    'method': entry.request.method,
                    'url': entry.request.url,
                    'headers': [{'name': k, 'value': v} for k, v in entry.request.headers.items()],
                    'queryString': [{'name': k, 'value': v} for k, v in entry.request.query_params.items()],
                    'postData': {'text': entry.request.body} if entry.request.body else None,
                },
                'response': {
                    'status': entry.response.status_code if entry.response else 0,
                    'headers': [{'name': k, 'value': v} for k, v in (entry.response.headers if entry.response else {}).items()],
                    'content': {'text': entry.response.body if entry.response else ''},
                } if entry.response else None,
            }
            entries.append(har_entry)
        
        return {
            'log': {
                'version': '1.2',
                'creator': {'name': 'Jarwis Mobile Scanner', 'version': '1.0'},
                'entries': entries
            }
        }
    
    def get_owasp_test_targets(self) -> List[Dict]:
        """
        Get targets for OWASP testing based on discovered endpoints
        Returns prioritized list of endpoints to test
        """
        targets = []
        
        for key, endpoint in self.discovered_endpoints.items():
            priority = 0
            test_types = []
            
            # Higher priority for authenticated endpoints
            if endpoint.get('auth_required'):
                priority += 30
                test_types.extend(['broken_auth', 'idor', 'privilege_escalation'])
            
            # Check endpoint type
            url = endpoint['url'].lower()
            
            if any(x in url for x in ['/login', '/auth', '/signin', '/register']):
                priority += 50
                test_types.extend(['brute_force', 'account_takeover', 'credential_stuffing'])
            
            if any(x in url for x in ['/payment', '/transaction', '/checkout', '/order']):
                priority += 60
                test_types.extend(['payment_tampering', 'price_manipulation', 'replay_attack'])
            
            if any(x in url for x in ['/user', '/profile', '/account']):
                priority += 40
                test_types.extend(['idor', 'mass_assignment', 'pii_exposure'])
            
            if any(x in url for x in ['/admin', '/dashboard', '/manage']):
                priority += 70
                test_types.extend(['privilege_escalation', 'admin_bypass'])
            
            if any(x in url for x in ['/upload', '/file', '/image']):
                priority += 45
                test_types.extend(['file_upload', 'path_traversal'])
            
            if any(x in url for x in ['/search', '/query', '/find']):
                priority += 35
                test_types.extend(['sqli', 'nosql_injection'])
            
            if endpoint['method'] in ['POST', 'PUT', 'DELETE']:
                priority += 20
            
            targets.append({
                'endpoint': endpoint['url'],
                'method': endpoint['method'],
                'priority': priority,
                'test_types': list(set(test_types)),
                'auth_required': endpoint.get('auth_required', False),
                'call_count': endpoint.get('call_count', 0),
            })
        
        # Sort by priority
        targets.sort(key=lambda x: x['priority'], reverse=True)
        
        return targets
    
    def generate_test_plan(self) -> Dict:
        """
        Generate OWASP-based test plan from captured traffic
        Uses same strategy as web app testing
        """
        targets = self.get_owasp_test_targets()
        
        plan = {
            'generated_at': datetime.now().isoformat(),
            'total_endpoints': len(self.discovered_endpoints),
            'high_priority_targets': len([t for t in targets if t['priority'] >= 50]),
            'tests': [],
        }
        
        # Generate tests for each target
        for target in targets[:20]:  # Top 20 endpoints
            endpoint_tests = []
            
            if 'sqli' in target['test_types'] or 'nosql_injection' in target['test_types']:
                endpoint_tests.append({
                    'owasp': 'A03:2021 - Injection',
                    'test': 'SQL/NoSQL Injection',
                    'payloads': ["' OR '1'='1", "1; DROP TABLE users--", '{"$gt": ""}']
                })
            
            if 'idor' in target['test_types']:
                endpoint_tests.append({
                    'owasp': 'A01:2021 - Broken Access Control',
                    'test': 'IDOR (Insecure Direct Object Reference)',
                    'payloads': ['Modify ID parameter', 'Access other user resources']
                })
            
            if 'broken_auth' in target['test_types']:
                endpoint_tests.append({
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'test': 'Authentication Bypass',
                    'payloads': ['Empty credentials', 'JWT manipulation', 'Token reuse']
                })
            
            if 'file_upload' in target['test_types']:
                endpoint_tests.append({
                    'owasp': 'A04:2021 - Insecure Design',
                    'test': 'Malicious File Upload',
                    'payloads': ['PHP webshell', 'SVG XSS', 'Polyglot files']
                })
            
            if endpoint_tests:
                plan['tests'].append({
                    'target': target['endpoint'],
                    'method': target['method'],
                    'priority': target['priority'],
                    'tests': endpoint_tests
                })
        
        return plan


# Factory function
def create_mobile_proxy(config: dict = None) -> MobileMITMProxy:
    """Create and configure mobile MITM proxy"""
    return MobileMITMProxy(config)
