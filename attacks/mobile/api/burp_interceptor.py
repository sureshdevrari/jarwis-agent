"""
Jarwis AGI - Mobile Burp-Style Traffic Interceptor
Real-time traffic interception and analysis with Burp Suite-like interface

Features:
- Live request/response capture
- Request modification and replay
- Traffic filtering and search
- Session history with full HTTP details
- Export to various formats (Burp XML, HAR, JSON)
"""

import os
import re
import json
import asyncio
import logging
import threading
from queue import Queue
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


@dataclass
class HTTPMessage:
    """Represents an HTTP request or response"""
    raw: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    
    @classmethod
    def parse_request(cls, raw: str) -> 'HTTPMessage':
        """Parse raw HTTP request"""
        msg = cls(raw=raw)
        
        try:
            parts = raw.split('\r\n\r\n', 1) if '\r\n' in raw else raw.split('\n\n', 1)
            header_section = parts[0]
            msg.body = parts[1] if len(parts) > 1 else ""
            
            lines = header_section.split('\r\n') if '\r\n' in header_section else header_section.split('\n')
            
            for line in lines[1:]:  # Skip request line
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    msg.headers[key] = value
                    
        except Exception as e:
            logger.warning(f"Failed to parse request: {e}")
        
        return msg
    
    @classmethod
    def parse_response(cls, raw: str) -> 'HTTPMessage':
        """Parse raw HTTP response"""
        return cls.parse_request(raw)  # Same parsing logic


@dataclass
class InterceptedTraffic:
    """Single intercepted HTTP transaction"""
    id: int
    timestamp: str
    
    # Request details
    method: str
    url: str
    host: str
    path: str
    scheme: str = "https"
    
    # Full HTTP messages
    request_raw: str = ""
    response_raw: str = ""
    
    # Parsed data
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    request_params: Dict[str, str] = field(default_factory=dict)
    
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_content_type: str = ""
    response_length: int = 0
    
    # Timing
    response_time_ms: float = 0
    
    # Analysis
    has_auth: bool = False
    auth_type: str = ""
    is_api_call: bool = False
    is_sensitive: bool = False
    findings: List[Dict] = field(default_factory=list)
    
    # Tags and notes
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    highlight_color: str = ""  # red, orange, yellow, green, blue, purple


class BurpStyleInterceptor:
    """
    Burp Suite-style HTTP traffic interceptor for mobile apps
    
    Features:
    - Real-time traffic capture from Frida hooks or MITM proxy
    - Full HTTP history with request/response pairs
    - Filtering, searching, and highlighting
    - Request modification and replay
    - Export capabilities
    """
    
    # Patterns for identifying sensitive data
    SENSITIVE_PATTERNS = {
        'password': r'(?i)(password|passwd|pwd|pass)["\s:=]+["\']?([^"\'&\s]{4,})',
        'token': r'(?i)(token|jwt|bearer|auth|session)["\s:=]+["\']?([A-Za-z0-9_\-\.=]{20,})',
        'api_key': r'(?i)(api[_-]?key|apikey|x-api-key)["\s:=]+["\']?([A-Za-z0-9_\-]{16,})',
        'secret': r'(?i)(secret|private[_-]?key)["\s:=]+["\']?([A-Za-z0-9_\-\.=]{16,})',
        'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'(?:\+?1[-.]?)?\(?[2-9]\d{2}\)?[-.]?\d{3}[-.]?\d{4}',
        'private_key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'firebase': r'AIza[0-9A-Za-z\-_]{35}',
    }
    
    # Auth-related headers
    AUTH_HEADERS = [
        'authorization', 'x-auth-token', 'x-api-key', 'x-access-token',
        'x-session-id', 'cookie', 'x-csrf-token', 'bearer'
    ]
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        # Traffic history
        self.history: List[InterceptedTraffic] = []
        self._traffic_counter = 0
        self._lock = threading.Lock()
        
        # Live traffic queue
        self._traffic_queue: Queue = Queue()
        
        # Filters
        self._filter_pattern: Optional[re.Pattern] = None
        self._filter_methods: Set[str] = set()
        self._filter_status_codes: Set[int] = set()
        self._filter_content_types: Set[str] = set()
        self._show_only_in_scope: bool = False
        self._scope_patterns: List[str] = []
        
        # Callbacks
        self._on_request_callback: Optional[Callable] = None
        self._on_response_callback: Optional[Callable] = None
        self._on_finding_callback: Optional[Callable] = None
        
        # Intercept mode
        self._intercept_enabled: bool = False
        self._intercept_queue: Queue = Queue()
    
    def set_on_request_callback(self, callback: Callable):
        """Set callback for new requests"""
        self._on_request_callback = callback
    
    def set_on_response_callback(self, callback: Callable):
        """Set callback for responses"""
        self._on_response_callback = callback
    
    def set_on_finding_callback(self, callback: Callable):
        """Set callback for security findings"""
        self._on_finding_callback = callback
    
    def add_traffic(
        self,
        url: str,
        method: str,
        request_headers: Dict[str, str] = None,
        request_body: str = "",
        response_status: int = 0,
        response_headers: Dict[str, str] = None,
        response_body: str = "",
        response_time_ms: float = 0
    ) -> InterceptedTraffic:
        """
        Add intercepted traffic entry
        
        Returns:
            InterceptedTraffic entry
        """
        with self._lock:
            self._traffic_counter += 1
            entry_id = self._traffic_counter
        
        parsed = urlparse(url)
        
        entry = InterceptedTraffic(
            id=entry_id,
            timestamp=datetime.now().isoformat(),
            method=method.upper(),
            url=url,
            host=parsed.netloc,
            path=parsed.path or '/',
            scheme=parsed.scheme or 'https',
            request_headers=request_headers or {},
            request_body=request_body,
            request_params=dict(parse_qs(parsed.query)),
            response_status=response_status,
            response_headers=response_headers or {},
            response_body=response_body[:50000],  # Limit size
            response_content_type=(response_headers or {}).get('content-type', ''),
            response_length=len(response_body),
            response_time_ms=response_time_ms
        )
        
        # Build raw HTTP messages
        entry.request_raw = self._build_raw_request(entry)
        entry.response_raw = self._build_raw_response(entry)
        
        # Analyze for sensitive data and auth
        self._analyze_traffic(entry)
        
        # Add to history
        with self._lock:
            self.history.append(entry)
        
        # Trigger callbacks
        if self._on_request_callback:
            try:
                self._on_request_callback(entry)
            except:
                pass
        
        return entry
    
    def _build_raw_request(self, entry: InterceptedTraffic) -> str:
        """Build raw HTTP request string"""
        lines = [f"{entry.method} {entry.path} HTTP/1.1"]
        lines.append(f"Host: {entry.host}")
        
        for key, value in entry.request_headers.items():
            if key.lower() != 'host':
                lines.append(f"{key}: {value}")
        
        if entry.request_body:
            lines.append(f"Content-Length: {len(entry.request_body)}")
            lines.append("")
            lines.append(entry.request_body)
        
        return '\r\n'.join(lines)
    
    def _build_raw_response(self, entry: InterceptedTraffic) -> str:
        """Build raw HTTP response string"""
        status_texts = {
            200: 'OK', 201: 'Created', 204: 'No Content',
            301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
            400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
            404: 'Not Found', 405: 'Method Not Allowed',
            500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable'
        }
        
        status_text = status_texts.get(entry.response_status, 'Unknown')
        lines = [f"HTTP/1.1 {entry.response_status} {status_text}"]
        
        for key, value in entry.response_headers.items():
            lines.append(f"{key}: {value}")
        
        if entry.response_body:
            lines.append("")
            lines.append(entry.response_body)
        
        return '\r\n'.join(lines)
    
    def _analyze_traffic(self, entry: InterceptedTraffic):
        """Analyze traffic for sensitive data and security issues"""
        # Check for auth headers
        for header in entry.request_headers:
            if header.lower() in self.AUTH_HEADERS:
                entry.has_auth = True
                entry.auth_type = header.lower()
                break
        
        # Check for auth in response (tokens)
        if 'token' in entry.response_body.lower() or 'session' in entry.response_body.lower():
            entry.is_sensitive = True
        
        # Check if API call
        content_type = entry.response_content_type.lower()
        if 'application/json' in content_type or 'application/xml' in content_type:
            entry.is_api_call = True
        
        if '/api/' in entry.path or '/v1/' in entry.path or '/v2/' in entry.path:
            entry.is_api_call = True
        
        # Scan for sensitive data patterns
        combined_text = f"{entry.request_raw}\n{entry.response_body}"
        
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                entry.is_sensitive = True
                finding = {
                    "type": f"sensitive_data_{pattern_name}",
                    "pattern": pattern_name,
                    "matches_count": len(matches),
                    "location": "request" if pattern_name in entry.request_raw else "response"
                }
                entry.findings.append(finding)
                
                if self._on_finding_callback:
                    try:
                        self._on_finding_callback(entry, finding)
                    except:
                        pass
        
        # Check for security issues
        self._check_security_issues(entry)
    
    def _check_security_issues(self, entry: InterceptedTraffic):
        """Check for common security issues in traffic"""
        # Insecure transport
        if entry.scheme == 'http':
            entry.findings.append({
                "type": "insecure_transport",
                "severity": "high",
                "title": "HTTP Used Instead of HTTPS",
                "description": f"Request to {entry.host} uses unencrypted HTTP"
            })
        
        # Missing security headers in response
        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-content-type-options',
            'x-frame-options'
        ]
        
        response_headers_lower = {k.lower(): v for k, v in entry.response_headers.items()}
        
        for header in security_headers:
            if header not in response_headers_lower:
                entry.findings.append({
                    "type": "missing_security_header",
                    "severity": "low",
                    "header": header
                })
        
        # Check for verbose error messages
        if entry.response_status >= 500:
            if 'stack' in entry.response_body.lower() or 'exception' in entry.response_body.lower():
                entry.findings.append({
                    "type": "verbose_error",
                    "severity": "medium",
                    "title": "Verbose Error Message",
                    "description": "Server returned detailed error information"
                })
        
        # Check for potential IDOR
        if re.search(r'/users?/\d+', entry.path) or re.search(r'[?&](id|user_id|uid)=\d+', entry.url):
            entry.findings.append({
                "type": "potential_idor",
                "severity": "info",
                "title": "Potential IDOR Endpoint",
                "description": "Endpoint contains numeric user/object reference"
            })
        
        # CORS issues
        if 'access-control-allow-origin' in response_headers_lower:
            origin = response_headers_lower['access-control-allow-origin']
            if origin == '*':
                entry.findings.append({
                    "type": "cors_wildcard",
                    "severity": "medium",
                    "title": "Wildcard CORS Policy",
                    "description": "API allows requests from any origin"
                })
    
    def get_history(
        self,
        filter_text: str = None,
        filter_methods: List[str] = None,
        filter_status: List[int] = None,
        filter_has_auth: bool = None,
        filter_is_api: bool = None,
        filter_has_findings: bool = None,
        limit: int = None,
        offset: int = 0
    ) -> List[InterceptedTraffic]:
        """
        Get traffic history with optional filters
        
        Returns:
            Filtered list of traffic entries
        """
        results = []
        
        for entry in self.history:
            # Apply filters
            if filter_text:
                combined = f"{entry.url} {entry.request_body} {entry.response_body}"
                if filter_text.lower() not in combined.lower():
                    continue
            
            if filter_methods and entry.method not in filter_methods:
                continue
            
            if filter_status and entry.response_status not in filter_status:
                continue
            
            if filter_has_auth is not None and entry.has_auth != filter_has_auth:
                continue
            
            if filter_is_api is not None and entry.is_api_call != filter_is_api:
                continue
            
            if filter_has_findings is not None:
                if filter_has_findings and not entry.findings:
                    continue
                if not filter_has_findings and entry.findings:
                    continue
            
            results.append(entry)
        
        # Apply pagination
        if offset:
            results = results[offset:]
        
        if limit:
            results = results[:limit]
        
        return results
    
    def get_entry(self, entry_id: int) -> Optional[InterceptedTraffic]:
        """Get specific traffic entry by ID"""
        for entry in self.history:
            if entry.id == entry_id:
                return entry
        return None
    
    def search(self, query: str, search_in: List[str] = None) -> List[InterceptedTraffic]:
        """
        Search traffic history
        
        Args:
            query: Search query (supports regex if starts with ~)
            search_in: List of fields to search ['url', 'request', 'response', 'headers']
            
        Returns:
            Matching traffic entries
        """
        search_in = search_in or ['url', 'request', 'response']
        results = []
        
        # Check if regex
        is_regex = query.startswith('~')
        if is_regex:
            try:
                pattern = re.compile(query[1:], re.IGNORECASE)
            except:
                return []
        
        for entry in self.history:
            match = False
            
            for field in search_in:
                text = ""
                
                if field == 'url':
                    text = entry.url
                elif field == 'request':
                    text = entry.request_raw
                elif field == 'response':
                    text = entry.response_body
                elif field == 'headers':
                    text = json.dumps(entry.request_headers) + json.dumps(entry.response_headers)
                
                if is_regex:
                    if pattern.search(text):
                        match = True
                        break
                else:
                    if query.lower() in text.lower():
                        match = True
                        break
            
            if match:
                results.append(entry)
        
        return results
    
    def highlight(self, entry_id: int, color: str):
        """Highlight a traffic entry with color"""
        entry = self.get_entry(entry_id)
        if entry:
            entry.highlight_color = color
    
    def add_tag(self, entry_id: int, tag: str):
        """Add tag to traffic entry"""
        entry = self.get_entry(entry_id)
        if entry and tag not in entry.tags:
            entry.tags.append(tag)
    
    def add_note(self, entry_id: int, note: str):
        """Add note to traffic entry"""
        entry = self.get_entry(entry_id)
        if entry:
            entry.notes = note
    
    def get_endpoints_summary(self) -> List[Dict]:
        """Get summary of unique endpoints discovered"""
        endpoints = {}
        
        for entry in self.history:
            key = f"{entry.method}:{entry.host}{entry.path}"
            
            if key not in endpoints:
                endpoints[key] = {
                    "method": entry.method,
                    "host": entry.host,
                    "path": entry.path,
                    "url": f"{entry.scheme}://{entry.host}{entry.path}",
                    "has_auth": entry.has_auth,
                    "is_api": entry.is_api_call,
                    "request_count": 0,
                    "status_codes": set(),
                    "findings_count": 0
                }
            
            endpoints[key]["request_count"] += 1
            endpoints[key]["status_codes"].add(entry.response_status)
            endpoints[key]["findings_count"] += len(entry.findings)
        
        # Convert sets to lists for JSON serialization
        result = list(endpoints.values())
        for ep in result:
            ep["status_codes"] = sorted(list(ep["status_codes"]))
        
        return result
    
    def get_hosts(self) -> List[Dict]:
        """Get summary of hosts contacted"""
        hosts = {}
        
        for entry in self.history:
            if entry.host not in hosts:
                hosts[entry.host] = {
                    "host": entry.host,
                    "scheme": entry.scheme,
                    "request_count": 0,
                    "endpoints": set(),
                    "methods": set()
                }
            
            hosts[entry.host]["request_count"] += 1
            hosts[entry.host]["endpoints"].add(entry.path)
            hosts[entry.host]["methods"].add(entry.method)
        
        result = list(hosts.values())
        for h in result:
            h["endpoints"] = list(h["endpoints"])
            h["methods"] = list(h["methods"])
        
        return result
    
    def export_burp_xml(self, entries: List[InterceptedTraffic] = None) -> str:
        """Export traffic history in Burp XML format"""
        entries = entries or self.history
        
        xml = '<?xml version="1.0"?>\n'
        xml += '<!DOCTYPE items [\n'
        xml += '<!ELEMENT items (item*)>\n'
        xml += '<!ELEMENT item (time,url,host,port,protocol,method,path,extension,request,status,responselength,mimetype,response,comment)>\n'
        xml += ']>\n'
        xml += '<items burpVersion="2023.1" exportTime="{}">\n'.format(datetime.now().isoformat())
        
        import base64
        
        for entry in entries:
            port = 443 if entry.scheme == 'https' else 80
            extension = Path(entry.path).suffix if '.' in entry.path else ''
            
            xml += '  <item>\n'
            xml += f'    <time>{entry.timestamp}</time>\n'
            xml += f'    <url><![CDATA[{entry.url}]]></url>\n'
            xml += f'    <host ip="">{entry.host}</host>\n'
            xml += f'    <port>{port}</port>\n'
            xml += f'    <protocol>{entry.scheme}</protocol>\n'
            xml += f'    <method><![CDATA[{entry.method}]]></method>\n'
            xml += f'    <path><![CDATA[{entry.path}]]></path>\n'
            xml += f'    <extension>{extension}</extension>\n'
            xml += f'    <request base64="true"><![CDATA[{base64.b64encode(entry.request_raw.encode()).decode()}]]></request>\n'
            xml += f'    <status>{entry.response_status}</status>\n'
            xml += f'    <responselength>{entry.response_length}</responselength>\n'
            xml += f'    <mimetype>{entry.response_content_type}</mimetype>\n'
            xml += f'    <response base64="true"><![CDATA[{base64.b64encode(entry.response_raw.encode()).decode()}]]></response>\n'
            xml += f'    <comment><![CDATA[{entry.notes}]]></comment>\n'
            xml += '  </item>\n'
        
        xml += '</items>\n'
        
        return xml
    
    def export_har(self, entries: List[InterceptedTraffic] = None) -> Dict:
        """Export traffic history in HAR format"""
        entries = entries or self.history
        
        har = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Jarwis Mobile Interceptor",
                    "version": "1.0"
                },
                "entries": []
            }
        }
        
        for entry in entries:
            har_entry = {
                "startedDateTime": entry.timestamp,
                "time": entry.response_time_ms,
                "request": {
                    "method": entry.method,
                    "url": entry.url,
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in entry.request_headers.items()],
                    "queryString": [{"name": k, "value": v[0] if isinstance(v, list) else v} 
                                   for k, v in entry.request_params.items()],
                    "bodySize": len(entry.request_body),
                    "postData": {
                        "mimeType": entry.request_headers.get("Content-Type", ""),
                        "text": entry.request_body
                    } if entry.request_body else {}
                },
                "response": {
                    "status": entry.response_status,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in entry.response_headers.items()],
                    "content": {
                        "size": entry.response_length,
                        "mimeType": entry.response_content_type,
                        "text": entry.response_body[:10000]  # Limit size
                    },
                    "redirectURL": "",
                    "bodySize": entry.response_length
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": entry.response_time_ms,
                    "receive": 0
                }
            }
            
            har["log"]["entries"].append(har_entry)
        
        return har
    
    def export_json(self, entries: List[InterceptedTraffic] = None) -> str:
        """Export traffic history as JSON"""
        entries = entries or self.history
        return json.dumps([asdict(e) for e in entries], indent=2, default=str)
    
    def clear_history(self):
        """Clear all traffic history"""
        with self._lock:
            self.history.clear()
            self._traffic_counter = 0
    
    def get_statistics(self) -> Dict:
        """Get traffic statistics"""
        stats = {
            "total_requests": len(self.history),
            "unique_hosts": len(set(e.host for e in self.history)),
            "unique_endpoints": len(set(f"{e.method}:{e.path}" for e in self.history)),
            "methods": {},
            "status_codes": {},
            "api_calls": 0,
            "authenticated_requests": 0,
            "sensitive_data_found": 0,
            "findings_count": 0
        }
        
        for entry in self.history:
            # Method counts
            stats["methods"][entry.method] = stats["methods"].get(entry.method, 0) + 1
            
            # Status code counts
            status_group = f"{entry.response_status // 100}xx"
            stats["status_codes"][status_group] = stats["status_codes"].get(status_group, 0) + 1
            
            if entry.is_api_call:
                stats["api_calls"] += 1
            
            if entry.has_auth:
                stats["authenticated_requests"] += 1
            
            if entry.is_sensitive:
                stats["sensitive_data_found"] += 1
            
            stats["findings_count"] += len(entry.findings)
        
        return stats


# Integration with Frida SSL Bypass
class FridaTrafficIntegration:
    """Integration layer between Frida SSL bypass and Burp-style interceptor"""
    
    def __init__(self, interceptor: BurpStyleInterceptor):
        self.interceptor = interceptor
        self._pending_requests: Dict[str, Dict] = {}
    
    def on_frida_message(self, message: Dict, data: Any):
        """Handle messages from Frida scripts"""
        if message['type'] != 'send':
            return
        
        payload = message.get('payload', {})
        msg_type = payload.get('type', '')
        
        if msg_type == 'http_request':
            # Store pending request
            url = payload.get('url', '')
            self._pending_requests[url] = {
                'method': payload.get('method', 'GET'),
                'url': url,
                'headers': payload.get('headers', {}),
                'body': payload.get('body', ''),
                'timestamp': datetime.now()
            }
            
        elif msg_type == 'http_response':
            url = payload.get('url', '')
            
            # Find matching request
            if url in self._pending_requests:
                request = self._pending_requests.pop(url)
                
                # Calculate response time
                response_time = (datetime.now() - request['timestamp']).total_seconds() * 1000
                
                # Add to interceptor
                self.interceptor.add_traffic(
                    url=request['url'],
                    method=request['method'],
                    request_headers=request['headers'],
                    request_body=request['body'],
                    response_status=payload.get('status', 0),
                    response_body=payload.get('body', ''),
                    response_time_ms=response_time
                )


# Convenience functions
def create_interceptor(config: dict = None) -> BurpStyleInterceptor:
    """Create Burp-style interceptor instance"""
    return BurpStyleInterceptor(config)


def create_frida_integration(interceptor: BurpStyleInterceptor) -> FridaTrafficIntegration:
    """Create Frida integration for traffic capture"""
    return FridaTrafficIntegration(interceptor)
