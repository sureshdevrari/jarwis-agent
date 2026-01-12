
"""
Jarwis MITM Addon - Captures all HTTP/HTTPS traffic

Enhanced to distinguish between:
1. CRAWL traffic - Browser crawling during discovery
2. ATTACK traffic - Modified requests from scanners via JarwisHTTPClient

Attack traffic is identified by:
- X-Jarwis-Attack header (set by JarwisHTTPClient)
- X-Jarwis-Scanner header (scanner name)
- X-Jarwis-Attack-Type header (sqli, xss, etc.)

This allows proper separation and analysis of attack vs crawl data.
"""
import json
import sys
import os
import hashlib
import time
from mitmproxy import http, ctx
from datetime import datetime
from typing import Dict, List, Any, Optional


class JarwisAddon:
    """
    Enhanced MITM addon for Jarwis pen testing.
    
    Features:
    - Separates crawl traffic from attack traffic
    - Tags attack requests with scanner/payload info
    - Stores to separate log files for crawl vs attack
    - Calculates response timing for time-based attacks
    - Removes Jarwis headers before forwarding to target
    """
    
    # Header names used to identify attack traffic
    JARWIS_ATTACK_HEADER = "X-Jarwis-Attack"
    JARWIS_SCANNER_HEADER = "X-Jarwis-Scanner"
    JARWIS_ATTACK_TYPE_HEADER = "X-Jarwis-Attack-Type"
    JARWIS_REQUEST_ID_HEADER = "X-Jarwis-Request-Id"
    JARWIS_PAYLOAD_HEADER = "X-Jarwis-Payload"
    
    def __init__(self):
        # Separate logs for crawl and attack traffic
        self.crawl_log: List[Dict] = []
        self.attack_log: List[Dict] = []
        
        # File paths
        self.crawl_log_file: Optional[str] = None
        self.attack_log_file: Optional[str] = None
        
        # Legacy combined log (for backward compatibility)
        self.traffic_log: List[Dict] = []
        self.log_file: Optional[str] = None
        
        # Request timing for response time calculation
        self._request_times: Dict[int, float] = {}
        
        # Statistics
        self.stats = {
            'crawl_requests': 0,
            'crawl_responses': 0,
            'attack_requests': 0,
            'attack_responses': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0
        }
        
    def load(self, loader):
        """Register mitmproxy options"""
        loader.add_option(
            name="jarwis_log_file",
            typespec=str,
            default="",
            help="Path to write traffic log (legacy combined log)"
        )
        loader.add_option(
            name="jarwis_crawl_log",
            typespec=str,
            default="",
            help="Path to write crawl traffic log"
        )
        loader.add_option(
            name="jarwis_attack_log",
            typespec=str,
            default="",
            help="Path to write attack traffic log"
        )
    
    def configure(self, updates):
        """Configure from mitmproxy options"""
        if ctx.options.jarwis_log_file:
            self.log_file = ctx.options.jarwis_log_file
        
        if ctx.options.jarwis_crawl_log:
            self.crawl_log_file = ctx.options.jarwis_crawl_log
        
        if ctx.options.jarwis_attack_log:
            self.attack_log_file = ctx.options.jarwis_attack_log
    
    def _is_attack_request(self, flow: http.HTTPFlow) -> bool:
        """Check if this is an attack request from JarwisHTTPClient"""
        return self.JARWIS_ATTACK_HEADER in flow.request.headers
    
    def _extract_attack_metadata(self, flow: http.HTTPFlow) -> Dict[str, str]:
        """Extract Jarwis attack metadata from headers"""
        return {
            'is_attack': True,
            'scanner_name': flow.request.headers.get(self.JARWIS_SCANNER_HEADER, 'unknown'),
            'attack_type': flow.request.headers.get(self.JARWIS_ATTACK_TYPE_HEADER, 'unknown'),
            'request_id': flow.request.headers.get(self.JARWIS_REQUEST_ID_HEADER, ''),
            'payload': flow.request.headers.get(self.JARWIS_PAYLOAD_HEADER, '')[:200]  # Limit payload size
        }
    
    def _remove_jarwis_headers(self, flow: http.HTTPFlow):
        """Remove Jarwis headers before forwarding to target"""
        headers_to_remove = [
            self.JARWIS_ATTACK_HEADER,
            self.JARWIS_SCANNER_HEADER,
            self.JARWIS_ATTACK_TYPE_HEADER,
            self.JARWIS_REQUEST_ID_HEADER,
            self.JARWIS_PAYLOAD_HEADER
        ]
        
        for header in headers_to_remove:
            if header in flow.request.headers:
                del flow.request.headers[header]
    
    def _generate_entry_id(self, url: str, method: str, timestamp: str) -> str:
        """Generate unique ID for a log entry"""
        content = f"{method}:{url}:{timestamp}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def request(self, flow: http.HTTPFlow):
        """Called when a request is received - BEFORE forwarding to target"""
        
        # Record request time for response timing
        self._request_times[id(flow)] = time.time()
        
        timestamp = datetime.now().isoformat()
        is_attack = self._is_attack_request(flow)
        
        # Base entry
        entry = {
            "timestamp": timestamp,
            "entry_id": self._generate_entry_id(flow.request.pretty_url, flow.request.method, timestamp),
            "type": "request",
            "flow_id": id(flow),
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "headers": dict(flow.request.headers),
            "is_https": flow.request.scheme == "https",
            "is_attack": is_attack,
            "traffic_type": "attack" if is_attack else "crawl"
        }
        
        # Add body for stateful requests
        if flow.request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            body = flow.request.get_text()
            if body and len(body) < 50000:
                entry["body"] = body
            entry["body_size"] = len(body) if body else 0
            self.stats['total_bytes_sent'] += entry["body_size"]
        
        # Add attack metadata if this is an attack request
        if is_attack:
            entry.update(self._extract_attack_metadata(flow))
            self.attack_log.append(entry)
            self.stats['attack_requests'] += 1
            
            # Remove Jarwis headers before forwarding to target
            self._remove_jarwis_headers(flow)
            
            ctx.log.info(f"[JARWIS-ATTACK] -> {entry['scanner_name']}:{entry['attack_type']} {flow.request.method} {flow.request.pretty_url[:80]}")
        else:
            self.crawl_log.append(entry)
            self.stats['crawl_requests'] += 1
            ctx.log.info(f"[JARWIS-CRAWL] -> {flow.request.method} {flow.request.pretty_url[:80]}")
        
        # Also write to combined log for backward compatibility
        self.traffic_log.append(entry)
        
        # Write logs
        self._write_logs()
    
    def response(self, flow: http.HTTPFlow):
        """Called when a response is received from target"""
        
        # Calculate response time
        request_time = self._request_times.pop(id(flow), None)
        response_time_ms = (time.time() - request_time) * 1000 if request_time else 0
        
        timestamp = datetime.now().isoformat()
        
        # Determine if this was an attack request
        # We look at the most recent request entry with matching flow_id
        is_attack = False
        attack_metadata = {}
        
        for log_entry in reversed(self.attack_log):
            if log_entry.get('flow_id') == id(flow) and log_entry.get('type') == 'request':
                is_attack = True
                attack_metadata = {
                    'scanner_name': log_entry.get('scanner_name', ''),
                    'attack_type': log_entry.get('attack_type', ''),
                    'request_id': log_entry.get('request_id', ''),
                    'payload': log_entry.get('payload', '')
                }
                break
        
        entry = {
            "timestamp": timestamp,
            "type": "response",
            "flow_id": id(flow),
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "status": flow.response.status_code,
            "reason": flow.response.reason,
            "headers": dict(flow.response.headers),
            "is_https": flow.request.scheme == "https",
            "is_attack": is_attack,
            "traffic_type": "attack" if is_attack else "crawl",
            "response_time_ms": round(response_time_ms, 2)
        }
        
        # Add attack metadata to response
        if is_attack:
            entry.update(attack_metadata)
        
        # Log response body (limited size)
        content_type = flow.response.headers.get("content-type", "")
        body = ""
        if "text" in content_type or "json" in content_type or "html" in content_type or "xml" in content_type:
            try:
                body = flow.response.get_text()
                if body and len(body) < 100000:
                    entry["body"] = body[:100000]
                entry["body_size"] = len(body) if body else 0
            except:
                entry["body_size"] = 0
        else:
            # Binary content
            entry["body_size"] = len(flow.response.content) if flow.response.content else 0
        
        self.stats['total_bytes_received'] += entry.get("body_size", 0)
        
        # Add to appropriate log
        if is_attack:
            self.attack_log.append(entry)
            self.stats['attack_responses'] += 1
            ctx.log.info(f"[JARWIS-ATTACK] <- {flow.response.status_code} ({response_time_ms:.0f}ms) {flow.request.pretty_url[:80]}")
        else:
            self.crawl_log.append(entry)
            self.stats['crawl_responses'] += 1
            ctx.log.info(f"[JARWIS-CRAWL] <- {flow.response.status_code} {flow.request.pretty_url[:80]}")
        
        # Combined log
        self.traffic_log.append(entry)
        
        # Write logs
        self._write_logs()
    
    def error(self, flow: http.HTTPFlow):
        """Called when an error occurs"""
        timestamp = datetime.now().isoformat()
        
        entry = {
            "timestamp": timestamp,
            "type": "error",
            "flow_id": id(flow),
            "url": flow.request.pretty_url if flow.request else "unknown",
            "error": str(flow.error) if flow.error else "Unknown error"
        }
        
        self.traffic_log.append(entry)
        ctx.log.error(f"[JARWIS-ERROR] {entry['url']}: {entry['error']}")
        self._write_logs()
    
    def _write_logs(self):
        """Write all logs to their respective files"""
        # Legacy combined log
        if self.log_file:
            self._write_json(self.log_file, self.traffic_log)
        
        # Separate crawl log
        if self.crawl_log_file:
            self._write_json(self.crawl_log_file, self.crawl_log)
        
        # Separate attack log
        if self.attack_log_file:
            self._write_json(self.attack_log_file, self.attack_log)
    
    def _write_json(self, filepath: str, data: List[Dict]):
        """Write data to JSON file atomically"""
        try:
            # Write to temp file first, then rename (atomic)
            temp_file = f"{filepath}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Atomic rename
            if os.path.exists(filepath):
                os.remove(filepath)
            os.rename(temp_file, filepath)
            
        except Exception as e:
            ctx.log.error(f"Failed to write log {filepath}: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get traffic statistics"""
        return {
            **self.stats,
            'crawl_log_size': len(self.crawl_log),
            'attack_log_size': len(self.attack_log)
        }


# Create addon instance
addons = [JarwisAddon()]
