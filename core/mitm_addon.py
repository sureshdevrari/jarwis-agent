
"""
Jarwis MITM Addon - Captures all HTTP/HTTPS traffic
"""
import json
import sys
from mitmproxy import http, ctx
from datetime import datetime

class JarwisAddon:
    def __init__(self):
        self.traffic_log = []
        self.log_file = None
        
    def load(self, loader):
        loader.add_option(
            name="jarwis_log_file",
            typespec=str,
            default="",
            help="Path to write traffic log"
        )
    
    def configure(self, updates):
        if ctx.options.jarwis_log_file:
            self.log_file = ctx.options.jarwis_log_file
    
    def request(self, flow: http.HTTPFlow):
        """Called when a request is received"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "request",
            "id": id(flow),
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "path": flow.request.path,
            "headers": dict(flow.request.headers),
            "is_https": flow.request.scheme == "https"
        }
        
        # Log body for POST requests (limited size)
        if flow.request.method in ["POST", "PUT", "PATCH"]:
            body = flow.request.get_text()
            if body and len(body) < 10000:
                entry["body"] = body
        
        self.traffic_log.append(entry)
        self._write_log()
        ctx.log.info(f"[JARWIS] -> {flow.request.method} {flow.request.pretty_url}")
    
    def response(self, flow: http.HTTPFlow):
        """Called when a response is received"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "response",
            "id": id(flow),
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "is_https": flow.request.scheme == "https"
        }
        
        # Log response body (limited size)
        content_type = flow.response.headers.get("content-type", "")
        if "text" in content_type or "json" in content_type or "html" in content_type:
            body = flow.response.get_text()
            if body and len(body) < 50000:
                entry["body"] = body[:50000]
        
        self.traffic_log.append(entry)
        self._write_log()
        ctx.log.info(f"[JARWIS] <- {flow.response.status_code} {flow.request.pretty_url}")
    
    def _write_log(self):
        """Write traffic log to file"""
        if self.log_file:
            try:
                with open(self.log_file, 'w') as f:
                    json.dump(self.traffic_log, f, indent=2)
            except Exception as e:
                ctx.log.error(f"Failed to write log: {e}")

addons = [JarwisAddon()]
