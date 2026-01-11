"""
JARWIS AGI PEN TEST - MITM Proxy for HTTPS Interception
True man-in-the-middle proxy using mitmproxy for HTTPS traffic interception
"""

import asyncio
import logging
import json
import os
import sys
import threading
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class MITMRequest:
    """Represents an intercepted HTTPS request/response"""
    id: str
    timestamp: str
    url: str
    method: str
    scheme: str  # http or https
    host: str
    path: str
    request_headers: Dict
    request_body: Optional[bytes]
    response_status: int = 0
    response_headers: Dict = field(default_factory=dict)
    response_body: bytes = b""
    is_https: bool = False


class JarwisMITMProxy:
    """
    MITM Proxy for intercepting HTTPS traffic.
    Uses mitmproxy under the hood with automatic certificate generation.
    
    Callbacks:
        on_request: Called when a request is captured (url, method, headers, body)
        on_response: Called when a response is captured (request_id, status, headers, body)
    """
    
    def __init__(
        self, 
        host: str = "127.0.0.1", 
        port: int = 8080,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None
    ):
        self.host = host
        self.port = port
        self.running = False
        self.requests: List[MITMRequest] = []
        self._request_id = 0
        self._callbacks: List[Callable] = []
        self._process = None
        self._cert_dir = Path.home() / ".jarwis" / "certs"
        self._mitm_script_path = Path(__file__).parent / "mitm_addon.py"
        
        # Callbacks for request/response capture
        self._on_request = on_request
        self._on_response = on_response
        self._traffic_log_path = self._cert_dir / "traffic_log.json"
        self._last_processed_index = 0
        
    @property
    def ca_cert_path(self) -> Path:
        """Path to the CA certificate for browser/system trust"""
        return self._cert_dir / "mitmproxy-ca-cert.pem"
    
    def _ensure_cert_directory(self):
        """Ensure certificate directory exists"""
        self._cert_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Certificate directory: {self._cert_dir}")
    
    def _create_mitm_addon_script(self):
        """Create the mitmproxy addon script for traffic capture"""
        addon_script = '''
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
'''
        self._mitm_script_path.write_text(addon_script)
        logger.info(f"Created MITM addon script: {self._mitm_script_path}")
    
    async def start(self):
        """Start the MITM proxy server"""
        self._ensure_cert_directory()
        self._create_mitm_addon_script()
        
        # Check if mitmproxy is installed (with timeout)
        try:
            result = subprocess.run(
                ["mitmdump", "--version"],
                capture_output=True,
                text=True,
                timeout=10  # 10 second timeout
            )
            if result.returncode != 0:
                logger.warning("mitmproxy not found. Installing...")
                subprocess.run([sys.executable, "-m", "pip", "install", "mitmproxy"], check=True, timeout=120)
        except FileNotFoundError:
            logger.warning("mitmdump not found. Installing mitmproxy...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "mitmproxy"], check=True, timeout=120)
            except subprocess.TimeoutExpired:
                logger.error("Timeout installing mitmproxy")
                return False
        except subprocess.TimeoutExpired:
            logger.error("Timeout checking mitmproxy version")
            return False
        except Exception as e:
            logger.error(f"Failed to check/install mitmproxy: {e}")
            return False
        
        # Start mitmdump as a subprocess (headless version of mitmproxy)
        traffic_log_path = self._cert_dir / "traffic_log.json"
        cmd = [
            "mitmdump",
            "--mode", "regular",
            "--listen-host", self.host,
            "--listen-port", str(self.port),
            "--set", f"confdir={self._cert_dir}",
            "--set", f"jarwis_log_file={traffic_log_path}",
            "-s", str(self._mitm_script_path),
            "--ssl-insecure",  # Don't verify upstream certificates
            "-q"  # Quiet mode
        ]
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait a bit for proxy to start
            await asyncio.sleep(2)
            
            if self._process.poll() is None:
                self.running = True
                logger.info(f"Jarwis MITM Proxy started on {self.host}:{self.port}")
                logger.info(f"CA Certificate: {self.ca_cert_path}")
                return True
            else:
                stderr = self._process.stderr.read().decode()
                logger.error(f"MITM proxy failed to start: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start MITM proxy: {e}")
            return False
    
    async def stop(self):
        """Stop the MITM proxy server"""
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        
        self.running = False
        logger.info("Jarwis MITM Proxy stopped")
    
    def get_proxy_settings(self) -> Dict:
        """Get proxy settings for browser/tools configuration"""
        return {
            "server": f"http://{self.host}:{self.port}",
            "host": self.host,
            "port": self.port,
            "ca_cert": str(self.ca_cert_path)
        }
    
    def get_captured_traffic(self) -> List[Dict]:
        """Read captured traffic from log file"""
        if self._traffic_log_path.exists():
            try:
                with open(self._traffic_log_path) as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def process_new_traffic(self) -> int:
        """
        Process new traffic entries and invoke callbacks.
        Returns the number of new entries processed.
        
        This should be called periodically during crawling to populate RequestStore.
        """
        if not self._traffic_log_path.exists():
            return 0
        
        try:
            with open(self._traffic_log_path) as f:
                all_traffic = json.load(f)
        except (json.JSONDecodeError, IOError):
            return 0
        
        new_entries = all_traffic[self._last_processed_index:]
        processed_count = 0
        
        # Track request IDs for matching responses
        request_id_map = {}  # flow_id -> our_request_id
        
        for entry in new_entries:
            entry_type = entry.get('type')
            
            if entry_type == 'request' and self._on_request:
                try:
                    request_id = self._on_request(
                        url=entry.get('url', ''),
                        method=entry.get('method', 'GET'),
                        headers=entry.get('headers', {}),
                        body=entry.get('body', '')
                    )
                    if request_id:
                        request_id_map[entry.get('id')] = request_id
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error processing request callback: {e}")
            
            elif entry_type == 'response' and self._on_response:
                try:
                    flow_id = entry.get('id')
                    our_request_id = request_id_map.get(flow_id, '')
                    if our_request_id:
                        self._on_response(
                            request_id=our_request_id,
                            status=entry.get('status', 0),
                            headers=entry.get('headers', {}),
                            body=entry.get('body', '')
                        )
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error processing response callback: {e}")
        
        self._last_processed_index = len(all_traffic)
        return processed_count
    
    def get_traffic_log_path(self) -> Path:
        """Get the path to the traffic log file"""
        return self._traffic_log_path


class PlaywrightMITMIntegration:
    """
    Integration layer for using MITM proxy with Playwright.
    Handles certificate trust and proxy configuration.
    """
    
    def __init__(self, mitm_proxy: JarwisMITMProxy):
        self.mitm_proxy = mitm_proxy
    
    def get_browser_context_options(self) -> Dict:
        """Get Playwright browser context options for MITM proxy"""
        proxy_settings = self.mitm_proxy.get_proxy_settings()
        
        return {
            'proxy': {
                'server': proxy_settings['server']
            },
            'ignore_https_errors': True,  # Trust MITM-generated certificates
            'user_agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    
    async def install_ca_certificate(self) -> bool:
        """
        Install the MITM CA certificate in the system trust store.
        This allows HTTPS interception without browser warnings.
        """
        ca_cert = self.mitm_proxy.ca_cert_path
        
        if not ca_cert.exists():
            logger.warning("CA certificate not found. Start the proxy first.")
            return False
        
        # Platform-specific certificate installation
        if sys.platform == "win32":
            return await self._install_cert_windows(ca_cert)
        elif sys.platform == "darwin":
            return await self._install_cert_macos(ca_cert)
        else:
            return await self._install_cert_linux(ca_cert)
    
    async def _install_cert_windows(self, ca_cert: Path) -> bool:
        """Install CA certificate on Windows"""
        try:
            # Use certutil to add to trusted root store
            result = subprocess.run(
                ["certutil", "-addstore", "-f", "ROOT", str(ca_cert)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("CA certificate installed in Windows trust store")
                return True
            else:
                logger.warning(f"Certificate install requires admin rights: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Failed to install certificate: {e}")
            return False
    
    async def _install_cert_macos(self, ca_cert: Path) -> bool:
        """Install CA certificate on macOS"""
        try:
            result = subprocess.run(
                ["security", "add-trusted-cert", "-d", "-r", "trustRoot", 
                 "-k", "/Library/Keychains/System.keychain", str(ca_cert)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("CA certificate installed in macOS Keychain")
                return True
            else:
                logger.warning(f"Certificate install requires admin rights: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Failed to install certificate: {e}")
            return False
    
    async def _install_cert_linux(self, ca_cert: Path) -> bool:
        """Install CA certificate on Linux"""
        try:
            # Copy to system certificates directory
            dest = Path("/usr/local/share/ca-certificates/jarwis-mitm.crt")
            subprocess.run(["sudo", "cp", str(ca_cert), str(dest)], check=True)
            subprocess.run(["sudo", "update-ca-certificates"], check=True)
            logger.info("CA certificate installed in Linux trust store")
            return True
        except Exception as e:
            logger.error(f"Failed to install certificate: {e}")
            return False


def check_mitm_capability() -> Dict:
    """
    Check if MITM proxy is properly configured and can intercept HTTPS.
    Returns a status dictionary.
    """
    status = {
        "mitmproxy_installed": False,
        "ca_cert_exists": False,
        "ca_cert_path": "",
        "can_intercept_https": False,
        "issues": []
    }
    
    # Check mitmproxy installation - use mitmdump which is the CLI tool
    try:
        result = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True,
            text=True
        )
        status["mitmproxy_installed"] = result.returncode == 0
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]
            logger.info(f"mitmproxy version: {version}")
    except FileNotFoundError:
        status["issues"].append("mitmproxy not found in PATH. Run: pip install mitmproxy")
    except Exception as e:
        status["issues"].append(f"mitmproxy check failed: {e}")
    
    # Check CA certificate
    cert_path = Path.home() / ".jarwis" / "certs" / "mitmproxy-ca-cert.pem"
    status["ca_cert_path"] = str(cert_path)
    status["ca_cert_exists"] = cert_path.exists()
    
    if not status["mitmproxy_installed"]:
        status["issues"].append("mitmproxy is not installed. Run: pip install mitmproxy")
    
    if not status["ca_cert_exists"]:
        status["issues"].append("CA certificate not generated. Start MITM proxy once to generate it.")
    
    # Overall status
    status["can_intercept_https"] = (
        status["mitmproxy_installed"] and 
        status["ca_cert_exists"]
    )
    
    return status


async def test_https_interception():
    """Test HTTPS interception capability"""
    print("\n" + "="*60)
    print("  Jarwis HTTPS Interception Test")
    print("="*60 + "\n")
    
    # Check current capability
    status = check_mitm_capability()
    
    print(f"  mitmproxy installed: {'[OK]' if status['mitmproxy_installed'] else '[FAIL]'}")
    print(f"  CA certificate exists: {'[OK]' if status['ca_cert_exists'] else '[FAIL]'}")
    print(f"  CA certificate path: {status['ca_cert_path']}")
    print(f"  Can intercept HTTPS: {'[OK]' if status['can_intercept_https'] else '[FAIL]'}")
    
    if status["issues"]:
        print("\n  Issues:")
        for issue in status["issues"]:
            print(f"    - {issue}")
    
    if not status["mitmproxy_installed"]:
        print("\n  Installing mitmproxy...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "mitmproxy"], check=True)
            print("  [OK] mitmproxy installed successfully")
        except Exception as e:
            print(f"  [FAIL] Failed to install mitmproxy: {e}")
            return False
    
    # Start proxy to generate certificates
    if not status["ca_cert_exists"]:
        print("\n  Starting proxy to generate certificates...")
        proxy = JarwisMITMProxy()
        success = await proxy.start()
        if success:
            print("  [OK] MITM proxy started")
            print(f"  [OK] CA certificate generated at: {proxy.ca_cert_path}")
            await asyncio.sleep(2)
            await proxy.stop()
            print("  [OK] MITM proxy stopped")
        else:
            print("  [FAIL] Failed to start MITM proxy")
            return False
    
    print("\n" + "="*60)
    print("  HTTPS Interception Ready!")
    print("="*60)
    print(f"\n  To use with browser, configure proxy: 127.0.0.1:8080")
    print(f"  CA Certificate: {status['ca_cert_path']}")
    print("\n  For Windows, run as admin to install CA cert:")
    print(f"    certutil -addstore -f ROOT \"{status['ca_cert_path']}\"")
    print("\n")
    
    return True


if __name__ == "__main__":
    asyncio.run(test_https_interception())
