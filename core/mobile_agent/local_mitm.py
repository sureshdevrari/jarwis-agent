"""
Jarwis Mobile Agent - Local MITM Proxy Manager

Manages a local mitmproxy instance for capturing mobile app traffic.
Provides callback mechanism for traffic relay to server.
"""

import asyncio
import logging
import os
import signal
import sys
from typing import Dict, Optional, Callable, Awaitable, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class MITMAddon:
    """
    Mitmproxy addon for capturing traffic.
    Invokes callback for each request/response pair.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def set_callback(self, callback: Callable):
        self.callback = callback
    
    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
    
    def response(self, flow):
        """Called when response is received"""
        if not self.callback:
            return
        
        try:
            # Extract request data
            url = flow.request.pretty_url
            method = flow.request.method
            request_headers = dict(flow.request.headers)
            request_body = flow.request.get_text() if flow.request.content else ""
            
            # Extract response data
            response_status = flow.response.status_code
            response_headers = dict(flow.response.headers)
            response_body = ""
            
            # Get response body (with size limit)
            if flow.response.content:
                content_type = response_headers.get("content-type", "")
                if "text" in content_type or "json" in content_type or "xml" in content_type:
                    try:
                        response_body = flow.response.get_text()[:100000]
                    except Exception:
                        response_body = "[binary content]"
            
            # Calculate duration
            duration_ms = 0
            if hasattr(flow, 'request') and hasattr(flow.request, 'timestamp_start'):
                if hasattr(flow, 'response') and hasattr(flow.response, 'timestamp_end'):
                    duration_ms = int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
            
            # Invoke callback
            if self._loop and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.callback(
                        url=url,
                        method=method,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_status=response_status,
                        response_headers=response_headers,
                        response_body=response_body,
                        duration_ms=duration_ms
                    ),
                    self._loop
                )
                
        except Exception as e:
            logger.error(f"Error processing flow: {e}")


class LocalMITMManager:
    """
    Manages local mitmproxy instance for mobile traffic interception.
    
    Features:
    - Automatic CA certificate generation
    - Traffic callback for relay
    - Port management
    - Graceful shutdown
    """
    
    def __init__(
        self,
        port: int = 8082,
        data_dir: Optional[str] = None
    ):
        self.port = port
        self.data_dir = Path(data_dir) if data_dir else Path.home() / ".jarwis" / "agent"
        
        self._process: Optional[asyncio.subprocess.Process] = None
        self._master = None
        self._addon: Optional[MITMAddon] = None
        self._running = False
        self._traffic_callback: Optional[Callable] = None
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir = self.data_dir / "certs"
        self.certs_dir.mkdir(exist_ok=True)
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def ca_cert_path(self) -> Path:
        """Path to CA certificate for device installation"""
        return self.certs_dir / "mitmproxy-ca-cert.pem"
    
    def set_traffic_callback(self, callback: Optional[Callable]):
        """Set callback for captured traffic"""
        self._traffic_callback = callback
        if self._addon:
            self._addon.set_callback(callback)
    
    async def start(self) -> bool:
        """Start MITM proxy"""
        if self._running:
            logger.warning("MITM proxy already running")
            return True
        
        logger.info(f"Starting MITM proxy on port {self.port}...")
        
        try:
            # Try in-process mitmproxy first (better integration)
            if await self._start_inprocess():
                return True
            
            # Fall back to subprocess
            return await self._start_subprocess()
            
        except Exception as e:
            logger.error(f"Failed to start MITM proxy: {e}")
            return False
    
    async def _start_inprocess(self) -> bool:
        """Start mitmproxy in-process using asyncio"""
        try:
            from mitmproxy import options
            from mitmproxy.tools import dump
            
            # Create addon
            self._addon = MITMAddon(self._traffic_callback)
            self._addon.set_loop(asyncio.get_event_loop())
            
            # Configure options
            opts = options.Options(
                listen_port=self.port,
                confdir=str(self.certs_dir),
                ssl_insecure=True,  # Accept invalid upstream certs
            )
            
            # Create master in background thread
            # (mitmproxy has its own event loop)
            import threading
            
            def run_proxy():
                from mitmproxy.tools.dump import DumpMaster
                
                master = DumpMaster(opts)
                master.addons.add(self._addon)
                self._master = master
                
                try:
                    master.run()
                except Exception as e:
                    logger.error(f"MITM proxy error: {e}")
            
            self._proxy_thread = threading.Thread(target=run_proxy, daemon=True)
            self._proxy_thread.start()
            
            # Wait for startup
            await asyncio.sleep(1)
            
            self._running = True
            logger.info(f"MITM proxy started (in-process) on port {self.port}")
            logger.info(f"CA certificate: {self.ca_cert_path}")
            
            return True
            
        except ImportError:
            logger.warning("mitmproxy not available for in-process mode")
            return False
        except Exception as e:
            logger.error(f"In-process MITM failed: {e}")
            return False
    
    async def _start_subprocess(self) -> bool:
        """Start mitmproxy as subprocess"""
        try:
            # Build command
            cmd = [
                sys.executable, "-m", "mitmproxy.tools.main",
                "mitmdump",
                "--listen-port", str(self.port),
                "--set", f"confdir={self.certs_dir}",
                "--ssl-insecure",
                "--quiet"
            ]
            
            # Add script for traffic capture (if we have one)
            script_path = self._create_capture_script()
            if script_path:
                cmd.extend(["-s", str(script_path)])
            
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for startup
            await asyncio.sleep(2)
            
            if self._process.returncode is not None:
                stderr = await self._process.stderr.read()
                logger.error(f"MITM proxy failed to start: {stderr.decode()}")
                return False
            
            self._running = True
            logger.info(f"MITM proxy started (subprocess) on port {self.port}")
            
            return True
            
        except Exception as e:
            logger.error(f"Subprocess MITM failed: {e}")
            return False
    
    def _create_capture_script(self) -> Optional[Path]:
        """Create mitmproxy addon script for traffic capture"""
        script_content = '''
import json
import os
import sys
from datetime import datetime

# Output file for captured traffic
OUTPUT_FILE = os.environ.get("JARWIS_TRAFFIC_FILE", "traffic.jsonl")

def response(flow):
    """Log each request/response"""
    try:
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text() if flow.request.content else "",
            "response_status": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
        }
        
        # Response body (with limits)
        if flow.response.content:
            content_type = flow.response.headers.get("content-type", "")
            if "text" in content_type or "json" in content_type:
                try:
                    data["response_body"] = flow.response.get_text()[:50000]
                except:
                    data["response_body"] = "[decode error]"
        
        with open(OUTPUT_FILE, "a") as f:
            f.write(json.dumps(data) + "\\n")
            
    except Exception as e:
        print(f"Capture error: {e}", file=sys.stderr)
'''
        
        script_path = self.data_dir / "mitm_capture.py"
        try:
            script_path.write_text(script_content)
            return script_path
        except Exception:
            return None
    
    async def stop(self):
        """Stop MITM proxy"""
        if not self._running:
            return
        
        logger.info("Stopping MITM proxy...")
        
        try:
            # Stop in-process master
            if self._master:
                self._master.shutdown()
                self._master = None
            
            # Stop subprocess
            if self._process:
                self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self._process.kill()
                self._process = None
                
        except Exception as e:
            logger.error(f"Error stopping MITM: {e}")
        finally:
            self._running = False
            logger.info("MITM proxy stopped")
    
    async def get_ca_certificate(self) -> Optional[bytes]:
        """Get CA certificate content for device installation"""
        if self.ca_cert_path.exists():
            return self.ca_cert_path.read_bytes()
        return None
    
    def get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration for device setup"""
        return {
            "host": "127.0.0.1",
            "port": self.port,
            "ca_cert": str(self.ca_cert_path),
            "type": "http"
        }


class TrafficFileWatcher:
    """
    Watches traffic file written by mitmproxy subprocess.
    Used when in-process mode isn't available.
    """
    
    def __init__(
        self,
        file_path: Path,
        callback: Callable
    ):
        self.file_path = file_path
        self.callback = callback
        self._running = False
        self._position = 0
    
    async def start(self):
        """Start watching traffic file"""
        self._running = True
        
        while self._running:
            try:
                if self.file_path.exists():
                    with open(self.file_path, 'r') as f:
                        f.seek(self._position)
                        for line in f:
                            if line.strip():
                                import json
                                data = json.loads(line)
                                await self.callback(**data)
                        self._position = f.tell()
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Traffic file watcher error: {e}")
                await asyncio.sleep(1)
    
    def stop(self):
        self._running = False
