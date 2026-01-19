"""
Jarwis Universal Agent - Multi-Scan Support Module

Extends the mobile agent to support all security testing types:
- Mobile Dynamic Analysis (Frida, ADB, MITM)
- Internal Network Scanning (port scan, service detection, CVE)
- Internal Web Application Testing (proxy for internal URLs)
- On-Premise Cloud Infrastructure Testing

This module adds network and web scanning capabilities alongside mobile.
"""

import asyncio
import logging
import socket
import ipaddress
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ScanType(str, Enum):
    """Supported scan types for the universal agent"""
    MOBILE_DYNAMIC = "mobile_dynamic"
    NETWORK_INTERNAL = "network_internal"
    WEB_INTERNAL = "web_internal"
    CLOUD_ONPREM = "cloud_onprem"


@dataclass
class NetworkScanConfig:
    """Configuration for network scanning"""
    target_range: str = ""  # CIDR or IP range
    ports: List[int] = field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443])
    scan_type: str = "tcp_connect"  # tcp_connect, syn, udp
    timeout: float = 2.0
    max_concurrent: int = 100
    service_detection: bool = True
    os_detection: bool = False
    vuln_scan: bool = True


@dataclass
class WebScanConfig:
    """Configuration for internal web scanning"""
    target_url: str = ""
    crawl_depth: int = 3
    include_subdomains: bool = False
    authentication: Optional[Dict[str, str]] = None
    custom_headers: Optional[Dict[str, str]] = None


class UniversalCapabilities:
    """
    Detects and reports agent capabilities across all scan types.
    """
    
    def __init__(self):
        self.capabilities = {}
    
    async def detect_all(self) -> Dict[str, Any]:
        """Detect all agent capabilities"""
        results = {
            "scan_types": [],
            "mobile": await self._detect_mobile_capabilities(),
            "network": await self._detect_network_capabilities(),
            "web": await self._detect_web_capabilities(),
            "system": await self._detect_system_capabilities(),
        }
        
        # Determine supported scan types
        if results["mobile"]["available"]:
            results["scan_types"].append(ScanType.MOBILE_DYNAMIC.value)
        if results["network"]["available"]:
            results["scan_types"].append(ScanType.NETWORK_INTERNAL.value)
        if results["web"]["available"]:
            results["scan_types"].append(ScanType.WEB_INTERNAL.value)
        
        return results
    
    async def _detect_mobile_capabilities(self) -> Dict[str, Any]:
        """Detect mobile testing capabilities"""
        result = {
            "available": False,
            "adb": False,
            "frida": False,
            "emulator": False,
            "devices": [],
        }
        
        # Check ADB
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "devices",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                result["adb"] = True
                # Parse devices
                lines = stdout.decode().strip().split('\n')[1:]
                for line in lines:
                    if '\t' in line:
                        device_id, status = line.split('\t')
                        if status == 'device':
                            result["devices"].append(device_id)
        except FileNotFoundError:
            pass
        
        # Check Frida
        try:
            import frida
            result["frida"] = True
            result["frida_version"] = frida.__version__
        except ImportError:
            pass
        
        result["available"] = result["adb"] and result["frida"]
        result["emulator"] = any('emulator' in d for d in result["devices"])
        
        return result
    
    async def _detect_network_capabilities(self) -> Dict[str, Any]:
        """Detect network scanning capabilities"""
        result = {
            "available": True,  # Basic network scanning always available
            "nmap": False,
            "raw_sockets": False,
            "local_interfaces": [],
            "reachable_networks": [],
        }
        
        # Check for nmap
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                result["nmap"] = True
        except FileNotFoundError:
            pass
        
        # Check for raw socket capability (needed for SYN scans)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            result["raw_sockets"] = True
        except (PermissionError, OSError):
            pass
        
        # Get local network interfaces
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        if ip and not ip.startswith('127.'):
                            result["local_interfaces"].append({
                                "interface": iface,
                                "ip": ip,
                                "netmask": netmask,
                            })
                            # Calculate network range
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                result["reachable_networks"].append(str(network))
                            except:
                                pass
        except ImportError:
            # Fallback without netifaces
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            result["local_interfaces"].append({
                "interface": "default",
                "ip": local_ip,
                "netmask": "255.255.255.0",
            })
        
        return result
    
    async def _detect_web_capabilities(self) -> Dict[str, Any]:
        """Detect web scanning capabilities"""
        result = {
            "available": True,
            "mitmproxy": False,
            "browser_automation": False,
        }
        
        # Check mitmproxy
        try:
            import mitmproxy
            result["mitmproxy"] = True
        except ImportError:
            pass
        
        # Check for browser automation
        try:
            from playwright.sync_api import sync_playwright
            result["browser_automation"] = True
        except ImportError:
            pass
        
        return result
    
    async def _detect_system_capabilities(self) -> Dict[str, Any]:
        """Detect system-level capabilities"""
        import platform
        import psutil
        
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "hostname": socket.gethostname(),
            "cpu_count": psutil.cpu_count(),
            "memory_gb": round(psutil.virtual_memory().total / (1024**3), 1),
            "disk_free_gb": round(psutil.disk_usage('/').free / (1024**3), 1),
        }


class NetworkScanner:
    """
    Internal network scanner for port scanning, service detection, and vulnerability assessment.
    Runs on the agent to scan internal networks not accessible from the cloud.
    """
    
    def __init__(self, config: NetworkScanConfig):
        self.config = config
        self._running = False
        self._results = []
    
    async def scan(self, progress_callback=None) -> List[Dict[str, Any]]:
        """
        Execute network scan based on configuration.
        
        Args:
            progress_callback: Async function to report progress
        
        Returns:
            List of discovered hosts with open ports and services
        """
        self._running = True
        self._results = []
        
        try:
            # Parse target range
            targets = self._parse_targets(self.config.target_range)
            total_targets = len(targets) * len(self.config.ports)
            scanned = 0
            
            # Create semaphore for concurrency control
            semaphore = asyncio.Semaphore(self.config.max_concurrent)
            
            async def scan_port(ip: str, port: int):
                nonlocal scanned
                async with semaphore:
                    if not self._running:
                        return None
                    
                    result = await self._tcp_connect_scan(ip, port)
                    scanned += 1
                    
                    if progress_callback and scanned % 100 == 0:
                        progress = int((scanned / total_targets) * 100)
                        await progress_callback(progress, f"Scanned {scanned}/{total_targets}")
                    
                    return result
            
            # Create all scan tasks
            tasks = []
            for ip in targets:
                for port in self.config.ports:
                    tasks.append(scan_port(ip, port))
            
            # Execute all scans
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Aggregate results by host
            hosts = {}
            for result in results:
                if isinstance(result, dict) and result.get("open"):
                    ip = result["ip"]
                    if ip not in hosts:
                        hosts[ip] = {
                            "ip": ip,
                            "hostname": await self._resolve_hostname(ip),
                            "ports": [],
                            "services": [],
                        }
                    hosts[ip]["ports"].append({
                        "port": result["port"],
                        "state": "open",
                        "service": result.get("service", "unknown"),
                        "version": result.get("version", ""),
                    })
            
            self._results = list(hosts.values())
            
            # Run service detection on open ports
            if self.config.service_detection:
                await self._detect_services()
            
            return self._results
            
        finally:
            self._running = False
    
    def stop(self):
        """Stop ongoing scan"""
        self._running = False
    
    def _parse_targets(self, target_range: str) -> List[str]:
        """Parse target range into list of IPs"""
        targets = []
        
        try:
            # Try as CIDR
            network = ipaddress.ip_network(target_range, strict=False)
            for ip in network.hosts():
                targets.append(str(ip))
        except ValueError:
            # Try as single IP or hostname
            try:
                ip = socket.gethostbyname(target_range)
                targets.append(ip)
            except socket.gaierror:
                # Try as IP range (e.g., 192.168.1.1-50)
                if '-' in target_range:
                    base, end = target_range.rsplit('.', 1)[0], target_range.rsplit('-', 1)
                    # Simplified range parsing
                    pass
        
        return targets[:10000]  # Limit to 10k hosts
    
    async def _tcp_connect_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Perform TCP connect scan on a single port"""
        result = {"ip": ip, "port": port, "open": False}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.config.timeout
            )
            result["open"] = True
            
            # Try to grab banner
            try:
                writer.write(b"\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                result["banner"] = banner.decode(errors='ignore').strip()
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        
        return result
    
    async def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return None
    
    async def _detect_services(self):
        """Detect services on open ports"""
        # Common port to service mapping
        port_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            8080: "http-proxy", 8443: "https-alt",
        }
        
        for host in self._results:
            for port_info in host["ports"]:
                port = port_info["port"]
                if port in port_services:
                    port_info["service"] = port_services[port]
                
                # Add to services list
                if port_info["service"] != "unknown":
                    host["services"].append(port_info["service"])


class InternalWebScanner:
    """
    Scanner for internal web applications not accessible from the internet.
    Proxies requests through the agent to reach internal URLs.
    """
    
    def __init__(self, config: WebScanConfig):
        self.config = config
    
    async def probe(self) -> Dict[str, Any]:
        """
        Probe the internal web application for basic information.
        """
        import aiohttp
        
        result = {
            "url": self.config.target_url,
            "reachable": False,
            "status_code": None,
            "server": None,
            "technologies": [],
            "security_headers": {},
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = self.config.custom_headers or {}
                async with session.get(
                    self.config.target_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,  # Skip SSL verification for internal testing
                ) as response:
                    result["reachable"] = True
                    result["status_code"] = response.status
                    result["server"] = response.headers.get("Server", "")
                    
                    # Check security headers
                    security_headers = [
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                        "X-XSS-Protection",
                    ]
                    for header in security_headers:
                        result["security_headers"][header] = response.headers.get(header)
                    
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def relay_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str] = None,
        body: bytes = None,
    ) -> Dict[str, Any]:
        """
        Relay an HTTP request to the internal web application.
        Used by the cloud to send attack payloads through the agent.
        """
        import aiohttp
        from urllib.parse import urljoin
        
        url = urljoin(self.config.target_url, path)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False,
                ) as response:
                    return {
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "body": await response.read(),
                        "url": str(response.url),
                    }
        except Exception as e:
            return {
                "error": str(e),
                "status_code": 0,
            }
