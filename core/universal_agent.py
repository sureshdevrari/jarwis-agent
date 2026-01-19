"""
Jarwis Universal Security Agent
================================

Comprehensive security testing agent that handles ALL scan types:
- Web Application Security (OWASP Top 10, API, Auth)
- Mobile Security (Static Analysis, Dynamic Analysis)
- Network Security (Port Scanning, Vuln Assessment)
- Cloud Security (AWS, Azure, GCP, Kubernetes)
- SAST (Static Application Security Testing)

The agent is REQUIRED for all scan types to ensure:
1. Security - All tests run through authenticated agent
2. Internal Access - Can reach internal/private networks
3. Credential Safety - Sensitive creds never leave client machine
4. Compliance - Audit trail of all security tests

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │                      JARWIS SERVER (Cloud)                          │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │
    │  │ Scan        │  │ WebSocket   │  │ Attack Orchestrator         │ │
    │  │ Manager     │  │ Gateway     │  │ (coordinates attacks)       │ │
    │  │             │  │ (wss://)    │  │                             │ │
    │  └─────────────┘  └──────┬──────┘  └─────────────────────────────┘ │
    └──────────────────────────┼──────────────────────────────────────────┘
                               │ Secure WebSocket
    ┌──────────────────────────┼──────────────────────────────────────────┐
    │                      CLIENT MACHINE (Agent)                         │
    │  ┌─────────────────────────────────────────────────────────────┐   │
    │  │               Universal Jarwis Agent                        │   │
    │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ │   │
    │  │  │   Web   │ │ Mobile  │ │ Network │ │  Cloud  │ │ SAST  │ │   │
    │  │  │Executor │ │Executor │ │Executor │ │Executor │ │Execut.│ │   │
    │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └───────┘ │   │
    │  └─────────────────────────────────────────────────────────────┘   │
    │                                                                     │
    │  ┌─────────────────────────────────────────────────────────────┐   │
    │  │ Local Resources: Browser, ADB, Frida, Docker, Cloud CLIs   │   │
    │  └─────────────────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────────────┘
"""

import asyncio
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import aiohttp
import websockets
from websockets.client import WebSocketClientProtocol

logger = logging.getLogger(__name__)


# ==============================================================================
# Enums and Data Classes
# ==============================================================================

class ScanType(str, Enum):
    """All supported scan types - matches attacks/ folder structure"""
    WEB = "web"
    MOBILE_STATIC = "mobile_static"
    MOBILE_DYNAMIC = "mobile_dynamic"
    NETWORK = "network"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"
    CLOUD_K8S = "cloud_kubernetes"
    SAST = "sast"


class AgentStatus(str, Enum):
    """Agent connection status"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    SCANNING = "scanning"
    ERROR = "error"


class MessageType(str, Enum):
    """WebSocket message types"""
    # Agent -> Server
    REGISTER = "register"
    CAPABILITIES = "capabilities"
    HEARTBEAT = "heartbeat"
    ATTACK_RESULT = "attack_result"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETE = "scan_complete"
    ERROR = "error"
    LOG = "log"
    
    # Server -> Agent
    ATTACK_REQUEST = "attack_request"
    SCAN_START = "scan_start"
    SCAN_STOP = "scan_stop"
    CONFIG_UPDATE = "config_update"
    PING = "ping"


@dataclass
class AgentConfig:
    """Configuration for the universal agent"""
    server_url: str = ""
    auth_token: str = ""
    agent_id: str = ""
    agent_name: str = ""
    data_dir: str = ""
    
    # Feature flags
    enable_web: bool = True
    enable_mobile: bool = True
    enable_network: bool = True
    enable_cloud: bool = True
    enable_sast: bool = True
    
    # Network settings
    mitm_port: int = 8082
    proxy_port: int = 8083
    
    # Timeouts
    connect_timeout: int = 30
    attack_timeout: int = 300
    heartbeat_interval: int = 30
    
    def __post_init__(self):
        if not self.agent_id:
            self.agent_id = f"agent-{uuid.uuid4().hex[:12]}"
        if not self.data_dir:
            self.data_dir = str(Path.home() / ".jarwis" / "agent")
        if not self.agent_name:
            self.agent_name = f"{platform.node()}-{self.agent_id[:8]}"


@dataclass
class AttackRequest:
    """Request to execute an attack"""
    attack_id: str
    scan_id: str
    scan_type: ScanType
    attack_type: str  # e.g., "sqli", "xss", "port_scan"
    target: Dict[str, Any]
    payload: Dict[str, Any]
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    """Result of an attack execution"""
    attack_id: str
    scan_id: str
    success: bool
    vulnerable: bool = False
    severity: str = "info"
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0


# ==============================================================================
# Capability Detection
# ==============================================================================

class UniversalAgentCapabilities:
    """
    Detects and reports what security testing capabilities this agent has.
    Checks for required tools, permissions, and resources.
    """
    
    def __init__(self):
        self.capabilities: Dict[str, Any] = {}
        self._detected = False
    
    async def detect_all(self) -> Dict[str, Any]:
        """Detect all agent capabilities"""
        if self._detected:
            return self.capabilities
        
        self.capabilities = {
            "agent_version": "2.0.0",
            "scan_types": [],
            "system": await self._detect_system(),
            "web": await self._detect_web_capabilities(),
            "mobile": await self._detect_mobile_capabilities(),
            "network": await self._detect_network_capabilities(),
            "cloud": await self._detect_cloud_capabilities(),
            "sast": await self._detect_sast_capabilities(),
        }
        
        # Determine available scan types
        if self.capabilities["web"]["available"]:
            self.capabilities["scan_types"].append(ScanType.WEB.value)
        
        if self.capabilities["mobile"]["static_available"]:
            self.capabilities["scan_types"].append(ScanType.MOBILE_STATIC.value)
        if self.capabilities["mobile"]["dynamic_available"]:
            self.capabilities["scan_types"].append(ScanType.MOBILE_DYNAMIC.value)
        
        if self.capabilities["network"]["available"]:
            self.capabilities["scan_types"].append(ScanType.NETWORK.value)
        
        if self.capabilities["cloud"]["aws_available"]:
            self.capabilities["scan_types"].append(ScanType.CLOUD_AWS.value)
        if self.capabilities["cloud"]["azure_available"]:
            self.capabilities["scan_types"].append(ScanType.CLOUD_AZURE.value)
        if self.capabilities["cloud"]["gcp_available"]:
            self.capabilities["scan_types"].append(ScanType.CLOUD_GCP.value)
        if self.capabilities["cloud"]["k8s_available"]:
            self.capabilities["scan_types"].append(ScanType.CLOUD_K8S.value)
        
        if self.capabilities["sast"]["available"]:
            self.capabilities["scan_types"].append(ScanType.SAST.value)
        
        self._detected = True
        return self.capabilities
    
    async def _detect_system(self) -> Dict[str, Any]:
        """Detect system information"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            return {
                "os": platform.system(),
                "os_version": platform.version(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
                "hostname": socket.gethostname(),
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": round(memory.total / (1024**3), 1),
                "memory_available_gb": round(memory.available / (1024**3), 1),
                "disk_free_gb": round(disk.free / (1024**3), 1),
            }
        except ImportError:
            return {
                "os": platform.system(),
                "os_version": platform.version(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
                "hostname": socket.gethostname(),
            }
    
    async def _detect_web_capabilities(self) -> Dict[str, Any]:
        """Detect web testing capabilities"""
        result = {
            "available": True,  # Basic HTTP always available
            "browser_automation": False,
            "playwright_browsers": [],
            "mitmproxy": False,
            "http_client": True,
        }
        
        # Check Playwright
        try:
            from playwright.async_api import async_playwright
            result["browser_automation"] = True
            # Check installed browsers
            browser_path = Path.home() / ".cache" / "ms-playwright"
            if browser_path.exists():
                for browser_dir in browser_path.iterdir():
                    if browser_dir.is_dir():
                        result["playwright_browsers"].append(browser_dir.name)
        except ImportError:
            pass
        
        # Check mitmproxy
        try:
            import mitmproxy
            result["mitmproxy"] = True
        except ImportError:
            pass
        
        return result
    
    async def _detect_mobile_capabilities(self) -> Dict[str, Any]:
        """Detect mobile testing capabilities"""
        result = {
            "static_available": True,  # APK/IPA analysis always possible
            "dynamic_available": False,
            "adb": False,
            "adb_version": None,
            "frida": False,
            "frida_version": None,
            "connected_devices": [],
            "emulator_available": False,
            "ios_deploy": False,
        }
        
        # Check ADB
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                result["adb"] = True
                version_line = stdout.decode().split('\n')[0]
                result["adb_version"] = version_line
                
                # List connected devices
                proc2 = await asyncio.create_subprocess_exec(
                    "adb", "devices", "-l",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout2, _ = await proc2.communicate()
                for line in stdout2.decode().split('\n')[1:]:
                    if '\t' in line or 'device' in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] == 'device':
                            result["connected_devices"].append(parts[0])
        except FileNotFoundError:
            pass
        
        # Check Frida
        try:
            import frida
            result["frida"] = True
            result["frida_version"] = frida.__version__
        except ImportError:
            pass
        
        # Check emulator
        emulator_paths = [
            os.environ.get("ANDROID_HOME", "") + "/emulator/emulator",
            os.environ.get("ANDROID_SDK_ROOT", "") + "/emulator/emulator",
            str(Path.home() / "AppData/Local/Android/Sdk/emulator/emulator.exe"),
            "/usr/local/android-sdk/emulator/emulator",
        ]
        for path in emulator_paths:
            if path and Path(path).exists():
                result["emulator_available"] = True
                break
        
        # Dynamic available if ADB + Frida + (device or emulator)
        result["dynamic_available"] = (
            result["adb"] and 
            result["frida"] and 
            (len(result["connected_devices"]) > 0 or result["emulator_available"])
        )
        
        # Check ios-deploy for iOS
        try:
            proc = await asyncio.create_subprocess_exec(
                "ios-deploy", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                result["ios_deploy"] = True
        except FileNotFoundError:
            pass
        
        return result
    
    async def _detect_network_capabilities(self) -> Dict[str, Any]:
        """Detect network scanning capabilities"""
        result = {
            "available": True,  # Basic socket scanning always available
            "nmap": False,
            "nmap_version": None,
            "masscan": False,
            "raw_sockets": False,
            "local_interfaces": [],
        }
        
        # Check nmap
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                result["nmap"] = True
                result["nmap_version"] = stdout.decode().split('\n')[0]
        except FileNotFoundError:
            pass
        
        # Check masscan
        try:
            proc = await asyncio.create_subprocess_exec(
                "masscan", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                result["masscan"] = True
        except FileNotFoundError:
            pass
        
        # Check raw socket capability
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            result["raw_sockets"] = True
        except (PermissionError, OSError):
            pass
        
        # Get local interfaces
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if 2 in addrs:  # AF_INET
                    for addr in addrs[2]:
                        ip = addr.get('addr')
                        if ip and not ip.startswith('127.'):
                            result["local_interfaces"].append({
                                "name": iface,
                                "ip": ip,
                                "netmask": addr.get('netmask', '255.255.255.0'),
                            })
        except ImportError:
            # Fallback
            hostname = socket.gethostname()
            try:
                ip = socket.gethostbyname(hostname)
                result["local_interfaces"].append({
                    "name": "default",
                    "ip": ip,
                    "netmask": "255.255.255.0",
                })
            except socket.gaierror:
                pass
        
        return result
    
    async def _detect_cloud_capabilities(self) -> Dict[str, Any]:
        """Detect cloud security testing capabilities"""
        result = {
            "aws_available": False,
            "aws_cli": False,
            "aws_configured": False,
            "azure_available": False,
            "azure_cli": False,
            "azure_configured": False,
            "gcp_available": False,
            "gcloud_cli": False,
            "gcp_configured": False,
            "k8s_available": False,
            "kubectl": False,
            "k8s_context": None,
            "docker": False,
        }
        
        # Check AWS CLI
        try:
            proc = await asyncio.create_subprocess_exec(
                "aws", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                result["aws_cli"] = True
                # Check if configured
                proc2 = await asyncio.create_subprocess_exec(
                    "aws", "sts", "get-caller-identity",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc2.communicate()
                result["aws_configured"] = proc2.returncode == 0
                result["aws_available"] = result["aws_configured"]
        except FileNotFoundError:
            pass
        
        # Check Azure CLI
        try:
            proc = await asyncio.create_subprocess_exec(
                "az", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                result["azure_cli"] = True
                # Check if logged in
                proc2 = await asyncio.create_subprocess_exec(
                    "az", "account", "show",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc2.communicate()
                result["azure_configured"] = proc2.returncode == 0
                result["azure_available"] = result["azure_configured"]
        except FileNotFoundError:
            pass
        
        # Check Google Cloud CLI
        try:
            proc = await asyncio.create_subprocess_exec(
                "gcloud", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                result["gcloud_cli"] = True
                # Check if configured
                proc2 = await asyncio.create_subprocess_exec(
                    "gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout2, _ = await proc2.communicate()
                result["gcp_configured"] = len(stdout2.decode().strip()) > 0
                result["gcp_available"] = result["gcp_configured"]
        except FileNotFoundError:
            pass
        
        # Check kubectl
        try:
            proc = await asyncio.create_subprocess_exec(
                "kubectl", "version", "--client",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                result["kubectl"] = True
                # Get current context
                proc2 = await asyncio.create_subprocess_exec(
                    "kubectl", "config", "current-context",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout2, _ = await proc2.communicate()
                if proc2.returncode == 0:
                    result["k8s_context"] = stdout2.decode().strip()
                    result["k8s_available"] = True
        except FileNotFoundError:
            pass
        
        # Check Docker
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            result["docker"] = proc.returncode == 0
        except FileNotFoundError:
            pass
        
        return result
    
    async def _detect_sast_capabilities(self) -> Dict[str, Any]:
        """Detect SAST capabilities"""
        result = {
            "available": True,  # Basic regex scanning always available
            "semgrep": False,
            "semgrep_version": None,
            "bandit": False,
            "eslint": False,
            "supported_languages": ["python", "javascript", "java", "go", "ruby", "php"],
        }
        
        # Check Semgrep
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                result["semgrep"] = True
                result["semgrep_version"] = stdout.decode().strip()
        except FileNotFoundError:
            pass
        
        # Check Bandit (Python)
        try:
            proc = await asyncio.create_subprocess_exec(
                "bandit", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                result["bandit"] = True
        except FileNotFoundError:
            pass
        
        # Check ESLint (JavaScript)
        try:
            proc = await asyncio.create_subprocess_exec(
                "npx", "eslint", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            if proc.returncode == 0:
                result["eslint"] = True
        except FileNotFoundError:
            pass
        
        return result


# ==============================================================================
# Attack Executors
# ==============================================================================

class BaseAttackExecutor:
    """Base class for attack executors"""
    
    def __init__(self, agent: 'UniversalJarwisAgent'):
        self.agent = agent
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def execute(self, request: AttackRequest) -> AttackResult:
        """Execute an attack - to be implemented by subclasses"""
        raise NotImplementedError


class WebAttackExecutor(BaseAttackExecutor):
    """
    Executes web application attacks.
    Supports: SQL Injection, XSS, CSRF, Auth bypass, API testing, etc.
    """
    
    async def execute(self, request: AttackRequest) -> AttackResult:
        """Execute a web attack"""
        start_time = datetime.now()
        
        try:
            attack_type = request.attack_type
            target = request.target
            payload = request.payload
            
            # Route to specific attack handler
            if attack_type in ("sqli", "sql_injection"):
                result = await self._execute_sqli(target, payload, request.options)
            elif attack_type in ("xss", "cross_site_scripting"):
                result = await self._execute_xss(target, payload, request.options)
            elif attack_type == "http_request":
                result = await self._execute_http_request(target, payload, request.options)
            elif attack_type == "browser_action":
                result = await self._execute_browser_action(target, payload, request.options)
            else:
                result = await self._execute_generic(target, payload, request.options)
            
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success=True,
                vulnerable=result.get("vulnerable", False),
                severity=result.get("severity", "info"),
                evidence=result,
                duration_ms=duration
            )
            
        except Exception as e:
            self.logger.error(f"Web attack failed: {e}")
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success=False,
                error=str(e),
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000)
            )
    
    async def _execute_http_request(
        self, 
        target: Dict[str, Any], 
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a raw HTTP request"""
        url = target.get("url")
        method = payload.get("method", "GET").upper()
        headers = payload.get("headers", {})
        body = payload.get("body")
        
        timeout = aiohttp.ClientTimeout(total=options.get("timeout", 30))
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                ssl=not options.get("ignore_ssl", False),
                allow_redirects=options.get("follow_redirects", True),
            ) as response:
                response_body = await response.text()
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": response_body[:50000],  # Limit response size
                    "url": str(response.url),
                }
    
    async def _execute_sqli(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute SQL injection test"""
        # The payload contains the actual SQL injection test
        result = await self._execute_http_request(target, payload, options)
        
        # Check for SQL error indicators in response
        sql_errors = [
            "SQL syntax", "mysql_", "ORA-", "PostgreSQL", "sqlite",
            "SQLSTATE", "syntax error", "unclosed quotation",
        ]
        
        response_body = result.get("body", "").lower()
        vulnerable = any(err.lower() in response_body for err in sql_errors)
        
        if options.get("time_based"):
            # Time-based detection would be handled by measuring response time
            pass
        
        result["vulnerable"] = vulnerable
        result["severity"] = "critical" if vulnerable else "info"
        return result
    
    async def _execute_xss(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute XSS test"""
        result = await self._execute_http_request(target, payload, options)
        
        # Check if our payload is reflected
        xss_payload = payload.get("xss_payload", "")
        response_body = result.get("body", "")
        
        vulnerable = xss_payload in response_body
        
        result["vulnerable"] = vulnerable
        result["severity"] = "high" if vulnerable else "info"
        result["reflected"] = vulnerable
        return result
    
    async def _execute_browser_action(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute browser-based action using Playwright"""
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                # Navigate to URL
                await page.goto(target.get("url"), wait_until="networkidle")
                
                # Execute actions
                actions = payload.get("actions", [])
                for action in actions:
                    action_type = action.get("type")
                    if action_type == "click":
                        await page.click(action.get("selector"))
                    elif action_type == "fill":
                        await page.fill(action.get("selector"), action.get("value", ""))
                    elif action_type == "wait":
                        await page.wait_for_timeout(action.get("ms", 1000))
                
                # Capture result
                result = {
                    "url": page.url,
                    "title": await page.title(),
                    "content": await page.content(),
                }
                
                await browser.close()
                return result
                
        except ImportError:
            return {"error": "Playwright not available"}
    
    async def _execute_generic(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute generic web attack"""
        return await self._execute_http_request(target, payload, options)


class MobileAttackExecutor(BaseAttackExecutor):
    """
    Executes mobile security attacks.
    Supports: Static analysis, Dynamic analysis with Frida, Traffic interception
    """
    
    async def execute(self, request: AttackRequest) -> AttackResult:
        """Execute a mobile attack"""
        start_time = datetime.now()
        
        try:
            attack_type = request.attack_type
            target = request.target
            payload = request.payload
            
            if attack_type == "frida_inject":
                result = await self._execute_frida_inject(target, payload, request.options)
            elif attack_type == "adb_command":
                result = await self._execute_adb_command(target, payload, request.options)
            elif attack_type == "apk_static":
                result = await self._execute_static_analysis(target, payload, request.options)
            elif attack_type == "intercept_traffic":
                result = await self._start_traffic_intercept(target, payload, request.options)
            else:
                result = {"error": f"Unknown mobile attack type: {attack_type}"}
            
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success="error" not in result,
                vulnerable=result.get("vulnerable", False),
                severity=result.get("severity", "info"),
                evidence=result,
                duration_ms=duration
            )
            
        except Exception as e:
            self.logger.error(f"Mobile attack failed: {e}")
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success=False,
                error=str(e),
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000)
            )
    
    async def _execute_frida_inject(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Inject Frida script into app"""
        try:
            import frida
            
            device_id = target.get("device_id")
            package_name = target.get("package_name")
            script_code = payload.get("script")
            
            # Get device
            if device_id:
                device = frida.get_device(device_id)
            else:
                device = frida.get_usb_device()
            
            # Attach to process
            session = device.attach(package_name)
            
            # Create and load script
            script = session.create_script(script_code)
            
            results = []
            
            def on_message(message, data):
                results.append(message)
            
            script.on('message', on_message)
            script.load()
            
            # Wait for results
            await asyncio.sleep(options.get("timeout", 5))
            
            script.unload()
            session.detach()
            
            return {
                "package": package_name,
                "results": results,
                "success": True,
            }
            
        except ImportError:
            return {"error": "Frida not available"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _execute_adb_command(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute ADB command"""
        device_id = target.get("device_id")
        command = payload.get("command", [])
        
        if isinstance(command, str):
            command = command.split()
        
        adb_cmd = ["adb"]
        if device_id:
            adb_cmd.extend(["-s", device_id])
        adb_cmd.extend(command)
        
        proc = await asyncio.create_subprocess_exec(
            *adb_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        return {
            "command": " ".join(adb_cmd),
            "stdout": stdout.decode(errors='ignore'),
            "stderr": stderr.decode(errors='ignore'),
            "return_code": proc.returncode,
        }
    
    async def _execute_static_analysis(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute static analysis on APK/IPA"""
        file_path = target.get("file_path")
        checks = payload.get("checks", [])
        
        results = {
            "file": file_path,
            "findings": [],
        }
        
        # This would integrate with static analysis tools
        # For now, return placeholder
        return results
    
    async def _start_traffic_intercept(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Start MITM traffic interception"""
        # This integrates with the MITM proxy
        return {"status": "intercept_started"}


class NetworkAttackExecutor(BaseAttackExecutor):
    """
    Executes network security attacks.
    Supports: Port scanning, Service detection, Vulnerability assessment
    """
    
    async def execute(self, request: AttackRequest) -> AttackResult:
        """Execute a network attack"""
        start_time = datetime.now()
        
        try:
            attack_type = request.attack_type
            target = request.target
            payload = request.payload
            
            if attack_type == "port_scan":
                result = await self._execute_port_scan(target, payload, request.options)
            elif attack_type == "service_detect":
                result = await self._execute_service_detection(target, payload, request.options)
            elif attack_type == "vuln_check":
                result = await self._execute_vuln_check(target, payload, request.options)
            elif attack_type == "dns_enum":
                result = await self._execute_dns_enum(target, payload, request.options)
            else:
                result = {"error": f"Unknown network attack type: {attack_type}"}
            
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success="error" not in result,
                vulnerable=result.get("vulnerable", False),
                severity=result.get("severity", "info"),
                evidence=result,
                duration_ms=duration
            )
            
        except Exception as e:
            self.logger.error(f"Network attack failed: {e}")
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success=False,
                error=str(e),
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000)
            )
    
    async def _execute_port_scan(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute port scan"""
        host = target.get("host")
        ports = payload.get("ports", [80, 443, 22, 21, 25, 3306, 5432])
        timeout = options.get("timeout", 2.0)
        
        open_ports = []
        
        async def check_port(port: int) -> Optional[int]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        # Scan ports concurrently
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        open_ports = [p for p in results if p is not None]
        
        return {
            "host": host,
            "open_ports": open_ports,
            "scanned_ports": len(ports),
        }
    
    async def _execute_service_detection(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detect services on open ports"""
        host = target.get("host")
        ports = payload.get("ports", [])
        
        services = []
        
        # Common port->service mapping
        port_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 8080: "http-proxy", 8443: "https-alt",
        }
        
        for port in ports:
            service_info = {
                "port": port,
                "service": port_map.get(port, "unknown"),
                "banner": None,
            }
            
            # Try to grab banner
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2.0
                )
                writer.write(b"\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                service_info["banner"] = banner.decode(errors='ignore').strip()[:200]
                writer.close()
                await writer.wait_closed()
            except:
                pass
            
            services.append(service_info)
        
        return {
            "host": host,
            "services": services,
        }
    
    async def _execute_vuln_check(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check for known vulnerabilities"""
        host = target.get("host")
        port = target.get("port")
        check_type = payload.get("check_type")
        
        # This would integrate with vulnerability databases
        return {
            "host": host,
            "port": port,
            "vulnerabilities": [],
        }
    
    async def _execute_dns_enum(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enumerate DNS records"""
        domain = target.get("domain")
        record_types = payload.get("record_types", ["A", "AAAA", "MX", "NS", "TXT"])
        
        import socket
        
        records = {}
        
        for rtype in record_types:
            try:
                if rtype == "A":
                    records["A"] = socket.gethostbyname_ex(domain)[2]
            except:
                pass
        
        return {
            "domain": domain,
            "records": records,
        }


class CloudAttackExecutor(BaseAttackExecutor):
    """
    Executes cloud security checks.
    Supports: AWS, Azure, GCP, Kubernetes
    """
    
    async def execute(self, request: AttackRequest) -> AttackResult:
        """Execute a cloud security check"""
        start_time = datetime.now()
        
        try:
            scan_type = request.scan_type
            attack_type = request.attack_type
            target = request.target
            payload = request.payload
            
            if scan_type == ScanType.CLOUD_AWS:
                result = await self._execute_aws_check(attack_type, target, payload, request.options)
            elif scan_type == ScanType.CLOUD_AZURE:
                result = await self._execute_azure_check(attack_type, target, payload, request.options)
            elif scan_type == ScanType.CLOUD_GCP:
                result = await self._execute_gcp_check(attack_type, target, payload, request.options)
            elif scan_type == ScanType.CLOUD_K8S:
                result = await self._execute_k8s_check(attack_type, target, payload, request.options)
            else:
                result = {"error": f"Unknown cloud type: {scan_type}"}
            
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success="error" not in result,
                vulnerable=result.get("vulnerable", False),
                severity=result.get("severity", "info"),
                evidence=result,
                duration_ms=duration
            )
            
        except Exception as e:
            self.logger.error(f"Cloud check failed: {e}")
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success=False,
                error=str(e),
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000)
            )
    
    async def _execute_aws_check(
        self,
        check_type: str,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute AWS security check"""
        command = payload.get("command", [])
        
        if isinstance(command, str):
            command = command.split()
        
        proc = await asyncio.create_subprocess_exec(
            "aws", *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        try:
            output = json.loads(stdout.decode())
        except:
            output = stdout.decode()
        
        return {
            "check_type": check_type,
            "output": output,
            "error": stderr.decode() if stderr else None,
        }
    
    async def _execute_azure_check(
        self,
        check_type: str,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Azure security check"""
        command = payload.get("command", [])
        
        if isinstance(command, str):
            command = command.split()
        
        proc = await asyncio.create_subprocess_exec(
            "az", *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        try:
            output = json.loads(stdout.decode())
        except:
            output = stdout.decode()
        
        return {
            "check_type": check_type,
            "output": output,
            "error": stderr.decode() if stderr else None,
        }
    
    async def _execute_gcp_check(
        self,
        check_type: str,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute GCP security check"""
        command = payload.get("command", [])
        
        if isinstance(command, str):
            command = command.split()
        
        proc = await asyncio.create_subprocess_exec(
            "gcloud", *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        return {
            "check_type": check_type,
            "output": stdout.decode(),
            "error": stderr.decode() if stderr else None,
        }
    
    async def _execute_k8s_check(
        self,
        check_type: str,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Kubernetes security check"""
        command = payload.get("command", [])
        
        if isinstance(command, str):
            command = command.split()
        
        proc = await asyncio.create_subprocess_exec(
            "kubectl", *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        try:
            output = json.loads(stdout.decode())
        except:
            output = stdout.decode()
        
        return {
            "check_type": check_type,
            "output": output,
            "error": stderr.decode() if stderr else None,
        }


class SASTExecutor(BaseAttackExecutor):
    """
    Executes Static Application Security Testing.
    Supports: Semgrep, Bandit, ESLint, custom patterns
    """
    
    async def execute(self, request: AttackRequest) -> AttackResult:
        """Execute SAST analysis"""
        start_time = datetime.now()
        
        try:
            attack_type = request.attack_type
            target = request.target
            payload = request.payload
            
            if attack_type == "semgrep":
                result = await self._execute_semgrep(target, payload, request.options)
            elif attack_type == "bandit":
                result = await self._execute_bandit(target, payload, request.options)
            elif attack_type == "pattern_match":
                result = await self._execute_pattern_match(target, payload, request.options)
            else:
                result = {"error": f"Unknown SAST type: {attack_type}"}
            
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success="error" not in result,
                vulnerable=len(result.get("findings", [])) > 0,
                severity=result.get("severity", "info"),
                evidence=result,
                duration_ms=duration
            )
            
        except Exception as e:
            self.logger.error(f"SAST check failed: {e}")
            return AttackResult(
                attack_id=request.attack_id,
                scan_id=request.scan_id,
                success=False,
                error=str(e),
                duration_ms=int((datetime.now() - start_time).total_seconds() * 1000)
            )
    
    async def _execute_semgrep(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Semgrep analysis"""
        file_path = target.get("file_path")
        rules = payload.get("rules", "auto")
        
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--json", "--config", rules, file_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        try:
            findings = json.loads(stdout.decode())
            return {
                "tool": "semgrep",
                "findings": findings.get("results", []),
                "errors": findings.get("errors", []),
            }
        except:
            return {
                "tool": "semgrep",
                "findings": [],
                "error": stderr.decode(),
            }
    
    async def _execute_bandit(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Bandit analysis for Python"""
        file_path = target.get("file_path")
        
        proc = await asyncio.create_subprocess_exec(
            "bandit", "-f", "json", "-r", file_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        try:
            findings = json.loads(stdout.decode())
            return {
                "tool": "bandit",
                "findings": findings.get("results", []),
                "metrics": findings.get("metrics", {}),
            }
        except:
            return {
                "tool": "bandit",
                "findings": [],
                "error": stderr.decode(),
            }
    
    async def _execute_pattern_match(
        self,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute regex pattern matching for secrets/vulns"""
        import re
        
        file_path = target.get("file_path")
        patterns = payload.get("patterns", {})
        
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for pattern_name, pattern in patterns.items():
                    for line_num, line in enumerate(lines, 1):
                        matches = re.findall(pattern, line)
                        for match in matches:
                            findings.append({
                                "type": pattern_name,
                                "line": line_num,
                                "match": match[:100],  # Truncate
                            })
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "tool": "pattern_match",
            "findings": findings,
            "patterns_checked": len(patterns),
        }


# ==============================================================================
# Main Universal Agent
# ==============================================================================

class UniversalJarwisAgent:
    """
    Universal Jarwis Security Agent
    
    Handles all security testing types and is REQUIRED for all scans.
    Connects to Jarwis server via WebSocket and executes attacks locally.
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.status = AgentStatus.DISCONNECTED
        self.ws: Optional[WebSocketClientProtocol] = None
        self.capabilities = UniversalAgentCapabilities()
        self.logger = logging.getLogger(__name__)
        
        # Attack executors
        self.executors: Dict[str, BaseAttackExecutor] = {
            "web": WebAttackExecutor(self),
            "mobile": MobileAttackExecutor(self),
            "network": NetworkAttackExecutor(self),
            "cloud": CloudAttackExecutor(self),
            "sast": SASTExecutor(self),
        }
        
        # Active scans
        self.active_scans: Set[str] = set()
        
        # Message handlers
        self._handlers: Dict[str, Callable] = {}
        self._running = False
        
        # Ensure data directory exists
        Path(self.config.data_dir).mkdir(parents=True, exist_ok=True)
    
    async def connect(self) -> bool:
        """Connect to Jarwis server"""
        self.status = AgentStatus.CONNECTING
        
        try:
            # Detect capabilities first
            caps = await self.capabilities.detect_all()
            self.logger.info(f"Agent capabilities: {caps['scan_types']}")
            
            # Connect to WebSocket
            self.ws = await websockets.connect(
                self.config.server_url,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=10,
            )
            
            self.status = AgentStatus.CONNECTED
            
            # Send registration message
            await self._send_message(MessageType.REGISTER, {
                "agent_id": self.config.agent_id,
                "agent_name": self.config.agent_name,
                "token": self.config.auth_token,
                "version": "2.0.0",
            })
            
            # Send capabilities
            await self._send_message(MessageType.CAPABILITIES, caps)
            
            self.status = AgentStatus.AUTHENTICATED
            return True
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            self.status = AgentStatus.ERROR
            return False
    
    async def disconnect(self):
        """Disconnect from server"""
        self._running = False
        if self.ws:
            await self.ws.close()
        self.status = AgentStatus.DISCONNECTED
    
    async def run_forever(self):
        """Main agent loop - listen for and handle messages"""
        self._running = True
        
        try:
            async for message in self.ws:
                if not self._running:
                    break
                
                try:
                    data = json.loads(message)
                    await self._handle_message(data)
                except json.JSONDecodeError:
                    self.logger.warning(f"Invalid JSON message: {message[:100]}")
                except Exception as e:
                    self.logger.error(f"Error handling message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            self.logger.info("Connection closed by server")
        except Exception as e:
            self.logger.error(f"Agent error: {e}")
        finally:
            self._running = False
            self.status = AgentStatus.DISCONNECTED
    
    async def _send_message(self, msg_type: MessageType, data: Dict[str, Any]):
        """Send message to server"""
        if not self.ws:
            return
        
        message = {
            "type": msg_type.value,
            "agent_id": self.config.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data,
        }
        
        await self.ws.send(json.dumps(message))
    
    async def _handle_message(self, message: Dict[str, Any]):
        """Handle incoming message from server"""
        msg_type = message.get("type")
        data = message.get("data", {})
        
        if msg_type == MessageType.PING.value:
            await self._send_message(MessageType.HEARTBEAT, {"status": "ok"})
            
        elif msg_type == MessageType.ATTACK_REQUEST.value:
            await self._handle_attack_request(data)
            
        elif msg_type == MessageType.SCAN_START.value:
            await self._handle_scan_start(data)
            
        elif msg_type == MessageType.SCAN_STOP.value:
            await self._handle_scan_stop(data)
            
        elif msg_type == MessageType.CONFIG_UPDATE.value:
            await self._handle_config_update(data)
    
    async def _handle_attack_request(self, data: Dict[str, Any]):
        """Handle attack request from server"""
        try:
            request = AttackRequest(
                attack_id=data["attack_id"],
                scan_id=data["scan_id"],
                scan_type=ScanType(data["scan_type"]),
                attack_type=data["attack_type"],
                target=data["target"],
                payload=data["payload"],
                options=data.get("options", {}),
            )
            
            # Route to appropriate executor
            executor = self._get_executor(request.scan_type)
            if not executor:
                await self._send_message(MessageType.ATTACK_RESULT, {
                    "attack_id": request.attack_id,
                    "success": False,
                    "error": f"No executor for scan type: {request.scan_type}",
                })
                return
            
            # Execute attack
            self.status = AgentStatus.SCANNING
            result = await executor.execute(request)
            
            # Send result back
            await self._send_message(MessageType.ATTACK_RESULT, {
                "attack_id": result.attack_id,
                "scan_id": result.scan_id,
                "success": result.success,
                "vulnerable": result.vulnerable,
                "severity": result.severity,
                "evidence": result.evidence,
                "error": result.error,
                "duration_ms": result.duration_ms,
            })
            
            self.status = AgentStatus.AUTHENTICATED
            
        except Exception as e:
            self.logger.error(f"Attack execution failed: {e}")
            await self._send_message(MessageType.ERROR, {
                "attack_id": data.get("attack_id"),
                "error": str(e),
            })
    
    def _get_executor(self, scan_type: ScanType) -> Optional[BaseAttackExecutor]:
        """Get the appropriate executor for a scan type"""
        if scan_type == ScanType.WEB:
            return self.executors["web"]
        elif scan_type in (ScanType.MOBILE_STATIC, ScanType.MOBILE_DYNAMIC):
            return self.executors["mobile"]
        elif scan_type == ScanType.NETWORK:
            return self.executors["network"]
        elif scan_type in (ScanType.CLOUD_AWS, ScanType.CLOUD_AZURE, ScanType.CLOUD_GCP, ScanType.CLOUD_K8S):
            return self.executors["cloud"]
        elif scan_type == ScanType.SAST:
            return self.executors["sast"]
        return None
    
    async def _handle_scan_start(self, data: Dict[str, Any]):
        """Handle scan start command"""
        scan_id = data.get("scan_id")
        self.active_scans.add(scan_id)
        self.logger.info(f"Scan started: {scan_id}")
    
    async def _handle_scan_stop(self, data: Dict[str, Any]):
        """Handle scan stop command"""
        scan_id = data.get("scan_id")
        self.active_scans.discard(scan_id)
        self.logger.info(f"Scan stopped: {scan_id}")
    
    async def _handle_config_update(self, data: Dict[str, Any]):
        """Handle configuration update from server"""
        # Update config as needed
        self.logger.info(f"Config update received: {data.keys()}")


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    "UniversalJarwisAgent",
    "AgentConfig",
    "UniversalAgentCapabilities",
    "ScanType",
    "AgentStatus",
    "MessageType",
    "AttackRequest",
    "AttackResult",
    "WebAttackExecutor",
    "MobileAttackExecutor",
    "NetworkAttackExecutor",
    "CloudAttackExecutor",
    "SASTExecutor",
]
