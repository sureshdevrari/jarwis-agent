"""
Jarwis Mobile Agent - Core Agent Module

Main orchestrator for the client-side mobile testing agent.
Manages WebSocket connection, component lifecycle, and scan execution.
"""

import asyncio
import json
import logging
import platform
import socket
import uuid
import psutil
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:
    import websockets
    from websockets.client import WebSocketClientProtocol
    HAS_WEBSOCKETS = True
except ImportError:
    websockets = None
    WebSocketClientProtocol = None
    HAS_WEBSOCKETS = False

from .agent_protocol import (
    AgentMessageType,
    AgentMessage,
    AgentStatus,
    AgentCapability,
    ScanCommand,
    TrafficData,
    AttackRequest,
    AttackResponse,
    create_auth_request,
    create_status_message,
    create_progress_message,
    create_attack_response_message,
)

logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    """Configuration for mobile agent"""
    server_url: str = "wss://localhost:8000/ws/agent"
    auth_token: str = ""
    agent_id: str = ""
    
    # Reconnection settings
    reconnect_interval: int = 5
    max_reconnect_attempts: int = 10
    heartbeat_interval: int = 30
    
    # Local component settings
    mitm_port: int = 8082
    frida_port: int = 27042
    
    # Paths
    data_dir: str = ""
    sdk_path: str = ""
    
    def __post_init__(self):
        if not self.agent_id:
            self.agent_id = f"agent_{uuid.uuid4().hex[:8]}"
        if not self.data_dir:
            self.data_dir = str(Path.home() / ".jarwis" / "agent")


class MobileAgent:
    """
    Client-side agent for remote mobile security testing.
    
    Responsibilities:
    1. Maintain WebSocket connection to Jarwis server
    2. Manage local emulator/device, MITM proxy, Frida
    3. Relay captured traffic to server
    4. Execute attack requests from server via local proxy
    5. Report scan progress and results
    
    Usage:
        agent = MobileAgent(server_url="wss://jarwis.io/ws/agent")
        await agent.connect(auth_token="...")
        # Agent now listens for scan commands from server
        await agent.run_forever()
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, config: Optional[AgentConfig] = None, **kwargs):
        """Initialize agent with configuration"""
        if config:
            self.config = config
        else:
            self.config = AgentConfig(**kwargs)
        
        # Connection state
        self._ws = None  # WebSocket connection
        self._connected = False
        self._authenticated = False
        self._reconnect_count = 0
        
        # Component references (lazy initialized)
        self._emulator_controller = None
        self._frida_manager = None
        self._mitm_manager = None
        self._traffic_relay = None
        
        # Scan state
        self._current_scan_id: Optional[str] = None
        self._scan_state: str = "idle"  # idle, scanning, paused, stopping
        
        # Message handlers
        self._handlers: Dict[AgentMessageType, Callable] = {}
        self._register_default_handlers()
        
        # Background tasks
        self._tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        
        # Callbacks for external integration
        self._on_traffic_captured: Optional[Callable] = None
        self._on_scan_started: Optional[Callable] = None
        self._on_scan_stopped: Optional[Callable] = None
        
        logger.info(f"MobileAgent initialized: {self.config.agent_id}")
    
    def _register_default_handlers(self):
        """Register default message handlers"""
        self._handlers = {
            AgentMessageType.AUTH_RESPONSE: self._handle_auth_response,
            AgentMessageType.SCAN_START: self._handle_scan_start,
            AgentMessageType.SCAN_STOP: self._handle_scan_stop,
            AgentMessageType.SCAN_PAUSE: self._handle_scan_pause,
            AgentMessageType.SCAN_RESUME: self._handle_scan_resume,
            AgentMessageType.ATTACK_REQUEST: self._handle_attack_request,
            AgentMessageType.ATTACK_BATCH: self._handle_attack_batch,
            AgentMessageType.CONFIG_UPDATE: self._handle_config_update,
            AgentMessageType.HEARTBEAT: self._handle_heartbeat,
        }
    
    # === Connection Management ===
    
    async def connect(self, auth_token: Optional[str] = None) -> bool:
        """
        Connect to Jarwis server and authenticate.
        
        Args:
            auth_token: JWT token for authentication (uses config if not provided)
        
        Returns:
            True if connected and authenticated successfully
        """
        if websockets is None:
            logger.error("websockets library not installed")
            return False
        
        if auth_token:
            self.config.auth_token = auth_token
        
        try:
            logger.info(f"Connecting to {self.config.server_url}...")
            
            self._ws = await websockets.connect(
                self.config.server_url,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5
            )
            self._connected = True
            self._reconnect_count = 0
            
            logger.info("WebSocket connected, authenticating...")
            
            # Send authentication request
            auth_msg = create_auth_request(
                self.config.auth_token,
                self.config.agent_id
            )
            await self._send_message(auth_msg)
            
            # Wait for auth response with timeout
            try:
                response = await asyncio.wait_for(
                    self._ws.recv(),
                    timeout=10.0
                )
                msg = AgentMessage.from_json(response)
                
                if msg.type == AgentMessageType.AUTH_RESPONSE:
                    if msg.data.get("success"):
                        self._authenticated = True
                        logger.info("Authentication successful")
                        
                        # Send initial status
                        await self._send_status()
                        return True
                    else:
                        logger.error(f"Authentication failed: {msg.data.get('error')}")
                        return False
            except asyncio.TimeoutError:
                logger.error("Authentication timeout")
                return False
                
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self._connected = False
            return False
    
    async def disconnect(self):
        """Gracefully disconnect from server"""
        logger.info("Disconnecting from server...")
        
        self._shutdown_event.set()
        
        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
        
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
        
        self._connected = False
        self._authenticated = False
        self._ws = None
    
    async def reconnect(self) -> bool:
        """Attempt to reconnect after disconnection"""
        if self._reconnect_count >= self.config.max_reconnect_attempts:
            logger.error("Max reconnection attempts reached")
            return False
        
        self._reconnect_count += 1
        wait_time = min(self.config.reconnect_interval * self._reconnect_count, 60)
        
        logger.info(f"Reconnecting in {wait_time}s (attempt {self._reconnect_count})...")
        await asyncio.sleep(wait_time)
        
        return await self.connect()
    
    # === Main Loop ===
    
    async def run_forever(self):
        """
        Main event loop - listens for messages and handles them.
        Automatically reconnects on disconnection.
        """
        logger.info("Starting agent main loop...")
        
        # Start background tasks
        self._tasks.append(asyncio.create_task(self._heartbeat_loop()))
        self._tasks.append(asyncio.create_task(self._status_report_loop()))
        
        while not self._shutdown_event.is_set():
            try:
                if not self._connected:
                    if not await self.reconnect():
                        break
                    continue
                
                # Receive and process messages
                try:
                    message = await asyncio.wait_for(
                        self._ws.recv(),
                        timeout=1.0
                    )
                    await self._process_message(message)
                except asyncio.TimeoutError:
                    continue
                except websockets.ConnectionClosed:
                    logger.warning("Connection closed")
                    self._connected = False
                    continue
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                await asyncio.sleep(1)
        
        logger.info("Agent main loop ended")
    
    async def _process_message(self, raw_message: str):
        """Process incoming message from server"""
        try:
            msg = AgentMessage.from_json(raw_message)
            logger.debug(f"Received: {msg.type.value}")
            
            handler = self._handlers.get(msg.type)
            if handler:
                await handler(msg)
            else:
                logger.warning(f"No handler for message type: {msg.type}")
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON message: {e}")
        except Exception as e:
            logger.error(f"Error processing message: {e}")
    
    # === Message Sending ===
    
    async def _send_message(self, message: AgentMessage):
        """Send message to server"""
        if not self._ws or not self._connected:
            logger.warning("Cannot send message: not connected")
            return
        
        try:
            await self._ws.send(message.to_json())
            logger.debug(f"Sent: {message.type.value}")
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self._connected = False
    
    async def _send_status(self):
        """Send current agent status to server"""
        status = await self._collect_status()
        msg = create_status_message(status)
        await self._send_message(msg)
    
    async def send_progress(self, phase: str, progress: int, message: str, details: Optional[Dict] = None):
        """Send scan progress update"""
        if self._current_scan_id:
            msg = create_progress_message(
                self._current_scan_id,
                phase,
                progress,
                message,
                details
            )
            await self._send_message(msg)
    
    async def send_traffic(self, traffic: TrafficData):
        """Send captured traffic to server"""
        if not self._current_scan_id:
            logger.warning("No active scan, traffic not sent")
            return
        
        msg = AgentMessage(
            type=AgentMessageType.TRAFFIC_CAPTURED,
            scan_id=self._current_scan_id,
            data=traffic.to_dict()
        )
        await self._send_message(msg)
    
    # === Message Handlers ===
    
    async def _handle_auth_response(self, msg: AgentMessage):
        """Handle authentication response"""
        if msg.data.get("success"):
            self._authenticated = True
            logger.info("Authenticated successfully")
        else:
            logger.error(f"Auth failed: {msg.data.get('error')}")
            await self.disconnect()
    
    async def _handle_scan_start(self, msg: AgentMessage):
        """Handle scan start command from server"""
        if self._scan_state != "idle":
            logger.warning(f"Cannot start scan: agent is {self._scan_state}")
            await self._send_error("Agent is busy with another scan")
            return
        
        try:
            command = ScanCommand.from_dict(msg.data)
            self._current_scan_id = command.scan_id
            self._scan_state = "scanning"
            
            logger.info(f"Starting scan: {command.scan_id}")
            
            # Send acknowledgment
            await self.send_progress("starting", 0, "Initializing scan environment")
            
            # Initialize components
            await self._initialize_scan_environment(command)
            
            # Start traffic capture
            await self._start_traffic_capture(command)
            
            # Install and launch app
            if command.app_path:
                await self._install_and_launch_app(command)
            
            # Notify callback
            if self._on_scan_started:
                await self._on_scan_started(command)
                
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            self._scan_state = "idle"
            self._current_scan_id = None
            await self._send_error(f"Failed to start scan: {e}")
    
    async def _handle_scan_stop(self, msg: AgentMessage):
        """Handle scan stop command"""
        scan_id = msg.data.get("scan_id") or msg.scan_id
        
        if self._current_scan_id != scan_id:
            logger.warning(f"Stop requested for unknown scan: {scan_id}")
            return
        
        logger.info(f"Stopping scan: {scan_id}")
        self._scan_state = "stopping"
        
        try:
            # Stop components
            await self._cleanup_scan()
            
            # Send completion
            await self._send_message(AgentMessage(
                type=AgentMessageType.SCAN_COMPLETE,
                scan_id=scan_id,
                data={"status": "stopped", "reason": "user_request"}
            ))
            
            if self._on_scan_stopped:
                await self._on_scan_stopped(scan_id)
                
        finally:
            self._scan_state = "idle"
            self._current_scan_id = None
    
    async def _handle_scan_pause(self, msg: AgentMessage):
        """Handle scan pause command"""
        if self._scan_state == "scanning":
            self._scan_state = "paused"
            logger.info(f"Scan paused: {self._current_scan_id}")
            await self.send_progress("paused", -1, "Scan paused by user")
    
    async def _handle_scan_resume(self, msg: AgentMessage):
        """Handle scan resume command"""
        if self._scan_state == "paused":
            self._scan_state = "scanning"
            logger.info(f"Scan resumed: {self._current_scan_id}")
            await self.send_progress("resumed", -1, "Scan resumed")
    
    async def _handle_attack_request(self, msg: AgentMessage):
        """Handle single attack request from server"""
        attack = AttackRequest.from_dict(msg.data)
        
        logger.debug(f"Executing attack: {attack.attack_id} ({attack.scanner_name})")
        
        try:
            response = await self._execute_attack(attack)
            
            # Send response back
            response_msg = create_attack_response_message(
                response,
                self._current_scan_id
            )
            await self._send_message(response_msg)
            
        except Exception as e:
            logger.error(f"Attack execution failed: {e}")
            # Send error response
            error_response = AttackResponse(
                attack_id=attack.attack_id,
                request_id=attack.request_id,
                scanner_name=attack.scanner_name,
                status_code=0,
                headers={},
                body="",
                duration_ms=0,
                success=False,
                error=str(e)
            )
            await self._send_message(create_attack_response_message(
                error_response,
                self._current_scan_id
            ))
    
    async def _handle_attack_batch(self, msg: AgentMessage):
        """Handle batch of attack requests"""
        attacks = [AttackRequest.from_dict(a) for a in msg.data.get("attacks", [])]
        
        logger.info(f"Executing attack batch: {len(attacks)} attacks")
        
        # Execute attacks with concurrency limit
        semaphore = asyncio.Semaphore(5)
        
        async def execute_with_limit(attack: AttackRequest):
            async with semaphore:
                return await self._handle_attack_request(
                    AgentMessage(
                        type=AgentMessageType.ATTACK_REQUEST,
                        scan_id=self._current_scan_id,
                        data=attack.to_dict()
                    )
                )
        
        await asyncio.gather(*[execute_with_limit(a) for a in attacks])
    
    async def _handle_config_update(self, msg: AgentMessage):
        """Handle configuration update from server"""
        config_updates = msg.data
        logger.info(f"Received config update: {list(config_updates.keys())}")
        
        # Apply relevant updates
        if "mitm_port" in config_updates:
            self.config.mitm_port = config_updates["mitm_port"]
        if "heartbeat_interval" in config_updates:
            self.config.heartbeat_interval = config_updates["heartbeat_interval"]
    
    async def _handle_heartbeat(self, msg: AgentMessage):
        """Handle heartbeat from server"""
        # Respond with pong
        await self._send_message(AgentMessage(
            type=AgentMessageType.HEARTBEAT,
            data={"pong": True, "timestamp": datetime.utcnow().isoformat()}
        ))
    
    # === Background Tasks ===
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                if self._connected and self._authenticated:
                    await self._send_message(AgentMessage(
                        type=AgentMessageType.HEARTBEAT,
                        data={"ping": True}
                    ))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    async def _status_report_loop(self):
        """Send periodic status reports"""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(60)  # Every minute
                if self._connected and self._authenticated:
                    await self._send_status()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Status report error: {e}")
    
    # === Component Management ===
    
    async def _initialize_scan_environment(self, command: ScanCommand):
        """Initialize emulator, Frida, MITM for scan"""
        await self.send_progress("setup", 10, "Checking environment...")
        
        # Lazy import to avoid circular dependencies
        from .emulator_controller import EmulatorController
        from .frida_manager import FridaManager
        from .local_mitm import LocalMITMManager
        from .traffic_relay import TrafficRelay
        
        # Initialize MITM proxy
        await self.send_progress("setup", 20, "Starting MITM proxy...")
        self._mitm_manager = LocalMITMManager(port=self.config.mitm_port)
        await self._mitm_manager.start()
        
        # Initialize emulator/device
        await self.send_progress("setup", 40, "Preparing device/emulator...")
        self._emulator_controller = EmulatorController(sdk_path=self.config.sdk_path)
        device_id = await self._emulator_controller.ensure_device_ready()
        
        if not device_id:
            raise RuntimeError("No device/emulator available")
        
        # Configure proxy on device
        await self.send_progress("setup", 60, "Configuring proxy on device...")
        await self._emulator_controller.set_proxy(
            device_id,
            "10.0.2.2" if "emulator" in device_id else self._get_host_ip(),
            self.config.mitm_port
        )
        
        # Initialize Frida
        if command.ssl_bypass:
            await self.send_progress("setup", 80, "Setting up Frida SSL bypass...")
            self._frida_manager = FridaManager()
            await self._frida_manager.ensure_server_running(device_id)
        
        # Initialize traffic relay
        self._traffic_relay = TrafficRelay(
            agent=self,
            mitm_manager=self._mitm_manager
        )
        
        await self.send_progress("setup", 100, "Environment ready")
    
    async def _start_traffic_capture(self, command: ScanCommand):
        """Start capturing traffic"""
        if self._traffic_relay:
            self._traffic_relay.set_target_hosts(command.target_hosts)
            await self._traffic_relay.start()
    
    async def _install_and_launch_app(self, command: ScanCommand):
        """Install and launch the target app"""
        await self.send_progress("app_setup", 0, "Installing app...")
        
        if self._emulator_controller:
            device_id = self._emulator_controller.current_device_id
            
            # Install APK
            if command.app_path:
                await self._emulator_controller.install_app(device_id, command.app_path)
            
            # Launch app
            if command.app_package:
                await self.send_progress("app_setup", 50, "Launching app...")
                await self._emulator_controller.launch_app(device_id, command.app_package)
            
            # Apply Frida SSL bypass
            if command.ssl_bypass and self._frida_manager and command.app_package:
                await self.send_progress("app_setup", 80, "Applying SSL bypass...")
                await self._frida_manager.apply_ssl_bypass(command.app_package)
        
        await self.send_progress("app_setup", 100, "App ready")
        
        # Notify app launched
        await self._send_message(AgentMessage(
            type=AgentMessageType.APP_LAUNCHED,
            scan_id=self._current_scan_id,
            data={
                "package": command.app_package,
                "platform": command.platform
            }
        ))
    
    async def _execute_attack(self, attack: AttackRequest) -> AttackResponse:
        """Execute attack request through local proxy"""
        import aiohttp
        
        start_time = datetime.utcnow()
        
        try:
            # Route through local MITM proxy
            proxy_url = f"http://127.0.0.1:{self.config.mitm_port}"
            
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=attack.method,
                    url=attack.url,
                    headers=attack.headers,
                    data=attack.body if attack.body else None,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=attack.timeout),
                    allow_redirects=attack.follow_redirects,
                    ssl=False
                ) as resp:
                    body = await resp.text()
                    duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                    
                    return AttackResponse(
                        attack_id=attack.attack_id,
                        request_id=attack.request_id,
                        scanner_name=attack.scanner_name,
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        duration_ms=duration,
                        timestamp=datetime.utcnow().isoformat()
                    )
                    
        except asyncio.TimeoutError:
            duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            return AttackResponse(
                attack_id=attack.attack_id,
                request_id=attack.request_id,
                scanner_name=attack.scanner_name,
                status_code=0,
                headers={},
                body="",
                duration_ms=duration,
                success=False,
                error="Request timeout"
            )
        except Exception as e:
            duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            return AttackResponse(
                attack_id=attack.attack_id,
                request_id=attack.request_id,
                scanner_name=attack.scanner_name,
                status_code=0,
                headers={},
                body="",
                duration_ms=duration,
                success=False,
                error=str(e)
            )
    
    async def _cleanup_scan(self):
        """Clean up scan resources"""
        logger.info("Cleaning up scan resources...")
        
        # Stop traffic relay
        if self._traffic_relay:
            await self._traffic_relay.stop()
            self._traffic_relay = None
        
        # Stop Frida
        if self._frida_manager:
            await self._frida_manager.cleanup()
            self._frida_manager = None
        
        # Stop MITM proxy
        if self._mitm_manager:
            await self._mitm_manager.stop()
            self._mitm_manager = None
        
        # Note: Don't stop emulator - reuse for next scan
    
    async def _send_error(self, error: str):
        """Send error message to server"""
        await self._send_message(AgentMessage(
            type=AgentMessageType.AGENT_ERROR,
            scan_id=self._current_scan_id,
            data={"error": error}
        ))
    
    # === Status Collection ===
    
    async def _collect_status(self) -> AgentStatus:
        """Collect current agent status"""
        capabilities = await self._detect_capabilities()
        
        return AgentStatus(
            agent_id=self.config.agent_id,
            version=self.VERSION,
            os=platform.system().lower(),
            os_version=platform.version(),
            hostname=socket.gethostname(),
            capabilities=[c.value for c in capabilities],
            state=self._scan_state,
            current_scan_id=self._current_scan_id,
            cpu_percent=psutil.cpu_percent(),
            memory_percent=psutil.virtual_memory().percent,
            disk_free_gb=psutil.disk_usage('/').free / (1024**3),
            emulator_running=self._emulator_controller.is_running if self._emulator_controller else False,
            emulator_device_id=self._emulator_controller.current_device_id if self._emulator_controller else "",
            frida_running=self._frida_manager.is_running if self._frida_manager else False,
            frida_version=self._frida_manager.version if self._frida_manager else "",
            mitm_running=self._mitm_manager.is_running if self._mitm_manager else False,
            mitm_port=self.config.mitm_port if self._mitm_manager else 0,
            devices=await self._list_devices()
        )
    
    async def _detect_capabilities(self) -> List[AgentCapability]:
        """Detect available capabilities on this machine"""
        capabilities = []
        
        # Check for Android SDK
        if self._check_android_sdk():
            capabilities.append(AgentCapability.ANDROID_EMULATOR)
        
        # Check for connected devices
        devices = await self._list_devices()
        for device in devices:
            if device.get("type") == "device":
                capabilities.append(AgentCapability.ANDROID_DEVICE)
                break
        
        # Check for Frida
        try:
            import frida
            capabilities.append(AgentCapability.FRIDA)
        except ImportError:
            pass
        
        # MITM proxy is always available
        capabilities.append(AgentCapability.MITM_PROXY)
        
        return capabilities
    
    def _check_android_sdk(self) -> bool:
        """Check if Android SDK is available"""
        import os
        sdk_paths = [
            os.environ.get("ANDROID_HOME"),
            os.environ.get("ANDROID_SDK_ROOT"),
            str(Path.home() / "AppData" / "Local" / "Android" / "Sdk"),
            str(Path.home() / ".jarwis" / "android-sdk"),
        ]
        
        for path in sdk_paths:
            if path and Path(path).exists():
                adb = Path(path) / "platform-tools" / ("adb.exe" if platform.system() == "Windows" else "adb")
                if adb.exists():
                    return True
        return False
    
    async def _list_devices(self) -> List[Dict[str, str]]:
        """List connected Android devices"""
        import subprocess
        
        try:
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            devices = []
            for line in result.stdout.strip().split("\n")[1:]:
                if line.strip() and "device" in line:
                    parts = line.split()
                    device_id = parts[0]
                    device_type = "emulator" if device_id.startswith("emulator") else "device"
                    devices.append({
                        "id": device_id,
                        "type": device_type,
                        "status": "online"
                    })
            return devices
            
        except Exception:
            return []
    
    def _get_host_ip(self) -> str:
        """Get host IP address for device proxy configuration"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    # === Public API ===
    
    @property
    def is_connected(self) -> bool:
        return self._connected and self._authenticated
    
    @property
    def is_scanning(self) -> bool:
        return self._scan_state == "scanning"
    
    @property
    def current_scan_id(self) -> Optional[str]:
        return self._current_scan_id
    
    def set_traffic_callback(self, callback: Callable[[TrafficData], Awaitable[None]]):
        """Set callback for captured traffic"""
        self._on_traffic_captured = callback
    
    def set_scan_callbacks(
        self,
        on_started: Optional[Callable] = None,
        on_stopped: Optional[Callable] = None
    ):
        """Set scan lifecycle callbacks"""
        self._on_scan_started = on_started
        self._on_scan_stopped = on_stopped
