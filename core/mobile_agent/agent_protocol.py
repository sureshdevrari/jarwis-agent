"""
Jarwis Mobile Agent - Protocol Definitions

Defines the WebSocket message protocol between the client agent and Jarwis server.
All communication is JSON-encoded with strong typing.
"""

import json
import hashlib
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict, field
from datetime import datetime


class AgentMessageType(str, Enum):
    """Message types for agent-server communication"""
    
    # === Connection & Authentication ===
    AUTH_REQUEST = "auth_request"           # Agent -> Server: Authenticate
    AUTH_RESPONSE = "auth_response"         # Server -> Agent: Auth result
    HEARTBEAT = "heartbeat"                 # Bidirectional: Keep-alive
    
    # === Agent Status ===
    AGENT_STATUS = "agent_status"           # Agent -> Server: Capabilities/status
    AGENT_READY = "agent_ready"             # Agent -> Server: Ready for scans
    AGENT_BUSY = "agent_busy"               # Agent -> Server: Currently scanning
    AGENT_ERROR = "agent_error"             # Agent -> Server: Error occurred
    
    # === Scan Control ===
    SCAN_START = "scan_start"               # Server -> Agent: Start a scan
    SCAN_STOP = "scan_stop"                 # Server -> Agent: Stop scan
    SCAN_PAUSE = "scan_pause"               # Server -> Agent: Pause scan
    SCAN_RESUME = "scan_resume"             # Server -> Agent: Resume scan
    SCAN_PROGRESS = "scan_progress"         # Agent -> Server: Progress update
    SCAN_COMPLETE = "scan_complete"         # Agent -> Server: Scan finished
    
    # === Traffic Relay ===
    TRAFFIC_CAPTURED = "traffic_captured"   # Agent -> Server: Intercepted request
    TRAFFIC_BATCH = "traffic_batch"         # Agent -> Server: Multiple requests
    TRAFFIC_ACK = "traffic_ack"             # Server -> Agent: Received confirmation
    
    # === Attack Execution ===
    ATTACK_REQUEST = "attack_request"       # Server -> Agent: Execute attack
    ATTACK_RESPONSE = "attack_response"     # Agent -> Server: Attack result
    ATTACK_BATCH = "attack_batch"           # Server -> Agent: Multiple attacks
    
    # === Setup & Configuration ===
    SETUP_STATUS = "setup_status"           # Agent -> Server: Setup progress
    SETUP_COMPLETE = "setup_complete"       # Agent -> Server: Environment ready
    CONFIG_UPDATE = "config_update"         # Server -> Agent: Update config
    
    # === Frida Specific ===
    FRIDA_LOG = "frida_log"                 # Agent -> Server: Frida console output
    FRIDA_HOOK_DATA = "frida_hook_data"     # Agent -> Server: Runtime hook data
    
    # === App Interaction ===
    APP_INSTALLED = "app_installed"         # Agent -> Server: APK/IPA installed
    APP_LAUNCHED = "app_launched"           # Agent -> Server: App running
    APP_SCREENSHOT = "app_screenshot"       # Agent -> Server: Screen capture
    APP_LOG = "app_log"                     # Agent -> Server: Logcat/device log


class AgentCapability(str, Enum):
    """Agent capabilities for feature negotiation"""
    ANDROID_EMULATOR = "android_emulator"
    ANDROID_DEVICE = "android_device"
    IOS_SIMULATOR = "ios_simulator"
    IOS_DEVICE = "ios_device"
    FRIDA = "frida"
    MITM_PROXY = "mitm_proxy"
    ROOT_ACCESS = "root_access"
    JAILBREAK = "jailbreak"


@dataclass
class AgentMessage:
    """Base message format for agent-server communication"""
    type: AgentMessageType
    data: Dict[str, Any]
    scan_id: Optional[str] = None
    message_id: Optional[str] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        if self.message_id is None:
            # Generate unique message ID
            content = f"{self.type.value}:{self.timestamp}:{json.dumps(self.data, sort_keys=True)}"
            self.message_id = hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_json(self) -> str:
        """Serialize to JSON string"""
        return json.dumps({
            "type": self.type.value,
            "data": self.data,
            "scan_id": self.scan_id,
            "message_id": self.message_id,
            "timestamp": self.timestamp
        })
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AgentMessage':
        """Deserialize from JSON string"""
        obj = json.loads(json_str)
        return cls(
            type=AgentMessageType(obj["type"]),
            data=obj.get("data", {}),
            scan_id=obj.get("scan_id"),
            message_id=obj.get("message_id"),
            timestamp=obj.get("timestamp")
        )
    
    @classmethod
    def from_dict(cls, obj: dict) -> 'AgentMessage':
        """Create from dictionary"""
        return cls(
            type=AgentMessageType(obj["type"]),
            data=obj.get("data", {}),
            scan_id=obj.get("scan_id"),
            message_id=obj.get("message_id"),
            timestamp=obj.get("timestamp")
        )


@dataclass
class TrafficData:
    """
    Captured HTTP traffic from mobile app.
    Sent from agent to server for attack analysis.
    """
    request_id: str
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    
    # Response (if captured via MITM)
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    
    # Mobile context
    source: str = "mitm"              # frida, mitm
    frida_hook: str = ""              # okhttp3, retrofit, etc.
    app_package: str = ""
    platform: str = "android"
    
    # Auth detection
    has_auth: bool = False
    auth_type: str = ""
    auth_header: str = ""
    
    # Timing
    timestamp: str = ""
    duration_ms: int = 0
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'TrafficData':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AttackRequest:
    """
    Attack request sent from server to agent.
    Agent executes via local MITM proxy.
    """
    attack_id: str
    request_id: str                   # Original request ID to base attack on
    scanner_name: str                 # sqli, xss, etc.
    
    # Modified request data
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    
    # Attack metadata
    payload: str = ""
    injection_point: str = ""         # header, param, body, path
    parameter_name: str = ""
    
    # Execution config
    timeout: int = 30
    follow_redirects: bool = True
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AttackRequest':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AttackResponse:
    """
    Attack result sent from agent back to server.
    Contains full response for vulnerability analysis.
    """
    attack_id: str
    request_id: str
    scanner_name: str
    
    # Response data
    status_code: int
    headers: Dict[str, str]
    body: str
    
    # Timing
    duration_ms: int
    timestamp: str = ""
    
    # Error info (if failed)
    success: bool = True
    error: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AttackResponse':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AgentStatus:
    """Agent status report sent periodically to server"""
    agent_id: str
    version: str
    
    # System info
    os: str                           # windows, macos, linux
    os_version: str
    hostname: str
    
    # Capabilities
    capabilities: List[str]           # List of AgentCapability values
    
    # Current state
    state: str                        # idle, scanning, error
    current_scan_id: Optional[str] = None
    
    # Resource usage
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_free_gb: float = 0.0
    
    # Environment status
    emulator_running: bool = False
    emulator_device_id: str = ""
    frida_running: bool = False
    frida_version: str = ""
    mitm_running: bool = False
    mitm_port: int = 0
    
    # Connected devices
    devices: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AgentStatus':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ScanCommand:
    """Scan command from server to agent"""
    scan_id: str
    command: str                      # start, stop, pause, resume
    
    # Scan configuration (for start command)
    app_path: Optional[str] = None    # Local path or download URL
    app_package: str = ""
    platform: str = "android"
    
    # Scan options
    ssl_bypass: bool = True
    crawl_enabled: bool = True
    crawl_duration: int = 120
    auth_config: Optional[Dict[str, Any]] = None
    
    # Target scope
    target_hosts: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ScanCommand':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# === Message Factory Functions ===

def create_auth_request(auth_token: str, agent_id: str) -> AgentMessage:
    """Create authentication request message"""
    return AgentMessage(
        type=AgentMessageType.AUTH_REQUEST,
        data={
            "token": auth_token,
            "agent_id": agent_id
        }
    )


def create_traffic_message(traffic: TrafficData, scan_id: str) -> AgentMessage:
    """Create traffic captured message"""
    return AgentMessage(
        type=AgentMessageType.TRAFFIC_CAPTURED,
        scan_id=scan_id,
        data=traffic.to_dict()
    )


def create_attack_response_message(response: AttackResponse, scan_id: str) -> AgentMessage:
    """Create attack response message"""
    return AgentMessage(
        type=AgentMessageType.ATTACK_RESPONSE,
        scan_id=scan_id,
        data=response.to_dict()
    )


def create_status_message(status: AgentStatus) -> AgentMessage:
    """Create agent status message"""
    return AgentMessage(
        type=AgentMessageType.AGENT_STATUS,
        data=status.to_dict()
    )


def create_progress_message(
    scan_id: str,
    phase: str,
    progress: int,
    message: str,
    details: Optional[Dict] = None
) -> AgentMessage:
    """Create scan progress message"""
    return AgentMessage(
        type=AgentMessageType.SCAN_PROGRESS,
        scan_id=scan_id,
        data={
            "phase": phase,
            "progress": progress,
            "message": message,
            "details": details or {}
        }
    )
