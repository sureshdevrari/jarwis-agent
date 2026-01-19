"""
Jarwis Mobile Agent - Client-Side Dynamic Testing Infrastructure

This module provides the client-side agent that runs on the user's machine
to enable remote mobile security testing.

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │                      JARWIS SERVER (Cloud)                          │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │
    │  │ Static      │  │ WebSocket   │  │ Attack Engine               │ │
    │  │ Analysis    │  │ Gateway     │  │ (runs on relayed traffic)   │ │
    │  │ (APK/IPA)   │  │ (wss://)    │  │                             │ │
    │  └─────────────┘  └──────┬──────┘  └─────────────────────────────┘ │
    └──────────────────────────┼──────────────────────────────────────────┘
                               │ Secure WebSocket (no VPN needed)
    ┌──────────────────────────┼──────────────────────────────────────────┐
    │                      CLIENT MACHINE                                 │
    │  ┌─────────────┐  ┌──────┴──────┐  ┌─────────────┐  ┌───────────┐  │
    │  │ Jarwis      │◄─┤ Traffic     │◄─┤ MITM Proxy  │◄─┤ Emulator  │  │
    │  │ Agent       │  │ Relay       │  │ (local)     │  │ + Frida   │  │
    │  │ (this pkg)  │  │             │  │             │  │           │  │
    │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘  │
    └─────────────────────────────────────────────────────────────────────┘

Components:
    - agent_core.py: Main agent orchestrator
    - traffic_relay.py: WebSocket traffic bridge to server
    - local_mitm.py: Local MITM proxy manager
    - emulator_controller.py: Emulator/device lifecycle management
    - frida_manager.py: Frida server and script management
    - agent_protocol.py: Message protocol definitions

Usage:
    from core.mobile_agent import MobileAgent
    
    agent = MobileAgent(server_url="wss://jarwis.io/agent")
    await agent.connect(auth_token="...")
    await agent.start_scan(scan_id="...", app_path="app.apk")
"""

from .agent_core import MobileAgent
from .agent_protocol import (
    AgentMessageType,
    AgentMessage,
    TrafficData,
    AttackRequest,
    AttackResponse,
    AgentStatus,
    ScanCommand,
)
from .traffic_relay import TrafficRelay
from .local_mitm import LocalMITMManager
from .emulator_controller import EmulatorController
from .frida_manager import FridaManager
from .universal_scanner import (
    ScanType,
    NetworkScanConfig,
    WebScanConfig,
    UniversalCapabilities,
    NetworkScanner,
    InternalWebScanner,
)

# For backwards compatibility, export AgentConfig from agent_core
from .agent_core import AgentConfig

__all__ = [
    "MobileAgent",
    "AgentConfig",
    "AgentMessageType",
    "AgentMessage",
    "TrafficData",
    "AttackRequest",
    "AttackResponse",
    "AgentStatus",
    "ScanCommand",
    "TrafficRelay",
    "LocalMITMManager",
    "EmulatorController",
    "FridaManager",
    # Universal scanner exports
    "ScanType",
    "NetworkScanConfig",
    "WebScanConfig",
    "UniversalCapabilities",
    "NetworkScanner",
    "InternalWebScanner",
]
