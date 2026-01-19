"""
JARWIS AGI PEN TEST - Core Module
OWASP Top 10 AI-Powered Penetration Testing Framework

Architecture:
┌─────────────────────────────────────────────────────────────┐
│                      SCANNERS                                │
│   WebScanRunner - Pre/Post login web scanning               │
│   MobileScanRunner - APK/IPA analysis                       │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   ATTACK ENGINES                             │
│   AttackEngine - Unified web attacks on captured requests   │
│   MobileAttackEngine - Mobile + API attacks                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                     DATA LAYER                               │
│   RequestStore - Stores captured MITM requests/responses    │
│   CapturedRequest/CapturedResponse - Data models            │
└─────────────────────────────────────────────────────────────┘
"""

__version__ = "2.0.0"
__author__ = "Jarwis Security Team"

# Legacy runner (still works)
from .runner import PenTestRunner

# Browser automation
from .browser import BrowserController

# Proxy
from .proxy import ProxyInterceptor
from .mitm_proxy import JarwisMITMProxy as MITMProxy

# AI components
from .ai_planner import AIPlanner

# Reporting
from .reporters import ReportGenerator

# NEW: Request/Response storage
from .request_store import (
    RequestStore,
    CapturedRequest,
    CapturedResponse
)

# NEW: Unified attack engines
from .attack_engine import (
    AttackEngine,
    AttackResult,
    BaseAttack,
    # Individual attack modules
    SQLInjectionAttack,
    XSSAttack,
    NoSQLInjectionAttack,
    CommandInjectionAttack,
    SSTIAttack,
    XXEAttack,
    IDORAttack,
    BOLAAttack,
    BFLAAttack,
    AuthBypassAttack,
    JWTAttack,
    SSRFAttack,
    CSRFAttack,
    CORSAttack,
    PathTraversalAttack,
)

# NEW: OOB Callback Server for blind vulnerability detection (SSRF, XXE)
from .oob_callback_server import (
    OOBCallbackServer,
    OOBIntegration,
    OOBPayloadTemplates,
    get_callback_server,
    ensure_callback_server_running,
)

# NEW: Web scan orchestrator
from .web_scan_runner import WebScanRunner

# NEW: Mobile attack engine
from .mobile_attack_engine import (
    MobileAttackEngine,
    MobileScanRunner,
    MobileAppInfo,
    MobileVulnerability
)

# NEW: Universal Agent (handles ALL scan types)
from .universal_agent import (
    UniversalJarwisAgent,
    AgentConfig,
    UniversalAgentCapabilities,
    ScanType as AgentScanType,
    AgentStatus,
    MessageType as AgentMessageType,
    AttackRequest as AgentAttackRequest,
    AttackResult as AgentAttackResult,
)

__all__ = [
    # Version
    "__version__",
    
    # Orchestrators
    "PenTestRunner",      # Legacy
    "WebScanRunner",      # New web scanner
    "MobileScanRunner",   # New mobile scanner
    
    # Core components
    "BrowserController",
    "ProxyInterceptor",
    "MITMProxy",
    "AIPlanner",
    "ReportGenerator",
    
    # OOB Callback Server (for blind SSRF/XXE)
    "OOBCallbackServer",
    "OOBIntegration",
    "OOBPayloadTemplates",
    "get_callback_server",
    "ensure_callback_server_running",
    
    # Data storage
    "RequestStore",
    "CapturedRequest",
    "CapturedResponse",
    
    # Attack engines
    "AttackEngine",
    "AttackResult",
    "BaseAttack",
    "MobileAttackEngine",
    "MobileAppInfo",
    "MobileVulnerability",
    
    # Attack modules (all available for customization)
    "SQLInjectionAttack",
    "XSSAttack",
    "NoSQLInjectionAttack",
    "CommandInjectionAttack",
    "SSTIAttack",
    "XXEAttack",
    "IDORAttack",
    "BOLAAttack",
    "BFLAAttack",
    "AuthBypassAttack",
    "JWTAttack",
    "SSRFAttack",
    "CSRFAttack",
    "CORSAttack",
    "PathTraversalAttack",
    
    # Universal Agent (ALL scan types)
    "UniversalJarwisAgent",
    "AgentConfig",
    "UniversalAgentCapabilities",
    "AgentScanType",
    "AgentStatus",
    "AgentMessageType",
    "AgentAttackRequest",
    "AgentAttackResult",
]

