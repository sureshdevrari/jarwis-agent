"""
JARWIS AGI PEN TEST - Attack Modules
Central Attack Dispatcher - Routes to correct attack module based on scan_type

Supported Scan Types:
- web: Web application security testing (OWASP Top 10)
- mobile: Mobile app security testing (OWASP Mobile Top 10)
- cloud: Cloud infrastructure security (AWS, Azure, GCP)
- network: Network security testing (ports, services, vulns)
- sast: Source code security testing (secrets, dependencies, code)
- api: API security testing (subset of web)

NEW STRUCTURE (Jan 2026):
    attacks/
    ├── registry.py           # UNIFIED scanner registry (use this!)
    ├── web/
    │   ├── a01_broken_access/  # OWASP A01
    │   ├── a02_crypto/         # OWASP A02
    │   ├── a03_injection/      # OWASP A03
    │   └── ...                 # OWASP A04-A10
    ├── mobile/
    │   ├── static/             # Static analysis
    │   ├── dynamic/            # Runtime analysis
    │   ├── platform/           # Android/iOS specific
    │   └── api/                # Mobile API security
    ├── cloud/
    │   ├── aws/                # AWS scanners
    │   ├── azure/              # Azure scanners
    │   ├── gcp/                # GCP scanners
    │   └── cnapp/              # CIEM, Runtime, Drift
    ├── sast/
    │   ├── providers/          # GitHub, GitLab, etc.
    │   └── analyzers/          # Secrets, dependencies
    └── network/                # Already organized

RECOMMENDED IMPORTS:
    from attacks.registry import ScannerRegistry
    from attacks.web.a03_injection import InjectionScanner
    from attacks.cloud.aws import AWSSecurityScanner
"""

from typing import List, Any, Optional
from enum import Enum
from dataclasses import dataclass


class ScanType(Enum):
    """Supported scan types"""
    WEB = "web"
    MOBILE = "mobile"
    CLOUD = "cloud"
    NETWORK = "network"
    SAST = "sast"
    API = "api"


# Unified Scanner Registry (recommended)
from .registry import ScannerRegistry, ScannerInfo, OWASPCategory, ScanType as RegistryScanType

# Backward compatibility imports
from .web import PreLoginAttacks, PostLoginAttacks, WebAttacks
from .mobile import MobileSecurityScanner, MobileAttacks
from .cloud import CloudSecurityScanner, CloudAttacks
from .sast import SASTAttacks


class AttackDispatcher:
    """
    Parent dispatcher that routes to the correct attack module
    based on user's requested scan_type.
    
    Usage:
        dispatcher = AttackDispatcher(
            scan_type="web",
            config=config,
            context=context
        )
        findings = await dispatcher.run()
    """
    
    def __init__(self, scan_type: str, config: dict, context, browser_controller=None):
        """
        Initialize the attack dispatcher.
        
        Args:
            scan_type: Type of scan (web, mobile, cloud, network, api)
            config: Scan configuration dictionary
            context: ScanContext with endpoints, cookies, etc.
            browser_controller: Optional browser for web scans
        """
        self.scan_type = scan_type.lower() if scan_type else "web"
        self.config = config
        self.context = context
        self.browser_controller = browser_controller
        self._attack_module = None
    
    @property
    def attack_module(self):
        """Lazy load the attack module"""
        if self._attack_module is None:
            self._attack_module = self._get_attack_module()
        return self._attack_module
    
    def _get_attack_module(self):
        """Route to correct attack module based on scan_type"""
        
        if self.scan_type == ScanType.WEB.value:
            from .web import WebAttacks
            return WebAttacks(self.config, self.context, self.browser_controller)
        
        elif self.scan_type == ScanType.MOBILE.value:
            from .mobile import MobileAttacks
            return MobileAttacks(self.config, self.context)
        
        elif self.scan_type == ScanType.CLOUD.value:
            from .cloud import CloudAttacks
            return CloudAttacks(self.config, self.context)
        
        elif self.scan_type == ScanType.NETWORK.value:
            from .network import NetworkAttacks
            return NetworkAttacks(self.config, self.context)
        
        elif self.scan_type == ScanType.API.value:
            # API uses web scanners focused on API endpoints
            from .web import WebAttacks
            return WebAttacks(self.config, self.context, self.browser_controller)
        
        else:
            raise ValueError(f"Unknown scan type: {self.scan_type}. "
                           f"Supported types: {self.get_available_types()}")
    
    async def run(self) -> List[Any]:
        """Run the appropriate attack module"""
        return await self.attack_module.run()
    
    async def run_pre_login(self) -> List[Any]:
        """Run only pre-login (unauthenticated) attacks - for web/api only"""
        if self.scan_type in [ScanType.WEB.value, ScanType.API.value]:
            from .web import WebAttacks
            web = WebAttacks(self.config, self.context, self.browser_controller)
            return await web.run_pre_login()
        return []
    
    async def run_post_login(self) -> List[Any]:
        """Run only post-login (authenticated) attacks - for web/api only"""
        if self.scan_type in [ScanType.WEB.value, ScanType.API.value]:
            from .web import WebAttacks
            web = WebAttacks(self.config, self.context, self.browser_controller)
            return await web.run_post_login()
        return []
    
    @staticmethod
    def get_available_types() -> List[str]:
        """List all available scan types"""
        return [t.value for t in ScanType]
    
    @staticmethod
    def get_scanner_info(scan_type: str) -> dict:
        """Get information about a scan type"""
        info = {
            ScanType.WEB.value: {
                "name": "Web Security Scan",
                "description": "OWASP Top 10 web application testing",
                "phases": ["pre_login", "authentication", "post_login"],
                "scanner_count": "45+"
            },
            ScanType.MOBILE.value: {
                "name": "Mobile Security Scan",
                "description": "OWASP Mobile Top 10 testing for Android/iOS",
                "phases": ["static_analysis", "dynamic_analysis", "api_testing"],
                "scanner_count": "15+"
            },
            ScanType.CLOUD.value: {
                "name": "Cloud Security Scan",
                "description": "Multi-cloud security assessment (AWS, Azure, GCP)",
                "phases": ["discovery", "cspm", "ciem", "compliance"],
                "scanner_count": "12+"
            },
            ScanType.NETWORK.value: {
                "name": "Network Security Scan",
                "description": "Port scanning, service enumeration, vulnerability detection",
                "phases": ["discovery", "port_scan", "service_enum", "vuln_scan"],
                "scanner_count": "20+"
            },
            ScanType.API.value: {
                "name": "API Security Scan",
                "description": "REST/GraphQL API security testing",
                "phases": ["discovery", "authentication", "injection", "business_logic"],
                "scanner_count": "30+"
            },
        }
        return info.get(scan_type, {"error": "Unknown scan type"})


__all__ = [
    # Main dispatcher
    'AttackDispatcher',
    'ScanType',
    
    # Backward compatibility
    'PreLoginAttacks', 
    'PostLoginAttacks',
    'MobileSecurityScanner',
    'CloudSecurityScanner',
]
