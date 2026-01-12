"""
Jarwis AGI - Mobile Application Security Scanner
OWASP Mobile Top 10 Coverage for Android & iOS

Central Mobile Attack Module - Aggregates ALL mobile security scanners

NEW STRUCTURE (Recommended):
    from attacks.mobile.static import StaticAnalyzer
    from attacks.mobile.dynamic import RuntimeAnalyzer, DynamicAppCrawler
    from attacks.mobile.platform.android import AndroidAttackScanner
    from attacks.mobile.platform.ios import IOSAttackScanner
    
LEGACY IMPORT (Deprecated but still works):
    from attacks.mobile import StaticAnalyzer, RuntimeAnalyzer

OWASP Mobile Top 10 2024:
- M1: Improper Credential Usage
- M2: Inadequate Supply Chain Security
- M3: Insecure Authentication/Authorization
- M4: Insufficient Input/Output Validation
- M5: Insecure Communication
- M6: Inadequate Privacy Controls
- M7: Insufficient Binary Protections
- M8: Security Misconfiguration
- M9: Insecure Data Storage
- M10: Insufficient Cryptography

Phase-based organization:
- static/     - Static analysis (APK/IPA decompilation, secrets extraction)
- dynamic/    - Runtime analysis (Frida, app crawling)
- platform/   - Platform-specific (android/, ios/)
- api/        - API security (traffic interception, MITM)
- orchestration/ - Scan orchestration
- utils/      - Shared utilities (auth detection, OTP handling)
"""

from typing import List, Any
import logging

logger = logging.getLogger(__name__)

# =============================================================================
# BACKWARD-COMPATIBLE IMPORTS FROM NEW PHASE LOCATIONS
# =============================================================================

# Static Analysis
from .static.static_analyzer import StaticAnalyzer
from .static.unpacker import AppUnpacker, get_unpacker

# Dynamic Analysis
from .dynamic.runtime_analyzer import RuntimeAnalyzer
from .dynamic.app_crawler import MobileAppCrawler, create_app_crawler, CrawledEndpoint, CrawlResult
from .dynamic.dynamic_crawler import DynamicAppCrawler, DiscoveredAPI, DynamicCrawlResult, crawl_app_dynamically
from .dynamic.frida_ssl_bypass import FridaSSLBypass, SSLBypassResult, InterceptedSSLRequest
from .dynamic.frida_request_bridge import FridaRequestBridge, FridaHttpMessage  # NEW

# Platform-Specific
from .platform.android.android_attacks import AndroidAttackScanner
from .platform.android.emulator_manager import (
    EmulatorManager,
    EmulatorConfig,
    EmulatorStatus,
    create_emulator_manager,
    setup_emulator
)
from .platform.ios.ios_attacks import IOSAttackScanner
from .platform.ios.ios_simulator_manager import (
    IOSSimulatorManager,
    SimulatorConfig,
    SimulatorDevice,
    SimulatorStatus
)

# API Security
from .api.api_discovery import APIDiscoveryEngine
from .api.mobile_mitm import MobileMITMProxy, create_mobile_proxy
from .api.burp_interceptor import BurpStyleInterceptor, InterceptedTraffic, FridaTrafficIntegration

# API Attack Scanners (NEW - MITM-first)
from .api.mobile_sqli_scanner import MobileSQLiScanner
from .api.mobile_idor_scanner import MobileIDORScanner
from .api.mobile_xss_scanner import MobileXSSScanner as MobileAPIXSSScanner

# Base Mobile Scanner (NEW)
from .base_mobile_scanner import BaseMobileScanner, MobileFinding

# Orchestration
from .orchestration.mobile_orchestrator import (
    MobilePenTestOrchestrator,
    MobileScanConfig,
    MobileScanContext,
    MobileEndpoint,
    MobileVulnerability
)
from .orchestration.mobile_scanner import MobileSecurityScanner
from .orchestration.mobile_post_scanner import MobilePostMethodScanner

# Alias for backward compat
MobilePostScanner = MobilePostMethodScanner

# Utils
from .utils.auth_detector import MobileAuthDetector, AuthType, create_auth_detector
from .utils.otp_handler import (
    SecureOTPHandler, 
    SocialAuthHandler, 
    UsernamePasswordHandler,
    create_otp_handler,
    create_social_auth_handler,
    create_password_handler,
    OTPStatus,
    AuthSessionStatus
)
from .utils.llm_analyzer import MobileLLMAnalyzer, create_llm_analyzer
from .utils.deeplink_scanner import DeepLinkHijackingScanner

# Alias for backward compat
DeeplinkScanner = DeepLinkHijackingScanner
from .utils.mobile_xss_scanner import MobileXSSScanner, MobileXSSTester
from .utils.mobile_security_scanner import MobileSecurityScanner as MobileWebSecurityScanner


class MobileAttacks:
    """
    Aggregates ALL mobile security scanners.
    
    Coordinates static analysis, dynamic testing, and API security
    for mobile applications.
    """
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.scanners = []
        
        # Initialize based on config
        mobile_config = config.get('mobile', {})
        
        # Static Analysis
        if mobile_config.get('static_analysis', {}).get('enabled', True):
            self.scanners.append(StaticAnalyzer(config, context))
        
        # Dynamic Analysis
        if mobile_config.get('dynamic_analysis', {}).get('enabled', True):
            self.scanners.append(RuntimeAnalyzer(config, context))
        
        # API Discovery
        if mobile_config.get('api_discovery', {}).get('enabled', True):
            self.scanners.append(APIDiscoveryEngine(config, context))
        
        # Platform-specific
        platform = mobile_config.get('platform', 'android')
        if platform == 'android':
            self.scanners.append(AndroidAttackScanner(config, context))
        elif platform == 'ios':
            self.scanners.append(IOSAttackScanner(config, context))
        
        # Mobile Security Scanner (OWASP Mobile Top 10)
        if mobile_config.get('owasp_mobile', {}).get('enabled', True):
            self.scanners.append(MobileSecurityScanner(config, context))
    
    async def run(self) -> List[Any]:
        """Run all mobile scanners."""
        findings = []
        for scanner in self.scanners:
            try:
                result = await scanner.run()
                if result:
                    findings.extend(result if isinstance(result, list) else [result])
            except Exception as e:
                logger.error(f"Scanner {scanner.__class__.__name__} failed: {e}")
        return findings


# Backward compatibility class
class CloudSecurityScanner:
    """Backward compatibility - import from attacks.cloud instead."""
    pass


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main Classes
    'MobileAttacks',
    'MobileSecurityScanner',
    
    # Static Analysis
    'StaticAnalyzer',
    'AppUnpacker',
    'get_unpacker',
    
    # Dynamic Analysis
    'RuntimeAnalyzer',
    'MobileAppCrawler',
    'create_app_crawler',
    'CrawledEndpoint',
    'CrawlResult',
    'DynamicAppCrawler',
    'DiscoveredAPI',
    'DynamicCrawlResult',
    'crawl_app_dynamically',
    'FridaSSLBypass',
    'SSLBypassResult',
    'InterceptedSSLRequest',
    'FridaRequestBridge',  # NEW
    'FridaHttpMessage',    # NEW
    
    # Platform - Android
    'AndroidAttackScanner',
    'EmulatorManager',
    'EmulatorConfig',
    'EmulatorStatus',
    'create_emulator_manager',
    'setup_emulator',
    
    # Platform - iOS
    'IOSAttackScanner',
    'IOSSimulatorManager',
    'SimulatorConfig',
    'SimulatorDevice',
    'SimulatorStatus',
    
    # API Security
    'APIDiscoveryEngine',
    'MobileMITMProxy',
    'create_mobile_proxy',
    'BurpStyleInterceptor',
    'InterceptedTraffic',
    'FridaTrafficIntegration',
    
    # API Attack Scanners (NEW - MITM-first)
    'MobileSQLiScanner',
    'MobileIDORScanner',
    'MobileAPIXSSScanner',
    
    # Base Mobile Scanner (NEW)
    'BaseMobileScanner',
    'MobileFinding',
    
    # Orchestration
    'MobilePenTestOrchestrator',
    'MobileScanConfig',
    'MobileScanContext',
    'MobileEndpoint',
    'MobileVulnerability',
    'MobilePostScanner',
    
    # Utils
    'MobileAuthDetector',
    'AuthType',
    'create_auth_detector',
    'SecureOTPHandler',
    'SocialAuthHandler',
    'UsernamePasswordHandler',
    'create_otp_handler',
    'create_social_auth_handler',
    'create_password_handler',
    'OTPStatus',
    'AuthSessionStatus',
    'MobileLLMAnalyzer',
    'create_llm_analyzer',
    'DeeplinkScanner',
    'MobileXSSScanner',
    'MobileXSSTester',
    'MobileWebSecurityScanner',
]
