"""
Jarwis AGI - Mobile Application Security Scanner
OWASP Mobile Top 10 Coverage for Android & iOS

Central Mobile Attack Module - Aggregates ALL mobile security scanners

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

Modules:
- Static Analysis Engine (APK/IPA analysis)
- Runtime Instrumentation (Frida-based)
- API Discovery Engine
- App Crawler (like web crawler for mobile apps)
- Dynamic App Crawler (Emulator + Frida-based)
- App Unpacker & Secrets Extractor
- Android-Specific Attacks
- iOS-Specific Attacks
- Mobile MITM Proxy
- LLM Security Analyzer
- Authentication Detector
- OTP Handler (Secure, Privacy-First)
- OWASP Mobile Top 10 Scanners
- Frida SSL Pinning Bypass (Android & iOS)
- iOS Simulator Manager
- Mobile Pen Test Orchestrator
- Burp-Style Traffic Interceptor
- Mobile XSS Scanner (WebView/Hybrid Apps) - Added 5 Jan 2026
- Mobile POST Method Scanner - Added 5 Jan 2026
"""

from typing import List, Any
import logging

from .static_analyzer import StaticAnalyzer
from .runtime_analyzer import RuntimeAnalyzer
from .api_discovery import APIDiscoveryEngine
from .app_crawler import MobileAppCrawler, create_app_crawler, CrawledEndpoint, CrawlResult
from .dynamic_crawler import DynamicAppCrawler, DiscoveredAPI, DynamicCrawlResult, crawl_app_dynamically
from .mobile_scanner import MobileSecurityScanner
from .unpacker import AppUnpacker, get_unpacker
from .android_attacks import AndroidAttackScanner
from .ios_attacks import IOSAttackScanner
from .mobile_mitm import MobileMITMProxy, create_mobile_proxy
from .llm_analyzer import MobileLLMAnalyzer, create_llm_analyzer
from .auth_detector import MobileAuthDetector, AuthType, create_auth_detector
from .otp_handler import (
    SecureOTPHandler, 
    SocialAuthHandler, 
    UsernamePasswordHandler,
    create_otp_handler,
    create_social_auth_handler,
    create_password_handler,
    OTPStatus,
    AuthSessionStatus
)
from .emulator_manager import (
    EmulatorManager,
    EmulatorConfig,
    EmulatorStatus,
    create_emulator_manager,
    setup_emulator
)

# New modules for full mobile pentesting
from .frida_ssl_bypass import (
    FridaSSLBypass,
    SSLBypassResult,
    InterceptedSSLRequest
)
from .ios_simulator_manager import (
    IOSSimulatorManager,
    SimulatorConfig,
    SimulatorDevice,
    SimulatorStatus
)
from .mobile_orchestrator import (
    MobilePenTestOrchestrator,
    MobileScanConfig,
    MobileScanContext,
    MobileEndpoint,
    MobileVulnerability
)
from .burp_interceptor import (
    BurpStyleInterceptor,
    InterceptedTraffic,
    FridaTrafficIntegration
)

# New Scanners Added 5 Jan 2026
from .mobile_xss_scanner import MobileXSSScanner, MobileXSSTester
from .mobile_post_scanner import MobilePostMethodScanner, MobileFormDataGenerator

logger = logging.getLogger(__name__)


class MobileAttacks:
    """
    Aggregates ALL mobile security scanners.
    
    Orchestrates mobile app security testing including:
    - Static analysis (APK/IPA decompilation, secrets detection)
    - Dynamic analysis (runtime instrumentation, traffic interception)
    - API security testing (discovered endpoints)
    - Platform-specific attacks (Android, iOS)
    
    Usage:
        mobile = MobileAttacks(config, context)
        findings = await mobile.run()
    """
    
    def __init__(self, config: dict, context):
        """
        Initialize mobile attack module.
        
        Args:
            config: Scan configuration with app_path, platform, etc.
            context: MobileScanContext with discovered endpoints, etc.
        """
        self.config = config
        self.context = context
        self.platform = config.get('platform', 'android').lower()
        self.app_path = config.get('app_path', '')
        
        # Initialize scanners based on config
        self.scanners = self._init_scanners()
    
    def _init_scanners(self) -> List[Any]:
        """Initialize all mobile scanners based on configuration"""
        scanners = []
        mobile_config = self.config.get('mobile', {})
        
        # Static Analysis (always enabled)
        if mobile_config.get('static_analysis', {}).get('enabled', True):
            scanners.append(StaticAnalyzer(self.config))
        
        # Dynamic Analysis (if emulator available)
        if mobile_config.get('dynamic_analysis', {}).get('enabled', True):
            try:
                scanners.append(DynamicAppCrawler(self.config))
            except Exception as e:
                logger.warning(f"Dynamic analysis unavailable: {e}")
        
        # API Discovery
        if mobile_config.get('api_discovery', {}).get('enabled', True):
            scanners.append(APIDiscoveryEngine(self.config))
        
        # Platform-specific scanners
        if self.platform == 'android':
            scanners.append(AndroidAttackScanner(self.config))
        elif self.platform == 'ios':
            scanners.append(IOSAttackScanner(self.config))
        
        # XSS Scanner for hybrid/WebView apps
        if mobile_config.get('xss_scanning', {}).get('enabled', True):
            try:
                scanners.append(MobileXSSScanner(self.config))
            except Exception as e:
                logger.warning(f"Mobile XSS scanner unavailable: {e}")
        
        # POST Method Scanner
        if mobile_config.get('post_scanning', {}).get('enabled', True):
            try:
                scanners.append(MobilePostMethodScanner(self.config))
            except Exception as e:
                logger.warning(f"Mobile POST scanner unavailable: {e}")
        
        return scanners
    
    async def run(self) -> List[Any]:
        """
        Run all mobile security scanners.
        
        Returns:
            List of all mobile security findings
        """
        results = []
        
        logger.info(f"Starting mobile security scan ({self.platform})...")
        logger.info(f"Loaded {len(self.scanners)} mobile scanners")
        
        for scanner in self.scanners:
            scanner_name = scanner.__class__.__name__
            logger.info(f"Running {scanner_name}...")
            
            try:
                if hasattr(scanner, 'scan'):
                    scanner_results = await scanner.scan()
                elif hasattr(scanner, 'analyze'):
                    scanner_results = await scanner.analyze()
                elif hasattr(scanner, 'run'):
                    scanner_results = await scanner.run()
                else:
                    logger.warning(f"{scanner_name} has no scan/analyze/run method")
                    continue
                
                if scanner_results:
                    results.extend(scanner_results)
                    logger.info(f"{scanner_name}: {len(scanner_results)} findings")
                    
            except Exception as e:
                logger.error(f"{scanner_name} failed: {e}")
                continue
        
        logger.info(f"Mobile scan complete: {len(results)} total findings")
        return results
    
    async def run_static_analysis(self) -> List[Any]:
        """Run only static analysis"""
        analyzer = StaticAnalyzer(self.config, self.context)
        return await analyzer.analyze()
    
    async def run_dynamic_analysis(self) -> List[Any]:
        """Run only dynamic analysis (requires emulator)"""
        crawler = DynamicAppCrawler(self.config, self.context)
        return await crawler.crawl()
    
    def get_scanner_count(self) -> int:
        """Get count of available scanners"""
        return len(self.scanners)
    
    def get_available_attacks(self) -> List[str]:
        """Get list of available attack categories"""
        return [
            "Static Analysis (Secrets, Hardcoded Keys)",
            "Binary Protection Analysis",
            "SSL/TLS Configuration",
            "Certificate Pinning Bypass",
            "Root/Jailbreak Detection Bypass",
            "Insecure Data Storage",
            "API Security Testing",
            "WebView XSS Attacks",
            "Deep Link Vulnerabilities",
            "Intent Hijacking (Android)",
            "IPC Vulnerabilities",
            "Cryptographic Implementation Flaws",
            "Authentication Bypass",
            "Session Management Issues",
        ]


__all__ = [
    # Main aggregator
    'MobileAttacks',
    
    # Core Scanners
    'StaticAnalyzer',
    'RuntimeAnalyzer', 
    'APIDiscoveryEngine',
    'MobileSecurityScanner',
    'AppUnpacker',
    'get_unpacker',
    'AndroidAttackScanner',
    'IOSAttackScanner',
    'MobileMITMProxy',
    'create_mobile_proxy',
    'MobileLLMAnalyzer',
    'create_llm_analyzer',
    # App Crawler (like web crawler)
    'MobileAppCrawler',
    'create_app_crawler',
    'CrawledEndpoint',
    'CrawlResult',
    # Dynamic App Crawler (Emulator + Frida)
    'DynamicAppCrawler',
    'DiscoveredAPI',
    'DynamicCrawlResult',
    'crawl_app_dynamically',
    # Authentication detection & handling
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
    # Emulator Manager
    'EmulatorManager',
    'EmulatorConfig',
    'EmulatorStatus',
    'create_emulator_manager',
    'setup_emulator',
    # Frida SSL Pinning Bypass
    'FridaSSLBypass',
    'SSLBypassResult',
    'InterceptedSSLRequest',
    # iOS Simulator Manager
    'IOSSimulatorManager',
    'SimulatorConfig',
    'SimulatorDevice',
    'SimulatorStatus',
    # Mobile Pen Test Orchestrator (Full workflow like web testing)
    'MobilePenTestOrchestrator',
    'MobileScanConfig',
    'MobileScanContext',
    'MobileEndpoint',
    'MobileVulnerability',
    # Burp-Style Traffic Interceptor
    'BurpStyleInterceptor',
    'InterceptedTraffic',
    'FridaTrafficIntegration',
    # New Scanners Added 5 Jan 2026
    'MobileXSSScanner',
    'MobileXSSTester',
    'MobilePostMethodScanner',
    'MobileFormDataGenerator',
]

