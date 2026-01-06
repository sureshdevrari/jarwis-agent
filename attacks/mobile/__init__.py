"""
Jarwis AGI - Mobile Application Security Scanner
OWASP Mobile Top 10 Coverage for Android & iOS

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

__all__ = [
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

