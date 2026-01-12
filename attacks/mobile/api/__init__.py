"""
Mobile API - Attack Scanners and Interception

This package contains:
- API discovery and mapping
- Burp-style traffic interception
- Mobile MITM proxy integration
- Mobile API attack scanners (SQLi, IDOR, XSS)
"""

from .api_discovery import APIEndpoint, APIMap, APIDiscoveryEngine
from .burp_interceptor import HTTPMessage, InterceptedTraffic, BurpStyleInterceptor, FridaTrafficIntegration
from .mobile_mitm import MobileRequest, MobileResponse, MobileTrafficEntry, MobileMITMProxy
from .mobile_sqli_scanner import MobileSQLiScanner
from .mobile_idor_scanner import MobileIDORScanner
from .mobile_xss_scanner import MobileXSSScanner

__all__ = [
    # Discovery & Interception
    'APIEndpoint', 'APIMap', 'APIDiscoveryEngine',
    'HTTPMessage', 'InterceptedTraffic', 'BurpStyleInterceptor', 'FridaTrafficIntegration',
    'MobileRequest', 'MobileResponse', 'MobileTrafficEntry', 'MobileMITMProxy',
    # Attack Scanners
    'MobileSQLiScanner',
    'MobileIDORScanner',
    'MobileXSSScanner',
]
