"""
OWASP A05_MISCONFIG
"""

from .cors_scanner import ScanResult, CORSScanner, CacheDeceptionScanner
from .framework_scanner import ScanResult, Log4ShellScanner, Spring4ShellScanner, FrameworkScanner
from .host_header_scanner import ScanResult, HostHeaderInjectionScanner, CRLFInjectionScanner
from .hpp_scanner import ScanResult, HTTPParameterPollutionScanner
from .info_disclosure_scanner import ScanResult, InformationDisclosureScanner, DirectoryListingScanner
from .misconfig_scanner import ScanResult, MisconfigScanner
from .open_redirect_scanner import ScanResult, OpenRedirectScanner
from .response_manipulation_addon import ResponseManipulationAddon
from .response_manipulation_scanner import ScanResult, CapturedResponse, ResponseManipulationScanner
from .response_swap_scanner import ScanResult, AuthToken, TestCredentials, ResponseSwapScanner
from .security_headers_scanner import ScanResult, SecurityHeadersScanner, CSPAnalyzer, CookieSecurityScanner

# NEW: PortSwigger-based enterprise scanners (MITM-based)
from .cache_poisoning_scanner import WebCachePoisoningScannerV2, WebCachePoisoningScanner

__all__ = [
    'ScanResult', 'CORSScanner', 'CacheDeceptionScanner', 'Log4ShellScanner', 'Spring4ShellScanner',
    'FrameworkScanner', 'HostHeaderInjectionScanner', 'CRLFInjectionScanner', 'HTTPParameterPollutionScanner',
    'InformationDisclosureScanner', 'DirectoryListingScanner', 'MisconfigScanner', 'OpenRedirectScanner',
    'ResponseManipulationAddon', 'CapturedResponse', 'ResponseManipulationScanner', 'AuthToken',
    'TestCredentials', 'ResponseSwapScanner', 'SecurityHeadersScanner', 'CSPAnalyzer', 'CookieSecurityScanner',
    # NEW PortSwigger-based enterprise scanners
    'WebCachePoisoningScannerV2', 'WebCachePoisoningScanner',
]
