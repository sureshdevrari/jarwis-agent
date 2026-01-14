"""
JARWIS AGI PEN TEST - Pre-Login Attack Modules (Backward Compatibility)
===============================================================================

This module provides backward-compatible imports for the web/pre_login scanners.
Scanners have been reorganized into OWASP Top 10 2021 categories.

NEW STRUCTURE (Recommended):
    from attacks.web.a03_injection import InjectionScanner, XSSScanner
    from attacks.web.a01_broken_access import IDORScanner
    from attacks.web.a05_misconfig import CORSScanner
    
LEGACY IMPORT (Deprecated but still works):
    from attacks.web.pre_login import InjectionScanner, XSSScanner

OWASP Top 10 2021 Categories:
- a01_broken_access/  - Broken Access Control
- a02_crypto/         - Cryptographic Failures
- a03_injection/      - Injection (SQL, XSS, Command, etc.)
- a04_insecure_design/- Insecure Design
- a05_misconfig/      - Security Misconfiguration
- a06_vulnerable_components/ - Vulnerable & Outdated Components
- a07_auth_failures/  - Identification and Authentication Failures
- a08_integrity/      - Software and Data Integrity Failures
- a09_logging/        - Security Logging and Monitoring Failures
- a10_ssrf/           - Server-Side Request Forgery
"""

import warnings
from typing import List, Any
import logging

logger = logging.getLogger(__name__)

# =============================================================================
# BACKWARD-COMPATIBLE IMPORTS FROM NEW OWASP LOCATIONS
# =============================================================================

# A01:2021 - Broken Access Control
from ..a01_broken_access.access_control_scanner import AccessControlScanner
from ..a01_broken_access.idor_scanner import IDORScanner, MassAssignmentScanner
from ..a01_broken_access.auth_bypass_scanner import AuthBypassScanner
from ..a01_broken_access.path_traversal_scanner import PathTraversalScanner, LFIScanner, RFIScanner

# A02:2021 - Cryptographic Failures
from ..a02_crypto.jwt_scanner import JWTAttackScanner
from ..a02_crypto.session_scanner import SessionSecurityScanner

# A03:2021 - Injection (SQL, NoSQL, Command, LDAP, XSS, etc.)
from ..a03_injection.injection_scanner import InjectionScanner
from ..a03_injection.xss_scanner import XSSScanner
from ..a03_injection.xss_advanced_scanner import AdvancedXSSScanner, DOMXSSScanner
from ..a03_injection.xss_reflected_scanner import XSSReflectedScanner, ReflectedXSSScanner
from ..a03_injection.xss_stored_scanner import StoredXSSScanner
from ..a03_injection.sqli_advanced_scanner import SQLInjectionScanner, UnionBasedSQLiScanner
from ..a03_injection.ssti_scanner import SSTIScanner
from ..a03_injection.xxe_scanner import XXEScanner
from ..a03_injection.ldap_injection_scanner import LDAPInjectionScanner, XPathInjectionScanner, EmailInjectionScanner

# A04:2021 - Insecure Design
from ..a04_insecure_design.business_logic_scanner import BusinessLogicScanner, WorkflowBypassScanner
from ..a04_insecure_design.race_condition_scanner import RaceConditionScanner, LimitBypassScanner
from ..a04_insecure_design.captcha_scanner import CaptchaBypassScanner

# A05:2021 - Security Misconfiguration
from ..a05_misconfig.misconfig_scanner import MisconfigScanner
from ..a05_misconfig.cors_scanner import CORSScanner, CacheDeceptionScanner
from ..a05_misconfig.security_headers_scanner import SecurityHeadersScanner, CSPAnalyzer, CookieSecurityScanner
from ..a05_misconfig.host_header_scanner import HostHeaderInjectionScanner as HostHeaderScanner
from ..a05_misconfig.open_redirect_scanner import OpenRedirectScanner
from ..a05_misconfig.info_disclosure_scanner import InformationDisclosureScanner, DirectoryListingScanner
from ..a05_misconfig.framework_scanner import Log4ShellScanner, Spring4ShellScanner, FrameworkScanner
from ..a05_misconfig.hpp_scanner import HTTPParameterPollutionScanner as HPPScanner
from ..a05_misconfig.response_manipulation_scanner import ResponseManipulationScanner
from ..a05_misconfig.response_swap_scanner import ResponseSwapScanner

# A06:2021 - Vulnerable and Outdated Components
from ..a06_vulnerable_components.subdomain_takeover_scanner import SubdomainTakeoverScanner

# A07:2021 - Identification and Authentication Failures
from ..a07_auth_failures.auth_scanner import AuthenticationScanner, SessionManagementScanner, PasswordResetScanner
from ..a07_auth_failures.csrf_scanner import CSRFScanner, CSRFTokenAnalyzer
from ..a07_auth_failures.clickjacking_scanner import ClickjackingScanner, DoubleClickjackingScanner, UIRedressScanner
from ..a07_auth_failures.oauth_scanner import OAuthSecurityScanner
from ..a07_auth_failures.oauth_saml_scanner import OAuthVulnScanner, SAMLVulnScanner

# A08:2021 - Software and Data Integrity Failures
from ..a08_integrity.prototype_pollution_scanner import PrototypePollutionScanner, DeserializationScanner

# A09:2021 - Security Logging and Monitoring Failures
from ..a09_logging.sensitive_data_scanner import SensitiveDataScanner

# A10:2021 - Server-Side Request Forgery
from ..a10_ssrf.ssrf_scanner import SSRFScanner
from ..a10_ssrf.ssrf_advanced_scanner import SSRFScanner as SSRFAdvancedScanner, BlindSSRFScanner

# API Security (separate category)
from ..api.api_scanner import APIScanner
from ..api.api_security_scanner import APISecurityScanner, NoSQLInjectionScanner
from ..api.graphql_scanner import GraphQLScanner
from ..api.websocket_scanner import WebSocketScanner

# File Upload
from ..file_upload.file_upload_scanner import FileUploadScanner, CommandInjectionScanner
from ..file_upload.upload_scanner import UploadScanner

# Other
from ..other.post_method_scanner import PostMethodScanner, SmartFormDataGenerator
from ..other.smuggling_scanner import HTTPSmugglingScanner, CachePoisoningScanner
from ..other.rate_limit_scanner import RateLimitBypassScanner

# Input Field Attacker (comprehensive form/input vulnerability scanner)
try:
    from ..input_field_attacker import InputFieldAttacker
except ImportError:
    InputFieldAttacker = None  # Optional - file may not exist

# V2 Scanners (enhanced versions)
try:
    from ..a03_injection.sqli_scanner_v2 import SQLiScannerV2
except ImportError:
    SQLiScannerV2 = None

try:
    from ..file_upload.file_upload_scanner_v2 import FileUploadScannerV2
except ImportError:
    FileUploadScannerV2 = None

# Note: MobileSecurityScanner was moved to attacks/mobile/utils/
# Import from there if needed:
# from attacks.mobile.utils.mobile_security_scanner import MobileSecurityScanner


class PreLoginAttacks:
    """
    Orchestrates all pre-login attack modules with OWASP detection logic.
    
    This class provides backward compatibility for existing code that uses
    PreLoginAttacks. For new code, consider using the OWASP-organized
    scanner imports directly.
    """
    
    def __init__(self, config: dict, context, browser_controller=None):
        self.config = config
        self.context = context
        self.browser = browser_controller
        self.scanners = []
        
        # Initialize enabled scanners based on OWASP categories
        owasp_config = config.get('owasp', {})
        
        # A01:2021 - Broken Access Control
        if owasp_config.get('access_control', {}).get('enabled', True):
            scanner = AccessControlScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A03:2021 - Injection (SQL, NoSQL, Command, LDAP)
        if owasp_config.get('injection', {}).get('enabled', True):
            scanner = InjectionScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A03:2021 - Cross-Site Scripting (XSS)
        if owasp_config.get('xss', {}).get('enabled', True):
            scanner = XSSScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A05:2021 - Security Misconfiguration
        if owasp_config.get('misconfig', {}).get('enabled', True):
            scanner = MisconfigScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A02:2021 - Cryptographic Failures / Sensitive Data Exposure
        if owasp_config.get('sensitive_data', {}).get('enabled', True):
            scanner = SensitiveDataScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A10:2021 - Server-Side Request Forgery (SSRF)
        if owasp_config.get('ssrf', {}).get('enabled', True):
            scanner = SSRFScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A07:2021 - Authentication Bypass
        if owasp_config.get('auth_bypass', {}).get('enabled', True):
            scanner = AuthBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # A02:2021 - Session Security
        if owasp_config.get('session_security', {}).get('enabled', True):
            scanner = SessionSecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # Rate Limit Bypass
        if owasp_config.get('rate_limit_bypass', {}).get('enabled', True):
            scanner = RateLimitBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - OAuth Security
        if owasp_config.get('oauth_security', {}).get('enabled', True):
            scanner = OAuthSecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # CAPTCHA Bypass
        if owasp_config.get('captcha_bypass', {}).get('enabled', True):
            scanner = CaptchaBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # Response Manipulation
        if owasp_config.get('response_manipulation', {}).get('enabled', True):
            scanner = ResponseManipulationScanner(config, context)
            self.scanners.append(scanner)
        
        # Response Swap Attack
        if owasp_config.get('response_swap', {}).get('enabled', True):
            scanner = ResponseSwapScanner(config, context)
            self.scanners.append(scanner)
        
        # Stored XSS
        if owasp_config.get('stored_xss', {}).get('enabled', True):
            scanner = StoredXSSScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # Reflected XSS
        if owasp_config.get('reflected_xss', {}).get('enabled', True):
            scanner = XSSReflectedScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # POST Method Scanner
        if owasp_config.get('post_method', {}).get('enabled', True):
            scanner = PostMethodScanner(config, context, browser_controller)
            self.scanners.append(scanner)
        
        # Open Redirect
        if owasp_config.get('open_redirect', {}).get('enabled', True):
            scanner = OpenRedirectScanner(config, context)
            self.scanners.append(scanner)
        
        # HTTP Parameter Pollution
        if owasp_config.get('hpp', {}).get('enabled', True):
            scanner = HPPScanner(config, context)
            self.scanners.append(scanner)
        
        # Host Header Injection
        if owasp_config.get('host_header', {}).get('enabled', True):
            scanner = HostHeaderScanner(config, context)
            self.scanners.append(scanner)
        
        # Server-Side Template Injection
        if owasp_config.get('ssti', {}).get('enabled', True):
            scanner = SSTIScanner(config, context)
            self.scanners.append(scanner)
        
        # XXE
        if owasp_config.get('xxe', {}).get('enabled', True):
            scanner = XXEScanner(config, context)
            self.scanners.append(scanner)
        
        # JWT Attacks
        if owasp_config.get('jwt', {}).get('enabled', True):
            scanner = JWTAttackScanner(config, context)
            self.scanners.append(scanner)
        
        # GraphQL Security
        if owasp_config.get('graphql', {}).get('enabled', True):
            scanner = GraphQLScanner(config, context)
            self.scanners.append(scanner)
        
        # WebSocket Security
        if owasp_config.get('websocket', {}).get('enabled', True):
            scanner = WebSocketScanner(config, context)
            self.scanners.append(scanner)
        
        # CORS Misconfiguration
        if owasp_config.get('cors', {}).get('enabled', True):
            scanner = CORSScanner(config, context)
            self.scanners.append(scanner)
        
        # HTTP Smuggling
        if owasp_config.get('http_smuggling', {}).get('enabled', True):
            scanner = HTTPSmugglingScanner(config, context)
            self.scanners.append(scanner)
        
        # Race Conditions
        if owasp_config.get('race_condition', {}).get('enabled', True):
            scanner = RaceConditionScanner(config, context)
            self.scanners.append(scanner)
        
        # Subdomain Takeover
        if owasp_config.get('subdomain_takeover', {}).get('enabled', True):
            scanner = SubdomainTakeoverScanner(config, context)
            self.scanners.append(scanner)
        
        # Business Logic
        if owasp_config.get('business_logic', {}).get('enabled', True):
            scanner = BusinessLogicScanner(config, context)
            self.scanners.append(scanner)
        
        # IDOR
        if owasp_config.get('idor', {}).get('enabled', True):
            scanner = IDORScanner(config, context)
            self.scanners.append(scanner)
        
        # Information Disclosure
        if owasp_config.get('info_disclosure', {}).get('enabled', True):
            scanner = InformationDisclosureScanner(config, context)
            self.scanners.append(scanner)
        
        # OAuth/SAML Vulnerabilities
        if owasp_config.get('oauth_saml', {}).get('enabled', True):
            scanner = OAuthVulnScanner(config, context)
            self.scanners.append(scanner)
        
        # API Security
        if owasp_config.get('api_security', {}).get('enabled', True):
            scanner = APISecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # Prototype Pollution
        if owasp_config.get('prototype_pollution', {}).get('enabled', True):
            scanner = PrototypePollutionScanner(config, context)
            self.scanners.append(scanner)
        
        # File Upload
        if owasp_config.get('file_upload', {}).get('enabled', True):
            scanner = FileUploadScanner(config, context)
            self.scanners.append(scanner)
        
        # Path Traversal
        if owasp_config.get('path_traversal', {}).get('enabled', True):
            scanner = PathTraversalScanner(config, context)
            self.scanners.append(scanner)
        
        # Advanced SSRF
        if owasp_config.get('ssrf_advanced', {}).get('enabled', True):
            scanner = SSRFAdvancedScanner(config, context)
            self.scanners.append(scanner)
        
        # Advanced XSS
        if owasp_config.get('xss_advanced', {}).get('enabled', True):
            scanner = AdvancedXSSScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # Advanced SQLi
        if owasp_config.get('sqli_advanced', {}).get('enabled', True):
            scanner = SQLInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # Security Headers
        if owasp_config.get('security_headers', {}).get('enabled', True):
            scanner = SecurityHeadersScanner(config, context)
            self.scanners.append(scanner)
        
        # Authentication Scanner
        if owasp_config.get('authentication', {}).get('enabled', True):
            scanner = AuthenticationScanner(config, context)
            self.scanners.append(scanner)
        
        # CSRF
        if owasp_config.get('csrf', {}).get('enabled', True):
            scanner = CSRFScanner(config, context)
            self.scanners.append(scanner)
        
        # Clickjacking
        if owasp_config.get('clickjacking', {}).get('enabled', True):
            scanner = ClickjackingScanner(config, context)
            self.scanners.append(scanner)
        
        # LDAP Injection
        if owasp_config.get('ldap_injection', {}).get('enabled', True):
            scanner = LDAPInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # Framework Vulnerabilities
        if owasp_config.get('framework', {}).get('enabled', True):
            scanner = FrameworkScanner(config, context)
            self.scanners.append(scanner)
    
    async def run(self) -> List[Any]:
        """Run all pre-login scanners."""
        findings = []
        for scanner in self.scanners:
            try:
                result = await scanner.run()
                if result:
                    findings.extend(result if isinstance(result, list) else [result])
            except Exception as e:
                logger.error(f"Scanner {scanner.__class__.__name__} failed: {e}")
        return findings
    
    async def run_all(self) -> List[Any]:
        """
        Alias for run() - provided for backward compatibility.
        
        This method is called by runner.py and other orchestration code.
        """
        return await self.run()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main Class
    'PreLoginAttacks',
    
    # A01 - Broken Access Control
    'AccessControlScanner',
    'IDORScanner',
    'MassAssignmentScanner',
    'AuthBypassScanner',
    'PathTraversalScanner',
    'LFIScanner',
    'RFIScanner',
    
    # A02 - Cryptographic Failures
    'JWTAttackScanner',
    'SessionSecurityScanner',
    
    # A03 - Injection
    'InjectionScanner',
    'XSSScanner',
    'AdvancedXSSScanner',
    'DOMXSSScanner',
    'XSSReflectedScanner',
    'ReflectedXSSScanner',
    'StoredXSSScanner',
    'SQLInjectionScanner',
    'UnionBasedSQLiScanner',
    'SSTIScanner',
    'XXEScanner',
    'LDAPInjectionScanner',
    'XPathInjectionScanner',
    'EmailInjectionScanner',
    
    # A04 - Insecure Design
    'BusinessLogicScanner',
    'WorkflowBypassScanner',
    'RaceConditionScanner',
    'LimitBypassScanner',
    'CaptchaBypassScanner',
    
    # A05 - Security Misconfiguration
    'MisconfigScanner',
    'CORSScanner',
    'CacheDeceptionScanner',
    'SecurityHeadersScanner',
    'CSPAnalyzer',
    'CookieSecurityScanner',
    'HostHeaderScanner',
    'OpenRedirectScanner',
    'InformationDisclosureScanner',
    'DirectoryListingScanner',
    'Log4ShellScanner',
    'Spring4ShellScanner',
    'FrameworkScanner',
    'HPPScanner',
    'ResponseManipulationScanner',
    'ResponseSwapScanner',
    
    # A06 - Vulnerable Components
    'SubdomainTakeoverScanner',
    
    # A07 - Auth Failures
    'AuthenticationScanner',
    'SessionManagementScanner',
    'PasswordResetScanner',
    'CSRFScanner',
    'CSRFTokenAnalyzer',
    'ClickjackingScanner',
    'DoubleClickjackingScanner',
    'UIRedressScanner',
    'OAuthSecurityScanner',
    'OAuthVulnScanner',
    'SAMLVulnScanner',
    
    # A08 - Integrity Failures
    'PrototypePollutionScanner',
    'DeserializationScanner',
    
    # A09 - Logging Failures
    'SensitiveDataScanner',
    
    # A10 - SSRF
    'SSRFScanner',
    'SSRFAdvancedScanner',
    'BlindSSRFScanner',
    
    # API Security
    'APIScanner',
    'APISecurityScanner',
    'NoSQLInjectionScanner',
    'GraphQLScanner',
    'WebSocketScanner',
    
    # File Upload
    'FileUploadScanner',
    'CommandInjectionScanner',
    'UploadScanner',
    
    # Other
    'PostMethodScanner',
    'SmartFormDataGenerator',
    'HTTPSmugglingScanner',
    'CachePoisoningScanner',
    'RateLimitBypassScanner',
    
    # Input Field Attacker (comprehensive form scanner)
    'InputFieldAttacker',
    
    # V2 Enhanced Scanners
    'SQLiScannerV2',
    'FileUploadScannerV2',
]
