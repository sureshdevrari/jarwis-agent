"""
JARWIS AGI PEN TEST - Pre-Login Attack Modules
Enhanced with OWASP Top 10 Detection Logic and JavaScript Rendering Support
Includes Security Bypass Scanners based on defensive security knowledge
Includes New Scanners Added 5 Jan 2026
"""

from .injection_scanner import InjectionScanner
from .xss_scanner import XSSScanner
from .misconfig_scanner import MisconfigScanner
from .sensitive_data_scanner import SensitiveDataScanner
from .api_scanner import APIScanner
from .upload_scanner import UploadScanner
from .ssrf_scanner import SSRFScanner
from .access_control_scanner import AccessControlScanner

# Security Bypass Scanners (based on defensive security implementation knowledge)
from .auth_bypass_scanner import AuthBypassScanner
from .session_scanner import SessionSecurityScanner
from .rate_limit_scanner import RateLimitBypassScanner
from .oauth_scanner import OAuthSecurityScanner
from .captcha_scanner import CaptchaBypassScanner
from .mobile_security_scanner import MobileSecurityScanner

# Advanced Attack Scanners
from .response_manipulation_scanner import ResponseManipulationScanner
from .response_swap_scanner import ResponseSwapScanner

# New Scanners Added 5 Jan 2026
from .xss_stored_scanner import StoredXSSScanner
from .xss_reflected_scanner import XSSReflectedScanner, ReflectedXSSScanner
from .post_method_scanner import PostMethodScanner, SmartFormDataGenerator


class PreLoginAttacks:
    """Orchestrates all pre-login attack modules with OWASP detection logic"""
    
    def __init__(self, config: dict, context, browser_controller=None):
        self.config = config
        self.context = context
        self.browser = browser_controller  # For JavaScript rendering
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
        
        # A07:2021 - Cross-Site Scripting (XSS)
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
        
        # ========== Security Bypass Scanners ==========
        # These scanners test for vulnerabilities based on common security implementations
        
        # A07:2021 - Authentication Bypass (JWT, Headers, Default Creds, MFA)
        if owasp_config.get('auth_bypass', {}).get('enabled', True):
            scanner = AuthBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - Session Security (Cookies, Token Entropy, Timeout)
        if owasp_config.get('session_security', {}).get('enabled', True):
            scanner = SessionSecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - Rate Limit Bypass (IP Rotation, Headers, Race Conditions)
        if owasp_config.get('rate_limit_bypass', {}).get('enabled', True):
            scanner = RateLimitBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - OAuth/SSO Security (State, Redirect, PKCE)
        if owasp_config.get('oauth_security', {}).get('enabled', True):
            scanner = OAuthSecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - CAPTCHA Bypass (Token Reuse, Client-side Only, Missing)
        if owasp_config.get('captcha_bypass', {}).get('enabled', True):
            scanner = CaptchaBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # M3/M4:2024 - Mobile Security (SSL, Device Binding, Root Detection)
        if owasp_config.get('mobile_security', {}).get('enabled', True):
            scanner = MobileSecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - Response Manipulation (MITM, Token Binding, Login/OTP Bypass)
        if owasp_config.get('response_manipulation', {}).get('enabled', True):
            scanner = ResponseManipulationScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - Response Swap Attack (Comprehensive Token Binding Tests)
        # This scanner requires test credentials for full testing
        if owasp_config.get('response_swap', {}).get('enabled', True):
            scanner = ResponseSwapScanner(config, context)
            self.scanners.append(scanner)
        
        # ========== New Scanners Added 5 Jan 2026 ==========
        
        # A03:2021 - Stored XSS (Persistent XSS with delayed execution detection)
        if owasp_config.get('stored_xss', {}).get('enabled', True):
            scanner = StoredXSSScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A03:2021 - Reflected XSS (Browser-verified with comprehensive payloads)
        if owasp_config.get('reflected_xss', {}).get('enabled', True):
            scanner = XSSReflectedScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A03:2021 - POST Method Scanner (Form discovery and testing)
        if owasp_config.get('post_method', {}).get('enabled', True):
            scanner = PostMethodScanner(config, context, browser_controller)
            self.scanners.append(scanner)
    
    async def run_all(self):
        """Run all enabled pre-login scanners"""
        findings = []
        
        for scanner in self.scanners:
            try:
                scanner_findings = await scanner.scan()
                findings.extend(scanner_findings)
            except Exception as e:
                print(f"Scanner {scanner.__class__.__name__} failed: {e}")
        
        return findings


__all__ = [
    'PreLoginAttacks',
    # Original OWASP Scanners
    'InjectionScanner',
    'XSSScanner', 
    'MisconfigScanner',
    'SensitiveDataScanner',
    'APIScanner',
    'UploadScanner',
    'SSRFScanner',
    'AccessControlScanner',
    # Security Bypass Scanners
    'AuthBypassScanner',
    'SessionSecurityScanner',
    'RateLimitBypassScanner',
    'OAuthSecurityScanner',
    'CaptchaBypassScanner',
    'MobileSecurityScanner',
    # Advanced Attack Scanners
    'ResponseManipulationScanner',
    'ResponseSwapScanner',
    # New Scanners Added 5 Jan 2026
    'StoredXSSScanner',
    'XSSReflectedScanner',
    'ReflectedXSSScanner',
    'PostMethodScanner',
    'SmartFormDataGenerator',
]

