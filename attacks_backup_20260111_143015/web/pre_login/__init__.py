"""
JARWIS AGI PEN TEST - Pre-Login Attack Modules
Enhanced with OWASP Top 10 Detection Logic and JavaScript Rendering Support
Includes Security Bypass Scanners based on defensive security knowledge
Includes 45+ Attack Scanners based on Web Hacking 101 Techniques - Updated Jan 2026
"""

# ========== Core OWASP Scanners ==========
from .injection_scanner import InjectionScanner
from .xss_scanner import XSSScanner
from .misconfig_scanner import MisconfigScanner
from .sensitive_data_scanner import SensitiveDataScanner
from .api_scanner import APIScanner
from .upload_scanner import UploadScanner
from .ssrf_scanner import SSRFScanner
from .access_control_scanner import AccessControlScanner

# ========== Security Bypass Scanners ==========
from .auth_bypass_scanner import AuthBypassScanner
from .session_scanner import SessionSecurityScanner
from .rate_limit_scanner import RateLimitBypassScanner
from .oauth_scanner import OAuthSecurityScanner
from .captcha_scanner import CaptchaBypassScanner
from .mobile_security_scanner import MobileSecurityScanner

# ========== Advanced Attack Scanners ==========
from .response_manipulation_scanner import ResponseManipulationScanner
from .response_swap_scanner import ResponseSwapScanner

# ========== New Scanners Added 5 Jan 2026 ==========
from .xss_stored_scanner import StoredXSSScanner
from .xss_reflected_scanner import XSSReflectedScanner, ReflectedXSSScanner
from .post_method_scanner import PostMethodScanner, SmartFormDataGenerator

# ========== Web Hacking 101 Scanners (Jan 2026) ==========
# Open Redirect, HPP, Host Header
from .open_redirect_scanner import OpenRedirectScanner
from .hpp_scanner import HTTPParameterPollutionScanner as HPPScanner
from .host_header_scanner import HostHeaderInjectionScanner as HostHeaderScanner

# Template Injection, XXE
from .ssti_scanner import SSTIScanner
from .xxe_scanner import XXEScanner

# JWT, GraphQL, WebSocket
from .jwt_scanner import JWTAttackScanner
from .graphql_scanner import GraphQLScanner
from .websocket_scanner import WebSocketScanner

# CORS, Cache Deception
from .cors_scanner import CORSScanner, CacheDeceptionScanner

# HTTP Smuggling, Cache Poisoning
from .smuggling_scanner import HTTPSmugglingScanner, CachePoisoningScanner

# Race Conditions, Rate Limit Bypass
from .race_condition_scanner import RaceConditionScanner, LimitBypassScanner

# Subdomain Takeover
from .subdomain_takeover_scanner import SubdomainTakeoverScanner

# Business Logic, Workflow Bypass
from .business_logic_scanner import BusinessLogicScanner, WorkflowBypassScanner

# IDOR, Mass Assignment
from .idor_scanner import IDORScanner, MassAssignmentScanner

# Information Disclosure, Directory Listing
from .info_disclosure_scanner import InformationDisclosureScanner, DirectoryListingScanner

# OAuth/SAML Vulnerabilities
from .oauth_saml_scanner import OAuthVulnScanner, SAMLVulnScanner

# API Security, NoSQL Injection
from .api_security_scanner import APISecurityScanner, NoSQLInjectionScanner

# Prototype Pollution, Deserialization
from .prototype_pollution_scanner import PrototypePollutionScanner, DeserializationScanner

# File Upload, Command Injection
from .file_upload_scanner import FileUploadScanner, CommandInjectionScanner

# Path Traversal, LFI, RFI
from .path_traversal_scanner import PathTraversalScanner, LFIScanner, RFIScanner

# Advanced SSRF
from .ssrf_advanced_scanner import SSRFScanner as SSRFAdvancedScanner, BlindSSRFScanner

# Advanced XSS
from .xss_advanced_scanner import AdvancedXSSScanner, DOMXSSScanner

# Advanced SQLi
from .sqli_advanced_scanner import SQLInjectionScanner, UnionBasedSQLiScanner

# Security Headers, CSP, Cookies
from .security_headers_scanner import SecurityHeadersScanner, CSPAnalyzer, CookieSecurityScanner

# Authentication, Session, Password Reset
from .auth_scanner import AuthenticationScanner, SessionManagementScanner, PasswordResetScanner

# CSRF
from .csrf_scanner import CSRFScanner, CSRFTokenAnalyzer

# Clickjacking
from .clickjacking_scanner import ClickjackingScanner, DoubleClickjackingScanner, UIRedressScanner

# LDAP, XPath, Email Injection
from .ldap_injection_scanner import LDAPInjectionScanner, XPathInjectionScanner, EmailInjectionScanner

# Framework Vulnerabilities (Log4Shell, Spring4Shell)
from .framework_scanner import Log4ShellScanner, Spring4ShellScanner, FrameworkScanner


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
        
        # ========== Web Hacking 101 Scanners (Jan 2026) ==========
        
        # A01:2021 - Open Redirect
        if owasp_config.get('open_redirect', {}).get('enabled', True):
            scanner = OpenRedirectScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - HTTP Parameter Pollution
        if owasp_config.get('hpp', {}).get('enabled', True):
            scanner = HPPScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Host Header Injection
        if owasp_config.get('host_header', {}).get('enabled', True):
            scanner = HostHeaderScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - Server-Side Template Injection
        if owasp_config.get('ssti', {}).get('enabled', True):
            scanner = SSTIScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - XXE (XML External Entity)
        if owasp_config.get('xxe', {}).get('enabled', True):
            scanner = XXEScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - JWT Attacks
        if owasp_config.get('jwt', {}).get('enabled', True):
            scanner = JWTAttackScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - GraphQL Vulnerabilities
        if owasp_config.get('graphql', {}).get('enabled', True):
            scanner = GraphQLScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - WebSocket Security
        if owasp_config.get('websocket', {}).get('enabled', True):
            scanner = WebSocketScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - CORS Misconfiguration
        if owasp_config.get('cors', {}).get('enabled', True):
            scanner = CORSScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Cache Deception
        if owasp_config.get('cache_deception', {}).get('enabled', True):
            scanner = CacheDeceptionScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - HTTP Request Smuggling
        if owasp_config.get('http_smuggling', {}).get('enabled', True):
            scanner = HTTPSmugglingScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Cache Poisoning
        if owasp_config.get('cache_poisoning', {}).get('enabled', True):
            scanner = CachePoisoningScanner(config, context)
            self.scanners.append(scanner)
        
        # A04:2021 - Race Conditions
        if owasp_config.get('race_condition', {}).get('enabled', True):
            scanner = RaceConditionScanner(config, context)
            self.scanners.append(scanner)
        
        # A04:2021 - Limit Bypass
        if owasp_config.get('limit_bypass', {}).get('enabled', True):
            scanner = LimitBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Subdomain Takeover
        if owasp_config.get('subdomain_takeover', {}).get('enabled', True):
            scanner = SubdomainTakeoverScanner(config, context)
            self.scanners.append(scanner)
        
        # A04:2021 - Business Logic Flaws
        if owasp_config.get('business_logic', {}).get('enabled', True):
            scanner = BusinessLogicScanner(config, context)
            self.scanners.append(scanner)
        
        # A04:2021 - Workflow Bypass
        if owasp_config.get('workflow_bypass', {}).get('enabled', True):
            scanner = WorkflowBypassScanner(config, context)
            self.scanners.append(scanner)
        
        # A01:2021 - IDOR
        if owasp_config.get('idor', {}).get('enabled', True):
            scanner = IDORScanner(config, context)
            self.scanners.append(scanner)
        
        # A01:2021 - Mass Assignment
        if owasp_config.get('mass_assignment', {}).get('enabled', True):
            scanner = MassAssignmentScanner(config, context)
            self.scanners.append(scanner)
        
        # A01:2021 - Information Disclosure
        if owasp_config.get('info_disclosure', {}).get('enabled', True):
            scanner = InformationDisclosureScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Directory Listing
        if owasp_config.get('directory_listing', {}).get('enabled', True):
            scanner = DirectoryListingScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - OAuth Vulnerabilities
        if owasp_config.get('oauth_vuln', {}).get('enabled', True):
            scanner = OAuthVulnScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - SAML Vulnerabilities
        if owasp_config.get('saml_vuln', {}).get('enabled', True):
            scanner = SAMLVulnScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - API Security
        if owasp_config.get('api_security', {}).get('enabled', True):
            scanner = APISecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - NoSQL Injection
        if owasp_config.get('nosql_injection', {}).get('enabled', True):
            scanner = NoSQLInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - Prototype Pollution
        if owasp_config.get('prototype_pollution', {}).get('enabled', True):
            scanner = PrototypePollutionScanner(config, context)
            self.scanners.append(scanner)
        
        # A08:2021 - Deserialization
        if owasp_config.get('deserialization', {}).get('enabled', True):
            scanner = DeserializationScanner(config, context)
            self.scanners.append(scanner)
        
        # A04:2021 - File Upload Vulnerabilities
        if owasp_config.get('file_upload', {}).get('enabled', True):
            scanner = FileUploadScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - Command Injection
        if owasp_config.get('command_injection', {}).get('enabled', True):
            scanner = CommandInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # A01:2021 - Path Traversal
        if owasp_config.get('path_traversal', {}).get('enabled', True):
            scanner = PathTraversalScanner(config, context)
            self.scanners.append(scanner)
        
        # A01:2021 - LFI/RFI
        if owasp_config.get('lfi_rfi', {}).get('enabled', True):
            scanner = LFIScanner(config, context)
            self.scanners.append(scanner)
            scanner = RFIScanner(config, context)
            self.scanners.append(scanner)
        
        # A10:2021 - Advanced SSRF
        if owasp_config.get('ssrf_advanced', {}).get('enabled', True):
            scanner = SSRFAdvancedScanner(config, context)
            self.scanners.append(scanner)
        
        # A10:2021 - Blind SSRF
        if owasp_config.get('blind_ssrf', {}).get('enabled', True):
            scanner = BlindSSRFScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - Advanced XSS
        if owasp_config.get('xss_advanced', {}).get('enabled', True):
            scanner = AdvancedXSSScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A03:2021 - DOM XSS
        if owasp_config.get('dom_xss', {}).get('enabled', True):
            scanner = DOMXSSScanner(config, context)
            scanner.browser = browser_controller
            self.scanners.append(scanner)
        
        # A03:2021 - Advanced SQL Injection
        if owasp_config.get('sqli_advanced', {}).get('enabled', True):
            scanner = SQLInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - UNION-based SQLi
        if owasp_config.get('union_sqli', {}).get('enabled', True):
            scanner = UnionBasedSQLiScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Security Headers
        if owasp_config.get('security_headers', {}).get('enabled', True):
            scanner = SecurityHeadersScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - CSP Analysis
        if owasp_config.get('csp_analysis', {}).get('enabled', True):
            scanner = CSPAnalyzer(config, context)
            self.scanners.append(scanner)
        
        # A02:2021 - Cookie Security
        if owasp_config.get('cookie_security', {}).get('enabled', True):
            scanner = CookieSecurityScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - Authentication Testing
        if owasp_config.get('auth_testing', {}).get('enabled', True):
            scanner = AuthenticationScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - Session Management
        if owasp_config.get('session_management', {}).get('enabled', True):
            scanner = SessionManagementScanner(config, context)
            self.scanners.append(scanner)
        
        # A07:2021 - Password Reset
        if owasp_config.get('password_reset', {}).get('enabled', True):
            scanner = PasswordResetScanner(config, context)
            self.scanners.append(scanner)
        
        # A01:2021 - CSRF
        if owasp_config.get('csrf', {}).get('enabled', True):
            scanner = CSRFScanner(config, context)
            self.scanners.append(scanner)
        
        # A01:2021 - CSRF Token Analysis
        if owasp_config.get('csrf_token', {}).get('enabled', True):
            scanner = CSRFTokenAnalyzer(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Clickjacking
        if owasp_config.get('clickjacking', {}).get('enabled', True):
            scanner = ClickjackingScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - Double Clickjacking
        if owasp_config.get('double_clickjacking', {}).get('enabled', True):
            scanner = DoubleClickjackingScanner(config, context)
            self.scanners.append(scanner)
        
        # A05:2021 - UI Redressing
        if owasp_config.get('ui_redress', {}).get('enabled', True):
            scanner = UIRedressScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - LDAP Injection
        if owasp_config.get('ldap_injection', {}).get('enabled', True):
            scanner = LDAPInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - XPath Injection
        if owasp_config.get('xpath_injection', {}).get('enabled', True):
            scanner = XPathInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # A03:2021 - Email Injection
        if owasp_config.get('email_injection', {}).get('enabled', True):
            scanner = EmailInjectionScanner(config, context)
            self.scanners.append(scanner)
        
        # A06:2021 - Log4Shell
        if owasp_config.get('log4shell', {}).get('enabled', True):
            scanner = Log4ShellScanner(config, context)
            self.scanners.append(scanner)
        
        # A06:2021 - Spring4Shell
        if owasp_config.get('spring4shell', {}).get('enabled', True):
            scanner = Spring4ShellScanner(config, context)
            self.scanners.append(scanner)
        
        # A06:2021 - Framework Detection
        if owasp_config.get('framework_detection', {}).get('enabled', True):
            scanner = FrameworkScanner(config, context)
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
    # ========== Core OWASP Scanners ==========
    'InjectionScanner',
    'XSSScanner', 
    'MisconfigScanner',
    'SensitiveDataScanner',
    'APIScanner',
    'UploadScanner',
    'SSRFScanner',
    'AccessControlScanner',
    # ========== Security Bypass Scanners ==========
    'AuthBypassScanner',
    'SessionSecurityScanner',
    'RateLimitBypassScanner',
    'OAuthSecurityScanner',
    'CaptchaBypassScanner',
    'MobileSecurityScanner',
    # ========== Advanced Attack Scanners ==========
    'ResponseManipulationScanner',
    'ResponseSwapScanner',
    # ========== New Scanners Added 5 Jan 2026 ==========
    'StoredXSSScanner',
    'XSSReflectedScanner',
    'ReflectedXSSScanner',
    'PostMethodScanner',
    'SmartFormDataGenerator',
    # ========== Web Hacking 101 Scanners (Jan 2026) ==========
    # Open Redirect, HPP, Host Header
    'OpenRedirectScanner',
    'HPPScanner',
    'HostHeaderScanner',
    # Template Injection, XXE
    'SSTIScanner',
    'XXEScanner',
    # JWT, GraphQL, WebSocket
    'JWTAttackScanner',
    'GraphQLScanner',
    'WebSocketScanner',
    # CORS, Cache
    'CORSScanner',
    'CacheDeceptionScanner',
    'HTTPSmugglingScanner',
    'CachePoisoningScanner',
    # Race Conditions
    'RaceConditionScanner',
    'LimitBypassScanner',
    # Subdomain Takeover
    'SubdomainTakeoverScanner',
    # Business Logic
    'BusinessLogicScanner',
    'WorkflowBypassScanner',
    # IDOR, Mass Assignment
    'IDORScanner',
    'MassAssignmentScanner',
    # Information Disclosure
    'InformationDisclosureScanner',
    'DirectoryListingScanner',
    # OAuth/SAML
    'OAuthVulnScanner',
    'SAMLVulnScanner',
    # API Security
    'APISecurityScanner',
    'NoSQLInjectionScanner',
    # Prototype Pollution, Deserialization
    'PrototypePollutionScanner',
    'DeserializationScanner',
    # File Upload, Command Injection
    'FileUploadScanner',
    'CommandInjectionScanner',
    # Path Traversal, LFI, RFI
    'PathTraversalScanner',
    'LFIScanner',
    'RFIScanner',
    # Advanced SSRF
    'SSRFAdvancedScanner',
    'BlindSSRFScanner',
    # Advanced XSS
    'AdvancedXSSScanner',
    'DOMXSSScanner',
    # Advanced SQLi
    'SQLInjectionScanner',
    'UnionBasedSQLiScanner',
    # Security Headers
    'SecurityHeadersScanner',
    'CSPAnalyzer',
    'CookieSecurityScanner',
    # Authentication
    'AuthenticationScanner',
    'SessionManagementScanner',
    'PasswordResetScanner',
    # CSRF
    'CSRFScanner',
    'CSRFTokenAnalyzer',
    # Clickjacking
    'ClickjackingScanner',
    'DoubleClickjackingScanner',
    'UIRedressScanner',
    # LDAP, XPath, Email Injection
    'LDAPInjectionScanner',
    'XPathInjectionScanner',
    'EmailInjectionScanner',
    # Framework Scanners
    'Log4ShellScanner',
    'Spring4ShellScanner',
    'FrameworkScanner',
]

