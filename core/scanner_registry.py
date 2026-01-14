"""
Jarwis AGI Pen Test - Unified Scanner Registry

Single source of truth for ALL scanners.
Pre-login and post-login are CONTEXTS, not separate scanner sets.
All scanners can run on both contexts (with some exceptions).

Usage:
    registry = ScannerRegistry()
    scanners = registry.get_scanners(context="pre_login")
    for scanner_class in scanners:
        scanner = scanner_class(config, context, request_store)
        results = await scanner.scan()
"""

import logging
from typing import Dict, List, Type, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ScanContext(Enum):
    """Scan context - pre-login or post-login"""
    PRE_LOGIN = "pre_login"
    POST_LOGIN = "post_login"
    BOTH = "both"  # Scanner runs on both contexts


@dataclass
class ScannerMeta:
    """Metadata for a registered scanner"""
    name: str
    scanner_class: Type
    contexts: List[ScanContext]  # Which contexts this scanner supports
    owasp_category: str  # A01, A02, A03, etc.
    timeout: int = 60  # Default timeout in seconds
    enabled: bool = True
    description: str = ""
    

class ScannerRegistry:
    """
    Unified registry for all vulnerability scanners.
    
    Architecture:
    - Pre-login and post-login are CONTEXTS, not scanner types
    - Most scanners run on BOTH contexts with the same code
    - Some scanners are context-specific (e.g., CSRF needs auth tokens)
    - RequestStore provides the data for each context
    """
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._scanners: Dict[str, ScannerMeta] = {}
        self._initialized = True
        self._load_all_scanners()
    
    def _load_all_scanners(self):
        """Load all scanners from attacks modules"""
        
        # ========== Pre-Login Scanners (run on BOTH contexts) ==========
        try:
            from attacks.web.pre_login import (
                # Core OWASP
                InjectionScanner, XSSScanner, MisconfigScanner,
                SensitiveDataScanner, APIScanner, UploadScanner,
                SSRFScanner, AccessControlScanner,
                # Security Bypass
                AuthBypassScanner, SessionSecurityScanner, RateLimitBypassScanner,
                OAuthSecurityScanner, CaptchaBypassScanner, MobileSecurityScanner,
                # Advanced
                ResponseManipulationScanner, ResponseSwapScanner,
                # XSS Variants
                StoredXSSScanner, XSSReflectedScanner, ReflectedXSSScanner,
                # Form/POST
                PostMethodScanner,
                # Web Hacking 101
                OpenRedirectScanner, HPPScanner, HostHeaderScanner,
                SSTIScanner, XXEScanner, JWTAttackScanner,
                GraphQLScanner, WebSocketScanner,
                CORSScanner, CacheDeceptionScanner,
                HTTPSmugglingScanner, CachePoisoningScanner,
                RaceConditionScanner, LimitBypassScanner,
                SubdomainTakeoverScanner,
                BusinessLogicScanner, WorkflowBypassScanner,
                IDORScanner, MassAssignmentScanner,
                InformationDisclosureScanner, DirectoryListingScanner,
                OAuthVulnScanner, SAMLVulnScanner,
                APISecurityScanner, NoSQLInjectionScanner,
                PrototypePollutionScanner, DeserializationScanner,
                FileUploadScanner, CommandInjectionScanner,
                PathTraversalScanner, LFIScanner, RFIScanner,
                SSRFAdvancedScanner, BlindSSRFScanner,
                AdvancedXSSScanner, DOMXSSScanner,
                SQLInjectionScanner, UnionBasedSQLiScanner,
                SecurityHeadersScanner, CSPAnalyzer, CookieSecurityScanner,
                AuthenticationScanner, SessionManagementScanner, PasswordResetScanner,
                CSRFScanner, CSRFTokenAnalyzer,
                ClickjackingScanner, DoubleClickjackingScanner, UIRedressScanner,
                LDAPInjectionScanner, XPathInjectionScanner, EmailInjectionScanner,
                Log4ShellScanner, Spring4ShellScanner, FrameworkScanner,
            )
            
            # Try to import InputFieldAttacker (comprehensive form scanner)
            try:
                from attacks.web.pre_login import InputFieldAttacker
                has_input_field_attacker = InputFieldAttacker is not None
            except (ImportError, TypeError):
                has_input_field_attacker = False
                InputFieldAttacker = None
            
            # Try to import V2 scanners
            try:
                from attacks.web.pre_login import SQLiScannerV2
                has_sqli_v2 = SQLiScannerV2 is not None
            except (ImportError, TypeError):
                has_sqli_v2 = False
                SQLiScannerV2 = None
                
            try:
                from attacks.web.pre_login import FileUploadScannerV2
                has_upload_v2 = FileUploadScannerV2 is not None
            except (ImportError, TypeError):
                has_upload_v2 = False
                FileUploadScannerV2 = None
            
            # Register all pre-login scanners (most run on BOTH contexts)
            pre_login_scanners = [
                # Core OWASP - A01-A10
                (InjectionScanner, "A03", "SQL, NoSQL, Command Injection"),
                (XSSScanner, "A03", "Cross-Site Scripting"),
                (MisconfigScanner, "A05", "Security Misconfiguration"),
                (SensitiveDataScanner, "A02", "Sensitive Data Exposure"),
                (APIScanner, "A01", "API Security Issues"),
                (UploadScanner, "A04", "File Upload Vulnerabilities"),
                (SSRFScanner, "A10", "Server-Side Request Forgery"),
                (AccessControlScanner, "A01", "Broken Access Control"),
                
                # Security Bypass
                (AuthBypassScanner, "A07", "Authentication Bypass"),
                (SessionSecurityScanner, "A07", "Session Security Issues"),
                (RateLimitBypassScanner, "A07", "Rate Limit Bypass"),
                (OAuthSecurityScanner, "A07", "OAuth Security Issues"),
                (CaptchaBypassScanner, "A07", "CAPTCHA Bypass"),
                (MobileSecurityScanner, "A07", "Mobile Security Issues"),
                
                # Advanced
                (ResponseManipulationScanner, "A05", "Response Manipulation"),
                (ResponseSwapScanner, "A05", "Response Swapping"),
                
                # XSS Variants
                (StoredXSSScanner, "A03", "Stored XSS"),
                (XSSReflectedScanner, "A03", "Reflected XSS"),
                (AdvancedXSSScanner, "A03", "Advanced XSS"),
                (DOMXSSScanner, "A03", "DOM-based XSS"),
                
                # Form/POST
                (PostMethodScanner, "A03", "POST Method Security"),
                
                # Web Hacking 101
                (OpenRedirectScanner, "A01", "Open Redirect"),
                (HPPScanner, "A03", "HTTP Parameter Pollution"),
                (HostHeaderScanner, "A05", "Host Header Injection"),
                (SSTIScanner, "A03", "Server-Side Template Injection"),
                (XXEScanner, "A03", "XML External Entity"),
                (JWTAttackScanner, "A07", "JWT Attacks"),
                (GraphQLScanner, "A03", "GraphQL Security"),
                (WebSocketScanner, "A03", "WebSocket Security"),
                (CORSScanner, "A05", "CORS Misconfiguration"),
                (CacheDeceptionScanner, "A05", "Cache Deception"),
                (HTTPSmugglingScanner, "A05", "HTTP Smuggling"),
                (CachePoisoningScanner, "A05", "Cache Poisoning"),
                (RaceConditionScanner, "A01", "Race Conditions"),
                (LimitBypassScanner, "A07", "Limit Bypass"),
                (SubdomainTakeoverScanner, "A05", "Subdomain Takeover"),
                (BusinessLogicScanner, "A04", "Business Logic Flaws"),
                (WorkflowBypassScanner, "A04", "Workflow Bypass"),
                (IDORScanner, "A01", "Insecure Direct Object Reference"),
                (MassAssignmentScanner, "A04", "Mass Assignment"),
                (InformationDisclosureScanner, "A01", "Information Disclosure"),
                (DirectoryListingScanner, "A01", "Directory Listing"),
                (OAuthVulnScanner, "A07", "OAuth Vulnerabilities"),
                (SAMLVulnScanner, "A07", "SAML Vulnerabilities"),
                (APISecurityScanner, "A01", "API Security"),
                (NoSQLInjectionScanner, "A03", "NoSQL Injection"),
                (PrototypePollutionScanner, "A03", "Prototype Pollution"),
                (DeserializationScanner, "A08", "Insecure Deserialization"),
                (FileUploadScanner, "A04", "File Upload Bypass"),
                (CommandInjectionScanner, "A03", "Command Injection"),
                (PathTraversalScanner, "A01", "Path Traversal"),
                (LFIScanner, "A01", "Local File Inclusion"),
                (RFIScanner, "A01", "Remote File Inclusion"),
                (SSRFAdvancedScanner, "A10", "Advanced SSRF"),
                (BlindSSRFScanner, "A10", "Blind SSRF"),
                (SQLInjectionScanner, "A03", "SQL Injection"),
                (UnionBasedSQLiScanner, "A03", "Union-Based SQLi"),
                (SecurityHeadersScanner, "A05", "Security Headers"),
                (CSPAnalyzer, "A05", "Content Security Policy"),
                (CookieSecurityScanner, "A05", "Cookie Security"),
                (AuthenticationScanner, "A07", "Authentication Issues"),
                (SessionManagementScanner, "A07", "Session Management"),
                (PasswordResetScanner, "A07", "Password Reset Flaws"),
                (CSRFScanner, "A01", "Cross-Site Request Forgery"),
                (CSRFTokenAnalyzer, "A01", "CSRF Token Analysis"),
                (ClickjackingScanner, "A01", "Clickjacking"),
                (DoubleClickjackingScanner, "A01", "Double Clickjacking"),
                (UIRedressScanner, "A01", "UI Redressing"),
                (LDAPInjectionScanner, "A03", "LDAP Injection"),
                (XPathInjectionScanner, "A03", "XPath Injection"),
                (EmailInjectionScanner, "A03", "Email Injection"),
                (Log4ShellScanner, "A06", "Log4Shell (CVE-2021-44228)"),
                (Spring4ShellScanner, "A06", "Spring4Shell"),
                (FrameworkScanner, "A06", "Framework Vulnerabilities"),
            ]
            
            # Add InputFieldAttacker if available
            if has_input_field_attacker and InputFieldAttacker:
                pre_login_scanners.append((InputFieldAttacker, "A03", "Comprehensive Input Field Scanner"))
                logger.info("InputFieldAttacker registered")
            
            # Add V2 scanners if available
            if has_sqli_v2 and SQLiScannerV2:
                pre_login_scanners.append((SQLiScannerV2, "A03", "SQL Injection V2 (Enhanced)"))
                logger.info("SQLiScannerV2 registered")
            
            if has_upload_v2 and FileUploadScannerV2:
                pre_login_scanners.append((FileUploadScannerV2, "A04", "File Upload V2 (Enhanced)"))
                logger.info("FileUploadScannerV2 registered")
            
            for scanner_class, owasp_cat, description in pre_login_scanners:
                self._register_scanner(
                    scanner_class=scanner_class,
                    contexts=[ScanContext.BOTH],
                    owasp_category=owasp_cat,
                    description=description
                )
            
            logger.info(f"Loaded {len(pre_login_scanners)} pre-login scanners")
            
        except ImportError as e:
            logger.error(f"Failed to import pre-login scanners: {e}")
        
        # ========== Post-Login Specific Scanners ==========
        # These only make sense in post-login context (need auth)
        try:
            from attacks.web.post_login import (
                PostLoginStoredXSSScanner,
                PostLoginReflectedXSSScanner,
                PostLoginPostMethodScanner,
                PostLoginIDORScanner,
                PostLoginPrivilegeEscalation,
                PostLoginDataExfiltration,
                PostLoginCSRFScanner,
                PostLoginSensitiveActionScanner,
            )
            
            # Use name_override for scanners that have conflicting __name__
            # with pre-login scanners (they're aliased from different classes)
            post_login_only_scanners = [
                (PostLoginStoredXSSScanner, "A03", "Post-Login Stored XSS", "PostLoginStoredXSSScanner"),
                (PostLoginReflectedXSSScanner, "A03", "Post-Login Reflected XSS", "PostLoginReflectedXSSScanner"),
                (PostLoginPostMethodScanner, "A03", "Post-Login POST Methods", "PostLoginPostMethodScanner"),
                (PostLoginIDORScanner, "A01", "Authenticated IDOR", None),
                (PostLoginPrivilegeEscalation, "A01", "Privilege Escalation", None),
                (PostLoginDataExfiltration, "A02", "Data Exfiltration", None),
                (PostLoginCSRFScanner, "A01", "Authenticated CSRF", None),
                (PostLoginSensitiveActionScanner, "A01", "Sensitive Action Protection", None),
            ]
            
            for scanner_class, owasp_cat, description, name_override in post_login_only_scanners:
                self._register_scanner(
                    scanner_class=scanner_class,
                    contexts=[ScanContext.POST_LOGIN],  # Only post-login
                    owasp_category=owasp_cat,
                    description=description,
                    name_override=name_override
                )
            
            logger.info(f"Loaded {len(post_login_only_scanners)} post-login specific scanners")
            
        except ImportError as e:
            logger.warning(f"Some post-login scanners not available: {e}")
        
        # ========== AttackEngine Modules (MITM replay attacks) ==========
        # These work on captured requests from RequestStore
        try:
            from core.attack_engine import (
                SQLInjectionAttack, XSSAttack, NoSQLInjectionAttack,
                CommandInjectionAttack, SSTIAttack, XXEAttack,
                LDAPInjectionAttack, XPathInjectionAttack,
                IDORAttack, BOLAAttack, BFLAAttack,
                PathTraversalAttack, AuthBypassAttack, JWTAttack,
                SessionAttack, SSRFAttack, CSRFAttack,
                HostHeaderAttack, CORSAttack, HPPAttack,
                CRLFAttack, CachePoisonAttack, HTTPSmugglingAttack,
                OpenRedirectAttack, FileUploadAttack, RateLimitBypassAttack,
            )
            
            # Attack engine modules run on captured requests (both contexts)
            attack_modules = [
                (SQLInjectionAttack, "A03", "SQLi on Captured Requests"),
                (XSSAttack, "A03", "XSS on Captured Requests"),
                (NoSQLInjectionAttack, "A03", "NoSQLi on Captured Requests"),
                (CommandInjectionAttack, "A03", "CMDi on Captured Requests"),
                (SSTIAttack, "A03", "SSTI on Captured Requests"),
                (XXEAttack, "A03", "XXE on Captured Requests"),
                (LDAPInjectionAttack, "A03", "LDAPi on Captured Requests"),
                (XPathInjectionAttack, "A03", "XPath on Captured Requests"),
                (IDORAttack, "A01", "IDOR on Captured Requests"),
                (BOLAAttack, "A01", "BOLA on Captured Requests"),
                (BFLAAttack, "A01", "BFLA on Captured Requests"),
                (PathTraversalAttack, "A01", "Path Traversal on Captured Requests"),
                (AuthBypassAttack, "A07", "Auth Bypass on Captured Requests"),
                (JWTAttack, "A07", "JWT Attack on Captured Requests"),
                (SessionAttack, "A07", "Session Attack on Captured Requests"),
                (SSRFAttack, "A10", "SSRF on Captured Requests"),
                (CSRFAttack, "A01", "CSRF on Captured Requests"),
                (HostHeaderAttack, "A05", "Host Header on Captured Requests"),
                (CORSAttack, "A05", "CORS on Captured Requests"),
                (HPPAttack, "A05", "HPP on Captured Requests"),
                (CRLFAttack, "A05", "CRLF on Captured Requests"),
                (CachePoisonAttack, "A05", "Cache Poison on Captured Requests"),
                (HTTPSmugglingAttack, "A05", "HTTP Smuggling on Captured Requests"),
                (OpenRedirectAttack, "A01", "Open Redirect on Captured Requests"),
                (FileUploadAttack, "A04", "File Upload on Captured Requests"),
                (RateLimitBypassAttack, "A07", "Rate Limit on Captured Requests"),
            ]
            
            for attack_class, owasp_cat, description in attack_modules:
                self._register_scanner(
                    scanner_class=attack_class,
                    contexts=[ScanContext.BOTH],
                    owasp_category=owasp_cat,
                    description=description,
                    timeout=30  # Attack modules are faster
                )
            
            logger.info(f"Loaded {len(attack_modules)} attack engine modules")
            
        except ImportError as e:
            logger.warning(f"Attack engine modules not available: {e}")
        
        logger.info(f"Total scanners registered: {len(self._scanners)}")
    
    def _register_scanner(
        self,
        scanner_class: Type,
        contexts: List[ScanContext],
        owasp_category: str,
        description: str = "",
        timeout: int = 60,
        enabled: bool = True,
        name_override: str = None
    ):
        """Register a scanner in the registry"""
        name = name_override or scanner_class.__name__
        
        if name in self._scanners:
            # Already registered - update contexts if this is a broader context
            existing = self._scanners[name]
            if ScanContext.BOTH not in existing.contexts:
                # Merge contexts
                combined = list(set(existing.contexts + contexts))
                if ScanContext.PRE_LOGIN in combined and ScanContext.POST_LOGIN in combined:
                    combined = [ScanContext.BOTH]
                existing.contexts = combined
            return
        
        self._scanners[name] = ScannerMeta(
            name=name,
            scanner_class=scanner_class,
            contexts=contexts,
            owasp_category=owasp_category,
            timeout=timeout,
            enabled=enabled,
            description=description
        )
    
    def get_scanners(
        self, 
        context: str = "pre_login",
        owasp_filter: Optional[List[str]] = None,
        enabled_only: bool = True
    ) -> List[ScannerMeta]:
        """
        Get scanners for a specific context.
        
        Args:
            context: "pre_login" or "post_login"
            owasp_filter: Optional list of OWASP categories to filter (e.g., ["A01", "A03"])
            enabled_only: Only return enabled scanners
            
        Returns:
            List of ScannerMeta for applicable scanners
        """
        scan_context = ScanContext.PRE_LOGIN if context == "pre_login" else ScanContext.POST_LOGIN
        
        result = []
        for meta in self._scanners.values():
            # Check context
            if ScanContext.BOTH not in meta.contexts and scan_context not in meta.contexts:
                continue
            
            # Check enabled
            if enabled_only and not meta.enabled:
                continue
            
            # Check OWASP filter
            if owasp_filter and meta.owasp_category not in owasp_filter:
                continue
            
            result.append(meta)
        
        return result
    
    def get_all_scanners(self) -> Dict[str, ScannerMeta]:
        """Get all registered scanners"""
        return self._scanners.copy()
    
    def get_scanner(self, name: str) -> Optional[ScannerMeta]:
        """Get a specific scanner by name"""
        return self._scanners.get(name)
    
    def disable_scanner(self, name: str):
        """Disable a scanner"""
        if name in self._scanners:
            self._scanners[name].enabled = False
    
    def enable_scanner(self, name: str):
        """Enable a scanner"""
        if name in self._scanners:
            self._scanners[name].enabled = True
    
    def set_scanner_timeout(self, name: str, timeout: int):
        """Set timeout for a specific scanner"""
        if name in self._scanners:
            self._scanners[name].timeout = timeout
    
    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        contexts_count = {
            "pre_login_only": 0,
            "post_login_only": 0,
            "both": 0
        }
        
        owasp_count = {}
        
        for meta in self._scanners.values():
            # Count contexts
            if ScanContext.BOTH in meta.contexts:
                contexts_count["both"] += 1
            elif ScanContext.PRE_LOGIN in meta.contexts:
                contexts_count["pre_login_only"] += 1
            elif ScanContext.POST_LOGIN in meta.contexts:
                contexts_count["post_login_only"] += 1
            
            # Count OWASP categories
            cat = meta.owasp_category
            owasp_count[cat] = owasp_count.get(cat, 0) + 1
        
        return {
            "total_scanners": len(self._scanners),
            "enabled_scanners": len([s for s in self._scanners.values() if s.enabled]),
            "by_context": contexts_count,
            "by_owasp": owasp_count
        }


def get_registry() -> ScannerRegistry:
    """Get the singleton scanner registry instance"""
    return ScannerRegistry()
