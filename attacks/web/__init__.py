"""
JARWIS AGI PEN TEST - Web Attack Module
Bundles ALL web security scanners (pre-login + post-login)

OWASP Top 10 2021 Coverage:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection (SQL, NoSQL, Command, LDAP)
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable Components
- A07:2021 - Identification & Authentication Failures
- A08:2021 - Software & Data Integrity Failures
- A09:2021 - Security Logging & Monitoring Failures
- A10:2021 - Server-Side Request Forgery (SSRF)

Web Hacking 101 Coverage:
- XSS (Reflected, Stored, DOM)
- SQL Injection (Union, Blind, Error-based)
- CSRF, Clickjacking
- IDOR, Mass Assignment
- Open Redirect, Host Header Injection
- JWT Attacks, OAuth/SAML Vulnerabilities
- GraphQL, WebSocket Security
- And 30+ more attack vectors
"""

from typing import List, Any
import logging

# Direct exports for convenience
from .pre_login import PreLoginAttacks
from .post_login import PostLoginAttacks

logger = logging.getLogger(__name__)


class WebAttacks:
    """
    Aggregates ALL web security scanners.
    
    Handles both pre-login (unauthenticated) and post-login (authenticated)
    testing phases.
    
    Usage:
        web = WebAttacks(config, context, browser_controller)
        
        # Run all phases
        findings = await web.run()
        
        # Or run specific phases
        pre_findings = await web.run_pre_login()
        post_findings = await web.run_post_login()
    """
    
    def __init__(self, config: dict, context, browser_controller=None):
        """
        Initialize web attack module.
        
        Args:
            config: Scan configuration dictionary
            context: ScanContext with endpoints, cookies, etc.
            browser_controller: Optional Playwright browser for JS rendering
        """
        self.config = config
        self.context = context
        self.browser_controller = browser_controller
        
        # Lazy load attack modules
        self._pre_login = None
        self._post_login = None
    
    @property
    def pre_login(self):
        """Lazy load PreLoginAttacks"""
        if self._pre_login is None:
            from .pre_login import PreLoginAttacks
            self._pre_login = PreLoginAttacks(
                self.config, 
                self.context, 
                self.browser_controller
            )
        return self._pre_login
    
    @property
    def post_login(self):
        """Lazy load PostLoginAttacks"""
        if self._post_login is None:
            from .post_login import PostLoginAttacks
            self._post_login = PostLoginAttacks(
                self.config, 
                self.context
            )
        return self._post_login
    
    async def run(self) -> List[Any]:
        """
        Run all web scanners (pre-login + post-login).
        
        Returns:
            List of all findings from both phases
        """
        results = []
        
        # Phase 1: Pre-login (unauthenticated) attacks
        logger.info("Starting web pre-login attacks...")
        try:
            pre_results = await self.run_pre_login()
            results.extend(pre_results)
            logger.info(f"Pre-login attacks complete: {len(pre_results)} findings")
        except Exception as e:
            logger.error(f"Pre-login attacks failed: {e}")
        
        # Phase 2: Post-login (authenticated) attacks
        # Only run if we have authenticated session
        if self._is_authenticated():
            logger.info("Starting web post-login attacks...")
            try:
                post_results = await self.run_post_login()
                results.extend(post_results)
                logger.info(f"Post-login attacks complete: {len(post_results)} findings")
            except Exception as e:
                logger.error(f"Post-login attacks failed: {e}")
        else:
            logger.info("Skipping post-login attacks (no authentication configured)")
        
        return results
    
    async def run_pre_login(self) -> List[Any]:
        """
        Run only pre-login (unauthenticated) attacks.
        
        Tests for vulnerabilities accessible without authentication:
        - SQL Injection, XSS, SSRF
        - Security Misconfigurations
        - Information Disclosure
        - Authentication Bypass
        """
        try:
            return await self.pre_login.run()
        except Exception as e:
            logger.error(f"Pre-login scan error: {e}")
            return []
    
    async def run_post_login(self) -> List[Any]:
        """
        Run only post-login (authenticated) attacks.
        
        Tests for vulnerabilities requiring authentication:
        - IDOR (Insecure Direct Object Reference)
        - Privilege Escalation
        - CSRF on sensitive actions
        - Session Management issues
        """
        try:
            return await self.post_login.run()
        except Exception as e:
            logger.error(f"Post-login scan error: {e}")
            return []
    
    def _is_authenticated(self) -> bool:
        """Check if we have an authenticated session"""
        # Check if context has cookies or auth token
        if hasattr(self.context, 'is_authenticated'):
            return self.context.is_authenticated
        
        if hasattr(self.context, 'cookies') and self.context.cookies:
            return True
        
        if hasattr(self.context, 'auth_token') and self.context.auth_token:
            return True
        
        # Check config for auth credentials
        auth_config = self.config.get('auth', {})
        if auth_config.get('username') and auth_config.get('password'):
            return True
        
        return False
    
    def get_scanner_count(self) -> dict:
        """Get count of available scanners"""
        return {
            "pre_login": len(getattr(self.pre_login, 'scanners', [])),
            "post_login": len(getattr(self.post_login, 'scanners', [])),
            "total": len(getattr(self.pre_login, 'scanners', [])) + 
                     len(getattr(self.post_login, 'scanners', []))
        }
    
    def get_available_attacks(self) -> List[str]:
        """Get list of available attack categories"""
        return [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Server-Side Request Forgery (SSRF)",
            "Cross-Site Request Forgery (CSRF)",
            "Insecure Direct Object Reference (IDOR)",
            "Security Misconfiguration",
            "Broken Authentication",
            "Sensitive Data Exposure",
            "XML External Entity (XXE)",
            "Broken Access Control",
            "Open Redirect",
            "Host Header Injection",
            "HTTP Parameter Pollution",
            "Template Injection (SSTI)",
            "JWT Attacks",
            "GraphQL Vulnerabilities",
            "WebSocket Security",
            "CORS Misconfiguration",
            "Clickjacking",
            "HTTP Smuggling",
            "Race Conditions",
            "Business Logic Flaws",
            "File Upload Vulnerabilities",
            "Path Traversal",
            "Command Injection",
            "LDAP Injection",
            "Prototype Pollution",
            "Deserialization Attacks",
        ]


__all__ = ['WebAttacks', 'PreLoginAttacks', 'PostLoginAttacks']
