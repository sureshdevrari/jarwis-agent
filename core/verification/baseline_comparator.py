"""
Baseline Comparator - Compares responses to detect real vulnerabilities

This module provides utilities for comparing baseline (normal) responses
with test responses to determine if a vulnerability is real or a false positive.

Key concepts:
- A baseline is the "normal" response (e.g., unauthenticated, original parameter)
- A test response is with the attack payload
- True vulnerability = meaningful difference between baseline and test

Use cases:
- Auth bypass: Compare authenticated vs unauthenticated response
- IDOR: Compare response with original ID vs manipulated ID  
- Access control: Compare normal user vs admin endpoint access
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from difflib import SequenceMatcher
import logging

logger = logging.getLogger(__name__)


@dataclass
class BaselineResult:
    """Result of baseline comparison"""
    is_different: bool
    similarity_ratio: float
    content_changed: bool
    status_changed: bool
    length_difference: int
    new_sensitive_data: List[str] = field(default_factory=list)
    confidence: float = 0.0
    reasoning: str = ""
    

class BaselineComparator:
    """
    Compares responses to detect real vulnerabilities vs false positives.
    
    Core principle: A vulnerability is real if the attack produces
    a MEANINGFUL difference from the baseline, not just ANY difference.
    """
    
    # Patterns that indicate sensitive data access
    SENSITIVE_DATA_PATTERNS = [
        r'"email"\s*:\s*"[^"]+@[^"]+"',  # Email in JSON
        r'"password"\s*:\s*"[^"]+"',      # Password hash/value in JSON
        r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}"',  # SSN
        r'"credit_card"\s*:\s*"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"',
        r'"phone"\s*:\s*"[\d\s\-\+\(\)]+"',
        r'"address"\s*:\s*"[^"]+"',
        r'"api[_-]?key"\s*:\s*"[^"]+"',
        r'"secret"\s*:\s*"[^"]+"',
        r'"token"\s*:\s*"[^"]+"',
        r'"private[_-]?key"\s*:\s*"[^"]+"',
        r'BEGIN\s+(RSA\s+)?PRIVATE\s+KEY',
        r'-----BEGIN.*PRIVATE.*KEY-----',
    ]
    
    # Public endpoints that should NOT be flagged for auth bypass
    PUBLIC_ENDPOINT_PATTERNS = [
        r'/login',
        r'/signin', 
        r'/signup',
        r'/register',
        r'/forgot[-_]?password',
        r'/reset[-_]?password',
        r'/auth/.*',
        r'/oauth/.*',
        r'/public/.*',
        r'/static/.*',
        r'/assets/.*',
        r'/api/v\d+/health',
        r'/health',
        r'/ping',
        r'/status',
        r'\.css$',
        r'\.js$',
        r'\.png$',
        r'\.jpg$',
        r'\.gif$',
        r'\.ico$',
        r'\.svg$',
        r'\.woff',
    ]
    
    # Indicators of actual authenticated content (not just a page)
    AUTHENTICATED_CONTENT_INDICATORS = [
        r'"user_?id"\s*:\s*["\d]',
        r'"account_?id"\s*:\s*["\d]',
        r'"profile"\s*:\s*\{',
        r'"balance"\s*:\s*[\d"]',
        r'"transactions"\s*:\s*\[',
        r'"orders"\s*:\s*\[',
        r'"permissions"\s*:\s*\[',
        r'"role"\s*:\s*"(admin|user|moderator)',
        r'class="user-?profile"',
        r'class="dashboard-?content"',
        r'data-user-?id=',
    ]
    
    # Generic content that appears on public pages (reduces false positives)
    PUBLIC_PAGE_INDICATORS = [
        r'<form[^>]*action="[^"]*login',
        r'<input[^>]*name="(username|email|password)"',
        r'<title>[^<]*(login|sign\s*in|welcome)[^<]*</title>',
        r'Please\s+(log\s*in|sign\s*in)',
        r'(Don\'t|Don.t)\s+have\s+an?\s+account',
        r'Create\s+an?\s+account',
        r'Forgot\s+(your\s+)?password',
    ]
    
    def __init__(self):
        self._compiled_sensitive = [re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_DATA_PATTERNS]
        self._compiled_public = [re.compile(p, re.IGNORECASE) for p in self.PUBLIC_ENDPOINT_PATTERNS]
        self._compiled_auth_content = [re.compile(p, re.IGNORECASE) for p in self.AUTHENTICATED_CONTENT_INDICATORS]
        self._compiled_public_page = [re.compile(p, re.IGNORECASE) for p in self.PUBLIC_PAGE_INDICATORS]
    
    def is_public_endpoint(self, url: str) -> bool:
        """Check if URL is a known public endpoint that shouldn't trigger auth bypass"""
        for pattern in self._compiled_public:
            if pattern.search(url):
                return True
        return False
    
    def has_public_page_indicators(self, body: str) -> bool:
        """Check if response body looks like a public login/register page"""
        if not body:
            return False
        body_lower = body.lower()[:5000]  # Check first 5KB
        matches = sum(1 for p in self._compiled_public_page if p.search(body_lower))
        return matches >= 2  # At least 2 indicators = likely public page
    
    def has_authenticated_content(self, body: str) -> bool:
        """Check if response contains actual authenticated/private data"""
        if not body:
            return False
        for pattern in self._compiled_auth_content:
            if pattern.search(body):
                return True
        return False
    
    def extract_sensitive_data(self, body: str) -> List[str]:
        """Extract patterns of sensitive data found in response"""
        found = []
        for pattern in self._compiled_sensitive:
            matches = pattern.findall(body)
            if matches:
                # Redact actual values, just note the pattern
                found.append(pattern.pattern[:50])
        return found
    
    def compare_responses(
        self,
        baseline_status: int,
        baseline_body: str,
        baseline_headers: Dict[str, str],
        test_status: int,
        test_body: str,
        test_headers: Dict[str, str],
        attack_type: str = "generic"
    ) -> BaselineResult:
        """
        Compare baseline response with test response.
        
        Args:
            baseline_*: The "normal" response (unauthenticated, original params)
            test_*: The response after applying attack payload
            attack_type: Type of attack for context-specific analysis
            
        Returns:
            BaselineResult with analysis of whether this is a real vulnerability
        """
        # Basic checks
        status_changed = baseline_status != test_status
        length_diff = len(test_body) - len(baseline_body) if baseline_body and test_body else 0
        
        # Calculate similarity
        if baseline_body and test_body:
            # Use hash for quick comparison first
            baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()
            test_hash = hashlib.md5(test_body.encode()).hexdigest()
            
            if baseline_hash == test_hash:
                similarity = 1.0
            else:
                # For large bodies, sample for performance
                b_sample = baseline_body[:10000]
                t_sample = test_body[:10000]
                similarity = SequenceMatcher(None, b_sample, t_sample).ratio()
        else:
            similarity = 0.0 if baseline_body != test_body else 1.0
        
        content_changed = similarity < 0.95
        
        # Check for new sensitive data in test response
        baseline_sensitive = set(self.extract_sensitive_data(baseline_body or ""))
        test_sensitive = set(self.extract_sensitive_data(test_body or ""))
        new_sensitive = list(test_sensitive - baseline_sensitive)
        
        # Determine if this is a real vulnerability
        is_vulnerable, confidence, reasoning = self._analyze_for_attack_type(
            attack_type=attack_type,
            baseline_status=baseline_status,
            test_status=test_status,
            baseline_body=baseline_body,
            test_body=test_body,
            similarity=similarity,
            new_sensitive=new_sensitive,
            length_diff=length_diff
        )
        
        return BaselineResult(
            is_different=content_changed or status_changed,
            similarity_ratio=similarity,
            content_changed=content_changed,
            status_changed=status_changed,
            length_difference=length_diff,
            new_sensitive_data=new_sensitive,
            confidence=confidence,
            reasoning=reasoning
        )
    
    def _analyze_for_attack_type(
        self,
        attack_type: str,
        baseline_status: int,
        test_status: int,
        baseline_body: str,
        test_body: str,
        similarity: float,
        new_sensitive: List[str],
        length_diff: int
    ) -> Tuple[bool, float, str]:
        """Analyze results based on specific attack type"""
        
        if attack_type in ["auth_bypass", "authentication_bypass"]:
            return self._analyze_auth_bypass(
                baseline_status, test_status, baseline_body, test_body, 
                similarity, new_sensitive
            )
        
        elif attack_type in ["idor", "bola"]:
            return self._analyze_idor(
                baseline_status, test_status, baseline_body, test_body,
                similarity, new_sensitive, length_diff
            )
        
        elif attack_type == "bfla":
            return self._analyze_bfla(
                baseline_status, test_status, baseline_body, test_body,
                new_sensitive
            )
        
        else:
            # Generic analysis
            return self._analyze_generic(
                baseline_status, test_status, similarity, new_sensitive
            )
    
    def _analyze_auth_bypass(
        self,
        baseline_status: int,
        test_status: int,
        baseline_body: str,
        test_body: str,
        similarity: float,
        new_sensitive: List[str]
    ) -> Tuple[bool, float, str]:
        """
        Analyze auth bypass - requires:
        1. Baseline should be 401/403 (or redirect to login)
        2. Test response should be 200 with ACTUAL protected content
        3. NOT just a public page that happens to return 200
        """
        
        # If baseline was already 200, this isn't a bypass - it's public
        if baseline_status == 200:
            return False, 0.0, "Baseline already returned 200 - endpoint is public, not a bypass"
        
        # If test is not 200, no bypass
        if test_status != 200:
            return False, 0.0, f"Test returned {test_status}, not 200 - no bypass"
        
        # Check if test response looks like a login page (false positive!)
        if self.has_public_page_indicators(test_body):
            return False, 0.0, "Response contains login form - this is the login page, not a bypass"
        
        # Check for actual authenticated content
        if self.has_authenticated_content(test_body):
            confidence = 0.85
            if new_sensitive:
                confidence = 0.95
            return True, confidence, f"Test shows authenticated content not in baseline. New data patterns: {new_sensitive}"
        
        # If responses are very similar, probably just different rendering
        if similarity > 0.9:
            return False, 0.0, f"Responses are {similarity:.0%} similar - likely same content"
        
        # Got 200 but no clear authenticated content - low confidence
        return False, 0.3, "Got 200 but no clear authenticated/sensitive content detected - likely false positive"
    
    def _analyze_idor(
        self,
        baseline_status: int,
        test_status: int,
        baseline_body: str,
        test_body: str,
        similarity: float,
        new_sensitive: List[str],
        length_diff: int
    ) -> Tuple[bool, float, str]:
        """
        Analyze IDOR - requires:
        1. Both requests return 200 (original ID and manipulated ID)
        2. Response content is DIFFERENT (different user's data)
        3. Contains actual data, not error messages
        """
        
        # If test returned 403/404, the access control is working
        if test_status in [403, 404, 401]:
            return False, 0.0, f"Access control working - returned {test_status} for unauthorized ID"
        
        # If test didn't return 200, probably not vulnerable
        if test_status != 200:
            return False, 0.0, f"Test returned {test_status} - not clear IDOR"
        
        # If responses are identical, we got the SAME data (might be cached or default)
        if similarity > 0.98:
            return False, 0.0, "Responses are nearly identical - got same data, not different user's data"
        
        # If responses are too similar, might be error pages or default response
        if similarity > 0.85:
            return False, 0.2, f"Responses are {similarity:.0%} similar - possibly default response"
        
        # Different content - check if it's meaningful
        if new_sensitive:
            return True, 0.9, f"Got different data with new sensitive patterns: {new_sensitive}"
        
        # Significant content difference without clear sensitive data
        if abs(length_diff) > 100 and similarity < 0.7:
            return True, 0.7, f"Significant content difference ({length_diff} bytes, {similarity:.0%} similar)"
        
        return False, 0.4, "Some difference but no clear evidence of unauthorized data access"
    
    def _analyze_bfla(
        self,
        baseline_status: int,
        test_status: int,
        baseline_body: str,
        test_body: str,
        new_sensitive: List[str]
    ) -> Tuple[bool, float, str]:
        """
        Analyze BFLA (Broken Function Level Authorization) - requires:
        1. Regular user accessing admin endpoint
        2. Getting actual admin functionality, not just a page
        """
        
        # If we get 401/403, authorization is working
        if test_status in [401, 403]:
            return False, 0.0, f"Authorization working - returned {test_status}"
        
        # If redirected, likely to login
        if test_status in [302, 301, 307]:
            return False, 0.0, "Redirected - likely requires authentication"
        
        if test_status != 200:
            return False, 0.0, f"Status {test_status} - not clear vulnerability"
        
        # Check for login page in response
        if self.has_public_page_indicators(test_body):
            return False, 0.0, "Response is a login page - not an admin bypass"
        
        # Check for actual admin content
        admin_patterns = [
            r'class="admin',
            r'id="admin',
            r'"users"\s*:\s*\[',
            r'"admin_?panel"',
            r'"system_?settings"',
            r'<title>[^<]*admin[^<]*</title>',
        ]
        
        admin_content_found = any(
            re.search(p, test_body, re.IGNORECASE) for p in admin_patterns
        )
        
        if admin_content_found:
            return True, 0.85, "Admin panel content detected in response"
        
        if new_sensitive:
            return True, 0.75, f"Sensitive data exposed: {new_sensitive}"
        
        return False, 0.3, "Got 200 but no clear admin functionality detected"
    
    def _analyze_generic(
        self,
        baseline_status: int,
        test_status: int,
        similarity: float,
        new_sensitive: List[str]
    ) -> Tuple[bool, float, str]:
        """Generic analysis when attack type is unknown"""
        
        if test_status != 200:
            return False, 0.0, f"Non-200 status: {test_status}"
        
        if new_sensitive:
            return True, 0.7, f"New sensitive data patterns found: {new_sensitive}"
        
        if similarity < 0.5 and baseline_status != test_status:
            return True, 0.5, "Significant response difference"
        
        return False, 0.2, "No clear vulnerability indicators"
    
    def verify_auth_bypass_for_url(
        self,
        url: str,
        status: int,
        body: str,
        original_status: int = None,
        original_body: str = None
    ) -> Tuple[bool, float, str]:
        """
        Simplified check for auth bypass - designed to prevent false positives.
        
        Returns: (is_vulnerable, confidence, reason)
        """
        # Check if this is a public endpoint
        if self.is_public_endpoint(url):
            return False, 0.0, f"Public endpoint pattern detected in URL: {url}"
        
        # Check if response looks like a login/public page
        if self.has_public_page_indicators(body):
            return False, 0.0, "Response contains login/registration form"
        
        # If we have original response to compare
        if original_status is not None and original_body is not None:
            result = self.compare_responses(
                baseline_status=original_status,
                baseline_body=original_body,
                baseline_headers={},
                test_status=status,
                test_body=body,
                test_headers={},
                attack_type="auth_bypass"
            )
            return result.is_different and result.confidence > 0.5, result.confidence, result.reasoning
        
        # No baseline to compare - need authenticated content
        if status == 200 and self.has_authenticated_content(body):
            return True, 0.7, "Contains authenticated content indicators"
        
        # Just 200 status is NOT enough
        return False, 0.0, "Status 200 alone is not sufficient evidence of auth bypass"
