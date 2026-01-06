"""
JARWIS AGI PEN TEST - Domain Scope Manager
Enforces strict domain-only scanning - subdomains are treated as separate domains.
Each domain counts as a token for subscription purposes.
"""

import logging
from urllib.parse import urlparse
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class ScopeManager:
    """
    Manages domain scope for scanning operations.
    
    IMPORTANT: Subdomains are NOT automatically included!
    - If user enters example.com, only example.com is scanned
    - If user enters api.example.com, only api.example.com is scanned
    - www.example.com and example.com are treated as the SAME domain (www is stripped)
    
    Each distinct subdomain counts as a separate subscription token.
    """
    
    def __init__(self, target_url: str):
        """
        Initialize scope manager with target URL.
        
        Args:
            target_url: The target URL entered by user (e.g., https://example.com)
        """
        self.target_url = target_url
        self.target_domain = self._extract_domain(target_url)
        self.target_normalized = self._normalize_domain(self.target_domain)
        logger.info(f"Scope initialized: {self.target_normalized} (from {target_url})")
    
    @staticmethod
    def _extract_domain(url: str) -> str:
        """
        Extract domain (netloc) from URL.
        
        Args:
            url: Full URL or domain string
            
        Returns:
            Domain including port if present (e.g., 'example.com', 'localhost:3000')
        """
        if not url:
            return ""
        
        try:
            # Handle URLs that may not have scheme
            if '://' not in url:
                url = 'http://' + url
            
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception as e:
            logger.warning(f"Failed to extract domain from {url}: {e}")
            return ""
    
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """
        Normalize domain by stripping 'www.' prefix.
        www.example.com and example.com are treated as the same domain.
        
        Args:
            domain: Domain string
            
        Returns:
            Normalized domain without www prefix
        """
        if not domain:
            return ""
        
        domain = domain.lower().strip()
        
        # Strip www. prefix - www.example.com == example.com
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain
    
    @staticmethod
    def _extract_base_domain_for_comparison(domain: str) -> Tuple[str, str]:
        """
        Extract the domain and port separately for comparison.
        
        Args:
            domain: Domain string possibly with port
            
        Returns:
            Tuple of (domain_without_port, port)
        """
        if ':' in domain:
            parts = domain.rsplit(':', 1)
            return parts[0], parts[1]
        return domain, ''
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is within the target domain scope.
        
        STRICT MATCHING: Only the exact domain entered is in scope.
        Subdomains are NOT included unless user specifically enters them.
        
        Examples (if target is example.com):
            - https://example.com/page âœ" IN SCOPE
            - https://www.example.com/page âœ" IN SCOPE (www is stripped)
            - https://api.example.com/page âœ-- OUT OF SCOPE (different subdomain)
            - https://shop.example.com/page âœ-- OUT OF SCOPE (different subdomain)
            - https://other-site.com/page âœ-- OUT OF SCOPE (different domain)
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is within scope, False otherwise
        """
        if not url or not self.target_normalized:
            return False
        
        try:
            url_domain = self._extract_domain(url)
            url_normalized = self._normalize_domain(url_domain)
            
            if not url_normalized:
                return False
            
            # Handle ports - domains with different ports on localhost are same scope
            target_host, target_port = self._extract_base_domain_for_comparison(self.target_normalized)
            url_host, url_port = self._extract_base_domain_for_comparison(url_normalized)
            
            # For localhost, ignore port differences
            if target_host in ('localhost', '127.0.0.1'):
                return url_host in ('localhost', '127.0.0.1')
            
            # Strict domain match (ports must match for non-localhost)
            in_scope = url_normalized == self.target_normalized
            
            if not in_scope:
                logger.debug(f"URL out of scope: {url} (domain: {url_normalized}, target: {self.target_normalized})")
            
            return in_scope
            
        except Exception as e:
            logger.warning(f"Scope check failed for {url}: {e}")
            return False
    
    def is_same_domain(self, base_url: str, test_url: str) -> bool:
        """
        Check if two URLs are on the same domain.
        Uses strict matching - subdomains are different domains.
        
        Args:
            base_url: Base URL
            test_url: URL to compare
            
        Returns:
            True if both URLs are on the same normalized domain
        """
        try:
            base_domain = self._normalize_domain(self._extract_domain(base_url))
            test_domain = self._normalize_domain(self._extract_domain(test_url))
            
            if not base_domain or not test_domain:
                return False
            
            # Handle localhost specially
            base_host, _ = self._extract_base_domain_for_comparison(base_domain)
            test_host, _ = self._extract_base_domain_for_comparison(test_domain)
            
            if base_host in ('localhost', '127.0.0.1'):
                return test_host in ('localhost', '127.0.0.1')
            
            return base_domain == test_domain
            
        except Exception as e:
            logger.warning(f"Domain comparison failed: {e}")
            return False
    
    def get_domain_for_subscription(self) -> str:
        """
        Get the domain string for subscription token counting.
        
        Returns:
            Normalized domain string that represents the subscription token
        """
        return self.target_normalized


def is_in_scope(url: str, target_url: str) -> bool:
    """
    Convenience function to check if a URL is in scope of target.
    
    Args:
        url: URL to check
        target_url: Target URL defining the scope
        
    Returns:
        True if URL is in scope
    """
    manager = ScopeManager(target_url)
    return manager.is_in_scope(url)


def extract_domain(url: str) -> str:
    """
    Convenience function to extract normalized domain from URL.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Normalized domain string
    """
    return ScopeManager._normalize_domain(ScopeManager._extract_domain(url))
