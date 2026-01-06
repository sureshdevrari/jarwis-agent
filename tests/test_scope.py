"""
Tests for domain scope manager
Ensures strict domain matching is enforced correctly
"""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scope import ScopeManager, is_in_scope, extract_domain


class TestScopeManager:
    """Test strict domain scope enforcement"""
    
    def test_extract_domain_basic(self):
        """Test basic domain extraction"""
        assert ScopeManager._extract_domain("https://example.com") == "example.com"
        assert ScopeManager._extract_domain("https://example.com/path") == "example.com"
        assert ScopeManager._extract_domain("http://example.com:8080") == "example.com:8080"
    
    def test_extract_domain_with_www(self):
        """Test domain extraction with www"""
        assert ScopeManager._extract_domain("https://www.example.com") == "www.example.com"
    
    def test_normalize_domain_strips_www(self):
        """Test that www prefix is stripped during normalization"""
        assert ScopeManager._normalize_domain("www.example.com") == "example.com"
        assert ScopeManager._normalize_domain("example.com") == "example.com"
        assert ScopeManager._normalize_domain("WWW.EXAMPLE.COM") == "example.com"
    
    def test_subdomain_not_stripped(self):
        """Test that subdomains other than www are NOT stripped"""
        assert ScopeManager._normalize_domain("api.example.com") == "api.example.com"
        assert ScopeManager._normalize_domain("shop.example.com") == "shop.example.com"
    
    def test_scope_same_domain_in_scope(self):
        """Test that same domain URLs are in scope"""
        scope = ScopeManager("https://example.com")
        
        assert scope.is_in_scope("https://example.com") == True
        assert scope.is_in_scope("https://example.com/") == True
        assert scope.is_in_scope("https://example.com/page") == True
        assert scope.is_in_scope("https://example.com/page?query=1") == True
        assert scope.is_in_scope("http://example.com/page") == True  # Different protocol OK
    
    def test_scope_www_equivalent(self):
        """Test that www.domain and domain are treated as equivalent"""
        scope = ScopeManager("https://example.com")
        assert scope.is_in_scope("https://www.example.com") == True
        assert scope.is_in_scope("https://www.example.com/page") == True
        
        # Also test the reverse
        scope2 = ScopeManager("https://www.example.com")
        assert scope2.is_in_scope("https://example.com") == True
        assert scope2.is_in_scope("https://example.com/page") == True
    
    def test_scope_subdomain_out_of_scope(self):
        """Test that subdomains are OUT of scope - CRITICAL for subscription tokens"""
        scope = ScopeManager("https://example.com")
        
        # All subdomains should be OUT of scope
        assert scope.is_in_scope("https://api.example.com") == False
        assert scope.is_in_scope("https://api.example.com/v1/users") == False
        assert scope.is_in_scope("https://shop.example.com") == False
        assert scope.is_in_scope("https://blog.example.com") == False
        assert scope.is_in_scope("https://admin.example.com") == False
        assert scope.is_in_scope("https://staging.example.com") == False
        assert scope.is_in_scope("https://dev.example.com") == False
    
    def test_scope_nested_subdomain_out_of_scope(self):
        """Test that nested subdomains are also out of scope"""
        scope = ScopeManager("https://example.com")
        
        assert scope.is_in_scope("https://api.v1.example.com") == False
        assert scope.is_in_scope("https://eu.api.example.com") == False
        assert scope.is_in_scope("https://dev.staging.example.com") == False
    
    def test_scope_different_domain_out_of_scope(self):
        """Test that different domains are out of scope"""
        scope = ScopeManager("https://example.com")
        
        assert scope.is_in_scope("https://example.org") == False
        assert scope.is_in_scope("https://other-site.com") == False
        assert scope.is_in_scope("https://notexample.com") == False
        assert scope.is_in_scope("https://example.com.evil.com") == False
    
    def test_scope_subdomain_target(self):
        """Test that if subdomain is the target, only that subdomain is in scope"""
        scope = ScopeManager("https://api.example.com")
        
        # The target subdomain is in scope
        assert scope.is_in_scope("https://api.example.com") == True
        assert scope.is_in_scope("https://api.example.com/v1/users") == True
        
        # Parent domain is OUT of scope
        assert scope.is_in_scope("https://example.com") == False
        
        # Other subdomains are OUT of scope
        assert scope.is_in_scope("https://shop.example.com") == False
        assert scope.is_in_scope("https://www.example.com") == False
    
    def test_scope_localhost(self):
        """Test localhost handling"""
        scope = ScopeManager("http://localhost:3000")
        
        # Same localhost is in scope regardless of port
        assert scope.is_in_scope("http://localhost:3000") == True
        assert scope.is_in_scope("http://localhost:8080") == True
        assert scope.is_in_scope("http://localhost") == True
        
        # 127.0.0.1 is also considered localhost
        assert scope.is_in_scope("http://127.0.0.1:3000") == True
        assert scope.is_in_scope("http://127.0.0.1") == True
    
    def test_scope_empty_invalid(self):
        """Test handling of empty/invalid URLs"""
        scope = ScopeManager("https://example.com")
        
        assert scope.is_in_scope("") == False
        assert scope.is_in_scope(None) == False
        assert scope.is_in_scope("not-a-url") == False
    
    def test_is_same_domain(self):
        """Test same domain comparison"""
        scope = ScopeManager("https://example.com")
        
        # Same domains
        assert scope.is_same_domain("https://example.com", "https://example.com/page") == True
        assert scope.is_same_domain("https://example.com", "http://example.com") == True
        assert scope.is_same_domain("https://www.example.com", "https://example.com") == True
        
        # Different domains
        assert scope.is_same_domain("https://example.com", "https://api.example.com") == False
        assert scope.is_same_domain("https://example.com", "https://other.com") == False
    
    def test_get_domain_for_subscription(self):
        """Test getting the normalized domain for subscription token counting"""
        scope = ScopeManager("https://www.example.com")
        assert scope.get_domain_for_subscription() == "example.com"
        
        scope2 = ScopeManager("https://api.example.com")
        assert scope2.get_domain_for_subscription() == "api.example.com"
        
        scope3 = ScopeManager("http://localhost:3000")
        assert scope3.get_domain_for_subscription() == "localhost:3000"
    
    def test_convenience_functions(self):
        """Test module-level convenience functions"""
        assert is_in_scope("https://example.com/page", "https://example.com") == True
        assert is_in_scope("https://api.example.com", "https://example.com") == False
        
        assert extract_domain("https://www.example.com") == "example.com"
        assert extract_domain("https://api.example.com") == "api.example.com"


class TestSubscriptionTokenCounting:
    """Test cases specifically for subscription token counting logic"""
    
    def test_each_subdomain_is_separate_token(self):
        """Each subdomain should count as a separate subscription token"""
        domains = [
            "https://example.com",
            "https://api.example.com",
            "https://shop.example.com",
            "https://blog.example.com",
        ]
        
        normalized = [ScopeManager(d).get_domain_for_subscription() for d in domains]
        
        # All should be unique (4 different subscription tokens)
        assert len(set(normalized)) == 4
        assert normalized == ["example.com", "api.example.com", "shop.example.com", "blog.example.com"]
    
    def test_www_is_not_separate_token(self):
        """www should NOT count as a separate token from the base domain"""
        scope1 = ScopeManager("https://example.com")
        scope2 = ScopeManager("https://www.example.com")
        
        # Should be the same subscription token
        assert scope1.get_domain_for_subscription() == scope2.get_domain_for_subscription()
    
    def test_user_entering_subdomain_gets_only_that(self):
        """If user enters api.example.com, they can only scan api.example.com"""
        scope = ScopeManager("https://api.example.com")
        
        # Can scan the entered subdomain
        assert scope.is_in_scope("https://api.example.com/users") == True
        
        # Cannot scan parent or other subdomains
        assert scope.is_in_scope("https://example.com/users") == False
        assert scope.is_in_scope("https://shop.example.com") == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
