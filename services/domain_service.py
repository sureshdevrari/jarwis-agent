"""
Domain Verification Service

Handles domain ownership verification for credential-based scans.
Extracted from api/routes/domains.py for better separation of concerns.
"""

import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    
logger = logging.getLogger(__name__)


class DomainService:
    """
    Domain verification service.
    
    Handles TXT record verification for proving domain ownership
    before allowing credential-based security scans.
    """
    
    def __init__(self):
        # In-memory stores (use Redis/DB in production)
        self._verification_codes: Dict[str, Dict[str, Any]] = {}
        self._verified_domains: Dict[str, Dict[str, Any]] = {}
    
    def _make_user_key(self, user_id: int, domain: str) -> str:
        """Create unique key for user+domain combination"""
        return f"{user_id}:{domain}"
    
    def normalize_domain(self, domain: str) -> str:
        """Normalize domain by removing protocol and trailing slashes"""
        domain = domain.lower().strip()
        for prefix in ["https://", "http://", "www."]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.rstrip("/").split("/")[0]
    
    def generate_verification_code(self, domain: str, user_id: int) -> str:
        """Generate a unique verification code for domain ownership"""
        random_part = secrets.token_hex(8)
        hash_input = f"{domain}:{user_id}:{random_part}"
        code_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        return f"jarwis-verify-{code_hash}"
    
    def create_verification(self, domain: str, user_id: int) -> Dict[str, Any]:
        """
        Create a new verification request for a domain.
        
        Returns:
            Dict with verification code and instructions
        """
        normalized = self.normalize_domain(domain)
        user_key = self._make_user_key(user_id, normalized)
        
        # Check if already verified
        if user_key in self._verified_domains:
            info = self._verified_domains[user_key]
            return {
                "domain": normalized,
                "verified": True,
                "verified_at": info.get("verified_at"),
                "message": "Domain already verified"
            }
        
        # Generate new code or return existing
        if user_key in self._verification_codes:
            existing = self._verification_codes[user_key]
            # Check if expired (24 hours)
            created = datetime.fromisoformat(existing["created_at"])
            if datetime.utcnow() - created < timedelta(hours=24):
                return {
                    "domain": normalized,
                    "verification_code": existing["code"],
                    "txt_record": f"_jarwis-verify.{normalized}",
                    "instructions": self._get_instructions(normalized, existing["code"]),
                    "expires_in_hours": 24 - int((datetime.utcnow() - created).total_seconds() / 3600)
                }
        
        # Generate new code
        code = self.generate_verification_code(normalized, user_id)
        self._verification_codes[user_key] = {
            "code": code,
            "domain": normalized,
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat()
        }
        
        return {
            "domain": normalized,
            "verification_code": code,
            "txt_record": f"_jarwis-verify.{normalized}",
            "instructions": self._get_instructions(normalized, code),
            "expires_in_hours": 24
        }
    
    def _get_instructions(self, domain: str, code: str) -> str:
        """Get TXT record setup instructions"""
        return f"""
To verify ownership of {domain}:

1. Log in to your DNS provider (e.g., Cloudflare, GoDaddy, Namecheap)
2. Add a new TXT record:
   - Name/Host: _jarwis-verify
   - Value: {code}
   - TTL: 300 (or lowest available)
3. Wait 5-10 minutes for DNS propagation
4. Click "Verify" in the Jarwis dashboard

Example DNS record:
_jarwis-verify.{domain}  TXT  "{code}"
"""
    
    def check_txt_record(self, domain: str, user_id: int) -> Tuple[bool, Optional[str]]:
        """
        Check if TXT record is properly configured.
        
        Returns:
            Tuple of (is_verified, error_message)
        """
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed, skipping DNS verification")
            return False, "DNS verification not available"
        
        normalized = self.normalize_domain(domain)
        user_key = self._make_user_key(user_id, normalized)
        
        # Get expected code
        if user_key not in self._verification_codes:
            return False, "No verification code generated. Generate a code first."
        
        expected_code = self._verification_codes[user_key]["code"]
        txt_name = f"_jarwis-verify.{normalized}"
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            
            answers = resolver.resolve(txt_name, "TXT")
            
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value == expected_code:
                    # Verification successful!
                    self._verified_domains[user_key] = {
                        "domain": normalized,
                        "user_id": user_id,
                        "verified_at": datetime.utcnow().isoformat(),
                        "method": "txt"
                    }
                    
                    # Clean up verification code
                    del self._verification_codes[user_key]
                    
                    logger.info(f"Domain {normalized} verified for user {user_id}")
                    return True, None
            
            return False, f"TXT record found but value doesn't match. Expected: {expected_code}"
            
        except dns.resolver.NXDOMAIN:
            return False, f"TXT record not found at {txt_name}. Please add the record and wait for DNS propagation."
        except dns.resolver.NoAnswer:
            return False, f"No TXT records found for {txt_name}"
        except dns.resolver.Timeout:
            return False, "DNS lookup timed out. Please try again."
        except Exception as e:
            logger.error(f"DNS verification error for {domain}: {e}")
            return False, f"DNS verification failed: {str(e)}"
    
    def get_verification_status(self, domain: str, user_id: int) -> Dict[str, Any]:
        """Get current verification status for a domain"""
        normalized = self.normalize_domain(domain)
        user_key = self._make_user_key(user_id, normalized)
        
        if user_key in self._verified_domains:
            info = self._verified_domains[user_key]
            return {
                "domain": normalized,
                "verified": True,
                "verified_at": info.get("verified_at")
            }
        
        if user_key in self._verification_codes:
            code_info = self._verification_codes[user_key]
            return {
                "domain": normalized,
                "verified": False,
                "verification_code": code_info.get("code")
            }
        
        return {
            "domain": normalized,
            "verified": False
        }
    
    def is_domain_verified(self, domain: str, user_id: int) -> bool:
        """Quick check if domain is verified for user"""
        normalized = self.normalize_domain(domain)
        user_key = self._make_user_key(user_id, normalized)
        return user_key in self._verified_domains
    
    def list_verified_domains(self, user_id: int) -> list:
        """List all verified domains for a user"""
        prefix = f"{user_id}:"
        domains = []
        
        for key, info in self._verified_domains.items():
            if key.startswith(prefix):
                domains.append({
                    "domain": info["domain"],
                    "verified_at": info["verified_at"]
                })
        
        return domains
    
    def revoke_verification(self, domain: str, user_id: int) -> bool:
        """Revoke domain verification"""
        normalized = self.normalize_domain(domain)
        user_key = self._make_user_key(user_id, normalized)
        
        if user_key in self._verified_domains:
            del self._verified_domains[user_key]
            logger.info(f"Revoked verification for {normalized} (user {user_id})")
            return True
        
        return False


# Global singleton instance
domain_service = DomainService()
