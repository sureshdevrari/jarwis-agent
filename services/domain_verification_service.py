"""
Domain Verification Service (Database-backed)

Handles domain ownership verification for credential-based scans.
Supports:
1. DNS TXT record verification
2. Corporate email domain auto-verification

Corporate Email Rule:
- User with email user@company.com can scan company.com and subdomains
- No DNS TXT verification needed for matching email domain

Personal Email Rule:
- Users with personal emails (gmail, yahoo, etc.) must verify ALL domains
- They cannot scan any domain without DNS TXT verification
"""

import secrets
import hashlib
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Import personal email checker from shared constants
from shared.constants import FREE_EMAIL_PROVIDERS, is_personal_email
    
logger = logging.getLogger(__name__)


class DomainVerificationService:
    """
    Database-backed domain verification service.
    
    Handles:
    - TXT record verification for proving domain ownership
    - Corporate email auto-verification
    - Subdomain authorization checks
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain by removing protocol and trailing slashes"""
        domain = domain.lower().strip()
        for prefix in ["https://", "http://", "www."]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.rstrip("/").split("/")[0]
    
    @staticmethod
    def get_root_domain(domain: str) -> str:
        """Extract root domain (e.g., api.jarwis.ai -> jarwis.ai)"""
        normalized = DomainVerificationService.normalize_domain(domain)
        parts = normalized.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return normalized
    
    @staticmethod
    def extract_email_domain(email: str) -> Optional[str]:
        """Extract domain from email address"""
        if '@' in email:
            return email.split('@')[1].lower()
        return None
    
    async def is_authorized_to_scan(
        self, 
        user_id: uuid.UUID, 
        user_email: str,
        target_domain: str,
        require_verification_for_personal: bool = True
    ) -> Tuple[bool, str]:
        """
        Check if user is authorized to scan a domain.
        
        Authorization logic:
        - Personal email users (gmail, yahoo, etc.): MUST have DNS TXT verification
        - Corporate email users: Can scan their own domain + verified domains
        
        Args:
            user_id: The user's ID
            user_email: The user's email address
            target_domain: The domain to scan
            require_verification_for_personal: If True, personal emails always need verification
            
        Returns:
            Tuple of (is_authorized, reason)
        """
        normalized_target = self.normalize_domain(target_domain)
        target_root = self.get_root_domain(target_domain)
        user_has_personal_email = is_personal_email(user_email)
        
        # Personal email users MUST have explicit domain verification
        if user_has_personal_email and require_verification_for_personal:
            # Check 1: Explicit domain verification only
            is_verified = await self.is_domain_verified(user_id, target_domain)
            if is_verified:
                return True, "dns_txt_verified"
            
            # Check 2: Check if root domain is verified (allows subdomains)
            if target_root != normalized_target:
                is_root_verified = await self.is_domain_verified(user_id, target_root)
                if is_root_verified:
                    return True, "root_domain_verified"
            
            return False, "personal_email_requires_verification"
        
        # Corporate email users get auto-verification for their domain
        email_domain = self.extract_email_domain(user_email)
        if email_domain:
            email_root = self.get_root_domain(email_domain)
            
            # Direct match or subdomain match
            if target_root == email_root:
                logger.info(f"Corporate email authorization: {user_email} -> {target_domain}")
                return True, "corporate_email_match"
            
            # Check if target is subdomain of email domain
            if normalized_target.endswith(f".{email_root}"):
                logger.info(f"Corporate subdomain authorization: {user_email} -> {target_domain}")
                return True, "corporate_subdomain_match"
        
        # Check 3: Explicit domain verification for other domains
        is_verified = await self.is_domain_verified(user_id, target_domain)
        if is_verified:
            return True, "dns_txt_verified"
        
        # Check 4: Check if root domain is verified (allows subdomains)
        if target_root != normalized_target:
            is_root_verified = await self.is_domain_verified(user_id, target_root)
            if is_root_verified:
                return True, "root_domain_verified"
        
        return False, "not_authorized"
    
    async def has_any_verified_domain(self, user_id: uuid.UUID) -> bool:
        """Check if user has at least one verified domain"""
        from database.models import VerifiedDomain
        
        result = await self.db.execute(
            select(VerifiedDomain).where(
                and_(
                    VerifiedDomain.user_id == user_id,
                    VerifiedDomain.is_verified == True
                )
            ).limit(1)
        )
        return result.scalar_one_or_none() is not None
    
    async def is_domain_verified(self, user_id: uuid.UUID, domain: str) -> bool:
        """Check if domain is verified for user"""
        from database.models import VerifiedDomain
        
        normalized = self.normalize_domain(domain)
        
        result = await self.db.execute(
            select(VerifiedDomain).where(
                and_(
                    VerifiedDomain.user_id == user_id,
                    VerifiedDomain.normalized_domain == normalized,
                    VerifiedDomain.is_verified == True
                )
            )
        )
        return result.scalar_one_or_none() is not None
    
    async def create_verification(
        self, 
        user_id: uuid.UUID, 
        domain: str
    ) -> Dict[str, Any]:
        """Create a new verification request for a domain"""
        from database.models import VerifiedDomain
        
        normalized = self.normalize_domain(domain)
        
        # Check if already verified
        result = await self.db.execute(
            select(VerifiedDomain).where(
                and_(
                    VerifiedDomain.user_id == user_id,
                    VerifiedDomain.normalized_domain == normalized
                )
            )
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            if existing.is_verified:
                return {
                    "domain": normalized,
                    "verified": True,
                    "verified_at": existing.verified_at.isoformat() if existing.verified_at else None,
                    "message": "Domain already verified"
                }
            else:
                # Return existing code if not expired
                if existing.created_at and datetime.utcnow() - existing.created_at < timedelta(hours=24):
                    return {
                        "domain": normalized,
                        "verification_code": existing.verification_code,
                        "txt_record": f"_jarwis-verify.{normalized}",
                        "instructions": self._get_instructions(normalized, existing.verification_code),
                        "expires_in_hours": 24 - int((datetime.utcnow() - existing.created_at).total_seconds() / 3600)
                    }
                else:
                    # Regenerate expired code
                    existing.verification_code = self._generate_code(normalized, user_id)
                    existing.created_at = datetime.utcnow()
                    await self.db.commit()
                    return {
                        "domain": normalized,
                        "verification_code": existing.verification_code,
                        "txt_record": f"_jarwis-verify.{normalized}",
                        "instructions": self._get_instructions(normalized, existing.verification_code),
                        "expires_in_hours": 24
                    }
        
        # Create new verification record
        code = self._generate_code(normalized, user_id)
        verification = VerifiedDomain(
            user_id=user_id,
            domain=domain,
            normalized_domain=normalized,
            verification_code=code,
            verification_method="txt",
            is_verified=False,
            created_at=datetime.utcnow()
        )
        
        self.db.add(verification)
        await self.db.commit()
        
        return {
            "domain": normalized,
            "verification_code": code,
            "txt_record": f"_jarwis-verify.{normalized}",
            "instructions": self._get_instructions(normalized, code),
            "expires_in_hours": 24
        }
    
    def _generate_code(self, domain: str, user_id: uuid.UUID) -> str:
        """Generate a unique verification code"""
        random_part = secrets.token_hex(8)
        hash_input = f"{domain}:{user_id}:{random_part}"
        code_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        return f"jarwis-verify-{code_hash}"
    
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
    
    async def verify_txt_record(
        self, 
        user_id: uuid.UUID, 
        domain: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if TXT record is properly configured and verify.
        
        Returns:
            Tuple of (is_verified, error_message)
        """
        from database.models import VerifiedDomain
        
        if not DNS_AVAILABLE:
            logger.warning("dnspython not installed, skipping DNS verification")
            return False, "DNS verification not available. Install dnspython."
        
        normalized = self.normalize_domain(domain)
        
        # Get verification record
        result = await self.db.execute(
            select(VerifiedDomain).where(
                and_(
                    VerifiedDomain.user_id == user_id,
                    VerifiedDomain.normalized_domain == normalized
                )
            )
        )
        record = result.scalar_one_or_none()
        
        if not record:
            return False, "No verification code generated. Generate a code first."
        
        if record.is_verified:
            return True, None
        
        expected_code = record.verification_code
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
                    record.is_verified = True
                    record.verified_at = datetime.utcnow()
                    await self.db.commit()
                    
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
    
    async def get_verification_status(
        self, 
        user_id: uuid.UUID, 
        domain: str
    ) -> Dict[str, Any]:
        """Get current verification status for a domain"""
        from database.models import VerifiedDomain
        
        normalized = self.normalize_domain(domain)
        
        result = await self.db.execute(
            select(VerifiedDomain).where(
                and_(
                    VerifiedDomain.user_id == user_id,
                    VerifiedDomain.normalized_domain == normalized
                )
            )
        )
        record = result.scalar_one_or_none()
        
        if not record:
            return {
                "domain": normalized,
                "verified": False
            }
        
        if record.is_verified:
            return {
                "domain": normalized,
                "verified": True,
                "verified_at": record.verified_at.isoformat() if record.verified_at else None,
                "method": record.verification_method
            }
        
        return {
            "domain": normalized,
            "verified": False,
            "verification_code": record.verification_code
        }
    
    async def list_verified_domains(self, user_id: uuid.UUID) -> List[Dict[str, Any]]:
        """List all verified domains for a user"""
        from database.models import VerifiedDomain
        
        result = await self.db.execute(
            select(VerifiedDomain).where(
                and_(
                    VerifiedDomain.user_id == user_id,
                    VerifiedDomain.is_verified == True
                )
            )
        )
        records = result.scalars().all()
        
        return [
            {
                "domain": r.domain,
                "verified_at": r.verified_at.isoformat() if r.verified_at else None,
                "method": r.verification_method
            }
            for r in records
        ]
    
    async def revoke_verification(
        self, 
        user_id: uuid.UUID, 
        domain: str
    ) -> bool:
        """Revoke domain verification"""
        from database.models import VerifiedDomain
        
        normalized = self.normalize_domain(domain)
        
        result = await self.db.execute(
            select(VerifiedDomain).where(
                and_(
                    VerifiedDomain.user_id == user_id,
                    VerifiedDomain.normalized_domain == normalized
                )
            )
        )
        record = result.scalar_one_or_none()
        
        if record:
            await self.db.delete(record)
            await self.db.commit()
            logger.info(f"Revoked verification for {normalized} (user {user_id})")
            return True
        
        return False


# Legacy sync service for backward compatibility
class DomainService:
    """Legacy in-memory service (for backward compatibility)"""
    
    def __init__(self):
        self._verification_codes: Dict[str, Dict[str, Any]] = {}
        self._verified_domains: Dict[str, Dict[str, Any]] = {}
    
    def normalize_domain(self, domain: str) -> str:
        return DomainVerificationService.normalize_domain(domain)
    
    def is_domain_verified(self, domain: str, user_id: int) -> bool:
        normalized = self.normalize_domain(domain)
        user_key = f"{user_id}:{normalized}"
        return user_key in self._verified_domains


# Global singleton for legacy code
domain_service = DomainService()
