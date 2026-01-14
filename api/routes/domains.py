"""
Domain Verification Routes - TXT Record Verification for Credential-based Scans
Protects against unauthorized testing by requiring domain ownership proof

Uses database-backed DomainVerificationService for persistence.
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.dependencies import get_current_user
from database.models import User
from services.domain_verification_service import DomainVerificationService

router = APIRouter(prefix="/api/domains", tags=["domains"])


class DomainVerificationRequest(BaseModel):
    domain: str
    method: str = "txt"  # txt or html


class DomainGenerateRequest(BaseModel):
    domain: str


class DomainStatusResponse(BaseModel):
    domain: str
    verified: bool
    verification_code: Optional[str] = None
    verified_at: Optional[str] = None


class VerificationCheckResponse(BaseModel):
    domain: str
    verified: bool
    error: Optional[str] = None


def normalize_domain(domain: str) -> str:
    """Normalize domain by removing protocol and trailing slashes"""
    domain = domain.lower().strip()
    for prefix in ["https://", "http://", "www."]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/").split("/")[0]


def generate_verification_code(domain: str, user_id: int) -> str:
    """Generate a unique verification code for domain"""
    random_part = secrets.token_hex(8)
    hash_input = f"{domain}:{user_id}:{random_part}"
    code_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    return f"jarwis-verify-{code_hash}"


@router.get("/has-verified")
async def has_verified_domains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if user has any verified domains or a corporate email.
    Used to determine if personal email users can access the dashboard.
    
    Returns:
        - has_domains: True if user has at least one verified domain
        - is_personal_email: True if user has a personal email provider
        - can_scan: True if user can start scans (has verified domain OR corporate email)
    """
    from shared.constants import is_personal_email as check_personal
    
    service = DomainVerificationService(db)
    
    user_has_personal_email = check_personal(current_user.email)
    has_verified = await service.has_any_verified_domain(current_user.id)
    
    # Corporate email users can always scan their own domain
    # Personal email users need at least one verified domain
    can_scan = not user_has_personal_email or has_verified
    
    return {
        "has_domains": has_verified,
        "is_personal_email": user_has_personal_email,
        "can_scan": can_scan,
        "user_email": current_user.email,
        "user_email_domain": current_user.email.split('@')[1] if '@' in current_user.email else None
    }


@router.get("/verify/status", response_model=DomainStatusResponse)
async def get_verification_status(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get verification status for a domain (database-backed)"""
    service = DomainVerificationService(db)
    normalized = service.normalize_domain(domain)
    
    # First check if user has corporate email authorization
    is_authorized, reason = await service.is_authorized_to_scan(
        current_user.id, 
        current_user.email, 
        domain
    )
    
    if is_authorized and reason in ("corporate_email_match", "corporate_subdomain_match"):
        return DomainStatusResponse(
            domain=normalized,
            verified=True,
            verified_at=None  # Auto-verified via email
        )
    
    # Get verification status from database
    status = await service.get_verification_status(current_user.id, domain)
    
    return DomainStatusResponse(
        domain=normalized,
        verified=status.get("verified", False),
        verification_code=status.get("verification_code"),
        verified_at=status.get("verified_at")
    )


@router.post("/verify/generate")
async def generate_verification_code_endpoint(
    request: DomainGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate a verification code for a domain (database-backed)"""
    service = DomainVerificationService(db)
    
    # Check if user has corporate email authorization (no need to verify)
    is_authorized, reason = await service.is_authorized_to_scan(
        current_user.id, 
        current_user.email, 
        request.domain
    )
    
    if is_authorized and reason in ("corporate_email_match", "corporate_subdomain_match"):
        return {
            "domain": service.normalize_domain(request.domain),
            "already_verified": True,
            "message": f"Your email domain ({current_user.email.split('@')[1]}) matches the target domain. No DNS verification needed."
        }
    
    # Generate verification code using database-backed service
    result = await service.create_verification(current_user.id, request.domain)
    
    if result.get("verified"):
        return {
            "domain": result["domain"],
            "already_verified": True,
            "verified_at": result.get("verified_at")
        }
    
    return {
        "domain": result["domain"],
        "verification_code": result["verification_code"],
        "txt_record_host": "_jarwis-verify",
        "txt_record_value": result["verification_code"],
        "instructions": {
            "step1": f"Add a TXT record to your DNS for {result['domain']}",
            "step2": f"Host: _jarwis-verify.{result['domain']}",
            "step3": f"Value: {result['verification_code']}",
            "step4": "Wait for DNS propagation (can take up to 10 minutes)",
            "step5": "Return here and click 'Verify' to confirm"
        },
        "expires_in": f"{result.get('expires_in_hours', 24)} hours"
    }


@router.post("/verify/check-txt", response_model=VerificationCheckResponse)
async def check_txt_record(
    request: DomainGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Check if the TXT record is properly set up (database-backed)"""
    service = DomainVerificationService(db)
    normalized = service.normalize_domain(request.domain)
    
    # Use the database-backed service for TXT verification
    is_verified, error_message = await service.verify_txt_record(
        current_user.id, 
        request.domain
    )
    
    return VerificationCheckResponse(
        domain=normalized,
        verified=is_verified,
        error=error_message
    )


@router.post("/verify")
async def verify_domain(
    request: DomainVerificationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify domain ownership using specified method (database-backed)"""
    service = DomainVerificationService(db)
    normalized = service.normalize_domain(request.domain)
    
    if request.method == "txt":
        # Use the check-txt endpoint logic
        result = await check_txt_record(
            DomainGenerateRequest(domain=normalized),
            current_user,
            db
        )
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported verification method: {request.method}. Use 'txt'."
        )


@router.get("/verified")
async def list_verified_domains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all verified domains for the current user (database-backed)"""
    service = DomainVerificationService(db)
    
    # Get verified domains from database
    domains = await service.list_verified_domains(current_user.id)
    
    # Also include corporate email domain as "auto-verified"
    email_domain = service.extract_email_domain(current_user.email)
    if email_domain:
        # Check if email domain is already in list
        email_domain_exists = any(d["domain"] == email_domain for d in domains)
        if not email_domain_exists:
            domains.insert(0, {
                "domain": email_domain,
                "verified_at": None,
                "method": "corporate_email",
                "auto_verified": True
            })
    
    return {
        "domains": domains,
        "count": len(domains)
    }


@router.delete("/verified/{domain}")
async def remove_verified_domain(
    domain: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Remove a verified domain (requires re-verification for future scans)"""
    service = DomainVerificationService(db)
    normalized = service.normalize_domain(domain)
    
    # Don't allow removing corporate email domain
    email_domain = service.extract_email_domain(current_user.email)
    if email_domain and normalized == email_domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your corporate email domain. This is automatically verified."
        )
    
    success = await service.revoke_verification(current_user.id, domain)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain {domain} is not verified"
        )
    
    return {
        "success": True,
        "message": f"Domain {normalized} has been removed from verified domains"
    }


# Additional endpoint for scan authorization check
@router.get("/check-authorization")
async def check_scan_authorization(
    target_url: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if user is authorized to scan a target URL.
    Returns authorization status and reason.
    """
    # ========== DEVELOPER ACCOUNT BYPASS ==========
    from shared.constants import is_developer_account
    if is_developer_account(current_user.email):
        normalized = DomainVerificationService(db).normalize_domain(target_url)
        return {
            "target": normalized,
            "authorized": True,
            "reason": "Developer account - all domains authorized",
            "user_email": current_user.email
        }
    # ==============================================
    
    service = DomainVerificationService(db)
    
    is_authorized, reason = await service.is_authorized_to_scan(
        current_user.id,
        current_user.email,
        target_url
    )
    
    normalized = service.normalize_domain(target_url)
    
    response = {
        "target": normalized,
        "authorized": is_authorized,
        "reason": reason,
        "user_email": current_user.email
    }
    
    if not is_authorized:
        response["verification_url"] = f"/dashboard/verify-domain?domain={normalized}"
        response["message"] = f"Please verify ownership of {normalized} before scanning with credentials."
    
    return response