"""
Domain Verification Routes - TXT Record Verification for Credential-based Scans
Protects against unauthorized testing by requiring domain ownership proof
"""

import secrets
import hashlib
import dns.resolver
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.dependencies import get_current_user
from database.models import User

router = APIRouter(prefix="/api/domains", tags=["domains"])

# In-memory store for verification codes (in production, use database)
verification_codes = {}
verified_domains = {}


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


@router.get("/verify/status", response_model=DomainStatusResponse)
async def get_verification_status(
    domain: str,
    current_user: User = Depends(get_current_user)
):
    """Get verification status for a domain"""
    normalized = normalize_domain(domain)
    user_key = f"{current_user.id}:{normalized}"
    
    if user_key in verified_domains:
        info = verified_domains[user_key]
        return DomainStatusResponse(
            domain=normalized,
            verified=True,
            verified_at=info.get("verified_at")
        )
    
    # Check if there's a pending verification code
    if user_key in verification_codes:
        code_info = verification_codes[user_key]
        return DomainStatusResponse(
            domain=normalized,
            verified=False,
            verification_code=code_info.get("code")
        )
    
    return DomainStatusResponse(
        domain=normalized,
        verified=False
    )


@router.post("/verify/generate")
async def generate_verification_code_endpoint(
    request: DomainGenerateRequest,
    current_user: User = Depends(get_current_user)
):
    """Generate a verification code for a domain"""
    normalized = normalize_domain(request.domain)
    user_key = f"{current_user.id}:{normalized}"
    
    # Check if already verified
    if user_key in verified_domains:
        return {
            "domain": normalized,
            "already_verified": True,
            "verified_at": verified_domains[user_key].get("verified_at")
        }
    
    # Generate new code
    code = generate_verification_code(normalized, current_user.id)
    
    verification_codes[user_key] = {
        "code": code,
        "domain": normalized,
        "user_id": current_user.id,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat()
    }
    
    return {
        "domain": normalized,
        "verification_code": code,
        "txt_record_host": "_jarwis-verification",
        "txt_record_value": code,
        "instructions": {
            "step1": f"Add a TXT record to your DNS for {normalized}",
            "step2": f"Host: _jarwis-verification.{normalized}",
            "step3": f"Value: {code}",
            "step4": "Wait for DNS propagation (can take up to 10 minutes)",
            "step5": "Return here and click 'Verify' to confirm"
        },
        "expires_in": "24 hours"
    }


@router.post("/verify/check-txt", response_model=VerificationCheckResponse)
async def check_txt_record(
    request: DomainGenerateRequest,
    current_user: User = Depends(get_current_user)
):
    """Check if the TXT record is properly set up"""
    normalized = normalize_domain(request.domain)
    user_key = f"{current_user.id}:{normalized}"
    
    # Get the expected verification code
    if user_key not in verification_codes:
        return VerificationCheckResponse(
            domain=normalized,
            verified=False,
            error="No verification code found. Please generate one first."
        )
    
    expected_code = verification_codes[user_key]["code"]
    
    try:
        # Query DNS for TXT records
        txt_host = f"_jarwis-verification.{normalized}"
        answers = dns.resolver.resolve(txt_host, 'TXT')
        
        for rdata in answers:
            txt_value = str(rdata).strip('"')
            if txt_value == expected_code:
                # Mark as verified
                verified_domains[user_key] = {
                    "domain": normalized,
                    "user_id": current_user.id,
                    "verified_at": datetime.utcnow().isoformat(),
                    "method": "txt"
                }
                
                # Clean up verification code
                del verification_codes[user_key]
                
                return VerificationCheckResponse(
                    domain=normalized,
                    verified=True
                )
        
        return VerificationCheckResponse(
            domain=normalized,
            verified=False,
            error=f"TXT record found but value doesn't match. Expected: {expected_code}"
        )
        
    except dns.resolver.NXDOMAIN:
        return VerificationCheckResponse(
            domain=normalized,
            verified=False,
            error=f"TXT record not found at _jarwis-verification.{normalized}. Please add the DNS record."
        )
    except dns.resolver.NoAnswer:
        return VerificationCheckResponse(
            domain=normalized,
            verified=False,
            error="No TXT records found. Please add the DNS record and wait for propagation."
        )
    except dns.resolver.Timeout:
        return VerificationCheckResponse(
            domain=normalized,
            verified=False,
            error="DNS query timed out. Please try again in a few minutes."
        )
    except Exception as e:
        return VerificationCheckResponse(
            domain=normalized,
            verified=False,
            error=f"DNS lookup failed: {str(e)}"
        )


@router.post("/verify")
async def verify_domain(
    request: DomainVerificationRequest,
    current_user: User = Depends(get_current_user)
):
    """Verify domain ownership using specified method"""
    normalized = normalize_domain(request.domain)
    
    if request.method == "txt":
        # Use the check-txt endpoint logic
        result = await check_txt_record(
            DomainGenerateRequest(domain=normalized),
            current_user
        )
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported verification method: {request.method}. Use 'txt'."
        )


@router.get("/verified")
async def list_verified_domains(
    current_user: User = Depends(get_current_user)
):
    """List all verified domains for the current user"""
    user_domains = []
    
    for key, info in verified_domains.items():
        if key.startswith(f"{current_user.id}:"):
            user_domains.append({
                "domain": info["domain"],
                "verified_at": info["verified_at"],
                "method": info.get("method", "txt")
            })
    
    return {
        "domains": user_domains,
        "count": len(user_domains)
    }


@router.delete("/verified/{domain}")
async def remove_verified_domain(
    domain: str,
    current_user: User = Depends(get_current_user)
):
    """Remove a verified domain (requires re-verification for future scans)"""
    normalized = normalize_domain(domain)
    user_key = f"{current_user.id}:{normalized}"
    
    if user_key not in verified_domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain {domain} is not verified"
        )
    
    del verified_domains[user_key]
    
    return {
        "success": True,
        "message": f"Domain {normalized} has been removed from verified domains"
    }
