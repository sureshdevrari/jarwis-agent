"""
Contact Form API Routes
Handles contact form submissions with reCAPTCHA verification
Uses database for persistent storage

Security Features:
- Input sanitization
- Rate limiting
- reCAPTCHA verification (when enabled)
"""

import os
import logging
from datetime import datetime
from typing import Optional, List
from uuid import uuid4

import httpx
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User, ContactSubmission
from database.dependencies import get_current_superuser
from database.security import InputValidator, get_client_ip, security_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Contact"])


# ============== Configuration ==============

RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "6LdKAT8sAAAAADBqqf5nnrwGYcfg7oIibPABz3pC")
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


# ============== Request/Response Models ==============

class ContactFormRequest(BaseModel):
    """Contact form submission request"""
    firstName: str
    lastName: Optional[str] = ""
    workEmail: EmailStr
    companyName: Optional[str] = ""
    companyWebsite: Optional[str] = ""
    plan: str
    captchaToken: Optional[str] = None  # reCAPTCHA response token


class ContactFormResponse(BaseModel):
    """Contact form submission response"""
    success: bool
    message: str
    submission_id: Optional[str] = None


# ============== Helper Functions ==============

async def verify_recaptcha(token: str) -> bool:
    """Verify reCAPTCHA token with Google"""
    if not token:
        logger.warning("No reCAPTCHA token provided")
        return False
    
    if not RECAPTCHA_SECRET_KEY:
        logger.warning("RECAPTCHA_SECRET_KEY not configured, skipping verification")
        return True  # Skip verification if not configured
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                RECAPTCHA_VERIFY_URL,
                data={
                    "secret": RECAPTCHA_SECRET_KEY,
                    "response": token
                }
            )
            result = response.json()
            
            if result.get("success"):
                logger.info("reCAPTCHA verification successful")
                return True
            else:
                logger.warning(f"reCAPTCHA verification failed: {result.get('error-codes', [])}")
                return False
                
    except Exception as e:
        logger.error(f"reCAPTCHA verification error: {e}")
        return False


# ============== Routes ==============

@router.post("/contact", response_model=ContactFormResponse)
async def submit_contact_form(
    data: ContactFormRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit a contact form.
    Verifies reCAPTCHA and stores the submission in database.
    
    Security:
    - Rate limiting
    - Input sanitization
    - reCAPTCHA verification (when enabled)
    """
    client_ip = get_client_ip(request)
    
    # Rate limit contact form submissions
    is_blocked, reason, remaining = await security_store.is_blocked(client_ip)
    if is_blocked:
        logger.warning(f"Blocked contact form submission from {client_ip}: {reason}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many submissions. Please try again in {remaining} seconds."
        )
    
    # Check for injection attempts in all fields
    for field_name, field_value in [
        ("firstName", data.firstName),
        ("lastName", data.lastName or ""),
        ("companyName", data.companyName or ""),
        ("companyWebsite", data.companyWebsite or ""),
    ]:
        if InputValidator.check_sql_injection(field_value):
            logger.warning(f"SQL injection attempt in contact form {field_name} from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid characters in {field_name}"
            )
        if InputValidator.check_xss(field_value):
            logger.warning(f"XSS attempt in contact form {field_name} from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid content in {field_name}"
            )
    
    # Verify reCAPTCHA - TEMPORARILY DISABLED
    # TODO: Re-enable CAPTCHA verification later
    # if data.captchaToken:
    #     is_valid = await verify_recaptcha(data.captchaToken)
    #     if not is_valid:
    #         raise HTTPException(
    #             status_code=status.HTTP_400_BAD_REQUEST,
    #             detail="reCAPTCHA verification failed. Please try again."
    #         )
    # else:
    #     # Allow submission without captcha in development
    #     if os.getenv("DEBUG", "false").lower() != "true":
    #         raise HTTPException(
    #             status_code=status.HTTP_400_BAD_REQUEST,
    #             detail="reCAPTCHA verification required."
    #         )
    
    try:
        # Sanitize all input fields
        sanitized_first_name = InputValidator.sanitize_string(data.firstName, max_length=100)
        sanitized_last_name = InputValidator.sanitize_string(data.lastName or "", max_length=100)
        sanitized_company_name = InputValidator.sanitize_string(data.companyName or "", max_length=255)
        sanitized_company_website = InputValidator.sanitize_string(data.companyWebsite or "", max_length=255)
        
        # Create submission in database
        submission = ContactSubmission(
            first_name=sanitized_first_name,
            last_name=sanitized_last_name,
            work_email=data.workEmail,
            company_name=sanitized_company_name,
            company_website=sanitized_company_website,
            plan=data.plan,
            status="new"
        )
        
        db.add(submission)
        await db.commit()
        await db.refresh(submission)
        
        logger.info(f"New contact form submission: {submission.id} from {data.workEmail}")
        
        return ContactFormResponse(
            success=True,
            message="Thank you for your interest! We'll be in touch soon.",
            submission_id=str(submission.id)
        )
        
    except Exception as e:
        logger.error(f"Error saving contact submission: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save submission. Please try again."
        )


@router.get("/admin/contact-submissions")
async def get_contact_submissions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
):
    """
    Get all contact form submissions (admin only).
    Requires admin/superuser authentication.
    """
    try:
        # Query all submissions, ordered by newest first
        result = await db.execute(
            select(ContactSubmission).order_by(desc(ContactSubmission.submitted_at))
        )
        submissions = result.scalars().all()
        
        return {
            "submissions": [sub.to_dict() for sub in submissions],
            "total": len(submissions)
        }
        
    except Exception as e:
        logger.error(f"Error fetching contact submissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch submissions."
        )


@router.delete("/admin/contact-submissions/{submission_id}")
async def delete_contact_submission(
    submission_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
):
    """
    Delete a contact form submission (admin only).
    Requires admin/superuser authentication.
    """
    try:
        # Find submission
        result = await db.execute(
            select(ContactSubmission).where(ContactSubmission.id == submission_id)
        )
        submission = result.scalar_one_or_none()
        
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Submission not found"
            )
        
        # Delete submission
        await db.delete(submission)
        await db.commit()
        
        logger.info(f"Contact submission {submission_id} deleted by {current_user.email}")
        
        return {"success": True, "message": "Submission deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting contact submission: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete submission."
        )


@router.patch("/admin/contact-submissions/{submission_id}/status")
async def update_submission_status(
    submission_id: str,
    status_update: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
):
    """
    Update the status of a contact form submission (admin only).
    Status can be: new, contacted, converted, archived
    """
    valid_statuses = ["new", "contacted", "converted", "archived"]
    if status_update not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    try:
        # Find submission
        result = await db.execute(
            select(ContactSubmission).where(ContactSubmission.id == submission_id)
        )
        submission = result.scalar_one_or_none()
        
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Submission not found"
            )
        
        # Update status
        submission.status = status_update
        await db.commit()
        await db.refresh(submission)
        
        logger.info(f"Contact submission {submission_id} status updated to {status_update}")
        
        return {"success": True, "submission": submission.to_dict()}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating contact submission status: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update submission status."
        )
