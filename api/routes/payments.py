"""
Razorpay Payment Integration Routes
Handles subscription payments, order creation, and verification
"""

import os
import hmac
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

import razorpay
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_user_optional, get_current_active_user, get_current_user
from database.auth import get_user_by_id, get_user_by_email

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/payments", tags=["Payments"])

# Razorpay Configuration
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "rzp_live_RzTkobSpY2KixL")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "hqast300eIY8XV7fglQPjAQT")

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Currency conversion rates (approximate, for testing)
# In production, use a real-time currency API
CURRENCY_RATES = {
    "INR": 1.0,
    "USD": 0.012,  # 1 INR = 0.012 USD
    "EUR": 0.011,  # 1 INR = 0.011 EUR
    "GBP": 0.0095,  # 1 INR = 0.0095 GBP
    "AUD": 0.018,  # 1 INR = 0.018 AUD
    "CAD": 0.016,  # 1 INR = 0.016 CAD
    "SGD": 0.016,  # 1 INR = 0.016 SGD
    "AED": 0.044,  # 1 INR = 0.044 AED
}

# Plan pricing in INR (base currency) - TEST PRICES
PLAN_PRICES_INR = {
    "individual": 100,  # 1 rupee in paise (Razorpay uses smallest currency unit)
    "professional": 200,  # 2 rupees in paise
}

# Plan pricing display
PLAN_PRICES_DISPLAY = {
    "individual": {"INR": "₹1", "USD": "$0.01", "EUR": "€0.01", "GBP": "£0.01"},
    "professional": {"INR": "₹2", "USD": "$0.02", "EUR": "€0.02", "GBP": "£0.02"},
}


# ============== Request/Response Models ==============

class CreateOrderRequest(BaseModel):
    """Request to create a payment order"""
    plan: str  # individual, professional
    currency: str = "INR"
    email: Optional[EmailStr] = None
    user_id: Optional[str] = None


class CreateOrderResponse(BaseModel):
    """Response with Razorpay order details"""
    order_id: str
    amount: int
    currency: str
    plan: str
    key_id: str
    user_email: Optional[str] = None
    display_amount: str


class VerifyPaymentRequest(BaseModel):
    """Request to verify payment after completion"""
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    plan: str
    user_id: Optional[str] = None
    email: Optional[EmailStr] = None


class PaymentSuccessResponse(BaseModel):
    """Response after successful payment"""
    success: bool
    message: str
    plan: str
    user_id: Optional[str] = None
    subscription_expires: Optional[str] = None


class CurrencyInfoResponse(BaseModel):
    """Currency information based on location"""
    currency: str
    symbol: str
    plans: dict


# ============== Helper Functions ==============

def get_currency_from_country(country_code: str) -> str:
    """Map country code to currency"""
    country_currency_map = {
        # Asia
        "IN": "INR", "PK": "INR", "BD": "INR", "LK": "INR", "NP": "INR",
        "SG": "SGD", "MY": "INR", "TH": "INR", "ID": "INR", "PH": "INR",
        "JP": "INR", "KR": "INR", "CN": "INR", "HK": "INR",
        # Middle East
        "AE": "AED", "SA": "AED", "QA": "AED", "KW": "AED", "BH": "AED", "OM": "AED",
        # Europe
        "DE": "EUR", "FR": "EUR", "IT": "EUR", "ES": "EUR", "NL": "EUR",
        "BE": "EUR", "AT": "EUR", "PT": "EUR", "IE": "EUR", "FI": "EUR",
        "GR": "EUR", "LU": "EUR", "SK": "EUR", "SI": "EUR", "EE": "EUR",
        "LV": "EUR", "LT": "EUR", "CY": "EUR", "MT": "EUR",
        "GB": "GBP", "UK": "GBP",
        # Americas
        "US": "USD", "CA": "CAD", "MX": "USD", "BR": "USD", "AR": "USD",
        # Oceania
        "AU": "AUD", "NZ": "AUD",
    }
    return country_currency_map.get(country_code, "USD")


def convert_to_currency(amount_inr: int, target_currency: str) -> int:
    """
    Convert INR paise to target currency's smallest unit.
    Razorpay supports: INR, USD, EUR, GBP, SGD, AED, AUD, CAD, etc.
    """
    if target_currency == "INR":
        return amount_inr
    
    rate = CURRENCY_RATES.get(target_currency, 0.012)  # Default to USD rate
    # Convert paise to target currency cents/smallest unit
    converted = int(amount_inr * rate)
    return max(converted, 1)  # Minimum 1 cent/unit


def get_amount_display(amount_paise: int, currency: str) -> str:
    """Get display string for amount"""
    symbols = {
        "INR": "₹", "USD": "$", "EUR": "€", "GBP": "£",
        "AUD": "A$", "CAD": "C$", "SGD": "S$", "AED": "د.إ"
    }
    symbol = symbols.get(currency, "$")
    
    # Convert from smallest unit to main unit
    amount = amount_paise / 100
    
    if currency == "INR":
        return f"{symbol}{amount:.0f}"
    return f"{symbol}{amount:.2f}"


def verify_razorpay_signature(order_id: str, payment_id: str, signature: str) -> bool:
    """Verify Razorpay payment signature"""
    message = f"{order_id}|{payment_id}"
    generated_signature = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(generated_signature, signature)


# ============== API Endpoints ==============

@router.get("/currency-info")
async def get_currency_info(
    country_code: str = "IN"
) -> CurrencyInfoResponse:
    """
    Get currency information based on country code.
    Returns currency, symbol, and plan prices in that currency.
    """
    currency = get_currency_from_country(country_code)
    symbols = {
        "INR": "₹", "USD": "$", "EUR": "€", "GBP": "£",
        "AUD": "A$", "CAD": "C$", "SGD": "S$", "AED": "د.إ"
    }
    
    plans = {}
    for plan_id, amount_inr in PLAN_PRICES_INR.items():
        converted_amount = convert_to_currency(amount_inr, currency)
        plans[plan_id] = {
            "amount": converted_amount,
            "display": get_amount_display(converted_amount, currency),
        }
    
    return CurrencyInfoResponse(
        currency=currency,
        symbol=symbols.get(currency, "$"),
        plans=plans
    )


@router.post("/create-order", response_model=CreateOrderResponse)
async def create_payment_order(
    request: CreateOrderRequest,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a Razorpay order for subscription payment.
    Can be called by authenticated users or guest checkout with email.
    """
    # Validate plan
    if request.plan not in PLAN_PRICES_INR:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan. Available plans: {list(PLAN_PRICES_INR.keys())}"
        )
    
    # Get base price in INR paise
    base_amount = PLAN_PRICES_INR[request.plan]
    
    # Convert to requested currency
    currency = request.currency.upper()
    if currency not in CURRENCY_RATES and currency != "INR":
        currency = "INR"  # Fallback to INR
    
    amount = convert_to_currency(base_amount, currency)
    
    # Razorpay requires minimum amount (100 paise = 1 INR, or equivalent)
    # For testing, we use very small amounts
    
    # Get user email
    user_email = None
    if current_user:
        user_email = current_user.email
    elif request.email:
        user_email = request.email
    
    # Create Razorpay order
    try:
        order_data = {
            "amount": amount,
            "currency": currency,
            "receipt": f"jarwis_{request.plan}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "notes": {
                "plan": request.plan,
                "user_email": user_email or "",
                "user_id": str(current_user.id) if current_user else (request.user_id or ""),
            }
        }
        
        order = razorpay_client.order.create(data=order_data)
        
        return CreateOrderResponse(
            order_id=order["id"],
            amount=order["amount"],
            currency=order["currency"],
            plan=request.plan,
            key_id=RAZORPAY_KEY_ID,
            user_email=user_email,
            display_amount=get_amount_display(amount, currency)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create payment order: {str(e)}"
        )


@router.post("/verify", response_model=PaymentSuccessResponse)
async def verify_payment(
    request: VerifyPaymentRequest,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """
    Verify Razorpay payment and activate subscription.
    Called after successful payment on frontend.
    """
    # Log payment verification attempt
    logger.info(f"Payment verification attempt: order={request.razorpay_order_id}, payment={request.razorpay_payment_id}")
    
    # Verify signature (HMAC timing-safe comparison)
    if not verify_razorpay_signature(
        request.razorpay_order_id,
        request.razorpay_payment_id,
        request.razorpay_signature
    ):
        logger.warning(f"Payment signature verification FAILED: order={request.razorpay_order_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid payment signature. Payment verification failed."
        )
    
    # Verify payment with Razorpay
    try:
        payment = razorpay_client.payment.fetch(request.razorpay_payment_id)
        if payment["status"] != "captured":
            # Try to capture the payment
            razorpay_client.payment.capture(
                request.razorpay_payment_id, 
                payment["amount"]
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Payment verification failed: {str(e)}"
        )
    
    # Find or identify user
    user = current_user
    if not user and request.user_id:
        try:
            user = await get_user_by_id(db, UUID(request.user_id))
        except:
            pass
    
    if not user and request.email:
        user = await get_user_by_email(db, request.email)
    
    if not user and request.email:
        # Create new user for guest checkout with payment
        # This user is auto-approved since they paid
        from uuid import uuid4
        import secrets
        
        username = request.email.split('@')[0]
        # Make username unique
        from database.auth import get_user_by_username
        existing = await get_user_by_username(db, username)
        if existing:
            username = f"{username}_{secrets.token_hex(4)}"
        
        user = User(
            id=uuid4(),
            email=request.email,
            username=username,
            full_name=username,
            hashed_password="",  # No password - user will need to set via "forgot password" or OAuth
            is_active=True,
            is_verified=True,  # Auto-verified since they paid
            approval_status="approved",  # Auto-approved since they paid
            plan=request.plan,
            created_at=datetime.utcnow(),
            last_login=datetime.utcnow(),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        logger.info(f"Created new user via payment: {request.email} with plan {request.plan}")
    
    if not user:
        # Payment successful but no user found and no email provided
        return PaymentSuccessResponse(
            success=True,
            message="Payment successful! Please complete registration with the same email to activate your subscription.",
            plan=request.plan,
            user_id=None,
            subscription_expires=None
        )
    
    # Calculate subscription period
    if request.plan == "individual":
        # Individual plan: per-scan basis, give 30 days access
        subscription_end = datetime.utcnow() + timedelta(days=30)
    else:
        # Professional plan: monthly
        subscription_end = datetime.utcnow() + timedelta(days=30)
    
    # Update user subscription
    user.plan = request.plan
    user.approval_status = "approved"  # Auto-approve after payment
    user.is_verified = True  # Mark as verified
    user.subscription_start = datetime.utcnow()
    user.subscription_end = subscription_end
    
    # Set plan-specific features
    if request.plan == "individual":
        user.max_users = 1
        user.max_websites = 1
        user.has_api_testing = False
        user.has_credential_scanning = False
        user.has_chatbot_access = False
        user.has_mobile_pentest = False
        user.dashboard_access_days = 7
    elif request.plan == "professional":
        user.max_users = 3
        user.max_websites = 10
        user.has_api_testing = True
        user.has_credential_scanning = True
        user.has_chatbot_access = True
        user.has_mobile_pentest = False
        user.dashboard_access_days = 365
    
    user.scans_this_month = 0  # Reset scan count
    
    await db.commit()
    await db.refresh(user)
    
    return PaymentSuccessResponse(
        success=True,
        message=f"Payment successful! Your {request.plan.title()} plan is now active.",
        plan=request.plan,
        user_id=str(user.id),
        subscription_expires=subscription_end.isoformat()
    )


@router.get("/plans")
async def get_plans():
    """
    Get all available plans with pricing.
    Returns pricing in multiple currencies.
    """
    plans = []
    
    for plan_id, amount_inr in PLAN_PRICES_INR.items():
        pricing = {}
        for currency in CURRENCY_RATES.keys():
            converted = convert_to_currency(amount_inr, currency)
            pricing[currency] = {
                "amount": converted,
                "display": get_amount_display(converted, currency)
            }
        
        plans.append({
            "id": plan_id,
            "name": plan_id.title(),
            "base_price_inr": amount_inr,
            "pricing": pricing,
            "billing": "monthly" if plan_id == "professional" else "per-scan"
        })
    
    return {"plans": plans}


@router.get("/config")
async def get_payment_config():
    """
    Get Razorpay configuration for frontend.
    Only returns public key.
    """
    return {
        "key_id": RAZORPAY_KEY_ID,
        "currency_default": "INR",
        "supported_currencies": list(CURRENCY_RATES.keys()),
    }


# ============== Razorpay Webhook ==============

RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")

def verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    """Verify Razorpay webhook signature"""
    if not secret:
        return True  # Skip verification if no secret configured (dev mode)
    generated = hmac.new(
        secret.encode(),
        body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(generated, signature)


@router.get("/history")
async def get_payment_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get payment history for the current user"""
    # For now, return placeholder data since we don't have a PaymentHistory model yet
    # In production, this would query a payments table
    payments = []
    
    # If user has a subscription, create a mock entry
    if current_user.plan and current_user.plan != "free":
        payments.append({
            "id": str(current_user.id),
            "date": current_user.subscription_start.isoformat() if current_user.subscription_start else datetime.utcnow().isoformat(),
            "amount": 19900 if current_user.plan == "professional" else 0,  # Rs. 199 in paise
            "currency": "INR",
            "plan": current_user.plan,
            "status": "success",
            "description": f"Subscription to {current_user.plan.capitalize()} plan"
        })
    
    return {
        "payments": payments,
        "total": len(payments)
    }


@router.get("/cards")
async def get_saved_cards(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get saved payment cards for the current user"""
    # For now, return empty list since Razorpay handles card storage
    # In production with saved cards enabled, this would fetch from Razorpay
    return {
        "cards": [],
        "total": 0
    }


@router.post("/webhook")
async def razorpay_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Handle Razorpay webhook events.
    This ensures payment is processed even if frontend callback fails.
    """
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")
    
    # Verify webhook signature
    if RAZORPAY_WEBHOOK_SECRET and not verify_webhook_signature(body, signature, RAZORPAY_WEBHOOK_SECRET):
        logger.warning("Razorpay webhook signature verification failed")
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    try:
        event = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    event_type = event.get("event")
    payload = event.get("payload", {})
    
    logger.info(f"Razorpay webhook received: {event_type}")
    
    if event_type == "payment.captured":
        # Payment was successfully captured
        payment_entity = payload.get("payment", {}).get("entity", {})
        order_id = payment_entity.get("order_id")
        payment_id = payment_entity.get("id")
        email = payment_entity.get("email")
        notes = payment_entity.get("notes", {})
        plan = notes.get("plan", "individual")
        
        if email:
            # Find or create user
            user = await get_user_by_email(db, email)
            
            if not user:
                # Create new user
                from uuid import uuid4
                import secrets as sec
                from database.auth import get_user_by_username
                
                username = email.split('@')[0]
                existing = await get_user_by_username(db, username)
                if existing:
                    username = f"{username}_{sec.token_hex(4)}"
                
                user = User(
                    id=uuid4(),
                    email=email,
                    username=username,
                    full_name=username,
                    hashed_password="",
                    is_active=True,
                    is_verified=True,
                    approval_status="approved",
                    plan=plan,
                    created_at=datetime.utcnow(),
                    last_login=datetime.utcnow(),
                )
                db.add(user)
                logger.info(f"Webhook: Created new user {email} with plan {plan}")
            
            # Update user subscription
            subscription_end = datetime.utcnow() + timedelta(days=30)
            user.plan = plan
            user.approval_status = "approved"
            user.is_verified = True
            user.subscription_start = datetime.utcnow()
            user.subscription_end = subscription_end
            user.scans_this_month = 0
            
            await db.commit()
            logger.info(f"Webhook: Updated user {email} subscription to {plan}")
    
    return {"status": "ok"}
