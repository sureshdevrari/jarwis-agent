"""
Jarwis AGI Secure Chat Gateway
Provides user-isolated chatbot sessions with:
- Token usage limits by subscription plan
- User data isolation (one account cannot access another's data)
- Scan history context injection
- Security-focused topic filtering

Token Limits (per month):
- Professional: 500,000 tokens/month (Suru 1.1 model)
- Enterprise: 5,000,000 tokens/month (10x professional, Savi 3.1 Thinking model)

Created by BKD Labs
"""

import json
import logging
from typing import Optional, List
from uuid import UUID
from datetime import datetime, date, timedelta
import asyncio

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from pydantic import BaseModel, Field

from database.connection import get_db
from database.models import User, ScanHistory, Finding, ChatTokenUsage
from database.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v2/chat", tags=["Chat Gateway"])

# ============== Configuration ==============

# Token limits per subscription plan (tokens per month)
TOKEN_LIMITS = {
    "free": 0,              # No chatbot access
    "individual": 0,        # No chatbot access (web-only plan)
    "professional": 500000, # 500K tokens/month (Suru 1.1 model)
    "enterprise": 5000000,  # 5M tokens/month (Savi 3.1 Thinking)
}

# Estimated tokens per request (for pre-check)
ESTIMATED_TOKENS_PER_REQUEST = 1000

# Global chatbot instance
_chatbot = None
_chatbot_config = None


def _load_config():
    """Load AI config from config.yaml"""
    global _chatbot_config
    if _chatbot_config:
        return _chatbot_config
    
    try:
        import yaml
        import os
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'config.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        _chatbot_config = config.get('ai', {
            'provider': 'gemini',
            'model': 'gemini-2.5-flash',
            'api_key': ''
        })
    except Exception as e:
        logger.warning(f"Could not load config: {e}")
        _chatbot_config = {
            'provider': 'gemini',
            'model': 'gemini-2.5-flash'
        }
    return _chatbot_config


def get_chatbot():
    """Get or create chatbot instance with config"""
    global _chatbot
    if _chatbot is None:
        try:
            from core.chatbot import JarwisChatbot
            config = {'ai': _load_config()}
            _chatbot = JarwisChatbot(config)
            logger.info(f"Chat gateway initialized with provider: {config['ai'].get('provider')}")
        except Exception as e:
            logger.error(f"Failed to initialize chatbot: {e}")
            return None
    return _chatbot


# ============== Request/Response Models ==============

class SecureChatRequest(BaseModel):
    """Secure chat message request"""
    message: str = Field(..., min_length=1, max_length=5000)
    model_mode: str = Field(default="jarwis", pattern="^(jarwis|sav)$")
    include_scan_context: bool = Field(default=True)


class TokenUsageResponse(BaseModel):
    """Token usage info for user"""
    tokens_used_this_month: int
    token_limit: int
    tokens_remaining: int
    requests_this_month: int
    plan: str
    has_chatbot_access: bool
    reset_time: str  # Next reset time (1st of next month)


class ChatStatusResponse(BaseModel):
    """Chat service status with access info"""
    available: bool
    has_access: bool
    plan: str
    tokens_remaining: int
    message: str


# ============== Token Management ==============

async def get_user_token_usage(db: AsyncSession, user_id: UUID) -> tuple[int, int]:
    """Get user's token usage for this month. Returns (tokens_used, request_count)"""
    today = date.today()
    month_start = datetime.combine(date(today.year, today.month, 1), datetime.min.time())
    
    result = await db.execute(
        select(ChatTokenUsage).where(
            and_(
                ChatTokenUsage.user_id == user_id,
                ChatTokenUsage.date >= month_start
            )
        )
    )
    usages = result.scalars().all()
    
    total_tokens = sum(u.tokens_used for u in usages)
    total_requests = sum(u.request_count for u in usages)
    return total_tokens, total_requests


async def record_token_usage(db: AsyncSession, user_id: UUID, tokens: int):
    """Record token usage for a user"""
    today = date.today()
    today_start = datetime.combine(today, datetime.min.time())
    
    # Try to get existing record
    result = await db.execute(
        select(ChatTokenUsage).where(
            and_(
                ChatTokenUsage.user_id == user_id,
                ChatTokenUsage.date >= today_start,
                ChatTokenUsage.date < today_start + timedelta(days=1)
            )
        )
    )
    usage = result.scalar_one_or_none()
    
    if usage:
        usage.tokens_used += tokens
        usage.request_count += 1
    else:
        usage = ChatTokenUsage(
            user_id=user_id,
            date=today_start,
            tokens_used=tokens,
            request_count=1
        )
        db.add(usage)
    
    await db.commit()


def get_token_limit(plan: str) -> int:
    """Get token limit for a subscription plan"""
    return TOKEN_LIMITS.get(plan, 0)


def estimate_tokens(text: str) -> int:
    """Estimate token count for text (rough: 4 chars = 1 token)"""
    return max(1, len(text) // 4)


# ============== User Scan Data Loader ==============

async def load_user_scan_context(db: AsyncSession, user_id: UUID, limit: int = 5) -> dict:
    """
    Load user's recent scan data for chat context.
    CRITICAL: Only loads scans belonging to THIS user for isolation.
    """
    # Get user's recent scans (most recent first)
    result = await db.execute(
        select(ScanHistory)
        .where(ScanHistory.user_id == user_id)
        .order_by(ScanHistory.started_at.desc())
        .limit(limit)
    )
    scans = result.scalars().all()
    
    if not scans:
        return {
            "has_scans": False,
            "message": "No scan history found. Run a security scan to get personalized insights."
        }
    
    scan_summaries = []
    total_findings = 0
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for scan in scans:
        # Get findings for this scan
        findings_result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .limit(20)  # Limit findings per scan for context window
        )
        findings = findings_result.scalars().all()
        
        finding_details = []
        for f in findings[:10]:  # Top 10 findings per scan
            finding_details.append({
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "url": f.url[:100] if f.url else "",
                "description": (f.description[:200] + "...") if f.description and len(f.description) > 200 else f.description
            })
        
        scan_summaries.append({
            "scan_id": scan.scan_id,
            "target": scan.target_url,
            "type": scan.scan_type,
            "status": scan.status,
            "date": scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else "Unknown",
            "findings_count": scan.findings_count,
            "severity_breakdown": {
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "info": scan.info_count
            },
            "top_findings": finding_details
        })
        
        total_findings += scan.findings_count
        severity_totals["critical"] += scan.critical_count
        severity_totals["high"] += scan.high_count
        severity_totals["medium"] += scan.medium_count
        severity_totals["low"] += scan.low_count
        severity_totals["info"] += scan.info_count
    
    return {
        "has_scans": True,
        "scan_count": len(scans),
        "total_findings": total_findings,
        "severity_totals": severity_totals,
        "recent_scans": scan_summaries
    }


# ============== Access Control ==============

def check_chatbot_access(user: User) -> tuple[bool, str]:
    """
    Check if user has chatbot access based on their subscription.
    Returns (has_access, message)
    
    Access is controlled by the has_chatbot_access flag which is set 
    by apply_plan_features() when a user's plan is assigned or changed.
    
    Current plan matrix:
    - Free: No chatbot access
    - Individual: Has chatbot access (with token limits)
    - Professional: Has chatbot access (with token limits)
    - Enterprise: Has chatbot access (higher token limits)
    """
    plan = user.plan.lower() if user.plan else "free"
    
    # Check explicit chatbot access flag (set by plan features)
    if not user.has_chatbot_access:
        if plan == "free":
            return False, "Upgrade to Individual or higher to access Jarwis AI chatbot."
        else:
            return False, "Chatbot access is not enabled for your account. Please contact support."
    
    # Check subscription validity (for paid plans with expiry)
    if user.subscription_end and user.subscription_end < datetime.utcnow():
        return False, "Your subscription has expired. Please renew to access the chatbot."
    
    return True, "Access granted"


async def check_token_limit(db: AsyncSession, user: User) -> tuple[bool, int, str]:
    """
    Check if user has tokens remaining.
    Returns (has_tokens, remaining, message)
    """
    plan = user.plan.lower() if user.plan else "free"
    limit = get_token_limit(plan)
    
    if limit == 0:
        return False, 0, "Your plan does not include chatbot tokens."
    
    tokens_used, _ = await get_user_token_usage(db, user.id)
    remaining = max(0, limit - tokens_used)
    
    if remaining < ESTIMATED_TOKENS_PER_REQUEST:
        return False, remaining, f"Monthly token limit reached ({tokens_used:,}/{limit:,}). Resets on the 1st of next month."
    
    return True, remaining, f"Tokens remaining: {remaining:,}/{limit:,}"


# ============== API Endpoints ==============

@router.get("/status", response_model=ChatStatusResponse)
async def get_chat_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get chat service status and user's access level.
    Requires authentication.
    """
    chatbot = get_chatbot()
    is_available = chatbot.is_available if chatbot else False
    
    has_access, access_msg = check_chatbot_access(current_user)
    
    if has_access:
        has_tokens, remaining, token_msg = await check_token_limit(db, current_user)
        if not has_tokens:
            has_access = False
            access_msg = token_msg
    else:
        remaining = 0
    
    return ChatStatusResponse(
        available=is_available,
        has_access=has_access,
        plan=current_user.plan,
        tokens_remaining=remaining if has_access else 0,
        message=access_msg if not has_access else "Ready to assist with security testing!"
    )


@router.get("/usage", response_model=TokenUsageResponse)
async def get_token_usage(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user's token usage for this month.
    Requires authentication.
    """
    plan = current_user.plan.lower() if current_user.plan else "free"
    limit = get_token_limit(plan)
    tokens_used, request_count = await get_user_token_usage(db, current_user.id)
    
    # Calculate next reset time (1st of next month)
    today = date.today()
    if today.month == 12:
        next_month = date(today.year + 1, 1, 1)
    else:
        next_month = date(today.year, today.month + 1, 1)
    reset_time = datetime.combine(next_month, datetime.min.time())
    
    return TokenUsageResponse(
        tokens_used_this_month=tokens_used,
        token_limit=limit,
        tokens_remaining=max(0, limit - tokens_used),
        requests_this_month=request_count,
        plan=plan,
        has_chatbot_access=current_user.has_chatbot_access,
        reset_time=reset_time.isoformat() + "Z"
    )


@router.post("")
async def secure_chat(
    data: SecureChatRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Send a message to Jarwis AGI chatbot.
    
    SECURITY FEATURES:
    - Requires authentication
    - User session isolation (user_id based)
    - Token usage tracking and limits
    - Only loads THIS user's scan data
    - Security-focused topic filtering
    
    Token Limits:
    - Professional: 50,000 tokens/day
    - Enterprise: 500,000 tokens/day
    
    Returns streaming SSE response.
    """
    # Step 1: Check chatbot access
    has_access, access_msg = check_chatbot_access(current_user)
    if not has_access:
        async def access_denied():
            yield f"data: {json.dumps({'type': 'error', 'content': access_msg})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        return StreamingResponse(access_denied(), media_type="text/event-stream")
    
    # Step 2: Check token limit
    has_tokens, remaining, token_msg = await check_token_limit(db, current_user)
    if not has_tokens:
        async def limit_reached():
            yield f"data: {json.dumps({'type': 'error', 'content': token_msg})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        return StreamingResponse(limit_reached(), media_type="text/event-stream")
    
    # Step 3: Get chatbot
    chatbot = get_chatbot()
    if not chatbot or not chatbot.is_available:
        async def service_unavailable():
            yield f"data: {json.dumps({'type': 'error', 'content': 'Jarwis AI is temporarily unavailable. Please try again later.'})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        return StreamingResponse(service_unavailable(), media_type="text/event-stream")
    
    # Step 4: Load user's scan context (ISOLATED - only this user's data)
    if data.include_scan_context:
        scan_context = await load_user_scan_context(db, current_user.id)
        
        # Set context in chatbot session
        session_id = f"secure_user_{current_user.id}"
        chatbot.set_scan_context(
            session_id=session_id,
            findings=[],  # We inject context differently
            endpoints=[],
            scan_id=None,
            server_logs=[]
        )
        
        # Inject scan context into the chatbot's session
        if session_id in chatbot._sessions:
            chatbot._sessions[session_id].scan_context = scan_context
    else:
        session_id = f"secure_user_{current_user.id}"
    
    # Step 5: Stream response with token tracking
    async def generate():
        """Stream response chunks and track tokens"""
        total_tokens = 0
        input_tokens = estimate_tokens(data.message)
        total_tokens += input_tokens
        
        try:
            response_text = ""
            for chunk in chatbot.chat(
                data.message,
                session_id=session_id,
                model_mode=data.model_mode
            ):
                response_text += chunk
                yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
            
            # Calculate output tokens
            output_tokens = estimate_tokens(response_text)
            total_tokens += output_tokens
            
            # Record token usage
            await record_token_usage(db, current_user.id, total_tokens)
            
            # Send usage info
            yield f"data: {json.dumps({'type': 'usage', 'tokens': total_tokens, 'remaining': remaining - total_tokens})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
            
        except Exception as e:
            logger.error(f"Chat error for user {current_user.id}: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': 'An error occurred. Please try again.'})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.get("/context")
async def get_user_context(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user's scan context that will be shared with chatbot.
    Shows what data the AI can see about your account.
    
    SECURITY: Only returns THIS user's data.
    """
    has_access, access_msg = check_chatbot_access(current_user)
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=access_msg
        )
    
    context = await load_user_scan_context(db, current_user.id)
    
    return {
        "user_id": str(current_user.id),
        "username": current_user.username,
        "plan": current_user.plan,
        "scan_context": context
    }


@router.delete("/history")
async def clear_chat_history(
    current_user: User = Depends(get_current_user)
):
    """
    Clear chat history for current user.
    Does not affect token usage.
    """
    chatbot = get_chatbot()
    if chatbot:
        session_id = f"secure_user_{current_user.id}"
        if session_id in chatbot._sessions:
            chatbot._sessions[session_id].conversation_history = []
    
    return {"status": "ok", "message": "Chat history cleared"}


@router.get("/history")
async def get_chat_history(
    current_user: User = Depends(get_current_user)
):
    """
    Get chat history for current user.
    SECURITY: Only returns THIS user's history.
    """
    chatbot = get_chatbot()
    if not chatbot:
        return {"messages": []}
    
    session_id = f"secure_user_{current_user.id}"
    
    if session_id in chatbot._sessions:
        session = chatbot._sessions[session_id]
        messages = [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp
            }
            for msg in session.conversation_history
        ]
        return {"messages": messages}
    
    return {"messages": []}
