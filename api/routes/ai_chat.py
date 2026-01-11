"""
Jarwis AI Chat Routes (No LLM Required)
========================================

Alternative chat endpoints that use Jarwis's built-in AI
instead of Gemini/external LLMs.

Features:
- Intent classification
- Knowledge-based responses  
- Scan analysis
- Attack chain detection
- Self-learning from feedback

Can be used alongside or instead of the Gemini-based /api/chat

Author: Jarwis AI Team
Created: January 2026
"""

import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User, Finding, ScanHistory
from database.dependencies import get_current_user

# Core AI imports
from core.jarwis_chatbot import JarwisAIChatbot, ChatContext, ChatResponse as AIChatResponse
from services.ai_learning_service import get_ai_service, AILearningService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["AI Chat"])

# Global chatbot instance
_ai_chatbot: Optional[JarwisAIChatbot] = None


def get_ai_chatbot() -> JarwisAIChatbot:
    """Get or create AI chatbot instance"""
    global _ai_chatbot
    if _ai_chatbot is None:
        _ai_chatbot = JarwisAIChatbot()
        logger.info("Jarwis AI Chatbot initialized (no LLM required)")
    return _ai_chatbot


# ============== Request/Response Models ==============

class AIChatMessage(BaseModel):
    """AI Chat message request"""
    message: str = Field(..., min_length=1, max_length=2000)
    scan_id: Optional[str] = None


class AIChatAPIResponse(BaseModel):
    """AI Chat response"""
    response: str
    response_type: str = "text"
    confidence: float
    suggested_questions: List[str] = []
    requires_llm: bool = False


class FeedbackRequest(BaseModel):
    """Finding feedback request"""
    finding_id: str
    feedback_type: str = Field(..., pattern="^(confirmed|false_positive)$")
    notes: str = ""


class ScanInsightsRequest(BaseModel):
    """Request for scan insights"""
    scan_id: str


class ScanInsightsResponse(BaseModel):
    """AI-generated scan insights"""
    total_findings: int
    severity_distribution: Dict[str, int]
    top_vulnerabilities: List[str]
    attack_chain_count: int
    risk_score: float
    recommendations: List[str]


class AIStatusResponse(BaseModel):
    """AI service status"""
    available: bool = True
    mode: str = "jarwis_ai"
    requires_llm: bool = False
    learning_stats: Dict[str, Any] = {}


# ============== Chat Endpoints ==============

@router.get("/status", response_model=AIStatusResponse)
async def get_ai_status(
    current_user: User = Depends(get_current_user)
):
    """
    Get Jarwis AI service status.
    Unlike LLM-based chat, this is always available.
    """
    ai_service = get_ai_service()
    
    return AIStatusResponse(
        available=True,
        mode="jarwis_ai",
        requires_llm=False,
        learning_stats=ai_service.get_learning_stats()
    )


@router.post("/chat", response_model=AIChatAPIResponse)
async def ai_chat(
    data: AIChatMessage,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Chat with Jarwis AI (no LLM required).
    
    Features:
    - Vulnerability explanations
    - Remediation guidance
    - Scan analysis
    - Security concepts
    
    Always available, no external API needed.
    """
    chatbot = get_ai_chatbot()
    
    # Build context
    context = ChatContext(user_id=str(current_user.id))
    
    # If scan_id provided, load findings
    if data.scan_id:
        try:
            from sqlalchemy import select
            
            # Get scan findings
            result = await db.execute(
                select(Finding).where(Finding.scan_id == data.scan_id)
            )
            findings = result.scalars().all()
            
            context.scan_id = data.scan_id
            context.findings = [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.owasp_category or f.category or "",
                    "url": f.url or "",
                    "description": f.description or "",
                    "evidence": f.evidence or "",
                    "poc": f.poc or ""
                }
                for f in findings
            ]
            
            logger.info(f"Loaded {len(context.findings)} findings for AI chat context")
            
        except Exception as e:
            logger.warning(f"Could not load scan context: {e}")
    
    # Get response
    response = chatbot.chat(data.message, context)
    
    return AIChatAPIResponse(
        response=response.message,
        response_type=response.response_type,
        confidence=response.confidence,
        suggested_questions=response.suggested_questions,
        requires_llm=response.requires_llm_fallback
    )


@router.post("/chat/stream")
async def ai_chat_stream(
    data: AIChatMessage,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Stream chat response (for UI compatibility).
    Since AI responses are instant, this simulates streaming.
    """
    chatbot = get_ai_chatbot()
    
    # Build context
    context = ChatContext(user_id=str(current_user.id))
    
    # Load scan data if provided
    if data.scan_id:
        try:
            from sqlalchemy import select
            
            result = await db.execute(
                select(Finding).where(Finding.scan_id == data.scan_id)
            )
            findings = result.scalars().all()
            
            context.scan_id = data.scan_id
            context.findings = [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.owasp_category or f.category or "",
                    "url": f.url or "",
                    "description": f.description or "",
                }
                for f in findings
            ]
        except Exception as e:
            logger.warning(f"Could not load scan context: {e}")
    
    response = chatbot.chat(data.message, context)
    
    async def generate():
        """Simulate streaming for UI compatibility"""
        try:
            # Split response into chunks
            content = response.message
            chunk_size = 50
            
            for i in range(0, len(content), chunk_size):
                chunk = content[i:i + chunk_size]
                yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
            
            # Send metadata
            yield f"data: {json.dumps({'type': 'meta', 'confidence': response.confidence, 'suggestions': response.suggested_questions})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
            
        except Exception as e:
            logger.error(f"AI chat stream error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
    )


# ============== Feedback Endpoints ==============

@router.post("/feedback")
async def submit_feedback(
    data: FeedbackRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Submit feedback on a finding for AI self-learning.
    
    Feedback types:
    - confirmed: The finding is a real vulnerability
    - false_positive: The finding is incorrect
    
    This helps Jarwis learn and improve detection accuracy.
    """
    ai_service = get_ai_service()
    
    # Get the finding
    try:
        from sqlalchemy import select
        
        result = await db.execute(
            select(Finding).where(Finding.id == data.finding_id)
        )
        finding = result.scalar_one_or_none()
        
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found"
            )
        
        # Convert to dict
        finding_data = {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "category": finding.owasp_category or finding.category or "",
            "url": finding.url or "",
            "description": finding.description or "",
            "evidence": finding.evidence or "",
            "scanner": finding.scanner or "unknown"
        }
        
        # Record feedback
        success = ai_service.record_feedback(
            finding_id=data.finding_id,
            feedback_type=data.feedback_type,
            finding=finding_data,
            user_notes=data.notes
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to record feedback"
            )
        
        # Update finding in database
        if data.feedback_type == "false_positive":
            finding.is_false_positive = True
        else:
            finding.ai_verified = True
        
        await db.commit()
        
        logger.info(f"Recorded {data.feedback_type} feedback for finding {data.finding_id}")
        
        return {
            "status": "ok",
            "message": f"Feedback recorded: {data.feedback_type}",
            "learning_applied": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Feedback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/feedback/stats")
async def get_feedback_stats(
    current_user: User = Depends(get_current_user)
):
    """Get AI learning statistics from feedback"""
    ai_service = get_ai_service()
    
    return {
        "status": "ok",
        "stats": ai_service.get_learning_stats()
    }


# ============== Scan Analysis Endpoints ==============

@router.get("/insights/{scan_id}", response_model=ScanInsightsResponse)
async def get_scan_insights(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get AI-generated insights about a scan.
    
    Returns:
    - Risk score (0-100)
    - Attack chains detected
    - Prioritized recommendations
    - Severity distribution
    """
    ai_service = get_ai_service()
    
    try:
        from sqlalchemy import select
        
        # Get scan
        scan_result = await db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        # Get findings
        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = findings_result.scalars().all()
        
        # Convert to dicts
        finding_dicts = [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "category": f.owasp_category or f.category or "",
                "url": f.url or ""
            }
            for f in findings
        ]
        
        # Get insights
        insights = ai_service.generate_scan_insights(
            finding_dicts,
            target_url=scan.target_url
        )
        
        return ScanInsightsResponse(
            total_findings=insights.total_findings,
            severity_distribution=insights.severity_distribution,
            top_vulnerabilities=insights.top_vulnerabilities,
            attack_chain_count=len(insights.attack_chains),
            risk_score=insights.risk_score,
            recommendations=insights.recommendations
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Insights error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/enhance-findings")
async def enhance_findings(
    scan_id: str = Query(..., description="Scan ID to enhance"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Enhance scan findings with AI analysis.
    
    Adds:
    - Confidence scores
    - Exploitability assessment
    - Reasoning chain
    - Priority ranking
    - Attack chain detection
    """
    ai_service = get_ai_service()
    
    try:
        from sqlalchemy import select
        
        # Get findings
        result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = result.scalars().all()
        
        if not findings:
            return {"status": "ok", "findings": [], "message": "No findings to enhance"}
        
        # Convert to dicts
        finding_dicts = [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "category": f.owasp_category or f.category or "",
                "url": f.url or "",
                "description": f.description or "",
                "evidence": f.evidence or "",
                "parameter": f.parameter or ""
            }
            for f in findings
        ]
        
        # Enhance with AI
        enhanced = ai_service.enhance_findings(finding_dicts)
        
        # Update database with AI analysis
        for ef in enhanced:
            finding_id = ef.original.get("id")
            for f in findings:
                if str(f.id) == finding_id:
                    f.ai_confidence = ef.ai_confidence
                    f.ai_verified = False  # Will be set by user feedback
                    # Store reasoning as JSON in a field if available
                    break
        
        await db.commit()
        
        return {
            "status": "ok",
            "enhanced_count": len(enhanced),
            "findings": [ef.to_dict() for ef in enhanced]
        }
        
    except Exception as e:
        logger.error(f"Enhancement error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ============== Knowledge Endpoints ==============

@router.get("/knowledge/vulnerability/{vuln_type}")
async def get_vulnerability_info(
    vuln_type: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed information about a vulnerability type.
    
    Examples:
    - /api/ai/knowledge/vulnerability/sql_injection
    - /api/ai/knowledge/vulnerability/xss
    - /api/ai/knowledge/vulnerability/csrf
    """
    from services.knowledge_service import KnowledgeService
    
    service = KnowledgeService()
    result = service.get_vulnerability_definition(vuln_type)
    
    return {
        "status": "ok",
        "content": result.content,
        "confidence": result.confidence,
        "related": result.related_topics
    }


@router.get("/knowledge/owasp/{category}")
async def get_owasp_info(
    category: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get OWASP Top 10 category information.
    
    Examples:
    - /api/ai/knowledge/owasp/A01
    - /api/ai/knowledge/owasp/A03
    """
    from services.knowledge_service import KnowledgeService
    
    service = KnowledgeService()
    result = service.get_owasp_info(category)
    
    return {
        "status": "ok",
        "content": result.content,
        "confidence": result.confidence
    }


@router.get("/knowledge/remediation/{vuln_type}")
async def get_remediation_guidance(
    vuln_type: str,
    language: Optional[str] = Query(None, description="Programming language"),
    current_user: User = Depends(get_current_user)
):
    """
    Get remediation guidance for a vulnerability type.
    
    Examples:
    - /api/ai/knowledge/remediation/sql_injection?language=python
    - /api/ai/knowledge/remediation/xss?language=javascript
    """
    from services.knowledge_service import KnowledgeService
    
    service = KnowledgeService()
    result = service.get_remediation(vuln_type, language)
    
    return {
        "status": "ok",
        "content": result.content,
        "confidence": result.confidence,
        "related": result.related_topics
    }
