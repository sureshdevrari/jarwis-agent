"""
Chat Routes for Jarwis AGI Assistant
Provides user-isolated chatbot sessions with LLM integration

Security Features:
- File upload validation (extension, size, content)
- Input sanitization
- Rate limiting
"""

import json
import logging
from typing import Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_user, get_current_user_optional
from database.security import (
    FileUploadValidator, InputValidator, get_client_ip, security_store
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat", tags=["Chat"])

# Global chatbot instance (initialized lazily)
# Force reset on module reload to pick up config changes
_chatbot = None
_chatbot_config = None
logger.info("Chat module loaded - chatbot will be initialized on first request")


def _load_chat_config():
    """Load AI config from config.yaml - always reload fresh"""
    global _chatbot_config
    if _chatbot_config:
        return _chatbot_config
    
    try:
        import yaml
        import os
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'config.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        _chatbot_config = {'ai': config.get('ai', {})}
        logger.info(f"Loaded chat config: provider={config.get('ai', {}).get('provider')}, model={config.get('ai', {}).get('model')}")
    except Exception as e:
        logger.warning(f"Could not load config: {e}, using defaults")
        import os
        _chatbot_config = {
            'ai': {
                'provider': 'gemini',
                'model': 'gemini-2.5-flash',
                'api_key': os.environ.get('GEMINI_API_KEY', '')
            }
        }
    return _chatbot_config


def reset_chatbot():
    """Force reset the chatbot instance to reload config"""
    global _chatbot, _chatbot_config
    _chatbot = None
    _chatbot_config = None
    logger.info("Chatbot instance reset - will reinitialize on next request")


def get_chatbot():
    """Get or create chatbot instance"""
    global _chatbot
    if _chatbot is None:
        try:
            from core.chatbot import JarwisChatbot
            config = _load_chat_config()
            ai_config = config.get('ai', {})
            logger.info(f"Initializing chatbot with provider: {ai_config.get('provider')}, model: {ai_config.get('model')}, api_key present: {bool(ai_config.get('api_key'))}")
            _chatbot = JarwisChatbot(config)
            logger.info(f"Chatbot initialized successfully, available: {_chatbot.is_available}")
        except Exception as e:
            logger.error(f"Failed to initialize chatbot: {e}", exc_info=True)
            return None
    return _chatbot


# ============== Request/Response Models ==============

class ChatMessage(BaseModel):
    """Chat message request"""
    message: str
    scan_id: Optional[str] = None
    model_mode: Optional[str] = "jarwis"  # jarwis or sav


class ChatResponse(BaseModel):
    """Chat response"""
    response: str
    session_id: str


class ChatContextRequest(BaseModel):
    """Request to set chat context"""
    scan_id: str
    findings: Optional[list] = []
    endpoints: Optional[list] = []


class ChatStatusResponse(BaseModel):
    """Chat service status"""
    available: bool
    model: str
    provider: str


# ============== Chat Endpoints ==============

@router.get("/status", response_model=ChatStatusResponse)
async def get_chat_status():
    """Get chat service status"""
    chatbot = get_chatbot()
    config = _load_chat_config()
    return {
        "available": chatbot.is_available if chatbot else False,
        "model": config['ai']['model'],
        "provider": config['ai']['provider']
    }


@router.post("/reset")
async def reset_chat_service():
    """Force reset the chatbot to reload configuration"""
    reset_chatbot()
    chatbot = get_chatbot()
    return {
        "message": "Chatbot reset successfully",
        "available": chatbot.is_available if chatbot else False
    }


@router.post("")
async def chat(
    data: ChatMessage,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Send a message to Jarwis AGI chatbot.
    REQUIRES AUTHENTICATION - user must be logged in.
    Uses authenticated user ID for session isolation.
    Returns streaming SSE response.
    """
    chatbot = get_chatbot()
    
    if not chatbot or not chatbot.is_available:
        # Return a fallback response when LLM is not available
        async def fallback_stream():
            fallback_msg = "I'm currently in offline mode. The AI service is not available. Please check the API key configuration or try again later."
            yield f"data: {json.dumps({'type': 'chunk', 'content': fallback_msg})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        
        return StreamingResponse(
            fallback_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive"
            }
        )
    
    # Use authenticated user ID for session isolation (required)
    session_id = f"user_{current_user.id}"
    
    # If scan_id provided, set context
    if data.scan_id:
        try:
            # Get scan findings for context
            from api.server import scan_jobs
            if data.scan_id in scan_jobs:
                job = scan_jobs[data.scan_id]
                chatbot.set_scan_context(
                    session_id=session_id,
                    findings=job.get('findings', []),
                    endpoints=[],
                    scan_id=data.scan_id
                )
        except Exception as e:
            logger.warning(f"Could not set scan context: {e}")
    
    async def generate():
        """Stream response chunks"""
        try:
            for chunk in chatbot.chat(
                data.message, 
                session_id=session_id,
                model_mode=data.model_mode or "jarwis"
            ):
                yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        except Exception as e:
            logger.error(f"Chat error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
    )


@router.post("/context")
async def set_chat_context(
    data: ChatContextRequest,
    current_user: User = Depends(get_current_user)
):
    """Set scan context for chat session"""
    chatbot = get_chatbot()
    
    if not chatbot:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Chat service not available"
        )
    
    session_id = f"user_{current_user.id}"
    
    chatbot.set_scan_context(
        session_id=session_id,
        findings=data.findings,
        endpoints=data.endpoints,
        scan_id=data.scan_id
    )
    
    return {"status": "ok", "message": "Context set successfully"}


@router.get("/history")
async def get_chat_history(
    session_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get chat history for current user"""
    chatbot = get_chatbot()
    
    if not chatbot:
        return {"messages": []}
    
    # Use authenticated user's session
    user_session_id = f"user_{current_user.id}"
    
    if user_session_id in chatbot._sessions:
        session = chatbot._sessions[user_session_id]
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


@router.post("/clear")
async def clear_chat_history(
    current_user: User = Depends(get_current_user)
):
    """Clear chat history for current user"""
    chatbot = get_chatbot()
    
    if not chatbot:
        return {"status": "ok"}
    
    session_id = f"user_{current_user.id}"
    
    if session_id in chatbot._sessions:
        chatbot._sessions[session_id].conversation_history = []
    
    return {"status": "ok", "message": "Chat history cleared"}


# Maximum file size: 10MB
MAX_FILE_SIZE = 10 * 1024 * 1024

@router.post("/upload")
async def upload_file_for_analysis(
    request: Request,
    file: UploadFile = File(...),
    scan_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """
    Upload a file for AI analysis.
    
    Security:
    - File extension validation
    - File size limit (10MB)
    - Content validation
    - Rate limiting
    """
    client_ip = get_client_ip(request)
    
    # Rate limit file uploads
    is_blocked, _, remaining = await security_store.is_blocked(client_ip)
    if is_blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests. Please try again in {remaining} seconds."
        )
    
    chatbot = get_chatbot()
    
    if not chatbot or not chatbot.is_available:
        async def fallback_stream():
            fallback_msg = "File analysis is not available - LLM service is offline."
            yield f"data: {json.dumps({'type': 'chunk', 'content': fallback_msg})}\n\n"
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        
        return StreamingResponse(
            fallback_stream(),
            media_type="text/event-stream"
        )
    
    # Sanitize filename to prevent path traversal
    safe_filename = FileUploadValidator.sanitize_filename(file.filename or "unnamed")
    
    # Validate file extension
    valid, error = FileUploadValidator.validate_file_extension(safe_filename)
    if not valid:
        logger.warning(f"File upload rejected - invalid extension: {file.filename} from {client_ip}")
        async def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'content': error})}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    try:
        # Read file content with size limit
        content = await file.read()
        
        # Validate file size
        valid, error = FileUploadValidator.validate_file_size(len(content))
        if not valid:
            logger.warning(f"File upload rejected - size: {len(content)} bytes from {client_ip}")
            async def error_stream():
                yield f"data: {json.dumps({'type': 'error', 'content': error})}\n\n"
            return StreamingResponse(error_stream(), media_type="text/event-stream")
        
        # Validate file content
        valid, error = FileUploadValidator.validate_file_content(content, safe_filename)
        if not valid:
            logger.warning(f"File upload rejected - content validation: {safe_filename} from {client_ip}")
            async def error_stream():
                yield f"data: {json.dumps({'type': 'error', 'content': error})}\n\n"
            return StreamingResponse(error_stream(), media_type="text/event-stream")
        
        text_content = content.decode('utf-8', errors='ignore')
        
        # Limit file size for context (50KB for LLM)
        if len(text_content) > 50000:
            text_content = text_content[:50000] + "\n\n[File truncated - showing first 50KB]"
        
        # Log successful upload
        logger.info(f"File uploaded for analysis: {safe_filename} ({len(content)} bytes) by user {current_user.id}")
        
        # Create analysis prompt
        analysis_prompt = f"""Please analyze this file ({safe_filename}):

```
{text_content}
```

Provide a security-focused analysis including:
1. Any potential vulnerabilities or security issues
2. Sensitive data exposure risks
3. Recommendations for improvement"""
        
        session_id = f"user_{current_user.id}"
        
        async def generate():
            """Stream response chunks"""
            try:
                for chunk in chatbot.chat(analysis_prompt, session_id=session_id):
                    yield f"data: {json.dumps({'type': 'chunk', 'content': chunk})}\n\n"
                yield f"data: {json.dumps({'type': 'end'})}\n\n"
            except Exception as e:
                logger.error(f"File analysis error: {e}")
                yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
        
        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive"
            }
        )
        
    except Exception as e:
        logger.error(f"File upload error: {e}")
        async def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'content': 'Error processing file. Please try again.'})}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")
