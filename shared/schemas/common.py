"""
Common Response Schemas

Shared response models used across multiple endpoints.
"""

from typing import Any, Dict, Generic, List, Optional, TypeVar
from pydantic import BaseModel
from datetime import datetime

T = TypeVar("T")


class MessageResponse(BaseModel):
    """Standard message response"""
    message: str
    success: bool = True
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "Operation completed successfully",
                "success": True
            }
        }


class ErrorResponse(BaseModel):
    """Standard error response"""
    error: str
    error_code: Optional[str] = None
    detail: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "error": "subscription_limit_exceeded",
                "error_code": "LIMIT_001",
                "detail": "You have reached your monthly scan limit"
            }
        }


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper"""
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    version: str
    timestamp: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "service": "jarwis-api",
                "version": "1.0.0",
                "timestamp": "2026-01-07T10:00:00Z"
            }
        }


class SubscriptionStatusResponse(BaseModel):
    """Subscription status for current user"""
    plan: str
    scans_used: int
    scans_remaining: int
    tokens_used: int
    tokens_remaining: int
    renewal_date: Optional[datetime] = None
    is_active: bool = True
