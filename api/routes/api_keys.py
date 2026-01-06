"""
API Key Management Routes
Create, list, and revoke API keys for programmatic access
"""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User, APIKey
from database.schemas import APIKeyCreate, APIKeyResponse, APIKeyInfo, MessageResponse
from database.dependencies import get_current_active_user
from database import crud

router = APIRouter(prefix="/api/keys", tags=["API Keys"])


@router.post("/", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new API key for programmatic access.
    
    **IMPORTANT**: The API key is only shown once! Save it securely.
    
    - **name**: A descriptive name for the key
    - **expires_in_days**: Optional expiry in days (null = never expires)
    """
    # Calculate expiry
    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)
    
    # Default scopes (full access for now)
    scopes = {
        "scans:read": True,
        "scans:write": True,
        "reports:read": True,
        "profile:read": True,
        "profile:write": True
    }
    
    # Create key
    api_key_record, raw_key = await crud.create_api_key(
        db=db,
        user_id=current_user.id,
        name=key_data.name,
        scopes=scopes,
        expires_at=expires_at
    )
    
    return APIKeyResponse(
        id=api_key_record.id,
        name=api_key_record.name,
        key=raw_key,  # Only time the raw key is returned!
        created_at=api_key_record.created_at,
        expires_at=api_key_record.expires_at
    )


@router.get("/", response_model=list[APIKeyInfo])
async def list_api_keys(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all API keys for the current user.
    Note: The actual key values are not returned for security.
    """
    keys = await crud.get_user_api_keys(db, current_user.id)
    
    return [
        APIKeyInfo(
            id=key.id,
            name=key.name,
            is_active=key.is_active,
            last_used_at=key.last_used_at,
            usage_count=key.usage_count,
            created_at=key.created_at,
            expires_at=key.expires_at
        )
        for key in keys
    ]


@router.delete("/{key_id}", response_model=MessageResponse)
async def delete_api_key(
    key_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete an API key permanently.
    """
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid key ID format"
        )
    
    # Find the key
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_uuid,
            APIKey.user_id == current_user.id
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    await crud.delete_api_key(db, api_key)
    
    return MessageResponse(
        message=f"API key '{api_key.name}' has been deleted",
        success=True
    )


@router.post("/{key_id}/revoke", response_model=MessageResponse)
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke an API key (deactivate without deleting).
    """
    try:
        key_uuid = UUID(key_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid key ID format"
        )
    
    # Find the key
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_uuid,
            APIKey.user_id == current_user.id
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    await crud.revoke_api_key(db, api_key)
    
    return MessageResponse(
        message=f"API key '{api_key.name}' has been revoked",
        success=True
    )
