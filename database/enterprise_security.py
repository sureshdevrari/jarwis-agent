"""
Enterprise Security Integration Layer

This module provides the integration between the Trust Agent, 
Compliance Reporter, and the rest of the Jarwis application.

It handles:
- Automatic audit logging for all security-sensitive operations
- RBAC enforcement middleware
- Encrypted credential access
- Compliance report scheduling
- Data retention enforcement
"""

import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from contextlib import asynccontextmanager

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Type variable for generic decorators
F = TypeVar("F", bound=Callable[..., Any])


# ============== Lazy Imports ==============

def _get_trust_agent():
    """Lazy import of TrustAgent to avoid circular imports"""
    from core.trust_agent import get_trust_agent
    return get_trust_agent()


def _get_compliance_reporter():
    """Lazy import of ComplianceReporter"""
    from core.compliance_reporter import create_compliance_reporter
    return create_compliance_reporter(_get_trust_agent())


# ============== RBAC Middleware ==============

class RBACMiddleware:
    """
    FastAPI middleware for enforcing Role-Based Access Control.
    
    Usage in route:
        @app.get("/scans")
        @rbac.require(Permission.SCAN_VIEW_ALL)
        async def list_scans(request: Request):
            ...
    """
    
    def __init__(self):
        self._trust = None
    
    @property
    def trust_agent(self):
        if self._trust is None:
            self._trust = _get_trust_agent()
        return self._trust
    
    def require(self, *permissions: str):
        """
        Decorator to require specific permissions.
        
        Args:
            permissions: One or more permission strings required
        """
        def decorator(func: F) -> F:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract request from args/kwargs
                request: Optional[Request] = None
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
                if not request:
                    request = kwargs.get("request")
                
                if not request:
                    # No request context, skip RBAC check
                    return await func(*args, **kwargs)
                
                # Get user from request state (set by auth middleware)
                user = getattr(request.state, "user", None)
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                # Get user's role (from tenant membership or default)
                user_role = getattr(request.state, "user_role", None)
                if not user_role:
                    # Default to viewer for non-enterprise users
                    from core.trust_agent import Role
                    user_role = Role.VIEWER
                
                # Check permissions
                from core.trust_agent import Permission, Role
                
                for perm_str in permissions:
                    try:
                        perm = Permission(perm_str)
                    except ValueError:
                        logger.warning(f"Unknown permission: {perm_str}")
                        continue
                    
                    if not self.trust_agent.check_permission(user_role, perm):
                        # Log the access denial
                        from core.trust_agent import AuditAction
                        await self.trust_agent.log_action(
                            action=AuditAction.CONFIG_CHANGED,
                            user_id=str(user.id),
                            success=False,
                            error_message=f"Permission denied: {perm_str}",
                            request_context={
                                "ip_address": request.client.host if request.client else None,
                                "user_agent": request.headers.get("user-agent"),
                                "endpoint": str(request.url.path)
                            }
                        )
                        
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Permission denied: {perm_str}"
                        )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_role(self, *roles: str):
        """
        Decorator to require specific roles.
        
        Args:
            roles: One or more role names required (user must have one of them)
        """
        def decorator(func: F) -> F:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                request: Optional[Request] = None
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
                if not request:
                    request = kwargs.get("request")
                
                if not request:
                    return await func(*args, **kwargs)
                
                user_role = getattr(request.state, "user_role", None)
                
                from core.trust_agent import Role
                
                if user_role is None:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="No role assigned"
                    )
                
                if user_role.value not in roles:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required role: {' or '.join(roles)}"
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator


# Global RBAC middleware instance
rbac = RBACMiddleware()


# ============== Audit Decorators ==============

def audit_endpoint(
    action: str,
    resource_type: str = None,
    include_request_body: bool = False,
    include_response: bool = False
):
    """
    Decorator to automatically audit API endpoint calls.
    
    Args:
        action: Audit action string (e.g., "scan.started")
        resource_type: Type of resource being accessed
        include_request_body: Whether to include request body in audit
        include_response: Whether to include response in audit
    """
    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            trust = _get_trust_agent()
            
            # Extract request
            request: Optional[Request] = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")
            
            # Get user info
            user = getattr(request.state, "user", None) if request else None
            user_id = str(user.id) if user else None
            tenant_id = getattr(request.state, "tenant_id", None) if request else None
            
            # Build request context
            request_context = {}
            if request:
                request_context = {
                    "ip_address": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent"),
                    "method": request.method,
                    "endpoint": str(request.url.path),
                    "request_id": request.headers.get("x-request-id")
                }
            
            # Build metadata
            metadata = {}
            if include_request_body and request:
                try:
                    body = await request.json()
                    # Sanitize sensitive fields
                    sanitized = _sanitize_audit_data(body)
                    metadata["request_body"] = sanitized
                except:
                    pass
            
            try:
                # Execute the function
                result = await func(*args, **kwargs)
                
                # Log success
                from core.trust_agent import AuditAction
                try:
                    audit_action = AuditAction(action)
                except ValueError:
                    audit_action = AuditAction.CONFIG_CHANGED  # Fallback
                
                if include_response and result:
                    metadata["response_summary"] = str(result)[:500]
                
                await trust.log_action(
                    action=audit_action,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    success=True,
                    metadata=metadata,
                    request_context=request_context
                )
                
                return result
                
            except Exception as e:
                # Log failure
                from core.trust_agent import AuditAction
                try:
                    audit_action = AuditAction(action)
                except ValueError:
                    audit_action = AuditAction.CONFIG_CHANGED
                
                await trust.log_action(
                    action=audit_action,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    success=False,
                    error_message=str(e),
                    metadata=metadata,
                    request_context=request_context
                )
                raise
        
        return wrapper
    return decorator


def _sanitize_audit_data(data: Dict) -> Dict:
    """Remove sensitive fields from audit data"""
    sensitive_keys = {
        "password", "secret", "token", "key", "credential",
        "api_key", "access_token", "refresh_token", "private_key",
        "client_secret", "aws_secret", "azure_secret"
    }
    
    if not isinstance(data, dict):
        return data
    
    sanitized = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(s in key_lower for s in sensitive_keys):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_audit_data(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_audit_data(v) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            sanitized[key] = value
    
    return sanitized


# ============== Credential Access ==============

class SecureCredentialAccess:
    """
    Secure wrapper for accessing encrypted credentials.
    Provides audit logging and access control.
    """
    
    def __init__(self):
        self._trust = None
    
    @property
    def trust_agent(self):
        if self._trust is None:
            self._trust = _get_trust_agent()
        return self._trust
    
    async def get_credential(
        self,
        credential_id: str,
        user_id: str,
        user_role: str,
        purpose: str,
        request: Optional[Request] = None
    ) -> Dict:
        """
        Retrieve a credential with access control and audit logging.
        
        Args:
            credential_id: ID of the credential to retrieve
            user_id: ID of the user requesting access
            user_role: Role of the user
            purpose: Reason for accessing the credential
            request: Optional FastAPI request for context
        
        Returns:
            Decrypted credential data
        
        Raises:
            PermissionError: If user doesn't have access
            ValueError: If credential not found
        """
        from core.trust_agent import Role
        
        try:
            role = Role(user_role)
        except ValueError:
            role = Role.VIEWER
        
        return await self.trust_agent.get_credential(
            credential_id=credential_id,
            user_id=user_id,
            user_role=role,
            purpose=purpose
        )
    
    async def store_credential(
        self,
        name: str,
        credential_type: str,
        credential_data: Dict,
        tenant_id: str,
        user_id: str,
        rotation_days: int = 90
    ) -> str:
        """
        Store a new encrypted credential.
        
        Returns:
            The credential ID
        """
        from core.trust_agent import CredentialType
        
        try:
            cred_type = CredentialType(credential_type)
        except ValueError:
            cred_type = CredentialType.API_TOKEN
        
        return await self.trust_agent.store_credential(
            name=name,
            credential_type=cred_type,
            credential_data=credential_data,
            tenant_id=tenant_id,
            created_by=user_id,
            rotation_days=rotation_days
        )


# Global secure credential access
credentials = SecureCredentialAccess()


# ============== Compliance Utilities ==============

async def generate_compliance_report(
    framework: str,
    tenant_id: str,
    user_id: str,
    period_days: int = 90
) -> Dict:
    """
    Generate a compliance report for a tenant.
    
    Args:
        framework: Compliance framework (soc2_type_ii, iso_27001, gdpr, etc.)
        tenant_id: Tenant ID
        user_id: User requesting the report
        period_days: Number of days to include in report
    
    Returns:
        Compliance report dictionary
    """
    from core.compliance_reporter import ComplianceFramework
    
    reporter = _get_compliance_reporter()
    
    try:
        framework_enum = ComplianceFramework(framework)
    except ValueError:
        raise ValueError(f"Unknown compliance framework: {framework}")
    
    period_end = datetime.utcnow()
    period_start = period_end - timedelta(days=period_days)
    
    report = await reporter.generate_report(
        framework=framework_enum,
        tenant_id=tenant_id,
        period_start=period_start,
        period_end=period_end,
        generated_by=user_id
    )
    
    return report.to_dict()


async def export_compliance_report(
    report_data: Dict,
    format: str = "json"
) -> bytes:
    """
    Export a compliance report in the specified format.
    
    Args:
        report_data: Report data dictionary
        format: Export format (json, html, csv)
    
    Returns:
        Report content as bytes
    """
    from core.compliance_reporter import ComplianceReportResult, ComplianceFramework
    
    reporter = _get_compliance_reporter()
    
    # Reconstruct report object from dict
    # This is a simplified version - full implementation would properly deserialize
    
    if format == "json":
        import json
        return json.dumps(report_data, indent=2, default=str).encode()
    elif format == "html":
        # Generate HTML directly from dict
        return _generate_html_from_dict(report_data).encode()
    else:
        raise ValueError(f"Unsupported format: {format}")


def _generate_html_from_dict(report: Dict) -> str:
    """Generate HTML report from dictionary"""
    summary = report.get("summary", {})
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>{report.get('framework', 'Compliance')} Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #1e3a5f; }}
        .score {{ font-size: 48px; font-weight: bold; 
                  color: {'#22c55e' if summary.get('overall_score', 0) >= 80 else '#f59e0b'}; }}
    </style>
</head>
<body>
    <h1>{report.get('framework', 'Compliance').upper()} Compliance Report</h1>
    <div class="score">{summary.get('overall_score', 0)}%</div>
    <p>Total Controls: {summary.get('total_controls', 0)}</p>
    <p>Compliant: {summary.get('compliant', 0)}</p>
    <p>Non-Compliant: {summary.get('non_compliant', 0)}</p>
</body>
</html>
"""


# ============== Data Retention ==============

async def enforce_retention_policy(
    tenant_id: str,
    dry_run: bool = True
) -> Dict:
    """
    Enforce data retention policy for a tenant.
    
    Args:
        tenant_id: Tenant ID
        dry_run: If True, only simulate deletion
    
    Returns:
        Summary of items deleted/to be deleted
    """
    trust = _get_trust_agent()
    return await trust.enforce_retention_policy(tenant_id, dry_run=dry_run)


# ============== Request Context Manager ==============

@asynccontextmanager
async def enterprise_context(
    request: Request,
    db: AsyncSession
):
    """
    Context manager for enterprise operations.
    Sets up trust agent, tenant context, and ensures proper cleanup.
    
    Usage:
        async with enterprise_context(request, db) as ctx:
            # ctx.trust_agent, ctx.tenant, ctx.user available
            pass
    """
    trust = _get_trust_agent()
    
    user = getattr(request.state, "user", None)
    tenant_id = getattr(request.state, "tenant_id", None)
    
    class EnterpriseContext:
        def __init__(self):
            self.trust_agent = trust
            self.user = user
            self.tenant_id = tenant_id
            self.db = db
    
    ctx = EnterpriseContext()
    
    try:
        yield ctx
    finally:
        # Any cleanup if needed
        pass


# ============== Health Check ==============

async def enterprise_health_check() -> Dict:
    """
    Check health of enterprise security components.
    
    Returns:
        Health status dictionary
    """
    health = {
        "trust_agent": "unknown",
        "encryption": "unknown",
        "audit_logging": "unknown",
        "compliance_reporter": "unknown"
    }
    
    try:
        trust = _get_trust_agent()
        health["trust_agent"] = "healthy"
        
        # Test encryption
        try:
            test_data = b"health_check_test"
            encrypted, _ = await trust._secrets.encrypt(test_data, None)
            decrypted = await trust._secrets.decrypt(encrypted, None, {})
            if decrypted == test_data:
                health["encryption"] = "healthy"
            else:
                health["encryption"] = "degraded"
        except Exception as e:
            health["encryption"] = f"error: {str(e)}"
        
        # Test audit logging
        try:
            from core.trust_agent import AuditAction
            await trust.log_action(
                action=AuditAction.CONFIG_CHANGED,
                metadata={"type": "health_check"}
            )
            health["audit_logging"] = "healthy"
        except Exception as e:
            health["audit_logging"] = f"error: {str(e)}"
        
        # Test compliance reporter
        try:
            reporter = _get_compliance_reporter()
            health["compliance_reporter"] = "healthy"
        except Exception as e:
            health["compliance_reporter"] = f"error: {str(e)}"
        
    except Exception as e:
        health["trust_agent"] = f"error: {str(e)}"
    
    return health
