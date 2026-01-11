"""
Jarwis Services Layer

Business logic layer that sits between API routes and core modules.
This layer:
1. Contains all business logic (not in routes or core)
2. Can be called by routes, CLI, or tests
3. Handles cross-cutting concerns (logging, metrics)
4. Never imports from api.routes (prevents circular deps)

Architecture:
    API Routes → Services → Core Engines → Database
                    ↓
              (Orchestration)

Usage:
    from services.otp_service import otp_service
    from services.domain_service import domain_service
    from services.subscription_service import SubscriptionService
"""

# Lazy imports to avoid circular dependencies
# Import services directly when needed:
#   from services.otp_service import otp_service
#   from services.scan_service import ScanService

__all__ = [
    "AuthService",
    "ScanService", 
    "OTPService",
    "DomainService",
    "SubscriptionService",
]


def __getattr__(name):
    """Lazy import to avoid circular dependencies"""
    if name == "AuthService":
        from services.auth_service import AuthService
        return AuthService
    elif name == "ScanService":
        from services.scan_service import ScanService
        return ScanService
    elif name == "OTPService":
        from services.otp_service import OTPService
        return OTPService
    elif name == "DomainService":
        from services.domain_service import DomainService
        return DomainService
    elif name == "SubscriptionService":
        from services.subscription_service import SubscriptionService
        return SubscriptionService
    raise AttributeError(f"module 'services' has no attribute '{name}'")
