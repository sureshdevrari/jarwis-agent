"""
Jarwis Shared Contracts Layer

This package is the SINGLE SOURCE OF TRUTH for:
- API endpoint definitions
- Request/Response schemas
- Plan limits and constants
- Configuration validation

Rules:
1. Backend routes import endpoints from here
2. Frontend types are auto-generated from here
3. All shared constants live here
4. NEVER hardcode endpoints or limits elsewhere
"""

from shared.api_endpoints import APIEndpoints, build_endpoint
from shared.constants import (
    PlanLimits, PLAN_LIMITS, 
    TokenLimits, RateLimits,
    ScanTypes, SeverityLevels
)

__all__ = [
    "APIEndpoints",
    "build_endpoint",
    "PlanLimits",
    "PLAN_LIMITS",
    "TokenLimits",
    "RateLimits", 
    "ScanTypes",
    "SeverityLevels",
]
