"""
API Routes Package
"""

from fastapi import APIRouter
from api.routes.auth import router as auth_router
from api.routes.users import router as users_router
from api.routes.api_keys import router as api_keys_router
from api.routes.scans import router as scans_router
from api.routes.oauth import router as oauth_router
from api.routes.chat import router as chat_router
from api.routes.chat_gateway import router as chat_gateway_router  # Secure chat gateway v2
from api.routes.contact import router as contact_router
from api.routes.payments import router as payments_router
from api.routes.network import router as network_router
from api.routes.two_factor import router as two_factor_router
from api.routes.scan_otp import router as scan_otp_router
from api.routes.scan_manual_auth import router as scan_manual_auth_router  # Social login / manual auth
from api.routes.domains import router as domains_router
from api.routes.mobile import router as mobile_router  # Mobile app security scanning
try:
    from api.routes.mobile_agent import router as mobile_agent_router  # Mobile agent WebSocket + REST
except Exception as e:
    print(f"[ERROR] Failed to load mobile_agent router: {e}")
    import traceback
    traceback.print_exc()
    # Create dummy router
    mobile_agent_router = APIRouter(prefix="/api/mobile-agent", tags=["Mobile Agent"])
from api.routes.cloud import router as cloud_router  # Cloud security scanning
from api.routes.dashboard import router as dashboard_router  # Unified dashboard endpoints
from api.routes.health import router as health_router  # System health checks and scanner validation
from api.routes.sast import router as sast_router  # SAST / Source code review scanning
from api.routes.websocket_routes import router as websocket_router  # Real-time WebSocket updates
from api.routes.ai_chat import router as ai_chat_router  # Jarwis AI chat (no LLM required)
from api.routes.agent_downloads import router as agent_downloads_router  # Agent installer downloads

# Try to import universal agent router
try:
    from api.routes.universal_agent import router as universal_agent_router
except Exception as e:
    print(f"[ERROR] Failed to load universal_agent router: {e}")
    import traceback
    traceback.print_exc()
    universal_agent_router = APIRouter(prefix="/api/agent", tags=["Universal Agent"])

# Try to import admin router if it exists
try:
    from api.routes.admin import router as admin_router
except ImportError:
    admin_router = None

# Create main API router
api_router = APIRouter()

# Include all route modules
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(api_keys_router)
api_router.include_router(scans_router)
api_router.include_router(network_router)
api_router.include_router(oauth_router)
api_router.include_router(chat_router)  # Legacy chat endpoint
api_router.include_router(chat_gateway_router)  # Secure chat gateway with token limits
api_router.include_router(contact_router)
api_router.include_router(payments_router)
api_router.include_router(two_factor_router)
api_router.include_router(scan_otp_router)  # For target website 2FA OTP handling
api_router.include_router(scan_manual_auth_router)  # For social login / manual auth
api_router.include_router(domains_router)  # Domain verification for credential-based scans
api_router.include_router(mobile_router)  # Mobile app security scanning
api_router.include_router(mobile_agent_router)  # Mobile agent WebSocket + REST
api_router.include_router(cloud_router)  # Cloud security scanning
api_router.include_router(dashboard_router)  # Unified dashboard endpoints
api_router.include_router(health_router)  # System health checks and scanner validation
api_router.include_router(sast_router)  # SAST / Source code review scanning
api_router.include_router(websocket_router)  # Real-time WebSocket updates
api_router.include_router(ai_chat_router)  # Jarwis AI chat (no LLM required)
api_router.include_router(agent_downloads_router)  # Agent installer downloads
api_router.include_router(universal_agent_router)  # Universal agent WebSocket + REST (ALL scan types)

if admin_router:
    api_router.include_router(admin_router)

__all__ = [
    "api_router", 
    "auth_router", 
    "users_router",
    "api_keys_router",
    "scans_router",
    "network_router",
    "chat_router",
    "chat_gateway_router",
    "contact_router",
    "payments_router",
    "two_factor_router",
    "scan_otp_router",
    "scan_manual_auth_router",
    "mobile_router",
    "cloud_router",
    "sast_router",
    "health_router",
    "agent_downloads_router",
    "universal_agent_router",
]
