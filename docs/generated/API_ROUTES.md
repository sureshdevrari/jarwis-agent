# API Routes Reference

> **Auto-generated**: 2026-01-14 02:09:34
> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`

## Summary

Total route modules: **22**

## Route Modules

| Module | Prefix | Tags | Endpoints | Status |
|--------|--------|------|-----------|--------|
| `admin` | `/api/admin` | Admin | 0 | ✅ |
| `ai_chat` | `/api/ai` | AI Chat | 0 | ✅ |
| `api_keys` | `/api/keys` | API Keys | 0 | ✅ |
| `auth` | `/api/auth` | Authentication | 0 | ✅ |
| `chat` | `/api/chat` | Chat | 0 | ✅ |
| `chat_gateway` | `/api/v2/chat` | Chat Gateway | 0 | ✅ |
| `cloud` | `/api/scan/cloud` | Cloud Security Scans | 0 | ✅ |
| `contact` | `/api` | Contact | 0 | ✅ |
| `dashboard` | `/api/dashboard` | dashboard | 0 | ✅ |
| `domains` | `/api/domains` | domains | 0 | ✅ |
| `health` | `/api/health` | Health | 0 | ✅ |
| `mobile` | `/api/scan/mobile` | Mobile Security Scans | 0 | ✅ |
| `network` | `/api/network` | Network Security Scans | 0 | ✅ |
| `oauth` | `/api/oauth` | OAuth | 0 | ✅ |
| `payments` | `/api/payments` | Payments | 0 | ✅ |
| `sast` | `/` | SAST Scans | 0 | ✅ |
| `scan_manual_auth` | `/api/scan-auth` | Scan Manual Auth | 0 | ✅ |
| `scan_otp` | `/api/scan-otp` | Scan OTP | 0 | ✅ |
| `scans` | `/api/scans` | Security Scans | 0 | ✅ |
| `two_factor` | `/api/2fa` | Two-Factor Authentication | 0 | ✅ |
| `users` | `/api/users` | Users | 0 | ✅ |
| `websocket_routes` | `/` | WebSocket | 0 | ✅ |

## Endpoint Details

---

## Wiring

All routes are registered in `api/routes/__init__.py`:

```python
# api/routes/__init__.py imports ALL routers at module load time
# If ANY route file has a broken import, the entire API fails to start
```

**⚠️ WARNING**: Adding a new route requires:
1. Create `api/routes/your_route.py` with `router = APIRouter(...)`
2. Import in `api/routes/__init__.py`
3. Add to `api_router.include_router()`
4. Add to `__all__` list
