# Jarwis Core Architecture - Quick Reference

## Complete Web Scan Data Flow (Updated January 11, 2026)

### 4-Step Data Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: FRONTEND (ScanWizard.jsx)                               │
│     - User configures scan in multi-step wizard                  │
│     - Collects: target_url, scope, auth_method, 2FA, profile     │
│     - URL auto-normalized with https://                          │
│     - handleStartScan() builds scanConfig                        │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: API LAYER (api.js)                                      │
│     - scanAPI.startScan() transforms to backend format           │
│     - Auto-detects auth_method or uses explicit selection        │
│     - Passes: scope, phone_number, session_cookie, social_provs  │
│     - Passes: two_factor config, rate_limit, scan_profile        │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: BACKEND API (scans.py)                                  │
│     - POST /api/scans/ validates via ScanCreate schema           │
│     - crud.create_scan() persists to database                    │
│     - Spawns BackgroundTask for async execution                  │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 4: RUNNER CONFIG (_build_runner_config)                    │
│     - Reads from scan.config: scope, rate_limit, timeout         │
│     - Reads: proxy.enabled, report_formats, auth_selectors       │
│     - scan_profile → crawl limits (full: 100/4, quick: 25/2)     │
│     - scan_profile → attack selection via _build_attacks_config  │
└──────────────────────────────────────────────────────────────────┘
```

## 6-Phase Execution (Scan Runner)

Pre-login and post-login are **NOT** different attack types. Same attacks run on both.

```
┌─────────────────────────────────────────────────────────────────┐
│  1. PRE-LOGIN CRAWL                                              │
│     - Start MITM proxy                                           │
│     - Browser crawls unauthenticated pages                       │
│     - MITM captures all request/response headers                 │
│     - Crawl limits based on scan_profile (full: 100, quick: 25)  │
│     - Store in RequestStore.pre_login_requests                   │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  2. AUTHENTICATION (based on auth_method)                        │
│     - username_password: Fill form via CSS selectors             │
│     - phone_otp: Handle OTP via phone_number                     │
│     - social_login: OAuth flow via social_providers              │
│     - manual_session: Use session_cookie/session_token           │
│     - 2FA support: email, SMS, or authenticator app              │
│     - Capture JWT/session cookies → RequestStore.auth_tokens     │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  3. POST-LOGIN CRAWL                                             │
│     - Crawl authenticated pages                                  │
│     - Submit forms to capture POST requests                      │
│     - Store in RequestStore.post_login_requests                  │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  4. ATTACK PRE-LOGIN REQUESTS                                    │
│     - Attack selection based on scan_profile                     │
│     - Run attack modules on pre_login_requests                   │
│     - Modify request → Send via MITM → Analyze response          │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  5. ATTACK POST-LOGIN REQUESTS                                   │
│     - Run SAME attack modules on post_login_requests             │
│     - Additional auth tests: no token, invalid token, expired    │
│     - Monitor token expiry, refresh if needed                    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  6. GENERATE REPORT                                              │
│     - Combine all findings                                       │
│     - Output formats from config (HTML, JSON, SARIF, PDF)        │
└──────────────────────────────────────────────────────────────────┘
```

## Authentication Methods

| Method | Fields | Description |
|--------|--------|-------------|
| `username_password` | login_url, username, password | Traditional form login |
| `phone_otp` | phone_number | OTP sent to phone |
| `social_login` | social_providers[] | OAuth (Google, Facebook, LinkedIn, Apple) |
| `manual_session` | session_cookie, session_token | Pre-authenticated sessions |

## 2FA Support

| Type | Field | Description |
|------|-------|-------------|
| `email` | two_factor.email | OTP code sent to email |
| `sms` | two_factor.phone | OTP code sent via SMS |
| `authenticator` | - | TOTP app (Google Authenticator, Authy) |

## Scan Profiles

| Profile | Max Pages | Depth | Attack Focus |
|---------|-----------|-------|--------------|
| `full` | 100 | 4 | All OWASP categories |
| `quick` | 25 | 2 | High-impact vulns only |
| `api` | 50 | 3 | API security focus |
| `authenticated` | 150 | 5 | Deep auth testing |

## Key Files

| File | Purpose |
|------|---------|
| `core/web_scan_runner.py` | Main orchestrator for web scans |
| `core/attack_engine.py` | Unified attack engine with 28 attack modules |
| `core/request_store.py` | Stores MITM-captured requests/responses |
| `core/mobile_attack_engine.py` | Mobile scanning (reuses web attacks on API traffic) |

## Attack Engine Pattern

All attacks follow this pattern:

```python
class AttackModule(BaseAttack):
    async def run(self, session, request: CapturedRequest, is_post_login: bool):
        # 1. Modify request parameters with payloads
        # 2. Send modified request via self.engine.send_modified_request()
        # 3. Analyze response for vulnerability indicators
        # 4. Return List[AttackResult]
```

## 28 Attack Modules (All in attack_engine.py)

- **Injection**: SQLi, XSS, NoSQLi, CMDi, SSTI, XXE, LDAP, XPath
- **Access Control**: IDOR, BOLA, BFLA, Path Traversal
- **Auth**: Auth Bypass, JWT, Session
- **Request Forgery**: SSRF, CSRF
- **Headers**: Host Header, CORS, HPP, CRLF
- **Cache/Smuggling**: Cache Poison, HTTP Smuggling
- **Misc**: Open Redirect, File Upload, Rate Limit Bypass

## Mobile Scanning Flow

```
APK/IPA Upload → Static Analysis → Install on Emulator → MITM Capture → Run ALL Web Attacks on API → Mobile-specific attacks
```

Same attacks work on mobile API traffic because they're just HTTP requests!
