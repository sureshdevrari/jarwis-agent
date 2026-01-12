# 02 - Scan Flow

## Complete Web Scan Data Flow (Updated January 11, 2026)

The web scan follows a 4-step data pipeline from user click to scanner execution:

### Step 1: Frontend (ScanWizard.jsx)
```
User clicks "Start Scan" → ScanWizard validates → handleStartScan() builds scanConfig
```

**Data collected:**
- `target_url` (auto-normalized with https://)
- `scan_type` / `scan_profile` (full, quick, api, authenticated)
- `scan_name` (user-friendly label)
- `rate_limit` (requests per second)
- `scope` (regex patterns for scan boundaries)
- `auth_method` (username_password, phone_otp, social_login, manual_session)
- `login_url`, `username`, `password`
- `phone_number` (for phone OTP auth)
- `session_cookie`, `session_token` (for manual session)
- `social_providers` (for social login: google, facebook, etc.)
- `two_factor` config (enabled, type: email/sms/authenticator, email, phone)

### Step 2: API Layer (api.js)
```
scanAPI.startScan(scanConfig) → Transform to backend format → POST /api/scans/
```

**Transformation:**
- Detects `auth_method` from credentials or explicit selection
- Wraps scan settings in `config` object
- Passes all auth fields (phone_number, session_cookie, social_providers, two_factor)

### Step 3: Backend (scans.py)
```
POST /api/scans/ → ScanCreate validation → crud.create_scan() → Background task
```

**Database fields:**
- `target_url`, `scan_type`, `scan_name`
- `auth_method`, `login_url`, `username`, `password`
- `phone_number`, `session_cookie`, `session_token`
- `social_providers`, `two_factor` (TwoFactorConfig)
- `config` (dict with scan_profile, rate_limit, scope, attacks)

### Step 4: Runner Config (WebScanRunner)
```
Background task → _build_runner_config() → WebScanRunner.run()
```

**Runner config reads from scan.config:**
- `scope` - scan boundaries
- `rate_limit` - throttling
- `timeout` - request timeout
- `proxy.enabled`, `proxy.port` - proxy settings
- `report_formats` - output formats
- `auth_selectors` - CSS selectors for login form
- `scan_profile` → affects crawl settings and attack selection

---

## Phased Execution Model

Jarwis uses a 6-phase execution model for web security testing:

### Phase 1: Anonymous Crawl
- `BrowserController` (Playwright) discovers endpoints via `crawl()` method
- Returns: `urls_visited`, `endpoints`, `upload_endpoints`, `api_endpoints`
- **CRITICAL**: Endpoints must be populated into `RequestStore` for scanners to use
- No authentication
- Builds endpoint map via `RequestStore.populate_from_browser_endpoints()`
- Crawl limits based on `scan_profile`:
  - `full`: 100 pages, depth 4
  - `quick`: 25 pages, depth 2
  - `api`: 50 pages, depth 3
  - `authenticated`: 150 pages, depth 5

### Phase 2: Pre-Login Scan
- Attack modules test unauthenticated surfaces
- Scanners organized by OWASP Top 10 in `attacks/web/a01-a10/` folders
- 48+ scanner modules (backward-compatible via `attacks/web/pre_login/`)
- `UnifiedExecutor` builds context from `RequestStore`
- Scanners receive `context.endpoints` list to test
- Attack selection based on `scan_profile` via `_build_attacks_config()`

### Phase 3: Authentication
- Form-based login via CSS selectors
- Supports multiple auth methods:
  - `username_password` - Traditional form login
  - `phone_otp` - Phone-based OTP
  - `social_login` - OAuth providers (Google, Facebook, etc.)
  - `manual_session` - User-provided cookies/tokens
- Session/cookie capture
- 2FA support (email, SMS, authenticator app)

### Phase 4: Post-Login Scan
- Authenticated testing
- IDOR, CSRF, privilege escalation
- Scanners in OWASP folders (e.g., `attacks/web/a01_broken_access/`, `attacks/web/a07_auth_failures/`)

### Phase 5: AI Planning
- LLM recommends targeted tests
- Based on findings from phases 1-4
- Uses `AIPlanner` class

### Phase 6: Reporting
- Multi-format output (configurable via `report_formats`)
- HTML, JSON, SARIF, PDF
- Uses `ReportGenerator` class

## Data Flow (Critical!)

```
┌─────────────────────────────────────────────────────────────┐
│ BrowserController.crawl()                                   │
│   Returns: endpoints[], urls_visited[], api_endpoints[]    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│ RequestStore.populate_from_browser_endpoints()              │
│   Stores endpoints as CapturedRequest objects               │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│ UnifiedExecutor._build_context_from_store()                 │
│   Builds context.endpoints for scanners                     │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│ XSSScanner, InjectionScanner, etc.                          │
│   Iterates over context.endpoints to test                   │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

| Component | File | Purpose |
|-----------|------|---------|
| `WebScanRunner` | `core/web_scan_runner.py` | Main web scan orchestrator |
| `BrowserController` | `core/browser.py` | Playwright automation, endpoint discovery |
| `RequestStore` | `core/request_store.py` | Central store for captured requests/endpoints |
| `UnifiedExecutor` | `core/unified_executor.py` | Runs all scanners with context |
| `AIPlanner` | `core/ai_planner.py` | LLM integration |
| `ReportGenerator` | `core/reporters.py` | Report generation |

## Scan Types

1. **Web Scanning** - `core/web_scan_runner.py`
2. **Mobile Scanning** - `core/mobile_attack_engine.py`
3. **Network Scanning** - `core/network_scan_runner.py`
4. **Cloud Scanning** - `core/cloud_scan_runner.py`
