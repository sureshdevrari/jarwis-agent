# Jarwis Core Architecture - Quick Reference

## Layered Architecture (Updated January 11, 2026)

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: FRONTEND (React)                                       │
│  jarwisfrontend/src/services/api.js                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓ HTTP/WebSocket
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 2: API ROUTES (FastAPI)                                   │
│  api/routes/*.py - HTTP handling only                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 3: SERVICES + ORCHESTRATION                               │
│  services/scan_orchestrator_service.py ← RECOMMENDED             │
│  - Business logic (validation, subscriptions)                    │
│  - Lifecycle management (state, progress, checkpoints)           │
│  - Engine coordination (delegates to runners)                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 4: CORE ENGINES (Runners)                                 │
│  core/web_scan_runner.py, network_scan_runner.py, etc.          │
│  - Pure scanning logic, no state management                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 5: ATTACK MODULES (OWASP-Organized - Jan 2026)            │
│  attacks/web/a01-a10/*.py (99 scanners total)                   │
│  attacks/cloud/{aws,azure,gcp,kubernetes,cnapp}/*.py            │
│  attacks/mobile/{static,dynamic,platform,api,utils}/*.py        │
│  attacks/sast/{providers,analyzers}/*.py                        │
│  attacks/registry.py ← UNIFIED scanner discovery                │
│                                                                 │
│  LIFECYCLE MANAGEMENT (Process Registries):                      │
│  core/browser.py → BrowserController._instances (web scans)     │
│  core/mobile_process_registry.py → MobileProcessRegistry (mobile)│
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 6: DATABASE                                               │
│  database/models.py, crud.py                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Orchestration Options

### Feature Flag: `USE_UNIFIED_ORCHESTRATOR`

| Value | Implementation | Description |
|-------|----------------|-------------|
| `"false"` | `run_security_scan()` | **Default** - Legacy path, logic in scans.py |
| `"service"` | `ScanOrchestratorService` | **RECOMMENDED** - Layer 3 approach |
| `"true"` | `ScanOrchestrator` | Layer 4 approach (extra hop) |

### Option 1: Service Approach (RECOMMENDED)

```
API Route → ScanOrchestratorService → Runner
    ↓               ↓                    ↓
 (HTTP)      (business + lifecycle)  (scanning)
```

```bash
$env:USE_UNIFIED_ORCHESTRATOR = "service"
```

**File:** `services/scan_orchestrator_service.py`
- Combines business logic + orchestration in one layer
- Fewer hops, cleaner architecture
- Single source of truth for scan operations

### Option 2: Separate Orchestrator (Layer 4)

```
API Route → Service → Orchestrator → Adapter → Runner
    ↓          ↓           ↓            ↓         ↓
 (HTTP)   (business)  (lifecycle)  (wrapper)  (scanning)
```

```bash
$env:USE_UNIFIED_ORCHESTRATOR = "true"
```

**File:** `core/scan_orchestrator.py`
- Stricter separation of concerns
- More layers = more flexibility but more complexity

---

## Key Orchestration Files

| File | Layer | Purpose |
|------|-------|---------|
| `services/scan_orchestrator_service.py` | 3 | **Combined service + orchestration** |
| `core/scan_orchestrator.py` | 4 | Separate orchestrator (alternative) |
| `core/engine_protocol.py` | 4 | ScanEngineProtocol interface |
| `core/progress_tracker.py` | 4 | Centralized progress tracking |
| `core/engines/legacy_adapter.py` | 4 | Wraps existing runners |

---

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
| `attacks/registry.py` | ⭐ **Unified scanner registry** (99 scanners) |
| `core/web_scan_runner.py` | Main orchestrator for web scans |
| `core/attack_engine.py` | Unified attack engine with 28 attack modules |
| `core/request_store.py` | Stores MITM-captured requests/responses |
| `core/mobile_attack_engine.py` | Mobile scanning (reuses web attacks on API traffic) |

---

## Attacks Folder Structure (Updated January 11, 2026)

### Web Scanners - OWASP Top 10 2021

```
attacks/web/
├── a01_broken_access/   # A01:2021 - Broken Access Control
│   ├── access_control_scanner.py
│   ├── idor_scanner.py
│   ├── auth_bypass_scanner.py
│   └── path_traversal_scanner.py
├── a02_crypto/          # A02:2021 - Cryptographic Failures
│   ├── jwt_scanner.py
│   └── session_scanner.py
├── a03_injection/       # A03:2021 - Injection (SQL, XSS, etc.)
│   ├── injection_scanner.py
│   ├── xss_scanner.py, xss_advanced_scanner.py
│   ├── sqli_advanced_scanner.py
│   ├── ssti_scanner.py, xxe_scanner.py
│   └── ldap_injection_scanner.py
├── a04_insecure_design/ # A04:2021 - Insecure Design
├── a05_misconfig/       # A05:2021 - Security Misconfiguration
├── a06_vulnerable_components/
├── a07_auth_failures/   # A07:2021 - Auth Failures (CSRF, OAuth)
├── a08_integrity/       # A08:2021 - Integrity Failures
├── a09_logging/         # A09:2021 - Logging Failures
├── a10_ssrf/            # A10:2021 - SSRF
├── api/                 # API Security (GraphQL, WebSocket)
├── file_upload/         # File Upload Security
├── other/               # Other scanners
├── pre_login/           # BACKWARD COMPAT (imports from OWASP folders)
└── post_login/          # Authenticated scanners
```

### Cloud Scanners - Provider-Based

```
attacks/cloud/
├── aws/                 # AWS-specific scanners
├── azure/               # Azure-specific scanners
├── gcp/                 # GCP-specific scanners
├── kubernetes/          # K8s and container security
├── cnapp/               # CNAPP (CIEM, Runtime, Drift, SBOM)
└── shared/              # Base classes, utilities
```

### Mobile Scanners - Phase-Based

```
attacks/mobile/
├── static/              # Static analysis (APK/IPA)
├── dynamic/             # Runtime analysis (Frida)
├── platform/android/    # Android-specific
├── platform/ios/        # iOS-specific
├── api/                 # Mobile API security
├── orchestration/       # Scan orchestration
└── utils/               # Utilities (OTP, auth detection)
```

### SAST Scanners - Function-Based

```
attacks/sast/
├── providers/           # SCM integrations (GitHub, GitLab, etc.)
├── analyzers/           # Secret, dependency, code analysis
└── language_analyzers/  # Language-specific (Python, JS, Java, Go)
```

### Import Examples

```python
# RECOMMENDED: Import from OWASP-organized folders
from attacks.web.a03_injection import InjectionScanner, XSSScanner
from attacks.cloud.aws import AWSSecurityScanner
from attacks.mobile.static import StaticAnalyzer
from attacks.sast.providers import GitHubScanner

# Registry for discovery (99 scanners)
from attacks.registry import ScannerRegistry
web_scanners = ScannerRegistry.get_scanners(ScanType.WEB)

# BACKWARD COMPAT: Still works
from attacks.web.pre_login import InjectionScanner
```

---

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

## Scan Lifecycle Management (Updated January 11, 2026)

### Web Scan Lifecycle
- **Process Registry**: `BrowserController._instances` tracks all Playwright browser processes by scan_id
- **Stop Mechanism**: `/api/scans/{scan_id}/stop` force-kills the browser, then broadcasts status
- **Startup Recovery**: `recover_running_scans()` marks orphaned "running" scans as STALLED on restart
- **Graceful Shutdown**: `graceful_shutdown()` stops active scans and kills browsers on shutdown
- **Stale Detection**: Background task every 5 minutes marks scans with no DB updates as STALLED

### Mobile Scan Lifecycle
- **Process Registry**: `MobileProcessRegistry` tracks emulator PIDs, Frida processes, MITM proxy, orchestrator by scan_id
- **Stop Mechanism**: `/api/mobile/{scan_id}/stop` kills emulator/Frida and cleans all processes
- **Cleanup**: `MobilePenTestOrchestrator._cleanup()` terminates emulator, Frida server, MITM proxy, crawler, simulator
- **Graceful Shutdown**: `graceful_shutdown()` calls `MobileProcessRegistry.cleanup_all()`
- **PID Tracking**: `EmulatorManager` stores emulator PID for reliable termination
- **Live Monitoring**: Mobile scans now update `scan_progress` for UI/live status

### Scan State Machine (Updated)
```python
class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_FOR_MANUAL_AUTH = "waiting_for_manual_auth"
    WAITING_FOR_OTP = "waiting_for_otp"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"
    CANCELLED = "cancelled"
    STALLED = "stalled"  # Orphaned scan from crash/restart
```

### Key Lifecycle Files
| File | Purpose |
|------|---------|
| core/browser.py | BrowserController with _instances registry for web scans |
| core/mobile_process_registry.py | MobileProcessRegistry for mobile process tracking |
| attacks/mobile/orchestration/mobile_orchestrator.py | Enhanced _cleanup() for emulator/Frida/MITM/crawler |
| attacks/mobile/platform/android/emulator_manager.py | PID tracking + PID kill fallback |
| services/mobile_service.py | stop_mobile_scan() now terminates processes via registry |
| api/server.py | Startup recovery, graceful shutdown, stale detection for web+mobile |
| services/scan_state_machine.py | State machine with STALLED status |
| api/routes/scans.py | scan_progress dict tracks live scans (web + mobile)

---

## Orchestrator vs Engine Responsibilities

### ScanOrchestrator (ONE for all scan types)
- ✅ State transitions (queued → running → completed)
- ✅ Progress tracking with throttled updates
- ✅ Checkpoint/resume for long scans
- ✅ WebSocket broadcasting
- ✅ Error handling and cleanup

### Engines (domain-specific)
- ✅ Execute actual scanning logic
- ✅ Report findings via progress callbacks
- ✅ Domain-specific phases (crawl, attack, etc.)
- ❌ NO state management (orchestrator handles)
- ❌ NO WebSocket calls (orchestrator handles)

### Scan States (ScanStateMachine)

```
QUEUED → RUNNING → COMPLETED
           ↓ ↑
        PAUSED
           ↓
WAITING_FOR_MANUAL_AUTH ←→ WAITING_FOR_OTP
           ↓
      ERROR / STOPPED / CANCELLED
```

### Progress Phases (ProgressTracker)

```python
class ProgressPhase(Enum):
    INITIALIZING = "initializing"
    DISCOVERY = "discovery"
    AUTHENTICATION = "authentication"
    PRE_LOGIN_CRAWL = "pre_login_crawl"
    POST_LOGIN_CRAWL = "post_login_crawl"
    PRE_LOGIN_ATTACK = "pre_login_attack"
    POST_LOGIN_ATTACK = "post_login_attack"
    AI_ANALYSIS = "ai_analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"
```
