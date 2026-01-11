# Jarwis AGI Pen Test - Project Architecture

> **Last Updated**: January 10, 2026  
> **Status**: Production Ready - All systems operational

---

## 📂 Project Structure Overview

```
D:\jarwis-ai-pentest\
│
├── 🏗️ BACKEND APPLICATION
│   ├── api/                    # FastAPI routes and server
│   │   ├── websocket.py        # WebSocket connection manager (NEW!)
│   │   └── routes/
│   │       └── websocket_routes.py  # WebSocket endpoints (NEW!)
│   ├── core/                   # Scan engines, orchestrators, AI
│   ├── services/               # Business logic layer
│   ├── database/               # SQLAlchemy models, migrations
│   ├── shared/                 # Contracts, schemas, constants
│   └── attacks/                # Scanner modules (web/mobile/network/cloud)
│
├── 💻 FRONTEND
│   └── jarwisfrontend/         # React 19 application
│       └── src/hooks/
│           └── useWebSocket.js # WebSocket React hooks (NEW!)
│
├── ⚙️ CONFIGURATION
│   ├── config/                 # YAML configs, OAuth credentials
│   └── templates/              # HTML report templates
│
├── 📚 DOCUMENTATION
│   └── docs/                   # All documentation
│       └── implementation_rules/   # Architecture guides
│
├── 🚀 DEPLOYMENT
│   └── deploy/                 # Docker, scripts, manifests
│       ├── docker/             # Dockerfiles, docker-compose
│       └── scripts/            # Deployment scripts
│
├── 🔧 SCRIPTS
│   └── scripts/                # Utility scripts
│       ├── startup/            # Server startup scripts
│       └── utilities/          # Diagnostic scripts
│
├── 🧪 TESTING
│   └── tests/                  # Pytest test files
│
├── 🎨 ASSETS
│   └── assets/                 # Media and AI training data
│       ├── logos/              # Logo files
│       └── ai-training/        # LLM training data
│
└── 📁 GENERATED DATA (gitignored)
    └── data/                   # Runtime generated files
        ├── jarwis.db           # SQLite database (ONLY location!)
        ├── logs/               # Application logs
        ├── reports/            # Generated scan reports
        ├── temp/               # Temporary scan data
        └── uploads/            # User uploads (APKs, etc.)
```

---

## 🏛️ Layered Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND                                 │
│   jarwisfrontend/src/services/api.js (SINGLE API client)        │
│   jarwisfrontend/src/config/*.generated.js (auto-generated)     │
│   jarwisfrontend/src/hooks/useWebSocket.js (WebSocket hooks)    │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP + WebSocket
┌────────────────────────────▼────────────────────────────────────┐
│                        API ROUTES                                │
│   api/routes/*.py (HTTP handling only - NO business logic!)     │
│   api/routes/websocket_routes.py (WebSocket endpoints)          │
│   api/websocket.py (ConnectionManager for real-time updates)    │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                         SERVICES                                 │
│   services/*.py (ALL business logic lives here)                 │
│   13 service files for auth, scans, billing, etc.               │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                      CORE ENGINES                                │
│   core/*.py (scanner logic, AI, reports - NO api imports!)      │
│   27 core modules for scanning and orchestration                │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                        DATABASE                                  │
│   database/*.py (SQLAlchemy models, CRUD)                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    SHARED CONTRACTS                              │
│   shared/api_endpoints.py    - All endpoint URLs                │
│   shared/constants.py        - Plan limits, enums, settings     │
│   shared/schemas/*.py        - Pydantic models                  │
│   shared/generate_frontend_types.py - Generates JS config       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Detailed Folder Contents

### API Layer (`api/`) - 19 Route Files

```
api/
├── server.py               # FastAPI app entry (uvicorn runs this)
├── app.py                  # Legacy Flask (deprecated)
├── startup_checks.py       # Health checks on startup
├── __init__.py
└── routes/
    ├── __init__.py         # Route aggregator
    ├── admin.py            # /api/admin/*
    ├── api_keys.py         # /api/api-keys/*
    ├── auth.py             # /api/auth/* (login, register, logout)
    ├── chat.py             # /api/chat/*
    ├── chat_gateway.py     # Token tracking for AI chat
    ├── cloud.py            # /api/cloud/*
    ├── contact.py          # /api/contact/*
    ├── dashboard.py        # /api/dashboard/*
    ├── domains.py          # /api/domains/*
    ├── health.py           # /api/health
    ├── mobile.py           # /api/scan/mobile/*
    ├── network.py          # /api/network/*
    ├── oauth.py            # /api/oauth/*
    ├── payments.py         # /api/payments/*
    ├── scans.py            # /api/scans/* (main scan endpoints)
    ├── scan_manual_auth.py # Manual auth scan endpoints
    ├── scan_otp.py         # OTP handling for scans
    ├── two_factor.py       # /api/2fa/*
    └── users.py            # /api/users/*
```

### Services Layer (`services/`) - 13 Service Files

```
services/
├── __init__.py
├── agent_service.py        # Jarwis agent communication
├── auth_service.py         # Authentication logic
├── cloud_service.py        # Cloud scan logic
├── dashboard_service.py    # Dashboard statistics
├── domain_service.py       # Domain management
├── domain_verification_service.py  # Domain verification
├── manual_auth_service.py  # Manual auth flow
├── mobile_service.py       # Mobile scan logic
├── network_service.py      # Network scan logic
├── otp_service.py          # OTP generation/verification
├── scan_service.py         # Scan CRUD operations
├── scan_state_machine.py   # Scan state transitions
└── subscription_service.py # Plan/billing logic
```

### Core Engines (`core/`) - 27 Modules

```
core/
├── __init__.py
│
├── # === MAIN ORCHESTRATORS ===
├── runner.py               # PenTestRunner (main orchestrator)
├── web_scan_runner.py      # Web scanning phases (MITM-based)
├── attack_engine.py        # Attack coordination
├── unified_executor.py     # Unified scan execution
│
├── # === BROWSER & NETWORK ===
├── browser.py              # BrowserController (Playwright)
├── http_helper.py          # HTTP utilities
├── proxy.py                # Proxy handling
├── mitm_proxy.py           # MITM proxy
├── mitm_addon.py           # MITM addon
├── request_store.py        # Request storage for attacks
├── scope.py                # Scope validation
│
├── # === AI INTEGRATION ===
├── ai_planner.py           # LLM integration (Ollama/OpenAI)
├── ai_verifier.py          # AI-powered verification
├── chatbot.py              # Gemini chatbot
│
├── # === SCAN RUNNERS BY TYPE ===
├── mobile_attack_engine.py # Mobile app analysis
├── network_scan_runner.py  # Network scanning
├── cloud_scan_runner.py    # Cloud scanning
├── cloud_graph.py          # Cloud resource graphing
├── cloud_scanner_registry.py  # Cloud scanner registration
│
├── # === DETECTION & ANALYSIS ===
├── detection_logic.py      # Vulnerability detection
├── preflight_validator.py  # Pre-scan validation
├── scanner_registry.py     # Scanner registration
├── tool_registry.py        # Tool registration
│
├── # === REPORTING ===
├── reporters.py            # HTML/PDF/JSON/SARIF output
├── network_reporter.py     # Network report generation
│
├── # === RELIABILITY ===
├── scan_checkpoint.py      # Scan checkpointing
└── scan_recovery.py        # Scan recovery
```

### Attack Modules (`attacks/`) - 4 Categories

```
attacks/
├── __init__.py             # AttackDispatcher - routes to scan type
├── scanner_registry.py     # Scanner registration
├── unified_registry.py     # Unified scanner registry
│
├── web/                    # Web security scanners
│   ├── __init__.py         # WebAttacks aggregator
│   │
│   ├── pre_login/          # 49 UNAUTHENTICATED SCANNERS
│   │   ├── __init__.py
│   │   ├── sqli_advanced_scanner.py
│   │   ├── xss_scanner.py, xss_advanced_scanner.py
│   │   ├── xss_reflected_scanner.py, xss_stored_scanner.py
│   │   ├── ssrf_scanner.py, ssrf_advanced_scanner.py
│   │   ├── csrf_scanner.py
│   │   ├── idor_scanner.py
│   │   ├── auth_scanner.py, auth_bypass_scanner.py
│   │   ├── injection_scanner.py
│   │   ├── jwt_scanner.py
│   │   ├── cors_scanner.py
│   │   ├── security_headers_scanner.py
│   │   ├── rate_limit_scanner.py
│   │   ├── file_upload_scanner.py, upload_scanner.py
│   │   ├── path_traversal_scanner.py
│   │   ├── xxe_scanner.py
│   │   ├── ssti_scanner.py
│   │   ├── open_redirect_scanner.py
│   │   ├── clickjacking_scanner.py
│   │   ├── graphql_scanner.py
│   │   ├── websocket_scanner.py
│   │   ├── oauth_scanner.py, oauth_saml_scanner.py
│   │   ├── session_scanner.py
│   │   ├── api_scanner.py, api_security_scanner.py
│   │   ├── ldap_injection_scanner.py
│   │   ├── host_header_scanner.py
│   │   ├── hpp_scanner.py
│   │   ├── smuggling_scanner.py
│   │   ├── prototype_pollution_scanner.py
│   │   ├── race_condition_scanner.py
│   │   ├── subdomain_takeover_scanner.py
│   │   ├── info_disclosure_scanner.py
│   │   ├── sensitive_data_scanner.py
│   │   ├── misconfig_scanner.py
│   │   ├── framework_scanner.py
│   │   ├── captcha_scanner.py
│   │   ├── business_logic_scanner.py
│   │   ├── access_control_scanner.py
│   │   ├── mobile_security_scanner.py
│   │   ├── response_manipulation_scanner.py
│   │   ├── response_swap_scanner.py
│   │   └── post_method_scanner.py
│   │
│   └── post_login/         # 5 AUTHENTICATED SCANNERS
│       ├── __init__.py
│       ├── idor_privesc_scanner.py
│       ├── csrf_postlogin_scanner.py
│       ├── xss_reflected_scanner_postlogin.py
│       ├── xss_stored_scanner_postlogin.py
│       └── post_method_scanner_postlogin.py
│
├── cloud/                  # 18 CLOUD SCANNERS
│   ├── __init__.py
│   ├── base.py
│   ├── aws_scanner.py
│   ├── azure_scanner.py, azure_scanner_complete.py
│   ├── gcp_scanner.py
│   ├── kubernetes_scanner.py
│   ├── container_scanner.py
│   ├── iac_scanner.py
│   ├── ciem_scanner.py
│   ├── data_security_scanner.py
│   ├── drift_scanner.py
│   ├── runtime_scanner.py
│   ├── compliance_mapper.py
│   └── sbom_generator.py
│
├── network/                # 10 NETWORK SCANNERS
│   ├── __init__.py
│   ├── base.py
│   ├── network_scanner.py
│   ├── port_scanner.py
│   ├── service_detector.py
│   ├── credential_scanner.py
│   ├── vuln_scanner.py
│   ├── metasploit_scanner.py
│   ├── orchestrator.py
│   ├── install_tools.py
│   └── scanners/           # Sub-scanners
│
└── mobile/                 # 22 MOBILE SCANNERS
    ├── __init__.py
    ├── static_analyzer.py
    ├── dynamic_crawler.py
    ├── mobile_scanner.py
    ├── mobile_orchestrator.py
    ├── mobile_post_scanner.py
    ├── emulator_manager.py
    ├── ios_simulator_manager.py
    ├── frida_ssl_bypass.py
    ├── llm_analyzer.py
    ├── otp_handler.py
    └── [12 more mobile modules]
```

### Database Layer (`database/`) - 14 Files

```
database/
├── __init__.py
├── models.py               # SQLAlchemy models (User, Scan, Finding)
├── crud.py                 # CRUD operations
├── connection.py           # Database connection
├── config.py               # Database config → data/jarwis.db
├── schemas.py              # Pydantic schemas
├── security.py             # Security utilities
├── auth.py                 # Auth utilities
├── cookie_auth.py          # Cookie authentication
├── dependencies.py         # FastAPI dependencies
├── otp.py                  # OTP database operations
├── subscription.py         # Subscription operations
├── setup.py                # Database setup
├── alembic.ini             # Alembic config
└── migrations/             # Database migrations
```

### Shared Contracts (`shared/`) - Single Source of Truth

```
shared/
├── __init__.py
├── api_endpoints.py        # ALL endpoint URLs
├── constants.py            # Plan limits, enums, settings
├── generate_frontend_types.py  # Generates JS config files
└── schemas/
    ├── __init__.py
    ├── auth.py             # Auth request/response schemas
    ├── scans.py            # Scan schemas
    ├── common.py           # Common schemas
    └── scanner_results.py  # Scanner result schemas
```

### Frontend (`jarwisfrontend/`) - React 19 Application

```
jarwisfrontend/
├── package.json
├── tailwind.config.js
├── postcss.config.js
│
└── src/
    ├── App.jsx             # Main app with routes
    ├── index.js            # React entry point
    │
    ├── services/           # API & EXTERNAL SERVICES
    │   ├── api.js          # ⭐ SINGLE API CLIENT (use only this!)
    │   ├── emailService.js
    │   ├── firebaseAuth.js
    │   └── paymentService.js
    │
    ├── config/             # CONFIGURATION
    │   ├── endpoints.generated.js  # Auto-generated (DON'T EDIT!)
    │   ├── constants.generated.js  # Auto-generated (DON'T EDIT!)
    │   └── planLimits.generated.js # Auto-generated (DON'T EDIT!)
    │
    ├── context/            # REACT CONTEXTS (7 contexts)
    │   ├── AuthContext.jsx
    │   ├── SubscriptionContext.jsx
    │   ├── ThemeContext.jsx
    │   ├── FirebaseAuthContext.jsx
    │   ├── UserManagementContext.jsx
    │   ├── UserApprovalContext.jsx
    │   └── ContactFormContext.jsx
    │
    ├── pages/              # PAGE COMPONENTS
    │   ├── auth/           # Login, Register, ForgotPassword
    │   ├── dashboard/      # Main dashboard pages
    │   ├── admin/          # Admin pages
    │   ├── cloud/          # Cloud scanning pages
    │   ├── Home.jsx, HomeNew.jsx
    │   ├── About.jsx, Contact.jsx
    │   ├── PricingPlans.jsx
    │   ├── Privacy.jsx, TermsofService.jsx
    │   └── NotFound.jsx
    │
    ├── components/         # REUSABLE COMPONENTS
    │   ├── common/         # Shared components
    │   ├── dashboard/      # Dashboard widgets
    │   ├── settings/       # Settings panels
    │   ├── auth/           # Auth components
    │   ├── cloud/          # Cloud components
    │   ├── scan/           # Scan components
    │   ├── landing/        # Landing page
    │   ├── layout/         # Layout components
    │   ├── payment/        # Payment components
    │   ├── subscription/   # Subscription components
    │   ├── ui/             # UI primitives
    │   ├── Header.jsx
    │   ├── Footer.jsx
    │   └── ProtectedRoute.jsx
    │
    └── styles/             # CSS/Tailwind styles
```

---

## 🔄 Scan Execution Flow

### Web Scanning - 6 Phases

```
Phase 1: Anonymous Crawl
    └── BrowserController (Playwright) discovers endpoints
    └── MITM Proxy captures requests/responses
    └── RequestStore saves pre-login traffic

Phase 2: Pre-Login Scan
    └── 49 attack modules test unauthenticated surfaces
    └── Uses captured requests from RequestStore
    └── Modifies and replays requests

Phase 3: Authentication
    └── Form-based login via CSS selectors
    └── Session/cookie capture

Phase 4: Post-Login Crawl
    └── Discover authenticated-only endpoints
    └── MITM captures post-login traffic
    └── RequestStore saves auth tokens

Phase 5: Post-Login Scan
    └── Re-runs ALL 49 pre-login scanners with auth
    └── Plus 5 dedicated post-login scanners
    └── IDOR, CSRF, privilege escalation focus

Phase 6: AI Planning & Reporting
    └── LLM recommends targeted tests
    └── Generate HTML/PDF/JSON/SARIF reports
```

### Scan Types

| Type | Runner | Scanners | Status |
|------|--------|----------|--------|
| **Web** | `core/web_scan_runner.py` | 49 pre + 5 post = 54 | ✅ Active |
| **Mobile** | `core/mobile_attack_engine.py` | 22 modules | ✅ Active |
| **Network** | `core/network_scan_runner.py` | 10 scanners | ✅ Active |
| **Cloud** | `core/cloud_scan_runner.py` | 18 scanners | ✅ Active |

---

## 🗄️ Database

**Single Location**: `data/jarwis.db` (SQLite)

### Key Models (`database/models.py`)

| Model | Purpose |
|-------|---------|
| `User` | User accounts, plans, approval status |
| `Scan` | Scan records, status, type |
| `Finding` | Vulnerability findings |
| `Domain` | Verified domains |
| `Subscription` | User subscriptions |
| `APIKey` | API keys for programmatic access |

---

## 🔒 Subscription Plans

| Plan | Scans/Month | Tokens/Month | Team Members |
|------|-------------|--------------|--------------|
| **Free** | 3 | 50,000 | 1 |
| **Professional** | 10 | 500,000 | 3 |
| **Enterprise** | Unlimited | 5,000,000 | Unlimited |

---

## 🔑 Test Credentials

| Type | Email | Password | Plan |
|------|-------|----------|------|
| **Super Admin** | akshaydevrari@gmail.com | Parilove@1 | enterprise |
| **Admin** | admin@jarwis.ai | admin123 | enterprise |
| **Individual** | user1@jarwis.ai | 12341234 | individual |
| **Professional** | user2@jarwis.ai | 12341234 | professional |
| **Enterprise** | user3@jarwis.ai | 12341234 | enterprise |

---

## 🚀 Running the Project

### Start Backend (Port 8000)
```powershell
cd D:\jarwis-ai-pentest
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
```

### Start Frontend (Port 3000)
```powershell
cd D:\jarwis-ai-pentest\jarwisfrontend
npm start
```

### Access Points
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Health**: http://localhost:8000/api/health
- **API Docs**: http://localhost:8000/docs

---

## ⚠️ Critical Rules

### 1. Layer Import Rules

```python
# ❌ NEVER DO THIS (core importing from api)
from api.routes.scans import some_function

# ✅ CORRECT (core imports from services)
from services.scan_service import some_function
```

### 2. Single API Client (Frontend)

```javascript
// ✅ ALWAYS use this
import api from '../services/api';

// ❌ NEVER create new API files
```

### 3. Database Location

```python
# ✅ ONLY location for database
DATABASE_URL = "sqlite:///data/jarwis.db"

# ❌ NEVER put database in root or database/
```

### 4. After Changing Contracts

```bash
# Always regenerate frontend types
python shared/generate_frontend_types.py
```

---

## 📊 Project Statistics

| Category | Count |
|----------|-------|
| **API Routes** | 19 files |
| **Services** | 13 files |
| **Core Modules** | 27 files |
| **Web Scanners** | 54 (49 pre + 5 post) |
| **Cloud Scanners** | 18 |
| **Network Scanners** | 10 |
| **Mobile Modules** | 22 |
| **React Contexts** | 7 |
| **Total Scanner Coverage** | 100+ modules |

---

## 📝 Documentation

| Document | Location | Purpose |
|----------|----------|---------|
| Implementation Rules | `docs/implementation_rules/` | Architecture guides |
| Copilot Instructions | `.github/copilot-instructions.md` | AI assistant context |
| Scan Flow | `.copilot_memory/SCAN_FLOW.md` | MITM-based scan flow |
| This File | `.copilot_memory/ARCHITECTURE.md` | Project architecture |

---

*Last verified: January 9, 2026 - All systems operational*
