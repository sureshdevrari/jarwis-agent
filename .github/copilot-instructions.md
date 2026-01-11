# Jarwis AGI Pen Test - Copilot Instructions

> ⚠️ **AI MUST READ**: Before making changes, read the detailed guides in [`docs/implementation_rules/`](../docs/implementation_rules/README.md):
> - [01_ROOT_ARCHITECTURE.md](../docs/implementation_rules/01_ROOT_ARCHITECTURE.md) - Layered architecture
> - [02_SCAN_FLOW.md](../docs/implementation_rules/02_SCAN_FLOW.md) - Scan execution phases
> - [03_LAYERED_RULES.md](../docs/implementation_rules/03_LAYERED_RULES.md) - Import rules (CRITICAL!)
> - [04_FRONTEND_INTEGRATION.md](../docs/implementation_rules/04_FRONTEND_INTEGRATION.md) - React patterns
> - [05_EXTENSION_PLAYBOOK.md](../docs/implementation_rules/05_EXTENSION_PLAYBOOK.md) - Step-by-step guides
> - [06_AI_CHECKLIST.md](../docs/implementation_rules/06_AI_CHECKLIST.md) - Pre-commit validation

---

## ⚠️ CRITICAL: Existing File Structure (DO NOT CREATE DUPLICATES)

Before creating ANY file or folder, CHECK if it already exists. The project has an established structure:

### Root-Level Files (Already Exist - DO NOT RECREATE)
```
D:\jarwis-ai-pentest\
├── main.py                 # CLI entry point (ONLY startup file at root!)
├── requirements.txt        # Python dependencies
├── package.json            # Node dependencies
├── .env                    # Environment variables
├── README.md               # Project readme
└── .gitignore              # Git ignore rules
```

### Project Folder Organization
```
D:\jarwis-ai-pentest\
│
├── 🏗️ CORE APPLICATION (Python backend)
│   ├── api/                # FastAPI routes and server
│   ├── core/               # Scan engines, orchestrators
│   ├── services/           # Business logic layer
│   ├── database/           # SQLAlchemy models, migrations
│   ├── shared/             # Contracts, schemas, constants
│   └── attacks/            # Scanner modules (web/mobile/network/cloud)
│
├── 💻 FRONTEND
│   └── jarwisfrontend/     # React application
│
├── ⚙️ CONFIGURATION
│   ├── config/             # YAML configs, OAuth credentials
│   └── templates/          # HTML report templates
│
├── 📚 DOCUMENTATION
│   └── docs/               # All documentation consolidated here
│       ├── architecture/   # Architecture diagrams
│       ├── developer/      # Developer notes & requirements
│       ├── design/         # UI/UX design specs
│       ├── reminders/      # TODO notes
│       └── cloud/          # Cloud-specific docs
│
├── 🚀 DEPLOYMENT & DEVOPS
│   └── deploy/             # All deployment files
│       ├── docker/         # docker-compose, Dockerfiles, nginx
│       ├── scripts/        # deploy.ps1, deploy.sh, install scripts
│       └── deployment_manifest.json
│
├── 🔧 SCRIPTS & UTILITIES
│   └── scripts/            # All utility scripts
│       ├── startup/        # start_jarwis.ps1, start_server.py, etc.
│       ├── utilities/      # diagnose_api.ps1, cleanup.ps1, etc.
│       └── [other scripts] # admin, dev, migration scripts
│
├── 🧪 TESTING
│   └── tests/              # Pytest test files
│
├── 🎨 ASSETS
│   └── assets/             # Media and AI training data
│       ├── logos/          # Logo files (JPG/PNG/SVG)
│       └── ai-training/    # LLM training data, Modelfile
│
├── 📁 GENERATED DATA (gitignored)
│   └── data/               # All generated/runtime files
│       ├── logs/           # Server logs
│       ├── reports/        # Scan reports (HTML/JSON/PDF)
│       ├── uploads/        # User uploads (mobile APKs)
│       ├── temp/           # Temporary scan data
│       └── jarwis.db       # SQLite database
│
└── 🔒 HIDDEN FOLDERS
    ├── .git/               # Git repository
    ├── .github/            # GitHub workflows, copilot-instructions
    ├── .venv/              # Python virtual environment
    ├── .vscode/            # VS Code settings
    └── .copilot_memory/    # AI assistant context
```

### API Layer (api/) - COMPLETE
```
api/
├── server.py              # FastAPI app entry (uvicorn runs this)
├── app.py                 # Legacy Flask app (deprecated, use server.py)
├── startup_checks.py      # Health checks on startup
├── __init__.py
└── routes/
    ├── __init__.py        # Route aggregator
    ├── auth.py            # /api/auth/* endpoints
    ├── scans.py           # /api/scans/* endpoints
    ├── dashboard.py       # /api/dashboard/* endpoints
    ├── mobile.py          # /api/scan/mobile/* endpoints
    ├── network.py         # /api/network/* endpoints
    ├── cloud.py           # /api/cloud/* endpoints
    ├── chat.py            # /api/chat/* endpoints
    ├── chat_gateway.py    # Token tracking for AI chat
    ├── domains.py         # /api/domains/* endpoints
    ├── health.py          # /api/health endpoint
    ├── oauth.py           # /api/oauth/* endpoints
    ├── two_factor.py      # /api/2fa/* endpoints
    ├── payments.py        # /api/payments/* endpoints
    ├── users.py           # /api/users/* endpoints
    ├── admin.py           # /api/admin/* endpoints
    ├── api_keys.py        # /api/api-keys/* endpoints
    ├── contact.py         # /api/contact/* endpoints
    ├── scan_manual_auth.py # Manual auth scan endpoints
    └── scan_otp.py        # OTP handling for scans
```

### Services Layer (services/) - COMPLETE
```
services/
├── __init__.py
├── auth_service.py        # Authentication logic
├── scan_service.py        # Scan CRUD operations
├── subscription_service.py # Plan/billing logic
├── dashboard_service.py   # Dashboard stats
├── otp_service.py         # OTP generation/verification
├── mobile_service.py      # Mobile scan logic
├── network_service.py     # Network scan logic
├── cloud_service.py       # Cloud scan logic
├── domain_service.py      # Domain management
├── domain_verification_service.py # Domain verification
├── agent_service.py       # Jarwis agent communication
├── manual_auth_service.py # Manual auth flow
└── scan_state_machine.py  # Scan state transitions
```

### Core Engines (core/) - COMPLETE
```
core/
├── __init__.py
├── runner.py              # PenTestRunner (main orchestrator)
├── web_scan_runner.py     # Web scanning phases
├── browser.py             # BrowserController (Playwright)
├── mobile_attack_engine.py # Mobile app analysis
├── network_scan_runner.py # Network scanning
├── cloud_scan_runner.py   # Cloud scanning
├── reporters.py           # Report generation (HTML/PDF/JSON/SARIF)
├── ai_planner.py          # LLM integration (Ollama/OpenAI)
├── ai_verifier.py         # AI-powered verification
├── chatbot.py             # AI chatbot (Gemini)
├── http_helper.py         # HTTP utilities
├── scope.py               # Scope validation
├── attack_engine.py       # Attack coordination
├── scanner_registry.py    # Scanner registration
├── detection_logic.py     # Vulnerability detection
├── proxy.py               # Proxy handling
├── mitm_proxy.py          # MITM proxy
├── mitm_addon.py          # MITM addon
├── request_store.py       # Request storage
├── preflight_validator.py # Pre-scan validation
├── scan_checkpoint.py     # Scan checkpointing
├── scan_recovery.py       # Scan recovery
├── unified_executor.py    # Unified scan execution
├── tool_registry.py       # Tool registration
├── network_reporter.py    # Network report generation
├── cloud_graph.py         # Cloud resource graphing
└── cloud_scanner_registry.py # Cloud scanner registration
```

### Attack Modules (attacks/) - COMPLETE
```
attacks/
├── __init__.py            # AttackDispatcher - routes to scan type
├── scanner_registry.py    # Scanner registration (also in shared/)
├── unified_registry.py    # Unified scanner registry (also in shared/)
├── web/                   # Web security scanners
│   ├── __init__.py        # WebAttacks aggregator
│   ├── pre_login/         # 45+ unauthenticated scanners
│   │   ├── __init__.py
│   │   ├── sqli_advanced_scanner.py
│   │   ├── xss_scanner.py, xss_advanced_scanner.py, xss_reflected_scanner.py, xss_stored_scanner.py
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
│   │   └── response_swap_scanner.py
│   └── post_login/        # Authenticated scanners
│       ├── __init__.py
│       ├── idor_privesc_scanner.py
│       ├── csrf_postlogin_scanner.py
│       ├── xss_reflected_scanner_postlogin.py
│       ├── xss_stored_scanner_postlogin.py
│       └── post_method_scanner_postlogin.py
├── cloud/                 # Cloud security scanners
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
├── network/               # Network scanners
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
│   └── scanners/          # Sub-scanners
└── mobile/                # Mobile app scanners
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
    └── [other mobile scanners]
```

### Database Layer (database/) - COMPLETE
```
database/
├── __init__.py
├── models.py              # SQLAlchemy models (User, Scan, Finding, etc.)
├── crud.py                # CRUD operations
├── db.py / connection.py  # Database connection
├── config.py              # Database config
├── schemas.py             # Pydantic schemas
├── security.py            # Security utilities
├── auth.py                # Auth utilities
├── cookie_auth.py         # Cookie authentication
├── dependencies.py        # FastAPI dependencies
├── otp.py                 # OTP database operations
├── subscription.py        # Subscription database operations
├── setup.py               # Database setup
├── alembic.ini            # Alembic config
├── migrations/            # Database migrations
└── jarwis.db              # SQLite database file
```

### Shared Contracts (shared/) - COMPLETE
```
shared/
├── __init__.py
├── api_endpoints.py       # ALL endpoint URLs (single source of truth)
├── constants.py           # Plan limits, enums, settings
├── generate_frontend_types.py  # Generates JS config files
└── schemas/
    ├── __init__.py
    ├── auth.py            # Auth request/response schemas
    ├── scans.py           # Scan schemas
    ├── common.py          # Common schemas
    └── scanner_results.py # Scanner result schemas
```

### Frontend (jarwisfrontend/) - COMPLETE
```
jarwisfrontend/
├── package.json
├── src/
│   ├── App.jsx            # Main React app with routes
│   ├── index.js           # React entry point
│   ├── services/
│   │   ├── api.js         # ⭐ SINGLE API CLIENT (use this only!)
│   │   ├── emailService.js
│   │   ├── firebaseAuth.js
│   │   └── paymentService.js
│   ├── config/
│   │   ├── endpoints.generated.js  # Auto-generated (don't edit!)
│   │   ├── constants.generated.js  # Auto-generated (don't edit!)
│   │   ├── planLimits.generated.js # Auto-generated (don't edit!)
│   │   ├── planLimits.js          # Manual plan limits
│   │   └── features.js            # Feature flags
│   ├── context/
│   │   ├── AuthContext.jsx
│   │   ├── SubscriptionContext.jsx
│   │   ├── ThemeContext.jsx
│   │   ├── FirebaseAuthContext.jsx
│   │   ├── UserManagementContext.jsx
│   │   ├── UserApprovalContext.jsx
│   │   └── ContactFormContext.jsx
│   ├── pages/
│   │   ├── auth/
│   │   │   ├── Login.jsx, Register.jsx, ForgotPassword.jsx, etc.
│   │   ├── dashboard/
│   │   │   ├── JarwisDashboard.jsx    # Main dashboard
│   │   │   ├── NewScan.jsx            # Create new scan
│   │   │   ├── ScanHistory.jsx        # Past scans
│   │   │   ├── Scanning.jsx           # Scan in progress
│   │   │   ├── Vulnerabilities.jsx    # Findings list
│   │   │   ├── VulnerabilityDetails.jsx
│   │   │   ├── Reports.jsx            # Report downloads
│   │   │   ├── Settings.jsx           # User settings
│   │   │   ├── Billing.jsx            # Billing page
│   │   │   ├── JarwisChatbot.jsx      # AI chatbot
│   │   │   ├── CloudDashboard.jsx     # Cloud scanning
│   │   │   ├── VerifyDomain.jsx       # Domain verification
│   │   │   └── SyndashDashboard.jsx   # Alternative dashboard
│   │   ├── admin/
│   │   │   ├── AdminOverview.jsx
│   │   │   ├── AdminUsersAndTenants.jsx
│   │   │   ├── AdminUserDetails.jsx
│   │   │   ├── AdminAuditLog.jsx
│   │   │   ├── AdminAccessRequests.jsx
│   │   │   ├── AdminContactSubmissions.jsx
│   │   │   └── AdminPushVulnerability.jsx
│   │   ├── cloud/                     # Cloud-specific pages
│   │   ├── Home.jsx, HomeNew.jsx
│   │   ├── About.jsx
│   │   ├── Contact.jsx
│   │   ├── PricingPlans.jsx
│   │   ├── Privacy.jsx
│   │   ├── TermsofService.jsx
│   │   └── NotFound.jsx
│   ├── components/
│   │   ├── common/                    # Shared components
│   │   ├── dashboard/                 # Dashboard components
│   │   ├── settings/                  # Settings panels
│   │   ├── auth/                      # Auth components
│   │   ├── cloud/                     # Cloud components
│   │   ├── scan/                      # Scan components
│   │   ├── landing/                   # Landing page components
│   │   ├── layout/                    # Layout components
│   │   ├── payment/                   # Payment components
│   │   ├── subscription/              # Subscription components
│   │   ├── ui/                        # UI primitives
│   │   ├── Header.jsx
│   │   ├── Footer.jsx
│   │   └── ProtectedRoute.jsx
│   ├── routes/                        # Route definitions
│   ├── styles/                        # CSS/Tailwind styles
│   └── firebase/                      # Firebase config
```

### Other Important Directories
```
config/                    # YAML configuration files
├── config.yaml            # Main config
├── config.local.yaml      # Local overrides
├── google_oauth_credentials.json
└── secrets/               # Sensitive files (gitignored)
    ├── key.txt            # API keys reference
    └── .gitkeep

templates/                 # Report templates (used by core/reporters.py)
├── report_template.html
├── report_template_v2.html
└── report_template_v3.html

deploy/                    # DevOps and deployment
├── docker/                # Docker files
│   ├── docker-compose.yml
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── nginx.conf
├── scripts/               # Deployment scripts
│   ├── deploy.ps1
│   ├── deploy.sh
│   └── install_jarwis_tools.sh
└── deployment_manifest.json

scripts/                   # Utility scripts
├── startup/               # Server startup scripts
│   ├── start_jarwis.ps1
│   ├── start_jarwis.py
│   ├── start_server.py
│   ├── start_server_windows.py
│   ├── start_backend.bat
│   ├── start_frontend.bat
│   └── start_dev.ps1
├── utilities/             # Diagnostic and maintenance
│   ├── diagnose_api.ps1
│   ├── monitor_services.ps1
│   ├── cleanup.ps1
│   └── restore.ps1
└── [35+ other scripts]    # Admin, dev, migration scripts

assets/                    # Media and AI training
├── logos/                 # Logo files (JPG/PNG/SVG)
└── ai-training/           # LLM training data

data/                      # Generated files (gitignored)
├── logs/                  # Application logs
├── reports/               # Generated reports
├── uploads/               # User uploads (mobile APKs)
│   └── mobile/
├── temp/                  # Temporary scan data
└── jarwis.db              # SQLite database

docs/                      # All documentation
├── architecture/          # Architecture diagrams (was architecture_flow/)
├── developer/             # Developer notes (was developer_input/)
├── design/                # UI/UX specs (was frontend-design/)
├── reminders/             # TODO notes (was reminders/)
├── cloud/                 # Cloud documentation
└── [other docs]           # ARCHITECTURE.md, guides, etc.

tests/                     # Python tests
├── test_scope.py

docs/implementation_rules/ # Architecture documentation
├── README.md
├── 01_ROOT_ARCHITECTURE.md
├── 02_SCAN_FLOW.md
├── 03_LAYERED_RULES.md
├── 04_FRONTEND_INTEGRATION.md
├── 05_EXTENSION_PLAYBOOK.md
└── 06_AI_CHECKLIST.md
```

---

## Architecture Overview

Jarwis is an AI-powered OWASP Top 10 penetration testing framework with a **phased execution model**:

1. **Phase 1 - Anonymous Crawl**: `BrowserController` (Playwright) discovers endpoints
2. **Phase 2 - Pre-Login Scan**: Attack modules test unauthenticated surfaces
3. **Phase 3 - Authentication**: Form-based login via selectors
4. **Phase 4 - Post-Login Scan**: Authenticated testing (IDOR, CSRF, PrivEsc)
5. **Phase 5 - AI Planning**: LLM recommends targeted tests based on findings
6. **Phase 6 - Reporting**: Multi-format output (HTML, JSON, SARIF)

**Core orchestration**: [core/runner.py](core/runner.py) (`PenTestRunner`) coordinates all phases and maintains `ScanContext` state across components.

## Layered Architecture (NEW!)

The project follows a **contract-first, layered architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                        FRONTEND                              │
│   jarwisfrontend/src/services/api.js (single API client)    │
│   jarwisfrontend/src/config/*.generated.js (auto-generated) │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                      API ROUTES                              │
│   api/routes/*.py (HTTP handling only, no business logic)   │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                       SERVICES                               │
│   services/*.py (all business logic lives here)             │
│   - auth_service.py, scan_service.py, otp_service.py        │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                    CORE ENGINES                              │
│   core/*.py (scanner logic, no API imports!)                │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                       DATABASE                               │
│   database/*.py (data access only)                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   SHARED CONTRACTS                           │
│   shared/api_endpoints.py   - All endpoint URLs             │
│   shared/constants.py       - Plan limits, settings         │
│   shared/schemas/*.py       - Pydantic models               │
│   shared/generate_frontend_types.py - Generates JS files    │
└─────────────────────────────────────────────────────────────┘
```

### Key Rules
1. **API Routes** only handle HTTP (parse request → call service → return response)
2. **Services** contain ALL business logic (auth, subscriptions, OTP, etc.)
3. **Core** modules NEVER import from `api.routes.*` (use services instead)
4. **Shared** is the single source of truth for endpoints and constants
5. Run `python shared/generate_frontend_types.py` after changing contracts

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `PenTestRunner` | [core/runner.py](core/runner.py) | Main orchestrator, config normalization |
| `BrowserController` | [core/browser.py](core/browser.py) | Playwright automation, endpoint discovery |
| `AIPlanner` | [core/ai_planner.py](core/ai_planner.py) | Ollama/OpenAI LLM integration |
| `PreLoginAttacks` | [attacks/pre_login/__init__.py](attacks/pre_login/__init__.py) | Scanner aggregator |
| `ReportGenerator` | [core/reporters.py](core/reporters.py) | HTML/JSON/SARIF/PDF output |
| **Services** | [services/](services/) | Business logic layer |
| **Contracts** | [shared/](shared/) | Single source of truth |

## Adding New Attack Scanners

New scanners go in `attacks/pre_login/` or `attacks/post_login/`. Follow this pattern:

```python
# attacks/pre_login/new_scanner.py
from dataclasses import dataclass

@dataclass
class ScanResult:  # Must match this structure
    id: str
    category: str  # OWASP category: A01, A02, A03, etc.
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    poc: str = ""  # Proof of concept payload
    reasoning: str = ""  # Why detected as vulnerability

class NewScanner:
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context  # ScanContext with endpoints, cookies, etc.
    
    async def scan(self) -> List[ScanResult]:
        # Access discovered endpoints via self.context.endpoints
        pass
```

**Register new scanner** in [attacks/pre_login/__init__.py](attacks/pre_login/__init__.py) within `PreLoginAttacks.__init__()`.

## Configuration System

Config flows: YAML file → `PenTestRunner._normalize_config()` → deep-merged with defaults.

Key config sections in [config/config.yaml](config/config.yaml):
- `target.url` / `target.scope` - scanning boundaries
- `auth.selectors` - login form CSS selectors
- `attacks.owasp.*` - enable/disable scanner modules
- `ai.provider` - "ollama" or "openai"

Interactive CLI (`main.py`) builds config dict directly; API (`api/app.py`) accepts JSON.

## Running & Testing

```bash
# Interactive mode
python main.py

# With config file
python main.py --config config/config.local.yaml

# Run pytest
pytest tests/ -v --asyncio-mode=auto
```

**Flask API** at `api/app.py` for frontend integration (scans run in background threads).

## Code Conventions

- **Async everywhere**: All scanners use `async def scan()`, browser/HTTP operations are async
- **Rate limiting**: Respect `config['rate_limit']` - use `await asyncio.sleep(1 / self.rate_limit)`
- **Scope checking**: Always validate URLs against target domain before testing
- **Rich console**: Use `rich.console.Console` for CLI output, not print()
- **Burp-style formatting**: Request/response evidence uses `_format_request()`/`_format_response()` helpers

## LLM Integration Notes

`AIPlanner` in [core/ai_planner.py](core/ai_planner.py):
- Defaults to Ollama at `localhost:11434` with `llama3.1`
- Falls back to mock responses if Ollama unavailable
- JSON-only responses expected from LLM (see `SYSTEM_PROMPT`)
- Returns `TestRecommendation` dataclass with tool, target, payload_type

Chatbot in [core/chatbot.py](core/chatbot.py):
- Uses Google Gemini (`gemini-2.0-flash`) as primary
- Token tracking is per-month in `chat_gateway.py`
- Limits: Free 50K, Pro 500K, Enterprise 5M tokens/month

## Frontend Architecture

| Component | Location | Purpose |
|-----------|----------|---------|
| `api.js` | [jarwisfrontend/src/services/api.js](jarwisfrontend/src/services/api.js) | **Single API client** (use this!) |
| `endpoints.generated.js` | [jarwisfrontend/src/config/endpoints.generated.js](jarwisfrontend/src/config/endpoints.generated.js) | Auto-generated endpoints |
| `planLimits.generated.js` | [jarwisfrontend/src/config/planLimits.generated.js](jarwisfrontend/src/config/planLimits.generated.js) | Auto-generated plan limits |
| `JarwisDashboard` | [jarwisfrontend/src/pages/dashboard/JarwisDashboard.jsx](jarwisfrontend/src/pages/dashboard/JarwisDashboard.jsx) | Main dashboard with stats |
| `SettingsPanel` | [jarwisfrontend/src/components/settings/SettingsPanel.jsx](jarwisfrontend/src/components/settings/SettingsPanel.jsx) | User settings, billing, preferences |
| `JarwisChatbot` | [jarwisfrontend/src/pages/dashboard/JarwisChatbot.jsx](jarwisfrontend/src/pages/dashboard/JarwisChatbot.jsx) | AI chatbot with token tracking |

### Frontend Development Rules
1. **NEVER create new API files** - use `services/api.js` only
2. **Use generated configs** - import from `config/*.generated.js`
3. **After changing Python contracts** - run `python shared/generate_frontend_types.py`
4. **Deprecated: `src/api.js`** - this file redirects to services/api.js

## Subscription Model

**Important**: Only **scans** matter for subscription limits, NOT websites.

| Plan | Scans/Month | Tokens/Month | Team Members |
|------|-------------|--------------|--------------|
| Free | 3 | 50,000 | 1 |
| Professional | 10 | 500,000 | 3 |
| Enterprise | Unlimited | 5,000,000 | Unlimited |

Plan limits defined in `planLimits.js`. Token tracking is **monthly** (not daily).

## PDF Generation

PDF generation uses **Playwright** (not WeasyPrint - fails on Windows due to GTK dependencies).

```python
# In core/reporters.py - use async wrapper for Playwright sync API
async def generate_pdf_async(self, html_path, output_path):
    return await asyncio.to_thread(self._generate_pdf_sync, html_path, output_path)
```

## Windows-Specific Notes

- **Server stability**: Run servers in separate PowerShell windows, not VS Code terminal
- **PDF generation**: Use Playwright with `asyncio.to_thread()` wrapper
- **Python venv**: Always use `.\.venv\Scripts\python.exe` for commands
- **Ports**: Backend 8000, Frontend 3000 - check with `netstat -ano | findstr ":8000.*LISTEN"`

```powershell
# Start servers in separate windows (prevents VS Code terminal from killing them)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd D:\jarwis-ai-pentest; .\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd D:\jarwis-ai-pentest\jarwisfrontend; npm start"
```

## Test Credentials (Updated January 10, 2026)

| Type | Email | Password | Plan |
|------|-------|----------|------|
| **Super Admin** | akshaydevrari@gmail.com | Parilove@1 | enterprise |
| **Admin** | admin@jarwis.ai | admin123 | enterprise |
| **Developer** | dev@jarwis.ai | 12341234 | developer |
| **Individual** | user1@jarwis.ai | 12341234 | individual |
| **Professional** | user2@jarwis.ai | 12341234 | professional |
| **Enterprise** | user3@jarwis.ai | 12341234 | enterprise |

**Developer Plan Features:**
- ⚠️ FOR TESTING ONLY - Remove before production!
- Unlimited scans, tokens, team members
- All features enabled (web, mobile, cloud, network, SAST)
- **Bypasses domain verification** for credential-based scans
- NOT an admin (can't access admin panel)
- Can test any feature without restrictions

**Helper Scripts (in `scripts/` folder):**
- `scripts/add_developer_user.py` - Create/update the developer test user
- `scripts/update_all_users.py` - Reset all user credentials to above values
- `tests/test_all_apis.py` - Comprehensive API test (auth, web, mobile, network scans)

## Current System Status (Last Verified: January 11, 2026)

All scan types working:
- ✅ **Web Scanning**: Full OWASP Top 10 phases with complete data flow
- ✅ **Mobile Scanning**: APK/IPA upload and analysis
- ✅ **Network Scanning**: Requires agent for private IPs, direct for public IPs
- ✅ **Cloud Scanning**: AWS/Azure/GCP security assessments
- ✅ **Authentication**: All user types login correctly
- ✅ **Frontend**: React app on port 3000
- ✅ **Backend**: FastAPI on port 8000

### Web Scan Data Flow (January 11, 2026)

**Complete pipeline from UI to scanner:**
```
ScanWizard.jsx → api.js → scans.py → runner_config → WebScanRunner
```

**Fields now flowing correctly:**
- ✅ `target_url` (auto-normalized with https://)
- ✅ `scan_name` (user-friendly label)
- ✅ `scan_profile` (full/quick/api/authenticated → affects crawl & attacks)
- ✅ `rate_limit` (requests per second)
- ✅ `scope` (regex patterns for scan boundaries)
- ✅ `auth_method` (username_password, phone_otp, social_login, manual_session)
- ✅ `phone_number` (for phone OTP auth)
- ✅ `session_cookie`, `session_token` (for manual session)
- ✅ `social_providers` (for social login: google, facebook, etc.)
- ✅ `two_factor` config (enabled, type, email, phone)
- ✅ `report_formats` (configurable output formats)
- ✅ `proxy.enabled`, `proxy.port` (proxy settings)
- ✅ `timeout` (request timeout)
- ✅ `can_resume` (checkpoint recovery support)

---

## 🚫 DO NOT CREATE DUPLICATES - Check First!

### Before Creating ANY File:
1. **Search the workspace** using file_search or list_dir
2. **Check the structure above** - most files already exist
3. **Extend existing files** instead of creating new ones

### Common Mistakes to AVOID:
```
❌ Creating api/routes/scan.py when api/routes/scans.py exists
❌ Creating services/scan.py when services/scan_service.py exists  
❌ Creating jarwisfrontend/src/api.js when services/api.js exists
❌ Creating new context files when they exist in context/
❌ Creating attacks/pre_login/ at root (use attacks/web/pre_login/)
❌ Creating core/scanner.py when core/runner.py exists
❌ Creating start_*.py at root (use scripts/startup/)
❌ Creating logs/ or reports/ at root (use data/logs/, data/reports/)
❌ Creating Dockerfile at root (use deploy/docker/)
❌ Creating architecture_flow/ or developer_input/ (use docs/architecture/, docs/developer/)
```

### Where to Add New Code:
| Want to Add | Put It In |
|-------------|-----------|
| New API endpoint | `api/routes/` - extend existing file or create new route file |
| New business logic | `services/` - extend existing service or create new *_service.py |
| New scanner | `attacks/web/pre_login/` or `attacks/web/post_login/` |
| New cloud check | `attacks/cloud/` |
| New network check | `attacks/network/` |
| New mobile check | `attacks/mobile/` |
| New frontend page | `jarwisfrontend/src/pages/dashboard/` |
| New component | `jarwisfrontend/src/components/` (check existing folders first) |
| New API call | Use existing `services/api.js` - NEVER create new API files |
| New constants | `shared/constants.py` then regenerate frontend types |
| New endpoint URL | `shared/api_endpoints.py` then regenerate frontend types |
| New startup script | `scripts/startup/` |
| New utility script | `scripts/utilities/` or `scripts/` root |
| New Docker/deploy file | `deploy/docker/` or `deploy/scripts/` |
| New documentation | `docs/` in appropriate subfolder |
| New logo/asset | `assets/logos/` |
| AI training data | `assets/ai-training/` |
