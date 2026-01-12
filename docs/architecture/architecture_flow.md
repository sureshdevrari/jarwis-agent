# Jarwis Architecture Flow (AI-Friendly Diagram)

This diagram is structured for LLM/AI parsing and reflects the layered architecture, main flows, and key responsibilities.

## Web Scan Data Pipeline (Updated January 11, 2026)

```mermaid
flowchart TB
    subgraph Step1[Step 1: Frontend UI]
        FE1[ScanWizard.jsx
- Target URL (auto https://)
- Scan profile: full/quick/api/authenticated
- Auth method: password/phone_otp/social/manual
- 2FA config: email/sms/authenticator
- Scope patterns]
    end

    subgraph Step2[Step 2: API Layer]
        FE2[api.js startScan()
- Transform to backend format
- Auto-detect auth_method
- Build two_factor config]
    end

    subgraph Step3[Step 3: Backend API]
        BE1[scans.py POST /api/scans/
- ScanCreate validation
- crud.create_scan()
- Background task spawn]
    end

    subgraph Step4[Step 4: Runner Config]
        BE2[_build_runner_config()
- scope from config
- rate_limit from config
- report_formats from config
- attacks based on scan_profile]
    end

    Step1 -->|handleStartScan| Step2
    Step2 -->|POST /api/scans/| Step3
    Step3 -->|BackgroundTask| Step4
    Step4 -->|WebScanRunner| Phases

    subgraph Phases[6 Execution Phases]
        P1[Phase 1: Anonymous Crawl]
        P2[Phase 2: Pre-Login Attacks]
        P3[Phase 3: Authentication]
        P4[Phase 4: Post-Login Crawl]
        P5[Phase 5: Post-Login Attacks]
        P6[Phase 6: Reporting]
    end
```

## Layered Architecture

```mermaid
flowchart TB
    subgraph Frontend
        FE[React (jarwisfrontend)
- Single API client: services/api.js
- Generated configs: config/*.generated.js
- ScanWizard: Multi-step wizard]
    end

    subgraph API_Routes[API Routes (FastAPI)]
        AR[api/routes/*.py
- HTTP parsing only
- Uses shared endpoints & schemas]
    end

    subgraph Services
        SV[services/*.py
- All business logic
- Auth, scan, subscription, dashboard, OTP]
    end

    subgraph Core[Core Engines]
        CR[core/*.py
- PenTestRunner orchestrates
- Web/mobile/network/cloud runners
- Reporting (HTML/JSON/SARIF/PDF)]
    end

    subgraph Attacks[Attack Modules]
        AT[attacks/web/a01-a10/* OWASP organized
attacks/cloud/* provider-based
attacks/mobile/* phase-based
- 99 scanners total via registry.py]
    end

    subgraph Database
        DB[(database/*.py
- SQLAlchemy models & session)]
    end

    subgraph Shared[Shared Contracts]
        SH[shared/api_endpoints.py
shared/constants.py
shared/schemas/*.py]
    end

    FE -->|HTTP (ENDPOINTS)| AR
    AR -->|Calls| SV
    SV -->|Coordinates| CR
    CR -->|Invokes| AT
    SV -->|Persist/load| DB
    CR -->|Persist findings| DB
    SH --> AR
    SH --> SV
    SH --> CR
    SH --> AT
```

## Authentication Methods Supported

| Method | Fields | Use Case |
|--------|--------|----------|
| `username_password` | login_url, username, password | Traditional form login |
| `phone_otp` | phone_number | OTP sent to phone |
| `social_login` | social_providers[] | OAuth (Google, Facebook, etc.) |
| `manual_session` | session_cookie, session_token | Pre-authenticated sessions |

## 2FA Configuration

| Type | Field | Description |
|------|-------|-------------|
| `email` | two_factor.email | OTP sent to email |
| `sms` | two_factor.phone | OTP sent to SMS |
| `authenticator` | - | TOTP app (Google Authenticator) |

## Scan Profiles

| Profile | Max Pages | Depth | Use Case |
|---------|-----------|-------|----------|
| `full` | 100 | 4 | Complete security audit |
| `quick` | 25 | 2 | Fast reconnaissance |
| `api` | 50 | 3 | API-focused testing |
| `authenticated` | 150 | 5 | Deep authenticated testing |

## Notes
- Layers are contract-first; Shared is the single source of truth for endpoints/constants/schemas.
- Services enforce plan limits, permissions, and coordination; routes stay thin.
- Frontend must use generated configs and the single API client.
- PDF generation uses Playwright via async wrapper.
- All auth fields flow from frontend → api.js → backend → runner_config → scanner.
