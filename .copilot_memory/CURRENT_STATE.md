# Jarwis AGI Pen Test - Project Memory

> Last Updated: January 6, 2026 (Evening)

## 🎯 Project Overview

**Jarwis** is an AI-powered OWASP Top 10 penetration testing framework with comprehensive security scanning capabilities for web applications, networks, mobile apps, and cloud infrastructure.

### Current Development Status
- **Backend**: FastAPI server via `api/server.py` (uvicorn on port 8000)
- **Frontend**: React 19 app in `jarwisfrontend/` (port 3000)
- **Virtual Env**: `.venv/` (Python)
- **AI Backend**: Ollama at localhost:11434 (llama3/llama3.1)
- **Database**: SQLite with async SQLAlchemy

### Key Features
- AI-powered vulnerability detection using Ollama/OpenAI LLMs
- OWASP Top 10 comprehensive coverage
- Multi-phase scanning (anonymous crawl → pre-login → auth → post-login)
- Browser-based JavaScript rendering via Playwright
- MITM proxy for HTTPS interception
- Professional PDF/HTML/SARIF report generation
- React frontend with Firebase authentication
- Subscription-based access with Stripe payments

---

## 📁 Project Structure

```
jarwis-ai-pentest/
├── core/                    # Core scanning engine
│   ├── runner.py           # Main orchestrator (PenTestRunner)
│   ├── browser.py          # Playwright browser automation (2509 lines)
│   ├── ai_planner.py       # LLM integration (AIPlanner)
│   ├── reporters.py        # PDF/HTML/SARIF reports
│   ├── mitm_proxy.py       # MITM HTTPS interception
│   ├── scope.py            # Domain scope management
│   └── ai_verifier.py      # AI request watcher
│
├── attacks/                 # Attack modules
│   ├── pre_login/          # Unauthenticated scanners (20+ modules)
│   ├── post_login/         # Authenticated scanners
│   ├── network/            # Network security scanning
│   ├── mobile/             # Android/iOS testing (Frida, ADB)
│   └── cloud/              # AWS/Azure/GCP scanners
│
├── api/                     # FastAPI backend
│   ├── app.py              # Main FastAPI app
│   └── routes/             # API endpoints (14 route modules)
│
├── database/               # SQLAlchemy models
│   ├── models.py           # User, Scan, Report models
│   ├── connection.py       # Async DB connection
│   └── auth.py             # Authentication logic
│
├── jarwisfrontend/         # React frontend
│   └── src/
│       ├── components/     # UI components
│       ├── pages/          # Page components
│       ├── services/       # API services
│       └── firebase/       # Firebase config
│
├── config/                  # Configuration
│   └── config.yaml         # Default config template
│
├── main.py                  # CLI entry point
└── start_server.py          # API server launcher
```

---

## 🔧 Core Components

### 1. PenTestRunner (`core/runner.py`)
Main orchestrator that coordinates all scanning phases:

```python
@dataclass
class ScanContext:
    target_url: str
    endpoints: List[Dict]
    cookies: Dict
    headers: Dict
    findings: List[ScanResult]
    authenticated: bool
    api_endpoints: List[Dict]
    upload_endpoints: List[Dict]
```

**Key Methods:**
- `run_scan()` - Main scan orchestration
- `_normalize_config()` - Config merging with defaults
- Manages 6 phases: Crawl → Pre-login → Auth → Post-login → AI Planning → Report

### 2. BrowserController (`core/browser.py`)
Playwright-based browser automation:
- Headless/headed browser modes
- MITM proxy support for HTTPS interception
- AI-powered request/response analysis
- 2FA/OTP handling during scans
- Traffic capture and analysis

### 3. AIPlanner (`core/ai_planner.py`)
LLM integration for intelligent test planning:
- Supports: Ollama (default), OpenAI, Anthropic
- Analyzes website structure to recommend attacks
- OWASP detection knowledge built into prompts
- Returns `TestRecommendation` dataclass

### 4. ReportGenerator (`core/reporters.py`)
Professional security reports:
- PDF with cover page (via WeasyPrint)
- HTML interactive reports
- SARIF for IDE integration
- OWASP category mapping
- Executive summary generation

---

## 🛡️ Attack Scanners

### Pre-Login Scanners (`attacks/pre_login/`)
| Scanner | OWASP | Purpose |
|---------|-------|---------|
| `InjectionScanner` | A03 | SQL, NoSQL, Command injection |
| `XSSScanner` | A03 | Reflected XSS |
| `StoredXSSScanner` | A03 | Persistent XSS with delayed execution detection |
| `XSSReflectedScanner` | A03 | Browser-verified XSS with comprehensive payloads |
| `PostMethodScanner` | A03 | Form discovery and POST endpoint testing |
| `MisconfigScanner` | A05 | Security headers, configs |
| `SensitiveDataScanner` | A02 | Data exposure |
| `SSRFScanner` | A10 | Server-side request forgery |
| `AccessControlScanner` | A01 | Broken access control |
| `AuthBypassScanner` | A07 | Auth bypass techniques |
| `SessionScanner` | A07 | Session security |
| `RateLimitScanner` | A07 | Rate limiting bypass |
| `OAuthScanner` | A07 | OAuth vulnerabilities |
| `CaptchaScanner` | A07 | CAPTCHA bypass |
| `UploadScanner` | A04 | File upload vulns |
| `APIScanner` | A01 | API security |
| `ResponseManipulationScanner` | A08 | Response tampering |
| `ResponseSwapScanner` | A08 | Response swapping |
| `MobileSecurityScanner` | A05 | Mobile API security |

### Post-Login Scanners (`attacks/post_login/`)
| Scanner | OWASP | Purpose |
|---------|-------|---------|
| `PostLoginAttacks` | All | Comprehensive post-login testing |
| `PostLoginStoredXSSScanner` | A03 | Stored XSS on authenticated pages |
| `PostLoginReflectedXSSScanner` | A03 | Reflected XSS with auth context |
| `PostLoginPostMethodScanner` | A03 | Authenticated form testing |

### Network Scanners (`attacks/network/`)
- `PortScanner` - Port discovery
- `ServiceDetector` - Service fingerprinting
- `VulnScanner` - CVE detection
- `CredentialScanner` - Default creds
- `MetasploitScanner` - Metasploit integration for exploitation (Added 5 Jan 2026)
- `NetworkOrchestrator` - Coordinates all

### Mobile Scanners (`attacks/mobile/`)
- Android attacks via ADB/Frida
- iOS attacks via iOS simulator
- SSL pinning bypass
- Runtime analysis
- Static APK/IPA analysis
- `MobileXSSScanner` - WebView/Hybrid app XSS (Added 5 Jan 2026)
- `MobilePostMethodScanner` - Mobile API POST testing (Added 5 Jan 2026)

### Cloud Scanners (`attacks/cloud/`)
- `AWSScanner` - S3, IAM, EC2 misconfigs
- `AzureScanner` - Azure security
- `GCPScanner` - GCP security

---

## 🌐 API Routes (`api/routes/`)

| Route | Purpose |
|-------|---------|
| `auth.py` | Login, register, password reset |
| `users.py` | User profile management |
| `scans.py` | Scan CRUD operations |
| `network.py` | Network scan endpoints |
| `chat.py` | AI chatbot endpoint |
| `payments.py` | Stripe subscription |
| `oauth.py` | Google/GitHub OAuth |
| `two_factor.py` | 2FA setup/verify |
| `scan_otp.py` | OTP during scans |
| `whitelisting.py` | WAF bypass headers |
| `domain_verification.py` | Domain ownership |
| `api_keys.py` | API key management |
| `admin.py` | Admin operations |
| `contact.py` | Contact form |

---

## 💾 Database Models (`database/models.py`)

### User Model
```python
class User(Base):
    id: UUID
    email: str
    username: str
    hashed_password: str
    plan: str  # free, individual, professional, enterprise
    max_websites: int
    scans_this_month: int
    has_api_testing: bool
    has_mobile_pentest: bool
    has_chatbot_access: bool
```

### Subscription Plans
- **Free**: 1 website, 7-day dashboard
- **Individual**: More websites, 30-day access
- **Professional**: API testing, mobile pentest
- **Enterprise**: Full features, dedicated support

---

## ⚙️ Configuration (`config/config.yaml`)

```yaml
target:
  url: "https://example.com"
  scope:
    include: ["https://example.com/*"]
    exclude: ["/logout", "/api/health"]

auth:
  enabled: true
  type: "form"  # form, basic, bearer, oauth2
  selectors:
    username_field: "#username"
    password_field: "#password"
    submit_button: "#login-btn"

ai:
  provider: "ollama"
  model: "llama3"
  base_url: "http://localhost:11434"

attacks:
  rate_limit: 10
  js_rendering: true
  owasp:
    injection: {enabled: true}
    xss: {enabled: true}
    ssrf: {enabled: true}
```

---

## 🖥️ Frontend (`jarwisfrontend/`)

**Tech Stack:**
- React 19 with TypeScript/JSX
- Tailwind CSS + Framer Motion
- React Router v7
- Firebase Authentication
- Axios for API calls

**Key Pages:**
- Dashboard with scan history
- New scan configuration
- Report viewer
- User profile/settings
- Subscription management

---

## 🚀 Running the Project

### Quick Start (PowerShell)
```powershell
# Activate virtual environment
& D:/jarwis-ai-pentest/.venv/Scripts/Activate.ps1

# Start Backend API
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload

# Start Frontend (separate terminal)
cd jarwisfrontend
npm start
```

### Alternative: Use start_dev.ps1
```powershell
.\start_dev.ps1
```

### Backend (API)
```bash
# Activate venv
.\.venv\Scripts\Activate.ps1

# Start FastAPI server
python start_server.py
# or
uvicorn api.server:app --reload --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd jarwisfrontend
npm install
npm start
```

### CLI Scan
```bash
python main.py
# or with config
python main.py --config config/config.local.yaml
```

---

## 📝 Code Conventions

1. **Async everywhere** - All scanners use `async def scan()`
2. **Rate limiting** - Respect `config['rate_limit']`
3. **Scope checking** - Always validate URLs against target domain
4. **Rich console** - Use `rich.console.Console` for CLI output
5. **Dataclass results** - All findings use `ScanResult` dataclass
6. **OWASP categories** - Use A01-A10 for category field

---

## 🔑 Environment Variables

```env
# Database
DATABASE_URL=sqlite+aiosqlite:///jarwis.db

# Firebase (frontend)
REACT_APP_FIREBASE_API_KEY=xxx
REACT_APP_FIREBASE_AUTH_DOMAIN=xxx

# Stripe
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

# OAuth
GOOGLE_CLIENT_ID=xxx
GOOGLE_CLIENT_SECRET=xxx
```
