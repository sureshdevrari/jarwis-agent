# Jarwis Development Session Log

> This file tracks development sessions, decisions, and changes made to the project.

---

## Session: January 6, 2026 - Development Environment Status

### Context
- Full-stack development environment with backend (FastAPI) and frontend (React)
- Services running on ports 8000 (backend) and 3000 (frontend)
- Virtual environment located at `.venv/`

### Current Status
- **Backend**: FastAPI with uvicorn at `http://localhost:8000`
- **Frontend**: React app at `http://localhost:3000` (jarwisfrontend/)
- **Database**: SQLite with async SQLAlchemy
- **AI Integration**: Ollama configured (localhost:11434)

### Commands for Running Services
```powershell
# Activate virtual environment
& D:/jarwis-ai-pentest/.venv/Scripts/Activate.ps1

# Start backend
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload

# Start frontend
cd jarwisfrontend
npm start

# Or use start script
.\start_dev.ps1
```

### Notes
- GitHub account switching in VS Code does NOT affect local project files
- All code remains on local disk at `D:\jarwis-ai-pentest`
- Only cloud features (Settings Sync, Copilot subscription, remote ops) are affected by account changes

---

## Session: January 6, 2026 - Attack Scanners Update

### Context
- Backup folder contains new attack scanners developed on 5 Jan 2026
- Need to integrate new scanners into web and mobile pentest modules

### Actions Taken
1. Copied copilot memory files from backup to project
2. Added new pre-login scanners:
   - `xss_stored_scanner.py` - Stored XSS with delayed execution detection
   - `xss_reflected_scanner.py` - Browser-verified XSS with comprehensive payloads
   - `post_method_scanner.py` - Form discovery and POST endpoint testing
3. Added new post-login scanners (postlogin versions):
   - `xss_stored_scanner_postlogin.py`
   - `xss_reflected_scanner_postlogin.py`
   - `post_method_scanner_postlogin.py`
4. Added new mobile scanners:
   - `mobile_xss_scanner.py` - WebView/Hybrid app XSS testing
   - `mobile_post_scanner.py` - Mobile API POST method testing
   - `mobile_orchestrator_new.py` - Enhanced mobile orchestrator
5. Added network scanner:
   - `metasploit_scanner.py` - Metasploit framework integration
6. Updated all `__init__.py` files to export new scanners
7. Updated CURRENT_STATE.md with new scanner documentation

---

## Session: January 6, 2026 - Initial

### Context
- Project backup exists from January 4 night: `jarwis-backup-4jan-night.zip`
- Frontend folder was deleted after Jan 4 night causing issues
- User requested memory files be populated with project knowledge

### Actions Taken
1. Created comprehensive `CURRENT_STATE.md` with full project architecture documentation
2. Documented all core components, attack scanners, API routes, and database models

---

## Architecture Decisions Log

### Phase Model (Established)
The scan follows 6 phases:
1. **Anonymous Crawl** - BrowserController discovers all endpoints
2. **Pre-Login Scan** - Test unauthenticated surfaces
3. **Authentication** - Login via form selectors
4. **Post-Login Scan** - Test authenticated surfaces (IDOR, CSRF)
5. **AI Planning** - LLM recommends additional tests
6. **Reporting** - Generate HTML/PDF/SARIF

### Scanner Pattern (Standard)
All scanners follow this pattern:
```python
class ScannerName:
    def __init__(self, config: dict, context: ScanContext):
        self.config = config
        self.context = context
        self.browser = None  # Set by PreLoginAttacks
    
    async def scan(self) -> List[ScanResult]:
        results = []
        for endpoint in self.context.endpoints:
            if not self.context.is_in_scope(endpoint['url']):
                continue
            # Test logic here
        return results
```

### ScanResult Dataclass (Standard)
```python
@dataclass
class ScanResult:
    id: str           # Unique ID
    category: str     # OWASP: A01, A02, A03, etc.
    severity: str     # critical, high, medium, low, info
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    poc: str = ""
    reasoning: str = ""
```

---

## Component Quick Reference

### Starting the Backend
```powershell
cd D:\jarwis-ai-pentest
& .\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
# Runs on http://localhost:8000
```

### Starting the Frontend
```powershell
cd D:\jarwis-ai-pentest\jarwisfrontend
npm start
# Runs on http://localhost:3000
```

### Running a CLI Scan
```bash
python main.py
# Interactive prompts for target, auth, etc.
```

### Running Tests
```bash
pytest tests/ -v --asyncio-mode=auto
```

---

## Key File Locations

| What | Where |
|------|-------|
| Main orchestrator | `core/runner.py` |
| Browser automation | `core/browser.py` |
| AI/LLM integration | `core/ai_planner.py` |
| Report generation | `core/reporters.py` |
| Pre-login scanners | `attacks/pre_login/` |
| Post-login scanners | `attacks/post_login/` |
| Network scanners | `attacks/network/` |
| Mobile scanners | `attacks/mobile/` |
| Cloud scanners | `attacks/cloud/` |
| FastAPI app | `api/app.py` |
| API routes | `api/routes/` |
| Database models | `database/models.py` |
| DB connection | `database/connection.py` |
| Config template | `config/config.yaml` |
| Frontend source | `jarwisfrontend/src/` |

---

## OWASP Top 10 2021 Mapping

| Code | Category | Scanners |
|------|----------|----------|
| A01 | Broken Access Control | AccessControlScanner, APIScanner |
| A02 | Cryptographic Failures | SensitiveDataScanner |
| A03 | Injection | InjectionScanner, XSSScanner, StoredXSSScanner |
| A04 | Insecure Design | UploadScanner |
| A05 | Security Misconfiguration | MisconfigScanner, MobileSecurityScanner |
| A06 | Vulnerable Components | (Nuclei integration planned) |
| A07 | Auth Failures | AuthBypassScanner, SessionScanner, RateLimitScanner, OAuthScanner |
| A08 | Data Integrity Failures | ResponseManipulationScanner, ResponseSwapScanner |
| A09 | Logging Failures | (In MisconfigScanner) |
| A10 | SSRF | SSRFScanner |

---

## Database Schema Overview

### Users Table
- UUID primary key
- Email, username (unique, indexed)
- Hashed password (bcrypt)
- Subscription plan: free/individual/professional/enterprise
- Feature flags: has_api_testing, has_mobile_pentest, has_chatbot_access
- Scan limits: max_websites, scans_this_month

### Scans Table (via models.py)
- UUID primary key
- User foreign key
- Target URL
- Status: pending/running/completed/failed
- Config (JSON)
- Results (JSON)
- Created/Updated timestamps

### Reports Table
- UUID primary key
- Scan foreign key
- Format: html/pdf/sarif/json
- File path
- Generated timestamp

---

## Integration Points

### Frontend ↔ Backend
- Frontend at `:3000` calls API at `:8000`
- CORS enabled for all origins in dev
- JWT token auth via Authorization header
- Firebase handles frontend auth, syncs with backend

### AI Integration
- Default: Ollama at `localhost:11434` with `llama3`
- Fallback: Mock responses if Ollama unavailable
- AI analyzes traffic during crawl
- AI recommends targeted tests after initial scan

### MITM Proxy
- Optional HTTPS interception
- CA cert generated at `~/.jarwis/certs/`
- Enables full request/response capture
- Required for some advanced attack detection

---

## Known Working Endpoints

| Endpoint | Purpose |
|----------|---------|
| `http://localhost:8000/api/scans/last` | Get last scan result |
| `http://localhost:8000/docs` | Swagger API docs |
| `http://localhost:3000` | React frontend |

---

## Known Issues / TODOs

1. Post-login scanners need implementation
2. Cloud scanners need AWS/Azure/GCP credentials
3. Mobile scanning requires ADB/Frida setup
4. SARIF report format needs validation
5. Rate limiting across distributed scans
6. Ensure port 8000 is free before starting backend (use `netstat -ano | Select-String ":8000.*LISTEN"`)

---

## Useful Commands

```bash
# Check Python environment
python --version
pip list | grep -E "playwright|fastapi|sqlalchemy"

# Database migrations
alembic upgrade head

# Install Playwright browsers
playwright install chromium

# Run specific scanner test
pytest tests/test_xss_scanner.py -v

# Format code
black core/ attacks/ api/

# Type checking
mypy core/ --ignore-missing-imports
```
