# Jarwis AGI Pen Test - Current State

> **Last Updated**: January 10, 2026  
> **Status**: ✅ Production Ready - All systems operational

---

## ⚠️ FIRST: Read These Files

| File | Purpose |
|------|---------|
| `.copilot_memory/ARCHITECTURE.md` | Complete project architecture |
| `.copilot_memory/SCAN_FLOW.md` | MITM-based scan execution flow |
| `.copilot_memory/SESSION_LOG.md` | Development session history |
| `docs/implementation_rules/` | Detailed implementation guides |
| `.github/copilot-instructions.md` | Full AI assistant context |

---

## 🎯 Project Summary

**Jarwis** is an AI-powered OWASP Top 10 penetration testing framework with:
- **100+ security scanners** across web, mobile, network, and cloud
- **AI-powered analysis** via Ollama/OpenAI/Gemini LLMs
- **React 19 frontend** with Firebase authentication
- **FastAPI backend** with SQLite database
- **MITM-based scanning** for comprehensive request/response analysis
- **WebSocket real-time updates** for instant scan progress (NEW!)

---

## 📅 January 10, 2026 - WebSocket Real-Time Updates

### What Was Done

1. **WebSocket Implementation** (Real-Time Scan Progress)
   - Created `api/websocket.py` - Connection manager with broadcast functions
   - Created `api/routes/websocket_routes.py` - WebSocket endpoints
   - Created `jarwisfrontend/src/hooks/useWebSocket.js` - React hooks
   - Integrated into `Scanning.jsx` with "Live" / "Polling" indicator
   - HTTP polling fallback when WebSocket disconnected

2. **Security Hardening**
   - Added CSRF middleware to server.py
   - Added CSRF token handling to frontend api.js

3. **Dashboard Fixes**
   - VerifyDomain now uses real API
   - Billing page error visibility
   - Vulnerabilities refresh button

4. **Bug Fixes**
   - Fixed ScanWizard.jsx API imports (domainsAPI→domainAPI, scansAPI→scanAPI)
   - Fixed WebScanPage.jsx import order
   - Enhanced useScanWebSocket hook with enabled/callback options

### WebSocket Architecture
```
Frontend (Scanning.jsx)
    │
    │ ws://localhost:8000/ws/scans/{scan_id}
    ▼
WebSocket Routes (websocket_routes.py)
    │
    ▼
ConnectionManager (websocket.py)
    │  - scan_connections: {scan_id: [ws1, ws2, ...]}
    │  - user_connections: {user_id: [ws1, ws2, ...]}
    ▼
Scan Runner (scans.py)
    │  - status_callback() → broadcast_scan_progress()
    │  - on completion   → broadcast_scan_complete()
    │  - on error        → broadcast_scan_error()
```

---

## 📅 January 9, 2026 - Project Reorganization Complete

### What Was Done

1. **Cleaned Root Level**
   - Removed duplicate `jarwis.db` files (root, database/)
   - Database now ONLY in `data/jarwis.db`
   - Removed backup files (`.backup`, `.bak`)
   - Moved Python files from docs/ to scripts/

2. **Created Implementation Rules** (`docs/implementation_rules/`)
   - `README.md` - Overview
   - `01_ROOT_ARCHITECTURE.md` - Folder structure
   - `02_SCAN_FLOW.md` - Scan phases
   - `03_LAYERED_RULES.md` - Import rules (CRITICAL!)
   - `04_FRONTEND_INTEGRATION.md` - React patterns
   - `05_EXTENSION_PLAYBOOK.md` - How to add features
   - `06_AI_CHECKLIST.md` - Pre-commit validation

3. **Updated Copilot Memory**
   - Created comprehensive `ARCHITECTURE.md` (new!)
   - Updated this `CURRENT_STATE.md`
   - Existing `SCAN_FLOW.md` still valid

4. **Validated Structure**
   - Ran `scripts/validate_restructure.py` - all checks pass
   - No duplicate files
   - Correct folder hierarchy

---

## 🏗️ Verified Folder Structure

```
D:\jarwis-ai-pentest\
│
├── main.py                 # CLI entry point (ONLY Python file at root!)
├── requirements.txt        # Python dependencies
├── package.json            # Node dependencies
├── README.md               # Project readme
├── .env                    # Environment variables
│
├── api/                    # FastAPI routes (19 route files)
│   └── routes/             # All API endpoints
│
├── attacks/                # Scanner modules (100+ total)
│   ├── web/
│   │   ├── pre_login/      # 49 pre-login scanners
│   │   └── post_login/     # 5 post-login scanners
│   ├── cloud/              # 18 cloud scanners
│   ├── network/            # 10 network scanners
│   └── mobile/             # 22 mobile modules
│
├── assets/                 # Logos and AI training data
├── config/                 # YAML configs, OAuth credentials
│
├── core/                   # 27 core engine modules
│   ├── runner.py           # Main orchestrator
│   ├── web_scan_runner.py  # MITM-based web scanning
│   ├── browser.py          # Playwright automation
│   ├── ai_planner.py       # LLM integration
│   └── reporters.py        # Report generation
│
├── data/                   # ← ALL generated data here!
│   ├── jarwis.db           # ← ONLY database location!
│   ├── logs/
│   ├── reports/
│   ├── temp/
│   └── uploads/
│
├── database/               # SQLAlchemy models, migrations
├── deploy/                 # Docker, deployment scripts
│
├── docs/                   # All documentation
│   └── implementation_rules/  # Architecture guides (7 files)
│
├── jarwisfrontend/         # React 19 application
│   └── src/
│       ├── services/api.js # SINGLE API client
│       ├── context/        # 7 React contexts
│       ├── pages/          # Page components
│       └── components/     # Reusable components
│
├── scripts/                # Utility scripts (40+ files)
│   ├── startup/            # Server startup scripts
│   └── utilities/          # Diagnostic scripts
│
├── services/               # 13 business logic services
├── shared/                 # Contracts (single source of truth)
├── templates/              # HTML report templates
└── tests/                  # Pytest tests
```

---

## ✅ System Status

| Component | Status | Port/Details |
|-----------|--------|--------------|
| Backend API | ✅ Running | Port 8000 |
| Frontend | ✅ Running | Port 3000 |
| Database | ✅ Ready | `data/jarwis.db` |
| Web Scanning | ✅ Active | 54 scanners |
| Mobile Scanning | ✅ Active | 22 modules |
| Network Scanning | ✅ Active | 10 scanners |
| Cloud Scanning | ✅ Active | 18 scanners |
| AI Chatbot | ✅ Active | Gemini-powered |
| Rate Limiting | ✅ Fixed | Auth users bypass for scans |
| Stuck Scans | ✅ Fixed | Auto-cleanup applied |

---

## 🔑 Quick Access

### Start Services
```powershell
# Backend (port 8000)
cd D:\jarwis-ai-pentest
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload

# Frontend (port 3000)
cd D:\jarwis-ai-pentest\jarwisfrontend
npm start
```

### Test Login
- **URL**: http://localhost:3000/login
- **Email**: user2@jarwis.ai
- **Password**: 12341234

### API Endpoints
- **Health**: http://localhost:8000/api/health
- **Docs**: http://localhost:8000/docs

---

## 🔐 Test Credentials

| Type | Email | Password | Plan |
|------|-------|----------|------|
| **Super Admin** | akshaydevrari@gmail.com | Parilove@1 | enterprise |
| **Admin** | admin@jarwis.ai | admin123 | enterprise |
| **Individual** | user1@jarwis.ai | 12341234 | individual |
| **Professional** | user2@jarwis.ai | 12341234 | professional |
| **Enterprise** | user3@jarwis.ai | 12341234 | enterprise |

---

## ⚠️ Critical Reminders

### 1. Database Location
```
✅ data/jarwis.db (ONLY here!)
❌ Never: root/jarwis.db, database/jarwis.db
```

### 2. Import Rules (CRITICAL!)
```python
# Core modules NEVER import from api/
✅ from services.scan_service import ...
❌ from api.routes.scans import ...
```

### 3. Frontend API (CRITICAL!)
```javascript
// Use ONLY services/api.js
✅ import api from '../services/api';
❌ Creating new API files
```

### 4. After Contract Changes
```bash
python shared/generate_frontend_types.py
```

---

## 📊 Scanner Count Summary

| Category | Count | Location |
|----------|-------|----------|
| Web Pre-Login | 49 | `attacks/web/pre_login/` |
| Web Post-Login | 5 | `attacks/web/post_login/` |
| Cloud | 18 | `attacks/cloud/` |
| Network | 10 | `attacks/network/` |
| Mobile | 22 | `attacks/mobile/` |
| **Total** | **104+** | |

---

## 🏛️ Layered Architecture

```
Frontend (React) → API Routes → Services → Core Engines → Database
                       ↑              ↑
                 Shared Contracts (schemas, endpoints, constants)
```

- **API Routes**: HTTP handling only (NO business logic!)
- **Services**: ALL business logic lives here
- **Core**: Scanner logic, AI, reports (NO api imports!)
- **Shared**: Single source of truth for contracts

---

## 📝 Recent Session History

### Jan 9, 2026
- ✅ Project reorganization completed
- ✅ Created ARCHITECTURE.md
- ✅ Created implementation rules docs
- ✅ Fixed duplicate database files
- ✅ All systems verified operational

### Jan 8, 2026
- ✅ Created SCAN_FLOW.md
- ✅ Fixed post-login scanning to run ALL scanners
- ✅ MITM-based architecture documented

### Jan 7, 2026
- ✅ Cloud integration completed (18 scanners)
- ✅ Fixed subscription enforcement
- ✅ Rate limiting bypass for auth users

---

*For detailed architecture, see `.copilot_memory/ARCHITECTURE.md`*  
*For scan flow details, see `.copilot_memory/SCAN_FLOW.md`*
