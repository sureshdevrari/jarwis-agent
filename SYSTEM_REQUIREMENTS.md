# JARWIS AGI PEN TEST - System Requirements & Tools Manifest

> **Last Updated**: January 6, 2026  
> **Purpose**: Complete documentation of all dependencies and tools for Windows restoration

---

## Quick Restore

After cloning or restoring from backup, run:

```powershell
.\restore.ps1
```

This will automatically install everything listed below.

---

## 1. System Prerequisites (Install Manually)

| Tool | Version | Download | Purpose |
|------|---------|----------|---------|
| **Python** | 3.11+ | [python.org](https://www.python.org/downloads/) | Backend runtime |
| **Node.js** | 18+ | [nodejs.org](https://nodejs.org/) | Frontend runtime |
| **Git** | Latest | [git-scm.com](https://git-scm.com/) | Version control |

### Windows Installation Commands (via winget):
```powershell
winget install Python.Python.3.11
winget install OpenJS.NodeJS.LTS
winget install Git.Git
```

---

## 2. Python Packages (Auto-installed)

Defined in: `requirements.txt`

### Core Framework
| Package | Purpose |
|---------|---------|
| `fastapi` | REST API backend |
| `uvicorn` | ASGI server |
| `playwright` | Browser automation, PDF generation |
| `aiohttp`, `httpx` | Async HTTP clients |

### AI/LLM Integration
| Package | Purpose |
|---------|---------|
| `google-generativeai` | Google Gemini chatbot |
| `openai` | OpenAI API (optional) |
| `ollama` | Local LLM (optional) |
| `langchain` | LLM orchestration |

### Security Testing
| Package | Purpose |
|---------|---------|
| `mitmproxy` | Traffic interception |
| `python-owasp-zap-v2.4` | ZAP integration |
| `python-nmap` | Network scanning |
| `androguard` | Mobile APK analysis |
| `frida`, `frida-tools` | Dynamic instrumentation |

### Database & Auth
| Package | Purpose |
|---------|---------|
| `sqlalchemy`, `asyncpg` | PostgreSQL ORM |
| `alembic` | Database migrations |
| `python-jose` | JWT tokens |
| `argon2-cffi` | Password hashing |

### Cloud SDKs
| Package | Purpose |
|---------|---------|
| `boto3` | AWS SDK |
| `azure-*` | Azure SDKs |
| `google-cloud-*` | GCP SDKs |

### Reporting
| Package | Purpose |
|---------|---------|
| `jinja2` | HTML templates |
| `reportlab` | PDF generation (fallback) |
| `sarif-om` | SARIF format output |

---

## 3. Node.js Packages (Auto-installed)

Defined in: `jarwisfrontend/package.json`

| Package | Purpose |
|---------|---------|
| `react` | UI framework |
| `react-router-dom` | Routing |
| `tailwindcss` | Styling |
| `axios` | API calls |
| `firebase` | Authentication |
| `framer-motion` | Animations |
| `lucide-react` | Icons |

---

## 4. External Tools (Post-install)

### Required
| Tool | Install Command | Purpose |
|------|-----------------|---------|
| **Playwright Chromium** | `playwright install chromium` | PDF generation, crawling |

### Optional
| Tool | Download | Purpose |
|------|----------|---------|
| **Ollama** | [ollama.com](https://ollama.com) | Local LLM (AI Planner) |
| **Android SDK** | [developer.android.com](https://developer.android.com/studio) | Mobile security testing |
| **Burp Suite** | [portswigger.net](https://portswigger.net/burp) | Manual testing |
| **OWASP ZAP** | [zaproxy.org](https://www.zaproxy.org/) | Scanner integration |

---

## 5. Environment Variables

Create `.env` file in project root:

```env
# Database (PostgreSQL)
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/jarwis

# AI Services
GEMINI_API_KEY=your_google_gemini_key
OPENAI_API_KEY=your_openai_key  # optional

# Payment
RAZORPAY_KEY_ID=your_razorpay_key
RAZORPAY_KEY_SECRET=your_razorpay_secret

# Firebase (frontend uses these)
REACT_APP_FIREBASE_API_KEY=your_firebase_key
REACT_APP_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=your_project_id
```

---

## 6. Ports Used

| Service | Port | URL |
|---------|------|-----|
| Backend API | 8000 | http://localhost:8000 |
| Frontend | 3000 | http://localhost:3000 |
| Ollama | 11434 | http://localhost:11434 |
| PostgreSQL | 5432 | localhost:5432 |

---

## 7. Backup Branches

| Branch | Date | Contents |
|--------|------|----------|
| `backup-jan6-2026` | Jan 6, 2026 | Settings fixes, token monthly, PDF playwright |

### Restore from backup:
```powershell
git checkout backup-jan6-2026     # Switch to backup
git checkout main                  # Return to main
git checkout backup-jan6-2026 -- path/to/file  # Restore single file
```

---

## 8. Complete Fresh Install

```powershell
# 1. Clone repository
git clone https://github.com/YOUR_ACCOUNT/jarwis-ai-pentest.git
cd jarwis-ai-pentest

# 2. Run restore script
.\restore.ps1

# 3. Configure environment
# Edit .env with your API keys

# 4. Start servers
.\start_dev.ps1
```

---

## 9. Troubleshooting

| Issue | Solution |
|-------|----------|
| `playwright not found` | Run `.\.venv\Scripts\playwright.exe install chromium` |
| Port 8000 in use | `netstat -ano \| findstr :8000` then `taskkill /PID <pid> /F` |
| npm install fails | Delete `node_modules` and `package-lock.json`, run `npm install` again |
| Python import errors | Ensure venv is activated: `.\.venv\Scripts\Activate.ps1` |
| PDF generation fails | WeasyPrint doesn't work on Windows, Playwright is used instead |

---

*This file is backed up with your code and serves as the complete restoration guide.*
