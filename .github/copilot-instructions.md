# Jarwis AGI Pen Test - Copilot Instructions

## Architecture Overview

Jarwis is an AI-powered OWASP Top 10 penetration testing framework with a **phased execution model**:

1. **Phase 1 - Anonymous Crawl**: `BrowserController` (Playwright) discovers endpoints
2. **Phase 2 - Pre-Login Scan**: Attack modules test unauthenticated surfaces
3. **Phase 3 - Authentication**: Form-based login via selectors
4. **Phase 4 - Post-Login Scan**: Authenticated testing (IDOR, CSRF, PrivEsc)
5. **Phase 5 - AI Planning**: LLM recommends targeted tests based on findings
6. **Phase 6 - Reporting**: Multi-format output (HTML, JSON, SARIF)

**Core orchestration**: [core/runner.py](core/runner.py) (`PenTestRunner`) coordinates all phases and maintains `ScanContext` state across components.

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `PenTestRunner` | [core/runner.py](core/runner.py) | Main orchestrator, config normalization |
| `BrowserController` | [core/browser.py](core/browser.py) | Playwright automation, endpoint discovery |
| `AIPlanner` | [core/ai_planner.py](core/ai_planner.py) | Ollama/OpenAI LLM integration |
| `PreLoginAttacks` | [attacks/pre_login/__init__.py](attacks/pre_login/__init__.py) | Scanner aggregator |
| `ReportGenerator` | [core/reporters.py](core/reporters.py) | HTML/JSON/SARIF/PDF output |

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
| `JarwisDashboard` | [jarwisfrontend/src/pages/dashboard/JarwisDashboard.jsx](jarwisfrontend/src/pages/dashboard/JarwisDashboard.jsx) | Main dashboard with stats |
| `SettingsPanel` | [jarwisfrontend/src/components/settings/SettingsPanel.jsx](jarwisfrontend/src/components/settings/SettingsPanel.jsx) | User settings, billing, preferences |
| `PlanUsageCard` | [jarwisfrontend/src/components/dashboard/PlanUsageCard.jsx](jarwisfrontend/src/components/dashboard/PlanUsageCard.jsx) | Sidebar subscription usage display |
| `planLimits.js` | [jarwisfrontend/src/config/planLimits.js](jarwisfrontend/src/config/planLimits.js) | Subscription plan definitions |
| `JarwisChatbot` | [jarwisfrontend/src/pages/dashboard/JarwisChatbot.jsx](jarwisfrontend/src/pages/dashboard/JarwisChatbot.jsx) | AI chatbot with token tracking |

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
