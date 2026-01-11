# ðŸ›¡ï¸ JARWIS AGI PEN TEST

## OWASP Top 10 AI-Powered Penetration Testing Framework

Jarwis is an automated penetration testing tool that leverages AI to perform comprehensive security assessments based on the OWASP Top 10 vulnerabilities. It tests both pre-login (anonymous) and post-login (authenticated) attack surfaces.

---

## ðŸ“‹ Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [OWASP Top 10 Coverage](#-owasp-top-10-coverage)
- [Reports](#-reports)
- [API Testing](#-api-testing)
- [AI Integration](#-ai-integration)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)

---

## âœ¨ Features

- **Pre-Login Scanning**: Anonymous crawling and vulnerability detection
- **Post-Login Scanning**: Authenticated testing for IDOR, CSRF, privilege escalation
- **OWASP Top 10 Coverage**: Comprehensive testing for all major vulnerability categories
- **AI-Powered Planning**: LLM integration for intelligent test prioritization
- **File Upload Testing**: Detects insecure upload vulnerabilities
- **API Security**: Swagger/OpenAPI and GraphQL testing
- **Multi-Format Reports**: SARIF, JSON, and HTML reports
- **Rate Limiting**: Built-in request throttling for safe scanning

---

## ðŸ—ï¸ Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  JSON config   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚   CLI / UI   â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¶â”‚ Orchestrator â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                                       â”‚ spawns
                                       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  traffic      â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚   Browser    â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¶â”‚    Proxy     â”‚ (mitmproxy)
â”‚ (Playwright) â”‚               â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                      â”‚
                                      â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  HAR + logs   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚Attack Engine â”‚ â—€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”‚  AI Planner  â”‚ (Ollama/GPT)
â”‚(ZAP, sqlmap) â”‚               â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â”‚ findings (SARIF/JSON)
       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚   Reporter   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## ðŸ“¦ Requirements

### System Requirements
- Python 3.10+
- Node.js 18+ (for browser automation)
- 4GB+ RAM
- Linux/macOS/Windows

### External Tools (Optional but Recommended)
- [OWASP ZAP](https://www.zaproxy.org/) - Web security scanner
- [sqlmap](https://sqlmap.org/) - SQL injection testing
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [Ollama](https://ollama.ai/) - Local LLM for AI planning

---

## ðŸš€ Installation

### Step 1: Clone/Extract the Project

```bash
# Extract the zip file
unzip jarwis-ai-pentest.zip
cd jarwis-ai-pentest
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# Linux/macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install Playwright Browsers

```bash
playwright install chromium
```

### Step 5: (Optional) Install Ollama for AI Features

```bash
# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# macOS
brew install ollama

# Then pull a model
ollama pull llama3.1
```

### Step 6: (Optional) Install Security Tools

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y zaproxy sqlmap nuclei

# macOS
brew install zaproxy sqlmap nuclei

# Or use Docker
docker pull zaproxy/zap-stable
```

---

## ðŸƒ Quick Start

### 1. Configure Your Target

```bash
# Copy the sample config
cp config/config.yaml config/config.local.yaml

# Edit with your target details
nano config/config.local.yaml
```

### 2. Basic Scan (Minimum Configuration)

Edit `config/config.local.yaml`:

```yaml
target:
  url: "https://your-target.com"
  scope:
    include:
      - "https://your-target.com/*"

auth:
  enabled: false  # Start with unauthenticated scan

ai:
  provider: "gemini"  # gemini (default), openai, anthropic
  model: "gemini-2.5-flash"
```

### 3. Run the Scan

```bash
python main.py --config config/config.local.yaml
```

---

## âš™ï¸ Configuration

### Full Configuration Options

```yaml
# config/config.yaml

# Target Configuration
target:
  url: "https://example.com"
  scope:
    include:
      - "https://example.com/*"
    exclude:
      - "https://example.com/logout"

# Authentication (for post-login testing)
auth:
  enabled: true
  type: "form"  # form, basic, bearer
  credentials:
    username: "testuser"
    password: "testpass"
  login_url: "/login"
  selectors:
    username_field: "#username"
    password_field: "#password"
    submit_button: "#login-btn"
  success_indicator: "/dashboard"

# AI Configuration
ai:
  provider: "gemini"  # gemini, openai, anthropic, ollama
  model: "gemini-2.5-flash"
  # api_key: "your-api-key"  # Or set GEMINI_API_KEY env var

# Attack Settings
attacks:
  rate_limit: 10  # Requests per second
  timeout: 30
  owasp:
    injection:
      enabled: true
      sqlmap_level: 2
    xss:
      enabled: true
    sensitive_data:
      enabled: true

# Reporting
reporting:
  format:
    - "sarif"
    - "html"
    - "json"
  output_dir: "./reports"
```

---

## ðŸ“– Usage

### Command Line Options

```bash
# Basic scan
python main.py --config config/config.local.yaml

# Verbose mode
python main.py --config config/config.local.yaml --verbose

# Run specific phase only
python main.py --config config/config.local.yaml --phase 2
```

### Scan Phases

| Phase | Description |
|-------|-------------|
| 1 | Anonymous crawling and endpoint discovery |
| 2 | Pre-login OWASP Top 10 scan |
| 3 | Authentication |
| 4 | Authenticated crawling |
| 5 | Post-login security scan (IDOR, CSRF, etc.) |
| 6 | API security testing |
| 7 | AI-guided advanced testing |
| 8 | Report generation |

---

## ðŸŽ¯ OWASP Top 10 Coverage

| Category | Vulnerability | Coverage |
|----------|--------------|----------|
| A01:2021 | Broken Access Control | IDOR, Privilege Escalation, Path Traversal |
| A02:2021 | Cryptographic Failures | Sensitive Data Exposure, Weak Encryption |
| A03:2021 | Injection | SQL, Command, NoSQL Injection |
| A04:2021 | Insecure Design | Business Logic Flaws |
| A05:2021 | Security Misconfiguration | Headers, CORS, Exposed Files |
| A06:2021 | Vulnerable Components | Version Detection, CVE Scanning |
| A07:2021 | Auth Failures | Weak Sessions, CSRF |
| A08:2021 | Data Integrity | XXE, Insecure Deserialization |
| A09:2021 | Logging Failures | Manual Review Flag |
| A10:2021 | SSRF | Server-Side Request Forgery |

---

## ðŸ“Š Reports

Reports are generated in the `reports/` directory:

### HTML Report
Interactive web-based report with:
- Executive summary
- Severity breakdown
- Detailed findings with evidence
- Remediation guidance

### SARIF Report
Standard format for:
- GitHub Security integration
- CI/CD pipeline integration
- IDE plugins

### JSON Report
Machine-readable format for:
- Custom integrations
- Automated processing
- API consumption

---

## ðŸ”Œ API Testing

### Swagger/OpenAPI
- Automatic discovery at common paths
- Endpoint enumeration
- Authentication testing

### GraphQL
- Introspection detection
- Query depth analysis
- Authorization testing

### REST APIs
- Rate limiting detection
- Authentication bypass testing
- IDOR in API endpoints

---

## ðŸ¤– AI Integration

Jarwis uses LLM (Large Language Model) for:

1. **Test Prioritization**: AI recommends the most impactful next test
2. **Finding Analysis**: Severity confirmation and false positive reduction
3. **Attack Chain Detection**: Correlating findings for complex attacks

### Supported Providers

| Provider | Model | Notes |
|----------|-------|-------|
| Ollama | llama3.1, codellama | Local, free, private |
| OpenAI | gpt-4, gpt-3.5-turbo | Cloud, requires API key |

---

## ðŸ“ Project Structure

```
jarwis-ai-pentest/
â”œâ”€â”€ main.py                 # Entry point
â”œâ”€â”€ requirements.txt        # Python dependencies
â”œâ”€â”€ config/
â”‚   â””â”€â”€ config.yaml        # Configuration template
â”œâ”€â”€ core/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ runner.py          # Main orchestrator
â”‚   â”œâ”€â”€ browser.py         # Playwright browser automation
â”‚   â”œâ”€â”€ proxy.py           # Traffic interception
â”‚   â”œâ”€â”€ ai_planner.py      # LLM integration
â”‚   â””â”€â”€ reporters.py       # Report generation
â”œâ”€â”€ attacks/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ pre_login/         # Anonymous attack modules
â”‚   â”‚   â”œâ”€â”€ injection_scanner.py
â”‚   â”‚   â”œâ”€â”€ xss_scanner.py
â”‚   â”‚   â”œâ”€â”€ misconfig_scanner.py
â”‚   â”‚   â”œâ”€â”€ sensitive_data_scanner.py
â”‚   â”‚   â”œâ”€â”€ api_scanner.py
â”‚   â”‚   â””â”€â”€ upload_scanner.py
â”‚   â””â”€â”€ post_login/        # Authenticated attack modules
â”‚       â””â”€â”€ __init__.py    # IDOR, CSRF, PrivEsc
â”œâ”€â”€ reports/               # Generated reports
â””â”€â”€ tests/                 # Test files
```

---

## ðŸ§ª Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/ -v
```

---

## âš ï¸ Disclaimer

**IMPORTANT: This tool is for authorized security testing only.**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices

**Before testing:**
1. Obtain written authorization
2. Define clear scope boundaries
3. Have incident response procedures ready
4. Document all testing activities

---

## ðŸ“„ License

This project is licensed under the MIT License. See LICENSE file for details.

---

## ðŸ¤ Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## ðŸ“ž Support

For issues and questions:
- Open a GitHub issue
- Check existing documentation
- Review closed issues for solutions

---

**Happy Hacking! ðŸŽ¯**
