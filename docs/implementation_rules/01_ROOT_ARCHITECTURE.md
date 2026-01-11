# 01 - Root Architecture

## Project Structure

```
D:\jarwis-ai-pentest\
│
├── 🏗️ CORE APPLICATION (Python backend)
│   ├── api/                # FastAPI routes and server
│   ├── core/               # Scan engines, orchestrators
│   ├── services/           # Business logic layer
│   ├── database/           # SQLAlchemy models, migrations
│   ├── shared/             # Contracts, schemas, constants
│   └── attacks/            # Scanner modules (99 total)
│       ├── web/            #   OWASP Top 10 organized (48+ scanners)
│       ├── cloud/          #   Provider-based (18 scanners)
│       ├── mobile/         #   Phase-based (22 scanners)
│       ├── sast/           #   Function-based (12 scanners)
│       ├── network/        #   Network scanners
│       └── registry.py     #   Unified scanner discovery
│
├── 💻 FRONTEND
│   └── jarwisfrontend/     # React application
│
├── ⚙️ CONFIGURATION
│   ├── config/             # YAML configs, OAuth credentials
│   └── templates/          # HTML report templates
│
├── 📚 DOCUMENTATION
│   └── docs/               # All documentation
│
├── 🚀 DEPLOYMENT
│   └── deploy/             # Docker, scripts, manifests
│
├── 🔧 SCRIPTS
│   └── scripts/            # Utility scripts
│       ├── startup/        # Server startup scripts
│       └── utilities/      # Diagnostic scripts
│
├── 🧪 TESTING
│   └── tests/              # Pytest test files
│
├── 🎨 ASSETS
│   └── assets/             # Media and AI training data
│
└── 📁 GENERATED DATA (gitignored)
    └── data/               # logs, reports, uploads, temp, jarwis.db
```

## Layer Responsibilities

### API Layer (`api/`)
- HTTP request/response handling ONLY
- Route definitions and middleware
- NO business logic here

### Services Layer (`services/`)
- ALL business logic
- Orchestrates between API and Core
- Database operations

### Core Layer (`core/`)
- Scanner engines and runners
- AI integration
- Report generation
- Process lifecycle management
    - `browser.py`: BrowserController registry for web scans
    - `mobile_process_registry.py`: Process tracking for mobile scans (emulator, Frida, MITM)

### Database Layer (`database/`)
- SQLAlchemy models
- CRUD operations
- Migrations

### Shared Layer (`shared/`)
- Single source of truth
- API endpoints
- Constants and schemas

---

## Attacks Folder Structure

The `attacks/` folder is organized by logical categories for maintainability:

### Web Scanners (`attacks/web/`) - OWASP Top 10 2021
```
attacks/web/
├── a01_broken_access/      # Broken Access Control
├── a02_crypto/             # Cryptographic Failures  
├── a03_injection/          # Injection (XSS, SQLi, SSTI, XXE)
├── a04_insecure_design/    # Insecure Design
├── a05_misconfig/          # Security Misconfiguration
├── a06_vulnerable_components/ # Vulnerable Components
├── a07_auth_failures/      # Auth Failures (CSRF, Session)
├── a08_integrity/          # Integrity Failures
├── a09_logging/            # Security Logging Failures
├── a10_ssrf/               # SSRF
├── api/                    # API-specific attacks
├── file_upload/            # File upload attacks
└── other/                  # Uncategorized attacks
```

### Cloud Scanners (`attacks/cloud/`) - Provider-Based
```
attacks/cloud/
├── aws/                    # AWS-specific scanners
├── azure/                  # Azure-specific scanners
├── gcp/                    # GCP-specific scanners
├── kubernetes/             # Kubernetes scanners
├── cnapp/                  # Cloud-native app scanners
└── shared/                 # Cross-provider utilities
```

### Mobile Scanners (`attacks/mobile/`) - Phase-Based
```
attacks/mobile/
├── static/                 # Static analysis
├── dynamic/                # Dynamic analysis
├── platform/android/       # Android-specific
├── platform/ios/           # iOS-specific
├── api/                    # Mobile API testing
├── orchestration/          # Scan coordination
└── utils/                  # Mobile utilities
```

### SAST Scanners (`attacks/sast/`) - Function-Based
```
attacks/sast/
├── providers/              # Git providers (GitHub, GitLab, etc.)
├── analyzers/              # Code analysis engines
└── language_analyzers/     # Language-specific analysis
```

### Unified Registry (`attacks/registry.py`)
- Single source of truth for all 99 scanners
- Auto-discovers scanners from all folders
- Use `ScannerRegistry.get_scanners(scan_type)` to retrieve scanners
