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

### Database Layer (`database/`)
- SQLAlchemy models
- CRUD operations
- Migrations

### Shared Layer (`shared/`)
- Single source of truth
- API endpoints
- Constants and schemas
