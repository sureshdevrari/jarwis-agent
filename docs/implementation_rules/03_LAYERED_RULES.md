# 03 - Layered Rules (CRITICAL!)

## Import Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                        FRONTEND                              │
│   jarwisfrontend/src/services/api.js (single API client)    │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                      API ROUTES                              │
│   api/routes/*.py (HTTP handling only)                      │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                       SERVICES                               │
│   services/*.py (all business logic)                        │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                    CORE ENGINES                              │
│   core/*.py (scanner logic, NO API imports!)                │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                       DATABASE                               │
│   database/*.py (data access only)                          │
└─────────────────────────────────────────────────────────────┘
```

## CRITICAL RULES

### ❌ NEVER DO THIS:
```python
# In core/runner.py - WRONG!
from api.routes.scans import some_function  # NO!
```

### ✅ CORRECT APPROACH:
```python
# In core/runner.py - CORRECT
from services.scan_service import some_function  # YES!
```

## Layer Rules

### API Routes (`api/routes/*.py`)
- ONLY handle HTTP parsing and responses
- Call services for business logic
- Never contain business logic

### Services (`services/*.py`)
- ALL business logic lives here
- Can import from core/ and database/
- Never import from api/

### Core (`core/*.py`)
- Scanner logic and engines
- NEVER import from api.routes.*
- Can import from database/ and shared/

### Shared (`shared/`)
- Single source of truth for:
  - API endpoints (`api_endpoints.py`)
  - Constants (`constants.py`)
  - Schemas (`schemas/*.py`)

## Frontend Integration

1. **Only use `services/api.js`** - never create new API files
2. **Import from `config/*.generated.js`** - auto-generated
3. **Run `python shared/generate_frontend_types.py`** after changes
