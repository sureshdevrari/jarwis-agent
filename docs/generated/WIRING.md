# Architecture Wiring Reference

> **Auto-generated**: 2026-01-14 02:09:34
> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`

## Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: FRONTEND (React)                                       │
│  jarwisfrontend/src/                                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓ HTTP/WebSocket
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 2: API ROUTES (FastAPI)                                   │
│  api/routes/*.py                                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 3: SERVICES                                               │
│  services/*.py                                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 4: CORE ENGINES                                           │
│  core/*_scan_runner.py, core/scan_orchestrator.py              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 5: ATTACK MODULES                                         │
│  attacks/web/, attacks/mobile/, attacks/network/, attacks/cloud/ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 6: DATABASE                                               │
│  database/models.py, database/crud.py                          │
└─────────────────────────────────────────────────────────────────┘
```

## Entry Points

| Entry | Purpose | Primary Imports |
|-------|---------|-----------------|
| `main.py` | CLI entry | core.runner, core.jarwis_chatbot |
| `api/app.py` | FastAPI app | api.routes, api.startup_checks |
| `api/server.py` | Extended API | api.app, core.web_scan_runner |

## Orchestration Paths

```
SCAN_ORCHESTRATOR_ENABLED=false (Legacy):
  api/routes/scans.py → core.scan_orchestrator → core.*_scan_runner → attacks.*

SCAN_ORCHESTRATOR_ENABLED=true (Recommended):
  api/routes/scans.py → services.scan_orchestrator_service → core.*_scan_runner → attacks.*
```

**⚠️ Use `services.scan_orchestrator_service` for new code**

## Critical Registries

| Registry | Location | Status |
|----------|----------|--------|
| ScannerRegistry | `attacks/registry.py` | ✅ **RECOMMENDED** |
| UnifiedScannerRegistry | `attacks/unified_registry.py` | ⚠️ Legacy |
| scanner_registry | `attacks/scanner_registry.py` | ⚠️ Auto-discovery helper |

## Config Sources

| Config | Location | Type |
|--------|----------|------|
| Database | `database/config.py` | Pydantic Settings (.env) |
| Scan Config | `config/config.yaml` | YAML file |
| AI Provider | `jarwis_ai/config.py` | Dataclass (env vars) |

---

## Common Wiring Mistakes

### 1. Circular Imports
```python
# ❌ BAD - top-level import causes circular dependency
from core.scanner import Scanner

# ✅ GOOD - lazy import inside function
def get_scanner():
    from core.scanner import Scanner
    return Scanner()
```

### 2. Missing Router Registration
```python
# api/routes/__init__.py - MUST add new routers here
from api.routes.your_route import router as your_router
api_router.include_router(your_router)
```

### 3. Scanner Not Discovered
- Ensure scanner inherits from `BaseAttackScanner`
- Ensure file is in correct folder: `attacks/{type}/{category}/`
- Check `scripts/validate_scanners.py --discover` to verify
