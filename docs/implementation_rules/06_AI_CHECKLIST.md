# 06 - AI Checklist

## Pre-Commit Validation Checklist

Before committing any changes, verify:

### Architecture Rules

- [ ] **No circular imports** - Core doesn't import from API
- [ ] **Services contain business logic** - Not in routes
- [ ] **API routes only handle HTTP** - Parse, call service, return
- [ ] **Shared is single source of truth** - Endpoints, constants

### File Organization

- [ ] **No files at root** except: `main.py`, `requirements.txt`, `package.json`, `README.md`, `.env`, `.gitignore`
- [ ] **Database in `data/jarwis.db`** - Not root or database/
- [ ] **Scripts in `scripts/`** - Not docs/ or root
- [ ] **No backup files** - Remove `.backup`, `.bak`, `.old`

### Folder Locations

| File Type | Correct Location |
|-----------|-----------------|
| API routes | `api/routes/` |
| Business logic | `services/` |
| Scanners (web) | `attacks/web/a01-a10/` (OWASP organized) |
| Scanners (cloud) | `attacks/cloud/{aws,azure,gcp,kubernetes}/` |
| Scanners (network) | `attacks/network/` |
| Scanners (mobile) | `attacks/mobile/{static,dynamic,platform}/` |
| Scanners (SAST) | `attacks/sast/{providers,analyzers}/` |
| Core engines | `core/` |
| Database models | `database/` |
| React pages | `jarwisfrontend/src/pages/` |
| React components | `jarwisfrontend/src/components/` |
| Startup scripts | `scripts/startup/` |
| Utility scripts | `scripts/utilities/` |
| Docker files | `deploy/docker/` |
| Documentation | `docs/` |
| Generated data | `data/` (gitignored) |

### Frontend Rules

- [ ] **Using `services/api.js`** - Not creating new API files
- [ ] **Importing from generated configs** - `config/*.generated.js`
- [ ] **Regenerated types after contract changes** - `python shared/generate_frontend_types.py`

### Naming Conventions

- Services: `*_service.py`
- Scanners: `*_scanner.py`
- React pages: `PascalCase.jsx`
- React components: `PascalCase.jsx`

## Quick Validation Script

```bash
# Check for issues
python scripts/validate_restructure.py
```
