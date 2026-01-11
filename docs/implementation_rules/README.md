# Jarwis Implementation Rules

This folder contains detailed architecture and implementation guidelines for the Jarwis AI Pen Test project.

## Contents

| File | Description |
|------|-------------|
| [01_ROOT_ARCHITECTURE.md](01_ROOT_ARCHITECTURE.md) | Layered architecture overview |
| [02_SCAN_FLOW.md](02_SCAN_FLOW.md) | Scan execution phases |
| [03_LAYERED_RULES.md](03_LAYERED_RULES.md) | Import rules (CRITICAL!) |
| [04_FRONTEND_INTEGRATION.md](04_FRONTEND_INTEGRATION.md) | React patterns |
| [05_EXTENSION_PLAYBOOK.md](05_EXTENSION_PLAYBOOK.md) | Step-by-step guides |
| [06_AI_CHECKLIST.md](06_AI_CHECKLIST.md) | Pre-commit validation |

## Quick Reference

### Layer Hierarchy
```
Frontend → API Routes → Services → Core Engines → Database
                ↑               ↑
            Shared Contracts (schemas, endpoints, constants)
```

### Key Rules
1. **API Routes** only handle HTTP (parse request → call service → return response)
2. **Services** contain ALL business logic
3. **Core** modules NEVER import from `api.routes.*`
4. **Shared** is the single source of truth for endpoints and constants
