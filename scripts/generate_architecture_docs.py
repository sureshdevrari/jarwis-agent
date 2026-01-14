#!/usr/bin/env python3
"""
Architecture Documentation Generator

Auto-generates documentation from code introspection to ensure docs stay in sync.
Run this script whenever routes, scanners, or core modules change.

Usage:
    python scripts/generate_architecture_docs.py
    python scripts/generate_architecture_docs.py --check  # Check if docs are up-to-date (for CI)
    python scripts/generate_architecture_docs.py --verbose

Generated files:
    - docs/generated/API_ROUTES.md
    - docs/generated/SCANNERS.md
    - docs/generated/EXPORTS.md
    - docs/generated/WIRING.md
"""

import argparse
import ast
import hashlib
import importlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def print_colored(text: str, color: str = "white"):
    """Print with ANSI colors"""
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")


# =============================================================================
# ROUTE EXTRACTION
# =============================================================================

def extract_routes_from_init() -> List[Dict[str, Any]]:
    """
    Extract route information from api/routes/__init__.py without importing.
    Uses AST parsing to avoid import side effects.
    """
    routes_init = project_root / "api" / "routes" / "__init__.py"
    routes = []
    
    if not routes_init.exists():
        return routes
    
    content = routes_init.read_text(encoding="utf-8")
    tree = ast.parse(content)
    
    for node in ast.walk(tree):
        # Find imports like: from api.routes.auth import router as auth_router
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("api.routes."):
                module_name = node.module.replace("api.routes.", "")
                for alias in node.names:
                    if alias.name == "router":
                        route_file = project_root / "api" / "routes" / f"{module_name}.py"
                        route_info = {
                            "module": module_name,
                            "alias": alias.asname or alias.name,
                            "file_exists": route_file.exists(),
                            "prefix": None,
                            "tags": [],
                            "endpoints": []
                        }
                        
                        # Try to extract prefix and endpoints from the route file
                        if route_file.exists():
                            route_info.update(extract_route_details(route_file))
                        
                        routes.append(route_info)
    
    return routes


def extract_route_details(route_file: Path) -> Dict[str, Any]:
    """Extract prefix, tags, and endpoints from a route file using AST."""
    try:
        content = route_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
    except Exception:
        return {"prefix": None, "tags": [], "endpoints": []}
    
    details = {"prefix": None, "tags": [], "endpoints": []}
    
    for node in ast.walk(tree):
        # Find APIRouter instantiation
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "router":
                    if isinstance(node.value, ast.Call):
                        for keyword in node.value.keywords:
                            if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
                                details["prefix"] = keyword.value.value
                            elif keyword.arg == "tags" and isinstance(keyword.value, ast.List):
                                details["tags"] = [
                                    e.value for e in keyword.value.elts 
                                    if isinstance(e, ast.Constant)
                                ]
        
        # Find route decorators
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    if isinstance(decorator.func, ast.Attribute):
                        method = decorator.func.attr.upper()
                        if method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                            path = ""
                            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                                path = decorator.args[0].value
                            details["endpoints"].append({
                                "method": method,
                                "path": path,
                                "function": node.name
                            })
    
    return details


# =============================================================================
# SCANNER EXTRACTION
# =============================================================================

def discover_scanner_files() -> Dict[str, List[Dict[str, Any]]]:
    """
    Discover all scanner files by walking the attacks directory.
    Returns scanners grouped by type (web, mobile, network, cloud, sast).
    """
    attacks_dir = project_root / "attacks"
    scanners = {
        "web": [],
        "mobile": [],
        "network": [],
        "cloud": [],
        "sast": []
    }
    
    scan_type_dirs = {
        "web": attacks_dir / "web",
        "mobile": attacks_dir / "mobile",
        "network": attacks_dir / "network",
        "cloud": attacks_dir / "cloud",
        "sast": attacks_dir / "sast"
    }
    
    for scan_type, type_dir in scan_type_dirs.items():
        if not type_dir.exists():
            continue
        
        # Find all *_scanner.py or *.py files that might be scanners
        for py_file in type_dir.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue
            if py_file.name == "__init__.py":
                continue
            
            scanner_info = extract_scanner_info(py_file, scan_type)
            if scanner_info:
                scanners[scan_type].append(scanner_info)
    
    return scanners


def extract_scanner_info(scanner_file: Path, scan_type: str) -> Optional[Dict[str, Any]]:
    """Extract scanner class info from a file using AST."""
    try:
        content = scanner_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
    except Exception:
        return None
    
    # Look for scanner classes
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Check if it's a scanner class (inherits from BaseAttackScanner or similar)
            is_scanner = False
            for base in node.bases:
                if isinstance(base, ast.Name):
                    if "Scanner" in base.id or "Attack" in base.id:
                        is_scanner = True
                        break
                elif isinstance(base, ast.Attribute):
                    if "Scanner" in base.attr or "Attack" in base.attr:
                        is_scanner = True
                        break
            
            if not is_scanner and "scanner" not in node.name.lower():
                continue
            
            # Extract class attributes
            info = {
                "class_name": node.name,
                "file": str(scanner_file.relative_to(project_root)),
                "scan_type": scan_type,
                "owasp_category": None,
                "cwe_id": None,
                "scanner_name": None,
                "docstring": ast.get_docstring(node)
            }
            
            # Extract class-level attributes
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name) and isinstance(item.value, ast.Constant):
                            attr_name = target.id
                            attr_value = item.value.value
                            if attr_name == "owasp_category":
                                info["owasp_category"] = attr_value
                            elif attr_name == "cwe_id":
                                info["cwe_id"] = attr_value
                            elif attr_name == "scanner_name":
                                info["scanner_name"] = attr_value
                            elif attr_name == "attack_type":
                                info["attack_type"] = attr_value
            
            return info
    
    return None


# =============================================================================
# INIT.PY EXPORT EXTRACTION
# =============================================================================

def extract_init_exports() -> Dict[str, Dict[str, Any]]:
    """Extract exports from critical __init__.py files."""
    init_files = [
        "api/__init__.py",
        "api/routes/__init__.py",
        "core/__init__.py",
        "attacks/__init__.py",
        "attacks/web/__init__.py",
        "attacks/mobile/__init__.py",
        "attacks/network/__init__.py",
        "attacks/cloud/__init__.py",
        "database/__init__.py",
        "services/__init__.py",
        "shared/__init__.py"
    ]
    
    exports = {}
    
    for init_path in init_files:
        full_path = project_root / init_path
        if not full_path.exists():
            continue
        
        export_info = {
            "file": init_path,
            "exports": [],
            "imports_from": [],
            "has_all": False,
            "import_count": 0,
            "risk_level": "low"
        }
        
        try:
            content = full_path.read_text(encoding="utf-8")
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Count imports
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    export_info["import_count"] += 1
                    if isinstance(node, ast.ImportFrom) and node.module:
                        export_info["imports_from"].append(node.module)
                
                # Find __all__
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "__all__":
                            export_info["has_all"] = True
                            if isinstance(node.value, ast.List):
                                export_info["exports"] = [
                                    e.value for e in node.value.elts
                                    if isinstance(e, ast.Constant)
                                ]
            
            # Determine risk level based on import count
            if export_info["import_count"] > 30:
                export_info["risk_level"] = "critical"
            elif export_info["import_count"] > 15:
                export_info["risk_level"] = "high"
            elif export_info["import_count"] > 5:
                export_info["risk_level"] = "medium"
            
        except Exception as e:
            export_info["error"] = str(e)
        
        exports[init_path] = export_info
    
    return exports


# =============================================================================
# WIRING GRAPH
# =============================================================================

def generate_wiring_graph() -> Dict[str, List[str]]:
    """
    Generate a dependency graph showing what imports what.
    Focus on the critical wiring paths.
    """
    wiring = {
        "entry_points": {
            "main.py": ["core.runner", "core.jarwis_chatbot"],
            "api/app.py": ["api.routes", "api.startup_checks"],
            "api/server.py": ["api.app", "core.web_scan_runner"]
        },
        "orchestration_paths": {
            "legacy": "core.scan_orchestrator -> core.*_scan_runner -> attacks.*",
            "recommended": "services.scan_orchestrator_service -> core.*_scan_runner -> attacks.*"
        },
        "critical_registries": [
            "attacks/registry.py (UNIFIED - recommended)",
            "attacks/unified_registry.py (health checking)",
            "attacks/scanner_registry.py (auto-discovery)"
        ],
        "config_sources": [
            "database/config.py - DatabaseSettings (env/.env)",
            "config/config.yaml - Scan configuration",
            "jarwis_ai/config.py - AI provider settings"
        ]
    }
    return wiring


# =============================================================================
# DOCUMENT GENERATORS
# =============================================================================

def generate_routes_md(routes: List[Dict[str, Any]]) -> str:
    """Generate API_ROUTES.md content."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    lines = [
        "# API Routes Reference",
        "",
        f"> **Auto-generated**: {timestamp}",
        "> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`",
        "",
        "## Summary",
        "",
        f"Total route modules: **{len(routes)}**",
        "",
        "## Route Modules",
        "",
        "| Module | Prefix | Tags | Endpoints | Status |",
        "|--------|--------|------|-----------|--------|"
    ]
    
    for route in sorted(routes, key=lambda r: r["module"]):
        status = "✅" if route["file_exists"] else "❌ Missing"
        prefix = route.get("prefix") or "/"
        tags = ", ".join(route.get("tags", [])) or "-"
        endpoint_count = len(route.get("endpoints", []))
        lines.append(f"| `{route['module']}` | `{prefix}` | {tags} | {endpoint_count} | {status} |")
    
    lines.extend([
        "",
        "## Endpoint Details",
        ""
    ])
    
    for route in sorted(routes, key=lambda r: r["module"]):
        if not route.get("endpoints"):
            continue
        
        lines.append(f"### {route['module']}")
        lines.append("")
        lines.append(f"**Prefix**: `{route.get('prefix') or '/'}`")
        lines.append("")
        lines.append("| Method | Path | Function |")
        lines.append("|--------|------|----------|")
        
        for endpoint in route["endpoints"]:
            lines.append(f"| {endpoint['method']} | `{endpoint['path']}` | `{endpoint['function']}` |")
        
        lines.append("")
    
    lines.extend([
        "---",
        "",
        "## Wiring",
        "",
        "All routes are registered in `api/routes/__init__.py`:",
        "",
        "```python",
        "# api/routes/__init__.py imports ALL routers at module load time",
        "# If ANY route file has a broken import, the entire API fails to start",
        "```",
        "",
        "**⚠️ WARNING**: Adding a new route requires:",
        "1. Create `api/routes/your_route.py` with `router = APIRouter(...)`",
        "2. Import in `api/routes/__init__.py`",
        "3. Add to `api_router.include_router()`",
        "4. Add to `__all__` list",
        ""
    ])
    
    return "\n".join(lines)


def generate_scanners_md(scanners: Dict[str, List[Dict[str, Any]]]) -> str:
    """Generate SCANNERS.md content."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    total = sum(len(s) for s in scanners.values())
    
    lines = [
        "# Scanner Registry Reference",
        "",
        f"> **Auto-generated**: {timestamp}",
        "> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`",
        "",
        "## Summary",
        "",
        f"Total scanners discovered: **{total}**",
        "",
        "| Scan Type | Count |",
        "|-----------|-------|"
    ]
    
    for scan_type, scanner_list in sorted(scanners.items()):
        lines.append(f"| {scan_type.upper()} | {len(scanner_list)} |")
    
    lines.extend([
        "",
        "## Registry Files",
        "",
        "| Registry | Location | Purpose |",
        "|----------|----------|---------|",
        "| **ScannerRegistry** | `attacks/registry.py` | ✅ UNIFIED - Use this one |",
        "| UnifiedScannerRegistry | `attacks/unified_registry.py` | Health checking, fallbacks |",
        "| scanner_registry | `attacks/scanner_registry.py` | Auto-discovery |",
        "",
        "**⚠️ Use `attacks/registry.py` for all new code**",
        ""
    ])
    
    # Details by scan type
    for scan_type, scanner_list in sorted(scanners.items()):
        if not scanner_list:
            continue
        
        lines.append(f"## {scan_type.upper()} Scanners ({len(scanner_list)})")
        lines.append("")
        lines.append("| Scanner | Class | OWASP | CWE |")
        lines.append("|---------|-------|-------|-----|")
        
        for scanner in sorted(scanner_list, key=lambda s: s.get("scanner_name") or s["class_name"]):
            name = scanner.get("scanner_name") or scanner["class_name"]
            owasp = scanner.get("owasp_category") or "-"
            cwe = scanner.get("cwe_id") or "-"
            lines.append(f"| `{name}` | `{scanner['class_name']}` | {owasp} | {cwe} |")
        
        lines.append("")
    
    lines.extend([
        "---",
        "",
        "## Adding New Scanners",
        "",
        "1. Create scanner in appropriate folder: `attacks/{type}/{category}/`",
        "2. Inherit from `BaseAttackScanner`",
        "3. Set class attributes: `scanner_name`, `owasp_category`, `cwe_id`",
        "4. Scanner will be auto-discovered by `ScannerRegistry.initialize()`",
        "",
        "**Do NOT** manually register scanners - discovery is automatic.",
        ""
    ])
    
    return "\n".join(lines)


def generate_exports_md(exports: Dict[str, Dict[str, Any]]) -> str:
    """Generate EXPORTS.md content."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    lines = [
        "# Module Exports Reference",
        "",
        f"> **Auto-generated**: {timestamp}",
        "> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`",
        "",
        "## Critical __init__.py Files",
        "",
        "These files control what gets exported and imported at module load time.",
        "**High import counts = fragile wiring**",
        "",
        "| File | Imports | Exports | Risk | Has __all__ |",
        "|------|---------|---------|------|-------------|"
    ]
    
    risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
    
    for file_path, info in sorted(exports.items(), key=lambda x: x[1].get("import_count", 0), reverse=True):
        risk = info.get("risk_level", "low")
        emoji = risk_emoji.get(risk, "⚪")
        has_all = "✅" if info.get("has_all") else "❌"
        export_count = len(info.get("exports", []))
        lines.append(f"| `{file_path}` | {info.get('import_count', 0)} | {export_count} | {emoji} {risk} | {has_all} |")
    
    lines.extend([
        "",
        "## Risk Levels",
        "",
        "- 🟢 **Low** (< 5 imports): Safe, minimal wiring",
        "- 🟡 **Medium** (5-15 imports): Moderate complexity",
        "- 🟠 **High** (15-30 imports): Breaking changes likely to cascade",
        "- 🔴 **Critical** (> 30 imports): Any error breaks entire module",
        "",
        "## Detailed Exports",
        ""
    ])
    
    for file_path, info in sorted(exports.items()):
        if not info.get("exports"):
            continue
        
        risk = info.get("risk_level", "low")
        emoji = risk_emoji.get(risk, "⚪")
        
        lines.append(f"### `{file_path}` {emoji}")
        lines.append("")
        lines.append("**Exports:**")
        for export in info["exports"]:
            lines.append(f"- `{export}`")
        lines.append("")
    
    lines.extend([
        "---",
        "",
        "## Best Practices",
        "",
        "1. **Use lazy imports** for heavy modules (see `core/scan_orchestrator.py` pattern)",
        "2. **Always define `__all__`** to make exports explicit",
        "3. **Avoid circular imports** - use `importlib.import_module()` inside functions",
        "4. **Test imports in isolation** before committing",
        ""
    ])
    
    return "\n".join(lines)


def generate_wiring_md(wiring: Dict[str, Any]) -> str:
    """Generate WIRING.md content."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    lines = [
        "# Architecture Wiring Reference",
        "",
        f"> **Auto-generated**: {timestamp}",
        "> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`",
        "",
        "## Layer Architecture",
        "",
        "```",
        "┌─────────────────────────────────────────────────────────────────┐",
        "│  LAYER 1: FRONTEND (React)                                       │",
        "│  jarwisfrontend/src/                                             │",
        "└─────────────────────────────────────────────────────────────────┘",
        "                              ↓ HTTP/WebSocket",
        "┌─────────────────────────────────────────────────────────────────┐",
        "│  LAYER 2: API ROUTES (FastAPI)                                   │",
        "│  api/routes/*.py                                                │",
        "└─────────────────────────────────────────────────────────────────┘",
        "                              ↓",
        "┌─────────────────────────────────────────────────────────────────┐",
        "│  LAYER 3: SERVICES                                               │",
        "│  services/*.py                                                  │",
        "└─────────────────────────────────────────────────────────────────┘",
        "                              ↓",
        "┌─────────────────────────────────────────────────────────────────┐",
        "│  LAYER 4: CORE ENGINES                                           │",
        "│  core/*_scan_runner.py, core/scan_orchestrator.py              │",
        "└─────────────────────────────────────────────────────────────────┘",
        "                              ↓",
        "┌─────────────────────────────────────────────────────────────────┐",
        "│  LAYER 5: ATTACK MODULES                                         │",
        "│  attacks/web/, attacks/mobile/, attacks/network/, attacks/cloud/ │",
        "└─────────────────────────────────────────────────────────────────┘",
        "                              ↓",
        "┌─────────────────────────────────────────────────────────────────┐",
        "│  LAYER 6: DATABASE                                               │",
        "│  database/models.py, database/crud.py                          │",
        "└─────────────────────────────────────────────────────────────────┘",
        "```",
        "",
        "## Entry Points",
        "",
        "| Entry | Purpose | Primary Imports |",
        "|-------|---------|-----------------|",
        "| `main.py` | CLI entry | core.runner, core.jarwis_chatbot |",
        "| `api/app.py` | FastAPI app | api.routes, api.startup_checks |",
        "| `api/server.py` | Extended API | api.app, core.web_scan_runner |",
        "",
        "## Orchestration Paths",
        "",
        "```",
        "SCAN_ORCHESTRATOR_ENABLED=false (Legacy):",
        "  api/routes/scans.py → core.scan_orchestrator → core.*_scan_runner → attacks.*",
        "",
        "SCAN_ORCHESTRATOR_ENABLED=true (Recommended):",
        "  api/routes/scans.py → services.scan_orchestrator_service → core.*_scan_runner → attacks.*",
        "```",
        "",
        "**⚠️ Use `services.scan_orchestrator_service` for new code**",
        "",
        "## Critical Registries",
        "",
        "| Registry | Location | Status |",
        "|----------|----------|--------|",
        "| ScannerRegistry | `attacks/registry.py` | ✅ **RECOMMENDED** |",
        "| UnifiedScannerRegistry | `attacks/unified_registry.py` | ⚠️ Legacy |",
        "| scanner_registry | `attacks/scanner_registry.py` | ⚠️ Auto-discovery helper |",
        "",
        "## Config Sources",
        "",
        "| Config | Location | Type |",
        "|--------|----------|------|",
        "| Database | `database/config.py` | Pydantic Settings (.env) |",
        "| Scan Config | `config/config.yaml` | YAML file |",
        "| AI Provider | `jarwis_ai/config.py` | Dataclass (env vars) |",
        "",
        "---",
        "",
        "## Common Wiring Mistakes",
        "",
        "### 1. Circular Imports",
        "```python",
        "# ❌ BAD - top-level import causes circular dependency",
        "from core.scanner import Scanner",
        "",
        "# ✅ GOOD - lazy import inside function",
        "def get_scanner():",
        "    from core.scanner import Scanner",
        "    return Scanner()",
        "```",
        "",
        "### 2. Missing Router Registration",
        "```python",
        "# api/routes/__init__.py - MUST add new routers here",
        "from api.routes.your_route import router as your_router",
        "api_router.include_router(your_router)",
        "```",
        "",
        "### 3. Scanner Not Discovered",
        "- Ensure scanner inherits from `BaseAttackScanner`",
        "- Ensure file is in correct folder: `attacks/{type}/{category}/`",
        "- Check `scripts/validate_scanners.py --discover` to verify",
        ""
    ]
    
    return "\n".join(lines)


# =============================================================================
# MAIN
# =============================================================================

def compute_content_hash(content: str) -> str:
    """Compute hash of content for change detection."""
    return hashlib.sha256(content.encode()).hexdigest()[:12]


def main():
    parser = argparse.ArgumentParser(description="Generate architecture documentation")
    parser.add_argument("--check", action="store_true", help="Check if docs are up-to-date (for CI)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    # Ensure output directory exists
    output_dir = project_root / "docs" / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print_colored("\n📚 ARCHITECTURE DOCUMENTATION GENERATOR", "blue")
    print_colored("=" * 50, "blue")
    
    # Collect data
    print_colored("\n🔍 Extracting routes...", "cyan")
    routes = extract_routes_from_init()
    print_colored(f"   Found {len(routes)} route modules", "white")
    
    print_colored("🔍 Discovering scanners...", "cyan")
    scanners = discover_scanner_files()
    total_scanners = sum(len(s) for s in scanners.values())
    print_colored(f"   Found {total_scanners} scanners", "white")
    
    print_colored("🔍 Analyzing exports...", "cyan")
    exports = extract_init_exports()
    print_colored(f"   Analyzed {len(exports)} __init__.py files", "white")
    
    print_colored("🔍 Generating wiring graph...", "cyan")
    wiring = generate_wiring_graph()
    
    # Generate documents
    docs = {
        "API_ROUTES.md": generate_routes_md(routes),
        "SCANNERS.md": generate_scanners_md(scanners),
        "EXPORTS.md": generate_exports_md(exports),
        "WIRING.md": generate_wiring_md(wiring)
    }
    
    # Check mode or write mode
    if args.check:
        print_colored("\n🔎 Checking if documentation is up-to-date...", "yellow")
        has_diff = False
        
        for filename, content in docs.items():
            file_path = output_dir / filename
            if not file_path.exists():
                print_colored(f"   ❌ {filename} does not exist", "red")
                has_diff = True
                continue
            
            existing = file_path.read_text(encoding="utf-8")
            # Compare ignoring timestamp line
            existing_lines = [l for l in existing.split("\n") if not l.startswith("> **Auto-generated**")]
            new_lines = [l for l in content.split("\n") if not l.startswith("> **Auto-generated**")]
            
            if existing_lines != new_lines:
                print_colored(f"   ❌ {filename} is out of date", "red")
                has_diff = True
            else:
                print_colored(f"   ✅ {filename} is up to date", "green")
        
        if has_diff:
            print_colored("\n❌ Documentation is out of sync!", "red")
            print_colored("   Run: python scripts/generate_architecture_docs.py", "yellow")
            return 1
        else:
            print_colored("\n✅ All documentation is up to date!", "green")
            return 0
    
    else:
        print_colored("\n📝 Writing documentation...", "cyan")
        
        for filename, content in docs.items():
            file_path = output_dir / filename
            file_path.write_text(content, encoding="utf-8")
            print_colored(f"   ✅ {filename}", "green")
        
        print_colored(f"\n✅ Generated {len(docs)} documents in docs/generated/", "green")
        
        if args.verbose:
            print_colored("\nGenerated files:", "white")
            for filename in docs:
                print_colored(f"   - docs/generated/{filename}", "white")
        
        return 0


if __name__ == "__main__":
    sys.exit(main())
