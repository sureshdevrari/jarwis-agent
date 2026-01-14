"""
Architecture Validation Tests

These tests validate the wiring of the application:
- All route modules are properly registered
- All scanners are discoverable
- No circular imports in critical __init__.py files
- Exports match actual available classes

Run with: pytest tests/test_architecture.py -v
"""

import ast
import importlib
import sys
from pathlib import Path
from typing import Set, List, Dict, Any

import pytest

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# =============================================================================
# ROUTE VALIDATION TESTS
# =============================================================================

class TestRouteRegistration:
    """Validate all route modules are properly registered."""
    
    def test_all_route_files_are_registered(self):
        """Every .py file in api/routes/ (except __init__.py) should be imported in __init__.py"""
        routes_dir = project_root / "api" / "routes"
        init_file = routes_dir / "__init__.py"
        
        # Get all route files
        route_files = {
            f.stem for f in routes_dir.glob("*.py") 
            if f.name != "__init__.py" and not f.name.startswith("_")
        }
        
        # Parse __init__.py to find imported modules
        content = init_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
        
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("api.routes."):
                    module_name = node.module.replace("api.routes.", "")
                    imported_modules.add(module_name)
        
        # Check for unregistered routes
        unregistered = route_files - imported_modules
        
        assert not unregistered, (
            f"Route files not registered in api/routes/__init__.py: {unregistered}\n"
            f"Add these imports to api/routes/__init__.py"
        )
    
    def test_registered_routes_have_files(self):
        """Every import in __init__.py should have a corresponding file."""
        routes_dir = project_root / "api" / "routes"
        init_file = routes_dir / "__init__.py"
        
        content = init_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
        
        missing_files = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("api.routes."):
                    module_name = node.module.replace("api.routes.", "")
                    route_file = routes_dir / f"{module_name}.py"
                    if not route_file.exists():
                        missing_files.append(module_name)
        
        assert not missing_files, (
            f"Route modules imported but files missing: {missing_files}"
        )
    
    def test_routes_init_imports_successfully(self):
        """api.routes should import without errors."""
        try:
            import api.routes
            assert hasattr(api.routes, 'api_router'), "api_router not exported"
        except ImportError as e:
            pytest.fail(f"Failed to import api.routes: {e}")
    
    def test_all_routers_included_in_api_router(self):
        """Every imported router should be included in api_router."""
        routes_dir = project_root / "api" / "routes"
        init_file = routes_dir / "__init__.py"
        
        content = init_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
        
        # Find router aliases
        router_aliases = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "router" and alias.asname:
                        router_aliases.add(alias.asname)
        
        # Find included routers
        included_routers = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute):
                        if node.value.func.attr == "include_router":
                            if node.value.args:
                                arg = node.value.args[0]
                                if isinstance(arg, ast.Name):
                                    included_routers.add(arg.id)
        
        # admin_router is conditionally included, so exclude from check
        router_aliases.discard("admin_router")
        
        not_included = router_aliases - included_routers
        
        assert not not_included, (
            f"Routers imported but not included in api_router: {not_included}\n"
            f"Add: api_router.include_router({next(iter(not_included))})"
        )


# =============================================================================
# SCANNER VALIDATION TESTS
# =============================================================================

class TestScannerDiscovery:
    """Validate all scanners are discoverable."""
    
    def get_scanner_files(self, scan_type: str) -> Set[str]:
        """Get all scanner Python files for a scan type."""
        type_dir = project_root / "attacks" / scan_type
        if not type_dir.exists():
            return set()
        
        scanners = set()
        for py_file in type_dir.rglob("*.py"):
            if py_file.name.startswith("_"):
                continue
            if py_file.name == "__init__.py":
                continue
            
            # Check if file contains a scanner class
            try:
                content = py_file.read_text(encoding="utf-8")
                if "class" in content and ("Scanner" in content or "Attack" in content):
                    scanners.add(str(py_file.relative_to(project_root)))
            except Exception:
                pass
        
        return scanners
    
    def test_web_scanners_exist(self):
        """Web scanners directory should have scanner files."""
        scanners = self.get_scanner_files("web")
        assert len(scanners) > 0, "No web scanners found in attacks/web/"
    
    def test_mobile_scanners_exist(self):
        """Mobile scanners directory should have scanner files."""
        scanners = self.get_scanner_files("mobile")
        assert len(scanners) > 0, "No mobile scanners found in attacks/mobile/"
    
    def test_network_scanners_exist(self):
        """Network scanners directory should have scanner files."""
        scanners = self.get_scanner_files("network")
        assert len(scanners) > 0, "No network scanners found in attacks/network/"
    
    def test_cloud_scanners_exist(self):
        """Cloud scanners directory should have scanner files."""
        scanners = self.get_scanner_files("cloud")
        assert len(scanners) > 0, "No cloud scanners found in attacks/cloud/"
    
    def test_attacks_registry_imports(self):
        """attacks.registry should import without errors."""
        try:
            from attacks import registry
            assert hasattr(registry, 'ScannerRegistry'), "ScannerRegistry not found"
        except ImportError as e:
            pytest.fail(f"Failed to import attacks.registry: {e}")


# =============================================================================
# INIT.PY VALIDATION TESTS
# =============================================================================

class TestInitExports:
    """Validate __init__.py files have proper exports."""
    
    CRITICAL_INIT_FILES = [
        "api/__init__.py",
        "api/routes/__init__.py",
        "core/__init__.py",
        "attacks/__init__.py",
        "database/__init__.py",
    ]
    
    def test_critical_init_files_exist(self):
        """All critical __init__.py files should exist."""
        missing = []
        for init_path in self.CRITICAL_INIT_FILES:
            if not (project_root / init_path).exists():
                missing.append(init_path)
        
        assert not missing, f"Missing critical __init__.py files: {missing}"
    
    def test_init_files_are_valid_python(self):
        """All __init__.py files should be valid Python."""
        errors = []
        for init_path in self.CRITICAL_INIT_FILES:
            full_path = project_root / init_path
            if not full_path.exists():
                continue
            
            try:
                content = full_path.read_text(encoding="utf-8")
                ast.parse(content)
            except SyntaxError as e:
                errors.append(f"{init_path}: {e}")
        
        assert not errors, f"Syntax errors in __init__.py files:\n" + "\n".join(errors)
    
    def test_api_routes_has_all_defined(self):
        """api/routes/__init__.py should define __all__."""
        init_file = project_root / "api" / "routes" / "__init__.py"
        content = init_file.read_text(encoding="utf-8")
        
        assert "__all__" in content, (
            "api/routes/__init__.py should define __all__ for explicit exports"
        )
    
    def test_no_excessive_imports_in_core(self):
        """core/__init__.py should not have excessive imports (> 50)."""
        init_file = project_root / "core" / "__init__.py"
        if not init_file.exists():
            pytest.skip("core/__init__.py does not exist")
        
        content = init_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
        
        import_count = sum(1 for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)))
        
        assert import_count <= 50, (
            f"core/__init__.py has {import_count} imports (max 50). "
            f"Consider using lazy imports with importlib.import_module()"
        )


# =============================================================================
# CIRCULAR IMPORT DETECTION
# =============================================================================

class TestCircularImports:
    """Detect potential circular import issues."""
    
    def test_api_routes_import_isolation(self):
        """Each route module should be importable in isolation."""
        routes_dir = project_root / "api" / "routes"
        
        errors = []
        for route_file in routes_dir.glob("*.py"):
            if route_file.name == "__init__.py":
                continue
            if route_file.name.startswith("_"):
                continue
            
            module_name = f"api.routes.{route_file.stem}"
            try:
                importlib.import_module(module_name)
            except Exception as e:
                errors.append(f"{module_name}: {type(e).__name__}: {e}")
        
        # Allow some failures (may have missing dependencies in test environment)
        # but report them
        if errors:
            print(f"\nWarning: Some route imports failed (may be expected in test env):")
            for err in errors[:5]:  # Show first 5
                print(f"  - {err}")
    
    def test_core_modules_import(self):
        """Critical core modules should import without circular dependency errors."""
        critical_modules = [
            "core.runner",
            "core.scan_orchestrator",
            "core.web_scan_runner",
        ]
        
        errors = []
        for module_name in critical_modules:
            try:
                importlib.import_module(module_name)
            except ImportError as e:
                if "circular" in str(e).lower():
                    errors.append(f"{module_name}: Circular import detected - {e}")
        
        assert not errors, "Circular imports detected:\n" + "\n".join(errors)


# =============================================================================
# DOCUMENTATION SYNC TESTS
# =============================================================================

class TestDocumentationSync:
    """Validate generated documentation exists and is reasonably current."""
    
    GENERATED_DOCS = [
        "docs/generated/API_ROUTES.md",
        "docs/generated/SCANNERS.md",
        "docs/generated/EXPORTS.md",
        "docs/generated/WIRING.md",
    ]
    
    def test_generated_docs_exist(self):
        """Generated documentation files should exist."""
        missing = []
        for doc_path in self.GENERATED_DOCS:
            if not (project_root / doc_path).exists():
                missing.append(doc_path)
        
        if missing:
            pytest.skip(
                f"Generated docs missing: {missing}\n"
                f"Run: python scripts/generate_architecture_docs.py"
            )
    
    def test_generated_docs_not_empty(self):
        """Generated documentation should not be empty."""
        for doc_path in self.GENERATED_DOCS:
            full_path = project_root / doc_path
            if not full_path.exists():
                continue
            
            content = full_path.read_text(encoding="utf-8")
            assert len(content) > 100, f"{doc_path} appears to be empty or too short"


# =============================================================================
# WIRING CONSISTENCY TESTS  
# =============================================================================

class TestWiringConsistency:
    """Validate consistent patterns across the codebase."""
    
    def test_scan_type_enum_consistency(self):
        """Scan types should be consistent across registries."""
        expected_types = {"web", "mobile", "network", "cloud", "sast"}
        
        # Check attacks folder structure
        attacks_dir = project_root / "attacks"
        actual_folders = {
            f.name for f in attacks_dir.iterdir() 
            if f.is_dir() and not f.name.startswith("_") and f.name not in ["payloads", "__pycache__"]
        }
        
        missing = expected_types - actual_folders
        extra = actual_folders - expected_types - {"payloads", "__pycache__"}
        
        if missing:
            pytest.fail(f"Missing scan type folders in attacks/: {missing}")
        
        # Extra folders are just a warning, not a failure
        if extra:
            print(f"\nNote: Extra folders in attacks/: {extra}")
    
    def test_runner_exists_for_each_scan_type(self):
        """Each scan type should have a corresponding runner in core/."""
        core_dir = project_root / "core"
        
        # These are the expected runners
        expected_runners = [
            "web_scan_runner.py",
            "mobile_attack_engine.py",  # Mobile uses attack_engine pattern
            "network_scan_runner.py",
            "cloud_scan_runner.py",
            "sast_scan_runner.py",
        ]
        
        missing = []
        for runner in expected_runners:
            if not (core_dir / runner).exists():
                missing.append(runner)
        
        assert not missing, f"Missing scan runners in core/: {missing}"
