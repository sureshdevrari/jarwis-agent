"""
Scanner Auto-Discovery Registry

Automatically discovers and registers scanner classes.
No manual imports required when adding new scanners.

Usage:
    from attacks.scanner_registry import get_registry
    
    registry = get_registry()
    registry.discover_scanners("attacks/pre_login", package="attacks.pre_login")
    scanners = registry.get_enabled_scanners(config)
"""

import asyncio
import importlib
import inspect
import logging
import re
from pathlib import Path
from typing import Dict, List, Type, Any, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """Issue found during scanner validation"""
    scanner_name: str
    issue_type: str  # "no_scan_method", "not_async", "wrong_signature", "no_init"
    message: str
    severity: str = "error"  # "error", "warning"
    auto_fixable: bool = False


@dataclass
class ScannerMetadata:
    """Metadata for registered scanner"""
    name: str
    category: str  # OWASP category: A01, A02, etc.
    description: str
    enabled_by_default: bool
    requires_auth: bool
    requires_js: bool
    scanner_class: Type
    module_name: str
    # Validation status
    is_valid: bool = True
    validation_issues: List[ValidationIssue] = field(default_factory=list)


class ScannerRegistry:
    """
    Centralized scanner registry with auto-discovery.
    
    Usage:
        registry = ScannerRegistry()
        registry.discover_scanners("attacks/pre_login", package="attacks.pre_login")
        scanners = registry.get_enabled_scanners(config)
    """
    
    # Required scanners by scan type
    REQUIRED_SCANNERS = {
        "web": ["SQLInjectionScanner", "XSSScanner", "CSRFScanner"],
        "mobile": ["StaticAnalyzer"],
        "network": ["PortScanner"],
        "cloud": ["CloudConfigScanner"]
    }
    
    # Recommended scanners by scan type
    RECOMMENDED_SCANNERS = {
        "web": ["SSRFScanner", "PathTraversalScanner", "CommandInjectionScanner"],
        "mobile": ["AndroidAttackScanner", "IOSAttackScanner"],
        "network": ["ServiceEnumerator", "VulnerabilityScanner"],
        "cloud": ["IAMAnalyzer", "NetworkSecurityScanner"]
    }
    
    def __init__(self):
        self._scanners: Dict[str, ScannerMetadata] = {}
        self._discovered_modules: set = set()
    
    def discover_scanners(self, module_path: str, package: str = None) -> int:
        """
        Auto-discover scanners in a directory.
        
        Args:
            module_path: Relative path to scanner directory (e.g., "attacks/pre_login")
            package: Package name for imports (e.g., "attacks.pre_login")
        
        Returns:
            Number of scanners discovered
        """
        discovered = 0
        base_path = Path(module_path)
        
        if not base_path.exists():
            logger.warning(f"Scanner path not found: {module_path}")
            return 0
        
        # Find all *_scanner.py files
        scanner_files = list(base_path.glob("*_scanner.py"))
        
        for scanner_file in scanner_files:
            module_name = scanner_file.stem  # Remove .py extension
            
            # Skip already discovered modules
            full_module = f"{package}.{module_name}" if package else module_name
            if full_module in self._discovered_modules:
                continue
            
            try:
                module = importlib.import_module(full_module)
                self._discovered_modules.add(full_module)
                
                # Find scanner classes (must end with "Scanner" and have scan method)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if name.endswith("Scanner") and hasattr(obj, "scan"):
                        # Skip if already registered (could be imported from another module)
                        if name in self._scanners:
                            continue
                        
                        # Extract metadata from class attributes or defaults
                        metadata = ScannerMetadata(
                            name=name,
                            category=getattr(obj, "CATEGORY", "A00"),
                            description=getattr(obj, "DESCRIPTION", obj.__doc__ or f"{name} security scanner"),
                            enabled_by_default=getattr(obj, "ENABLED_BY_DEFAULT", True),
                            requires_auth=getattr(obj, "REQUIRES_AUTH", False),
                            requires_js=getattr(obj, "REQUIRES_JS", False),
                            scanner_class=obj,
                            module_name=full_module
                        )
                        
                        self._scanners[name] = metadata
                        discovered += 1
                        logger.debug(f"✅ Discovered scanner: {name}")
                
            except Exception as e:
                logger.warning(f"⚠️ Failed to load scanner {module_name}: {e}")
        
        if discovered > 0:
            logger.info(f"🔍 Discovered {discovered} scanners in {module_path}")
        
        return discovered
    
    def get_all_scanners(self) -> Dict[str, ScannerMetadata]:
        """Get all registered scanners"""
        return self._scanners.copy()
    
    def get_scanner(self, name: str) -> Optional[ScannerMetadata]:
        """Get a specific scanner by name"""
        return self._scanners.get(name)
    
    def get_enabled_scanners(self, config: dict) -> List[ScannerMetadata]:
        """
        Get scanners enabled in config.
        
        Args:
            config: Configuration dict with attacks.owasp.* keys
        
        Returns:
            List of enabled scanner metadata
        """
        enabled = []
        owasp_config = config.get("attacks", {}).get("owasp", {})
        
        for scanner_name, metadata in self._scanners.items():
            # Check if scanner is enabled in config
            config_key = self._scanner_to_config_key(scanner_name)
            
            # Check config (default to metadata.enabled_by_default)
            is_enabled = owasp_config.get(config_key, metadata.enabled_by_default)
            
            if is_enabled:
                enabled.append(metadata)
        
        return enabled
    
    def get_required_scanners(self, scan_type: str) -> List[str]:
        """Get list of required scanner names for a scan type"""
        return self.REQUIRED_SCANNERS.get(scan_type, [])
    
    def get_recommended_scanners(self, scan_type: str) -> List[str]:
        """Get list of recommended scanner names for a scan type"""
        return self.RECOMMENDED_SCANNERS.get(scan_type, [])
    
    def validate_scan_type_coverage(self, scan_type: str) -> Tuple[bool, List[str]]:
        """
        Check if all required scanners are available for a scan type.
        
        Returns:
            Tuple of (all_available, missing_scanners)
        """
        required = self.get_required_scanners(scan_type)
        missing = [s for s in required if s not in self._scanners]
        return (len(missing) == 0, missing)
    
    def get_scanners_by_category(self, category: str) -> List[ScannerMetadata]:
        """Get all scanners for a specific OWASP category"""
        return [
            metadata for metadata in self._scanners.values()
            if metadata.category == category
        ]
    
    def instantiate_scanner(
        self, 
        metadata: ScannerMetadata, 
        config: dict, 
        context: Any,
        browser: Any = None
    ) -> Any:
        """
        Instantiate a scanner with config and context.
        
        Args:
            metadata: Scanner metadata
            config: Full configuration dict
            context: Scan context object
            browser: Optional browser controller
        
        Returns:
            Scanner instance
        """
        try:
            scanner = metadata.scanner_class(config, context)
            
            # Set browser if scanner supports it
            if browser and hasattr(scanner, 'set_browser'):
                scanner.set_browser(browser)
            elif browser and hasattr(scanner, 'browser'):
                scanner.browser = browser
            
            return scanner
        except Exception as e:
            logger.error(f"Failed to instantiate {metadata.name}: {e}")
            raise
    
    def instantiate_all_enabled(
        self,
        config: dict,
        context: Any,
        browser: Any = None
    ) -> List[Any]:
        """
        Instantiate all enabled scanners.
        
        Args:
            config: Full configuration dict
            context: Scan context object
            browser: Optional browser controller
        
        Returns:
            List of scanner instances
        """
        scanners = []
        enabled_metadata = self.get_enabled_scanners(config)
        
        for metadata in enabled_metadata:
            try:
                scanner = self.instantiate_scanner(metadata, config, context, browser)
                scanners.append(scanner)
                logger.debug(f"✅ Instantiated: {metadata.name}")
            except Exception as e:
                logger.error(f"❌ Failed to instantiate {metadata.name}: {e}")
        
        return scanners
    
    @staticmethod
    def _scanner_to_config_key(scanner_name: str) -> str:
        """
        Convert ScannerName to snake_case config key.
        
        Example:
            InjectionScanner -> injection
            XSSScanner -> xss
            HTTPSmugglingScanner -> http_smuggling
        """
        # Remove "Scanner" suffix
        name = scanner_name.replace("Scanner", "")
        
        # Convert CamelCase to snake_case
        name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()
        
        return name
    
    def validate_scanner(self, scanner_class: Type) -> Tuple[bool, List[ValidationIssue]]:
        """
        Validate a scanner class has the correct signature.
        
        Checks:
        1. Has __init__(self, config, context) signature
        2. Has async scan() method
        3. scan() method returns a List
        
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        scanner_name = scanner_class.__name__
        
        # Check 1: Has __init__ with correct signature
        init_method = getattr(scanner_class, '__init__', None)
        if init_method:
            sig = inspect.signature(init_method)
            params = list(sig.parameters.keys())
            
            # Expected: self, config, context (at minimum)
            if len(params) < 3:
                issues.append(ValidationIssue(
                    scanner_name=scanner_name,
                    issue_type="wrong_init_signature",
                    message=f"__init__ should accept (self, config, context), got {params}",
                    severity="warning"
                ))
            elif 'config' not in params and len(params) >= 2:
                # Check if second param could be config
                pass  # Allow flexible naming
        
        # Check 2: Has scan method
        scan_method = getattr(scanner_class, 'scan', None)
        if scan_method is None:
            issues.append(ValidationIssue(
                scanner_name=scanner_name,
                issue_type="no_scan_method",
                message="Scanner must have a scan() method",
                severity="error"
            ))
            return False, issues
        
        # Check 3: scan method is async (coroutine function)
        if not asyncio.iscoroutinefunction(scan_method):
            issues.append(ValidationIssue(
                scanner_name=scanner_name,
                issue_type="not_async",
                message="scan() method must be async (use 'async def scan(self)')",
                severity="error"
            ))
        
        # Check 4: scan method signature (should take no args besides self)
        sig = inspect.signature(scan_method)
        params = [p for p in sig.parameters.keys() if p != 'self']
        if params:
            # Allow optional parameters
            required_params = [
                p for p, param in sig.parameters.items() 
                if p != 'self' and param.default == inspect.Parameter.empty
            ]
            if required_params:
                issues.append(ValidationIssue(
                    scanner_name=scanner_name,
                    issue_type="wrong_scan_signature",
                    message=f"scan() should not require parameters (besides self), found: {required_params}",
                    severity="warning"
                ))
        
        # Check 5: Verify return type hint if present
        return_annotation = sig.return_annotation
        if return_annotation != inspect.Signature.empty:
            # Check if it's a List type
            origin = getattr(return_annotation, '__origin__', None)
            if origin is not list and str(return_annotation).lower() not in ('list', 'list[any]'):
                issues.append(ValidationIssue(
                    scanner_name=scanner_name,
                    issue_type="wrong_return_type",
                    message=f"scan() should return List, annotated as: {return_annotation}",
                    severity="warning"
                ))
        
        is_valid = not any(issue.severity == "error" for issue in issues)
        return is_valid, issues
    
    def validate_all_scanners(self) -> Dict[str, Tuple[bool, List[ValidationIssue]]]:
        """
        Validate all registered scanners.
        
        Returns:
            Dict mapping scanner name to (is_valid, issues) tuple
        """
        results = {}
        
        for name, metadata in self._scanners.items():
            is_valid, issues = self.validate_scanner(metadata.scanner_class)
            metadata.is_valid = is_valid
            metadata.validation_issues = issues
            results[name] = (is_valid, issues)
        
        return results
    
    def get_valid_scanners(self) -> List[ScannerMetadata]:
        """Get only scanners that passed validation"""
        return [m for m in self._scanners.values() if m.is_valid]
    
    def get_invalid_scanners(self) -> List[ScannerMetadata]:
        """Get scanners that failed validation"""
        return [m for m in self._scanners.values() if not m.is_valid]
    
    def get_validation_report(self) -> str:
        """Generate a formatted validation report"""
        lines = ["Scanner Validation Report", "=" * 50]
        
        valid_count = 0
        warning_count = 0
        error_count = 0
        
        for name, metadata in sorted(self._scanners.items()):
            if metadata.is_valid and not metadata.validation_issues:
                valid_count += 1
                continue
            
            if metadata.is_valid:
                # Has warnings but is valid
                warning_count += 1
                lines.append(f"\n⚠️  {name} (warnings):")
            else:
                error_count += 1
                lines.append(f"\n❌ {name} (INVALID):")
            
            for issue in metadata.validation_issues:
                icon = "⚠️" if issue.severity == "warning" else "❌"
                lines.append(f"    {icon} {issue.issue_type}: {issue.message}")
        
        # Summary
        lines.insert(2, f"\n✅ Valid: {valid_count}")
        lines.insert(3, f"⚠️  Warnings: {warning_count}")
        lines.insert(4, f"❌ Invalid: {error_count}")
        lines.insert(5, f"📊 Total: {len(self._scanners)}")
        
        return "\n".join(lines)
    
    def list_scanners(self) -> str:
        """Return a formatted list of all registered scanners"""
        lines = ["Registered Scanners:", "=" * 50]
        
        # Group by category
        by_category: Dict[str, List[ScannerMetadata]] = {}
        for metadata in self._scanners.values():
            if metadata.category not in by_category:
                by_category[metadata.category] = []
            by_category[metadata.category].append(metadata)
        
        for category in sorted(by_category.keys()):
            lines.append(f"\n{category}:")
            for metadata in sorted(by_category[category], key=lambda x: x.name):
                status = "✓" if metadata.enabled_by_default else "○"
                lines.append(f"  {status} {metadata.name}")
        
        return "\n".join(lines)


# Global registry instance
_global_registry: Optional[ScannerRegistry] = None


def get_registry() -> ScannerRegistry:
    """Get or create global scanner registry"""
    global _global_registry
    
    if _global_registry is None:
        _global_registry = ScannerRegistry()
    
    return _global_registry


def discover_all_scanners(validate: bool = True) -> int:
    """
    Discover all scanners in the project.
    
    Args:
        validate: Whether to validate scanner signatures after discovery
    
    Returns:
        Total number of scanners discovered
    """
    registry = get_registry()
    total = 0
    
    # Discover pre-login scanners
    total += registry.discover_scanners("attacks/pre_login", package="attacks.pre_login")
    
    # Discover post-login scanners
    total += registry.discover_scanners("attacks/post_login", package="attacks.post_login")
    
    # Discover mobile scanners
    total += registry.discover_scanners("attacks/mobile", package="attacks.mobile")
    
    # Discover cloud scanners
    total += registry.discover_scanners("attacks/cloud", package="attacks.cloud")
    
    # Discover network scanners
    total += registry.discover_scanners("attacks/network", package="attacks.network")
    
    logger.info(f"📊 Total scanners discovered: {total}")
    
    # Validate all scanners if requested
    if validate:
        validation_results = registry.validate_all_scanners()
        valid_count = sum(1 for is_valid, _ in validation_results.values() if is_valid)
        invalid_count = total - valid_count
        
        if invalid_count > 0:
            logger.warning(f"⚠️ {invalid_count} scanners have validation issues")
            for name, (is_valid, issues) in validation_results.items():
                if not is_valid:
                    for issue in issues:
                        if issue.severity == "error":
                            logger.error(f"  ❌ {name}: {issue.message}")
        else:
            logger.info(f"✅ All {valid_count} scanners passed validation")
    
    return total


def validate_scanner_file(file_path: str) -> Dict[str, List[ValidationIssue]]:
    """
    Validate scanners in a specific file.
    
    Useful for CI/CD checks or pre-commit hooks.
    
    Args:
        file_path: Path to scanner file
    
    Returns:
        Dict mapping scanner name to list of validation issues
    """
    path = Path(file_path)
    if not path.exists():
        return {"_file_error": [ValidationIssue(
            scanner_name="_file",
            issue_type="file_not_found",
            message=f"File not found: {file_path}",
            severity="error"
        )]}
    
    # Determine package from path
    parts = path.parts
    try:
        attacks_idx = parts.index("attacks")
        package = ".".join(parts[attacks_idx:-1] + (path.stem,))
    except ValueError:
        package = path.stem
    
    results = {}
    
    try:
        module = importlib.import_module(package)
        
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if name.endswith("Scanner") and hasattr(obj, "scan"):
                registry = ScannerRegistry()
                is_valid, issues = registry.validate_scanner(obj)
                results[name] = issues
                
    except Exception as e:
        results["_import_error"] = [ValidationIssue(
            scanner_name="_import",
            issue_type="import_error",
            message=f"Failed to import: {e}",
            severity="error"
        )]
    
    return results


# Module-level instance for backwards compatibility
scanner_registry = ScannerRegistry()

# Convenience function to get registry
def get_registry() -> ScannerRegistry:
    """Get the global scanner registry instance."""
    return scanner_registry
