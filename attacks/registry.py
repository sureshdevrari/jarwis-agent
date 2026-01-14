"""
Unified Scanner Registry

Single source of truth for all scanner discovery and management.
Consolidates the previous 3 registries:
- attacks/__init__.py (AttackDispatcher)
- attacks/scanner_registry.py (ScannerRegistry)
- attacks/unified_registry.py (UnifiedScannerRegistry)

Now supports both legacy scanners and new BaseAttackScanner-based scanners.

Usage:
    from attacks.registry import ScannerRegistry, ScanType
    
    # Get all scanners for a scan type
    web_scanners = ScannerRegistry.get_scanners(ScanType.WEB)
    
    # Get specific scanner
    sqli_scanner = ScannerRegistry.get_scanner("sqli_v2")
    
    # Create scanner instance with new interface
    scanner_class = ScannerRegistry.get_scanner_class("sqli_v2")
    scanner = scanner_class(http_client=client, request_store=store)
    findings = await scanner.run()
"""

import logging
import importlib
import inspect
from typing import Dict, List, Type, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Supported scan types."""
    WEB = "web"
    MOBILE = "mobile"
    NETWORK = "network"
    CLOUD = "cloud"
    SAST = "sast"


class OWASPCategory(Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS = "A01"
    A02_CRYPTO = "A02"
    A03_INJECTION = "A03"
    A04_INSECURE_DESIGN = "A04"
    A05_MISCONFIG = "A05"
    A06_VULNERABLE_COMPONENTS = "A06"
    A07_AUTH_FAILURES = "A07"
    A08_INTEGRITY = "A08"
    A09_LOGGING = "A09"
    A10_SSRF = "A10"


class ScannerInterface(Enum):
    """Scanner interface type."""
    LEGACY = "legacy"           # Old style: scan() method, direct aiohttp
    BASE_ATTACK = "base_attack" # New style: extends BaseAttackScanner, uses MITM


@dataclass
class ScannerInfo:
    """Metadata about a scanner."""
    name: str
    scan_type: ScanType
    owasp_category: Optional[OWASPCategory] = None
    description: str = ""
    enabled: bool = True
    class_name: str = ""
    module_path: str = ""
    interface: ScannerInterface = ScannerInterface.LEGACY
    attack_type: str = ""
    cwe_id: str = ""
    priority: int = 50  # 0-100, higher = run first
    
    # Cached class reference
    _cached_class: Optional[Type] = field(default=None, repr=False)


class ScannerRegistry:
    """
    Unified scanner registry for all scan types.
    
    Provides:
    - Scanner discovery by scan type
    - Scanner lookup by name
    - OWASP category filtering
    - Health checking
    - Support for both legacy and new BaseAttackScanner interface
    """
    
    _scanners: Dict[str, ScannerInfo] = {}
    _initialized: bool = False
    _base_attack_scanner_class: Optional[Type] = None
    
    @classmethod
    def initialize(cls) -> None:
        """Initialize the registry by discovering all scanners."""
        if cls._initialized:
            return
        
        # Try to import BaseAttackScanner for interface detection
        try:
            from attacks.web.base_attack_scanner import BaseAttackScanner
            cls._base_attack_scanner_class = BaseAttackScanner
        except ImportError:
            logger.warning("BaseAttackScanner not found - new interface detection disabled")
            cls._base_attack_scanner_class = None
        
        cls._discover_web_scanners()
        cls._discover_mobile_scanners()
        cls._discover_network_scanners()
        cls._discover_cloud_scanners()
        cls._discover_sast_scanners()
        
        cls._initialized = True
        
        # Count by interface type
        legacy_count = sum(1 for s in cls._scanners.values() if s.interface == ScannerInterface.LEGACY)
        new_count = sum(1 for s in cls._scanners.values() if s.interface == ScannerInterface.BASE_ATTACK)
        
        logger.info(
            f"Scanner registry initialized with {len(cls._scanners)} scanners "
            f"({new_count} new interface, {legacy_count} legacy)"
        )
    
    @classmethod
    def _discover_web_scanners(cls) -> None:
        """Discover web scanners from attacks/web/."""
        web_dir = Path(__file__).parent / "web"
        
        # Scan OWASP category folders
        for category_dir in web_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("_"):
                for scanner_file in category_dir.glob("*_scanner.py"):
                    cls._register_scanner_from_file(
                        scanner_file, 
                        ScanType.WEB,
                        category_dir.name
                    )
    
    @classmethod
    def _discover_mobile_scanners(cls) -> None:
        """Discover mobile scanners from attacks/mobile/."""
        mobile_dir = Path(__file__).parent / "mobile"
        
        for phase_dir in mobile_dir.iterdir():
            if phase_dir.is_dir() and not phase_dir.name.startswith("_"):
                for scanner_file in phase_dir.glob("*.py"):
                    if not scanner_file.name.startswith("_"):
                        cls._register_scanner_from_file(
                            scanner_file,
                            ScanType.MOBILE,
                            phase_dir.name
                        )
    
    @classmethod
    def _discover_network_scanners(cls) -> None:
        """Discover network scanners from attacks/network/."""
        network_dir = Path(__file__).parent / "network"
        scanners_dir = network_dir / "scanners"
        
        if scanners_dir.exists():
            for scanner_file in scanners_dir.glob("*.py"):
                if not scanner_file.name.startswith("_"):
                    cls._register_scanner_from_file(
                        scanner_file,
                        ScanType.NETWORK
                    )
    
    @classmethod
    def _discover_cloud_scanners(cls) -> None:
        """Discover cloud scanners from attacks/cloud/."""
        cloud_dir = Path(__file__).parent / "cloud"
        
        for provider_dir in cloud_dir.iterdir():
            if provider_dir.is_dir() and not provider_dir.name.startswith("_"):
                for scanner_file in provider_dir.glob("*_scanner.py"):
                    cls._register_scanner_from_file(
                        scanner_file,
                        ScanType.CLOUD,
                        provider_dir.name
                    )
    
    @classmethod
    def _discover_sast_scanners(cls) -> None:
        """Discover SAST scanners from attacks/sast/."""
        sast_dir = Path(__file__).parent / "sast"
        
        for func_dir in sast_dir.iterdir():
            if func_dir.is_dir() and not func_dir.name.startswith("_"):
                for scanner_file in func_dir.glob("*.py"):
                    if not scanner_file.name.startswith("_"):
                        cls._register_scanner_from_file(
                            scanner_file,
                            ScanType.SAST,
                            func_dir.name
                        )
    
    @classmethod
    def _register_scanner_from_file(
        cls,
        file_path: Path,
        scan_type: ScanType,
        category: str = None
    ) -> None:
        """Register a scanner from its file path."""
        name = file_path.stem
        module_path = str(file_path.relative_to(Path(__file__).parent.parent))
        module_path = module_path.replace("/", ".").replace("\\", ".").replace(".py", "")
        
        # Map category to OWASP
        owasp = None
        if scan_type == ScanType.WEB and category:
            owasp_map = {
                "a01_broken_access": OWASPCategory.A01_BROKEN_ACCESS,
                "a02_crypto": OWASPCategory.A02_CRYPTO,
                "a03_injection": OWASPCategory.A03_INJECTION,
                "a04_insecure_design": OWASPCategory.A04_INSECURE_DESIGN,
                "a05_misconfig": OWASPCategory.A05_MISCONFIG,
                "a06_vulnerable_components": OWASPCategory.A06_VULNERABLE_COMPONENTS,
                "a07_auth_failures": OWASPCategory.A07_AUTH_FAILURES,
                "a08_integrity": OWASPCategory.A08_INTEGRITY,
                "a09_logging": OWASPCategory.A09_LOGGING,
                "a10_ssrf": OWASPCategory.A10_SSRF,
            }
            owasp = owasp_map.get(category)
        
        # Detect scanner interface by inspecting the class
        interface = ScannerInterface.LEGACY
        attack_type = ""
        cwe_id = ""
        class_name = ""
        priority = 50
        
        try:
            module = importlib.import_module(module_path)
            
            # Find scanner class in module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if not inspect.isclass(attr):
                    continue
                if attr_name.startswith('_'):
                    continue
                
                # Check if it's a BaseAttackScanner subclass
                if cls._base_attack_scanner_class and issubclass(attr, cls._base_attack_scanner_class):
                    if attr is not cls._base_attack_scanner_class:
                        interface = ScannerInterface.BASE_ATTACK
                        class_name = attr_name
                        attack_type = getattr(attr, 'attack_type', '')
                        cwe_id = getattr(attr, 'cwe_id', '')
                        priority = 80  # New interface gets higher priority
                        break
                
                # Legacy scanner detection
                if 'Scanner' in attr_name and hasattr(attr, 'scan'):
                    class_name = attr_name
                    break
                    
        except Exception as e:
            logger.debug(f"Could not inspect scanner {name}: {e}")
        
        cls._scanners[name] = ScannerInfo(
            name=name,
            scan_type=scan_type,
            owasp_category=owasp,
            module_path=module_path,
            interface=interface,
            class_name=class_name,
            attack_type=attack_type,
            cwe_id=cwe_id,
            priority=priority,
        )
    
    @classmethod
    def get_scanners(
        cls,
        scan_type: ScanType = None,
        owasp_category: OWASPCategory = None,
        enabled_only: bool = True,
        interface: ScannerInterface = None,
        new_interface_only: bool = False
    ) -> List[ScannerInfo]:
        """
        Get scanners matching filters.
        
        Args:
            scan_type: Filter by scan type
            owasp_category: Filter by OWASP category
            enabled_only: Only return enabled scanners
            interface: Filter by interface type
            new_interface_only: Only return BaseAttackScanner-based scanners
            
        Returns:
            List of matching scanners, sorted by priority (highest first)
        """
        cls.initialize()
        
        result = []
        for scanner in cls._scanners.values():
            if scan_type and scanner.scan_type != scan_type:
                continue
            if owasp_category and scanner.owasp_category != owasp_category:
                continue
            if enabled_only and not scanner.enabled:
                continue
            if interface and scanner.interface != interface:
                continue
            if new_interface_only and scanner.interface != ScannerInterface.BASE_ATTACK:
                continue
            result.append(scanner)
        
        # Sort by priority (highest first)
        result.sort(key=lambda s: s.priority, reverse=True)
        
        return result
    
    @classmethod
    def get_scanner(cls, name: str) -> Optional[ScannerInfo]:
        """Get a specific scanner by name."""
        cls.initialize()
        return cls._scanners.get(name)
    
    @classmethod
    def get_scanner_class(cls, name: str) -> Optional[Type]:
        """Dynamically import and return the scanner class."""
        scanner = cls.get_scanner(name)
        if not scanner:
            return None
        
        # Return cached class if available
        if scanner._cached_class:
            return scanner._cached_class
        
        try:
            module = importlib.import_module(scanner.module_path)
            
            # Try the detected class name first
            if scanner.class_name and hasattr(module, scanner.class_name):
                cls_obj = getattr(module, scanner.class_name)
                scanner._cached_class = cls_obj
                return cls_obj
            
            # Try common class name patterns
            class_names = [
                f"{name.title().replace('_', '')}Scanner",
                f"{name.title().replace('_', '')}",
                f"{name.upper()}Scanner",
                name.title().replace('_', ''),
            ]
            
            for class_name in class_names:
                if hasattr(module, class_name):
                    cls_obj = getattr(module, class_name)
                    scanner._cached_class = cls_obj
                    return cls_obj
            
            # Last resort: find any class that looks like a scanner
            for attr_name in dir(module):
                if 'Scanner' in attr_name and not attr_name.startswith('_'):
                    attr = getattr(module, attr_name)
                    if inspect.isclass(attr):
                        scanner._cached_class = attr
                        return attr
            
            return None
        except ImportError as e:
            logger.error(f"Failed to import scanner {name}: {e}")
            return None
    
    @classmethod
    def create_scanner_instance(
        cls,
        name: str,
        http_client: Any = None,
        request_store: Any = None,
        checkpoint: Any = None,
        token_manager: Any = None,
        config: Dict[str, Any] = None,
        context: Any = None
    ) -> Optional[Any]:
        """
        Create a scanner instance with appropriate dependencies.
        
        For new BaseAttackScanner-based scanners, provides all required deps.
        For legacy scanners, provides config and context.
        
        Args:
            name: Scanner name
            http_client: JarwisHTTPClient instance (for new interface)
            request_store: RequestStoreDB instance (for new interface)
            checkpoint: RequestLevelCheckpoint instance (optional)
            token_manager: TokenManager instance (optional)
            config: Scanner configuration dict
            context: Legacy context object
            
        Returns:
            Instantiated scanner or None if not found
        """
        scanner_info = cls.get_scanner(name)
        if not scanner_info:
            logger.error(f"Scanner not found: {name}")
            return None
        
        scanner_class = cls.get_scanner_class(name)
        if not scanner_class:
            logger.error(f"Could not load scanner class: {name}")
            return None
        
        try:
            if scanner_info.interface == ScannerInterface.BASE_ATTACK:
                # New interface - requires http_client and request_store
                if not http_client or not request_store:
                    raise ValueError(
                        f"Scanner {name} requires http_client and request_store"
                    )
                return scanner_class(
                    http_client=http_client,
                    request_store=request_store,
                    checkpoint=checkpoint,
                    token_manager=token_manager,
                    config=config or {}
                )
            else:
                # Legacy interface
                return scanner_class(config=config or {}, context=context)
                
        except Exception as e:
            logger.error(f"Failed to instantiate scanner {name}: {e}")
            return None
    
    @classmethod
    def get_scanners_by_attack_type(cls, attack_type: str) -> List[ScannerInfo]:
        """Get all scanners for a specific attack type (e.g., 'sqli', 'xss')."""
        cls.initialize()
        return [
            s for s in cls._scanners.values()
            if s.attack_type == attack_type
        ]
    
    @classmethod
    def get_scanner_names(
        cls,
        scan_type: ScanType = None,
        new_interface_only: bool = False
    ) -> List[str]:
        """Get list of scanner names."""
        scanners = cls.get_scanners(
            scan_type=scan_type,
            new_interface_only=new_interface_only
        )
        return [s.name for s in scanners]
    
    @classmethod
    def reset(cls) -> None:
        """Reset the registry (mainly for testing)."""
        cls._scanners.clear()
        cls._initialized = False
        cls._base_attack_scanner_class = None


# Initialize on import
ScannerRegistry.initialize()


# =============================================================================
# Convenience functions for common operations
# =============================================================================

def get_web_scanners(new_interface_only: bool = False) -> List[ScannerInfo]:
    """Get all web scanners."""
    return ScannerRegistry.get_scanners(
        scan_type=ScanType.WEB,
        new_interface_only=new_interface_only
    )


def get_scanner(name: str) -> Optional[Type]:
    """Get a scanner class by name."""
    return ScannerRegistry.get_scanner_class(name)


def create_scanner(
    name: str,
    http_client: Any = None,
    request_store: Any = None,
    **kwargs
) -> Optional[Any]:
    """Create a scanner instance."""
    return ScannerRegistry.create_scanner_instance(
        name=name,
        http_client=http_client,
        request_store=request_store,
        **kwargs
    )


__all__ = [
    'ScanType',
    'OWASPCategory',
    'ScannerInterface',
    'ScannerInfo',
    'ScannerRegistry',
    'AttackRegistry',  # Alias for backwards compatibility
    'get_web_scanners',
    'get_scanner',
    'create_scanner',
]

# Backwards compatibility alias
AttackRegistry = ScannerRegistry
