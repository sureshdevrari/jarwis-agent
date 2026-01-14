"""
Jarwis Unified Scanner Registry
================================

Central registry for all scanner types with validation and health checking.
This ensures all scanners are properly connected before scans run.

Usage:
    from attacks.unified_registry import scanner_registry
    
    # Check all scanners at startup
    health = await scanner_registry.validate_all()
    
    # Get a scanner class safely
    WebScanRunner = scanner_registry.get_scanner('web')
    
    # Check if a scan type is available
    if scanner_registry.is_available('mobile'):
        # Safe to run mobile scan
        pass
"""

import importlib
import logging
from typing import Dict, List, Tuple, Optional, Any, Type
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ScanType(str, Enum):
    """Supported scan types"""
    WEB = "web"
    MOBILE = "mobile"
    NETWORK = "network"
    CLOUD = "cloud"
    SAST = "sast"


class ScannerStatus(str, Enum):
    """Scanner health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"


@dataclass
class ScannerInfo:
    """Information about a scanner"""
    name: str
    module_path: str
    class_name: str
    scan_type: ScanType
    description: str = ""
    required: bool = True  # Is this scanner required for the scan type to work?
    fallback_module: Optional[str] = None  # Fallback if primary fails
    fallback_class: Optional[str] = None


@dataclass
class ScannerHealthResult:
    """Result of a scanner health check"""
    scanner_name: str
    scan_type: str
    status: ScannerStatus
    message: str
    module_path: str
    class_name: str
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    fallback_used: bool = False
    error_details: Optional[str] = None


class UnifiedScannerRegistry:
    """
    Central registry for all Jarwis scanners.
    
    Provides:
    - Startup validation of all scanner imports
    - Runtime health checking
    - Safe scanner retrieval with fallbacks
    - Visibility into which scan types are available
    """
    
    # Define all required scanners for each scan type
    SCANNERS: Dict[ScanType, List[ScannerInfo]] = {
        ScanType.WEB: [
            ScannerInfo(
                name="WebScanRunner",
                module_path="core.web_scan_runner",
                class_name="WebScanRunner",
                scan_type=ScanType.WEB,
                description="Main web application security scanner",
                required=True,
                fallback_module="core.runner",
                fallback_class="PenTestRunner"
            ),
            ScannerInfo(
                name="BrowserController",
                module_path="core.browser",
                class_name="BrowserController",
                scan_type=ScanType.WEB,
                description="Playwright browser automation",
                required=True
            ),
            ScannerInfo(
                name="AttackEngine",
                module_path="core.attack_engine",
                class_name="AttackEngine",
                scan_type=ScanType.WEB,
                description="Attack execution engine",
                required=True
            ),
        ],
        ScanType.MOBILE: [
            ScannerInfo(
                name="MobilePenTestOrchestrator",
                module_path="attacks.mobile.mobile_orchestrator",
                class_name="MobilePenTestOrchestrator",
                scan_type=ScanType.MOBILE,
                description="Mobile app penetration testing orchestrator",
                required=True
            ),
            ScannerInfo(
                name="FridaSSLBypass",
                module_path="attacks.mobile.frida_ssl_bypass",
                class_name="FridaSSLBypass",
                scan_type=ScanType.MOBILE,
                description="Frida-based SSL pinning bypass",
                required=False  # Can do static analysis without Frida
            ),
            ScannerInfo(
                name="EmulatorManager",
                module_path="attacks.mobile.emulator_manager",
                class_name="EmulatorManager",
                scan_type=ScanType.MOBILE,
                description="Android emulator management",
                required=False
            ),
            ScannerInfo(
                name="StaticAnalyzer",
                module_path="attacks.mobile.static_analyzer",
                class_name="StaticAnalyzer",
                scan_type=ScanType.MOBILE,
                description="APK/IPA static analysis",
                required=True
            ),
            # Mobile API Attack Scanners
            ScannerInfo(
                name="MobileSQLiScanner",
                module_path="attacks.mobile.api.mobile_sqli_scanner",
                class_name="MobileSQLiScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile SQL injection scanner",
                required=False
            ),
            ScannerInfo(
                name="MobileXSSScanner",
                module_path="attacks.mobile.api.mobile_xss_scanner",
                class_name="MobileXSSScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile XSS scanner",
                required=False
            ),
            ScannerInfo(
                name="MobileIDORScanner",
                module_path="attacks.mobile.api.mobile_idor_scanner",
                class_name="MobileIDORScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile IDOR scanner",
                required=False
            ),
            ScannerInfo(
                name="MobileNoSQLScanner",
                module_path="attacks.mobile.api.mobile_nosql_scanner",
                class_name="MobileNoSQLScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile NoSQL injection scanner",
                required=False
            ),
            ScannerInfo(
                name="MobileCommandInjectionScanner",
                module_path="attacks.mobile.api.mobile_cmdi_scanner",
                class_name="MobileCommandInjectionScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile OS command injection scanner",
                required=False
            ),
            ScannerInfo(
                name="MobileSSTIScanner",
                module_path="attacks.mobile.api.mobile_ssti_scanner",
                class_name="MobileSSTIScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile SSTI scanner",
                required=False
            ),
            ScannerInfo(
                name="MobileXXEScanner",
                module_path="attacks.mobile.api.mobile_xxe_scanner",
                class_name="MobileXXEScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile XXE scanner",
                required=False
            ),
            ScannerInfo(
                name="MobileSSRFScanner",
                module_path="attacks.mobile.api.mobile_ssrf_scanner",
                class_name="MobileSSRFScanner",
                scan_type=ScanType.MOBILE,
                description="Mobile SSRF scanner",
                required=False
            ),
        ],
        ScanType.NETWORK: [
            ScannerInfo(
                name="NetworkOrchestrator",
                module_path="attacks.network.orchestrator",
                class_name="NetworkOrchestrator",
                scan_type=ScanType.NETWORK,
                description="Network security scan orchestrator",
                required=True
            ),
            ScannerInfo(
                name="PortScanner",
                module_path="attacks.network.port_scanner",
                class_name="PortScanner",
                scan_type=ScanType.NETWORK,
                description="TCP/UDP port scanning",
                required=True
            ),
            ScannerInfo(
                name="VulnerabilityScanner",
                module_path="attacks.network.vuln_scanner",
                class_name="VulnerabilityScanner",
                scan_type=ScanType.NETWORK,
                description="CVE vulnerability detection",
                required=False
            ),
        ],
        ScanType.CLOUD: [
            ScannerInfo(
                name="CloudScanRunner",
                module_path="core.cloud_scan_runner",
                class_name="CloudScanRunner",
                scan_type=ScanType.CLOUD,
                description="Cloud security posture scanner",
                required=True
            ),
            ScannerInfo(
                name="AWSScanner",
                module_path="attacks.cloud.aws_scanner",
                class_name="AWSSecurityScanner",
                scan_type=ScanType.CLOUD,
                description="AWS security scanner",
                required=False
            ),
            ScannerInfo(
                name="AzureScanner",
                module_path="attacks.cloud.azure_scanner",
                class_name="AzureSecurityScanner",
                scan_type=ScanType.CLOUD,
                description="Azure security scanner",
                required=False
            ),
            ScannerInfo(
                name="GCPScanner",
                module_path="attacks.cloud.gcp_scanner",
                class_name="GCPSecurityScanner",
                scan_type=ScanType.CLOUD,
                description="Google Cloud security scanner",
                required=False
            ),
        ],
        ScanType.SAST: [
            ScannerInfo(
                name="SASTScanRunner",
                module_path="core.sast_scan_runner",
                class_name="SASTScanRunner",
                scan_type=ScanType.SAST,
                description="Static Application Security Testing scanner",
                required=True
            ),
        ],
    }
    
    def __init__(self):
        self._cache: Dict[str, Type] = {}  # Cache imported classes
        self._health_results: Dict[str, ScannerHealthResult] = {}
        self._last_validation: Optional[datetime] = None
    
    def _try_import(self, module_path: str, class_name: str) -> Tuple[bool, Optional[Type], str]:
        """
        Try to import a scanner class.
        
        Returns:
            Tuple of (success, class_or_none, error_message)
        """
        cache_key = f"{module_path}.{class_name}"
        
        # Check cache first
        if cache_key in self._cache:
            return True, self._cache[cache_key], "OK (cached)"
        
        try:
            module = importlib.import_module(module_path)
            scanner_class = getattr(module, class_name)
            self._cache[cache_key] = scanner_class
            return True, scanner_class, "OK"
        except ImportError as e:
            return False, None, f"ImportError: {str(e)}"
        except AttributeError as e:
            return False, None, f"AttributeError: {class_name} not found in {module_path}"
        except Exception as e:
            return False, None, f"{type(e).__name__}: {str(e)}"
    
    def validate_scanner(self, scanner_info: ScannerInfo) -> ScannerHealthResult:
        """Validate a single scanner"""
        success, scanner_class, message = self._try_import(
            scanner_info.module_path,
            scanner_info.class_name
        )
        
        fallback_used = False
        
        # Try fallback if primary failed and fallback exists
        if not success and scanner_info.fallback_module:
            logger.info(f"Trying fallback for {scanner_info.name}: {scanner_info.fallback_module}")
            fallback_success, fallback_class, fallback_msg = self._try_import(
                scanner_info.fallback_module,
                scanner_info.fallback_class
            )
            if fallback_success:
                success = True
                fallback_used = True
                message = f"Using fallback: {scanner_info.fallback_class}"
        
        # Determine status
        if success:
            status = ScannerStatus.HEALTHY
        elif scanner_info.required:
            status = ScannerStatus.UNAVAILABLE
        else:
            status = ScannerStatus.DEGRADED
        
        result = ScannerHealthResult(
            scanner_name=scanner_info.name,
            scan_type=scanner_info.scan_type.value,
            status=status,
            message=message,
            module_path=scanner_info.module_path,
            class_name=scanner_info.class_name,
            fallback_used=fallback_used,
            error_details=message if not success else None
        )
        
        # Store in health results
        self._health_results[scanner_info.name] = result
        
        return result
    
    def validate_all(self) -> Dict[str, List[ScannerHealthResult]]:
        """
        Validate all registered scanners.
        
        Returns:
            Dict mapping scan type to list of health results
        """
        results: Dict[str, List[ScannerHealthResult]] = {}
        
        for scan_type, scanners in self.SCANNERS.items():
            results[scan_type.value] = []
            for scanner_info in scanners:
                result = self.validate_scanner(scanner_info)
                results[scan_type.value].append(result)
                
                if result.status == ScannerStatus.HEALTHY:
                    logger.debug(f"✅ {scanner_info.name}: {result.message}")
                elif result.status == ScannerStatus.DEGRADED:
                    logger.warning(f"⚠️ {scanner_info.name}: {result.message}")
                else:
                    logger.error(f"❌ {scanner_info.name}: {result.message}")
        
        self._last_validation = datetime.utcnow()
        return results
    
    async def validate_all_async(self) -> Dict[str, List[ScannerHealthResult]]:
        """Async version of validate_all for use in async contexts"""
        return self.validate_all()
    
    def get_scanner(self, scan_type: str, scanner_name: str = None) -> Optional[Type]:
        """
        Get a scanner class by scan type.
        
        Args:
            scan_type: One of 'web', 'mobile', 'network', 'cloud'
            scanner_name: Optional specific scanner name (e.g., 'WebScanRunner')
        
        Returns:
            The scanner class or None if not available
        """
        try:
            scan_type_enum = ScanType(scan_type)
        except ValueError:
            logger.error(f"Invalid scan type: {scan_type}")
            return None
        
        scanners = self.SCANNERS.get(scan_type_enum, [])
        
        for scanner_info in scanners:
            if scanner_name and scanner_info.name != scanner_name:
                continue
            
            if scanner_info.required or scanner_name == scanner_info.name:
                success, scanner_class, _ = self._try_import(
                    scanner_info.module_path,
                    scanner_info.class_name
                )
                
                if success:
                    return scanner_class
                
                # Try fallback
                if scanner_info.fallback_module:
                    success, scanner_class, _ = self._try_import(
                        scanner_info.fallback_module,
                        scanner_info.fallback_class
                    )
                    if success:
                        return scanner_class
        
        return None
    
    def is_available(self, scan_type: str) -> bool:
        """Check if a scan type has all required scanners available"""
        try:
            scan_type_enum = ScanType(scan_type)
        except ValueError:
            return False
        
        scanners = self.SCANNERS.get(scan_type_enum, [])
        
        for scanner_info in scanners:
            if not scanner_info.required:
                continue
            
            success, _, _ = self._try_import(
                scanner_info.module_path,
                scanner_info.class_name
            )
            
            if not success and scanner_info.fallback_module:
                success, _, _ = self._try_import(
                    scanner_info.fallback_module,
                    scanner_info.fallback_class
                )
            
            if not success:
                return False
        
        return True
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get a summary of scanner health for API response"""
        summary = {
            "overall_status": "healthy",
            "last_checked": self._last_validation.isoformat() if self._last_validation else None,
            "scan_types": {},
            "total_scanners": 0,
            "healthy_count": 0,
            "degraded_count": 0,
            "unavailable_count": 0,
        }
        
        for scan_type in ScanType:
            type_scanners = [
                r for r in self._health_results.values()
                if r.scan_type == scan_type.value
            ]
            
            if not type_scanners:
                summary["scan_types"][scan_type.value] = {
                    "status": "not_checked",
                    "available": False,
                    "scanners": []
                }
                continue
            
            healthy = sum(1 for r in type_scanners if r.status == ScannerStatus.HEALTHY)
            degraded = sum(1 for r in type_scanners if r.status == ScannerStatus.DEGRADED)
            unavailable = sum(1 for r in type_scanners if r.status == ScannerStatus.UNAVAILABLE)
            
            summary["total_scanners"] += len(type_scanners)
            summary["healthy_count"] += healthy
            summary["degraded_count"] += degraded
            summary["unavailable_count"] += unavailable
            
            # Determine scan type status
            if unavailable > 0:
                type_status = "unavailable"
                summary["overall_status"] = "degraded"
            elif degraded > 0:
                type_status = "degraded"
                if summary["overall_status"] == "healthy":
                    summary["overall_status"] = "degraded"
            else:
                type_status = "healthy"
            
            summary["scan_types"][scan_type.value] = {
                "status": type_status,
                "available": self.is_available(scan_type.value),
                "healthy": healthy,
                "degraded": degraded,
                "unavailable": unavailable,
                "scanners": [
                    {
                        "name": r.scanner_name,
                        "status": r.status.value,
                        "message": r.message,
                        "fallback_used": r.fallback_used
                    }
                    for r in type_scanners
                ]
            }
        
        return summary
    
    def clear_cache(self):
        """Clear the import cache (useful for hot-reload)"""
        self._cache.clear()
        self._health_results.clear()
        self._last_validation = None


# Global singleton instance
scanner_registry = UnifiedScannerRegistry()


# Convenience functions
async def validate_all_scanners() -> Dict[str, List[ScannerHealthResult]]:
    """Validate all scanners (async)"""
    return await scanner_registry.validate_all()


def get_scanner_class(scan_type: str, scanner_name: str = None) -> Optional[Type]:
    """Get a scanner class by type"""
    return scanner_registry.get_scanner(scan_type, scanner_name)


def is_scan_type_available(scan_type: str) -> bool:
    """Check if a scan type is available"""
    return scanner_registry.is_available(scan_type)


def get_health_summary() -> Dict[str, Any]:
    """Get scanner health summary"""
    return scanner_registry.get_health_summary()
