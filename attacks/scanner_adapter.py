"""
Jarwis Scanner Adapter Layer
=============================

Bridges the new sub-category scanners (with async scan() interface) to work with
the existing AttackEngine and UnifiedExecutor (which expect execute() interface).

This adapter:
1. Wraps new scanners to match expected interface
2. Converts results to standard ScanResult format
3. Provides unified entry point for all sub-category scanners
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Type
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AdaptedResult:
    """Standardized result from adapted scanner"""
    id: str
    category: str
    sub_type: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    remediation: str
    cwe_id: str
    poc: str
    reasoning: str
    request_data: str
    response_data: str
    confidence: float
    verification_status: str
    
    def to_dict(self) -> dict:
        return asdict(self)


class SubCategoryScannerAdapter:
    """
    Adapter that wraps new sub-category scanners to work with existing execution flow.
    
    Usage:
        adapter = SubCategoryScannerAdapter(config, context)
        findings = await adapter.run_all_xss()
        findings = await adapter.run_all_sqli()
        findings = await adapter.run_all_ssrf()
        findings = await adapter.run_all()  # Run everything
    """
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self._scanners_loaded = False
        self._xss_scanners = []
        self._sqli_scanners = []
        self._ssrf_scanners = []
    
    def _load_scanners(self):
        """Lazy-load scanner classes"""
        if self._scanners_loaded:
            return
        
        try:
            # Load XSS sub-category scanners
            from attacks.web.a03_injection.xss import XSSReflected, XSSStored, XSSDom
            self._xss_scanners = [XSSReflected, XSSStored, XSSDom]
        except ImportError as e:
            logger.warning(f"Could not load XSS sub-category scanners: {e}")
        
        try:
            # Load SQLi sub-category scanners
            from attacks.web.a03_injection.sqli import (
                SQLiErrorBased, SQLiBlindBoolean, SQLiBlindTime, SQLiUnionBased
            )
            self._sqli_scanners = [SQLiErrorBased, SQLiBlindBoolean, SQLiBlindTime, SQLiUnionBased]
        except ImportError as e:
            logger.warning(f"Could not load SQLi sub-category scanners: {e}")
        
        try:
            # Load SSRF sub-category scanners
            from attacks.web.a10_ssrf.ssrf import SSRFBasic, SSRFBlind, SSRFCloudMetadata
            self._ssrf_scanners = [SSRFBasic, SSRFBlind, SSRFCloudMetadata]
        except ImportError as e:
            logger.warning(f"Could not load SSRF sub-category scanners: {e}")
        
        self._scanners_loaded = True
    
    async def run_scanner(self, scanner_class: Type) -> List[AdaptedResult]:
        """Run a single scanner and adapt its results"""
        try:
            scanner = scanner_class(self.config, self.context)
            raw_results = await scanner.scan()
            
            adapted = []
            for result in raw_results:
                # Convert dataclass result to AdaptedResult
                adapted.append(AdaptedResult(
                    id=getattr(result, 'id', f"{scanner_class.__name__}-{len(adapted)}"),
                    category=getattr(result, 'category', 'A03:2021 - Injection'),
                    sub_type=getattr(result, 'sub_type', scanner_class.SUB_TYPE if hasattr(scanner_class, 'SUB_TYPE') else 'unknown'),
                    severity=getattr(result, 'severity', 'high'),
                    title=getattr(result, 'title', ''),
                    description=getattr(result, 'description', ''),
                    url=getattr(result, 'url', ''),
                    method=getattr(result, 'method', 'GET'),
                    parameter=getattr(result, 'parameter', ''),
                    payload=getattr(result, 'payload', ''),
                    evidence=getattr(result, 'evidence', ''),
                    remediation=getattr(result, 'remediation', ''),
                    cwe_id=getattr(result, 'cwe_id', ''),
                    poc=getattr(result, 'poc', ''),
                    reasoning=getattr(result, 'reasoning', ''),
                    request_data=getattr(result, 'request_data', ''),
                    response_data=getattr(result, 'response_data', ''),
                    confidence=getattr(result, 'confidence', 0.0),
                    verification_status=getattr(result, 'verification_status', 'pending'),
                ))
            
            logger.info(f"{scanner_class.__name__} found {len(adapted)} findings")
            return adapted
            
        except Exception as e:
            logger.error(f"Error running {scanner_class.__name__}: {e}")
            return []
    
    async def run_all_xss(self) -> List[AdaptedResult]:
        """Run all XSS sub-category scanners"""
        self._load_scanners()
        all_findings = []
        
        for scanner_class in self._xss_scanners:
            findings = await self.run_scanner(scanner_class)
            all_findings.extend(findings)
        
        logger.info(f"XSS sub-category scan complete: {len(all_findings)} total findings")
        return all_findings
    
    async def run_all_sqli(self) -> List[AdaptedResult]:
        """Run all SQLi sub-category scanners"""
        self._load_scanners()
        all_findings = []
        
        for scanner_class in self._sqli_scanners:
            findings = await self.run_scanner(scanner_class)
            all_findings.extend(findings)
        
        logger.info(f"SQLi sub-category scan complete: {len(all_findings)} total findings")
        return all_findings
    
    async def run_all_ssrf(self) -> List[AdaptedResult]:
        """Run all SSRF sub-category scanners"""
        self._load_scanners()
        all_findings = []
        
        for scanner_class in self._ssrf_scanners:
            findings = await self.run_scanner(scanner_class)
            all_findings.extend(findings)
        
        logger.info(f"SSRF sub-category scan complete: {len(all_findings)} total findings")
        return all_findings
    
    async def run_all(self) -> List[AdaptedResult]:
        """Run ALL sub-category scanners"""
        self._load_scanners()
        
        # Run all scanner types
        xss_findings = await self.run_all_xss()
        sqli_findings = await self.run_all_sqli()
        ssrf_findings = await self.run_all_ssrf()
        
        all_findings = xss_findings + sqli_findings + ssrf_findings
        logger.info(f"All sub-category scans complete: {len(all_findings)} total findings")
        
        return all_findings
    
    def get_available_scanners(self) -> Dict[str, List[str]]:
        """Get list of available sub-category scanners"""
        self._load_scanners()
        return {
            'xss': [s.__name__ for s in self._xss_scanners],
            'sqli': [s.__name__ for s in self._sqli_scanners],
            'ssrf': [s.__name__ for s in self._ssrf_scanners],
        }


# Convenience function for quick integration
async def run_subcategory_scans(config: dict, context) -> List[dict]:
    """
    Run all sub-category scanners and return findings as dicts.
    
    This is the main entry point for integrating sub-category scanners
    into existing scanning flows.
    
    Usage:
        from attacks.scanner_adapter import run_subcategory_scans
        
        findings = await run_subcategory_scans(config, context)
        all_findings.extend(findings)
    """
    adapter = SubCategoryScannerAdapter(config, context)
    results = await adapter.run_all()
    return [r.to_dict() for r in results]
