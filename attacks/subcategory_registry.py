"""
Jarwis Sub-Category Scanner Registry
=====================================

Maps attack categories to their sub-type scanners.
This enables clear reporting: "XSS Reflected Found" vs just "XSS"

Usage:
    from attacks.subcategory_registry import get_scanners_for_category
    
    xss_scanners = get_scanners_for_category('xss')
    # Returns: [XSSReflected, XSSStored, XSSDom]
"""

from typing import Dict, List, Type, Optional
import logging

logger = logging.getLogger(__name__)


# Sub-category scanner mappings
SUBCATEGORY_SCANNERS = {
    # XSS Sub-types
    'xss': {
        'module': 'attacks.web.a03_injection.xss',
        'scanners': [
            {'name': 'XSSReflected', 'class': 'XSSReflected', 'sub_type': 'reflected'},
            {'name': 'XSSStored', 'class': 'XSSStored', 'sub_type': 'stored'},
            {'name': 'XSSDom', 'class': 'XSSDom', 'sub_type': 'dom'},
        ]
    },
    
    # SQLi Sub-types
    'sqli': {
        'module': 'attacks.web.a03_injection.sqli',
        'scanners': [
            {'name': 'SQLiErrorBased', 'class': 'SQLiErrorBased', 'sub_type': 'error_based'},
            {'name': 'SQLiBlindBoolean', 'class': 'SQLiBlindBoolean', 'sub_type': 'blind_boolean'},
            {'name': 'SQLiBlindTime', 'class': 'SQLiBlindTime', 'sub_type': 'blind_time'},
            {'name': 'SQLiUnionBased', 'class': 'SQLiUnionBased', 'sub_type': 'union_based'},
        ]
    },
    
    # SSRF Sub-types
    'ssrf': {
        'module': 'attacks.web.a10_ssrf.ssrf',
        'scanners': [
            {'name': 'SSRFBasic', 'class': 'SSRFBasic', 'sub_type': 'basic'},
            {'name': 'SSRFBlind', 'class': 'SSRFBlind', 'sub_type': 'blind'},
            {'name': 'SSRFCloudMetadata', 'class': 'SSRFCloudMetadata', 'sub_type': 'cloud_metadata'},
        ]
    },
}


def get_scanners_for_category(category: str) -> List[Type]:
    """Get all scanner classes for a category"""
    if category not in SUBCATEGORY_SCANNERS:
        return []
    
    info = SUBCATEGORY_SCANNERS[category]
    scanners = []
    
    try:
        import importlib
        module = importlib.import_module(info['module'])
        
        for scanner_info in info['scanners']:
            cls = getattr(module, scanner_info['class'], None)
            if cls:
                scanners.append(cls)
            else:
                logger.warning(f"Scanner {scanner_info['class']} not found in {info['module']}")
    except ImportError as e:
        logger.error(f"Failed to import {info['module']}: {e}")
    
    return scanners


def get_all_subcategory_scanners() -> Dict[str, List[dict]]:
    """Get mapping of all categories to their sub-type scanners"""
    return SUBCATEGORY_SCANNERS


def format_finding_title(category: str, sub_type: str, param: str = "") -> str:
    """Format a finding title with sub-type info"""
    titles = {
        'xss': {
            'reflected': f"XSS Reflected{f' - {param}' if param else ''}",
            'stored': f"XSS Stored{f' - {param}' if param else ''}",
            'dom': f"XSS DOM-based{f' - {param}' if param else ''}",
        },
        'sqli': {
            'error_based': f"SQL Injection (Error-Based){f' - {param}' if param else ''}",
            'blind_boolean': f"SQL Injection (Blind Boolean){f' - {param}' if param else ''}",
            'blind_time': f"SQL Injection (Blind Time-Based){f' - {param}' if param else ''}",
            'union_based': f"SQL Injection (UNION-Based){f' - {param}' if param else ''}",
        },
        'ssrf': {
            'basic': f"SSRF (Basic){f' - {param}' if param else ''}",
            'blind': f"SSRF (Blind/OOB){f' - {param}' if param else ''}",
            'cloud_metadata': f"SSRF (Cloud Metadata){f' - {param}' if param else ''}",
        },
    }
    
    return titles.get(category, {}).get(sub_type, f"{category.upper()} - {sub_type}")
