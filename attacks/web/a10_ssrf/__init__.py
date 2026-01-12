"""
OWASP A10_SSRF
"""

from .ssrf_advanced_scanner import ScanResult, SSRFScanner, BlindSSRFScanner
from .ssrf_scanner import ScanResult, SSRFScanner

__all__ = ['ScanResult', 'SSRFScanner', 'BlindSSRFScanner', 'ScanResult', 'SSRFScanner']
