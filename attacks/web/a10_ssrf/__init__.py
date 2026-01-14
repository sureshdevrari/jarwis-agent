"""
OWASP A10_SSRF

Includes legacy scanners and new sub-category scanners.
"""

# Legacy scanners (backward compatibility)
from .ssrf_advanced_scanner import ScanResult, SSRFScanner, BlindSSRFScanner
from .ssrf_scanner import SSRFScanner as LegacySSRFScanner

# NEW: Sub-category scanners (modular, enhanced detection)
from .ssrf import SSRFBasic, SSRFBlind, SSRFCloudMetadata

__all__ = [
    # Legacy
    'ScanResult', 'SSRFScanner', 'BlindSSRFScanner', 'LegacySSRFScanner',
    # NEW sub-category SSRF
    'SSRFBasic', 'SSRFBlind', 'SSRFCloudMetadata',
]
