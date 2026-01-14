"""
OWASP A08_INTEGRITY
"""

from .prototype_pollution_scanner import ScanResult, PrototypePollutionScanner, DeserializationScanner

# NEW: PortSwigger-based enterprise scanners (MITM-based)
from .deserialization_scanner import DeserializationScannerV2, InsecureDeserializationScanner

__all__ = [
    'ScanResult', 'PrototypePollutionScanner', 'DeserializationScanner',
    # NEW PortSwigger-based enterprise scanners
    'DeserializationScannerV2', 'InsecureDeserializationScanner',
]
