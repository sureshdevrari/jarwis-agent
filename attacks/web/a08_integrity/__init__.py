"""
OWASP A08_INTEGRITY
"""

from .prototype_pollution_scanner import ScanResult, PrototypePollutionScanner, DeserializationScanner

__all__ = ['ScanResult', 'PrototypePollutionScanner', 'DeserializationScanner']
