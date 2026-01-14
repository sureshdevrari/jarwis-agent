"""
OWASP A03_INJECTION

Includes legacy scanners and new sub-category scanners.
"""

# Legacy scanners (backward compatibility)
from .injection_scanner import ScanResult, InjectionScanner
from .ldap_injection_scanner import LDAPInjectionScanner, XPathInjectionScanner, EmailInjectionScanner
from .sqli_advanced_scanner import SQLInjectionScanner, UnionBasedSQLiScanner
from .ssti_scanner import SSTIScanner
from .xss_advanced_scanner import AdvancedXSSScanner, DOMXSSScanner
from .xss_reflected_scanner import XSSReflectedScanner
from .xss_scanner import XSSScanner
from .xss_stored_scanner import StoredXSSScanner
from .xxe_scanner import XXEScanner

# NEW: Sub-category scanners (modular, enhanced detection)
from .xss import XSSReflected, XSSStored, XSSDom, XSSBase, XSSResult
from .sqli import SQLiErrorBased, SQLiBlindBoolean, SQLiBlindTime, SQLiUnionBased, SQLiBase, SQLiResult

# NEW: PortSwigger-based enterprise scanners (MITM-based)
from .command_injection_scanner import CommandInjectionScannerV2, CommandInjectionScanner
from .nosql_injection_scanner import NoSQLInjectionScannerV2, NoSQLInjectionScanner
from .crlf_injection_scanner import CRLFInjectionScannerV2, CRLFInjectionScanner, HTTPResponseSplittingScanner

__all__ = [
    # Legacy
    'ScanResult', 'InjectionScanner', 'LDAPInjectionScanner', 'XPathInjectionScanner',
    'EmailInjectionScanner', 'SQLInjectionScanner', 'UnionBasedSQLiScanner', 'SSTIScanner',
    'AdvancedXSSScanner', 'DOMXSSScanner', 'XSSReflectedScanner', 'XSSScanner', 'StoredXSSScanner',
    'XXEScanner',
    # NEW sub-category XSS
    'XSSReflected', 'XSSStored', 'XSSDom', 'XSSBase', 'XSSResult',
    # NEW sub-category SQLi
    'SQLiErrorBased', 'SQLiBlindBoolean', 'SQLiBlindTime', 'SQLiUnionBased', 'SQLiBase', 'SQLiResult',
    # NEW PortSwigger-based enterprise scanners
    'CommandInjectionScannerV2', 'CommandInjectionScanner',
    'NoSQLInjectionScannerV2', 'NoSQLInjectionScanner',
    'CRLFInjectionScannerV2', 'CRLFInjectionScanner', 'HTTPResponseSplittingScanner',
]
