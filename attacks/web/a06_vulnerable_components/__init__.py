"""
OWASP A06_VULNERABLE_COMPONENTS
"""

from .subdomain_takeover_scanner import ScanResult, SubdomainTakeoverScanner

__all__ = ['ScanResult', 'SubdomainTakeoverScanner']
