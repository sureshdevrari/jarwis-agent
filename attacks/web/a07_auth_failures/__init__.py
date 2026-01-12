"""
OWASP A07_AUTH_FAILURES
"""

from .auth_scanner import ScanResult, AuthenticationScanner, SessionManagementScanner, PasswordResetScanner
from .clickjacking_scanner import ScanResult, ClickjackingScanner, DoubleClickjackingScanner, UIRedressScanner
from .csrf_scanner import ScanResult, CSRFScanner, CSRFTokenAnalyzer
from .oauth_saml_scanner import ScanResult, OAuthVulnScanner, SAMLVulnScanner
from .oauth_scanner import ScanResult, OAuthSecurityScanner

__all__ = ['ScanResult', 'AuthenticationScanner', 'SessionManagementScanner', 'PasswordResetScanner', 'ScanResult', 'ClickjackingScanner', 'DoubleClickjackingScanner', 'UIRedressScanner', 'ScanResult', 'CSRFScanner', 'CSRFTokenAnalyzer', 'ScanResult', 'OAuthVulnScanner', 'SAMLVulnScanner', 'ScanResult', 'OAuthSecurityScanner']
