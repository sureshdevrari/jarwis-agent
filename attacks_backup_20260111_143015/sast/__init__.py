"""
Jarwis AGI - Source Code Security Scanner (SAST)
Static Application Security Testing

Comprehensive source code analysis for security vulnerabilities:
- Secret Detection (API keys, passwords, tokens)
- Dependency Scanning (SCA - vulnerable packages)
- Code Vulnerability Analysis (injection, XSS, etc.)
- IaC Security (if code includes infrastructure files)
- OWASP/CWE mapping for all findings

Supports:
- GitHub (OAuth App & Personal Access Token)
- GitLab (OAuth & PAT)
- Bitbucket (OAuth & App Password)
- Manual repository URL with token

Languages Supported:
- Python (Bandit-style rules)
- JavaScript/TypeScript (ESLint security rules)
- Java (FindSecBugs patterns)
- Go (gosec patterns)
- Ruby (Brakeman patterns)
- PHP (security patterns)
- C# (security patterns)

Inspired by: Snyk, Checkmarx, SonarQube, Semgrep
"""

from typing import List, Any, Optional, Dict
import logging

from .github_scanner import GitHubScanner
from .gitlab_scanner import GitLabScanner
from .secret_scanner import SecretScanner
from .dependency_scanner import DependencyScanner
from .code_analyzer import CodeAnalyzer
from .language_analyzers import (
    PythonAnalyzer,
    JavaScriptAnalyzer,
    JavaAnalyzer,
    GoAnalyzer,
)

logger = logging.getLogger(__name__)


class SASTAttacks:
    """
    Aggregates ALL SAST (Static Application Security Testing) scanners.
    
    Routes to appropriate source code scanner based on configuration.
    Supports multiple SCM providers and programming languages.
    
    Usage:
        sast = SASTAttacks(config, context)
        findings = await sast.run()
        
        # Or scan specific components
        secret_findings = await sast.scan_secrets()
        dependency_findings = await sast.scan_dependencies()
    """
    
    PROVIDERS = ['github', 'gitlab', 'bitbucket', 'manual']
    SCAN_TYPES = ['full', 'secrets', 'dependencies', 'code', 'iac']
    
    def __init__(self, config: dict, context):
        """
        Initialize SAST attack module.
        
        Args:
            config: Scan configuration with repository details
                - repository_url: GitHub/GitLab repo URL
                - branch: Branch to scan (default: main)
                - access_token: OAuth token or PAT
                - languages: List of languages to analyze (auto-detect if empty)
                - scan_secrets: Enable secret detection (default: True)
                - scan_dependencies: Enable SCA (default: True)
                - scan_code: Enable code vulnerability analysis (default: True)
                - exclude_paths: Paths to exclude from scanning
            context: SASTScanContext with cloned repository path
        """
        self.config = config
        self.context = context
        self.provider = self._detect_provider()
        
        # Initialize scanners
        self.scanners = self._init_scanners()
    
    def _detect_provider(self) -> str:
        """Detect SCM provider from repository URL"""
        repo_url = self.config.get('repository_url', '').lower()
        
        if 'github.com' in repo_url:
            return 'github'
        elif 'gitlab.com' in repo_url or 'gitlab' in repo_url:
            return 'gitlab'
        elif 'bitbucket.org' in repo_url:
            return 'bitbucket'
        else:
            return 'manual'
    
    def _init_scanners(self) -> List[Any]:
        """Initialize SAST scanners based on configuration"""
        scanners = []
        
        # SCM Provider scanner (for cloning/API access)
        if self.provider == 'github':
            scanners.append(GitHubScanner(self.config, self.context))
        elif self.provider == 'gitlab':
            scanners.append(GitLabScanner(self.config, self.context))
        
        # Secret detection (if enabled)
        if self.config.get('scan_secrets', True):
            scanners.append(SecretScanner(self.config, self.context))
        
        # Dependency scanning / SCA (if enabled)
        if self.config.get('scan_dependencies', True):
            scanners.append(DependencyScanner(self.config, self.context))
        
        # Code vulnerability analysis (if enabled)
        if self.config.get('scan_code', True):
            scanners.append(CodeAnalyzer(self.config, self.context))
        
        return scanners
    
    async def run(self) -> List[Dict[str, Any]]:
        """
        Run all enabled SAST scanners.
        
        Returns:
            List of vulnerability findings with OWASP/CWE mapping
        """
        all_findings = []
        
        for scanner in self.scanners:
            try:
                logger.info(f"Running SAST scanner: {scanner.__class__.__name__}")
                findings = await scanner.scan()
                all_findings.extend(findings)
                logger.info(f"  Found {len(findings)} issues")
            except Exception as e:
                logger.error(f"Scanner {scanner.__class__.__name__} failed: {e}")
        
        # Deduplicate and sort by severity
        all_findings = self._deduplicate_findings(all_findings)
        all_findings = self._sort_by_severity(all_findings)
        
        return all_findings
    
    async def scan_secrets(self) -> List[Dict[str, Any]]:
        """Run only secret detection scanner"""
        scanner = SecretScanner(self.config, self.context)
        return await scanner.scan()
    
    async def scan_dependencies(self) -> List[Dict[str, Any]]:
        """Run only dependency vulnerability scanner (SCA)"""
        scanner = DependencyScanner(self.config, self.context)
        return await scanner.scan()
    
    async def scan_code(self) -> List[Dict[str, Any]]:
        """Run only code vulnerability analysis"""
        scanner = CodeAnalyzer(self.config, self.context)
        return await scanner.scan()
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on file, line, and rule"""
        seen = set()
        unique = []
        
        for finding in findings:
            key = (
                finding.get('file', ''),
                finding.get('line', 0),
                finding.get('rule_id', ''),
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    def _sort_by_severity(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by severity (critical > high > medium > low > info)"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        return sorted(
            findings,
            key=lambda f: severity_order.get(f.get('severity', 'info').lower(), 5)
        )
    
    @staticmethod
    def get_supported_languages() -> List[str]:
        """Return list of supported programming languages"""
        return [
            'python', 'javascript', 'typescript', 'java', 'go',
            'ruby', 'php', 'csharp', 'kotlin', 'swift', 'rust'
        ]
    
    @staticmethod
    def get_scan_capabilities() -> Dict[str, str]:
        """Return description of scan capabilities"""
        return {
            'secrets': 'Detect hardcoded secrets, API keys, passwords, tokens',
            'dependencies': 'Find vulnerable packages (SCA) with CVE mapping',
            'code': 'Analyze code for injection, XSS, and other vulnerabilities',
            'iac': 'Scan Infrastructure as Code (Terraform, CloudFormation, K8s)',
        }


# Export main class and scanners
__all__ = [
    'SASTAttacks',
    'GitHubScanner',
    'GitLabScanner',
    'SecretScanner',
    'DependencyScanner',
    'CodeAnalyzer',
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'JavaAnalyzer',
    'GoAnalyzer',
]
