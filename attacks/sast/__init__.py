"""
Jarwis AGI - Source Code Security Scanner (SAST)
Static Application Security Testing

NEW STRUCTURE (Recommended):
    from attacks.sast.providers import GitHubScanner, GitLabScanner
    from attacks.sast.analyzers import SecretScanner, DependencyScanner
    
LEGACY IMPORT (Deprecated but still works):
    from attacks.sast import GitHubScanner, SecretScanner

Function-based organization:
- providers/   - SCM provider integrations (GitHub, GitLab, Bitbucket, etc.)
- analyzers/   - Analysis engines (secrets, dependencies, code analysis)
- language_analyzers/ - Language-specific analyzers (Python, JS, Java, etc.)

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
- Azure DevOps
- AWS CodeCommit
- Gitea
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

logger = logging.getLogger(__name__)

# =============================================================================
# BACKWARD-COMPATIBLE IMPORTS FROM NEW FUNCTION LOCATIONS
# =============================================================================

# Providers (SCM Integrations)
from .providers.github_scanner import GitHubScanner
from .providers.gitlab_scanner import GitLabScanner
from .providers.bitbucket_scanner import BitbucketScanner
from .providers.azure_devops_scanner import AzureDevOpsScanner
from .providers.aws_codecommit_scanner import AWSCodeCommitScanner
from .providers.gitea_scanner import GiteaScanner
from .providers.generic_scanner import GenericGitScanner

# Alias for backward compat
GenericScanner = GenericGitScanner

# Analyzers (Security Analysis Engines)
from .analyzers.secret_scanner import SecretScanner
from .analyzers.dependency_scanner import DependencyScanner
from .analyzers.code_analyzer import CodeAnalyzer

# Language Analyzers
from .language_analyzers import (
    PythonAnalyzer,
    JavaScriptAnalyzer,
    JavaAnalyzer,
    GoAnalyzer,
)


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
    
    PROVIDERS = ['github', 'gitlab', 'bitbucket', 'azure_devops', 'codecommit', 'gitea', 'manual']
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
            context: SASTScanContext with repository details
        """
        self.config = config
        self.context = context
        self.scanners = []
        
        sast_config = config.get('sast', {})
        
        # Secret Scanner (always enabled by default)
        if sast_config.get('scan_secrets', True):
            self.scanners.append(SecretScanner(config, context))
        
        # Dependency Scanner (SCA)
        if sast_config.get('scan_dependencies', True):
            self.scanners.append(DependencyScanner(config, context))
        
        # Code Analyzer
        if sast_config.get('scan_code', True):
            self.scanners.append(CodeAnalyzer(config, context))
        
        # Add provider-specific scanner
        provider = self._detect_provider(config.get('repository_url', ''))
        self.provider_scanner = self._get_provider_scanner(provider, config, context)
    
    def _detect_provider(self, repo_url: str) -> str:
        """Detect SCM provider from repository URL."""
        if 'github.com' in repo_url:
            return 'github'
        elif 'gitlab.com' in repo_url or 'gitlab' in repo_url:
            return 'gitlab'
        elif 'bitbucket.org' in repo_url:
            return 'bitbucket'
        elif 'dev.azure.com' in repo_url or 'visualstudio.com' in repo_url:
            return 'azure_devops'
        elif 'codecommit' in repo_url:
            return 'codecommit'
        elif 'gitea' in repo_url:
            return 'gitea'
        else:
            return 'generic'
    
    def _get_provider_scanner(self, provider: str, config: dict, context):
        """Get the appropriate provider scanner."""
        scanners = {
            'github': GitHubScanner,
            'gitlab': GitLabScanner,
            'bitbucket': BitbucketScanner,
            'azure_devops': AzureDevOpsScanner,
            'codecommit': AWSCodeCommitScanner,
            'gitea': GiteaScanner,
            'generic': GenericScanner,
        }
        scanner_class = scanners.get(provider, GenericScanner)
        return scanner_class(config, context)
    
    async def run(self) -> List[Any]:
        """Run all SAST scanners."""
        findings = []
        
        # First, clone/access the repository via provider
        if self.provider_scanner:
            try:
                await self.provider_scanner.prepare()
            except Exception as e:
                logger.error(f"Provider scanner preparation failed: {e}")
        
        # Then run all analysis scanners
        for scanner in self.scanners:
            try:
                result = await scanner.run()
                if result:
                    findings.extend(result if isinstance(result, list) else [result])
            except Exception as e:
                logger.error(f"Scanner {scanner.__class__.__name__} failed: {e}")
        
        return findings
    
    async def scan_secrets(self) -> List[Any]:
        """Run only secret detection."""
        scanner = SecretScanner(self.config, self.context)
        return await scanner.run()
    
    async def scan_dependencies(self) -> List[Any]:
        """Run only dependency scanning (SCA)."""
        scanner = DependencyScanner(self.config, self.context)
        return await scanner.run()
    
    async def scan_code(self) -> List[Any]:
        """Run only code vulnerability analysis."""
        scanner = CodeAnalyzer(self.config, self.context)
        return await scanner.run()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main Classes
    'SASTAttacks',
    
    # Providers
    'GitHubScanner',
    'GitLabScanner',
    'BitbucketScanner',
    'AzureDevOpsScanner',
    'AWSCodeCommitScanner',
    'GiteaScanner',
    'GenericScanner',
    
    # Analyzers
    'SecretScanner',
    'DependencyScanner',
    'CodeAnalyzer',
    
    # Language Analyzers
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'JavaAnalyzer',
    'GoAnalyzer',
]
