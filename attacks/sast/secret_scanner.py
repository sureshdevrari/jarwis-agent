"""
Secret Scanner - Detect Hardcoded Secrets in Source Code

Detects:
- API Keys (AWS, Azure, GCP, Stripe, Twilio, etc.)
- OAuth Tokens (GitHub, GitLab, Slack, etc.)
- Private Keys (RSA, SSH, PGP)
- Database Credentials
- JWT Secrets
- Generic Passwords and Secrets
- Environment Variable Leaks

Uses regex patterns inspired by:
- TruffleHog
- git-secrets
- detect-secrets
- Gitleaks
"""

import os
import re
import asyncio
import logging
from typing import List, Dict, Any, Pattern, Tuple
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SecretPattern:
    """Pattern definition for secret detection"""
    id: str
    name: str
    pattern: Pattern
    severity: str
    description: str
    cwe: str = "CWE-798"  # Use of Hard-coded Credentials


# Secret detection patterns
SECRET_PATTERNS: List[SecretPattern] = [
    # AWS
    SecretPattern(
        id='aws-access-key',
        name='AWS Access Key ID',
        pattern=re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
        severity='critical',
        description='AWS Access Key ID detected',
    ),
    SecretPattern(
        id='aws-secret-key',
        name='AWS Secret Access Key',
        pattern=re.compile(r'(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key[\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?'),
        severity='critical',
        description='AWS Secret Access Key detected',
    ),
    
    # Azure
    SecretPattern(
        id='azure-storage-key',
        name='Azure Storage Account Key',
        pattern=re.compile(r'(?i)(?:DefaultEndpointsProtocol|AccountKey)[\s:=]+["\']?([A-Za-z0-9+/=]{88})["\']?'),
        severity='critical',
        description='Azure Storage Account Key detected',
    ),
    SecretPattern(
        id='azure-client-secret',
        name='Azure Client Secret',
        pattern=re.compile(r'(?i)azure[_\-\.]?(?:client)?[_\-\.]?secret[\s:=]+["\']?([A-Za-z0-9~._\-]{34,})["\']?'),
        severity='critical',
        description='Azure Client Secret detected',
    ),
    
    # GCP
    SecretPattern(
        id='gcp-service-account',
        name='GCP Service Account Key',
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        severity='critical',
        description='GCP Service Account JSON key file detected',
    ),
    SecretPattern(
        id='gcp-api-key',
        name='GCP API Key',
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        severity='high',
        description='Google API Key detected',
    ),
    
    # GitHub
    SecretPattern(
        id='github-token',
        name='GitHub Token',
        pattern=re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
        severity='critical',
        description='GitHub Personal Access Token or OAuth Token detected',
    ),
    SecretPattern(
        id='github-app-token',
        name='GitHub App Token',
        pattern=re.compile(r'(?:ghu|ghs)_[A-Za-z0-9_]{36}'),
        severity='critical',
        description='GitHub App installation token detected',
    ),
    
    # GitLab
    SecretPattern(
        id='gitlab-token',
        name='GitLab Token',
        pattern=re.compile(r'glpat-[A-Za-z0-9\-]{20,}'),
        severity='critical',
        description='GitLab Personal Access Token detected',
    ),
    
    # Slack
    SecretPattern(
        id='slack-token',
        name='Slack Token',
        pattern=re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
        severity='high',
        description='Slack API Token detected',
    ),
    SecretPattern(
        id='slack-webhook',
        name='Slack Webhook',
        pattern=re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}'),
        severity='high',
        description='Slack Webhook URL detected',
    ),
    
    # Stripe
    SecretPattern(
        id='stripe-secret-key',
        name='Stripe Secret Key',
        pattern=re.compile(r'sk_(?:live|test)_[A-Za-z0-9]{24,}'),
        severity='critical',
        description='Stripe Secret API Key detected',
    ),
    SecretPattern(
        id='stripe-publishable-key',
        name='Stripe Publishable Key',
        pattern=re.compile(r'pk_(?:live|test)_[A-Za-z0-9]{24,}'),
        severity='medium',
        description='Stripe Publishable Key detected (less sensitive)',
    ),
    
    # Twilio
    SecretPattern(
        id='twilio-api-key',
        name='Twilio API Key',
        pattern=re.compile(r'SK[0-9a-fA-F]{32}'),
        severity='critical',
        description='Twilio API Key detected',
    ),
    
    # SendGrid
    SecretPattern(
        id='sendgrid-api-key',
        name='SendGrid API Key',
        pattern=re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
        severity='critical',
        description='SendGrid API Key detected',
    ),
    
    # Mailchimp
    SecretPattern(
        id='mailchimp-api-key',
        name='Mailchimp API Key',
        pattern=re.compile(r'[a-f0-9]{32}-us[0-9]{1,2}'),
        severity='high',
        description='Mailchimp API Key detected',
    ),
    
    # NPM
    SecretPattern(
        id='npm-token',
        name='NPM Token',
        pattern=re.compile(r'(?:npm_[A-Za-z0-9]{36}|//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-]+)'),
        severity='critical',
        description='NPM authentication token detected',
    ),
    
    # PyPI
    SecretPattern(
        id='pypi-token',
        name='PyPI Token',
        pattern=re.compile(r'pypi-[A-Za-z0-9_]{100,}'),
        severity='critical',
        description='PyPI API token detected',
    ),
    
    # Private Keys
    SecretPattern(
        id='private-key-rsa',
        name='RSA Private Key',
        pattern=re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
        severity='critical',
        description='RSA Private Key detected',
    ),
    SecretPattern(
        id='private-key-ssh',
        name='SSH Private Key',
        pattern=re.compile(r'-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----'),
        severity='critical',
        description='SSH Private Key detected',
    ),
    SecretPattern(
        id='private-key-pgp',
        name='PGP Private Key',
        pattern=re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        severity='critical',
        description='PGP Private Key detected',
    ),
    
    # JWT
    SecretPattern(
        id='jwt-secret',
        name='JWT Secret',
        pattern=re.compile(r'(?i)jwt[_\-\.]?secret[\s:=]+["\']?([A-Za-z0-9/+=_\-]{16,})["\']?'),
        severity='high',
        description='JWT Secret key detected',
    ),
    
    # Generic Secrets
    SecretPattern(
        id='generic-password',
        name='Hardcoded Password',
        pattern=re.compile(r'(?i)(?:password|passwd|pwd)[\s:=]+["\']([^"\']{8,})["\']'),
        severity='high',
        description='Hardcoded password detected',
    ),
    SecretPattern(
        id='generic-api-key',
        name='Generic API Key',
        pattern=re.compile(r'(?i)(?:api[_\-\.]?key|apikey|secret[_\-\.]?key)[\s:=]+["\']([A-Za-z0-9_\-]{16,})["\']'),
        severity='medium',
        description='Generic API key pattern detected',
    ),
    SecretPattern(
        id='generic-secret',
        name='Generic Secret',
        pattern=re.compile(r'(?i)(?:secret|token|credential)[\s:=]+["\']([A-Za-z0-9_\-/+=]{16,})["\']'),
        severity='medium',
        description='Generic secret pattern detected',
    ),
    
    # Database Connection Strings
    SecretPattern(
        id='database-url',
        name='Database Connection String',
        pattern=re.compile(r'(?:postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+'),
        severity='critical',
        description='Database connection string with credentials detected',
    ),
    
    # Bearer Tokens
    SecretPattern(
        id='bearer-token',
        name='Bearer Token',
        pattern=re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-\.]+'),
        severity='medium',
        description='Bearer token detected',
    ),
    
    # Basic Auth
    SecretPattern(
        id='basic-auth',
        name='Basic Auth Credentials',
        pattern=re.compile(r'(?i)basic\s+[A-Za-z0-9+/=]{20,}'),
        severity='high',
        description='Basic authentication credentials detected',
    ),
]

# Files/patterns to skip
SKIP_PATTERNS = [
    r'\.min\.js$',
    r'\.min\.css$',
    r'node_modules/',
    r'vendor/',
    r'\.git/',
    r'__pycache__/',
    r'\.pyc$',
    r'\.lock$',
    r'package-lock\.json$',
    r'yarn\.lock$',
    r'\.whl$',
    r'\.tar\.gz$',
    r'\.zip$',
]


class SecretScanner:
    """
    Scans source code for hardcoded secrets and credentials.
    
    Uses pattern-based detection with low false-positive tuning.
    Maps all findings to CWE-798 (Use of Hard-coded Credentials).
    """
    
    def __init__(self, config: dict, context):
        """
        Initialize secret scanner.
        
        Args:
            config: Scan configuration
                - exclude_paths: Additional paths to exclude
            context: SASTScanContext with repo_path
        """
        self.config = config
        self.context = context
        self.exclude_paths = config.get('exclude_paths', [])
        
        # Compile skip patterns
        self.skip_regex = [re.compile(p) for p in SKIP_PATTERNS]
        for path in self.exclude_paths:
            self.skip_regex.append(re.compile(re.escape(path)))
    
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Scan repository for secrets.
        
        Returns:
            List of secret findings
        """
        findings = []
        
        repo_path = getattr(self.context, 'repo_path', None)
        if not repo_path or not os.path.exists(repo_path):
            logger.warning("No repository path available for secret scanning")
            return findings
        
        # Walk through all files
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden and excluded directories
            dirs[:] = [d for d in dirs if not self._should_skip(os.path.join(root, d))]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if self._should_skip(file_path):
                    continue
                
                file_findings = await self._scan_file(file_path, repo_path)
                findings.extend(file_findings)
        
        logger.info(f"Secret scanner found {len(findings)} potential secrets")
        return findings
    
    def _should_skip(self, path: str) -> bool:
        """Check if path should be skipped"""
        for pattern in self.skip_regex:
            if pattern.search(path):
                return True
        return False
    
    async def _scan_file(self, file_path: str, repo_path: str) -> List[Dict[str, Any]]:
        """Scan a single file for secrets"""
        findings = []
        relative_path = os.path.relpath(file_path, repo_path)
        
        try:
            # Try to read file (skip binary files)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception:
                return findings
            
            # Skip large files (>1MB)
            if len(content) > 1_000_000:
                return findings
            
            # Check each line
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                # Skip empty lines and comments
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                    continue
                
                # Check against all patterns
                for pattern in SECRET_PATTERNS:
                    match = pattern.pattern.search(line)
                    if match:
                        # Extract matched secret (mask it)
                        secret_preview = self._mask_secret(match.group(0))
                        
                        findings.append({
                            'id': f'SECRET-{pattern.id.upper()}-{line_num}',
                            'category': 'A02:2021',  # Cryptographic Failures
                            'severity': pattern.severity,
                            'title': pattern.name,
                            'description': f'{pattern.description}. {pattern.cwe}',
                            'file': relative_path,
                            'line': line_num,
                            'column': match.start() + 1,
                            'rule_id': pattern.id,
                            'evidence': secret_preview,
                            'cwe': pattern.cwe,
                            'remediation': self._get_remediation(pattern.id),
                        })
            
        except Exception as e:
            logger.debug(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def _mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask secret value for safe display"""
        if len(secret) <= visible_chars * 2:
            return '*' * len(secret)
        return f"{secret[:visible_chars]}{'*' * (len(secret) - visible_chars * 2)}{secret[-visible_chars:]}"
    
    def _get_remediation(self, rule_id: str) -> str:
        """Get remediation guidance for a rule"""
        remediations = {
            'aws-access-key': 'Use AWS IAM roles or environment variables. Never commit AWS credentials.',
            'aws-secret-key': 'Rotate the exposed key immediately. Use AWS Secrets Manager.',
            'github-token': 'Revoke the token in GitHub settings and generate a new one.',
            'private-key-rsa': 'Remove the private key and regenerate. Never commit private keys.',
            'private-key-ssh': 'Regenerate SSH keys. Add private keys to .gitignore.',
            'database-url': 'Use environment variables for database credentials.',
            'generic-password': 'Use a secrets manager or environment variables for passwords.',
            'jwt-secret': 'Store JWT secrets in environment variables or secrets manager.',
        }
        return remediations.get(rule_id, 'Remove the hardcoded secret and use environment variables or a secrets manager.')


__all__ = ['SecretScanner', 'SecretPattern', 'SECRET_PATTERNS']
