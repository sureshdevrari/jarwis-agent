"""
GitHub Scanner - Repository Access and Code Fetching

Handles:
- GitHub OAuth token validation
- Repository cloning (shallow clone)
- GitHub API integration for repo metadata
- Branch/commit information
- File listing and content retrieval
"""

import os
import re
import shutil
import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class GitHubRepository:
    """GitHub repository metadata"""
    owner: str
    name: str
    full_name: str
    default_branch: str
    clone_url: str
    is_private: bool
    language: Optional[str] = None
    languages: Dict[str, int] = field(default_factory=dict)
    size_kb: int = 0
    last_push: Optional[datetime] = None


@dataclass
class CloneResult:
    """Result of repository clone operation"""
    success: bool
    local_path: Optional[str] = None
    error: Optional[str] = None
    commit_hash: Optional[str] = None
    branch: Optional[str] = None


class GitHubScanner:
    """
    GitHub repository scanner for SAST analysis.
    
    Handles repository access, cloning, and file retrieval
    using GitHub OAuth tokens or Personal Access Tokens.
    """
    
    GITHUB_API_BASE = "https://api.github.com"
    MAX_REPO_SIZE_MB = 500  # Maximum repository size to clone
    
    def __init__(self, config: dict, context):
        """
        Initialize GitHub scanner.
        
        Args:
            config: Scan configuration
                - repository_url: GitHub repo URL
                - access_token: OAuth token or PAT
                - branch: Branch to scan (optional)
            context: SASTScanContext
        """
        self.config = config
        self.context = context
        self.access_token = config.get('access_token', '')
        self.repo_url = config.get('repository_url', '')
        self.branch = config.get('branch', 'main')
        
        # Parse repository info from URL
        self.repo_info = self._parse_repo_url(self.repo_url)
        
        # Clone directory
        self.clone_dir = config.get('clone_dir', 'data/temp/sast')
    
    def _parse_repo_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse owner and repo name from GitHub URL"""
        patterns = [
            r'github\.com[/:]([^/]+)/([^/\.]+)',  # HTTPS or SSH
            r'github\.com/([^/]+)/([^/]+)\.git',  # With .git
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return {
                    'owner': match.group(1),
                    'repo': match.group(2).replace('.git', ''),
                    'full_name': f"{match.group(1)}/{match.group(2).replace('.git', '')}"
                }
        return None
    
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Clone and prepare repository for scanning.
        
        Returns:
            List of findings (repository access issues)
        """
        findings = []
        
        # Validate token
        if not self.access_token:
            findings.append({
                'id': 'SAST-GH-001',
                'category': 'A07:2021',  # Auth Failures
                'severity': 'high',
                'title': 'Missing GitHub Access Token',
                'description': 'No GitHub access token provided. Cannot access repository.',
                'file': '',
                'line': 0,
                'rule_id': 'missing-token',
            })
            return findings
        
        if not self.repo_info:
            findings.append({
                'id': 'SAST-GH-002',
                'category': 'A05:2021',  # Misconfiguration
                'severity': 'high',
                'title': 'Invalid Repository URL',
                'description': f'Cannot parse GitHub repository from URL: {self.repo_url}',
                'file': '',
                'line': 0,
                'rule_id': 'invalid-repo-url',
            })
            return findings
        
        # Clone repository
        clone_result = await self.clone_repository()
        
        if not clone_result.success:
            findings.append({
                'id': 'SAST-GH-003',
                'category': 'A05:2021',
                'severity': 'high',
                'title': 'Repository Clone Failed',
                'description': f'Failed to clone repository: {clone_result.error}',
                'file': '',
                'line': 0,
                'rule_id': 'clone-failed',
            })
        else:
            # Store cloned path in context for other scanners
            self.context.repo_path = clone_result.local_path
            self.context.commit_hash = clone_result.commit_hash
            self.context.branch = clone_result.branch
            
            logger.info(f"Repository cloned to: {clone_result.local_path}")
        
        return findings
    
    async def clone_repository(self) -> CloneResult:
        """
        Clone the repository to local storage.
        
        Uses shallow clone (depth=1) for efficiency.
        """
        if not self.repo_info:
            return CloneResult(success=False, error="Invalid repository URL")
        
        # Build clone URL with token
        clone_url = f"https://x-access-token:{self.access_token}@github.com/{self.repo_info['full_name']}.git"
        
        # Create unique clone directory
        scan_id = self.config.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        local_path = Path(self.clone_dir) / scan_id / self.repo_info['repo']
        
        # Ensure parent directory exists
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove if exists
        if local_path.exists():
            shutil.rmtree(local_path)
        
        try:
            # Shallow clone for speed
            cmd = [
                'git', 'clone',
                '--depth', '1',
                '--branch', self.branch,
                clone_url,
                str(local_path)
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                # Mask token in error message
                error_msg = error_msg.replace(self.access_token, '***TOKEN***')
                return CloneResult(success=False, error=error_msg)
            
            # Get commit hash
            commit_hash = await self._get_commit_hash(local_path)
            
            return CloneResult(
                success=True,
                local_path=str(local_path),
                commit_hash=commit_hash,
                branch=self.branch
            )
            
        except Exception as e:
            return CloneResult(success=False, error=str(e))
    
    async def _get_commit_hash(self, repo_path: Path) -> Optional[str]:
        """Get current HEAD commit hash"""
        try:
            process = await asyncio.create_subprocess_exec(
                'git', 'rev-parse', 'HEAD',
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            return stdout.decode().strip() if stdout else None
        except Exception:
            return None
    
    async def get_repository_info(self) -> Optional[GitHubRepository]:
        """Fetch repository metadata from GitHub API"""
        if not self.repo_info:
            return None
        
        try:
            import httpx
            
            async with httpx.AsyncClient() as client:
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                }
                
                # Get repo info
                url = f"{self.GITHUB_API_BASE}/repos/{self.repo_info['full_name']}"
                response = await client.get(url, headers=headers)
                
                if response.status_code != 200:
                    logger.error(f"GitHub API error: {response.status_code}")
                    return None
                
                data = response.json()
                
                # Get languages
                lang_url = f"{url}/languages"
                lang_response = await client.get(lang_url, headers=headers)
                languages = lang_response.json() if lang_response.status_code == 200 else {}
                
                return GitHubRepository(
                    owner=data['owner']['login'],
                    name=data['name'],
                    full_name=data['full_name'],
                    default_branch=data['default_branch'],
                    clone_url=data['clone_url'],
                    is_private=data['private'],
                    language=data.get('language'),
                    languages=languages,
                    size_kb=data.get('size', 0),
                    last_push=datetime.fromisoformat(data['pushed_at'].replace('Z', '+00:00')) if data.get('pushed_at') else None
                )
                
        except Exception as e:
            logger.error(f"Failed to get repository info: {e}")
            return None
    
    async def list_repositories(self) -> List[Dict[str, Any]]:
        """List accessible repositories for the authenticated user"""
        try:
            import httpx
            
            repos = []
            page = 1
            
            async with httpx.AsyncClient() as client:
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                }
                
                while True:
                    url = f"{self.GITHUB_API_BASE}/user/repos?per_page=100&page={page}"
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    if not data:
                        break
                    
                    for repo in data:
                        repos.append({
                            'id': repo['id'],
                            'name': repo['name'],
                            'full_name': repo['full_name'],
                            'private': repo['private'],
                            'html_url': repo['html_url'],
                            'default_branch': repo['default_branch'],
                            'language': repo.get('language'),
                            'updated_at': repo['updated_at'],
                        })
                    
                    page += 1
                    if len(data) < 100:
                        break
            
            return repos
            
        except Exception as e:
            logger.error(f"Failed to list repositories: {e}")
            return []
    
    async def validate_token(self) -> Dict[str, Any]:
        """Validate GitHub access token and get user info"""
        try:
            import httpx
            
            async with httpx.AsyncClient() as client:
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                }
                
                response = await client.get(f"{self.GITHUB_API_BASE}/user", headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'valid': True,
                        'username': data['login'],
                        'user_id': data['id'],
                        'name': data.get('name'),
                        'email': data.get('email'),
                        'scopes': response.headers.get('X-OAuth-Scopes', '').split(', '),
                    }
                else:
                    return {
                        'valid': False,
                        'error': f"Token validation failed: {response.status_code}",
                    }
                    
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
            }
    
    def cleanup(self):
        """Remove cloned repository from disk"""
        if hasattr(self.context, 'repo_path') and self.context.repo_path:
            try:
                shutil.rmtree(self.context.repo_path)
                logger.info(f"Cleaned up repository: {self.context.repo_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup repository: {e}")


__all__ = ['GitHubScanner', 'GitHubRepository', 'CloneResult']
