"""
GitLab Scanner - Repository Access and Code Fetching

Handles:
- GitLab OAuth token validation
- Repository cloning (shallow clone)
- GitLab API integration for repo metadata
- Branch/commit information
- Supports both gitlab.com and self-hosted GitLab instances
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
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class GitLabRepository:
    """GitLab repository metadata"""
    id: int
    name: str
    path_with_namespace: str
    default_branch: str
    http_url_to_repo: str
    visibility: str  # private, internal, public
    last_activity_at: Optional[datetime] = None


@dataclass
class CloneResult:
    """Result of repository clone operation"""
    success: bool
    local_path: Optional[str] = None
    error: Optional[str] = None
    commit_hash: Optional[str] = None
    branch: Optional[str] = None


class GitLabScanner:
    """
    GitLab repository scanner for SAST analysis.
    
    Supports:
    - gitlab.com (SaaS)
    - Self-hosted GitLab instances
    - OAuth tokens and Personal Access Tokens
    """
    
    MAX_REPO_SIZE_MB = 500
    
    def __init__(self, config: dict, context):
        """
        Initialize GitLab scanner.
        
        Args:
            config: Scan configuration
                - repository_url: GitLab repo URL
                - access_token: OAuth token or PAT
                - branch: Branch to scan (optional)
                - gitlab_url: Custom GitLab URL (for self-hosted)
            context: SASTScanContext
        """
        self.config = config
        self.context = context
        self.access_token = config.get('access_token', '')
        self.repo_url = config.get('repository_url', '')
        self.branch = config.get('branch', 'main')
        
        # Detect GitLab base URL
        self.gitlab_base = self._detect_gitlab_base()
        self.api_base = f"{self.gitlab_base}/api/v4"
        
        # Parse repository info from URL
        self.repo_info = self._parse_repo_url(self.repo_url)
        
        # Clone directory
        self.clone_dir = config.get('clone_dir', 'data/temp/sast')
    
    def _detect_gitlab_base(self) -> str:
        """Detect GitLab base URL from repository URL or config"""
        if custom_url := self.config.get('gitlab_url'):
            return custom_url.rstrip('/')
        
        parsed = urlparse(self.repo_url)
        if parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        
        return "https://gitlab.com"
    
    def _parse_repo_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse project path from GitLab URL"""
        # Remove .git suffix and extract path
        parsed = urlparse(url)
        path = parsed.path.strip('/').replace('.git', '')
        
        if path:
            return {
                'path': path,  # e.g., "owner/repo" or "group/subgroup/repo"
                'encoded_path': path.replace('/', '%2F'),
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
                'id': 'SAST-GL-001',
                'category': 'A07:2021',
                'severity': 'high',
                'title': 'Missing GitLab Access Token',
                'description': 'No GitLab access token provided. Cannot access repository.',
                'file': '',
                'line': 0,
                'rule_id': 'missing-token',
            })
            return findings
        
        if not self.repo_info:
            findings.append({
                'id': 'SAST-GL-002',
                'category': 'A05:2021',
                'severity': 'high',
                'title': 'Invalid Repository URL',
                'description': f'Cannot parse GitLab repository from URL: {self.repo_url}',
                'file': '',
                'line': 0,
                'rule_id': 'invalid-repo-url',
            })
            return findings
        
        # Clone repository
        clone_result = await self.clone_repository()
        
        if not clone_result.success:
            findings.append({
                'id': 'SAST-GL-003',
                'category': 'A05:2021',
                'severity': 'high',
                'title': 'Repository Clone Failed',
                'description': f'Failed to clone repository: {clone_result.error}',
                'file': '',
                'line': 0,
                'rule_id': 'clone-failed',
            })
        else:
            self.context.repo_path = clone_result.local_path
            self.context.commit_hash = clone_result.commit_hash
            self.context.branch = clone_result.branch
            
            logger.info(f"Repository cloned to: {clone_result.local_path}")
        
        return findings
    
    async def clone_repository(self) -> CloneResult:
        """Clone the repository to local storage."""
        if not self.repo_info:
            return CloneResult(success=False, error="Invalid repository URL")
        
        # Build clone URL with token
        parsed = urlparse(self.gitlab_base)
        clone_url = f"{parsed.scheme}://oauth2:{self.access_token}@{parsed.netloc}/{self.repo_info['path']}.git"
        
        # Create unique clone directory
        scan_id = self.config.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        repo_name = self.repo_info['path'].split('/')[-1]
        local_path = Path(self.clone_dir) / scan_id / repo_name
        
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        if local_path.exists():
            shutil.rmtree(local_path)
        
        try:
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
                error_msg = error_msg.replace(self.access_token, '***TOKEN***')
                return CloneResult(success=False, error=error_msg)
            
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
    
    async def list_projects(self) -> List[Dict[str, Any]]:
        """List accessible projects for the authenticated user"""
        try:
            import httpx
            
            projects = []
            page = 1
            
            async with httpx.AsyncClient() as client:
                headers = {'PRIVATE-TOKEN': self.access_token}
                
                while True:
                    url = f"{self.api_base}/projects?membership=true&per_page=100&page={page}"
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    if not data:
                        break
                    
                    for project in data:
                        projects.append({
                            'id': project['id'],
                            'name': project['name'],
                            'path_with_namespace': project['path_with_namespace'],
                            'visibility': project['visibility'],
                            'web_url': project['web_url'],
                            'default_branch': project.get('default_branch', 'main'),
                            'last_activity_at': project.get('last_activity_at'),
                        })
                    
                    page += 1
                    if len(data) < 100:
                        break
            
            return projects
            
        except Exception as e:
            logger.error(f"Failed to list GitLab projects: {e}")
            return []
    
    async def validate_token(self) -> Dict[str, Any]:
        """Validate GitLab access token and get user info"""
        try:
            import httpx
            
            async with httpx.AsyncClient() as client:
                headers = {'PRIVATE-TOKEN': self.access_token}
                response = await client.get(f"{self.api_base}/user", headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'valid': True,
                        'username': data['username'],
                        'user_id': data['id'],
                        'name': data.get('name'),
                        'email': data.get('email'),
                    }
                else:
                    return {
                        'valid': False,
                        'error': f"Token validation failed: {response.status_code}",
                    }
                    
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def cleanup(self):
        """Remove cloned repository from disk"""
        if hasattr(self.context, 'repo_path') and self.context.repo_path:
            try:
                shutil.rmtree(self.context.repo_path)
                logger.info(f"Cleaned up repository: {self.context.repo_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup repository: {e}")


__all__ = ['GitLabScanner', 'GitLabRepository', 'CloneResult']
