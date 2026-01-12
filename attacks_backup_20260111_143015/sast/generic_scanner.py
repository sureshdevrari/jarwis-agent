"""
Generic Git Scanner for SourceForge, Codeberg, and other Git hosts

Supports any Git repository that uses standard HTTPS or SSH authentication.
"""

import os
import asyncio
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class GenericGitScanner:
    """
    Generic scanner for any Git repository.
    
    Works with:
    - SourceForge (sourceforge.net)
    - Codeberg (codeberg.org) 
    - sr.ht (sourcehut)
    - Any standard Git server
    """
    
    def __init__(
        self,
        clone_dir: str,
        username: str = None,
        password: str = None,
        ssh_key_path: str = None,
    ):
        """
        Initialize generic Git scanner.
        
        Args:
            clone_dir: Directory to clone repository into
            username: HTTPS username (optional)
            password: HTTPS password or token (optional)
            ssh_key_path: Path to SSH private key (optional)
        """
        self.clone_dir = clone_dir
        self.username = username
        self.password = password
        self.ssh_key_path = ssh_key_path
    
    async def clone_repository(self, repo_url: str, branch: str = "main") -> bool:
        """
        Clone any Git repository.
        
        Args:
            repo_url: Repository URL (HTTPS or SSH)
            branch: Branch to clone
            
        Returns:
            True if successful
        """
        try:
            os.makedirs(self.clone_dir, exist_ok=True)
            
            env = os.environ.copy()
            
            # Handle HTTPS authentication
            if repo_url.startswith('https://') and self.username and self.password:
                # Insert credentials into URL
                auth_url = repo_url.replace(
                    'https://',
                    f'https://{self.username}:{self.password}@'
                )
            elif repo_url.startswith('git@') and self.ssh_key_path:
                # Use SSH with specific key
                auth_url = repo_url
                env['GIT_SSH_COMMAND'] = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no'
            else:
                auth_url = repo_url
            
            # Try to clone with branch, fallback to default
            process = await asyncio.create_subprocess_exec(
                'git', 'clone', '--depth', '1', '--branch', branch, auth_url, self.clone_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                # Try without branch specification (use default)
                process2 = await asyncio.create_subprocess_exec(
                    'git', 'clone', '--depth', '1', auth_url, self.clone_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                stdout2, stderr2 = await process2.communicate()
                
                if process2.returncode != 0:
                    logger.error(f"Git clone failed: {stderr2.decode()}")
                    return False
            
            logger.info(f"Successfully cloned repo to {self.clone_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Git clone error: {e}")
            return False


class SourceForgeScanner(GenericGitScanner):
    """
    Scanner specifically for SourceForge repositories.
    
    SourceForge uses standard Git with some specific URL patterns.
    """
    
    def __init__(self, clone_dir: str, username: str = None, password: str = None):
        super().__init__(clone_dir, username, password)
        self.base_url = "https://sourceforge.net"
    
    def get_clone_url(self, project: str, repo: str = "code") -> str:
        """
        Get SourceForge clone URL.
        
        Args:
            project: SourceForge project name
            repo: Repository name within project (default: "code")
            
        Returns:
            Clone URL
        """
        return f"https://git.code.sf.net/p/{project}/{repo}"
    
    async def clone_project(self, project: str, repo: str = "code", branch: str = "master") -> bool:
        """Clone a SourceForge project repository"""
        clone_url = self.get_clone_url(project, repo)
        return await self.clone_repository(clone_url, branch)


class CodebergScanner:
    """
    Scanner for Codeberg repositories.
    
    Codeberg uses Forgejo (Gitea fork) so has the same API.
    """
    
    def __init__(self, access_token: str, clone_dir: str):
        """
        Initialize Codeberg scanner.
        
        Args:
            access_token: Codeberg access token
            clone_dir: Directory to clone repository into
        """
        self.access_token = access_token
        self.clone_dir = clone_dir
        self.base_url = "https://codeberg.org"
        self.api_url = f"{self.base_url}/api/v1"
    
    async def clone_repository(self, repo_url: str, branch: str = "main") -> bool:
        """Clone a Codeberg repository"""
        try:
            os.makedirs(self.clone_dir, exist_ok=True)
            
            if not repo_url.startswith('http'):
                repo_url = f"{self.base_url}/{repo_url}.git"
            
            auth_url = repo_url.replace(
                'https://',
                f'https://x-access-token:{self.access_token}@'
            )
            
            process = await asyncio.create_subprocess_exec(
                'git', 'clone', '--depth', '1', '--branch', branch, auth_url, self.clone_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Codeberg clone failed: {stderr.decode()}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Codeberg clone error: {e}")
            return False
    
    async def validate_token(self) -> Dict[str, Any]:
        """Validate token and get user info"""
        import httpx
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/user",
                    headers={'Authorization': f'token {self.access_token}'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'valid': True,
                        'username': data.get('login') or data.get('username'),
                        'email': data.get('email'),
                    }
                else:
                    return {'valid': False, 'error': 'Invalid token'}
                    
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    async def list_repositories(self) -> List[Dict[str, Any]]:
        """List user's Codeberg repositories"""
        import httpx
        
        repos = []
        try:
            async with httpx.AsyncClient() as client:
                page = 1
                while True:
                    response = await client.get(
                        f"{self.api_url}/user/repos",
                        params={'page': page, 'limit': 50},
                        headers={'Authorization': f'token {self.access_token}'}
                    )
                    
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
                            'html_url': repo['html_url'],
                            'clone_url': repo['clone_url'],
                            'private': repo['private'],
                            'default_branch': repo.get('default_branch', 'main'),
                        })
                    
                    page += 1
                    if len(data) < 50:
                        break
                        
        except Exception as e:
            logger.error(f"Failed to list Codeberg repos: {e}")
        
        return repos
