"""
Gitea Repository Scanner

Supports Gitea and Forgejo self-hosted Git servers.
API is similar to GitHub, making integration straightforward.
"""

import os
import asyncio
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class GiteaScanner:
    """
    Scanner for Gitea repositories.
    
    Gitea is a self-hosted Git service with a GitHub-like API.
    Also supports Forgejo (Gitea fork).
    """
    
    def __init__(
        self,
        access_token: str,
        clone_dir: str,
        base_url: str = "https://gitea.com",
    ):
        """
        Initialize Gitea scanner.
        
        Args:
            access_token: Personal Access Token
            clone_dir: Directory to clone repository into
            base_url: Gitea instance URL (e.g., https://git.yourcompany.com)
        """
        self.access_token = access_token
        self.clone_dir = clone_dir
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/api/v1"
    
    async def clone_repository(self, repo_url: str, branch: str = "main") -> bool:
        """
        Clone a Gitea repository.
        
        Args:
            repo_url: Repository URL or owner/repo format
            branch: Branch to clone
            
        Returns:
            True if successful
        """
        try:
            os.makedirs(self.clone_dir, exist_ok=True)
            
            # Construct full URL if just owner/repo given
            if not repo_url.startswith('http'):
                repo_url = f"{self.base_url}/{repo_url}.git"
            
            # Add authentication
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
                logger.error(f"Gitea clone failed: {stderr.decode()}")
                return False
            
            logger.info(f"Successfully cloned Gitea repo to {self.clone_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Gitea clone error: {e}")
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
                        'full_name': data.get('full_name'),
                        'id': data.get('id'),
                    }
                else:
                    return {'valid': False, 'error': 'Invalid token'}
                    
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    async def list_repositories(self, include_org: bool = True) -> List[Dict[str, Any]]:
        """List all accessible repositories"""
        import httpx
        
        repos = []
        try:
            async with httpx.AsyncClient() as client:
                headers = {'Authorization': f'token {self.access_token}'}
                
                # Get user repos
                page = 1
                while True:
                    response = await client.get(
                        f"{self.api_url}/user/repos",
                        params={'page': page, 'limit': 50},
                        headers=headers
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
                            'owner': repo['owner']['login'],
                            'description': repo.get('description', ''),
                        })
                    
                    page += 1
                    if len(data) < 50:
                        break
                
                # Get org repos if requested
                if include_org:
                    orgs_response = await client.get(
                        f"{self.api_url}/user/orgs",
                        headers=headers
                    )
                    
                    if orgs_response.status_code == 200:
                        for org in orgs_response.json():
                            org_name = org.get('username') or org.get('name')
                            
                            page = 1
                            while True:
                                org_repos = await client.get(
                                    f"{self.api_url}/orgs/{org_name}/repos",
                                    params={'page': page, 'limit': 50},
                                    headers=headers
                                )
                                
                                if org_repos.status_code != 200:
                                    break
                                
                                org_data = org_repos.json()
                                if not org_data:
                                    break
                                
                                for repo in org_data:
                                    repos.append({
                                        'id': repo['id'],
                                        'name': repo['name'],
                                        'full_name': repo['full_name'],
                                        'html_url': repo['html_url'],
                                        'clone_url': repo['clone_url'],
                                        'private': repo['private'],
                                        'default_branch': repo.get('default_branch', 'main'),
                                        'owner': org_name,
                                        'organization': org_name,
                                    })
                                
                                page += 1
                                if len(org_data) < 50:
                                    break
                        
        except Exception as e:
            logger.error(f"Failed to list Gitea repos: {e}")
        
        return repos
