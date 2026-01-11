"""
Azure DevOps Repository Scanner

Supports Azure DevOps (dev.azure.com) repository access.
Uses Personal Access Token (PAT) or OAuth for authentication.
"""

import os
import asyncio
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class AzureDevOpsScanner:
    """
    Scanner for Azure DevOps repositories.
    
    Authentication options:
    1. Personal Access Token (PAT) - most common
    2. OAuth (Azure AD) - for enterprise SSO
    """
    
    def __init__(self, access_token: str, clone_dir: str, organization: str = None):
        """
        Initialize Azure DevOps scanner.
        
        Args:
            access_token: PAT or OAuth token
            clone_dir: Directory to clone repository into
            organization: Azure DevOps organization name
        """
        self.access_token = access_token
        self.clone_dir = clone_dir
        self.organization = organization
        self.base_url = "https://dev.azure.com"
    
    async def clone_repository(self, repo_url: str, branch: str = "main") -> bool:
        """
        Clone an Azure DevOps repository.
        
        Args:
            repo_url: Full repository URL or org/project/_git/repo format
            branch: Branch to clone
            
        Returns:
            True if successful
        """
        try:
            # Parse and construct authenticated URL
            # Azure DevOps URL format: https://dev.azure.com/{org}/{project}/_git/{repo}
            # Or: https://{org}@dev.azure.com/{org}/{project}/_git/{repo}
            
            if 'dev.azure.com' in repo_url:
                # Insert PAT into URL
                auth_url = repo_url.replace(
                    'https://',
                    f'https://x-access-token:{self.access_token}@'
                )
            elif 'visualstudio.com' in repo_url:
                # Legacy URL format
                auth_url = repo_url.replace(
                    'https://',
                    f'https://x-access-token:{self.access_token}@'
                )
            else:
                auth_url = repo_url
            
            # Ensure clone directory exists
            os.makedirs(self.clone_dir, exist_ok=True)
            
            # Clone with shallow depth
            process = await asyncio.create_subprocess_exec(
                'git', 'clone', '--depth', '1', '--branch', branch, auth_url, self.clone_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Azure DevOps clone failed: {stderr.decode()}")
                return False
            
            logger.info(f"Successfully cloned Azure DevOps repo to {self.clone_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Azure DevOps clone error: {e}")
            return False
    
    async def validate_token(self) -> Dict[str, Any]:
        """Validate the PAT and get user info"""
        import httpx
        
        try:
            async with httpx.AsyncClient() as client:
                # Get user profile
                response = await client.get(
                    f"{self.base_url}/{self.organization}/_apis/connectionData",
                    headers={
                        'Authorization': f'Basic {self._encode_pat()}',
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'valid': True,
                        'user_id': data.get('authenticatedUser', {}).get('id'),
                        'display_name': data.get('authenticatedUser', {}).get('providerDisplayName'),
                    }
                else:
                    return {'valid': False, 'error': 'Invalid token'}
                    
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    async def list_repositories(self, project: str = None) -> List[Dict[str, Any]]:
        """List repositories in the organization"""
        import httpx
        
        repos = []
        try:
            async with httpx.AsyncClient() as client:
                # If project specified, get repos for that project
                if project:
                    url = f"{self.base_url}/{self.organization}/{project}/_apis/git/repositories?api-version=7.0"
                else:
                    # Get all projects first
                    projects_url = f"{self.base_url}/{self.organization}/_apis/projects?api-version=7.0"
                    proj_response = await client.get(
                        projects_url,
                        headers={'Authorization': f'Basic {self._encode_pat()}'}
                    )
                    
                    if proj_response.status_code != 200:
                        return repos
                    
                    projects = proj_response.json().get('value', [])
                    
                    for proj in projects:
                        proj_name = proj['name']
                        url = f"{self.base_url}/{self.organization}/{proj_name}/_apis/git/repositories?api-version=7.0"
                        
                        response = await client.get(
                            url,
                            headers={'Authorization': f'Basic {self._encode_pat()}'}
                        )
                        
                        if response.status_code == 200:
                            for repo in response.json().get('value', []):
                                repos.append({
                                    'id': repo['id'],
                                    'name': repo['name'],
                                    'full_name': f"{self.organization}/{proj_name}/{repo['name']}",
                                    'html_url': repo.get('webUrl'),
                                    'clone_url': repo.get('remoteUrl'),
                                    'private': True,  # Azure DevOps repos are private by default
                                    'default_branch': repo.get('defaultBranch', 'main').replace('refs/heads/', ''),
                                    'project': proj_name,
                                })
                    return repos
                
                response = await client.get(
                    url,
                    headers={'Authorization': f'Basic {self._encode_pat()}'}
                )
                
                if response.status_code == 200:
                    for repo in response.json().get('value', []):
                        repos.append({
                            'id': repo['id'],
                            'name': repo['name'],
                            'full_name': f"{self.organization}/{project}/{repo['name']}",
                            'html_url': repo.get('webUrl'),
                            'clone_url': repo.get('remoteUrl'),
                            'private': True,
                            'default_branch': repo.get('defaultBranch', 'main').replace('refs/heads/', ''),
                            'project': project,
                        })
                        
        except Exception as e:
            logger.error(f"Failed to list Azure DevOps repos: {e}")
        
        return repos
    
    def _encode_pat(self) -> str:
        """Encode PAT for Basic auth (Azure DevOps format)"""
        import base64
        # Azure DevOps uses empty username with PAT
        credentials = f":{self.access_token}"
        return base64.b64encode(credentials.encode()).decode()
