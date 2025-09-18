"""Modrinth API integration for mod enrichment."""

import json
from typing import Optional, Dict, Any

try:
    import requests
except ImportError:
    requests = None


class ModrinthClient:
    """Simple client for Modrinth API."""
    
    def __init__(self, timeout: float = 10.0):
        self.base_url = "https://api.modrinth.com/v2"
        self.timeout = timeout
        self.session = None
        
        if requests:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'ModpackDoctor/1.0.0 (contact@example.com)'
            })
    
    def search_project(self, query: str, limit: int = 1) -> Optional[Dict[str, Any]]:
        """
        Search for a project by name or ID.
        
        Args:
            query: Search query (mod name or ID)
            limit: Maximum number of results
            
        Returns:
            First matching project or None
        """
        if not self.session:
            return None
        
        try:
            # First try direct project lookup if query looks like an ID
            if self._is_valid_project_id(query):
                project = self.get_project(query)
                if project:
                    return project
            
            # Fall back to search
            params = {
                'query': query,
                'limit': limit,
                'facets': '["project_type:mod"]'
            }
            
            response = self.session.get(
                f"{self.base_url}/search",
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', [])
                return hits[0] if hits else None
                
        except Exception:
            pass
        
        return None
    
    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """
        Get project details by ID.
        
        Args:
            project_id: Modrinth project ID
            
        Returns:
            Project data or None
        """
        if not self.session:
            return None
        
        try:
            response = self.session.get(
                f"{self.base_url}/project/{project_id}",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
                
        except Exception:
            pass
        
        return None
    
    def _is_valid_project_id(self, query: str) -> bool:
        """Check if query looks like a valid Modrinth project ID."""
        # Modrinth IDs are typically lowercase alphanumeric with dashes
        return (len(query) > 3 and 
                len(query) < 64 and 
                query.replace('-', '').replace('_', '').isalnum() and
                query.islower())


def enrich_mod_info(mod_info, online_enabled: bool = True) -> bool:
    """
    Enrich mod information with data from Modrinth.
    
    Args:
        mod_info: ModInfo object to enrich
        online_enabled: Whether online enrichment is enabled
        
    Returns:
        True if enrichment was successful, False otherwise
    """
    if not online_enabled or not requests:
        return False
    
    client = ModrinthClient()
    
    # Try different search strategies
    search_queries = []
    
    if mod_info.modid:
        search_queries.append(mod_info.modid)
    
    if mod_info.name and mod_info.name != mod_info.modid:
        search_queries.append(mod_info.name)
    
    # Clean up common mod name prefixes/suffixes
    if mod_info.name:
        clean_name = mod_info.name.lower()
        clean_name = clean_name.replace('[forge]', '').replace('[fabric]', '')
        clean_name = clean_name.replace('(forge)', '').replace('(fabric)', '')
        clean_name = clean_name.strip()
        if clean_name and clean_name != mod_info.name.lower():
            search_queries.append(clean_name)
    
    # Try each search query
    for query in search_queries:
        if not query:
            continue
            
        try:
            project = client.search_project(query.strip())
            if project:
                _apply_modrinth_data(mod_info, project)
                return True
        except Exception:
            continue
    
    return False


def _apply_modrinth_data(mod_info, project_data: Dict[str, Any]) -> None:
    """Apply Modrinth project data to ModInfo object."""
    try:
        # Update description if not available or very short
        if project_data.get('description'):
            if not mod_info.description or len(mod_info.description) < 50:
                mod_info.description = project_data['description']
        
        # Update homepage/project URL
        if not mod_info.homepage and project_data.get('project_url'):
            mod_info.homepage = project_data['project_url']
        
        if not mod_info.project_url and project_data.get('project_url'):
            mod_info.project_url = project_data['project_url']
        
        # Store Modrinth data for reference
        mod_info.modrinth = {
            'id': project_data.get('project_id'),
            'slug': project_data.get('slug'),
            'title': project_data.get('title'),
            'description': project_data.get('description'),
            'categories': project_data.get('categories', []),
            'project_url': project_data.get('project_url'),
            'downloads': project_data.get('downloads', 0),
            'followers': project_data.get('followers', 0),
            'icon_url': project_data.get('icon_url')
        }
        
    except Exception:
        pass