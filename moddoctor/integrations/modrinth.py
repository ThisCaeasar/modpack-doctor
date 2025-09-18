"""Modrinth API integration for mod enrichment."""

from typing import Optional, Dict, Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from ..core.model import ModInfo, Dependency


class ModrinthClient:
    """Lightweight Modrinth API client for mod enrichment."""
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the Modrinth client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.base_url = "https://api.modrinth.com/v2"
        self.timeout = timeout
    
    def enrich_mod(self, mod_info: ModInfo) -> bool:
        """
        Enrich mod information using Modrinth API.
        
        Args:
            mod_info: ModInfo object to enrich
            
        Returns:
            True if enrichment was successful, False otherwise
        """
        if not REQUESTS_AVAILABLE or not mod_info.sha256:
            return False
        
        try:
            # Try to find version by SHA256 hash
            version_data = self._get_version_by_hash(mod_info.sha256)
            if not version_data:
                # Fallback to SHA1 if available
                if mod_info.sha1:
                    version_data = self._get_version_by_hash(mod_info.sha1, algorithm="sha1")
            
            if version_data:
                mod_info.modrinth["version"] = version_data
                project_id = version_data.get("project_id")
                
                if project_id:
                    project_data = self._get_project(project_id)
                    if project_data:
                        mod_info.modrinth["project"] = project_data
                        self._apply_project_data(mod_info, project_data, version_data)
                        return True
        
        except Exception:
            # Silently fail on network errors
            pass
        
        return False
    
    def search_mod(self, query: str, limit: int = 20) -> Optional[Dict[str, Any]]:
        """
        Search for mods by name.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            Search results or None if failed
        """
        if not REQUESTS_AVAILABLE:
            return None
        
        try:
            params = {
                "query": query,
                "limit": limit,
                "facets": '["categories:mod"]'
            }
            
            response = requests.get(
                f"{self.base_url}/search",
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
        
        except Exception:
            pass
        
        return None
    
    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """
        Get project information by ID.
        
        Args:
            project_id: Modrinth project ID
            
        Returns:
            Project data or None if failed
        """
        return self._get_project(project_id)
    
    def _get_version_by_hash(self, hash_value: str, algorithm: str = "sha256") -> Optional[Dict[str, Any]]:
        """Get version data by file hash."""
        try:
            url = f"{self.base_url}/version_file/{hash_value}"
            params = {"algorithm": algorithm}
            
            response = requests.get(url, params=params, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        
        except Exception:
            pass
        
        return None
    
    def _get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get project data by ID."""
        try:
            response = requests.get(
                f"{self.base_url}/project/{project_id}",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
        
        except Exception:
            pass
        
        return None
    
    def _apply_project_data(self, mod_info: ModInfo, project_data: Dict[str, Any], version_data: Dict[str, Any]):
        """Apply enriched data to ModInfo."""
        # Update basic info if missing or empty
        if not mod_info.name or len(mod_info.name) < 3:
            mod_info.name = project_data.get("title") or mod_info.name
        
        if not mod_info.description or len(mod_info.description) < 10:
            mod_info.description = project_data.get("description") or mod_info.description
        
        # Set homepage/project URLs
        mod_info.homepage = mod_info.homepage or project_data.get("issues_url")
        mod_info.project_url = f"https://modrinth.com/mod/{project_data.get('slug', project_data.get('id'))}"
        
        # Add dependencies from Modrinth
        dependencies = version_data.get("dependencies") or []
        for dep in dependencies:
            dep_type = dep.get("dependency_type")
            if dep_type and dep.get("project_id"):
                kind_map = {
                    "required": "required",
                    "optional": "optional", 
                    "incompatible": "conflicts",
                    "embedded": "optional"
                }
                kind = kind_map.get(dep_type, "required")
                
                # Don't add duplicate dependencies
                existing_deps = {d.modid for d in mod_info.depends + mod_info.conflicts}
                if dep["project_id"] not in existing_deps:
                    dependency = Dependency(
                        modid=dep["project_id"],
                        version=dep.get("version_id"),
                        kind=kind,
                        source="modrinth"
                    )
                    
                    if kind == "conflicts":
                        mod_info.conflicts.append(dependency)
                    else:
                        mod_info.depends.append(dependency)


def enrich_mods_with_modrinth(mods: list[ModInfo], enabled: bool = True) -> int:
    """
    Enrich a list of mods with Modrinth data.
    
    Args:
        mods: List of ModInfo objects to enrich
        enabled: Whether online enrichment is enabled
        
    Returns:
        Number of mods successfully enriched
    """
    if not enabled or not REQUESTS_AVAILABLE:
        return 0
    
    client = ModrinthClient()
    enriched_count = 0
    
    for mod in mods:
        if client.enrich_mod(mod):
            enriched_count += 1
    
    return enriched_count