"""Cache management for mod metadata and icons."""

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from ..core.model import ModInfo


class CacheManager:
    """Manages local caching of mod metadata and icons."""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Optional custom cache directory. 
                      Defaults to %USERPROFILE%/.modpack-doctor/cache
        """
        if cache_dir:
            self.cache_dir = cache_dir
        else:
            # Use user profile directory
            if os.name == "nt":  # Windows
                base_dir = Path(os.environ.get("USERPROFILE", Path.home()))
            else:  # Unix-like
                base_dir = Path.home()
            
            self.cache_dir = base_dir / ".modpack-doctor" / "cache"
        
        # Create cache directories
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir = self.cache_dir / "metadata"
        self.icons_dir = self.cache_dir / "icons"
        self.metadata_dir.mkdir(exist_ok=True)
        self.icons_dir.mkdir(exist_ok=True)
    
    def get_mod_metadata(self, sha256: str) -> Optional[ModInfo]:
        """
        Retrieve cached mod metadata by SHA256 hash.
        
        Args:
            sha256: SHA256 hash of the mod file
            
        Returns:
            ModInfo object if cached, None otherwise
        """
        metadata_file = self.metadata_dir / f"{sha256}.json"
        
        if not metadata_file.exists():
            return None
        
        try:
            with open(metadata_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Reconstruct ModInfo from cached data
            # Handle backwards compatibility
            mod_info = ModInfo(
                file_name=data.get("file_name", ""),
                path=data.get("path", ""),
                loader=data.get("loader"),
                modid=data.get("modid"),
                name=data.get("name"),
                version=data.get("version"),
                description=data.get("description"),
                authors=data.get("authors", []),
                environment=data.get("environment"),
                depends=data.get("depends", []),
                recommends=data.get("recommends", []),
                conflicts=data.get("conflicts", []),
                provides=data.get("provides", []),
                minecraft_versions=data.get("minecraft_versions", []),
                sha256=data.get("sha256"),
                icon_path=data.get("icon_path"),
                homepage=data.get("homepage"),
                project_url=data.get("project_url"),
                issues=data.get("issues", [])
            )
            
            # Legacy compatibility
            mod_info.sha1 = data.get("sha1")
            mod_info.modrinth = data.get("modrinth", {})
            mod_info.curseforge = data.get("curseforge", {})
            
            return mod_info
            
        except Exception as e:
            # Remove corrupted cache file
            try:
                metadata_file.unlink()
            except Exception:
                pass
            return None
    
    def store_mod_metadata(self, sha256: str, mod_info: ModInfo):
        """
        Store mod metadata in cache.
        
        Args:
            sha256: SHA256 hash of the mod file
            mod_info: ModInfo object to cache
        """
        metadata_file = self.metadata_dir / f"{sha256}.json"
        
        try:
            # Convert to dict for JSON serialization
            data = asdict(mod_info)
            
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            # Silently fail on cache write errors
            pass
    
    def get_icon_path(self, sha256: str) -> Optional[Path]:
        """
        Get path to cached icon file.
        
        Args:
            sha256: SHA256 hash of the mod file
            
        Returns:
            Path to icon file if it exists, None otherwise
        """
        for ext in ['.png', '.jpg', '.jpeg', '.gif']:
            icon_file = self.icons_dir / f"{sha256}{ext}"
            if icon_file.exists():
                return icon_file
        return None
    
    def store_icon(self, sha256: str, icon_data: bytes, extension: str = '.png'):
        """
        Store icon data in cache.
        
        Args:
            sha256: SHA256 hash of the mod file
            icon_data: Raw icon data
            extension: File extension for the icon
        """
        icon_file = self.icons_dir / f"{sha256}{extension}"
        
        try:
            with open(icon_file, 'wb') as f:
                f.write(icon_data)
        except Exception:
            # Silently fail on cache write errors
            pass
    
    def clear_cache(self):
        """Clear all cached data."""
        try:
            import shutil
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.metadata_dir.mkdir(exist_ok=True)
            self.icons_dir.mkdir(exist_ok=True)
        except Exception:
            pass
    
    def get_cache_size(self) -> int:
        """
        Get total cache size in bytes.
        
        Returns:
            Cache size in bytes
        """
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(self.cache_dir):
                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    total_size += filepath.stat().st_size
        except Exception:
            pass
        return total_size