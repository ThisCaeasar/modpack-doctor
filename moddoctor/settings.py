"""Settings management for persistent configuration."""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional


class Settings:
    """Manages persistent application settings."""
    
    def __init__(self, config_file: Optional[Path] = None):
        """
        Initialize settings manager.
        
        Args:
            config_file: Optional custom config file path.
                        Defaults to %USERPROFILE%/.modpack-doctor/config.json
        """
        if config_file:
            self.config_file = config_file
        else:
            # Use user profile directory
            if os.name == "nt":  # Windows
                base_dir = Path(os.environ.get("USERPROFILE", Path.home()))
            else:  # Unix-like
                base_dir = Path.home()
            
            config_dir = base_dir / ".modpack-doctor"
            config_dir.mkdir(parents=True, exist_ok=True)
            self.config_file = config_dir / "config.json"
        
        self._settings = self._load_settings()
    
    def _load_settings(self) -> Dict[str, Any]:
        """Load settings from config file."""
        default_settings = {
            "last_mods_dir": "",
            "online_enabled": True,
            "window_geometry": "1000x800",
            "window_position": "",
            "analysis_auto_refresh": True,
            "cache_enabled": True,
            "jvm_recommendations_enabled": True,
            "export_format": "markdown",
            "theme": "default",
            "recent_directories": [],
            "max_recent_directories": 10
        }
        
        if not self.config_file.exists():
            return default_settings.copy()
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            
            # Merge with defaults to handle new settings
            merged = default_settings.copy()
            merged.update(settings)
            return merged
            
        except Exception:
            # Return defaults if config is corrupted
            return default_settings.copy()
    
    def _save_settings(self):
        """Save settings to config file."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._settings, f, ensure_ascii=False, indent=2)
        except Exception:
            # Silently fail on save errors
            pass
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a setting value.
        
        Args:
            key: Setting key
            default: Default value if key doesn't exist
            
        Returns:
            Setting value or default
        """
        return self._settings.get(key, default)
    
    def set(self, key: str, value: Any):
        """
        Set a setting value.
        
        Args:
            key: Setting key
            value: Setting value
        """
        self._settings[key] = value
        self._save_settings()
    
    def get_last_mods_dir(self) -> str:
        """Get the last used mods directory."""
        return self.get("last_mods_dir", "")
    
    def set_last_mods_dir(self, path: str):
        """Set the last used mods directory."""
        self.set("last_mods_dir", path)
        self._add_recent_directory(path)
    
    def is_online_enabled(self) -> bool:
        """Check if online features are enabled."""
        return self.get("online_enabled", True)
    
    def set_online_enabled(self, enabled: bool):
        """Enable or disable online features."""
        self.set("online_enabled", enabled)
    
    def get_window_geometry(self) -> str:
        """Get saved window geometry."""
        return self.get("window_geometry", "1000x800")
    
    def set_window_geometry(self, geometry: str):
        """Save window geometry."""
        self.set("window_geometry", geometry)
    
    def get_window_position(self) -> str:
        """Get saved window position."""
        return self.get("window_position", "")
    
    def set_window_position(self, position: str):
        """Save window position."""
        self.set("window_position", position)
    
    def is_cache_enabled(self) -> bool:
        """Check if caching is enabled."""
        return self.get("cache_enabled", True)
    
    def set_cache_enabled(self, enabled: bool):
        """Enable or disable caching."""
        self.set("cache_enabled", enabled)
    
    def get_recent_directories(self) -> list:
        """Get list of recent directories."""
        return self.get("recent_directories", [])
    
    def _add_recent_directory(self, path: str):
        """Add a directory to recent list."""
        recent = self.get_recent_directories()
        
        # Remove if already exists
        if path in recent:
            recent.remove(path)
        
        # Add to front
        recent.insert(0, path)
        
        # Limit size
        max_recent = self.get("max_recent_directories", 10)
        recent = recent[:max_recent]
        
        self.set("recent_directories", recent)
    
    def clear_recent_directories(self):
        """Clear the recent directories list."""
        self.set("recent_directories", [])
    
    def get_export_format(self) -> str:
        """Get preferred export format."""
        return self.get("export_format", "markdown")
    
    def set_export_format(self, format_type: str):
        """Set preferred export format."""
        self.set("export_format", format_type)
    
    def reset_to_defaults(self):
        """Reset all settings to defaults."""
        self._settings = {
            "last_mods_dir": "",
            "online_enabled": True,
            "window_geometry": "1000x800",
            "window_position": "",
            "analysis_auto_refresh": True,
            "cache_enabled": True,
            "jvm_recommendations_enabled": True,
            "export_format": "markdown",
            "theme": "default",
            "recent_directories": [],
            "max_recent_directories": 10
        }
        self._save_settings()