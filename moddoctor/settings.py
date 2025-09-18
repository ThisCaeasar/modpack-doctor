"""Settings management for persistent configuration."""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional


def get_settings_dir() -> Path:
    """Get the user settings directory."""
    if os.name == 'nt':
        # Windows
        settings_base = Path(os.environ.get('USERPROFILE', '~'))
    else:
        # Unix-like
        settings_base = Path(os.environ.get('HOME', '~'))
    
    settings_dir = settings_base / '.modpack-doctor'
    settings_dir.mkdir(parents=True, exist_ok=True)
    return settings_dir


def get_config_file() -> Path:
    """Get the path to the configuration file."""
    return get_settings_dir() / 'config.json'


def load_settings() -> Dict[str, Any]:
    """
    Load settings from the configuration file.
    
    Returns:
        Dictionary with settings, with defaults for missing values
    """
    defaults = {
        "last_mods_dir": "",
        "online_hints_enabled": True,
        "window_geometry": "1200x800",
        "window_maximized": False,
        "recent_mods_dirs": [],
        "analysis_settings": {
            "auto_analyze": True,
            "show_info_issues": True,
            "show_warning_issues": True,
            "show_error_issues": True
        },
        "export_settings": {
            "last_export_dir": "",
            "include_system_info": True,
            "include_recommendations": True
        }
    }
    
    config_file = get_config_file()
    
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            
            # Merge with defaults to ensure all keys exist
            merged = defaults.copy()
            _deep_update(merged, settings)
            return merged
            
        except Exception:
            # Return defaults if loading fails
            pass
    
    return defaults


def save_settings(settings: Dict[str, Any]) -> bool:
    """
    Save settings to the configuration file.
    
    Args:
        settings: Dictionary with settings to save
        
    Returns:
        True if successful, False otherwise
    """
    config_file = get_config_file()
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def update_setting(key: str, value: Any) -> bool:
    """
    Update a single setting value.
    
    Args:
        key: Setting key (supports dot notation for nested keys)
        value: New value for the setting
        
    Returns:
        True if successful, False otherwise
    """
    settings = load_settings()
    
    # Handle nested keys with dot notation
    keys = key.split('.')
    current = settings
    
    for k in keys[:-1]:
        if k not in current:
            current[k] = {}
        current = current[k]
    
    current[keys[-1]] = value
    
    return save_settings(settings)


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a single setting value.
    
    Args:
        key: Setting key (supports dot notation for nested keys)
        default: Default value if key doesn't exist
        
    Returns:
        Setting value or default
    """
    settings = load_settings()
    
    # Handle nested keys with dot notation
    keys = key.split('.')
    current = settings
    
    try:
        for k in keys:
            current = current[k]
        return current
    except (KeyError, TypeError):
        return default


def add_recent_mods_dir(mods_dir: str) -> bool:
    """
    Add a mods directory to the recent list.
    
    Args:
        mods_dir: Path to mods directory
        
    Returns:
        True if successful, False otherwise
    """
    settings = load_settings()
    recent_dirs = settings.get("recent_mods_dirs", [])
    
    # Remove if already in list
    if mods_dir in recent_dirs:
        recent_dirs.remove(mods_dir)
    
    # Add to front
    recent_dirs.insert(0, mods_dir)
    
    # Keep only last 10
    recent_dirs = recent_dirs[:10]
    
    settings["recent_mods_dirs"] = recent_dirs
    return save_settings(settings)


def get_recent_mods_dirs() -> list:
    """
    Get list of recently used mods directories.
    
    Returns:
        List of recent directory paths
    """
    return get_setting("recent_mods_dirs", [])


def _deep_update(base_dict: dict, update_dict: dict) -> None:
    """
    Deep update base_dict with values from update_dict.
    
    Args:
        base_dict: Dictionary to update (modified in place)
        update_dict: Dictionary with new values
    """
    for key, value in update_dict.items():
        if (key in base_dict and 
            isinstance(base_dict[key], dict) and 
            isinstance(value, dict)):
            _deep_update(base_dict[key], value)
        else:
            base_dict[key] = value