"""File operations for managing mods (disable/enable)."""

import os
import platform
import subprocess
from pathlib import Path
from typing import List, Optional

from .core.model import ModInfo, Severity


def disable_mod(mod_info: ModInfo) -> bool:
    """
    Disable a mod by moving it to mods_disabled folder.
    
    Args:
        mod_info: ModInfo object for the mod to disable
        
    Returns:
        True if successful, False otherwise
    """
    try:
        mod_path = Path(mod_info.path)
        if not mod_path.exists():
            return False
        
        # Create mods_disabled directory
        mods_dir = mod_path.parent
        disabled_dir = mods_dir / "mods_disabled"
        disabled_dir.mkdir(exist_ok=True)
        
        # Generate new filename with .disabled extension
        disabled_filename = mod_path.stem + ".disabled" + mod_path.suffix
        disabled_path = disabled_dir / disabled_filename
        
        # Handle name conflicts
        counter = 1
        while disabled_path.exists():
            disabled_filename = f"{mod_path.stem}.disabled.{counter}{mod_path.suffix}"
            disabled_path = disabled_dir / disabled_filename
            counter += 1
        
        # Move the file
        mod_path.rename(disabled_path)
        mod_info.path = str(disabled_path)
        
        return True
        
    except Exception:
        return False


def enable_mod(mod_info: ModInfo) -> bool:
    """
    Enable a previously disabled mod by moving it back to mods folder.
    
    Args:
        mod_info: ModInfo object for the mod to enable
        
    Returns:
        True if successful, False otherwise
    """
    try:
        disabled_path = Path(mod_info.path)
        if not disabled_path.exists() or "mods_disabled" not in str(disabled_path):
            return False
        
        # Determine original mods directory
        mods_disabled_dir = disabled_path.parent
        mods_dir = mods_disabled_dir.parent / "mods"
        
        # Generate original filename (remove .disabled)
        original_name = disabled_path.name
        if ".disabled" in original_name:
            original_name = original_name.replace(".disabled", "")
            # Remove numbered suffix if present
            if original_name.count('.') > 1:
                parts = original_name.split('.')
                if parts[-2].isdigit():  # Has numbered suffix
                    original_name = '.'.join(parts[:-2] + [parts[-1]])
        
        enabled_path = mods_dir / original_name
        
        # Handle name conflicts
        counter = 1
        while enabled_path.exists():
            stem = enabled_path.stem
            suffix = enabled_path.suffix
            enabled_path = mods_dir / f"{stem}.{counter}{suffix}"
            counter += 1
        
        # Move the file back
        disabled_path.rename(enabled_path)
        mod_info.path = str(enabled_path)
        
        return True
        
    except Exception:
        return False


def disable_duplicates(mods: List[ModInfo]) -> int:
    """
    Disable duplicate mods, keeping only the latest version.
    
    Args:
        mods: List of ModInfo objects
        
    Returns:
        Number of mods disabled
    """
    # Group mods by ID
    mod_groups = {}
    for mod in mods:
        key = (mod.modid or mod.name or mod.file_name).lower()
        if key not in mod_groups:
            mod_groups[key] = []
        mod_groups[key].append(mod)
    
    disabled_count = 0
    
    for group in mod_groups.values():
        if len(group) > 1:
            # Sort by version (keep latest), fallback to filename
            try:
                group.sort(key=lambda m: (m.version or "0", m.file_name), reverse=True)
            except Exception:
                # If version comparison fails, just use first mod
                pass
            
            # Disable all but the first (latest)
            for mod in group[1:]:
                if disable_mod(mod):
                    disabled_count += 1
    
    return disabled_count


def disable_conflicts(mods: List[ModInfo]) -> int:
    """
    Disable mods that have conflict issues.
    
    Args:
        mods: List of ModInfo objects
        
    Returns:
        Number of mods disabled
    """
    disabled_count = 0
    
    for mod in mods:
        # Check if mod has conflict issues
        has_conflicts = any(
            issue.severity == Severity.ERROR and 
            "conflict" in issue.message.lower()
            for issue in mod.issues
        )
        
        if has_conflicts:
            if disable_mod(mod):
                disabled_count += 1
    
    return disabled_count


def disable_all_errors(mods: List[ModInfo]) -> int:
    """
    Disable all mods that have error-level issues.
    
    Args:
        mods: List of ModInfo objects
        
    Returns:
        Number of mods disabled
    """
    disabled_count = 0
    
    for mod in mods:
        # Check if mod has any error-level issues
        has_errors = any(
            issue.severity == Severity.ERROR
            for issue in mod.issues
        )
        
        if has_errors:
            if disable_mod(mod):
                disabled_count += 1
    
    return disabled_count


def open_in_explorer(path: str) -> bool:
    """
    Open the specified path in the system file explorer.
    
    Args:
        path: File or directory path to open
        
    Returns:
        True if successful, False otherwise
    """
    try:
        path_obj = Path(path)
        
        # If it's a file, open the containing directory and select the file
        if path_obj.is_file():
            directory = path_obj.parent
            filename = path_obj.name
        else:
            directory = path_obj
            filename = None
        
        system = platform.system().lower()
        
        if system == "windows":
            if filename:
                # Select file in explorer
                subprocess.run(["explorer", "/select,", str(path_obj)], check=False)
            else:
                # Open directory
                subprocess.run(["explorer", str(directory)], check=False)
                
        elif system == "darwin":  # macOS
            if filename:
                # Select file in Finder
                subprocess.run(["open", "-R", str(path_obj)], check=False)
            else:
                # Open directory
                subprocess.run(["open", str(directory)], check=False)
                
        elif system == "linux":
            # Try common Linux file managers
            file_managers = ["nautilus", "dolphin", "thunar", "pcmanfm", "caja"]
            
            for fm in file_managers:
                try:
                    if filename:
                        subprocess.run([fm, str(directory)], check=False)
                    else:
                        subprocess.run([fm, str(directory)], check=False)
                    break
                except FileNotFoundError:
                    continue
            else:
                # Fallback: try xdg-open
                subprocess.run(["xdg-open", str(directory)], check=False)
        
        return True
        
    except Exception:
        return False


def get_mod_file_size(mod_info: ModInfo) -> Optional[int]:
    """
    Get the file size of a mod in bytes.
    
    Args:
        mod_info: ModInfo object
        
    Returns:
        File size in bytes, or None if unable to determine
    """
    try:
        return Path(mod_info.path).stat().st_size
    except Exception:
        return None


def is_mod_disabled(mod_info: ModInfo) -> bool:
    """
    Check if a mod is currently disabled.
    
    Args:
        mod_info: ModInfo object
        
    Returns:
        True if the mod is disabled, False otherwise
    """
    return "mods_disabled" in mod_info.path or ".disabled" in mod_info.file_name