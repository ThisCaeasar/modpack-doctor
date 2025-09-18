"""Mod management and fix operations."""

import os
import shutil
import platform
import subprocess
from pathlib import Path
from typing import List, Set

from .model import ModInfo, Issue, Severity


def disable_mod_file(mod_file_path: Path) -> bool:
    """
    Disable a mod by renaming it to .disabled.jar
    
    Args:
        mod_file_path: Path to the mod file to disable
        
    Returns:
        True if successful, False otherwise
    """
    if not mod_file_path.exists():
        return False
    
    try:
        # Create mods_disabled directory if it doesn't exist
        disabled_dir = mod_file_path.parent / "mods_disabled"
        disabled_dir.mkdir(exist_ok=True)
        
        # Generate new filename
        new_name = mod_file_path.stem + ".disabled.jar"
        new_path = disabled_dir / new_name
        
        # Handle name conflicts
        counter = 1
        while new_path.exists():
            new_name = f"{mod_file_path.stem}.disabled.{counter}.jar"
            new_path = disabled_dir / new_name
            counter += 1
        
        # Move and rename the file
        shutil.move(str(mod_file_path), str(new_path))
        return True
        
    except Exception:
        return False


def enable_mod_file(disabled_mod_path: Path, mods_dir: Path) -> bool:
    """
    Enable a disabled mod by moving it back to mods directory and removing .disabled
    
    Args:
        disabled_mod_path: Path to the disabled mod file
        mods_dir: Path to the mods directory
        
    Returns:
        True if successful, False otherwise
    """
    if not disabled_mod_path.exists():
        return False
    
    try:
        # Generate original filename
        original_name = disabled_mod_path.name.replace(".disabled", "")
        if original_name.endswith(".jar.jar"):
            original_name = original_name[:-4]  # Remove extra .jar
        
        new_path = mods_dir / original_name
        
        # Handle name conflicts
        counter = 1
        while new_path.exists():
            stem = Path(original_name).stem
            new_name = f"{stem}.{counter}.jar"
            new_path = mods_dir / new_name
            counter += 1
        
        # Move the file back
        shutil.move(str(disabled_mod_path), str(new_path))
        return True
        
    except Exception:
        return False


def open_in_explorer(file_path: Path) -> bool:
    """
    Open file location in system file explorer.
    
    Args:
        file_path: Path to file or directory to open
        
    Returns:
        True if successful, False otherwise
    """
    try:
        system = platform.system()
        
        if system == "Windows":
            # Use explorer with /select to highlight the file
            subprocess.run(["explorer", "/select,", str(file_path)], check=True)
        elif system == "Darwin":  # macOS
            subprocess.run(["open", "-R", str(file_path)], check=True)
        else:  # Linux and others
            # Try different file managers
            file_managers = ["nautilus", "dolphin", "thunar", "nemo", "pcmanfm"]
            parent_dir = file_path.parent if file_path.is_file() else file_path
            
            for fm in file_managers:
                try:
                    subprocess.run([fm, str(parent_dir)], check=True)
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            else:
                # Fallback to xdg-open
                subprocess.run(["xdg-open", str(parent_dir)], check=True)
        
        return True
        
    except Exception:
        return False


def disable_duplicates(mods: List[ModInfo], issues: List[Issue]) -> int:
    """
    Disable duplicate mods, keeping the newest version.
    
    Args:
        mods: List of all mods
        issues: List of issues to check for duplicates
        
    Returns:
        Number of mods disabled
    """
    disabled_count = 0
    
    # Find duplicate issues
    duplicate_issues = [issue for issue in issues if issue.category == "duplicates"]
    
    for issue in duplicate_issues:
        # Parse mod files from issue
        mod_files = [f.strip() for f in issue.mod_file.split(",")]
        
        # Find corresponding ModInfo objects
        duplicate_mods = []
        for mod in mods:
            if mod.file_name in mod_files:
                duplicate_mods.append(mod)
        
        if len(duplicate_mods) <= 1:
            continue
        
        # Sort by version (keep newest)
        duplicate_mods.sort(key=lambda m: _parse_version(m.version or "0.0.0"), reverse=True)
        
        # Disable all but the first (newest)
        for mod in duplicate_mods[1:]:
            if disable_mod_file(Path(mod.path)):
                disabled_count += 1
    
    return disabled_count


def disable_conflicts(mods: List[ModInfo], issues: List[Issue]) -> int:
    """
    Disable conflicting mods.
    
    Args:
        mods: List of all mods
        issues: List of issues to check for conflicts
        
    Returns:
        Number of mods disabled
    """
    disabled_count = 0
    
    # Find conflict issues
    conflict_issues = [issue for issue in issues 
                      if issue.category in ["known_conflicts", "loader_mismatch"]]
    
    for issue in conflict_issues:
        # Parse mod files from issue
        mod_files = [f.strip() for f in issue.mod_file.split(",")]
        
        # For conflicts, disable all but one (arbitrarily keep the first alphabetically)
        if len(mod_files) > 1:
            mod_files.sort()
            
            for mod_file in mod_files[1:]:  # Keep first, disable rest
                for mod in mods:
                    if mod.file_name == mod_file:
                        if disable_mod_file(Path(mod.path)):
                            disabled_count += 1
                        break
    
    return disabled_count


def disable_all_errors(mods: List[ModInfo], issues: List[Issue]) -> int:
    """
    Disable all mods that have error-level issues.
    
    Args:
        mods: List of all mods
        issues: List of issues to check
        
    Returns:
        Number of mods disabled
    """
    disabled_count = 0
    
    # Collect all mod files with errors
    error_mod_files = set()
    for issue in issues:
        if issue.get_severity_enum() == Severity.ERROR:
            # Handle both single files and comma-separated lists
            mod_files = [f.strip() for f in issue.mod_file.split(",")]
            error_mod_files.update(mod_files)
    
    # Disable error mods
    for mod in mods:
        if mod.file_name in error_mod_files:
            if disable_mod_file(Path(mod.path)):
                disabled_count += 1
    
    return disabled_count


def _parse_version(version_str: str) -> tuple:
    """
    Parse version string into comparable tuple.
    
    Args:
        version_str: Version string to parse
        
    Returns:
        Tuple of version components for comparison
    """
    import re
    
    # Extract numeric parts
    parts = re.findall(r'\d+', version_str)
    
    # Convert to integers, pad with zeros if needed
    numeric_parts = [int(p) for p in parts]
    
    # Pad to at least 3 components for consistent comparison
    while len(numeric_parts) < 3:
        numeric_parts.append(0)
    
    return tuple(numeric_parts)