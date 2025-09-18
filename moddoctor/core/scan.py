"""Mod directory scanning functionality."""

import os
from pathlib import Path
from typing import List, Callable, Optional

from .model import ModInfo
from ..util.cache import compute_file_fingerprint, get_cached_metadata, set_cached_metadata
from .metadata import extract_mod_info


def scan_mods_directory(mods_dir: Path, 
                       progress_callback: Optional[Callable[[str, int, int], None]] = None) -> List[ModInfo]:
    """
    Scan a mods directory for .jar files and extract mod information.
    
    Args:
        mods_dir: Path to the mods directory
        progress_callback: Optional callback function called with (filename, current, total)
        
    Returns:
        List of ModInfo objects for found mods
    """
    if not mods_dir.exists() or not mods_dir.is_dir():
        return []
    
    # Find all .jar files, excluding .disabled.jar files
    jar_files = []
    for file in mods_dir.iterdir():
        if file.is_file() and file.suffix.lower() == '.jar':
            if not file.name.endswith('.disabled.jar'):
                jar_files.append(file)
    
    jar_files.sort()  # Sort for consistent ordering
    
    mods = []
    total_files = len(jar_files)
    
    for i, jar_file in enumerate(jar_files):
        if progress_callback:
            progress_callback(jar_file.name, i + 1, total_files)
        
        try:
            mod_info = scan_single_mod(jar_file)
            if mod_info:
                mods.append(mod_info)
        except Exception as e:
            # Create a basic ModInfo for files that fail to parse
            mod_info = ModInfo(
                file_name=jar_file.name,
                path=str(jar_file),
                fingerprint_sha256=compute_file_fingerprint(jar_file)
            )
            mods.append(mod_info)
    
    return mods


def scan_single_mod(jar_file: Path, use_cache: bool = True) -> Optional[ModInfo]:
    """
    Scan a single mod jar file and extract information.
    
    Args:
        jar_file: Path to the jar file
        use_cache: Whether to use cached metadata if available
        
    Returns:
        ModInfo object or None if extraction fails
    """
    if not jar_file.exists():
        return None
    
    # Compute fingerprint
    fingerprint = compute_file_fingerprint(jar_file)
    
    # Check cache first
    if use_cache and fingerprint:
        cached_data = get_cached_metadata(fingerprint)
        if cached_data:
            try:
                # Reconstruct ModInfo from cached data
                mod_info = ModInfo(
                    file_name=jar_file.name,
                    path=str(jar_file),
                    fingerprint_sha256=fingerprint
                )
                
                # Restore cached fields
                for field, value in cached_data.items():
                    if hasattr(mod_info, field):
                        setattr(mod_info, field, value)
                
                return mod_info
            except Exception:
                pass  # Fall through to re-extract
    
    # Extract mod information
    mod_info = extract_mod_info(jar_file)
    if mod_info:
        mod_info.fingerprint_sha256 = fingerprint
        
        # Cache the extracted metadata
        if fingerprint:
            cache_data = {
                'modid': mod_info.modid,
                'name': mod_info.name,
                'version': mod_info.version,
                'description': mod_info.description,
                'authors': mod_info.authors,
                'loader': mod_info.loader,
                'environment': mod_info.environment,
                'minecraft_versions': mod_info.minecraft_versions,
                'homepage': mod_info.homepage,
                'project_url': mod_info.project_url,
                'dependencies': [
                    {
                        'modid': dep.modid,
                        'version': dep.version,
                        'kind': dep.kind,
                        'side': dep.side,
                        'source': dep.source
                    }
                    for dep in mod_info.dependencies
                ]
            }
            set_cached_metadata(fingerprint, cache_data)
    
    return mod_info


def is_mod_disabled(jar_file: Path) -> bool:
    """Check if a mod file is disabled (has .disabled.jar extension)."""
    return jar_file.name.endswith('.disabled.jar')


def get_enabled_mods_count(mods_dir: Path) -> int:
    """Get count of enabled mod files in directory."""
    if not mods_dir.exists():
        return 0
    
    count = 0
    for file in mods_dir.iterdir():
        if (file.is_file() and 
            file.suffix.lower() == '.jar' and 
            not file.name.endswith('.disabled.jar')):
            count += 1
    
    return count


def get_disabled_mods_count(mods_dir: Path) -> int:
    """Get count of disabled mod files in directory."""
    if not mods_dir.exists():
        return 0
    
    count = 0
    for file in mods_dir.iterdir():
        if (file.is_file() and 
            file.name.endswith('.disabled.jar')):
            count += 1
    
    return count