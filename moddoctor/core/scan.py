"""Mod scanning functionality with caching support."""

import hashlib
import json
from pathlib import Path
from typing import List, Optional

from .model import ModInfo
from .metadata import extract_mod_info
from ..util.cache import CacheManager


def scan_mods_folder(mods_dir: Path, cache_manager: Optional[CacheManager] = None) -> List[ModInfo]:
    """
    Scan a mods directory for JAR files and extract mod information.
    
    Args:
        mods_dir: Path to the mods directory
        cache_manager: Optional cache manager for storing/retrieving metadata
        
    Returns:
        List of ModInfo objects for valid mods found
    """
    if not mods_dir.exists() or not mods_dir.is_dir():
        return []
    
    jar_files = sorted([p for p in mods_dir.iterdir() if p.suffix.lower() == ".jar"])
    mods = []
    
    for jar_path in jar_files:
        try:
            # Calculate SHA256 fingerprint
            sha256 = calculate_sha256(jar_path)
            
            # Try to load from cache first
            cached_mod = None
            if cache_manager:
                cached_mod = cache_manager.get_mod_metadata(sha256)
            
            if cached_mod:
                # Use cached metadata but update path info
                mod_info = cached_mod
                mod_info.path = str(jar_path)
                mod_info.file_name = jar_path.name
            else:
                # Extract fresh metadata
                mod_info = extract_mod_info(jar_path)
                if mod_info:
                    mod_info.sha256 = sha256
                    
                    # Cache the metadata
                    if cache_manager:
                        cache_manager.store_mod_metadata(sha256, mod_info)
            
            if mod_info:
                mods.append(mod_info)
                
        except Exception as e:
            # Log error but continue with other mods
            print(f"Warning: Failed to process {jar_path}: {e}")
            continue
    
    return mods


def calculate_sha256(file_path: Path) -> str:
    """
    Calculate SHA256 hash of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Hexadecimal SHA256 hash string
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read in chunks to handle large files
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def filter_jar_files(directory: Path) -> List[Path]:
    """
    Filter JAR files from a directory.
    
    Args:
        directory: Directory to scan
        
    Returns:
        List of JAR file paths
    """
    if not directory.exists() or not directory.is_dir():
        return []
    
    return sorted([p for p in directory.iterdir() 
                  if p.is_file() and p.suffix.lower() == ".jar"])