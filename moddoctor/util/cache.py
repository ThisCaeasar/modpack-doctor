"""Caching functionality for mod analysis."""

import json
import hashlib
import os
from pathlib import Path
from typing import Dict, Any, Optional


def get_cache_dir() -> Path:
    """Get the user cache directory."""
    if os.name == 'nt':
        # Windows
        cache_base = Path(os.environ.get('USERPROFILE', '~'))
    else:
        # Unix-like
        cache_base = Path(os.environ.get('HOME', '~'))
    
    cache_dir = cache_base / '.modpack-doctor' / 'cache'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def compute_file_fingerprint(file_path: Path) -> str:
    """Compute SHA256 fingerprint of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception:
        return ""


def get_cached_metadata(fingerprint: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached metadata for a file fingerprint."""
    if not fingerprint:
        return None
        
    cache_dir = get_cache_dir()
    cache_file = cache_dir / f"{fingerprint}.json"
    
    try:
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    
    return None


def set_cached_metadata(fingerprint: str, metadata: Dict[str, Any]) -> None:
    """Store metadata in cache for a file fingerprint."""
    if not fingerprint:
        return
        
    cache_dir = get_cache_dir()
    cache_file = cache_dir / f"{fingerprint}.json"
    
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def get_cached_icon_path(fingerprint: str) -> Optional[Path]:
    """Get path to cached icon file."""
    if not fingerprint:
        return None
        
    cache_dir = get_cache_dir()
    icon_file = cache_dir / f"{fingerprint}_icon.png"
    
    return icon_file if icon_file.exists() else None


def set_cached_icon(fingerprint: str, icon_data: bytes) -> None:
    """Store icon data in cache."""
    if not fingerprint or not icon_data:
        return
        
    cache_dir = get_cache_dir()
    icon_file = cache_dir / f"{fingerprint}_icon.png"
    
    try:
        with open(icon_file, 'wb') as f:
            f.write(icon_data)
    except Exception:
        pass


def clear_cache() -> bool:
    """Clear all cached data."""
    try:
        cache_dir = get_cache_dir()
        for file in cache_dir.iterdir():
            if file.is_file():
                file.unlink()
        return True
    except Exception:
        return False


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics."""
    try:
        cache_dir = get_cache_dir()
        if not cache_dir.exists():
            return {"files": 0, "size_mb": 0.0}
            
        files = list(cache_dir.iterdir())
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        
        return {
            "files": len(files),
            "size_mb": round(total_size / (1024 * 1024), 2)
        }
    except Exception:
        return {"files": 0, "size_mb": 0.0}