"""Plugin to detect large mod files that might impact performance."""

import os
from typing import List
from pathlib import Path

from ...core.model import ModInfo, Issue, Severity


def evaluate(mods: List[ModInfo]) -> List[Issue]:
    """
    Detect mods with large file sizes that might impact loading performance.
    
    Args:
        mods: List of ModInfo objects to check
        
    Returns:
        List of issues for large files
    """
    issues = []
    large_file_threshold = 50 * 1024 * 1024  # 50 MB
    
    for mod in mods:
        try:
            file_path = Path(mod.path)
            if file_path.exists():
                file_size = file_path.stat().st_size
                
                if file_size > large_file_threshold:
                    size_mb = round(file_size / (1024 * 1024), 1)
                    issues.append(Issue(
                        mod_file=mod.file_name,
                        severity=Severity.INFO.value,
                        category="performance",
                        message=f"Large mod file detected: {size_mb} MB",
                        suggestion="Large mods may increase loading times. Consider alternatives if performance is important."
                    ))
        except Exception:
            # Skip files that can't be checked
            continue
    
    return issues