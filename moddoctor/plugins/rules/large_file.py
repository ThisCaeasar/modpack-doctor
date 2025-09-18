"""Example rule for detecting large mod files."""

from pathlib import Path
from typing import List

from ...core.model import ModInfo, Issue, Severity


class LargeFileRule:
    """Rule that warns about very large mod files (>50 MB)."""
    
    def __init__(self, size_threshold_mb: int = 50):
        """
        Initialize the rule.
        
        Args:
            size_threshold_mb: Size threshold in MB for warning
        """
        self.size_threshold_bytes = size_threshold_mb * 1024 * 1024
    
    def apply(self, mods: List[ModInfo]) -> None:
        """
        Apply the rule to detect large mod files.
        
        Args:
            mods: List of ModInfo objects to analyze
        """
        for mod in mods:
            try:
                file_path = Path(mod.path)
                if file_path.exists():
                    file_size = file_path.stat().st_size
                    
                    if file_size > self.size_threshold_bytes:
                        size_mb = file_size / (1024 * 1024)
                        issue = Issue(
                            severity=Severity.INFO,
                            message=f"Large mod file: {size_mb:.1f} MB",
                            suggestion="Large mods may impact loading times and memory usage",
                            mod_id=mod.modid
                        )
                        mod.issues.append(issue)
            
            except Exception:
                # Skip files that can't be checked
                continue