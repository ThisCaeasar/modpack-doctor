"""Core data models for mod analysis."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Literal
from PIL import Image

# Type alias for mod loaders
Loader = Literal["fabric", "quilt", "forge", "neoforge", "unknown"]


class Severity(Enum):
    """Issue severity levels."""
    OK = "ok"
    INFO = "info" 
    WARNING = "warning"
    ERROR = "error"

    def __str__(self) -> str:
        return self.value


@dataclass
class Dependency:
    """Represents a mod dependency."""
    modid: str
    version: Optional[str] = None
    kind: str = "required"  # required | recommended | optional | incompatible | breaks | conflicts
    side: Optional[str] = None
    source: Optional[str] = None  # fabric|forge|quilt|modrinth|curseforge|heuristic


@dataclass
class ModInfo:
    """Information about a mod file."""
    file_name: str
    path: str
    loader: Optional[Loader] = None
    modid: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    authors: List[str] = field(default_factory=list)
    environment: Optional[str] = None  # client|server|both|unknown
    dependencies: List[Dependency] = field(default_factory=list)
    minecraft_versions: List[str] = field(default_factory=list)
    fingerprint_sha256: Optional[str] = None
    homepage: Optional[str] = None
    project_url: Optional[str] = None
    icon_image: Optional[Image.Image] = None  # In-memory PIL Image
    
    # Legacy compatibility fields
    depends: List[Dependency] = field(default_factory=list)
    recommends: List[Dependency] = field(default_factory=list)
    conflicts: List[Dependency] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    sha1: Optional[str] = None
    modrinth: Dict[str, Any] = field(default_factory=dict)
    curseforge: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Consolidate dependencies into main dependencies list."""
        if self.depends or self.recommends or self.conflicts:
            # Merge legacy dependency lists
            all_deps = []
            for dep in self.depends:
                dep.kind = "required"
                all_deps.append(dep)
            for dep in self.recommends:
                dep.kind = "recommended"
                all_deps.append(dep)
            for dep in self.conflicts:
                dep.kind = "conflicts"
                all_deps.append(dep)
            
            # Add to main dependencies if not already there
            existing_modids = {dep.modid for dep in self.dependencies}
            for dep in all_deps:
                if dep.modid not in existing_modids:
                    self.dependencies.append(dep)


@dataclass
class Issue:
    """Represents an analysis issue."""
    mod_file: str
    severity: str  # String representation for compatibility
    message: str
    suggestion: Optional[str] = None
    category: str = "general"
    
    def get_severity_enum(self) -> Severity:
        """Convert string severity to enum."""
        try:
            return Severity(self.severity.lower())
        except ValueError:
            return Severity.INFO


@dataclass 
class AnalysisResult:
    """Complete analysis results."""
    loader_inferred: Optional[Loader]
    minecraft_versions_inferred: List[str]
    mods: List[ModInfo]
    issues: List[Issue] = field(default_factory=list)
    
    # Legacy compatibility fields
    missing_dependencies: List[Dict[str, Any]] = field(default_factory=list)
    version_mismatches: List[Dict[str, Any]] = field(default_factory=list)
    duplicates: List[Dict[str, Any]] = field(default_factory=list)
    explicit_conflicts: List[Dict[str, Any]] = field(default_factory=list)
    known_conflicts: List[Dict[str, Any]] = field(default_factory=list)
    potential_conflicts: List[Dict[str, Any]] = field(default_factory=list)
    mixed_loaders_warning: bool = False
    recommendations: Dict[str, Any] = field(default_factory=dict)
    kb_info: Dict[str, Any] = field(default_factory=dict)