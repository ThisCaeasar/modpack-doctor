"""Data model classes for mod analysis."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class Loader:
    """Supported mod loaders."""
    FABRIC = "fabric"
    QUILT = "quilt" 
    FORGE = "forge"
    NEOFORGE = "neoforge"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Issue severity levels."""
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class Dependency:
    """Represents a mod dependency."""
    modid: str
    version: Optional[str] = None
    kind: str = "required"  # required | recommended | optional | incompatible | breaks | conflicts
    side: Optional[str] = None
    source: Optional[str] = None  # fabric|forge|quilt|modrinth|curseforge|heuristic


@dataclass
class Issue:
    """Represents an analysis issue with a mod."""
    severity: Severity
    message: str
    suggestion: Optional[str] = None
    mod_id: Optional[str] = None


@dataclass
class ModInfo:
    """Information about a single mod."""
    file_name: str
    path: str
    loader: Optional[str] = None  # fabric|forge|quilt|unknown
    modid: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    authors: List[str] = field(default_factory=list)
    environment: Optional[str] = None  # client|server|both|unknown
    depends: List[Dependency] = field(default_factory=list)
    recommends: List[Dependency] = field(default_factory=list)
    conflicts: List[Dependency] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    minecraft_versions: List[str] = field(default_factory=list)
    sha256: Optional[str] = None  # SHA256 fingerprint for caching
    icon_path: Optional[str] = None
    icon_image: Optional[Any] = None  # PIL Image in memory
    homepage: Optional[str] = None
    project_url: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)
    
    # Legacy compatibility
    sha1: Optional[str] = None
    modrinth: Dict[str, Any] = field(default_factory=dict)
    curseforge: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def overall_severity(self) -> Severity:
        """Get the worst severity from all issues."""
        if not self.issues:
            return Severity.OK
        
        severities = [issue.severity for issue in self.issues]
        if Severity.ERROR in severities:
            return Severity.ERROR
        elif Severity.WARNING in severities:
            return Severity.WARNING
        elif Severity.INFO in severities:
            return Severity.INFO
        return Severity.OK


@dataclass
class AnalysisResult:
    """Results of mod pack analysis."""
    loader_inferred: Optional[str]
    minecraft_versions_inferred: List[str]
    mods: List[ModInfo]
    missing_dependencies: List[Dict[str, Any]]
    version_mismatches: List[Dict[str, Any]]
    duplicates: List[Dict[str, Any]]
    explicit_conflicts: List[Dict[str, Any]]
    known_conflicts: List[Dict[str, Any]]
    potential_conflicts: List[Dict[str, Any]]
    mixed_loaders_warning: bool
    recommendations: Dict[str, Any]
    kb_info: Dict[str, Any] = field(default_factory=dict)