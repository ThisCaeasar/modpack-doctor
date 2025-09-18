"""Analysis engine for detecting mod issues."""

from typing import List, Dict, Any, Set, Optional
from collections import defaultdict
import re

from .model import ModInfo, Issue, Severity, AnalysisResult, Dependency
from ..plugins.registry import get_plugin_issues


def analyze_mods(mods: List[ModInfo]) -> AnalysisResult:
    """
    Perform comprehensive analysis of mods.
    
    Args:
        mods: List of ModInfo objects to analyze
        
    Returns:
        AnalysisResult with all detected issues
    """
    issues = []
    
    # Basic analysis
    issues.extend(_detect_duplicates(mods))
    issues.extend(_detect_loader_mismatch(mods))
    issues.extend(_detect_known_conflicts(mods))
    issues.extend(_detect_missing_dependencies(mods))
    issues.extend(_detect_version_mismatches(mods))
    issues.extend(_detect_mc_version_mismatch(mods))
    issues.extend(_detect_prerelease_mods(mods))
    
    # Plugin-based analysis
    issues.extend(get_plugin_issues(mods))
    
    # Infer loader and MC versions
    loader_inferred = _infer_primary_loader(mods)
    mc_versions = _infer_mc_versions(mods)
    
    return AnalysisResult(
        loader_inferred=loader_inferred,
        minecraft_versions_inferred=mc_versions,
        mods=mods,
        issues=issues
    )


def _detect_duplicates(mods: List[ModInfo]) -> List[Issue]:
    """Detect duplicate mods (same mod ID but different versions)."""
    issues = []
    
    # Group mods by ID
    mod_groups = defaultdict(list)
    for mod in mods:
        mod_id = mod.modid or mod.name or mod.file_name
        if mod_id:
            mod_groups[mod_id.lower()].append(mod)
    
    for mod_id, mod_list in mod_groups.items():
        if len(mod_list) > 1:
            # Check if they have different versions
            versions = {mod.version or "unknown" for mod in mod_list}
            if len(versions) > 1:
                file_names = [mod.file_name for mod in mod_list]
                issues.append(Issue(
                    mod_file=", ".join(file_names),
                    severity=Severity.ERROR.value,
                    category="duplicates",
                    message=f"Duplicate mod detected: {mod_id}",
                    suggestion=f"Remove duplicate versions. Found: {', '.join(versions)}"
                ))
    
    return issues


def _detect_loader_mismatch(mods: List[ModInfo]) -> List[Issue]:
    """Detect mixed mod loaders."""
    issues = []
    
    loaders = {mod.loader for mod in mods if mod.loader and mod.loader != "unknown"}
    
    if len(loaders) > 1:
        loader_counts = defaultdict(int)
        for mod in mods:
            if mod.loader and mod.loader != "unknown":
                loader_counts[mod.loader] += 1
        
        # Find mods with minority loaders
        primary_loader = max(loader_counts.items(), key=lambda x: x[1])[0]
        
        for mod in mods:
            if mod.loader and mod.loader != "unknown" and mod.loader != primary_loader:
                issues.append(Issue(
                    mod_file=mod.file_name,
                    severity=Severity.ERROR.value,
                    category="loader_mismatch",
                    message=f"Mod uses {mod.loader} loader, but primary loader is {primary_loader}",
                    suggestion=f"Use {primary_loader} version of this mod or switch modpack loader"
                ))
    
    return issues


def _detect_known_conflicts(mods: List[ModInfo]) -> List[Issue]:
    """Detect known mod conflicts."""
    issues = []
    
    # Known conflict pairs
    known_conflicts = [
        ({"sodium", "rubidium"}, "Sodium and Rubidium are incompatible (both are rendering optimizers)"),
        ({"optifine", "sodium"}, "OptiFine and Sodium are incompatible"),
        ({"lithium", "sodium-extra"}, "Lithium and Sodium Extra can conflict"),
        ({"iris", "oculus"}, "Iris and Oculus are incompatible (both are shader mods)"),
        ({"optifabric", "sodium"}, "OptiFabric and Sodium are incompatible"),
    ]
    
    # Get set of installed mod IDs
    installed_mods = set()
    mod_lookup = {}
    for mod in mods:
        mod_id = (mod.modid or mod.name or mod.file_name).lower()
        installed_mods.add(mod_id)
        mod_lookup[mod_id] = mod
    
    for conflict_set, message in known_conflicts:
        conflicting_mods = conflict_set.intersection(installed_mods)
        if len(conflicting_mods) > 1:
            mod_files = [mod_lookup[mod_id].file_name for mod_id in conflicting_mods]
            issues.append(Issue(
                mod_file=", ".join(mod_files),
                severity=Severity.ERROR.value,
                category="known_conflicts",
                message=message,
                suggestion="Remove one of the conflicting mods"
            ))
    
    return issues


def _detect_missing_dependencies(mods: List[ModInfo]) -> List[Issue]:
    """Detect missing mod dependencies."""
    issues = []
    
    # Get set of available mod IDs
    available_mods = set()
    for mod in mods:
        if mod.modid:
            available_mods.add(mod.modid.lower())
        if mod.name:
            available_mods.add(mod.name.lower())
    
    for mod in mods:
        for dep in mod.dependencies:
            if dep.kind == "required" and dep.modid:
                dep_id = dep.modid.lower()
                
                # Skip built-in dependencies
                if dep_id in {"minecraft", "java", "fabricloader", "forge", "quilt_loader", "neoforge"}:
                    continue
                
                if dep_id not in available_mods:
                    issues.append(Issue(
                        mod_file=mod.file_name,
                        severity=Severity.ERROR.value,
                        category="missing_dependencies",
                        message=f"Missing required dependency: {dep.modid}",
                        suggestion=f"Install {dep.modid} mod"
                    ))
    
    return issues


def _detect_version_mismatches(mods: List[ModInfo]) -> List[Issue]:
    """Detect version mismatches in dependencies."""
    issues = []
    
    # Build version map
    mod_versions = {}
    for mod in mods:
        if mod.modid and mod.version:
            mod_versions[mod.modid.lower()] = mod.version
    
    for mod in mods:
        for dep in mod.dependencies:
            if dep.modid and dep.version and dep.modid.lower() in mod_versions:
                required_version = dep.version
                actual_version = mod_versions[dep.modid.lower()]
                
                # Simple version comparison (this could be enhanced)
                if required_version != actual_version and not _version_satisfies(actual_version, required_version):
                    issues.append(Issue(
                        mod_file=mod.file_name,
                        severity=Severity.WARNING.value,
                        category="version_mismatches",
                        message=f"Version mismatch for {dep.modid}: requires {required_version}, found {actual_version}",
                        suggestion=f"Update {dep.modid} to version {required_version}"
                    ))
    
    return issues


def _detect_mc_version_mismatch(mods: List[ModInfo]) -> List[Issue]:
    """Detect Minecraft version mismatches between mods."""
    issues = []
    
    # Collect all MC versions from mods
    mc_versions = []
    for mod in mods:
        mc_versions.extend(mod.minecraft_versions)
    
    if not mc_versions:
        return issues
    
    # Find the most common MC version
    from collections import Counter
    version_counts = Counter(mc_versions)
    primary_version = version_counts.most_common(1)[0][0] if version_counts else None
    
    if primary_version:
        for mod in mods:
            if mod.minecraft_versions:
                mod_mc_versions = set(mod.minecraft_versions)
                if primary_version not in mod_mc_versions:
                    issues.append(Issue(
                        mod_file=mod.file_name,
                        severity=Severity.WARNING.value,
                        category="mc_version_mismatch",
                        message=f"Mod targets MC {', '.join(mod.minecraft_versions)}, primary version is {primary_version}",
                        suggestion=f"Use version compatible with MC {primary_version}"
                    ))
    
    return issues


def _detect_prerelease_mods(mods: List[ModInfo]) -> List[Issue]:
    """Detect pre-release versions that might be unstable."""
    issues = []
    
    prerelease_patterns = [
        r'alpha', r'beta', r'rc', r'pre', r'snapshot', r'dev', r'experimental'
    ]
    
    for mod in mods:
        if mod.version:
            version_lower = mod.version.lower()
            for pattern in prerelease_patterns:
                if re.search(pattern, version_lower):
                    issues.append(Issue(
                        mod_file=mod.file_name,
                        severity=Severity.INFO.value,
                        category="prerelease",
                        message=f"Pre-release version detected: {mod.version}",
                        suggestion="Consider using stable release version"
                    ))
                    break
    
    return issues


def _infer_primary_loader(mods: List[ModInfo]) -> Optional[str]:
    """Infer the primary mod loader from installed mods."""
    loader_counts = defaultdict(int)
    
    for mod in mods:
        if mod.loader and mod.loader != "unknown":
            loader_counts[mod.loader] += 1
    
    if not loader_counts:
        return None
    
    return max(loader_counts.items(), key=lambda x: x[1])[0]


def _infer_mc_versions(mods: List[ModInfo]) -> List[str]:
    """Infer Minecraft versions from mod dependencies."""
    mc_versions = []
    
    for mod in mods:
        mc_versions.extend(mod.minecraft_versions)
    
    # Return unique versions, sorted
    return sorted(list(set(mc_versions)))


def _version_satisfies(actual: str, required: str) -> bool:
    """
    Check if actual version satisfies required version.
    This is a simplified implementation.
    """
    # Handle version ranges and comparators
    if '>=' in required:
        required_version = required.replace('>=', '').strip()
        return _compare_versions(actual, required_version) >= 0
    elif '>' in required:
        required_version = required.replace('>', '').strip()
        return _compare_versions(actual, required_version) > 0
    elif '<=' in required:
        required_version = required.replace('<=', '').strip()
        return _compare_versions(actual, required_version) <= 0
    elif '<' in required:
        required_version = required.replace('<', '').strip()
        return _compare_versions(actual, required_version) < 0
    else:
        # Exact match or fuzzy match
        return actual == required or required in actual


def _compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings.
    Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    def normalize_version(v):
        # Extract numeric parts
        parts = re.findall(r'\d+', v)
        return [int(p) for p in parts]
    
    parts1 = normalize_version(v1)
    parts2 = normalize_version(v2)
    
    # Pad shorter version with zeros
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))
    
    for p1, p2 in zip(parts1, parts2):
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
    
    return 0