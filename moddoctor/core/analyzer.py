"""Mod analysis and issue detection."""

import re
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Any, Optional

from .model import ModInfo, Issue, Severity, AnalysisResult
from ..plugins.registry import PluginRegistry

try:
    from packaging import specifiers
    PACKAGING_AVAILABLE = True
except ImportError:
    PACKAGING_AVAILABLE = False


class ModAnalyzer:
    """Analyzes mods for various issues and conflicts."""
    
    def __init__(self, knowledge_base_path: Optional[Path] = None):
        """
        Initialize the analyzer.
        
        Args:
            knowledge_base_path: Path to knowledge base files
        """
        self.plugin_registry = PluginRegistry()
        self.known_conflicts = self._load_known_conflicts(knowledge_base_path)
    
    def analyze_mods(self, mods: List[ModInfo]) -> AnalysisResult:
        """
        Perform comprehensive analysis of a mod list.
        
        Args:
            mods: List of ModInfo objects to analyze
            
        Returns:
            AnalysisResult with all detected issues
        """
        # Clear existing issues
        for mod in mods:
            mod.issues.clear()
        
        # Detect various types of issues
        duplicates = self._detect_duplicates(mods)
        loader_conflicts = self._detect_loader_conflicts(mods)
        known_conflicts = self._detect_known_conflicts(mods)
        missing_deps = self._detect_missing_dependencies(mods)
        version_mismatches = self._detect_version_mismatches(mods)
        mc_version_conflicts = self._detect_mc_version_conflicts(mods)
        prerelease_warnings = self._detect_prerelease_versions(mods)
        
        # Apply plugin rules
        self.plugin_registry.apply_rules(mods)
        
        # Infer loader and MC versions
        loader_inferred = self._infer_loader(mods)
        mc_versions_inferred = self._infer_mc_versions(mods)
        
        return AnalysisResult(
            loader_inferred=loader_inferred,
            minecraft_versions_inferred=mc_versions_inferred,
            mods=mods,
            missing_dependencies=missing_deps,
            version_mismatches=version_mismatches,
            duplicates=duplicates,
            explicit_conflicts=[],  # Computed from mod.conflicts
            known_conflicts=known_conflicts,
            potential_conflicts=[],  # Could be expanded later
            mixed_loaders_warning=len(loader_conflicts) > 0,
            recommendations={},  # Could be populated with optimization suggestions
            kb_info={}
        )
    
    def _detect_duplicates(self, mods: List[ModInfo]) -> List[Dict[str, Any]]:
        """Detect duplicate mods by mod ID."""
        mod_groups = defaultdict(list)
        
        for mod in mods:
            key = (mod.modid or mod.name or mod.file_name).lower()
            mod_groups[key].append(mod)
        
        duplicates = []
        for key, group in mod_groups.items():
            if len(group) > 1:
                # Add issues to each mod in the duplicate group
                for mod in group:
                    issue = Issue(
                        severity=Severity.WARNING,
                        message=f"Duplicate mod detected: {len(group)} versions of '{key}' found",
                        suggestion="Keep only one version of this mod",
                        mod_id=mod.modid
                    )
                    mod.issues.append(issue)
                
                duplicates.append({
                    "mod_id": key,
                    "mods": [{"name": m.name, "version": m.version, "file": m.file_name} for m in group]
                })
        
        return duplicates
    
    def _detect_loader_conflicts(self, mods: List[ModInfo]) -> List[str]:
        """Detect mixed mod loaders."""
        loaders = set()
        for mod in mods:
            if mod.loader:
                loaders.add(mod.loader)
        
        conflicts = []
        if len(loaders) > 1:
            for mod in mods:
                issue = Issue(
                    severity=Severity.ERROR,
                    message=f"Mixed loaders detected: {', '.join(sorted(loaders))}",
                    suggestion="Use mods for only one loader type",
                    mod_id=mod.modid
                )
                mod.issues.append(issue)
            conflicts = list(loaders)
        
        return conflicts
    
    def _detect_known_conflicts(self, mods: List[ModInfo]) -> List[Dict[str, Any]]:
        """Detect known conflicting mod combinations."""
        conflicts = []
        mod_ids = {(mod.modid or mod.name or "").lower(): mod for mod in mods if mod.modid or mod.name}
        
        for conflict in self.known_conflicts.get("pairs", []):
            mod_a = conflict["a"].lower()
            mod_b = conflict["b"].lower()
            
            if mod_a in mod_ids and mod_b in mod_ids:
                # Check if conflict applies to current loader
                when_condition = conflict.get("when", {})
                loader_condition = when_condition.get("loader", [])
                
                current_loader = self._infer_loader(mods)
                if not loader_condition or current_loader in loader_condition:
                    # Add issue to both conflicting mods
                    for mod_id in [mod_a, mod_b]:
                        mod = mod_ids[mod_id]
                        issue = Issue(
                            severity=Severity.ERROR,
                            message=f"Conflicts with {conflict['a']} / {conflict['b']}: {conflict['reason']}",
                            suggestion="Disable one of the conflicting mods",
                            mod_id=mod.modid
                        )
                        mod.issues.append(issue)
                    
                    conflicts.append({
                        "mod_a": conflict["a"],
                        "mod_b": conflict["b"],
                        "reason": conflict["reason"]
                    })
        
        return conflicts
    
    def _detect_missing_dependencies(self, mods: List[ModInfo]) -> List[Dict[str, Any]]:
        """Detect missing required dependencies."""
        available_mods = set()
        for mod in mods:
            if mod.modid:
                available_mods.add(mod.modid.lower())
            if mod.name:
                available_mods.add(mod.name.lower())
            for provided in mod.provides:
                available_mods.add(provided.lower())
        
        missing_deps = []
        for mod in mods:
            for dep in mod.depends:
                if dep.kind == "required" and dep.modid:
                    dep_id = dep.modid.lower()
                    if dep_id not in available_mods and dep_id not in ["minecraft", "java", "fabricloader", "quilt_loader", "forge"]:
                        issue = Issue(
                            severity=Severity.ERROR,
                            message=f"Missing required dependency: {dep.modid}",
                            suggestion=f"Install the required mod: {dep.modid}",
                            mod_id=mod.modid
                        )
                        mod.issues.append(issue)
                        
                        missing_deps.append({
                            "mod_id": mod.modid or mod.name,
                            "missing_dep": dep.modid,
                            "version": dep.version
                        })
        
        return missing_deps
    
    def _detect_version_mismatches(self, mods: List[ModInfo]) -> List[Dict[str, Any]]:
        """Detect version mismatches in dependencies."""
        version_mismatches = []
        
        if not PACKAGING_AVAILABLE:
            return version_mismatches
        
        # Build map of available mod versions
        mod_versions = {}
        for mod in mods:
            if mod.modid and mod.version:
                mod_versions[mod.modid.lower()] = mod.version
        
        # Check version requirements
        for mod in mods:
            for dep in mod.depends:
                if dep.modid and dep.version and dep.modid.lower() in mod_versions:
                    try:
                        spec = specifiers.SpecifierSet(dep.version)
                        available_version = mod_versions[dep.modid.lower()]
                        
                        if not spec.contains(available_version):
                            issue = Issue(
                                severity=Severity.WARNING,
                                message=f"Version mismatch: {dep.modid} {available_version} doesn't satisfy {dep.version}",
                                suggestion=f"Update {dep.modid} to match version requirement",
                                mod_id=mod.modid
                            )
                            mod.issues.append(issue)
                            
                            version_mismatches.append({
                                "mod_id": mod.modid or mod.name,
                                "dep_id": dep.modid,
                                "required_version": dep.version,
                                "available_version": available_version
                            })
                    except Exception:
                        # Skip invalid version specifiers
                        continue
        
        return version_mismatches
    
    def _detect_mc_version_conflicts(self, mods: List[ModInfo]):
        """Detect Minecraft version mismatches."""
        mc_versions = set()
        for mod in mods:
            for version in mod.minecraft_versions:
                if version:
                    # Normalize version (remove brackets, etc.)
                    normalized = re.sub(r'[^\d.]', '', version)
                    if normalized:
                        mc_versions.add(normalized)
        
        if len(mc_versions) > 1:
            for mod in mods:
                if mod.minecraft_versions:
                    issue = Issue(
                        severity=Severity.WARNING,
                        message=f"Multiple MC versions detected: {', '.join(sorted(mc_versions))}",
                        suggestion="Ensure all mods target the same Minecraft version",
                        mod_id=mod.modid
                    )
                    mod.issues.append(issue)
    
    def _detect_prerelease_versions(self, mods: List[ModInfo]):
        """Detect prerelease/development versions."""
        prerelease_patterns = [
            r'alpha', r'beta', r'rc', r'pre', r'snapshot', 
            r'dev', r'test', r'experimental', r'unstable'
        ]
        
        for mod in mods:
            if mod.version:
                version_lower = mod.version.lower()
                for pattern in prerelease_patterns:
                    if re.search(pattern, version_lower):
                        issue = Issue(
                            severity=Severity.INFO,
                            message=f"Prerelease version detected: {mod.version}",
                            suggestion="Consider using stable release versions for better stability",
                            mod_id=mod.modid
                        )
                        mod.issues.append(issue)
                        break
    
    def _infer_loader(self, mods: List[ModInfo]) -> Optional[str]:
        """Infer the primary mod loader from the mod list."""
        loader_counts = defaultdict(int)
        for mod in mods:
            if mod.loader:
                loader_counts[mod.loader] += 1
        
        if not loader_counts:
            return None
        
        return max(loader_counts, key=loader_counts.get)
    
    def _infer_mc_versions(self, mods: List[ModInfo]) -> List[str]:
        """Infer Minecraft versions from the mod list."""
        versions = set()
        for mod in mods:
            for version in mod.minecraft_versions:
                if version:
                    # Normalize version
                    normalized = re.sub(r'[^\d.]', '', version)
                    if normalized:
                        versions.add(normalized)
        
        return sorted(list(versions))
    
    def _load_known_conflicts(self, knowledge_base_path: Optional[Path]) -> Dict[str, Any]:
        """Load known conflicts from JSON file."""
        if not knowledge_base_path:
            # Try to find it relative to current file
            current_dir = Path(__file__).parent.parent.parent
            kb_file = current_dir / "data_known_conflicts_Version3.json"
        else:
            kb_file = knowledge_base_path
        
        if kb_file.exists():
            try:
                import json
                with open(kb_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        
        return {"pairs": []}