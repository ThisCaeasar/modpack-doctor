"""Report generation for analysis results."""

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .model import ModInfo, AnalysisResult, Severity


class ReportGenerator:
    """Generates reports from analysis results."""
    
    def __init__(self):
        """Initialize the report generator."""
        pass
    
    def generate_markdown_report(self, 
                                analysis_result: AnalysisResult, 
                                mods_directory: Optional[Path] = None) -> str:
        """
        Generate a Markdown report from analysis results.
        
        Args:
            analysis_result: Analysis results to report on
            mods_directory: Optional path to mods directory
            
        Returns:
            Markdown formatted report as string
        """
        lines = []
        
        # Header
        lines.append("# Modpack Analysis Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if mods_directory:
            lines.append(f"**Mods Directory:** `{mods_directory}`")
        
        lines.append(f"**Total Mods:** {len(analysis_result.mods)}")
        
        if analysis_result.loader_inferred:
            lines.append(f"**Detected Loader:** {analysis_result.loader_inferred}")
        
        if analysis_result.minecraft_versions_inferred:
            lines.append(f"**Minecraft Versions:** {', '.join(analysis_result.minecraft_versions_inferred)}")
        
        lines.append("")
        
        # Summary
        lines.append("## Summary")
        lines.append("")
        
        # Count issues by severity
        severity_counts = {s: 0 for s in Severity}
        for mod in analysis_result.mods:
            if mod.issues:
                mod_severity = mod.overall_severity
                severity_counts[mod_severity] += 1
            else:
                severity_counts[Severity.OK] += 1
        
        lines.append(f"- ✅ **OK:** {severity_counts[Severity.OK]} mods")
        lines.append(f"- ℹ️ **Info:** {severity_counts[Severity.INFO]} mods")
        lines.append(f"- ⚠️ **Warning:** {severity_counts[Severity.WARNING]} mods")
        lines.append(f"- ❌ **Error:** {severity_counts[Severity.ERROR]} mods")
        lines.append("")
        
        # Critical Issues
        if (len(analysis_result.duplicates) > 0 or 
            len(analysis_result.known_conflicts) > 0 or
            len(analysis_result.missing_dependencies) > 0 or
            analysis_result.mixed_loaders_warning):
            
            lines.append("## Critical Issues")
            lines.append("")
            
            if analysis_result.mixed_loaders_warning:
                lines.append("### ❌ Mixed Mod Loaders")
                lines.append("Multiple mod loaders detected. This will cause crashes.")
                lines.append("")
            
            if analysis_result.duplicates:
                lines.append("### ⚠️ Duplicate Mods")
                for dup in analysis_result.duplicates:
                    lines.append(f"- **{dup['mod_id']}**: {len(dup['mods'])} versions found")
                    for mod in dup['mods']:
                        lines.append(f"  - {mod['name']} v{mod['version']} (`{mod['file']}`)")
                lines.append("")
            
            if analysis_result.known_conflicts:
                lines.append("### ❌ Known Conflicts")
                for conflict in analysis_result.known_conflicts:
                    lines.append(f"- **{conflict['mod_a']}** vs **{conflict['mod_b']}**: {conflict['reason']}")
                lines.append("")
            
            if analysis_result.missing_dependencies:
                lines.append("### ❌ Missing Dependencies")
                for dep in analysis_result.missing_dependencies:
                    mod_name = dep['mod_id']
                    missing_mod = dep['missing_dep']
                    version = dep.get('version', 'any')
                    lines.append(f"- **{mod_name}** requires **{missing_mod}** ({version})")
                lines.append("")
        
        # Mod List
        lines.append("## Mod List")
        lines.append("")
        
        # Group mods by severity for better organization
        mods_by_severity = {s: [] for s in Severity}
        for mod in analysis_result.mods:
            mods_by_severity[mod.overall_severity].append(mod)
        
        # Show errors first, then warnings, then info, then OK
        for severity in [Severity.ERROR, Severity.WARNING, Severity.INFO, Severity.OK]:
            mods_list = mods_by_severity[severity]
            if not mods_list:
                continue
            
            severity_icon = {
                Severity.ERROR: "❌",
                Severity.WARNING: "⚠️", 
                Severity.INFO: "ℹ️",
                Severity.OK: "✅"
            }[severity]
            
            lines.append(f"### {severity_icon} {severity.value.title()} ({len(mods_list)} mods)")
            lines.append("")
            
            for mod in sorted(mods_list, key=lambda m: m.name or m.file_name):
                self._add_mod_to_report(mod, lines)
        
        # Hardware Recommendations (if available)
        if analysis_result.recommendations:
            lines.append("## Hardware & Performance")
            lines.append("")
            
            jvm_args = analysis_result.recommendations.get("recommended_jvm_args")
            if jvm_args:
                lines.append("### Recommended JVM Arguments")
                lines.append("```")
                lines.append(jvm_args)
                lines.append("```")
                lines.append("")
            
            ram_gb = analysis_result.recommendations.get("recommended_ram_gb")
            if ram_gb:
                lines.append(f"**Recommended RAM Allocation:** {ram_gb} GB")
                lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Generated by Modpack Doctor*")
        
        return "\n".join(lines)
    
    def _add_mod_to_report(self, mod: ModInfo, lines: List[str]):
        """Add a single mod's information to the report."""
        mod_name = mod.name or mod.file_name
        lines.append(f"#### {mod_name}")
        lines.append("")
        
        # Basic info
        info_lines = []
        if mod.version:
            info_lines.append(f"**Version:** {mod.version}")
        if mod.loader:
            info_lines.append(f"**Loader:** {mod.loader}")
        if mod.modid:
            info_lines.append(f"**Mod ID:** `{mod.modid}`")
        if mod.authors:
            info_lines.append(f"**Authors:** {', '.join(mod.authors)}")
        
        if info_lines:
            lines.extend(info_lines)
            lines.append("")
        
        # Description
        if mod.description:
            lines.append(f"**Description:** {mod.description}")
            lines.append("")
        
        # Issues
        if mod.issues:
            lines.append("**Issues:**")
            for issue in mod.issues:
                severity_icon = {
                    Severity.ERROR: "❌",
                    Severity.WARNING: "⚠️",
                    Severity.INFO: "ℹ️",
                    Severity.OK: "✅"
                }[issue.severity]
                
                lines.append(f"- {severity_icon} {issue.message}")
                if issue.suggestion:
                    lines.append(f"  - *Suggestion: {issue.suggestion}*")
            lines.append("")
        
        # Homepage link
        if mod.homepage or mod.project_url:
            url = mod.project_url or mod.homepage
            lines.append(f"**Homepage:** [{url}]({url})")
            lines.append("")
        
        lines.append("")
    
    def export_to_file(self, 
                      analysis_result: AnalysisResult, 
                      output_path: Path,
                      mods_directory: Optional[Path] = None) -> bool:
        """
        Export analysis results to a Markdown file.
        
        Args:
            analysis_result: Analysis results to export
            output_path: Path where to save the report
            mods_directory: Optional path to mods directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            report_content = self.generate_markdown_report(analysis_result, mods_directory)
            
            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write report
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return True
            
        except Exception:
            return False


def generate_markdown_report(analysis_result: AnalysisResult, 
                           mods_directory: Optional[Path] = None) -> str:
    """
    Convenience function to generate a Markdown report.
    
    Args:
        analysis_result: Analysis results to report on
        mods_directory: Optional path to mods directory
        
    Returns:
        Markdown formatted report as string
    """
    generator = ReportGenerator()
    return generator.generate_markdown_report(analysis_result, mods_directory)


def export_analysis_report(analysis_result: AnalysisResult, 
                          output_path: Path,
                          mods_directory: Optional[Path] = None) -> bool:
    """
    Convenience function to export analysis results to a file.
    
    Args:
        analysis_result: Analysis results to export
        output_path: Path where to save the report
        mods_directory: Optional path to mods directory
        
    Returns:
        True if successful, False otherwise
    """
    generator = ReportGenerator()
    return generator.export_to_file(analysis_result, output_path, mods_directory)