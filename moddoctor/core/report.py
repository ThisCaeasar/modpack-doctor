"""Markdown report generation."""

from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict, Counter

from .model import AnalysisResult, ModInfo, Issue, Severity
from .hardware import detect_system_info


def generate_markdown_report(analysis_result: AnalysisResult, 
                           include_system_info: bool = True,
                           include_recommendations: bool = True) -> str:
    """
    Generate a comprehensive Markdown report from analysis results.
    
    Args:
        analysis_result: Results from mod analysis
        include_system_info: Whether to include system information
        include_recommendations: Whether to include performance recommendations
        
    Returns:
        Markdown formatted report as string
    """
    lines = []
    
    # Header
    lines.append("# Modpack Doctor Analysis Report")
    lines.append(f"*Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}*")
    lines.append("")
    
    # Summary
    lines.extend(_generate_summary_section(analysis_result))
    
    # System Information
    if include_system_info:
        lines.extend(_generate_system_info_section())
    
    # Issues by Category
    lines.extend(_generate_issues_section(analysis_result.issues))
    
    # Mod List
    lines.extend(_generate_mod_list_section(analysis_result.mods))
    
    # Recommendations
    if include_recommendations and analysis_result.issues:
        lines.extend(_generate_recommendations_section(analysis_result.issues))
    
    return "\n".join(lines)


def _generate_summary_section(analysis_result: AnalysisResult) -> List[str]:
    """Generate summary section of the report."""
    lines = ["## Summary", ""]
    
    mods = analysis_result.mods
    issues = analysis_result.issues
    
    # Count issues by severity
    issue_counts = Counter(issue.get_severity_enum() for issue in issues)
    
    lines.append(f"- **Total Mods**: {len(mods)}")
    lines.append(f"- **Detected Loader**: {analysis_result.loader_inferred or 'Unknown'}")
    
    if analysis_result.minecraft_versions_inferred:
        mc_versions = ", ".join(analysis_result.minecraft_versions_inferred)
        lines.append(f"- **Minecraft Versions**: {mc_versions}")
    
    lines.append("")
    lines.append("### Issues Found")
    
    if not issues:
        lines.append("✅ No issues detected!")
    else:
        for severity in [Severity.ERROR, Severity.WARNING, Severity.INFO]:
            count = issue_counts.get(severity, 0)
            if count > 0:
                emoji = {"error": "❌", "warning": "⚠️", "info": "ℹ️"}[severity.value]
                lines.append(f"- {emoji} **{severity.value.title()}**: {count}")
    
    lines.append("")
    return lines


def _generate_system_info_section() -> List[str]:
    """Generate system information section."""
    lines = ["## System Information", ""]
    
    try:
        system_info = detect_system_info()
        
        lines.append(f"- **Operating System**: {system_info['os']} {system_info['os_version']}")
        lines.append(f"- **Architecture**: {system_info['architecture']}")
        lines.append(f"- **CPU**: {system_info['cpu_name']} ({system_info['cpu_count']} cores)")
        lines.append(f"- **Total RAM**: {system_info['total_ram_gb']:.1f} GB")
        lines.append(f"- **Available RAM**: {system_info['available_ram_gb']:.1f} GB")
        
    except Exception:
        lines.append("*System information could not be detected*")
    
    lines.append("")
    return lines


def _generate_issues_section(issues: List[Issue]) -> List[str]:
    """Generate issues section grouped by category."""
    lines = ["## Issues by Category", ""]
    
    if not issues:
        lines.append("No issues found.")
        lines.append("")
        return lines
    
    # Group issues by category
    issues_by_category = defaultdict(list)
    for issue in issues:
        issues_by_category[issue.category].append(issue)
    
    # Sort categories by severity (errors first)
    category_priority = {
        "duplicates": 1,
        "known_conflicts": 2,
        "loader_mismatch": 3,
        "missing_dependencies": 4,
        "version_mismatches": 5,
        "mc_version_mismatch": 6,
        "prerelease": 7,
        "performance": 8,
        "general": 9
    }
    
    sorted_categories = sorted(
        issues_by_category.keys(),
        key=lambda cat: (category_priority.get(cat, 999), cat)
    )
    
    for category in sorted_categories:
        category_issues = issues_by_category[category]
        
        # Category header
        category_name = category.replace('_', ' ').title()
        lines.append(f"### {category_name}")
        lines.append("")
        
        # Sort issues by severity within category
        category_issues.sort(key=lambda issue: (
            {"error": 0, "warning": 1, "info": 2}.get(issue.severity, 3),
            issue.mod_file
        ))
        
        for issue in category_issues:
            severity_emoji = {
                "error": "❌",
                "warning": "⚠️", 
                "info": "ℹ️"
            }.get(issue.severity, "•")
            
            lines.append(f"{severity_emoji} **{issue.mod_file}**")
            lines.append(f"   - {issue.message}")
            
            if issue.suggestion:
                lines.append(f"   - *Suggestion*: {issue.suggestion}")
            
            lines.append("")
        
        lines.append("")
    
    return lines


def _generate_mod_list_section(mods: List[ModInfo]) -> List[str]:
    """Generate detailed mod list section."""
    lines = ["## Mod List", ""]
    
    if not mods:
        lines.append("No mods found.")
        lines.append("")
        return lines
    
    # Sort mods alphabetically by display name
    sorted_mods = sorted(mods, key=lambda m: (m.name or m.modid or m.file_name).lower())
    
    lines.append("| Mod Name | Version | Loader | MC Version | File |")
    lines.append("|----------|---------|--------|------------|------|")
    
    for mod in sorted_mods:
        name = mod.name or mod.modid or "Unknown"
        version = mod.version or "Unknown"
        loader = mod.loader or "Unknown"
        mc_versions = ", ".join(mod.minecraft_versions) if mod.minecraft_versions else "Unknown"
        file_name = mod.file_name
        
        lines.append(f"| {name} | {version} | {loader} | {mc_versions} | {file_name} |")
    
    lines.append("")
    return lines


def _generate_recommendations_section(issues: List[Issue]) -> List[str]:
    """Generate recommendations section based on found issues."""
    lines = ["## Recommendations", ""]
    
    # Count issues by severity
    error_count = sum(1 for issue in issues if issue.get_severity_enum() == Severity.ERROR)
    warning_count = sum(1 for issue in issues if issue.get_severity_enum() == Severity.WARNING)
    
    if error_count > 0:
        lines.append("### Priority Actions (Errors)")
        lines.append("The following issues should be addressed immediately:")
        lines.append("")
        
        error_issues = [issue for issue in issues if issue.get_severity_enum() == Severity.ERROR]
        
        for issue in error_issues[:5]:  # Show top 5 errors
            lines.append(f"1. **{issue.mod_file}**: {issue.message}")
            if issue.suggestion:
                lines.append(f"   - {issue.suggestion}")
            lines.append("")
        
        if len(error_issues) > 5:
            lines.append(f"*... and {len(error_issues) - 5} more error(s)*")
            lines.append("")
    
    if warning_count > 0:
        lines.append("### Recommended Actions (Warnings)")
        lines.append("Consider addressing these issues for better stability:")
        lines.append("")
        
        warning_issues = [issue for issue in issues if issue.get_severity_enum() == Severity.WARNING]
        
        for issue in warning_issues[:3]:  # Show top 3 warnings
            lines.append(f"- **{issue.mod_file}**: {issue.message}")
            lines.append("")
    
    # General recommendations
    lines.append("### General Recommendations")
    lines.append("")
    lines.append("- Keep your mods updated to the latest stable versions")
    lines.append("- Backup your world saves before making changes")
    lines.append("- Test your modpack in a creative world first")
    lines.append("- Consider using a mod manager for easier updates")
    lines.append("")
    
    return lines


def export_report_to_file(report_content: str, file_path: str) -> bool:
    """
    Export report content to a file.
    
    Args:
        report_content: Markdown content to export
        file_path: Path where to save the report
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        return True
    except Exception:
        return False