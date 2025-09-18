"""Plugin registry for dynamic loading of analysis rules."""

import importlib
import pkgutil
from typing import List
from pathlib import Path

from ..core.model import ModInfo, Issue


def get_plugin_issues(mods: List[ModInfo]) -> List[Issue]:
    """
    Run all registered plugins and collect issues.
    
    Args:
        mods: List of ModInfo objects to analyze
        
    Returns:
        List of issues found by plugins
    """
    issues = []
    
    # Import and run plugins
    try:
        import moddoctor.plugins.rules
        
        # Dynamically load all modules in the rules package
        package_path = Path(moddoctor.plugins.rules.__file__).parent
        
        for importer, modname, ispkg in pkgutil.iter_modules([str(package_path)]):
            if not ispkg:  # Only load modules, not packages
                try:
                    full_module_name = f"moddoctor.plugins.rules.{modname}"
                    module = importlib.import_module(full_module_name)
                    
                    # Look for evaluate function
                    if hasattr(module, 'evaluate'):
                        plugin_issues = module.evaluate(mods)
                        if isinstance(plugin_issues, list):
                            issues.extend(plugin_issues)
                            
                except Exception as e:
                    # Skip failed plugins silently
                    pass
                    
    except Exception:
        # No plugins available or failed to import
        pass
    
    return issues