"""Plugin registry for extensible rule-based analysis."""

import importlib
import os
from pathlib import Path
from typing import List, Protocol

from ..core.model import ModInfo


class AnalysisRule(Protocol):
    """Protocol for analysis rule plugins."""
    
    def apply(self, mods: List[ModInfo]) -> None:
        """Apply the rule to a list of mods, adding issues as needed."""
        ...


class PluginRegistry:
    """Registry for analysis rule plugins."""
    
    def __init__(self):
        """Initialize the plugin registry."""
        self.rules: List[AnalysisRule] = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default rule plugins."""
        try:
            # Import the large file rule
            from ..plugins.rules.large_file import LargeFileRule
            self.rules.append(LargeFileRule())
        except ImportError:
            try:
                from .rules.large_file import LargeFileRule
                self.rules.append(LargeFileRule())
            except ImportError:
                pass
    
    def register_rule(self, rule: AnalysisRule):
        """
        Register a new analysis rule.
        
        Args:
            rule: Rule implementation to register
        """
        self.rules.append(rule)
    
    def apply_rules(self, mods: List[ModInfo]):
        """
        Apply all registered rules to a list of mods.
        
        Args:
            mods: List of ModInfo objects to analyze
        """
        for rule in self.rules:
            try:
                rule.apply(mods)
            except Exception as e:
                # Don't let plugin errors break the analysis
                print(f"Warning: Plugin rule failed: {e}")
                continue
    
    def load_plugins_from_directory(self, plugin_dir: Path):
        """
        Load plugins from a directory.
        
        Args:
            plugin_dir: Directory containing plugin modules
        """
        if not plugin_dir.exists() or not plugin_dir.is_dir():
            return
        
        for file_path in plugin_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue
            
            try:
                # Import the module dynamically
                module_name = file_path.stem
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Look for rule classes that implement AnalysisRule
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        hasattr(attr, 'apply') and 
                        attr_name.endswith('Rule')):
                        try:
                            rule_instance = attr()
                            self.register_rule(rule_instance)
                        except Exception:
                            continue
            except Exception:
                # Skip modules that can't be loaded
                continue