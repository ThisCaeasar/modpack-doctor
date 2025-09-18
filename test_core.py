#!/usr/bin/env python3
"""
Test script for the new modular architecture without GUI.
"""

import os
import sys
from pathlib import Path
import tempfile

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_core_functionality():
    """Test the core functionality without GUI."""
    print("Testing Modpack Doctor Core Functionality")
    print("=" * 50)
    
    # Test imports
    print("1. Testing imports...")
    try:
        from moddoctor.core.model import ModInfo, Severity, Issue, AnalysisResult
        from moddoctor.core.scan import scan_mods_folder, calculate_sha256
        from moddoctor.core.analyzer import ModAnalyzer
        from moddoctor.core.metadata import extract_mod_info
        from moddoctor.core.hardware import get_hardware_info
        from moddoctor.core.report import generate_markdown_report
        from moddoctor.util.cache import CacheManager
        from moddoctor.settings import Settings
        print("   ✓ All core modules imported successfully")
    except Exception as e:
        print(f"   ✗ Import failed: {e}")
        return False
    
    # Test model
    print("2. Testing data model...")
    try:
        mod = ModInfo("test.jar", "/path/test.jar")
        mod.name = "Test Mod"
        mod.version = "1.0.0"
        mod.loader = "fabric"
        mod.issues.append(Issue(Severity.WARNING, "Test warning", "Test suggestion"))
        
        assert mod.overall_severity == Severity.WARNING
        print("   ✓ Data model works correctly")
    except Exception as e:
        print(f"   ✗ Model test failed: {e}")
        return False
    
    # Test settings
    print("3. Testing settings...")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            settings = Settings(Path(temp_dir) / "test_config.json")
            settings.set_last_mods_dir("/test/path")
            settings.set_online_enabled(False)
            
            assert settings.get_last_mods_dir() == "/test/path"
            assert not settings.is_online_enabled()
        print("   ✓ Settings management works")
    except Exception as e:
        print(f"   ✗ Settings test failed: {e}")
        return False
    
    # Test cache
    print("4. Testing cache...")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = CacheManager(Path(temp_dir))
            
            # Test mod metadata caching
            mod = ModInfo("test.jar", "/path/test.jar")
            mod.name = "Cache Test Mod"
            
            cache.store_mod_metadata("test_hash", mod)
            retrieved = cache.get_mod_metadata("test_hash")
            
            assert retrieved is not None
            assert retrieved.name == "Cache Test Mod"
        print("   ✓ Cache system works")
    except Exception as e:
        print(f"   ✗ Cache test failed: {e}")
        return False
    
    # Test analyzer
    print("5. Testing analyzer...")
    try:
        analyzer = ModAnalyzer()
        
        # Create test mods with duplicate
        mod1 = ModInfo("mod1.jar", "/path/mod1.jar")
        mod1.modid = "testmod"
        mod1.name = "Test Mod"
        mod1.version = "1.0.0"
        
        mod2 = ModInfo("mod2.jar", "/path/mod2.jar")
        mod2.modid = "testmod"  # Same ID = duplicate
        mod2.name = "Test Mod"
        mod2.version = "2.0.0"
        
        result = analyzer.analyze_mods([mod1, mod2])
        
        assert len(result.duplicates) > 0
        assert len(mod1.issues) > 0 or len(mod2.issues) > 0
        print("   ✓ Analyzer detects issues correctly")
    except Exception as e:
        print(f"   ✗ Analyzer test failed: {e}")
        return False
    
    # Test hardware detection
    print("6. Testing hardware detection...")
    try:
        hardware = get_hardware_info()
        summary = hardware.get_hardware_summary()
        jvm_args = hardware.generate_jvm_arguments(4.0)
        
        assert "System:" in summary
        assert "-Xmx" in jvm_args
        print(f"   ✓ Hardware detected: {hardware.memory_info['total_gb']:.1f} GB RAM")
    except Exception as e:
        print(f"   ✗ Hardware test failed: {e}")
        return False
    
    # Test report generation
    print("7. Testing report generation...")
    try:
        # Create a simple analysis result
        mod = ModInfo("test.jar", "/path/test.jar")
        mod.name = "Report Test Mod"
        mod.issues.append(Issue(Severity.INFO, "Test issue"))
        
        result = AnalysisResult(
            loader_inferred="fabric",
            minecraft_versions_inferred=["1.20.1"],
            mods=[mod],
            missing_dependencies=[],
            version_mismatches=[],
            duplicates=[],
            explicit_conflicts=[],
            known_conflicts=[],
            potential_conflicts=[],
            mixed_loaders_warning=False,
            recommendations={}
        )
        
        report = generate_markdown_report(result)
        
        assert "# Modpack Analysis Report" in report
        assert "Report Test Mod" in report
        print("   ✓ Report generation works")
    except Exception as e:
        print(f"   ✗ Report test failed: {e}")
        return False
    
    print("\n" + "=" * 50)
    print("✅ All core functionality tests passed!")
    print("\nThe modular architecture is ready for the GUI.")
    return True

if __name__ == "__main__":
    success = test_core_functionality()
    sys.exit(0 if success else 1)