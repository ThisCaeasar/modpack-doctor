"""Mod metadata extraction from jar files."""

import json
import zipfile
import contextlib
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # fallback
    except ImportError:
        tomllib = None

from .model import ModInfo, Dependency, Loader
from ..util.image_utils import load_icon_from_bytes, create_placeholder_icon
from ..util.cache import get_cached_icon_path, set_cached_icon
from ..util.image_utils import icon_to_bytes


def extract_mod_info(jar_file: Path) -> Optional[ModInfo]:
    """
    Extract mod information from a jar file.
    
    Args:
        jar_file: Path to the jar file
        
    Returns:
        ModInfo object or None if extraction fails
    """
    mod_info = ModInfo(
        file_name=jar_file.name,
        path=str(jar_file)
    )
    
    try:
        with zipfile.ZipFile(jar_file, 'r') as zip_file:
            # Try to parse different mod formats
            _parse_fabric_metadata(zip_file, mod_info)
            _parse_quilt_metadata(zip_file, mod_info)
            _parse_forge_metadata(zip_file, mod_info)
            
            # Extract icon
            _extract_icon(zip_file, mod_info)
            
    except zipfile.BadZipFile:
        return None
    except Exception:
        # Return partial info even if parsing fails
        pass
    
    # If no loader was detected, try to infer from dependencies
    if not mod_info.loader:
        mod_info.loader = _infer_loader(mod_info)
    
    return mod_info


def _parse_fabric_metadata(zip_file: zipfile.ZipFile, mod_info: ModInfo) -> None:
    """Parse Fabric mod.json metadata."""
    try:
        with zip_file.open('fabric.mod.json') as f:
            data = json.loads(f.read().decode('utf-8'))
            
        mod_info.loader = "fabric"
        mod_info.modid = data.get('id')
        mod_info.name = data.get('name')
        mod_info.version = data.get('version')
        mod_info.description = data.get('description')
        mod_info.environment = data.get('environment', 'both')
        
        # Authors
        authors = data.get('authors', [])
        if isinstance(authors, list):
            mod_info.authors = [str(author) for author in authors]
        
        # Contact info
        contact = data.get('contact', {})
        if isinstance(contact, dict):
            mod_info.homepage = contact.get('homepage') or contact.get('sources')
            mod_info.project_url = contact.get('homepage')
        
        # Dependencies
        depends = data.get('depends', {})
        recommends = data.get('recommends', {})
        suggests = data.get('suggests', {})
        conflicts = data.get('conflicts', {})
        
        dependencies = []
        
        for modid, version in depends.items():
            dependencies.append(Dependency(
                modid=modid,
                version=version if isinstance(version, str) else None,
                kind="required",
                source="fabric"
            ))
            
        for modid, version in recommends.items():
            dependencies.append(Dependency(
                modid=modid,
                version=version if isinstance(version, str) else None,
                kind="recommended",
                source="fabric"
            ))
            
        for modid, version in suggests.items():
            dependencies.append(Dependency(
                modid=modid,
                version=version if isinstance(version, str) else None,
                kind="optional",
                source="fabric"
            ))
            
        for modid, version in conflicts.items():
            dependencies.append(Dependency(
                modid=modid,
                version=version if isinstance(version, str) else None,
                kind="conflicts",
                source="fabric"
            ))
        
        mod_info.dependencies = dependencies
        
        # Extract Minecraft version from dependencies
        mc_versions = []
        if 'minecraft' in depends:
            mc_dep = depends['minecraft']
            if isinstance(mc_dep, str):
                mc_versions.append(mc_dep)
        mod_info.minecraft_versions = mc_versions
        
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError):
        pass


def _parse_quilt_metadata(zip_file: zipfile.ZipFile, mod_info: ModInfo) -> None:
    """Parse Quilt mod.json metadata."""
    try:
        with zip_file.open('quilt.mod.json') as f:
            data = json.loads(f.read().decode('utf-8'))
            
        # Quilt uses a different structure
        quilt_loader = data.get('quilt_loader', {})
        metadata = quilt_loader.get('metadata', {})
        
        mod_info.loader = "quilt"
        mod_info.modid = quilt_loader.get('id')
        mod_info.name = metadata.get('name')
        mod_info.version = quilt_loader.get('version')
        mod_info.description = metadata.get('description')
        
        # Contact and contributors
        contact = metadata.get('contact', {})
        if isinstance(contact, dict):
            mod_info.homepage = contact.get('homepage') or contact.get('sources')
            mod_info.project_url = contact.get('homepage')
            
        contributors = metadata.get('contributors', {})
        if isinstance(contributors, dict):
            mod_info.authors = list(contributors.keys())
        
        # Dependencies (similar to Fabric)
        depends = quilt_loader.get('depends', [])
        dependencies = []
        
        for dep in depends:
            if isinstance(dep, dict):
                dependencies.append(Dependency(
                    modid=dep.get('id', ''),
                    version=dep.get('version'),
                    kind="required",
                    source="quilt"
                ))
            elif isinstance(dep, str):
                dependencies.append(Dependency(
                    modid=dep,
                    kind="required",
                    source="quilt"
                ))
        
        mod_info.dependencies = dependencies
        
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError):
        pass


def _parse_forge_metadata(zip_file: zipfile.ZipFile, mod_info: ModInfo) -> None:
    """Parse Forge/NeoForge mods.toml metadata."""
    if not tomllib:
        return
        
    try:
        with zip_file.open('META-INF/mods.toml') as f:
            data = tomllib.load(f)
            
        # Forge can have multiple mods in one jar
        mods = data.get('mods', [])
        if not mods:
            return
            
        # Use the first mod entry
        mod_data = mods[0]
        
        mod_info.loader = "forge"  # Will be refined later
        mod_info.modid = mod_data.get('modId')
        mod_info.name = mod_data.get('displayName')
        mod_info.version = mod_data.get('version')
        mod_info.description = mod_data.get('description')
        mod_info.authors = [mod_data.get('authors', '')]
        
        # URLs
        mod_info.homepage = mod_data.get('displayURL')
        
        # Dependencies
        dependencies = []
        dep_list = data.get('dependencies', {}).get(mod_info.modid, [])
        
        for dep in dep_list:
            if isinstance(dep, dict):
                dependencies.append(Dependency(
                    modid=dep.get('modId', ''),
                    version=dep.get('versionRange'),
                    kind=dep.get('mandatory', True) and "required" or "optional",
                    side=dep.get('side'),
                    source="forge"
                ))
        
        mod_info.dependencies = dependencies
        
        # Try to detect NeoForge
        loader_version = data.get('loaderVersion')
        if loader_version and 'neoforge' in str(loader_version).lower():
            mod_info.loader = "neoforge"
        
    except (KeyError, UnicodeDecodeError) as e:
        pass


def _extract_icon(zip_file: zipfile.ZipFile, mod_info: ModInfo) -> None:
    """Extract mod icon from jar file."""
    # Check cache first
    if mod_info.fingerprint_sha256:
        cached_icon_path = get_cached_icon_path(mod_info.fingerprint_sha256)
        if cached_icon_path:
            try:
                with open(cached_icon_path, 'rb') as f:
                    icon_data = f.read()
                mod_info.icon_image = load_icon_from_bytes(icon_data)
                return
            except Exception:
                pass
    
    # Common icon paths to check
    icon_paths = [
        'icon.png',
        'assets/*/icon.png',
        'pack.png',
        'logo.png'
    ]
    
    icon_data = None
    for path_pattern in icon_paths:
        try:
            if '*' in path_pattern:
                # Handle wildcard patterns
                for file_path in zip_file.namelist():
                    if file_path.endswith('icon.png') and 'assets/' in file_path:
                        with zip_file.open(file_path) as f:
                            icon_data = f.read()
                        break
            else:
                with zip_file.open(path_pattern) as f:
                    icon_data = f.read()
            
            if icon_data:
                break
                
        except KeyError:
            continue
        except Exception:
            continue
    
    if icon_data:
        mod_info.icon_image = load_icon_from_bytes(icon_data)
        
        # Cache the icon
        if mod_info.fingerprint_sha256:
            set_cached_icon(mod_info.fingerprint_sha256, icon_data)
    else:
        # Use placeholder icon
        mod_info.icon_image = create_placeholder_icon()


def _infer_loader(mod_info: ModInfo) -> Loader:
    """Infer loader type from dependencies and other clues."""
    if not mod_info.dependencies:
        return "unknown"
    
    loader_hints = {
        'fabric': ['fabricloader', 'fabric-api', 'fabric'],
        'quilt': ['quilt_loader', 'quilted_fabric_api', 'quilt'],
        'forge': ['forge', 'minecraft_forge'],
        'neoforge': ['neoforge', 'neoforged']
    }
    
    dep_modids = {dep.modid.lower() for dep in mod_info.dependencies}
    
    for loader, hints in loader_hints.items():
        for hint in hints:
            if hint in dep_modids:
                return loader
    
    return "unknown"