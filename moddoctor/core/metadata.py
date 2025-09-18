"""Mod metadata extraction from JAR files."""

import contextlib
import json
import re
import zipfile
from pathlib import Path
from typing import Optional, Dict, Tuple, List

from .model import ModInfo, Dependency

# Optional dependencies for TOML parsing
try:
    import tomllib  # Python 3.11+
except ImportError:
    tomllib = None

try:
    import tomli  # fallback for <3.11
except ImportError:
    tomli = None


def read_json_bytes(b: bytes) -> Optional[dict]:
    """Parse JSON from bytes."""
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        with contextlib.suppress(Exception):
            return json.loads(b.decode("utf-8", errors="ignore"))
    return None


def load_toml_bytes(b: bytes) -> Optional[dict]:
    """Parse TOML from bytes."""
    if tomllib:
        try:
            return tomllib.loads(b.decode("utf-8", errors="ignore"))
        except Exception:
            return None
    if tomli:
        try:
            return tomli.loads(b.decode("utf-8", errors="ignore"))
        except Exception:
            return None
    return None


def extract_mod_info(jar_path: Path) -> Optional[ModInfo]:
    """
    Extract mod information from a JAR file.
    
    Args:
        jar_path: Path to the JAR file
        
    Returns:
        ModInfo object if successful, None otherwise
    """
    mod_info = ModInfo(file_name=jar_path.name, path=str(jar_path))
    
    try:
        with zipfile.ZipFile(jar_path, "r") as z:
            # Try Fabric mod.json
            with contextlib.suppress(Exception):
                with z.open("fabric.mod.json") as f:
                    data = read_json_bytes(f.read())
                    if isinstance(data, dict):
                        parse_fabric_mod_json(data, mod_info)
                        # Extract icon if specified
                        extract_fabric_icon(data, mod_info, z)
            
            # Try Quilt mod.json  
            with contextlib.suppress(Exception):
                with z.open("quilt.mod.json") as f:
                    data = read_json_bytes(f.read())
                    if isinstance(data, dict):
                        parse_quilt_mod_json(data, mod_info)
                        
            # Try Forge mods.toml
            with contextlib.suppress(Exception):
                with z.open("META-INF/mods.toml") as f:
                    data = load_toml_bytes(f.read())
                    if isinstance(data, dict):
                        parse_forge_mods_toml(data, mod_info)
                        # Extract logo if specified
                        extract_forge_logo(data, mod_info, z)
                        
    except zipfile.BadZipFile:
        return None
    except Exception:
        return None
    
    # Fallback to filename if no mod info found
    if not (mod_info.modid or mod_info.name):
        mod_info.name = jar_path.stem
        
    return mod_info


def parse_fabric_mod_json(data: dict, mod_info: ModInfo):
    """Parse Fabric mod.json metadata."""
    mod_info.loader = mod_info.loader or "fabric"
    mod_info.modid = mod_info.modid or data.get("id")
    mod_info.name = mod_info.name or data.get("name") or data.get("id")
    mod_info.version = mod_info.version or data.get("version")
    mod_info.description = mod_info.description or data.get("description")
    
    # Parse authors
    authors = []
    if "authors" in data and isinstance(data["authors"], list):
        for a in data["authors"]:
            if isinstance(a, str):
                authors.append(a)
            elif isinstance(a, dict) and "name" in a:
                authors.append(a["name"])
    mod_info.authors = mod_info.authors or authors
    
    # Parse environment
    env = data.get("environment")
    if env in ("client", "server", "*"):
        mod_info.environment = {"*": "both"}.get(env, env)
    
    # Parse homepage from contact info
    contact = data.get("contact", {})
    if isinstance(contact, dict):
        mod_info.homepage = mod_info.homepage or contact.get("homepage")
    
    # Parse dependencies
    for key, kind in (("depends", "required"), ("recommends", "recommended"),
                      ("conflicts", "conflicts"), ("breaks", "breaks")):
        deps = data.get(key) or {}
        if isinstance(deps, dict):
            for dep_modid, ver in deps.items():
                dep = Dependency(
                    modid=dep_modid, 
                    version=str(ver) if ver is not None else None, 
                    kind=kind, 
                    source="fabric"
                )
                if kind in ("conflicts", "breaks"):
                    mod_info.conflicts.append(dep)
                elif kind == "recommended":
                    mod_info.recommends.append(dep)
                else:
                    mod_info.depends.append(dep)
    
    # Parse provides
    provides = data.get("provides")
    if isinstance(provides, list):
        mod_info.provides = [str(x) for x in provides if isinstance(x, (str, int))]
    
    # Extract Minecraft version from dependencies
    mc_dep = data.get("depends", {}).get("minecraft")
    if mc_dep:
        mod_info.minecraft_versions.append(str(mc_dep))


def parse_quilt_mod_json(data: dict, mod_info: ModInfo):
    """Parse Quilt mod.json metadata."""
    mod_info.loader = mod_info.loader or "quilt"
    quilt_m = data.get("quilt_loader", {})
    id_ = quilt_m.get("id") or data.get("id")
    mod_info.modid = mod_info.modid or id_
    mod_info.name = mod_info.name or quilt_m.get("metadata", {}).get("name") or data.get("name") or id_
    mod_info.version = mod_info.version or (quilt_m.get("version") or data.get("version"))
    mod_info.description = mod_info.description or quilt_m.get("metadata", {}).get("description") or data.get("description")
    
    # Parse authors/contributors
    authors = []
    authors_data = quilt_m.get("metadata", {}).get("contributors") or []
    for a in authors_data:
        if isinstance(a, dict) and "name" in a:
            authors.append(a["name"])
        elif isinstance(a, str):
            authors.append(a)
    mod_info.authors = mod_info.authors or authors
    
    # Parse dependencies
    deps = quilt_m.get("depends") or []
    for d in deps:
        if isinstance(d, dict):
            mod_info.depends.append(Dependency(
                modid=d.get("id") or "",
                version=d.get("versions") if isinstance(d.get("versions"), str) else None,
                kind="required" if d.get("required", True) else "optional",
                source="quilt"
            ))
    
    # Extract Minecraft version
    for d in deps:
        if isinstance(d, dict) and d.get("id") == "minecraft" and d.get("versions"):
            mod_info.minecraft_versions.append(str(d.get("versions")))


def parse_forge_mods_toml(data: dict, mod_info: ModInfo):
    """Parse Forge mods.toml metadata."""
    mod_info.loader = mod_info.loader or "forge"
    
    # Parse main mod info
    mods = data.get("mods")
    if isinstance(mods, list) and mods:
        first = mods[0]
        mod_info.modid = mod_info.modid or first.get("modId")
        mod_info.name = mod_info.name or first.get("displayName") or first.get("modId")
        mod_info.version = mod_info.version or first.get("version")
        mod_info.description = mod_info.description or first.get("description")
        mod_info.homepage = mod_info.homepage or first.get("displayURL")
        
        # Parse authors
        authors = first.get("authors")
        if isinstance(authors, str) and authors.strip():
            mod_info.authors = mod_info.authors or [authors.strip()]
    
    # Parse dependencies
    deps_root = data.get("dependencies") or {}
    if mod_info.modid and mod_info.modid in deps_root:
        deps = deps_root[mod_info.modid]
        if isinstance(deps, list):
            for d in deps:
                modid = d.get("modId")
                mandatory = d.get("mandatory", False)
                vrange = d.get("versionRange")
                side = d.get("side")
                kind = "required" if mandatory else "optional"
                dep = Dependency(modid=modid, version=vrange, kind=kind, side=side, source="forge")
                mod_info.depends.append(dep)
    
    # Extract Minecraft version from dependencies
    for d in mod_info.depends:
        if (d.modid or "").lower() == "minecraft" and d.version:
            mod_info.minecraft_versions.append(str(d.version))


def extract_fabric_icon(data: dict, mod_info: ModInfo, zip_file: zipfile.ZipFile):
    """Extract icon from Fabric mod metadata."""
    icon = data.get("icon")
    if isinstance(icon, str) and icon:
        try:
            mod_info.icon_path = icon
        except Exception:
            pass
    elif isinstance(icon, dict):
        # Multiple icon sizes - prefer 64x64 or first available
        for size in ["64", "32", "16"]:
            if size in icon:
                try:
                    mod_info.icon_path = icon[size]
                    break
                except Exception:
                    continue


def extract_forge_logo(data: dict, mod_info: ModInfo, zip_file: zipfile.ZipFile):
    """Extract logo from Forge mod metadata."""
    mods = data.get("mods")
    if isinstance(mods, list) and mods:
        logo_file = mods[0].get("logoFile")
        if logo_file:
            try:
                mod_info.icon_path = logo_file
            except Exception:
                pass