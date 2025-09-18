#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import concurrent.futures
import contextlib
import hashlib
import json
import os
import re
import sys
import time
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Optional dependencies
try:
    import tomllib  # Python 3.11+
except Exception:
    tomllib = None
try:
    import tomli  # fallback for <3.11
except Exception:
    tomli = None

try:
    import psutil  # for RAM detection (optional)
except Exception:
    psutil = None

try:
    import requests  # for Modrinth/CurseForge and remote DBs (optional)
except Exception:
    requests = None


APP_NAME = "Modpack Doctor"
APP_VERSION = "0.3.0"

# ---- Data classes ----

@dataclass
class Dependency:
    modid: str
    version: Optional[str] = None
    kind: str = "required"  # required | recommended | optional | incompatible | breaks | conflicts
    side: Optional[str] = None
    source: Optional[str] = None  # fabric|forge|quilt|modrinth|curseforge|heuristic

@dataclass
class ModInfo:
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
    sha1: Optional[str] = None
    modrinth: Dict[str, Any] = field(default_factory=dict)
    curseforge: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AnalysisResult:
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

# ---- Utils ----

def debug(msg: str):
    # Uncomment for local debug
    # print(f"[DEBUG] {msg}")
    pass

def read_json_bytes(b: bytes) -> Optional[dict]:
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        with contextlib.suppress(Exception):
            return json.loads(b.decode("utf-8", errors="ignore"))
    return None

def load_toml_bytes(b: bytes) -> Optional[dict]:
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

def file_sha1(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def numeric_version_tuple(v: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", v or "")
    if not parts:
        return (0,)
    return tuple(int(x) for x in parts[:4])

def satisfies_forge_range(version: str, range_expr: str) -> Optional[bool]:
    v = numeric_version_tuple(version or "0")
    expr = (range_expr or "").strip()
    if not expr:
        return None
    m_exact = re.fullmatch(r"\[(.+)\]", expr)
    if m_exact:
        target = numeric_version_tuple(m_exact.group(1))
        return v == target
    m = re.fullmatch(r"([\[\(])\s*([^,]*)\s*,\s*([^,\)]*)\s*([\]\)])", expr)
    if not m:
        t = numeric_version_tuple(expr.strip("[]() "))
        return v == t
    left_br, left_val, right_val, right_br = m.groups()
    if left_val:
        lv = numeric_version_tuple(left_val)
        if left_br == "[":
            if v < lv:
                return False
        else:
            if v <= lv:
                return False
    if right_val:
        rv = numeric_version_tuple(right_val)
        if right_br == "]":
            if v > rv:
                return False
        else:
            if v >= rv:
                return False
    return True

def guess_loader_from_counts(counts: Dict[str, int]) -> Optional[str]:
    if not counts:
        return None
    loader = max(counts.items(), key=lambda kv: kv[1])[0]
    if counts[loader] == 0:
        return None
    return loader

def safe_get(d: dict, path: List[str], default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

# ---- Parse mod metadata ----

def parse_fabric_mod_json(data: dict, mi: ModInfo):
    mi.loader = mi.loader or "fabric"
    mi.modid = mi.modid or data.get("id")
    mi.name = mi.name or data.get("name") or data.get("id")
    mi.version = mi.version or data.get("version")
    mi.description = mi.description or data.get("description")
    authors = []
    if "authors" in data and isinstance(data["authors"], list):
        for a in data["authors"]:
            if isinstance(a, str):
                authors.append(a)
            elif isinstance(a, dict) and "name" in a:
                authors.append(a["name"])
    mi.authors = mi.authors or authors
    env = data.get("environment")
    if env in ("client", "server", "*"):
        mi.environment = {"*": "both"}.get(env, env)
    for key, kind in (("depends", "required"), ("recommends", "recommended"),
                      ("conflicts", "conflicts"), ("breaks", "breaks")):
        deps = data.get(key) or {}
        if isinstance(deps, dict):
            for dep_modid, ver in deps.items():
                dep = Dependency(modid=dep_modid, version=str(ver) if ver is not None else None, kind=kind, source="fabric")
                if kind in ("conflicts", "breaks"):
                    mi.conflicts.append(dep)
                elif kind == "recommended":
                    mi.recommends.append(dep)
                else:
                    mi.depends.append(dep)
    provides = data.get("provides")
    if isinstance(provides, list):
        mi.provides = [str(x) for x in provides if isinstance(x, (str, int))]
    mc_dep = data.get("depends", {}).get("minecraft")
    if mc_dep:
        mi.minecraft_versions.append(str(mc_dep))

def parse_quilt_mod_json(data: dict, mi: ModInfo):
    mi.loader = mi.loader or "quilt"
    quilt_m = data.get("quilt_loader", {})
    id_ = quilt_m.get("id") or data.get("id")
    mi.modid = mi.modid or id_
    mi.name = mi.name or quilt_m.get("metadata", {}).get("name") or data.get("name") or id_
    mi.version = mi.version or (quilt_m.get("version") or data.get("version"))
    mi.description = mi.description or quilt_m.get("metadata", {}).get("description") or data.get("description")
    authors = []
    authors_data = quilt_m.get("metadata", {}).get("contributors") or []
    for a in authors_data:
        if isinstance(a, dict) and "name" in a:
            authors.append(a["name"])
        elif isinstance(a, str):
            authors.append(a)
    mi.authors = mi.authors or authors
    deps = quilt_m.get("depends") or []
    for d in deps:
        if isinstance(d, dict):
            mi.depends.append(Dependency(
                modid=d.get("id") or "",
                version=d.get("versions") if isinstance(d.get("versions"), str) else None,
                kind="required" if d.get("required", True) else "optional",
                source="quilt"
            ))
    for d in deps:
        if isinstance(d, dict) and d.get("id") == "minecraft" and d.get("versions"):
            mi.minecraft_versions.append(str(d.get("versions")))

def parse_forge_mods_toml(data: dict, mi: ModInfo):
    mi.loader = mi.loader or "forge"
    mods = data.get("mods")
    if isinstance(mods, list) and mods:
        first = mods[0]
        mi.modid = mi.modid or first.get("modId")
        mi.name = mi.name or first.get("displayName") or first.get("modId")
        mi.version = mi.version or first.get("version")
        mi.description = mi.description or first.get("description")
        authors = first.get("authors")
        if isinstance(authors, str) and authors.strip():
            mi.authors = mi.authors or [authors.strip()]
    deps_root = data.get("dependencies") or {}
    if mi.modid and mi.modid in deps_root:
        deps = deps_root[mi.modid]
        if isinstance(deps, list):
            for d in deps:
                modid = d.get("modId")
                mandatory = d.get("mandatory", False)
                vrange = d.get("versionRange")
                side = d.get("side")
                kind = "required" if mandatory else "optional"
                dep = Dependency(modid=modid, version=vrange, kind=kind, side=side, source="forge")
                mi.depends.append(dep)
    for d in mi.depends:
        if (d.modid or "").lower() == "minecraft" and d.version:
            mi.minecraft_versions.append(str(d.version))

def extract_mod_info_from_jar(jar_path: Path) -> Optional[ModInfo]:
    mi = ModInfo(file_name=jar_path.name, path=str(jar_path))
    try:
        with zipfile.ZipFile(jar_path, "r") as z:
            with contextlib.suppress(Exception):
                with z.open("fabric.mod.json") as f:
                    data = read_json_bytes(f.read())
                    if isinstance(data, dict):
                        parse_fabric_mod_json(data, mi)
            with contextlib.suppress(Exception):
                with z.open("quilt.mod.json") as f:
                    data = read_json_bytes(f.read())
                    if isinstance(data, dict):
                        parse_quilt_mod_json(data, mi)
            with contextlib.suppress(Exception):
                with z.open("META-INF/mods.toml") as f:
                    data = load_toml_bytes(f.read())
                    if isinstance(data, dict):
                        parse_forge_mods_toml(data, mi)
    except zipfile.BadZipFile:
        debug(f"Bad zip file: {jar_path}")
        return None
    except Exception as e:
        debug(f"Error reading {jar_path}: {e}")
        return None
    if not (mi.modid or mi.name):
        mi.name = mi.name or jar_path.stem
    return mi

# ---- Modrinth enrichment ----

def modrinth_enrich(mi: ModInfo, timeout: float = 10.0):
    if not requests or not mi.sha1:
        return
    try:
        url = f"https://api.modrinth.com/v2/version_file/{mi.sha1}?algorithm=sha1"
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            vdata = r.json()
            project_id = vdata.get("project_id")
            mi.modrinth["version"] = vdata
            if project_id:
                pr = requests.get(f"https://api.modrinth.com/v2/project/{project_id}", timeout=timeout)
                if pr.status_code == 200:
                    pdata = pr.json()
                    mi.modrinth["project"] = pdata
                    if not mi.name:
                        mi.name = pdata.get("title") or mi.name
                    if not mi.description:
                        mi.description = pdata.get("description") or mi.description
                    deps = vdata.get("dependencies") or []
                    for d in deps:
                        dep_type = d.get("dependency_type")
                        kind_map = {"required": "required", "optional": "optional", "incompatible": "conflicts"}
                        kind = kind_map.get(dep_type, "required")
                        mi.depends.append(Dependency(
                            modid=str(d.get("project_id") or d.get("file_name") or "unknown"),
                            version=None,
                            kind=kind,
                            source="modrinth"
                        ))
    except Exception:
        pass

# ---- CurseForge enrichment ----

CF_GAME_ID_MINECRAFT = 432

class CurseForgeClient:
    def __init__(self, api_key: str, cache_path: Optional[Path] = None):
        self.api_key = api_key
        self.base = "https://api.curseforge.com/v1"
        self.timeout = 12.0
        self.cache_path = cache_path
        self.cache: Dict[str, Any] = {}
        if cache_path:
            with contextlib.suppress(Exception):
                if cache_path.exists():
                    self.cache = json.loads(cache_path.read_text(encoding="utf-8"))

    def _headers(self):
        return {"x-api-key": self.api_key}

    def _cache_get(self, key: str):
        return self.cache.get(key)

    def _cache_set(self, key: str, value: Any):
        self.cache[key] = value
        if self.cache_path:
            with contextlib.suppress(Exception):
                self.cache_path.write_text(json.dumps(self.cache, ensure_ascii=False, indent=2), encoding="utf-8")

    def search_mod(self, query: str) -> Optional[dict]:
        if not requests or not query:
            return None
        qkey = f"search:{query.lower()}"
        cached = self._cache_get(qkey)
        if cached is not None:
            return cached
        params = {"gameId": CF_GAME_ID_MINECRAFT, "searchFilter": query, "pageSize": 20, "sortField": 2}
        try:
            r = requests.get(f"{self.base}/mods/search", headers=self._headers(), params=params, timeout=self.timeout)
            if r.status_code == 200:
                data = r.json().get("data") or []
                best = None
                ql = query.lower()
                for m in data:
                    name = (m.get("name") or "").lower()
                    slug = (m.get("slug") or "").lower()
                    if ql == slug or ql == name:
                        best = m
                        break
                if not best and data:
                    best = data[0]
                self._cache_set(qkey, best)
                return best
        except Exception:
            return None
        return None

    def get_mod(self, mod_id: int) -> Optional[dict]:
        if not requests:
            return None
        ckey = f"mod:{mod_id}"
        cached = self._cache_get(ckey)
        if cached is not None:
            return cached
        try:
            r = requests.get(f"{self.base}/mods/{mod_id}", headers=self._headers(), timeout=self.timeout)
            if r.status_code == 200:
                data = r.json().get("data")
                self._cache_set(ckey, data)
                return data
        except Exception:
            return None
        return None

    def get_files(self, mod_id: int) -> List[dict]:
        if not requests:
            return []
        ckey = f"files:{mod_id}"
        cached = self._cache_get(ckey)
        if cached is not None:
            return cached
        try:
            r = requests.get(f"{self.base}/mods/{mod_id}/files", headers=self._headers(), timeout=self.timeout, params={"pageSize": 50})
            if r.status_code == 200:
                data = r.json().get("data") or []
                self._cache_set(ckey, data)
                return data
        except Exception:
            return []
        return []

    @staticmethod
    def _cf_to_kind(rel_type: int) -> str:
        # 1: EmbeddedLibrary, 2: OptionalDependency, 3: RequiredDependency,
        # 4: Tool, 5: Incompatible, 6: Include
        return {3: "required", 2: "optional", 5: "conflicts"}.get(rel_type, "optional")

def curseforge_enrich(mi: ModInfo, cf: CurseForgeClient, target_loader: Optional[str], target_mc: Optional[str]):
    query = (mi.name or mi.modid or "").strip()
    if not query:
        return
    mod = cf.search_mod(query)
    if not mod:
        return
    mi.curseforge["mod"] = {"id": mod.get("id"), "name": mod.get("name"), "slug": mod.get("slug"), "links": mod.get("links")}
    files = cf.get_files(mod.get("id"))
    mi.curseforge["files_count"] = len(files)

    chosen = None
    tl = (target_loader or (mi.loader or "")).lower()
    tmc = (target_mc or "").lower()

    def supports(f: dict) -> int:
        score = 0
        gameVersions = [str(v).lower() for v in (f.get("gameVersions") or [])]
        if tl:
            if tl in ("fabric", "quilt"):
                if "fabric" in gameVersions or "quilt" in gameVersions:
                    score += 3
            if tl in ("forge", "neoforge"):
                if "forge" in gameVersions or "neoforge" in gameVersions:
                    score += 3
        if tmc:
            if any(tmc in gv for gv in gameVersions):
                score += 2
        release_type = f.get("releaseType")  # 1=release, 2=beta, 3=alpha
        if release_type == 1:
            score += 2
        return score

    for f in files:
        if chosen is None or supports(f) > supports(chosen):
            chosen = f

    if chosen:
        mi.curseforge["file"] = {
            "id": chosen.get("id"),
            "fileName": chosen.get("fileName"),
            "downloadUrl": chosen.get("downloadUrl"),
            "gameVersions": chosen.get("gameVersions"),
            "releaseType": chosen.get("releaseType")
        }
        for d in (chosen.get("dependencies") or []):
            dep_mod_id = d.get("modId")
            rel_type = d.get("relationType")
            kind = CurseForgeClient._cf_to_kind(rel_type)
            dep = Dependency(modid=str(dep_mod_id), version=None, kind=kind, source="curseforge")
            if kind == "conflicts":
                mi.conflicts.append(dep)
            elif kind == "optional":
                mi.recommends.append(dep)
            else:
                mi.depends.append(dep)

# ---- Knowledge base: local + remote auto-update ----

def validate_conflicts_db(db: dict) -> bool:
    return isinstance(db, dict) and isinstance(db.get("pairs"), list)

def validate_perf_db(db: dict) -> bool:
    return isinstance(db, dict) and all(k in db for k in ("fabric", "forge", "quilt"))

def load_local_db(base_dir: Path) -> Tuple[dict, dict]:
    known_conflicts = {}
    perf_mods = {}
    with contextlib.suppress(Exception):
        known_conflicts = json.loads((base_dir / "data" / "known_conflicts.json").read_text(encoding="utf-8"))
    with contextlib.suppress(Exception):
        perf_mods = json.loads((base_dir / "data" / "performance_mods.json").read_text(encoding="utf-8"))
    return known_conflicts, perf_mods

def merge_conflicts(base: dict, overlay: dict) -> dict:
    if not validate_conflicts_db(base):
        base = {"pairs": []}
    result = {"pairs": list(base.get("pairs", []))}
    if validate_conflicts_db(overlay):
        result["pairs"].extend(overlay.get("pairs", []))
    return result

def merge_perf_db(base: dict, overlay: dict) -> dict:
    if not validate_perf_db(base):
        base = {"fabric": [], "forge": [], "quilt": []}
    result = {k: list(base.get(k, [])) for k in ("fabric", "forge", "quilt")}
    if validate_perf_db(overlay):
        for k in ("fabric", "forge", "quilt"):
            result[k].extend(overlay.get(k, []))
    return result

def parse_ttl(ttl: str) -> int:
    # returns seconds
    ttl = (ttl or "").strip().lower()
    if ttl.endswith("d"):
        return int(ttl[:-1]) * 86400
    if ttl.endswith("h"):
        return int(ttl[:-1]) * 3600
    if ttl.endswith("m"):
        return int(ttl[:-1]) * 60
    with contextlib.suppress(Exception):
        return int(ttl)
    return 604800  # default 7d

def fetch_json(url: str, timeout: float = 12.0) -> Optional[dict]:
    if not requests:
        return None
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

def load_knowledge_base(base_dir: Path, out_dir: Path, args) -> Tuple[dict, dict, Dict[str, Any]]:
    # Start with local
    local_conf, local_perf = load_local_db(base_dir)

    # Local overrides
    local_overrides_path = base_dir / "data" / "local_conflicts.json"

    # Remote settings
    if getattr(args, "no_db_update", False):
        kb_info = {"channel": "local-only", "updated": False}
        # Apply overrides if exist
        if local_overrides_path.exists():
            with contextlib.suppress(Exception):
                local_conf = merge_conflicts(local_conf, json.loads(local_overrides_path.read_text(encoding="utf-8")))
        return local_conf, local_perf, kb_info

    ttl_seconds = parse_ttl(getattr(args, "db_ttl", "7d"))
    db_meta_path = out_dir / "db_cache_meta.json"
    now = int(time.time())
    meta = {}
    with contextlib.suppress(Exception):
        if db_meta_path.exists():
            meta = json.loads(db_meta_path.read_text(encoding="utf-8"))

    need_update = (getattr(args, "db_update", None) == "now") or (now - int(meta.get("last_check_ts", 0)) > ttl_seconds)

    remote_conf = {}
    remote_perf = {}
    updated = False
    channel = getattr(args, "db_channel", "main") or "main"
    if channel not in ("main", "release"):
        channel = "main"

    default_urls = []
    # For main channel, fetch from this repo's raw main branch
    default_urls.append(("conflicts", "https://raw.githubusercontent.com/ThisCaeasar/modpack-doctor/main/data/known_conflicts.json"))
    default_urls.append(("perf", "https://raw.githubusercontent.com/ThisCaeasar/modpack-doctor/main/data/performance_mods.json"))

    custom_urls = getattr(args, "db_url", None) or []  # list of extra URLs, if any

    if need_update and requests:
        for kind, url in default_urls:
            data = fetch_json(url)
            if kind == "conflicts" and validate_conflicts_db(data or {}):
                remote_conf = data
                updated = True
            if kind == "perf" and validate_perf_db(data or {}):
                remote_perf = data
                updated = True
        for url in custom_urls:
            data = fetch_json(url)
            # try to merge into the right DB based on keys
            if validate_conflicts_db(data or {}):
                remote_conf = merge_conflicts(remote_conf or {"pairs": []}, data)
                updated = True
            elif validate_perf_db(data or {}):
                remote_perf = merge_perf_db(remote_perf or {"fabric": [], "forge": [], "quilt": []}, data)
                updated = True
        meta["last_check_ts"] = now
        with contextlib.suppress(Exception):
            db_meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    # Apply remote overlays
    if remote_conf:
        local_conf = merge_conflicts(local_conf, remote_conf)
    if remote_perf:
        local_perf = merge_perf_db(local_perf, remote_perf)

    # Apply local overrides last
    if local_overrides_path.exists():
        with contextlib.suppress(Exception):
            local_conf = merge_conflicts(local_conf, json.loads(local_overrides_path.read_text(encoding="utf-8")))

    kb_info = {
        "channel": channel,
        "updated": bool(updated),
        "last_check_ts": meta.get("last_check_ts"),
        "ttl_sec": ttl_seconds,
        "sources": [u for _, u in default_urls] + custom_urls
    }
    return local_conf, local_perf, kb_info

# ---- Analysis ----

def analyze_mods(mods: List[ModInfo], known_conflicts: dict) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], bool]:
    missing_dependencies = []
    version_mismatches = []
    duplicates = []
    explicit_conflicts = []

    by_modid: Dict[str, List[ModInfo]] = {}
    for m in mods:
        key = (m.modid or m.name or m.file_name).lower()
        by_modid.setdefault(key, []).append(m)

    for key, lst in by_modid.items():
        if len(lst) > 1:
            versions = list({(m.version or "unknown") for m in lst})
            if len(versions) > 1:
                duplicates.append({
                    "modid": key,
                    "files": [m.file_name for m in lst],
                    "versions": versions,
                    "reason": "Multiple versions of the same mod present"
                })

    installed_ids = set(by_modid.keys())

    for m in mods:
        for d in m.depends:
            if d.kind != "required":
                continue
            dep_key = (d.modid or "").lower()
            if not dep_key:
                continue
            if dep_key not in installed_ids:
                missing_dependencies.append({
                    "mod": m.modid or m.name or m.file_name,
                    "requires": d.modid,
                    "version": d.version,
                    "side": d.side,
                    "source": d.source
                })

        for c in m.conflicts:
            ckey = (c.modid or "").lower()
            if ckey and ckey in installed_ids:
                explicit_conflicts.append({
                    "mod": m.modid or m.name or m.file_name,
                    "conflicts_with": c.modid,
                    "type": c.kind,
                    "source": c.source
                })

    loader_counts = {"fabric": 0, "forge": 0, "quilt": 0, "unknown": 0}
    for m in mods:
        loader_counts[m.loader or "unknown"] = loader_counts.get(m.loader or "unknown", 0) + 1
    nonzero_loaders = [k for k, v in loader_counts.items() if v > 0 and k in ("fabric", "forge", "quilt")]
    mixed = len(nonzero_loaders) > 1

    return missing_dependencies, [], duplicates, mixed

def infer_loader_and_mc_versions(mods: List[ModInfo]) -> Tuple[Optional[str], List[str]]:
    counts = {"fabric": 0, "forge": 0, "quilt": 0}
    mc_versions = []
    for m in mods:
        if m.loader in counts:
            counts[m.loader] += 1
        for v in m.minecraft_versions:
            if v and v not in mc_versions:
                mc_versions.append(v)
    loader = guess_loader_from_counts(counts)
    return loader, mc_versions

def detect_known_and_potential_conflicts(mods: List[ModInfo], known_conflicts: dict) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    ids_map: Dict[str, ModInfo] = {}
    for m in mods:
        key = (m.modid or m.name or m.file_name).lower()
        ids_map[key] = m

    known_hits = []
    for conflict in known_conflicts.get("pairs", []):
        a = conflict.get("a", "").lower()
        b = conflict.get("b", "").lower()
        loaders = set([x.lower() for x in conflict.get("when", {}).get("loader", [])]) if conflict.get("when") else set()
        if a in ids_map and b in ids_map:
            if loaders:
                loaders_present = set((m.loader or "unknown").lower() for m in (ids_map[a], ids_map[b]))
                if loaders.isdisjoint(loaders_present):
                    continue
            known_hits.append({"a": a, "b": b, "reason": conflict.get("reason", "Known conflict")})

    potentials = []
    present = lambda s: any(s in (m.modid or "").lower() or s in (m.name or "").lower() for m in mods)

    if present("sodium") and present("optifine"):
        potentials.append({"a": "sodium", "b": "optifine", "reason": "Sodium and OptiFine are incompatible"})
    if present("sodium") and (present("rubidium") or present("embeddium") or present("magnesium")):
        potentials.append({"a": "sodium", "b": "rubidium/embeddium", "reason": "Duplicate optimization mods across loaders"})
    if present("starlight") and present("phosphor"):
        potentials.append({"a": "starlight", "b": "phosphor", "reason": "Both modify lighting engine; use only one"})
    if present("iris") and present("optifine"):
        potentials.append({"a": "iris", "b": "optifine", "reason": "Iris/Sodium vs OptiFine cause conflicts"})
    if present("oculus") and present("optifine"):
        potentials.append({"a": "oculus", "b": "optifine", "reason": "Oculus (Forge shaders) vs OptiFine conflict"})
    if present("optifabric") and (present("sodium") or present("iris")):
        potentials.append({"a": "optifabric", "b": "sodium/iris", "reason": "OptiFabric conflicts with Sodium/Iris"})

    return known_hits, potentials

def recommend_optimizations(mods: List[ModInfo], perf_db: dict, total_ram_gb: Optional[float], user_ram_gb: Optional[float]) -> Dict[str, Any]:
    installed = set((m.modid or m.name or m.file_name).lower() for m in mods)
    loader_counts = {"fabric": 0, "forge": 0, "quilt": 0}
    for m in mods:
        loader_counts[m.loader or "unknown"] = loader_counts.get(m.loader or "unknown", 0) + 1
    loader = guess_loader_from_counts({k: loader_counts.get(k, 0) for k in ("fabric", "forge", "quilt")})

    suggestions = []
    if loader and perf_db.get(loader):
        for mod in perf_db[loader]:
            keys = [mod.get("modid_hint", "").lower(), mod.get("name_hint", "").lower()]
            if not any(k and any(k in x for x in installed) for k in keys if k):
                suggestions.append(mod)

    detected_ram_gb = None
    if total_ram_gb:
        detected_ram_gb = total_ram_gb
    elif psutil:
        try:
            detected_ram_gb = round(psutil.virtual_memory().total / (1024**3), 1)
        except Exception:
            detected_ram_gb = None

    alloc_gb = user_ram_gb
    if not alloc_gb:
        if detected_ram_gb:
            if detected_ram_gb <= 6:
                alloc_gb = max(2.0, min(3.0, detected_ram_gb * 0.5))
            elif detected_ram_gb <= 12:
                alloc_gb = min(6.0, detected_ram_gb * 0.6)
            else:
                alloc_gb = min(8.0, detected_ram_gb * 0.5)
            alloc_gb = round(alloc_gb, 1)
        else:
            alloc_gb = 4.0

    jvm_args = generate_jvm_args(alloc_gb)

    return {
        "loader": loader,
        "detected_total_ram_gb": detected_ram_gb,
        "recommended_ram_gb": alloc_gb,
        "recommended_jvm_args": jvm_args,
        "suggested_performance_mods": suggestions
    }

def generate_jvm_args(xmx_gb: float) -> str:
    xmx = f"{int(xmx_gb)}G" if abs(xmx_gb - int(xmx_gb)) < 0.1 else f"{xmx_gb}G"
    lines = [
        f"-Xms{xmx}",
        f"-Xmx{xmx}",
        "-XX:+UseG1GC",
        "-XX:+ParallelRefProcEnabled",
        "-XX:MaxGCPauseMillis=100",
        "-XX:+UnlockExperimentalVMOptions",
        "-XX:+AlwaysPreTouch",
        "-XX:G1NewSizePercent=20",
        "-XX:G1MaxNewSizePercent=60",
        "-XX:G1HeapRegionSize=16M",
        "-XX:G1ReservePercent=20",
        "-XX:G1HeapWastePercent=5",
        "-XX:InitiatingHeapOccupancyPercent=15",
        "-XX:G1MixedGCLiveThresholdPercent=90",
        "-XX:G1RSetUpdatingPauseTimePercent=5",
        "-XX:SurvivorRatio=32",
        "-XX:+PerfDisableSharedMem",
        "-XX:MaxTenuringThreshold=1",
        "-Dsun.rmi.dgc.server.gcInterval=2147483646",
        "-Dsun.rmi.dgc.client.gcInterval=2147483646",
        "-Dfile.encoding=UTF-8"
    ]
    return " ".join(lines)

# ---- Reporting ----

def build_markdown_report(ar: AnalysisResult) -> str:
    lines = []
    lines.append(f"# {APP_NAME} Report")
    lines.append("")
    lines.append(f"- Loader (inferred): {ar.loader_inferred or 'unknown'}")
    lines.append(f"- Minecraft versions (found in manifests): {', '.join(ar.minecraft_versions_inferred) or 'unknown'}")
    lines.append(f"- Mixed loaders detected: {'YES' if ar.mixed_loaders_warning else 'no'}")
    lines.append("")
    lines.append("## Mods")
    for m in sorted(ar.mods, key=lambda x: (x.modid or x.name or x.file_name).lower()):
        lines.append(f"- {m.name or m.file_name} [{m.modid or 'unknown'}] v{m.version or 'unknown'} ({m.loader or 'unknown'})")
        if m.description:
            desc = " ".join(str(m.description).split())
            lines.append(f"  - {desc[:200] + ('…' if len(desc)>200 else '')}")
        if m.authors:
            lines.append(f"  - Authors: {', '.join(m.authors)}")
        if m.environment:
            lines.append(f"  - Env: {m.environment}")
        if m.depends:
            reqs = [f"{d.modid}{' ' + d.version if d.version else ''}" for d in m.depends if d.kind=='required']
            if reqs:
                lines.append(f"  - Requires: {', '.join(reqs)}")
        if m.recommends:
            recs = [d.modid for d in m.recommends]
            if recs:
                lines.append(f"  - Recommends: {', '.join(recs)}")
        if m.conflicts:
            confs = [d.modid for d in m.conflicts]
            if confs:
                lines.append(f"  - Declared conflicts: {', '.join(confs)}")
        if m.modrinth.get("project"):
            lines.append(f"  - Modrinth: {m.modrinth['project'].get('title','')} ({m.modrinth['project'].get('slug','')})")
        if m.curseforge.get("mod"):
            lines.append(f"  - CurseForge: {m.curseforge['mod'].get('name','')} ({m.curseforge['mod'].get('slug','')})")
    lines.append("")
    def section(title, items):
        lines.append(f"## {title}")
        if not items:
            lines.append("- None")
        else:
            for it in items:
                if title.startswith("Missing"):
                    lines.append(f"- {it['mod']} requires {it['requires']} {it.get('version') or ''} [{it.get('source')}]")
                elif title.startswith("Version"):
                    lines.append(f"- {it['mod']} needs {it['dependency']} {it['required_range']} but installed {it['installed_version']}")
                elif title.startswith("Duplicates"):
                    lines.append(f"- {it['modid']}: {', '.join(it['files'])} (versions: {', '.join(it['versions'])})")
                elif title.startswith("Explicit"):
                    lines.append(f"- {it['mod']} conflicts with {it['conflicts_with']} ({it['type']})")
                elif title.startswith("Known"):
                    lines.append(f"- {it['a']} vs {it['b']}: {it['reason']}")
                elif title.startswith("Potential"):
                    lines.append(f"- {it['a']} vs {it['b']}: {it['reason']}")
        lines.append("")
    section("Missing dependencies", ar.missing_dependencies)
    section("Version mismatches", ar.version_mismatches)
    section("Duplicates", ar.duplicates)
    section("Explicit conflicts (declared)", ar.explicit_conflicts)
    section("Known conflicts (knowledge base)", ar.known_conflicts)
    section("Potential conflicts (heuristics)", ar.potential_conflicts)

    lines.append("## Optimization recommendations")
    rec = ar.recommendations or {}
    lines.append(f"- Recommended RAM: {rec.get('recommended_ram_gb', 'n/a')} GB (detected total: {rec.get('detected_total_ram_gb', 'n/a')} GB)")
    lines.append("- Recommended JVM args:")
    if rec.get("recommended_jvm_args"):
        lines.append(f"  - {rec['recommended_jvm_args']}")
    sugg = rec.get("suggested_performance_mods") or []
    if sugg:
        lines.append("- Suggested performance mods to consider:")
        for s in sugg:
            title = s.get("name") or s.get("modid_hint") or "unknown"
            note = s.get("note", "")
            lines.append(f"  - {title} ({s.get('loader','')}) - {note}")
    else:
        lines.append("- No additional performance mods suggested.")
    lines.append("")
    kb = ar.kb_info or {}
    lines.append("## Knowledge base")
    lines.append(f"- Channel: {kb.get('channel','n/a')}, updated: {kb.get('updated')}, TTL(sec): {kb.get('ttl_sec')}")
    if kb.get("last_check_ts"):
        lines.append(f"- Last check: {kb.get('last_check_ts')}")
    if kb.get("sources"):
        lines.append(f"- Sources: {', '.join(kb.get('sources'))}")
    lines.append("")
    lines.append("_Generated by Modpack Doctor_")
    return "\n".join(lines)

# ---- Main ----

def main():
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} — анализатор модпаков Minecraft (зависимости, конфликты, оптимизация)"
    )
    parser.add_argument("mods_dir", type=str, help="Путь к папке с модами (mods)")
    parser.add_argument("--online", action="store_true", help="Пытаться обогащать данные через Modrinth API")
    parser.add_argument("--curseforge", action="store_true", help="Включить обогащение через CurseForge API")
    parser.add_argument("--curseforge-key", type=str, default=None, help="Ключ CurseForge API (или задайте CURSEFORGE_API_KEY в окружении)")
    parser.add_argument("--mc", type=str, default=None, help="Целевая версия Minecraft (если знаете)")
    parser.add_argument("--loader", type=str, choices=["fabric", "forge", "quilt", "neoforge"], default=None, help="Целевой загрузчик (если знаете)")
    parser.add_argument("--ram-gb", type=float, default=None, help="Сколько RAM (ГБ) выделить клиенту")
    parser.add_argument("--threads", type=int, default=None, help="Количество потоков CPU (инфо для отчета)")
    parser.add_argument("--out", type=str, default=None, help="Папка для отчетов (по умолчанию: mods_dir/modpack_doctor_output)")
    # KB auto-update
    parser.add_argument("--db-update", choices=["now"], default=None, help="Принудительно обновить базы знаний сейчас")
    parser.add_argument("--db-ttl", type=str, default="7d", help="Периодичность проверки обновлений (напр. 1d, 7d, 30d)")
    parser.add_argument("--db-channel", choices=["main", "release"], default="main", help="Канал обновлений баз знаний (по умолчанию main)")
    parser.add_argument("--db-url", action="append", default=None, help="Дополнительный URL для загрузки баз (можно указывать несколько раз)")
    parser.add_argument("--no-db-update", action="store_true", help="Отключить обращение за обновлениями, использовать только локальные файлы")
    args = parser.parse_args()

    mods_dir = Path(args.mods_dir).expanduser().resolve()
    if not mods_dir.exists() or not mods_dir.is_dir():
        print(f"Папка не найдена: {mods_dir}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out or (mods_dir / "modpack_doctor_output"))
    out_dir.mkdir(parents=True, exist_ok=True)

    base_dir = Path(__file__).parent

    # Load KB with auto-update and overrides
    known_conflicts_db, perf_db, kb_info = load_knowledge_base(base_dir, out_dir, args)

    # Scan jars
    jar_files = sorted([p for p in mods_dir.iterdir() if p.suffix.lower() == ".jar"])
    mods: List[ModInfo] = []
    for jf in jar_files:
        mi = extract_mod_info_from_jar(jf)
        if mi is None:
            continue
        with contextlib.suppress(Exception):
            mi.sha1 = file_sha1(jf)
        mods.append(mi)

    # Optional Modrinth enrichment
    if args.online and requests:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(modrinth_enrich, mods))

    # Optional CurseForge enrichment
    cf_key = args.curseforge_key or os.getenv("CURSEFORGE_API_KEY")
    cf_cache_path = out_dir / "curseforge_cache.json"
    if args.curseforge and requests and cf_key:
        cf = CurseForgeClient(api_key=cf_key, cache_path=cf_cache_path)
        for mi in mods:
            with contextlib.suppress(Exception):
                curseforge_enrich(mi, cf=cf, target_loader=args.loader, target_mc=args.mc)

    # Analysis
    loader_inferred, mc_versions_inferred = infer_loader_and_mc_versions(mods)
    missing_deps, version_mismatches, duplicates, mixed = analyze_mods(mods, known_conflicts_db)
    known_conflicts, potential_conflicts = detect_known_and_potential_conflicts(mods, known_conflicts_db)

    # Recommendations
    total_ram_gb = None
    if psutil:
        with contextlib.suppress(Exception):
            total_ram_gb = round(psutil.virtual_memory().total / (1024**3), 1)

    recs = recommend_optimizations(
        mods=mods,
        perf_db=perf_db,
        total_ram_gb=total_ram_gb,
        user_ram_gb=args.ram_gb
    )

    # Prepare result
    ar = AnalysisResult(
        loader_inferred=args.loader or loader_inferred,
        minecraft_versions_inferred=([args.mc] if args.mc else []) or mc_versions_inferred,
        mods=mods,
        missing_dependencies=missing_deps,
        version_mismatches=version_mismatches,
        duplicates=duplicates,
        explicit_conflicts=[],  # recomputed below
        known_conflicts=known_conflicts,
        potential_conflicts=potential_conflicts,
        mixed_loaders_warning=mixed,
        recommendations=recs,
        kb_info=kb_info
    )

    installed_ids = set((m.modid or m.name or m.file_name).lower() for m in mods)
    explicit_conflicts = []
    for m in mods:
        for c in m.conflicts:
            if (c.modid or "").lower() in installed_ids:
                explicit_conflicts.append({
                    "mod": m.modid or m.name or m.file_name,
                    "conflicts_with": c.modid,
                    "type": c.kind,
                    "source": c.source
                })
    ar.explicit_conflicts = explicit_conflicts

    # Write JSON
    json_path = out_dir / "modpack_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "app": APP_NAME, "version": APP_VERSION,
            "loader_inferred": ar.loader_inferred,
            "minecraft_versions_inferred": ar.minecraft_versions_inferred,
            "mods": [asdict(m) for m in ar.mods],
            "missing_dependencies": ar.missing_dependencies,
            "version_mismatches": ar.version_mismatches,
            "duplicates": ar.duplicates,
            "explicit_conflicts": ar.explicit_conflicts,
            "known_conflicts": ar.known_conflicts,
            "potential_conflicts": ar.potential_conflicts,
            "mixed_loaders_warning": ar.mixed_loaders_warning,
            "recommendations": ar.recommendations,
            "kb_info": ar.kb_info
        }, f, ensure_ascii=False, indent=2)

    # Write Markdown
    md_path = out_dir / "modpack_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(build_markdown_report(ar))

    # Write JVM args
    jvm_path = out_dir / "recommended_jvm_args.txt"
    with open(jvm_path, "w", encoding="utf-8") as f:
        f.write((ar.recommendations or {}).get("recommended_jvm_args") or "")

    print(f"Готово!\n- JSON: {json_path}\n- Markdown: {md_path}\n- JVM args: {jvm_path}")

if __name__ == "__main__":
    main()