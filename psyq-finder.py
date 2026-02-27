#!/usr/bin/env python3
"""
PSY-Q SDK Version Identifier Tool
==================================
A tool for PS1 game decompilers to identify which PSY-Q SDK versions are used
in their codebase by comparing function signatures.

Features:
- Fetches and caches PSY-Q signature JSONs from GitHub
- Compares functions between SDK versions with visual diff
- Matches binary data against signatures to identify versions

Dependencies:
    pip install -r requirements.txt

Usage:
    python psyq-finder.py
"""

import json
import os
import re
import sys
import hashlib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from difflib import SequenceMatcher

import requests
import glfw
import OpenGL.GL as gl
import imgui
from imgui.integrations.glfw import GlfwRenderer


# =============================================================================
# Configuration
# =============================================================================

GITHUB_API_BASE = "https://api.github.com/repos/lab313ru/psx_psyq_signatures"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/lab313ru/psx_psyq_signatures/main"
CACHE_DIR = Path.home() / ".cache" / "psyq_signatures"

# Known SDK versions (will be auto-discovered from GitHub)
DEFAULT_SDK_VERSIONS = ["260","300","330","340","350","3610","3611","370","400", "410", "420", "430", "440", "450", "460", "470"]


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Label:
    name: str
    offset: int


@dataclass
class ObjectEntry:
    name: str
    sig: str
    labels: list[Label] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict) -> Optional["ObjectEntry"]:
        """Parse an object entry, returning None if essential fields are missing."""
        name = data.get("name", "")
        sig = data.get("sig", "")
        
        # Skip entries without signatures (e.g., BSS-only objects like xbss entries)
        # This is expected for some objects that only contain uninitialized data
        if not sig:
            return None
        
        labels = []
        for l in data.get("labels", []):
            if "name" in l and "offset" in l:
                labels.append(Label(l["name"], l["offset"]))
        
        return cls(name=name, sig=sig, labels=labels)


@dataclass
class Library:
    name: str
    version: str
    objects: list[ObjectEntry] = field(default_factory=list)
    
    def get_functions(self) -> dict[str, tuple[ObjectEntry, Label]]:
        """Get all real function labels mapped to their object."""
        functions: dict[str, tuple[ObjectEntry, Label]] = {}
    
        for obj in self.objects:
            for label in obj.labels:
                name = label.name
    
                # Skip assembler-generated labels
                if name.startswith("loc_") or name.startswith("text_"):
                    continue
    
                functions[name] = (obj, label)
    
        return functions


# =============================================================================
# GitHub API & Caching
# =============================================================================

class SDKManager:
    """Manages fetching and caching of PSY-Q SDK signature files."""
    
    def __init__(self, cache_dir: Path = CACHE_DIR):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._versions_cache: list[str] = []
        self._libraries_cache: dict[str, list[str]] = {}  # version -> library names
        self._loaded_libraries: dict[str, Library] = {}  # "version/libname" -> Library
        
    def get_cache_path(self, version: str, library: str) -> Path:
        """Get the cache file path for a specific library."""
        return self.cache_dir / version / f"{library}.json"
    
    def is_cached(self, version: str, library: str) -> bool:
        """Check if a library is already cached."""
        return self.get_cache_path(version, library).exists()
    
    def discover_versions(self) -> list[str]:
        """Discover available SDK versions from GitHub."""
        if self._versions_cache:
            return self._versions_cache
            
        # Check if we have a cached versions list
        versions_file = self.cache_dir / "versions.json"
        if versions_file.exists():
            try:
                with open(versions_file) as f:
                    self._versions_cache = json.load(f)
                return self._versions_cache
            except:
                pass
        
        # Fetch from GitHub API
        try:
            response = requests.get(f"{GITHUB_API_BASE}/contents", timeout=10)
            response.raise_for_status()
            contents = response.json()
            
            versions = []
            for item in contents:
                if item["type"] == "dir" and item["name"].isdigit():
                    versions.append(item["name"])
            
            versions.sort(key=lambda x: int(x))
            self._versions_cache = versions
            
            # Cache the versions list
            with open(versions_file, "w") as f:
                json.dump(versions, f)
                
            return versions
        except Exception as e:
            print(f"Failed to discover versions: {e}")
            return DEFAULT_SDK_VERSIONS
    
    def discover_libraries(self, version: str) -> list[str]:
        """Discover available libraries for a specific SDK version."""
        if version in self._libraries_cache:
            return self._libraries_cache[version]
            
        # Check cached list
        libs_file = self.cache_dir / version / "libraries.json"
        if libs_file.exists():
            try:
                with open(libs_file) as f:
                    self._libraries_cache[version] = json.load(f)
                return self._libraries_cache[version]
            except:
                pass
        
        # Fetch from GitHub API
        try:
            response = requests.get(f"{GITHUB_API_BASE}/contents/{version}", timeout=10)
            response.raise_for_status()
            contents = response.json()
            
            libraries = []
            for item in contents:
                if item["type"] == "file" and item["name"].endswith(".LIB.json"):
                    # Extract library name (e.g., "LIBSPU.LIB.json" -> "LIBSPU.LIB")
                    lib_name = item["name"][:-5]  # Remove .json
                    libraries.append(lib_name)
                elif item["type"] == "file" and item["name"].endswith(".OBJ.json"):
                    # Loose OBJ files (e.g., "2MBYTE.OBJ.json" -> "2MBYTE.OBJ")
                    obj_name = item["name"][:-5]  # Remove .json
                    libraries.append(obj_name)  # Treat as a pseudo-library
            
            libraries.sort()
            self._libraries_cache[version] = libraries
            
            # Cache the libraries list
            libs_file.parent.mkdir(parents=True, exist_ok=True)
            with open(libs_file, "w") as f:
                json.dump(libraries, f)
                
            return libraries
        except Exception as e:
            print(f"Failed to discover libraries for {version}: {e}")
            return []
    
    def fetch_library(self, version: str, library: str, force_refresh: bool = False) -> Optional[Library]:
        """Fetch a library, using cache if available."""
        cache_key = f"{version}/{library}"
        
        # Check memory cache
        if cache_key in self._loaded_libraries and not force_refresh:
            return self._loaded_libraries[cache_key]
        
        cache_path = self.get_cache_path(version, library)
        
        # Check disk cache
        if cache_path.exists() and not force_refresh:
            try:
                with open(cache_path) as f:
                    data = json.load(f)
                lib = self._parse_library(data, library, version)
                self._loaded_libraries[cache_key] = lib
                return lib
            except json.JSONDecodeError as e:
                print(f"Cache corrupted for {cache_key}, re-fetching...")
            except Exception as e:
                print(f"Failed to load {cache_key}: {type(e).__name__}: {e}")
        
        # Fetch from GitHub
        try:
            url = f"{GITHUB_RAW_BASE}/{version}/{library}.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # Cache to disk
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, "w") as f:
                json.dump(data, f)
            
            lib = self._parse_library(data, library, version)
            self._loaded_libraries[cache_key] = lib
            return lib
            
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching {cache_key}: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Invalid JSON from {cache_key}: {e}")
            return None
        except Exception as e:
            print(f"Error loading {cache_key}: {type(e).__name__}: {e}")
            return None
    
    def _parse_library(self, data, name: str, version: str) -> Library:
        """Parse JSON data into a Library object."""
        objects = []
        
        # Handle different possible JSON structures
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Check if this is a single object entry (loose OBJ file)
            # Single objects typically have "name" and "sig" at the top level
            if "name" in data and "sig" in data:
                # Single object - wrap in list
                items = [data]
            elif "objects" in data:
                items = data["objects"]
            elif "entries" in data:
                items = data["entries"]
            else:
                # Try to use all dict values that look like objects
                items = [v for v in data.values() if isinstance(v, dict)]
        else:
            print(f"Unexpected data type for {version}/{name}: {type(data)}")
            return Library(name=name, version=version, objects=[])
        
        for obj_data in items:
            if not isinstance(obj_data, dict):
                continue
            obj = ObjectEntry.from_dict(obj_data)
            if obj is not None:
                objects.append(obj)
        
        return Library(name=name, version=version, objects=objects)
    
    def clear_cache(self):
        """Clear all cached signature files, preserving false positive data."""
        import shutil
        fp_file = self.cache_dir / FalsePositiveStore.FILENAME
        fp_data = None
        
        # Preserve false positive data
        if fp_file.exists():
            try:
                with open(fp_file) as f:
                    fp_data = f.read()
            except Exception:
                pass
        
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Restore false positive data
        if fp_data is not None:
            try:
                with open(fp_file, "w") as f:
                    f.write(fp_data)
            except Exception:
                pass
        
        self._versions_cache = []
        self._libraries_cache = {}
        self._loaded_libraries = {}
    
    def get_all_library_names(self) -> list[str]:
        """Get a list of all unique library names across all SDK versions."""
        all_libs = set()
        versions = self.discover_versions()
        
        for version in versions:
            libs = self.discover_libraries(version)
            all_libs.update(libs)
        
        return sorted(all_libs)


# =============================================================================
# False Positive Store
# =============================================================================

class FalsePositiveStore:
    """
    Persists false positive dismissals for scan results.
    
    Keyed by a binary fingerprint (fast hash of size + head + tail) so
    dismissals are tied to a specific binary and survive across sessions.
    Each entry is (offset, library, object_name, optional version_extra).
    The version_extra allows marking specific version groups of ambiguous
    results as false positives without affecting other version groups.
    """
    
    FILENAME = "false_positives.json"
    
    def __init__(self, cache_dir: Path = CACHE_DIR):
        self.cache_dir = cache_dir
        self._store: dict[str, list[dict]] = {}  # fingerprint -> [{offset, library, object, version_extra?}]
        self._load()
    
    def _store_path(self) -> Path:
        return self.cache_dir / self.FILENAME
    
    def _load(self) -> None:
        path = self._store_path()
        if path.exists():
            try:
                with open(path) as f:
                    self._store = json.load(f)
            except Exception:
                self._store = {}
    
    def _save(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        with open(self._store_path(), "w") as f:
            json.dump(self._store, f, indent=2)
    
    @staticmethod
    def fingerprint(binary_path: str) -> str:
        """
        Fast fingerprint of a binary: hash of (size, first 4KB, last 4KB).
        Unique enough for our purposes and instant even on large files.
        """
        try:
            file_size = os.path.getsize(binary_path)
            h = hashlib.sha256()
            h.update(str(file_size).encode())
            with open(binary_path, "rb") as f:
                head = f.read(4096)
                h.update(head)
                if file_size > 4096:
                    f.seek(max(0, file_size - 4096))
                    tail = f.read(4096)
                    h.update(tail)
            return h.hexdigest()[:16]
        except Exception:
            # Fallback: use filename + size
            return hashlib.sha256(binary_path.encode()).hexdigest()[:16]
    
    def is_false_positive(self, fingerprint: str, offset: int, library: str, object_name: str, version_extra: str = None) -> bool:
        entries = self._store.get(fingerprint, [])
        for e in entries:
            if e["offset"] == offset and e["library"] == library and e["object"] == object_name:
                # If we have a version_extra, check if it matches
                e_extra = e.get("version_extra")
                if version_extra is None and e_extra is None:
                    return True
                if version_extra is not None and e_extra == version_extra:
                    return True
                # Also match if the entry has no version_extra (marks all groups)
                if e_extra is None and version_extra is not None:
                    return True
        return False
    
    def mark(self, fingerprint: str, offset: int, library: str, object_name: str, version_extra: str = None) -> None:
        if fingerprint not in self._store:
            self._store[fingerprint] = []
        # Don't double-add
        if not self.is_false_positive(fingerprint, offset, library, object_name, version_extra):
            entry = {
                "offset": offset,
                "library": library,
                "object": object_name,
            }
            if version_extra is not None:
                entry["version_extra"] = version_extra
            self._store[fingerprint].append(entry)
            self._save()
    
    def unmark(self, fingerprint: str, offset: int, library: str, object_name: str, version_extra: str = None) -> None:
        entries = self._store.get(fingerprint, [])
        new_entries = []
        for e in entries:
            keep = True
            if e["offset"] == offset and e["library"] == library and e["object"] == object_name:
                e_extra = e.get("version_extra")
                # Match if both None, or both have same value
                if version_extra is None and e_extra is None:
                    keep = False
                elif version_extra is not None and e_extra == version_extra:
                    keep = False
            if keep:
                new_entries.append(e)
        
        self._store[fingerprint] = new_entries
        if not self._store[fingerprint]:
            del self._store[fingerprint]
        self._save()
    
    def get_count(self, fingerprint: str) -> int:
        return len(self._store.get(fingerprint, []))
    
    def clear_for_binary(self, fingerprint: str) -> None:
        if fingerprint in self._store:
            del self._store[fingerprint]
            self._save()


# =============================================================================
# Signature Processing
# =============================================================================

def parse_signature(sig: str) -> list[tuple[int, bool]]:
    """
    Parse a signature string into a list of (byte_value, is_wildcard) tuples.
    Wildcards are marked as ?? in the signature.
    """
    # Clean up the signature - remove comments and extra whitespace
    sig = re.sub(r'/\*.*?\*/', '', sig)  # Remove /* ... */ comments
    sig = sig.strip()
    
    bytes_list = []
    tokens = sig.split()
    
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if token == "??":
            bytes_list.append((0, True))  # Wildcard
        else:
            try:
                byte_val = int(token, 16)
                bytes_list.append((byte_val, False))
            except ValueError:
                continue  # Skip invalid tokens
    
    return bytes_list


def signature_to_bytes(sig: str) -> tuple[bytes, bytes]:
    """
    Convert a signature to bytes and a mask.
    Returns (data, mask) where mask has 0xFF for concrete bytes and 0x00 for wildcards.
    """
    parsed = parse_signature(sig)
    data = bytes(b for b, _ in parsed)
    mask = bytes(0x00 if is_wild else 0xFF for _, is_wild in parsed)
    return data, mask


def parse_sdk_version(version: str) -> tuple[int, int, int]:
    """
    Parse an SDK version string into a comparable tuple.
    
    PSY-Q versions are encoded as:
    - 3 digits: X.Y.Z (e.g., "330" = 3.3.0, "470" = 4.7.0)
    - 4 digits: X.Y.ZZ (e.g., "3611" = 3.6.11, "4010" = 4.0.10)
    
    Returns (major, minor, patch) tuple for proper sorting.
    """
    version = version.strip()
    
    if len(version) == 3:
        # XYZ -> X.Y.Z
        return (int(version[0]), int(version[1]), int(version[2]))
    elif len(version) == 4:
        # XYZZ -> X.Y.ZZ
        return (int(version[0]), int(version[1]), int(version[2:4]))
    elif len(version) == 5:
        # XYZZZ or XXYZZ - assume X.Y.ZZZ or XX.Y.ZZ
        # Try X.Y.ZZZ first (more likely for SDK versions)
        return (int(version[0]), int(version[1]), int(version[2:5]))
    else:
        # Fallback: just use as integer for sorting
        try:
            return (int(version), 0, 0)
        except ValueError:
            return (0, 0, 0)


def format_sdk_version(version: str) -> str:
    """Format an SDK version for display (e.g., '470' -> '4.7.0')."""
    major, minor, patch = parse_sdk_version(version)
    return f"{major}.{minor}.{patch}"


def compare_signatures(sig1: str, sig2: str) -> list[tuple[str, str, str]]:
    """
    Compare two signatures and return a diff.
    Returns list of (type, bytes1, bytes2) where type is 'same', 'diff', or 'wildcard'.
    """
    parsed1 = parse_signature(sig1)
    parsed2 = parse_signature(sig2)
    
    result = []
    max_len = max(len(parsed1), len(parsed2))
    
    for i in range(max_len):
        if i >= len(parsed1):
            b1, w1 = 0, True
        else:
            b1, w1 = parsed1[i]
            
        if i >= len(parsed2):
            b2, w2 = 0, True
        else:
            b2, w2 = parsed2[i]
        
        str1 = "??" if w1 else f"{b1:02X}"
        str2 = "??" if w2 else f"{b2:02X}"
        
        if w1 and w2:
            diff_type = "wildcard"
        elif w1 or w2:
            diff_type = "diff"
        elif b1 == b2:
            diff_type = "same"
        else:
            diff_type = "diff"
            
        result.append((diff_type, str1, str2))
    
    return result


def match_binary_to_signature(binary_data: bytes, sig: str) -> bool:
    """Check if binary data matches a signature pattern."""
    parsed = parse_signature(sig)
    
    if len(binary_data) < len(parsed):
        return False
    
    for i, (expected, is_wildcard) in enumerate(parsed):
        if is_wildcard:
            continue
        if binary_data[i] != expected:
            return False
    
    return True


def find_function_in_binary(binary_path: str, offset: int, function_name: str, 
                            sdk_manager: SDKManager,
                            library_filter: Optional[str] = None) -> list[tuple[str, str, float]]:
    """
    Find which SDK versions match a function at a given offset.
    Returns list of (version, library, match_percentage) tuples.
    
    Args:
        binary_path: Path to the binary file
        offset: Offset in the binary where the function starts
        function_name: Name of the function to search for
        sdk_manager: SDKManager instance
        library_filter: If provided, only search this specific library
    """
    try:
        with open(binary_path, "rb") as f:
            f.seek(offset)
            # Read a reasonable chunk for matching
            binary_data = f.read(0x1000)
    except Exception as e:
        print(f"Failed to read binary: {e}")
        return []
    
    matches = []
    versions = sdk_manager.discover_versions()
    
    for version in versions:
        if library_filter:
            # Only search the specified library
            libraries = [library_filter]
        else:
            libraries = sdk_manager.discover_libraries(version)
        
        for lib_name in libraries:
            lib = sdk_manager.fetch_library(version, lib_name)
            if not lib:
                continue
                
            functions = lib.get_functions()
            if function_name not in functions:
                continue
            
            obj, label = functions[function_name]
            
            # Calculate how much of the signature matches
            parsed = parse_signature(obj.sig)
            if not parsed:
                continue
                
            # Adjust for label offset within the object
            sig_start = label.offset            
            sig_end = len(parsed)
            for l in obj.labels:
                # skip asm-generated labels
                if l.name.startswith(("loc_", "text_")):
                    continue
                if l.offset > sig_start:
                    sig_end = l.offset
                    break  # assumes obj.labels are sorted by offset

            
            matching_bytes = 0
            total_concrete_bytes = 0
            
            for i, (expected, is_wildcard) in enumerate(parsed[sig_start:sig_end]):
                if i >= len(binary_data):
                    break
                    
                if is_wildcard:
                    continue
                    
                total_concrete_bytes += 1
                if binary_data[i] == expected:
                    matching_bytes += 1
            
            if total_concrete_bytes > 0:
                match_pct = (matching_bytes / total_concrete_bytes) * 100
                if match_pct > 50:  # Only include decent matches
                    matches.append((version, lib_name, match_pct))
    
    # Sort by match percentage descending
    matches.sort(key=lambda x: x[2], reverse=True)
    return matches


# =============================================================================
# Enrichment (ELF parsing with pyelftools - cross-platform)
# =============================================================================

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


def parse_elf_sections(elf_path: Path) -> dict[str, dict]:
    """
    Parse ELF sections using pyelftools.
    Returns dict of section_name -> {size, offset, addr, type, flags}
    """
    if not PYELFTOOLS_AVAILABLE:
        return {}
    
    sections = {}
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                name = section.name
                if name:  # Skip empty names
                    sections[name] = {
                        "size": section['sh_size'],
                        "offset": section['sh_offset'],
                        "addr": section['sh_addr'],
                        "type": section['sh_type'],
                        "flags": section['sh_flags'],
                    }
    except Exception:
        pass  # Will be handled by caller
    
    return sections


def parse_elf_symbols(elf_path: Path) -> list[dict]:
    """
    Parse ELF symbols using pyelftools.
    Returns list of symbol dicts.
    """
    if not PYELFTOOLS_AVAILABLE:
        return []
    
    symbols = []
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            
            # Find symbol table sections
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                
                for idx, sym in enumerate(section.iter_symbols()):
                    name = sym.name
                    if not name:
                        continue
                    
                    # Get section index - handle special values
                    shndx = sym['st_shndx']
                    if isinstance(shndx, str):
                        ndx = shndx  # 'SHN_UNDEF', 'SHN_ABS', etc.
                    else:
                        ndx = str(shndx)
                    
                    symbols.append({
                        "num": idx,
                        "name": name,
                        "value": sym['st_value'],
                        "value_hex": f"0x{sym['st_value']:08X}",
                        "size": sym['st_size'],
                        "type": sym['st_info']['type'],
                        "bind": sym['st_info']['bind'],
                        "vis": sym['st_other']['visibility'],
                        "ndx": ndx,
                    })
    except Exception:
        pass  # Will be handled by caller
    
    return symbols


def parse_elf_relocations(elf_path: Path) -> dict[str, list[int]]:
    """
    Parse ELF relocation sections using pyelftools.
    Returns dict of target_section -> list of offsets that need wildcarding.
    
    For example:
    {
        ".data": [0, 4, 16],      # Offsets in .data that have relocations
        ".rdata": [8, 12],        # Offsets in .rdata that have relocations
    }
    
    Relocations are typically 4 bytes (32-bit pointers on MIPS).
    """
    if not PYELFTOOLS_AVAILABLE:
        return {}
    
    relocs: dict[str, list[int]] = {}
    
    try:
        from elftools.elf.relocation import RelocationSection
        
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            
            for section in elf.iter_sections():
                # Look for relocation sections
                if not isinstance(section, RelocationSection):
                    continue
                
                # Get the name of the section this applies to
                # .rel.data applies to .data, .rel.rdata applies to .rdata, etc.
                section_name = section.name
                if section_name.startswith('.rel.'):
                    target_section = '.' + section_name[5:]  # .rel.data -> .data
                elif section_name.startswith('.rela.'):
                    target_section = '.' + section_name[6:]  # .rela.data -> .data
                else:
                    continue
                
                if target_section not in relocs:
                    relocs[target_section] = []
                
                # Extract relocation offsets
                for reloc in section.iter_relocations():
                    offset = reloc['r_offset']
                    relocs[target_section].append(offset)
                
                # Sort offsets for easier processing
                relocs[target_section].sort()
    
    except Exception:
        pass  # Will be handled by caller
    
    return relocs


def lib_to_folder(lib: str) -> str:
    """Convert library name to folder name: LIBC2.LIB -> libc2"""
    return Path(lib).stem.lower()


def obj_to_filename(obj: str) -> str:
    """Convert object name to filename: ATOI.OBJ -> atoi.o"""
    return f"{Path(obj).stem.lower()}.o"


def enrich_object(o_path: Path, want_sections: list[str] = None) -> dict:
    """
    Get ELF data for an object file using pyelftools.
    Returns dict with sections, section_sizes, symbols, symbol_count, relocations, errors.
    """
    if want_sections is None:
        want_sections = [".text", ".data", ".rdata", ".bss", ".sdata", ".sbss"]
    
    result = {"errors": [], "obj_path": str(o_path)}
    
    if not PYELFTOOLS_AVAILABLE:
        result["errors"].append("pyelftools not installed - run: pip install pyelftools")
        result["sections"] = {}
        result["section_sizes"] = {s: 0 for s in want_sections}
        result["symbols"] = []
        result["symbol_count"] = 0
        result["relocations"] = {}
        return result
    
    if not o_path.exists():
        result["errors"].append(f"missing_object_file: {o_path}")
        result["sections"] = {}
        result["section_sizes"] = {s: 0 for s in want_sections}
        result["symbols"] = []
        result["symbol_count"] = 0
        result["relocations"] = {}
        return result
    
    # Get sections
    try:
        sections = parse_elf_sections(o_path)
        result["sections"] = sections
    except Exception as e:
        result["errors"].append(f"elf_sections_failed: {e}")
        result["sections"] = {}
    
    # Extract just sizes for the summary
    result["section_sizes"] = {
        s: result["sections"].get(s, {}).get("size", 0) 
        for s in want_sections
    }
    
    # Get symbols
    try:
        symbols = parse_elf_symbols(o_path)
        result["symbols"] = symbols
        result["symbol_count"] = len(symbols)
    except Exception as e:
        result["errors"].append(f"elf_symbols_failed: {e}")
        result["symbols"] = []
        result["symbol_count"] = 0
    
    # Get relocations
    try:
        relocations = parse_elf_relocations(o_path)
        result["relocations"] = relocations
    except Exception as e:
        result["errors"].append(f"elf_relocations_failed: {e}")
        result["relocations"] = {}
    
    return result

# =============================================================================
# Full Binary Scanner
# =============================================================================

@dataclass
class ScanSignature:
    """A preprocessed signature ready for scanning."""
    library: str
    object_name: str
    versions: list[str]
    data: bytes          # Concrete byte values
    mask: bytes          # 0xFF for concrete, 0x00 for wildcard
    sig_length: int      # Total signature length
    anchor_offset: int   # Offset of the anchor within the signature
    anchor_bytes: bytes  # Longest consecutive concrete byte run
    concrete_count: int  # Number of non-wildcard bytes (for match stats)
    subsumption_group: int = -1  # ID linking sigs that are prefixes of each other


@dataclass
class VersionGroup:
    """A group of SDK versions sharing the same signature variant for an object."""
    versions: list[str]
    sig_length: int


@dataclass
class ScanResult:
    """A match found during binary scanning."""
    offset: int
    library: str
    object_name: str
    version_groups: list[VersionGroup]  # One group if unambiguous, multiple if subsumed
    labels: list[Label]  # Functions within this object
    is_ambiguous: bool = False  # True if multiple version groups due to subsumption
    is_duplicate: bool = False  # True if same (library, object) found at another offset
    duplicate_offsets: list[int] = field(default_factory=list)  # Other offsets where this object was found
    is_overlap: bool = False  # True if different (library, object) pairs at same offset
    overlap_objects: list[tuple[str, str]] = field(default_factory=list)  # [(library, object), ...] at same offset

    @property
    def versions(self) -> list[str]:
        """All versions across all groups (for filtering and backward compat)."""
        all_v = []
        for vg in self.version_groups:
            all_v.extend(vg.versions)
        return all_v
    
    @property
    def sig_length(self) -> int:
        """Longest signature length across groups."""
        return max(vg.sig_length for vg in self.version_groups)


class ScanEngine:
    """
    High-performance full-binary scanner for PSY-Q object signatures.
    
    Strategy:
    1. Preprocess: Parse all signatures, deduplicate identical ones across versions,
       extract the best "anchor" (longest consecutive concrete byte run) from each.
    2. Scan: For each unique signature, use bytes.find() with the anchor to find
       candidate offsets in the binary (C-optimized Boyer-Moore, very fast).
    3. Verify: At each candidate offset, verify the full signature with mask.
    4. Report: Group results by offset.
    
    MIPS alignment: PS1 uses 4-byte aligned code, so we only verify at aligned offsets.
    """
    
    MIN_ANCHOR_LENGTH = 8  # Minimum anchor length to avoid too many false positives
    
    def __init__(self, sdk_manager: SDKManager):
        self.sdk_manager = sdk_manager
        self._signatures: list[ScanSignature] = []
        self._preprocessed = False
        self._progress_message = ""
        self._progress_pct = 0.0
    
    @property
    def progress_message(self) -> str:
        return self._progress_message
    
    @property 
    def progress_pct(self) -> float:
        return self._progress_pct
    
    @property
    def is_preprocessed(self) -> bool:
        return self._preprocessed
    
    @property
    def signature_count(self) -> int:
        return len(self._signatures)
    
    def _find_best_anchor(self, mask: bytes) -> tuple[int, int]:
        """
        Find the longest consecutive run of concrete (0xFF) bytes in the mask.
        Returns (offset, length) of the best anchor.
        """
        best_offset = 0
        best_length = 0
        current_offset = 0
        current_length = 0
        
        for i, m in enumerate(mask):
            if m == 0xFF:
                if current_length == 0:
                    current_offset = i
                current_length += 1
            else:
                if current_length > best_length:
                    best_offset = current_offset
                    best_length = current_length
                current_length = 0
        
        # Check the last run
        if current_length > best_length:
            best_offset = current_offset
            best_length = current_length
        
        return best_offset, best_length
    
    def preprocess(
        self, 
        library_filter: Optional[str] = None, 
        version_filter: Optional[str] = None,
        lib_version_overrides: Optional[dict[str, str]] = None
    ) -> None:
        """
        Preprocess all signatures from SDK versions.
        
        Deduplicates identical signatures across versions so we only scan once
        per unique byte pattern.
        
        Args:
            library_filter: If set, only preprocess this library (faster).
            version_filter: If set, only preprocess this SDK version (faster).
            lib_version_overrides: Dict mapping library names to override versions.
                                   Libraries with overrides use ONLY that version.
        """
        self._signatures = []
        self._preprocessed = False
        
        if lib_version_overrides is None:
            lib_version_overrides = {}
        
        all_versions = self.sdk_manager.discover_versions()
        
        # Determine which versions to process for non-overridden libraries
        base_versions = [version_filter] if version_filter else all_versions
        
        # Key: (library, object_name, data_bytes, mask_bytes) -> ScanSignature
        # This deduplicates identical signatures across versions
        sig_map: dict[tuple[str, str, bytes, bytes], ScanSignature] = {}
        
        # Also store labels per (library, object_name, version) for the results
        labels_map: dict[tuple[str, str, str], list[Label]] = {}
        
        # Track what we've processed
        processed_pairs: set[tuple[str, str]] = set()
        
        # First pass: process base versions for non-overridden libraries
        for version in base_versions:
            if version not in all_versions:
                continue
                
            self._progress_message = f"Loading SDK {version}..."
            self._progress_pct = base_versions.index(version) / max(len(base_versions), 1)
            
            if library_filter:
                lib_names = [library_filter]
            else:
                lib_names = self.sdk_manager.discover_libraries(version)
            
            for lib_name in lib_names:
                # Skip if this library has an override (we'll handle it separately)
                if lib_name in lib_version_overrides:
                    continue
                
                pair_key = (lib_name, version)
                if pair_key in processed_pairs:
                    continue
                processed_pairs.add(pair_key)
                
                lib = self.sdk_manager.fetch_library(version, lib_name)
                if not lib:
                    continue
                
                for obj in lib.objects:
                    if not obj.sig:
                        continue
                    
                    data, mask = signature_to_bytes(obj.sig)
                    if len(data) < self.MIN_ANCHOR_LENGTH:
                        continue
                    
                    key = (lib_name, obj.name, data, mask)
                    labels_map[(lib_name, obj.name, version)] = obj.labels
                    
                    if key in sig_map:
                        sig_map[key].versions.append(version)
                    else:
                        anchor_off, anchor_len = self._find_best_anchor(mask)
                        if anchor_len < self.MIN_ANCHOR_LENGTH:
                            continue
                        
                        anchor_bytes = data[anchor_off:anchor_off + anchor_len]
                        concrete_count = sum(1 for m in mask if m == 0xFF)
                        
                        sig_map[key] = ScanSignature(
                            library=lib_name,
                            object_name=obj.name,
                            versions=[version],
                            data=data,
                            mask=mask,
                            sig_length=len(data),
                            anchor_offset=anchor_off,
                            anchor_bytes=anchor_bytes,
                            concrete_count=concrete_count,
                        )
        
        # Second pass: process overridden libraries from their override versions
        for lib_name, override_ver in lib_version_overrides.items():
            if library_filter and lib_name != library_filter:
                continue
            if override_ver not in all_versions:
                continue
            
            pair_key = (lib_name, override_ver)
            if pair_key in processed_pairs:
                continue
            processed_pairs.add(pair_key)
            
            self._progress_message = f"Loading {lib_name} from SDK {override_ver} (override)..."
            
            lib = self.sdk_manager.fetch_library(override_ver, lib_name)
            if not lib:
                continue
            
            for obj in lib.objects:
                if not obj.sig:
                    continue
                
                data, mask = signature_to_bytes(obj.sig)
                if len(data) < self.MIN_ANCHOR_LENGTH:
                    continue
                
                key = (lib_name, obj.name, data, mask)
                labels_map[(lib_name, obj.name, override_ver)] = obj.labels
                
                if key in sig_map:
                    sig_map[key].versions.append(override_ver)
                else:
                    anchor_off, anchor_len = self._find_best_anchor(mask)
                    if anchor_len < self.MIN_ANCHOR_LENGTH:
                        continue
                    
                    anchor_bytes = data[anchor_off:anchor_off + anchor_len]
                    concrete_count = sum(1 for m in mask if m == 0xFF)
                    
                    sig_map[key] = ScanSignature(
                        library=lib_name,
                        object_name=obj.name,
                        versions=[override_ver],
                        data=data,
                        mask=mask,
                        sig_length=len(data),
                        anchor_offset=anchor_off,
                        anchor_bytes=anchor_bytes,
                        concrete_count=concrete_count,
                    )
        
        self._signatures = list(sig_map.values())
        # Sort versions within each signature
        for sig in self._signatures:
            sig.versions.sort(key=parse_sdk_version)
        
        self._labels_map = labels_map
        
        # Detect prefix/subsumption relationships
        self._progress_message = "Detecting signature subsumptions..."
        self._detect_subsumptions()
        
        self._preprocessed = True
        self._progress_pct = 1.0
        
        # Stats
        total_across_versions = sum(len(s.versions) for s in self._signatures)
        num_groups = len(set(s.subsumption_group for s in self._signatures if s.subsumption_group >= 0))
        subsumption_msg = f", {num_groups} subsumption groups" if num_groups else ""
        override_msg = f", {len(lib_version_overrides)} override(s)" if lib_version_overrides else ""
        self._progress_message = (
            f"Preprocessed {len(self._signatures)} unique signatures "
            f"({total_across_versions} total across versions{subsumption_msg}{override_msg})"
        )
    
    def _detect_subsumptions(self) -> None:
        """
        Detect prefix/subsumption relationships between signatures.
        
        For the same (library, object_name), if signature A is shorter than B
        and every concrete byte in A matches the corresponding position in B,
        then any binary matching B will also match A. We tag these with the
        same subsumption_group ID so the scanner can merge them in results.
        """
        # Group signatures by (library, object_name)
        from collections import defaultdict
        groups: dict[tuple[str, str], list[ScanSignature]] = defaultdict(list)
        
        for sig in self._signatures:
            groups[(sig.library, sig.object_name)].append(sig)
        
        next_group_id = 0
        
        for key, sigs in groups.items():
            if len(sigs) < 2:
                continue  # No subsumption possible with a single signature
            
            # Sort by length so we check shorter against longer
            sigs.sort(key=lambda s: s.sig_length)
            
            # For each pair, check if shorter is subsumed by longer.
            # A is subsumed by B means: for every position i < len(A) where 
            # A.mask[i] == 0xFF (concrete), B.mask[i] must also be 0xFF 
            # and A.data[i] == B.data[i].
            # In other words: anything matching B also matches A at the prefix.
            
            # Track which sigs are in a subsumption relationship
            related: set[int] = set()  # indices into sigs list
            
            for i in range(len(sigs)):
                for j in range(i + 1, len(sigs)):
                    shorter = sigs[i]
                    longer = sigs[j]
                    
                    if shorter.sig_length >= longer.sig_length:
                        continue  # Same length — already deduplicated, skip
                    
                    # Check if shorter is subsumed by longer
                    subsumed = True
                    for pos in range(shorter.sig_length):
                        if shorter.mask[pos] == 0xFF:
                            if longer.mask[pos] != 0xFF or shorter.data[pos] != longer.data[pos]:
                                subsumed = False
                                break
                    
                    if subsumed:
                        related.add(i)
                        related.add(j)
            
            if related:
                # Assign the same group ID to all related sigs
                group_id = next_group_id
                next_group_id += 1
                for idx in related:
                    sigs[idx].subsumption_group = group_id
    
    def _merge_subsumed_results(self, raw_results: list[ScanResult]) -> list[ScanResult]:
        """
        Merge scan results at the same offset that are related by subsumption.
        
        When a shorter signature and a longer signature both match at the same
        offset for the same library/object, merge them into a single result
        with multiple VersionGroups and mark it as ambiguous.
        """
        from collections import defaultdict
        
        # Group by (offset, library, object_name)
        groups: dict[tuple[int, str, str], list[ScanResult]] = defaultdict(list)
        for r in raw_results:
            groups[(r.offset, r.library, r.object_name)].append(r)
        
        merged: list[ScanResult] = []
        
        for key, results_at_offset in groups.items():
            if len(results_at_offset) == 1:
                merged.append(results_at_offset[0])
                continue
            
            # Multiple results at same offset for same lib/obj — merge them
            all_groups = []
            # Use labels from the result with the longest signature (most complete)
            best_labels = []
            best_sig_len = 0
            for r in results_at_offset:
                all_groups.extend(r.version_groups)
                r_max_len = max(vg.sig_length for vg in r.version_groups)
                if r_max_len > best_sig_len:
                    best_sig_len = r_max_len
                    best_labels = r.labels
            
            # Sort groups: longest signature first (most specific)
            all_groups.sort(key=lambda vg: vg.sig_length, reverse=True)
            
            merged.append(ScanResult(
                offset=key[0],
                library=key[1],
                object_name=key[2],
                version_groups=all_groups,
                labels=best_labels if best_labels else results_at_offset[0].labels,
                is_ambiguous=True,
            ))
        
        # Re-sort by offset
        merged.sort(key=lambda r: r.offset)
        return merged
    
    def _mark_duplicates(self, results: list[ScanResult]) -> list[ScanResult]:
        """
        Mark results where the same (library, object) appears at multiple offsets.
        These are likely false positives where only one is the real match.
        """
        from collections import defaultdict
        
        # Group by (library, object_name)
        by_obj: dict[tuple[str, str], list[ScanResult]] = defaultdict(list)
        for r in results:
            by_obj[(r.library, r.object_name)].append(r)
        
        # Mark duplicates
        for key, obj_results in by_obj.items():
            if len(obj_results) > 1:
                # Multiple matches for same object - mark all as duplicates
                all_offsets = [r.offset for r in obj_results]
                for r in obj_results:
                    r.is_duplicate = True
                    r.duplicate_offsets = [o for o in all_offsets if o != r.offset]
        
        return results
    
    def _mark_overlaps(self, results: list[ScanResult]) -> list[ScanResult]:
        """
        Mark results where different (library, object) pairs are at the same offset.
        This can happen when identical code exists in multiple libraries (e.g., strtok).
        """
        from collections import defaultdict
        
        # Group by offset
        by_offset: dict[int, list[ScanResult]] = defaultdict(list)
        for r in results:
            by_offset[r.offset].append(r)
        
        # Mark overlaps
        for offset, results_at_offset in by_offset.items():
            if len(results_at_offset) > 1:
                # Multiple different objects at same offset
                all_objs = [(r.library, r.object_name) for r in results_at_offset]
                for r in results_at_offset:
                    r.is_overlap = True
                    r.overlap_objects = [
                        (lib, obj) for lib, obj in all_objs 
                        if (lib, obj) != (r.library, r.object_name)
                    ]
        
        return results
    
    def scan(self, binary_path: str, align: int = 4) -> list[ScanResult]:
        """
        Scan a binary file for all matching PSY-Q object signatures.
        
        Args:
            binary_path: Path to the PS1 binary
            align: Byte alignment for candidate offsets (4 for MIPS)
        
        Returns:
            List of ScanResult sorted by offset
        """
        if not self._preprocessed:
            raise RuntimeError("Must call preprocess() before scan()")
        
        # Load entire binary into memory
        with open(binary_path, "rb") as f:
            binary = f.read()
        
        binary_len = len(binary)
        results: list[ScanResult] = []
        
        # For each unique signature, find candidates via anchor search
        total_sigs = len(self._signatures)
        
        for sig_idx, sig in enumerate(self._signatures):
            if sig_idx % 50 == 0:
                self._progress_message = (
                    f"Scanning: {sig_idx}/{total_sigs} signatures "
                    f"({len(results)} matches so far)"
                )
                self._progress_pct = sig_idx / total_sigs
            
            anchor = sig.anchor_bytes
            anchor_off = sig.anchor_offset
            
            # Use bytes.find() to locate anchor in binary — this is C-optimized
            search_start = 0
            while True:
                pos = binary.find(anchor, search_start)
                if pos == -1:
                    break
                
                # The actual object start would be at pos - anchor_off
                obj_start = pos - anchor_off
                search_start = pos + 1
                
                # Bounds and alignment check
                if obj_start < 0:
                    continue
                if align > 1 and obj_start % align != 0:
                    continue
                if obj_start + sig.sig_length > binary_len:
                    continue
                
                # Full verification: check ALL concrete bytes
                chunk = binary[obj_start:obj_start + sig.sig_length]
                match = True
                for i in range(sig.sig_length):
                    if sig.mask[i] == 0xFF and chunk[i] != sig.data[i]:
                        match = False
                        break
                
                if match:
                    # Collect labels from the first version (labels are usually the same)
                    first_version = sig.versions[0]
                    labels_key = (sig.library, sig.object_name, first_version)
                    labels = self._labels_map.get(labels_key, [])
                    
                    results.append(ScanResult(
                        offset=obj_start,
                        library=sig.library,
                        object_name=sig.object_name,
                        version_groups=[VersionGroup(
                            versions=list(sig.versions),
                            sig_length=sig.sig_length,
                        )],
                        labels=labels,
                    ))
        
        # Merge results that are related by subsumption (prefix signatures)
        results = self._merge_subsumed_results(results)
        
        # Sort by offset
        results.sort(key=lambda r: r.offset)
        
        # Detect duplicates (same library+object at multiple offsets)
        results = self._mark_duplicates(results)
        
        # Detect overlaps (different objects at same offset)
        results = self._mark_overlaps(results)
        
        self._progress_pct = 1.0
        ambiguous_count = sum(1 for r in results if r.is_ambiguous)
        duplicate_count = sum(1 for r in results if r.is_duplicate)
        overlap_count = sum(1 for r in results if r.is_overlap)
        ambig_msg = f" ({ambiguous_count} ambiguous)" if ambiguous_count else ""
        dup_msg = f" ({duplicate_count} duplicates)" if duplicate_count else ""
        overlap_msg = f" ({overlap_count} overlaps)" if overlap_count else ""
        self._progress_message = f"Scan complete: {len(results)} objects found{ambig_msg}{dup_msg}{overlap_msg}"
        
        return results


# =============================================================================
# ImGui Application
# =============================================================================

class PSYQApp:
    """Main application class with ImGui interface."""
    
    def __init__(self):
        self.sdk_manager = SDKManager()
        
        # UI State
        self.versions: list[str] = []
        self.libraries: dict[str, list[str]] = {}
        
        # Tab 1: Compare Functions
        self.compare_version1_idx = 0
        self.compare_version2_idx = 0
        self.compare_lib1_idx = 0
        self.compare_lib2_idx = 0
        self.compare_func_idx = 0
        self.compare_result: list[tuple[str, str, str]] = []
        self.compare_functions: list[str] = []
        self.compare_lib1: Optional[Library] = None
        self.compare_lib2: Optional[Library] = None
        
        # Tab 2: Match Function
        self.func_binary_path = ""
        self.func_offset_str = "0"
        self.function_name = ""
        self.func_match_results: list[tuple[str, str, float]] = []
        self.func_matching = False
        self.func_library_idx = 0
        self.all_libraries: list[str] = []  # Will be populated on first access
        
        # Tab 3: Match Object
        self.obj_binary_path = ""
        self.obj_offset_str = "0"
        self.obj_library_idx = 0
        self.obj_object_idx = 0
        self.obj_objects_list: list[str] = []  # Objects in selected library
        self.obj_match_results: list[tuple[str, float, int, int]] = []  # (version, match%, matched, total)
        self.obj_matching = False
        
        # Tab 4: Find Function
        self.find_func_name = ""
        self.find_func_library_idx = 0  # 0 = All Libraries
        self.find_func_results: list[tuple[str, str, list[str]]] = []  # (library, object, [versions])
        self.find_func_searching = False
        
        # Tab 5: Scan Binary
        self.scan_engine = ScanEngine(self.sdk_manager)
        self.scan_binary_path = ""
        self.scan_version_idx = 0  # 0 = All Versions
        self.scan_library_idx = 0  # 0 = All Libraries
        self.scan_results: list[ScanResult] = []
        self.scan_running = False
        self.scan_preprocessed = False
        self.scan_align_to_4 = True
        self.scan_export_path = ""
        self.scan_filter_text = ""
        self.scan_show_false_positives = False
        self.scan_binary_fingerprint = ""
        self.fp_store = FalsePositiveStore()
        
        # Enrichment (readelf data from .o files)
        self.enrich_repo_root = ""
        self.enrich_obj_root = ""  # Resolved path to obj files
        self.enrich_data: dict[tuple[str, str], dict] = {}  # (library, object) -> readelf info
        self.enrich_errors: list[str] = []
        
        # Per-library version overrides for enrichment
        # Key is library name (or "" for loose objs), value is version string
        self.lib_version_overrides: dict[str, str] = {}
        
        # Section ordering and offset resolution
        # Each entry: {"library": str, "object": str, "offset": int or None, "size": int}
        self.data_section_list: list[dict] = []
        self.rdata_section_list: list[dict] = []
        
        # Section search state
        self.section_search_results: list[tuple[int, float]] = []  # (offset, match%) candidates
        self.section_search_key: tuple[str, str, str] = ("", "", "")  # (library, object, section)
        self.section_searching = False
        
        # Section diff display state
        self.section_diff_key: tuple[str, str, str, int] = ("", "", "", 0)  # (library, object, section, offset)
        self.section_diff_data: Optional[dict] = None  # Diff data for inline display
        
        # Section verification cache to avoid repeated file I/O
        # Key: (library, object, section, offset) -> (match_pct, matched, total)
        self.section_verify_cache: dict[tuple[str, str, str, int], tuple[float, int, int]] = {}
        
        # Legacy block state (kept for compatibility during transition)
        self.blocks: list[dict] = []
        self.block_data_offsets: dict[int, int] = {}
        self.block_rdata_offsets: dict[int, int] = {}
        self.block_search_results: list[tuple[int, float]] = []
        self.block_searching = False
        self.current_block_idx = -1
        self.current_section_type = ""
        
        # Tab 7: Verify Splat (new)
        self.verify_splat_path = ""
        self.verify_results: list[dict] = []  # verification results
        self.verify_running = False
        
        # Tab 6: Library Explorer
        self.explorer_version_idx = 0
        self.explorer_lib_idx = 0
        self.explorer_obj_idx = -1  # -1 = nothing selected
        self.explorer_lib: Optional[Library] = None
        self.explorer_filter_text = ""
        self.explorer_filtered_objects: list[int] = []  # indices into explorer_lib.objects
        self.explorer_hex_bytes_per_row = 16
        
        # Status
        self.status_message = "Initializing..."
        self.loading = False
        
        # Initialize
        self._init_versions()
    
    def _init_versions(self):
        """Initialize available versions."""
        self.status_message = "Discovering SDK versions..."
        self.versions = self.sdk_manager.discover_versions()
        if self.versions:
            self.status_message = f"Found {len(self.versions)} SDK versions"
        else:
            self.status_message = "No SDK versions found - check internet connection"
    
    def _get_libraries_for_version(self, version: str) -> list[str]:
        """Get libraries for a version, discovering if needed."""
        if version not in self.libraries:
            self.libraries[version] = self.sdk_manager.discover_libraries(version)
        return self.libraries[version]
    
    def _load_compare_libraries(self):
        """Load libraries for comparison."""
        if not self.versions:
            return
            
        v1 = self.versions[self.compare_version1_idx]
        v2 = self.versions[self.compare_version2_idx]
        
        libs1 = self._get_libraries_for_version(v1)
        libs2 = self._get_libraries_for_version(v2)
        
        if not libs1 or not libs2:
            return
        
        # Clamp indices
        self.compare_lib1_idx = min(self.compare_lib1_idx, len(libs1) - 1)
        self.compare_lib2_idx = min(self.compare_lib2_idx, len(libs2) - 1)
        
        lib1_name = libs1[self.compare_lib1_idx]
        lib2_name = libs2[self.compare_lib2_idx]
        
        self.compare_lib1 = self.sdk_manager.fetch_library(v1, lib1_name)
        self.compare_lib2 = self.sdk_manager.fetch_library(v2, lib2_name)
        
        # Find common functions
        if self.compare_lib1 and self.compare_lib2:
            funcs1 = set(self.compare_lib1.get_functions().keys())
            funcs2 = set(self.compare_lib2.get_functions().keys())
            self.compare_functions = sorted(funcs1 & funcs2)
            self.compare_func_idx = min(self.compare_func_idx, max(0, len(self.compare_functions) - 1))
    
    def _do_compare(self):
        """Perform the signature comparison."""
        if not self.compare_lib1 or not self.compare_lib2:
            return
        if not self.compare_functions:
            return
        
        func_name = self.compare_functions[self.compare_func_idx]
        funcs1 = self.compare_lib1.get_functions()
        funcs2 = self.compare_lib2.get_functions()
        
        if func_name not in funcs1 or func_name not in funcs2:
            return
        
        obj1, label1 = funcs1[func_name]
        obj2, label2 = funcs2[func_name]
        
        self.compare_result = compare_signatures(obj1.sig, obj2.sig)
        self.status_message = f"Compared {func_name}: {len(self.compare_result)} bytes"
    
    def render_compare_tab(self):
        """Render the function comparison tab."""
        if not self.versions:
            imgui.text("No SDK versions available")
            return
        
        imgui.text("Compare function signatures between SDK versions")
        imgui.separator()
        
        # Version selectors
        libs1 = self._get_libraries_for_version(self.versions[self.compare_version1_idx]) if self.versions else []
        libs2 = self._get_libraries_for_version(self.versions[self.compare_version2_idx]) if self.versions else []
        
        imgui.columns(2, "version_columns")
        
        # Left column - Version 1
        imgui.text("Version 1")
        changed1, self.compare_version1_idx = imgui.combo(
            "SDK##1", self.compare_version1_idx, self.versions
        )
        
        if libs1:
            changed_lib1, self.compare_lib1_idx = imgui.combo(
                "Library##1", self.compare_lib1_idx, libs1
            )
            if changed1 or changed_lib1:
                self._load_compare_libraries()
        
        imgui.next_column()
        
        # Right column - Version 2
        imgui.text("Version 2")
        changed2, self.compare_version2_idx = imgui.combo(
            "SDK##2", self.compare_version2_idx, self.versions
        )
        
        if libs2:
            changed_lib2, self.compare_lib2_idx = imgui.combo(
                "Library##2", self.compare_lib2_idx, libs2
            )
            if changed2 or changed_lib2:
                self._load_compare_libraries()
        
        imgui.columns(1)
        imgui.separator()
        
        # Function selector
        if self.compare_functions:
            _, self.compare_func_idx = imgui.combo(
                "Function", self.compare_func_idx, self.compare_functions
            )
            
            if imgui.button("Compare", width=120):
                self._do_compare()
        else:
            imgui.text("No common functions found between selected libraries")
        
        imgui.separator()
        
        # Results display
        if self.compare_result:
            self._render_diff_view()
    
    def _render_diff_view(self):
        """Render the signature diff view."""
        imgui.begin_child("diff_view", 0, 0, border=True)
        
        # Header
        imgui.columns(3, "diff_header")
        imgui.text("Offset")
        imgui.next_column()
        imgui.text(f"Version {self.versions[self.compare_version1_idx]}")
        imgui.next_column()
        imgui.text(f"Version {self.versions[self.compare_version2_idx]}")
        imgui.columns(1)
        imgui.separator()
        
        # Display in rows of 16 bytes
        bytes_per_row = 16
        
        for row_start in range(0, len(self.compare_result), bytes_per_row):
            row_end = min(row_start + bytes_per_row, len(self.compare_result))
            row_data = self.compare_result[row_start:row_end]
            
            imgui.columns(3, f"diff_row_{row_start}")
            
            # Offset
            imgui.text(f"0x{row_start:04X}")
            imgui.next_column()
            
            # Version 1 bytes
            for diff_type, b1, b2 in row_data:
                if diff_type == "same":
                    imgui.text_colored(b1, 0.7, 0.7, 0.7, 1.0)
                elif diff_type == "wildcard":
                    imgui.text_colored(b1, 0.5, 0.5, 0.8, 1.0)
                else:  # diff
                    imgui.text_colored(b1, 1.0, 0.3, 0.3, 1.0)
                imgui.same_line()
            imgui.next_column()
            
            # Version 2 bytes
            for diff_type, b1, b2 in row_data:
                if diff_type == "same":
                    imgui.text_colored(b2, 0.7, 0.7, 0.7, 1.0)
                elif diff_type == "wildcard":
                    imgui.text_colored(b2, 0.5, 0.5, 0.8, 1.0)
                else:  # diff
                    imgui.text_colored(b2, 0.3, 1.0, 0.3, 1.0)
                imgui.same_line()
            
            imgui.columns(1)
        
        imgui.end_child()
        
        # Legend
        imgui.text("Legend: ")
        imgui.same_line()
        imgui.text_colored("Same", 0.7, 0.7, 0.7, 1.0)
        imgui.same_line()
        imgui.text_colored("Wildcard", 0.5, 0.5, 0.8, 1.0)
        imgui.same_line()
        imgui.text_colored("Different", 1.0, 0.5, 0.3, 1.0)
    
    def render_match_function_tab(self):
        """Render the function matching tab."""
        imgui.text("Match a function in your binary against SDK signatures")
        imgui.separator()
        
        # Binary path
        imgui.text("Binary File:")
        changed, self.func_binary_path = imgui.input_text("##func_binary_path", self.func_binary_path, 512)
        imgui.same_line()
        if imgui.button("Browse##func"):
            self.status_message = "File dialog not implemented - enter path manually"
        
        # Offset
        imgui.text("Function Offset (hex):")
        _, self.func_offset_str = imgui.input_text("##func_offset", self.func_offset_str, 32)
        
        # Library selector
        imgui.text("Library:")
        if not self.all_libraries:
            # Lazy load library list
            self.all_libraries = ["(All Libraries)"] + self.sdk_manager.get_all_library_names()
        
        _, self.func_library_idx = imgui.combo(
            "##func_library", self.func_library_idx, self.all_libraries
        )
        
        # Function name
        imgui.text("Function Name:")
        _, self.function_name = imgui.input_text("##func_name", self.function_name, 256)
        
        imgui.separator()
        
        if imgui.button("Find Matching Versions", width=200):
            self._do_match_function()
        
        imgui.separator()
        
        # Results
        if self.func_match_results:
            imgui.text(f"Found {len(self.func_match_results)} potential matches:")
            
            imgui.begin_child("func_match_results", 0, 200, border=True)
            
            imgui.columns(3, "func_match_columns")
            imgui.text("SDK Version")
            imgui.next_column()
            imgui.text("Library")
            imgui.next_column()
            imgui.text("Match %")
            imgui.columns(1)
            imgui.separator()
            
            for version, lib_name, match_pct in self.func_match_results:
                imgui.columns(3, f"func_match_{version}_{lib_name}")
                imgui.text(version)
                imgui.next_column()
                imgui.text(lib_name)
                imgui.next_column()
                
                # Color based on match percentage
                if match_pct >= 95:
                    imgui.text_colored(f"{match_pct:.1f}%", 0.3, 1.0, 0.3, 1.0)
                elif match_pct >= 80:
                    imgui.text_colored(f"{match_pct:.1f}%", 1.0, 1.0, 0.3, 1.0)
                else:
                    imgui.text_colored(f"{match_pct:.1f}%", 1.0, 0.5, 0.3, 1.0)
                
                imgui.columns(1)
            
            imgui.end_child()
        elif self.func_matching:
            imgui.text("Searching...")
    
    def _do_match_function(self):
        """Perform function matching."""
        if not self.func_binary_path or not self.function_name:
            self.status_message = "Please enter binary path and function name"
            return
        
        try:
            offset = int(self.func_offset_str, 16) if self.func_offset_str.startswith("0x") or any(c in self.func_offset_str.lower() for c in "abcdef") else int(self.func_offset_str, 16)
        except ValueError:
            try:
                offset = int(self.func_offset_str)
            except ValueError:
                self.status_message = "Invalid offset format"
                return
        
        if not os.path.exists(self.func_binary_path):
            self.status_message = f"File not found: {self.func_binary_path}"
            return
        
        # Get library filter (None if "All Libraries" selected)
        library_filter = None
        if self.func_library_idx > 0 and self.all_libraries:
            library_filter = self.all_libraries[self.func_library_idx]
        
        self.func_matching = True
        if library_filter:
            self.status_message = f"Searching for {self.function_name} in {library_filter}..."
        else:
            self.status_message = f"Searching for {self.function_name} in all libraries..."
        
        self.func_match_results = find_function_in_binary(
            self.func_binary_path, offset, self.function_name, self.sdk_manager,
            library_filter=library_filter
        )
        
        self.func_matching = False
        if self.func_match_results:
            self.status_message = f"Found {len(self.func_match_results)} potential matches"
        else:
            self.status_message = "No matches found"
    
    def _get_objects_for_library(self, library_name: str) -> list[str]:
        """Get list of object names for a library (union across all SDK versions that have it)."""
        object_names: set[str] = set()
    
        for version in self.versions:
            lib = self.sdk_manager.fetch_library(version, library_name)
            if not lib or not lib.objects:
                continue
    
            for obj in lib.objects:
                object_names.add(obj.name)
    
        return sorted(object_names)
    
    def render_match_object_tab(self):
        """Render the object matching tab."""
        imgui.text("Match an entire object in your binary against SDK signatures")
        imgui.text_colored("(More reliable than function matching - compares entire object)", 0.7, 0.7, 0.7, 1.0)
        imgui.separator()
        
        # Binary path
        imgui.text("Binary File:")
        changed, self.obj_binary_path = imgui.input_text("##obj_binary_path", self.obj_binary_path, 512)
        imgui.same_line()
        if imgui.button("Browse##obj"):
            self.status_message = "File dialog not implemented - enter path manually"
        
        # Offset
        imgui.text("Object Offset (hex):")
        _, self.obj_offset_str = imgui.input_text("##obj_offset", self.obj_offset_str, 32)
        
        # Library selector
        imgui.text("Library:")
        if not self.all_libraries:
            self.all_libraries = ["(All Libraries)"] + self.sdk_manager.get_all_library_names()
        
        # For object matching, we need a specific library (not "All")
        lib_list = self.all_libraries[1:] if len(self.all_libraries) > 1 else []
        if lib_list:
            changed_lib, self.obj_library_idx = imgui.combo(
                "##obj_library", self.obj_library_idx, lib_list
            )
            
            # Clamp index
            self.obj_library_idx = min(self.obj_library_idx, len(lib_list) - 1)
            
            # Update object list when library changes
            if changed_lib or not self.obj_objects_list:
                selected_lib = lib_list[self.obj_library_idx]
                self.obj_objects_list = self._get_objects_for_library(selected_lib)
                self.obj_object_idx = 0
        
        # Object selector
        imgui.text("Object:")
        if self.obj_objects_list:
            _, self.obj_object_idx = imgui.combo(
                "##obj_object", self.obj_object_idx, self.obj_objects_list
            )
            self.obj_object_idx = min(self.obj_object_idx, len(self.obj_objects_list) - 1)
        else:
            imgui.text_colored("(Select a library first)", 0.5, 0.5, 0.5, 1.0)
        
        imgui.separator()
        
        if self.obj_objects_list and imgui.button("Find Matching Versions", width=200):
            self._do_match_object()
        
        imgui.separator()
        
        # Results
        if self.obj_match_results:
            imgui.text(f"Found {len(self.obj_match_results)} potential matches:")
            
            imgui.begin_child("obj_match_results", 0, 200, border=True)
            
            imgui.columns(4, "obj_match_columns")
            imgui.text("SDK Version")
            imgui.next_column()
            imgui.text("Match %")
            imgui.next_column()
            imgui.text("Matched Bytes")
            imgui.next_column()
            imgui.text("Signature Size")
            imgui.columns(1)
            imgui.separator()
            
            for version, match_pct, matched, total in self.obj_match_results:
                imgui.columns(4, f"obj_match_{version}")
                imgui.text(version)
                imgui.next_column()
                
                # Color based on match percentage
                if match_pct >= 99:
                    imgui.text_colored(f"{match_pct:.1f}%", 0.3, 1.0, 0.3, 1.0)
                elif match_pct >= 95:
                    imgui.text_colored(f"{match_pct:.1f}%", 0.7, 1.0, 0.3, 1.0)
                elif match_pct >= 80:
                    imgui.text_colored(f"{match_pct:.1f}%", 1.0, 1.0, 0.3, 1.0)
                else:
                    imgui.text_colored(f"{match_pct:.1f}%", 1.0, 0.5, 0.3, 1.0)
                
                imgui.next_column()
                imgui.text(f"{matched}")
                imgui.next_column()
                imgui.text(f"{total}")
                imgui.columns(1)
            
            imgui.end_child()
        elif self.obj_matching:
            imgui.text("Searching...")
    
    def _do_match_object(self):
        """Perform object matching."""
        if not self.obj_binary_path:
            self.status_message = "Please enter binary path"
            return
        
        if not self.obj_objects_list:
            self.status_message = "Please select a library and object"
            return
        
        try:
            offset = int(self.obj_offset_str, 16) if self.obj_offset_str.startswith("0x") or any(c in self.obj_offset_str.lower() for c in "abcdef") else int(self.obj_offset_str, 16)
        except ValueError:
            try:
                offset = int(self.obj_offset_str)
            except ValueError:
                self.status_message = "Invalid offset format"
                return
        
        if not os.path.exists(self.obj_binary_path):
            self.status_message = f"File not found: {self.obj_binary_path}"
            return
        
        lib_list = self.all_libraries[1:] if len(self.all_libraries) > 1 else []
        if not lib_list:
            return
        
        library_name = lib_list[self.obj_library_idx]
        object_name = self.obj_objects_list[self.obj_object_idx]
        
        self.obj_matching = True
        self.status_message = f"Searching for {object_name} from {library_name}..."
        
        # Read binary data
        try:
            with open(self.obj_binary_path, "rb") as f:
                f.seek(offset)
                binary_data = f.read(0x10000)  # Read more for objects (64KB)
        except Exception as e:
            self.status_message = f"Failed to read binary: {e}"
            self.obj_matching = False
            return
        
        # Search across all SDK versions
        results = []
        for version in self.versions:
            lib = self.sdk_manager.fetch_library(version, library_name)
            if not lib:
                continue
            
            # Find the object
            for obj in lib.objects:
                if obj.name == object_name:
                    # Match against signature
                    parsed = parse_signature(obj.sig)
                    if not parsed:
                        continue
                    
                    matching_bytes = 0
                    total_concrete_bytes = 0
                    
                    for i, (expected, is_wildcard) in enumerate(parsed):
                        if i >= len(binary_data):
                            break
                        if is_wildcard:
                            continue
                        total_concrete_bytes += 1
                        if binary_data[i] == expected:
                            matching_bytes += 1
                    
                    if total_concrete_bytes > 0:
                        match_pct = (matching_bytes / total_concrete_bytes) * 100
                        results.append((version, match_pct, matching_bytes, total_concrete_bytes))
                    break
        
        # Sort by match percentage
        results.sort(key=lambda x: x[1], reverse=True)
        self.obj_match_results = results
        
        self.obj_matching = False
        if results:
            self.status_message = f"Found {len(results)} versions with matches"
        else:
            self.status_message = "No matches found"
    
    def render_find_function_tab(self):
        """Render the function search tab."""
        imgui.text("Search for a function to find which library/object it lives in")
        imgui.separator()
        
        # Function name input
        imgui.text("Function Name:")
        _, self.find_func_name = imgui.input_text("##find_func_name", self.find_func_name, 256)
        
        # Optional library filter
        imgui.text("Library Filter (optional):")
        if not self.all_libraries:
            self.all_libraries = ["(All Libraries)"] + self.sdk_manager.get_all_library_names()
        
        _, self.find_func_library_idx = imgui.combo(
            "##find_func_library", self.find_func_library_idx, self.all_libraries
        )
        
        imgui.separator()
        
        if imgui.button("Search", width=120):
            self._do_find_function()
        
        imgui.same_line()
        imgui.text_colored("(Searches all SDK versions)", 0.6, 0.6, 0.6, 1.0)
        
        imgui.separator()
        
        # Results
        if self.find_func_results:
            imgui.text(f"Found in {len(self.find_func_results)} location(s):")
            
            imgui.begin_child("find_func_results", 0, 300, border=True)
            
            imgui.columns(3, "find_func_columns")
            imgui.text("Library")
            imgui.next_column()
            imgui.text("Object")
            imgui.next_column()
            imgui.text("SDK Versions")
            imgui.columns(1)
            imgui.separator()
            
            for library, obj_name, versions in self.find_func_results:
                imgui.columns(3, f"find_{library}_{obj_name}")
                imgui.text(library)
                imgui.next_column()
                imgui.text(obj_name)
                imgui.next_column()
                
                # Always show all versions explicitly
                version_str = ", ".join(versions)
                imgui.text_wrapped(version_str)
                
                imgui.columns(1)
            
            imgui.end_child()
        elif self.find_func_searching:
            imgui.text("Searching...")
        elif self.find_func_name:
            imgui.text("No results. Click Search to find the function.")
    
    def _do_find_function(self):
        """Search for a function across all SDK versions."""
        if not self.find_func_name:
            self.status_message = "Please enter a function name"
            return
        
        self.find_func_searching = True
        self.status_message = f"Searching for {self.find_func_name}..."
        
        # Get library filter
        library_filter = None
        if self.find_func_library_idx > 0 and self.all_libraries:
            library_filter = self.all_libraries[self.find_func_library_idx]
        
        # Dict to collect: (library, object) -> [versions]
        location_versions: dict[tuple[str, str], list[str]] = {}
        
        for version in self.versions:
            if library_filter:
                libraries = [library_filter]
            else:
                libraries = self.sdk_manager.discover_libraries(version)
            
            for lib_name in libraries:
                lib = self.sdk_manager.fetch_library(version, lib_name)
                if not lib:
                    continue
                
                # Search for the function in this library
                for obj in lib.objects:
                    for label in obj.labels:
                        if label.name == self.find_func_name:
                            key = (lib_name, obj.name)
                            if key not in location_versions:
                                location_versions[key] = []
                            location_versions[key].append(version)
                            break  # Found in this object, move on
        
        # Convert to result list and sort
        results = []
        for (library, obj_name), versions in location_versions.items():
            # Sort versions by proper semantic versioning
            versions.sort(key=parse_sdk_version)
            results.append((library, obj_name, versions))
        
        # Sort results by library, then object
        results.sort(key=lambda x: (x[0], x[1]))
        
        self.find_func_results = results
        self.find_func_searching = False
        
        if results:
            total_versions = sum(len(v) for _, _, v in results)
            self.status_message = f"Found {self.find_func_name} in {len(results)} location(s) across {total_versions} version instances"
        else:
            self.status_message = f"Function {self.find_func_name} not found"
    
    def render_scan_tab(self):
        """Render the full binary scan tab."""
        imgui.text("Scan an entire binary to find all PSY-Q objects")
        imgui.text_colored(
            "Finds every SDK object in your binary with its offset and matching versions",
            0.7, 0.7, 0.7, 1.0
        )
        imgui.separator()
        
        # Binary path
        imgui.text("Binary File:")
        _, self.scan_binary_path = imgui.input_text("##scan_binary_path", self.scan_binary_path, 512)
        imgui.same_line()
        if imgui.button("Browse##scan"):
            self.status_message = "File dialog not implemented - enter path manually"
        
        # Library filter
        imgui.text("Library Filter (optional, speeds up preprocessing):")
        if not self.all_libraries:
            self.all_libraries = ["(All Libraries)"] + self.sdk_manager.get_all_library_names()
        
        changed_lib, self.scan_library_idx = imgui.combo(
            "##scan_library", self.scan_library_idx, self.all_libraries
        )
        if changed_lib:
            # Reset preprocessing when library filter changes
            self.scan_preprocessed = False
            self.scan_engine._preprocessed = False
            self.scan_results = []
        
        # Version filter
        imgui.text("SDK Version Filter (optional, for single-version search):")
        version_options = ["(All Versions)"] + self.versions
        changed_ver, self.scan_version_idx = imgui.combo(
            "##scan_version", self.scan_version_idx, version_options
        )
        if changed_ver:
            # Reset preprocessing when version filter changes
            self.scan_preprocessed = False
            self.scan_engine._preprocessed = False
            self.scan_results = []
        
        # Library version overrides (collapsible)
        if self.versions:
            expanded, _ = imgui.collapsing_header("Library Version Overrides")
            if expanded:
                imgui.text_colored(
                    "Override SDK version for specific libraries (e.g., LIBCARD uses 460 while others use 450)",
                    0.6, 0.6, 0.6, 1.0
                )
                
                # Always use the full library list from SDK (not filtered by scan results)
                # This ensures users can set overrides for libraries not yet found
                libraries_available = set()
                if self.all_libraries:
                    for lib in self.all_libraries:
                        if lib != "(All Libraries)":
                            libraries_available.add(lib)
                
                if libraries_available:
                    # Separate into .LIB and loose .OBJ files
                    lib_files = sorted([l for l in libraries_available if l.upper().endswith(".LIB")])
                    obj_files = sorted([l for l in libraries_available if l.upper().endswith(".OBJ")])
                    sorted_libs = lib_files + obj_files
                    
                    # Show in scrollable area
                    height = min(180, 25 * len(sorted_libs))
                    imgui.begin_child("version_overrides_scan", 0, height, border=True)
                    
                    for lib in sorted_libs:
                        current_override = self.lib_version_overrides.get(lib, "")
                        
                        # Display name: mark loose OBJ files
                        if lib.upper().endswith(".OBJ"):
                            display_lib = f"{lib} (loose)"
                        else:
                            display_lib = lib
                        
                        imgui.text(f"{display_lib}:")
                        imgui.same_line()
                        imgui.set_next_item_width(80)
                        
                        # Version dropdown
                        versions_with_default = ["(default)"] + self.versions
                        current_idx = 0
                        if current_override and current_override in self.versions:
                            current_idx = self.versions.index(current_override) + 1
                        
                        changed, new_idx = imgui.combo(
                            f"##scanver_{lib}", current_idx, versions_with_default
                        )
                        if changed:
                            if new_idx == 0:
                                if lib in self.lib_version_overrides:
                                    del self.lib_version_overrides[lib]
                            else:
                                self.lib_version_overrides[lib] = self.versions[new_idx - 1]
                            # Invalidate preprocessing when overrides change
                            self.scan_preprocessed = False
                            self.scan_engine._preprocessed = False
                            self.scan_results = []
                    
                    imgui.end_child()
                    
                    if self.lib_version_overrides:
                        if self.scan_preprocessed:
                            # Already preprocessed with these overrides
                            imgui.text_colored(
                                f"{len(self.lib_version_overrides)} override(s) applied",
                                0.3, 1.0, 0.3, 1.0
                            )
                        else:
                            # Need to preprocess to apply
                            imgui.text_colored(
                                f"{len(self.lib_version_overrides)} override(s) - will apply on preprocess",
                                0.8, 0.8, 0.3, 1.0
                            )
        
        # Alignment option
        _, self.scan_align_to_4 = imgui.checkbox("Require 4-byte alignment (MIPS)", self.scan_align_to_4)
        imgui.same_line()
        imgui.text_colored("(?)", 0.5, 0.5, 0.5, 1.0)
        if imgui.is_item_hovered():
            imgui.set_tooltip(
                "PS1 uses MIPS R3000 with 4-byte aligned instructions.\n"
                "Disabling this checks every byte offset (slower, rarely needed)."
            )
        
        imgui.separator()
        
        # Preprocess button
        if not self.scan_preprocessed:
            if imgui.button("1. Preprocess Signatures", width=220):
                self._do_scan_preprocess()
            imgui.same_line()
            imgui.text_colored("(Downloads & deduplicates all signatures)", 0.5, 0.5, 0.5, 1.0)
        else:
            imgui.text_colored(
                f"Signatures ready: {self.scan_engine.signature_count} unique patterns",
                0.3, 1.0, 0.3, 1.0
            )
            imgui.same_line()
            if imgui.small_button("Re-preprocess"):
                self.scan_preprocessed = False
                self.scan_engine._preprocessed = False
                self.scan_results = []
        
        # Scan button
        if self.scan_preprocessed and self.scan_binary_path:
            if imgui.button("2. Scan Binary", width=220):
                self._do_scan()
        elif self.scan_preprocessed:
            imgui.text_colored("Enter a binary path above to scan", 0.8, 0.6, 0.3, 1.0)
        
        imgui.separator()
        
        # Progress
        if self.scan_running:
            imgui.text(self.scan_engine.progress_message)
            imgui.progress_bar(self.scan_engine.progress_pct, (-1, 0))
        
        # Results
        if self.scan_results:
            ambiguous_count = sum(1 for r in self.scan_results if r.is_ambiguous)
            fp_count = sum(
                1 for r in self.scan_results
                if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                    self.scan_binary_fingerprint, r.offset, r.library, r.object_name
                )
            )
            
            summary = f"Found {len(self.scan_results)} objects in binary"
            if ambiguous_count:
                summary += f" ({ambiguous_count} ambiguous)"
            if fp_count:
                summary += f" [{fp_count} hidden as false positive]"
            imgui.text(summary)
            
            # Filter row
            imgui.text("Filter:")
            imgui.same_line()
            _, self.scan_filter_text = imgui.input_text(
                "##scan_filter", self.scan_filter_text, 256
            )
            imgui.same_line()
            if imgui.small_button("Export CSV"):
                self._export_scan_results()
            imgui.same_line()
            if imgui.small_button("Export TXT"):
                self._export_scan_results_txt()
            imgui.same_line()
            if imgui.small_button("Export JSON"):
                self._export_scan_results_json()
            
            # FP controls row
            _, self.scan_show_false_positives = imgui.checkbox(
                "Show false positives", self.scan_show_false_positives
            )
            if fp_count:
                imgui.same_line()
                if imgui.small_button("Clear all FPs for this binary"):
                    self.fp_store.clear_for_binary(self.scan_binary_fingerprint)
            
            # Filtered results
            filter_lower = self.scan_filter_text.lower()
            filtered = []
            for r in self.scan_results:
                is_fp = (
                    self.scan_binary_fingerprint
                    and self.fp_store.is_false_positive(
                        self.scan_binary_fingerprint, r.offset, r.library, r.object_name
                    )
                )
                
                # Skip FPs unless showing them
                if is_fp and not self.scan_show_false_positives:
                    continue
                
                # Apply text filter
                if filter_lower:
                    if not (
                        filter_lower in r.library.lower()
                        or filter_lower in r.object_name.lower()
                        or any(filter_lower in v for v in r.versions)
                        or any(filter_lower in lbl.name.lower() for lbl in r.labels)
                        or (filter_lower == "ambiguous" and r.is_ambiguous)
                        or (filter_lower == "duplicate" and r.is_duplicate)
                        or (filter_lower == "overlap" and r.is_overlap)
                        or (filter_lower == "false positive" and is_fp)
                    ):
                        continue
                
                # For ambiguous results, expand into separate lines (one per version group)
                # so user can mark individual groups as false positive
                if r.is_ambiguous and len(r.version_groups) > 1:
                    for vg_idx, vg in enumerate(r.version_groups):
                        # Create a pseudo-key for FP tracking that includes version group
                        vg_versions_str = ",".join(sorted(vg.versions))
                        is_vg_fp = (
                            self.scan_binary_fingerprint
                            and self.fp_store.is_false_positive(
                                self.scan_binary_fingerprint, 
                                r.offset, r.library, r.object_name,
                                vg_versions_str
                            )
                        )
                        if is_vg_fp and not self.scan_show_false_positives:
                            continue
                        filtered.append((r, is_vg_fp, vg_idx, vg))
                else:
                    filtered.append((r, is_fp, -1, None))
            
            # Count stats
            ambiguous_lines = sum(1 for f in filtered if f[2] >= 0)
            duplicate_count = sum(1 for f in filtered if f[0].is_duplicate)
            overlap_count = sum(1 for f in filtered if f[0].is_overlap)
            
            imgui.text(f"Showing {len(filtered)} lines ({len(self.scan_results)} objects)")
            if ambiguous_lines > 0:
                imgui.same_line()
                imgui.text_colored(f"[{ambiguous_lines} ambiguous]", 1.0, 0.9, 0.3, 1.0)
            if duplicate_count > 0:
                imgui.same_line()
                imgui.text_colored(f"[{duplicate_count} duplicates]", 1.0, 0.6, 0.3, 1.0)
            if overlap_count > 0:
                imgui.same_line()
                imgui.text_colored(f"[{overlap_count} overlaps]", 0.9, 0.4, 0.9, 1.0)
            imgui.same_line()
            imgui.text_colored(
                "(filter: 'ambiguous', 'duplicate', 'overlap', 'false positive')",
                0.5, 0.5, 0.5, 1.0
            )
            
            imgui.begin_child("scan_results", 0, 0, border=True)
            
            # Header
            imgui.columns(6, "scan_columns")
            imgui.set_column_width(0, 35)   # Action
            imgui.set_column_width(1, 90)   # Offset
            imgui.set_column_width(2, 130)  # Library
            imgui.set_column_width(3, 140)  # Object
            imgui.set_column_width(4, 80)   # Size
            imgui.text("")
            imgui.next_column()
            imgui.text("Offset")
            imgui.next_column()
            imgui.text("Library")
            imgui.next_column()
            imgui.text("Object")
            imgui.next_column()
            imgui.text("Size")
            imgui.next_column()
            imgui.text("SDK Versions (Functions)")
            imgui.columns(1)
            imgui.separator()
            
            for entry in filtered:
                result, is_fp, vg_idx, vg = entry
                is_ambiguous_line = vg_idx >= 0
                
                # For ambiguous lines, use a version-specific key
                if is_ambiguous_line:
                    vg_versions_str = ",".join(sorted(vg.versions))
                    row_id = f"scan_{result.offset:X}_{result.object_name}_{vg_idx}"
                    fp_extra = vg_versions_str
                    display_versions = vg.versions
                    display_size = vg.sig_length
                else:
                    row_id = f"scan_{result.offset:X}_{result.object_name}"
                    fp_extra = None
                    display_versions = result.versions
                    display_size = result.sig_length
                
                imgui.columns(6, row_id)
                imgui.set_column_width(0, 35)
                imgui.set_column_width(1, 90)
                imgui.set_column_width(2, 130)
                imgui.set_column_width(3, 140)
                imgui.set_column_width(4, 80)
                
                # Action column: FP toggle button
                if is_fp:
                    if imgui.small_button(f"+##{row_id}"):
                        self.fp_store.unmark(
                            self.scan_binary_fingerprint,
                            result.offset, result.library, result.object_name,
                            fp_extra
                        )
                    if imgui.is_item_hovered():
                        imgui.set_tooltip("Restore (unmark as false positive)")
                else:
                    if imgui.small_button(f"X##{row_id}"):
                        self.fp_store.mark(
                            self.scan_binary_fingerprint,
                            result.offset, result.library, result.object_name,
                            fp_extra
                        )
                    if imgui.is_item_hovered():
                        imgui.set_tooltip("Mark as false positive")
                imgui.next_column()
                
                # Offset — color coded by status
                # Magenta for overlap, orange for duplicate, yellow for ambiguous, gray for FP
                if is_fp:
                    imgui.text_colored(f"0x{result.offset:08X}", 0.5, 0.5, 0.5, 1.0)
                elif result.is_overlap:
                    imgui.text_colored(f"0x{result.offset:08X}", 0.9, 0.4, 0.9, 1.0)
                elif result.is_duplicate:
                    imgui.text_colored(f"0x{result.offset:08X}", 1.0, 0.6, 0.3, 1.0)
                elif is_ambiguous_line:
                    imgui.text_colored(f"0x{result.offset:08X}", 1.0, 0.9, 0.3, 1.0)
                else:
                    imgui.text(f"0x{result.offset:08X}")
                imgui.next_column()
                
                if is_fp:
                    imgui.text_colored(result.library, 0.5, 0.5, 0.5, 1.0)
                else:
                    imgui.text(result.library)
                imgui.next_column()
                
                if is_fp:
                    imgui.text_colored(result.object_name, 0.5, 0.5, 0.5, 1.0)
                else:
                    imgui.text(result.object_name)
                imgui.next_column()
                
                # Size column
                size_text = f"0x{display_size:X}"
                if is_fp:
                    imgui.text_colored(size_text, 0.5, 0.5, 0.5, 1.0)
                elif is_ambiguous_line:
                    imgui.text_colored(size_text, 1.0, 0.9, 0.3, 1.0)
                else:
                    imgui.text(size_text)
                imgui.next_column()
                
                # Versions column - with dynamic overlap/duplicate checking
                if is_fp:
                    imgui.text_colored("[FALSE POSITIVE]", 0.5, 0.5, 0.5, 1.0)
                    version_str = ", ".join(display_versions)
                    imgui.text_colored(f"  {version_str}", 0.4, 0.4, 0.4, 1.0)
                else:
                    # Check for active (non-FP) overlaps
                    active_overlaps = []
                    if result.is_overlap:
                        for lib, obj in result.overlap_objects:
                            if not self.fp_store.is_false_positive(
                                self.scan_binary_fingerprint, result.offset, lib, obj
                            ):
                                active_overlaps.append((lib, obj))
                    
                    # Check for active (non-FP) duplicates
                    active_duplicates = []
                    if result.is_duplicate:
                        for dup_offset in result.duplicate_offsets:
                            if not self.fp_store.is_false_positive(
                                self.scan_binary_fingerprint, dup_offset, result.library, result.object_name
                            ):
                                active_duplicates.append(dup_offset)
                    
                    # Show status based on what's still active
                    if active_overlaps:
                        overlap_str = ", ".join(f"{lib}/{obj}" for lib, obj in active_overlaps)
                        imgui.text_colored(f"[OVERLAP - same addr as {overlap_str}]", 0.9, 0.4, 0.9, 1.0)
                        version_str = ", ".join(display_versions)
                        imgui.text_wrapped(version_str)
                    elif active_duplicates:
                        other_offsets = ", ".join(f"0x{o:X}" for o in active_duplicates)
                        imgui.text_colored(f"[DUPLICATE - also at {other_offsets}]", 1.0, 0.6, 0.3, 1.0)
                        version_str = ", ".join(display_versions)
                        imgui.text_wrapped(version_str)
                    elif is_ambiguous_line:
                        imgui.text_colored("[AMBIGUOUS - mark others as FP]", 1.0, 0.9, 0.3, 1.0)
                        version_str = ", ".join(display_versions)
                        imgui.text_colored(f"  {version_str}", 0.9, 0.85, 0.5, 1.0)
                    else:
                        version_str = ", ".join(display_versions)
                        imgui.text_wrapped(version_str)
                
                # Show function labels in this object (only for non-ambiguous or first ambiguous line)
                if not is_fp and (not is_ambiguous_line or vg_idx == 0):
                    func_labels = [
                        l for l in result.labels
                        if not (l.name.startswith("loc_") or l.name.startswith("text_"))
                    ]
                
                    if func_labels:
                        for lbl in func_labels:
                            imgui.text_colored(
                                f"  {lbl.name} (+0x{lbl.offset:X} = 0x{result.offset + lbl.offset:08X})",
                                0.5, 0.8, 1.0, 1.0
                            )
                
                imgui.columns(1)
                imgui.separator()
            
            imgui.end_child()
    
    def _render_section_list(self, section: str, section_list: list[dict]):
        """Render the section ordering and offset resolution UI."""
        if not section_list:
            imgui.text_colored(f"No objects with {section} sections found", 0.6, 0.6, 0.6, 1.0)
            return
        
        # Count resolved
        resolved_count = sum(1 for e in section_list if e["offset"] is not None)
        imgui.text(f"{resolved_count}/{len(section_list)} offsets resolved")
        
        # Chain all button
        if resolved_count > 0 and resolved_count < len(section_list):
            imgui.same_line()
            if imgui.button(f"Chain All##{section}"):
                for i in range(len(section_list)):
                    if section_list[i]["offset"] is None and i > 0:
                        self._chain_section_offset(section_list, i)
        
        # Clear all button
        if resolved_count > 0:
            imgui.same_line()
            if imgui.button(f"Clear All##{section}"):
                for e in section_list:
                    e["offset"] = None
        
        imgui.begin_child(f"section_list_{section}", 0, 350, border=True)
        
        # Header
        imgui.columns(7, f"sec_cols_{section}")
        imgui.set_column_width(0, 50)   # Move
        imgui.set_column_width(1, 100)  # Library
        imgui.set_column_width(2, 100)  # Object
        imgui.set_column_width(3, 60)   # Size
        imgui.set_column_width(4, 90)   # Offset
        imgui.set_column_width(5, 60)   # Match%
        imgui.text("Move")
        imgui.next_column()
        imgui.text("Library")
        imgui.next_column()
        imgui.text("Object")
        imgui.next_column()
        imgui.text("Size")
        imgui.next_column()
        imgui.text("Offset")
        imgui.next_column()
        imgui.text("Match")
        imgui.next_column()
        imgui.text("Actions")
        imgui.columns(1)
        imgui.separator()
        
        for idx, entry in enumerate(section_list):
            row_id = f"{section}_{idx}_{entry['library']}_{entry['object']}"
            
            imgui.columns(7, row_id)
            imgui.set_column_width(0, 50)
            imgui.set_column_width(1, 100)
            imgui.set_column_width(2, 100)
            imgui.set_column_width(3, 60)
            imgui.set_column_width(4, 90)
            imgui.set_column_width(5, 60)
            
            # Move buttons - use ^ and v to conserve space
            if idx > 0:
                if imgui.small_button(f"^##{row_id}"):
                    self._move_section_entry(section_list, idx, -1)
            if idx < len(section_list) - 1:
                if idx > 0:
                    imgui.same_line()
                if imgui.small_button(f"v##{row_id}"):
                    self._move_section_entry(section_list, idx, 1)
            imgui.next_column()
            
            # Library
            lib_display = entry["library"] if entry["library"] else "(loose)"
            imgui.text(lib_display)
            imgui.next_column()
            
            # Object
            imgui.text(entry["object"])
            imgui.next_column()
            
            # Size
            imgui.text(f"0x{entry['size']:X}")
            imgui.next_column()
            
            # Offset
            if entry["offset"] is not None:
                imgui.text_colored(f"0x{entry['offset']:X}", 0.3, 1.0, 0.3, 1.0)
            else:
                imgui.text_colored("auto", 0.5, 0.5, 0.5, 1.0)
            imgui.next_column()
            
            # Match percentage (verify if offset is set)
            match_pct = 0.0
            if entry["offset"] is not None:
                match_pct, _, _ = self._verify_section_at_offset(
                    entry["library"], entry["object"], section, entry["offset"]
                )
                if match_pct >= 99.9:
                    imgui.text_colored(f"{match_pct:.1f}%", 0.3, 1.0, 0.3, 1.0)
                elif match_pct >= 90:
                    imgui.text_colored(f"{match_pct:.1f}%", 0.8, 1.0, 0.3, 1.0)
                else:
                    imgui.text_colored(f"{match_pct:.1f}%", 1.0, 0.5, 0.3, 1.0)
            else:
                imgui.text("-")
            imgui.next_column()
            
            # Actions
            if imgui.small_button(f"Search##{row_id}"):
                self._search_single_section(entry["library"], entry["object"], section)
            imgui.same_line()
            
            if idx > 0 and section_list[idx - 1]["offset"] is not None:
                if imgui.small_button(f"Chain##{row_id}"):
                    self._chain_section_offset(section_list, idx)
                imgui.same_line()
            
            if imgui.small_button(f"Set##{row_id}"):
                # Toggle manual input mode
                if not hasattr(self, '_manual_input_key') or self._manual_input_key != row_id:
                    self._manual_input_key = row_id
                    self._manual_input_str = f"0x{entry['offset']:X}" if entry["offset"] else "0x"
                else:
                    self._manual_input_key = None
            
            if entry["offset"] is not None:
                imgui.same_line()
                if imgui.small_button(f"X##{row_id}"):
                    entry["offset"] = None
                
                # Show diff button for non-perfect matches
                if match_pct < 99.9:
                    imgui.same_line()
                    if imgui.small_button(f"Diff##{row_id}"):
                        self._compute_section_diff(entry["library"], entry["object"], section, entry["offset"])
            
            imgui.columns(1)
            
            # Manual input row
            if hasattr(self, '_manual_input_key') and self._manual_input_key == row_id:
                imgui.indent()
                imgui.text("Offset:")
                imgui.same_line()
                imgui.set_next_item_width(100)
                _, self._manual_input_str = imgui.input_text(f"##manual_{row_id}", self._manual_input_str, 32)
                imgui.same_line()
                if imgui.small_button(f"Apply##{row_id}"):
                    try:
                        # Parse hex or decimal
                        val_str = self._manual_input_str.strip()
                        if val_str.startswith("0x") or val_str.startswith("0X"):
                            entry["offset"] = int(val_str, 16)
                        else:
                            entry["offset"] = int(val_str)
                        self._manual_input_key = None
                        self.status_message = f"Set offset to 0x{entry['offset']:X}"
                    except ValueError:
                        self.status_message = "Invalid offset format (use 0x1234 or decimal)"
                imgui.same_line()
                if imgui.small_button(f"Cancel##{row_id}"):
                    self._manual_input_key = None
                imgui.unindent()
            
            # Show search results if this is the current search
            if self.section_search_key == (entry["library"], entry["object"], section) and self.section_search_results:
                imgui.indent()
                imgui.text_colored("Search results:", 0.6, 0.6, 0.6, 1.0)
                for offset, match_pct in self.section_search_results[:5]:
                    if match_pct >= 99.9:
                        color = (0.3, 1.0, 0.3, 1.0)
                    elif match_pct >= 90:
                        color = (0.8, 1.0, 0.3, 1.0)
                    else:
                        color = (1.0, 0.8, 0.3, 1.0)
                    
                    imgui.text_colored(f"  0x{offset:08X} ({match_pct:.1f}%)", *color)
                    imgui.same_line()
                    if imgui.small_button(f"Use##use_{offset}_{row_id}"):
                        entry["offset"] = offset
                        self.section_search_results = []
                        self.section_search_key = ("", "", "")
                imgui.unindent()
            
            # Show inline diff if this is the current diff
            if (self.section_diff_data and 
                self.section_diff_key == (entry["library"], entry["object"], section, entry["offset"])):
                self._render_inline_diff()
            
            imgui.separator()
        
        imgui.end_child()
    
    def _render_inline_diff(self):
        """Render inline diff display for section comparison."""
        diff = self.section_diff_data
        if not diff:
            return
        
        imgui.indent()
        
        # Header with close button
        imgui.text_colored(f"Diff: {diff['library']}/{diff['object']} {diff['section']}", 0.4, 0.8, 1.0, 1.0)
        imgui.same_line()
        if imgui.small_button("Close##diff"):
            self.section_diff_data = None
            self.section_diff_key = ("", "", "", 0)
            imgui.unindent()
            return
        
        # Summary
        imgui.text(f"Version: {diff['version_used']}  |  Size: 0x{diff['section_size']:X}")
        imgui.text(f"Match: {diff['match_count']}  Mismatch: {diff['mismatch_count']}  Wildcard: {diff['wildcard_count']}")
        
        if diff['mismatch_count'] > 0:
            imgui.text_colored(f"Match: {diff['match_pct']:.1f}%", 1.0, 0.5, 0.3, 1.0)
        else:
            imgui.text_colored(f"Match: {diff['match_pct']:.1f}%", 0.3, 1.0, 0.3, 1.0)
        
        # Mismatch list
        if diff['mismatches']:
            imgui.text_colored(f"Mismatches ({diff['total_mismatches']} total):", 1.0, 0.7, 0.3, 1.0)
            for mm in diff['mismatches'][:10]:
                imgui.text(f"  @0x{mm['offset']:04X} (bin 0x{mm['binary_offset']:08X}): "
                          f"obj=0x{mm['obj_byte']:02X} bin=0x{mm['bin_byte']:02X}")
            if diff['total_mismatches'] > 10:
                imgui.text_colored(f"  ... and {diff['total_mismatches'] - 10} more", 0.5, 0.5, 0.5, 1.0)
        
        # Hex comparison (first 128 bytes or around first mismatch)
        imgui.text_colored("Hex comparison:", 0.6, 0.6, 0.6, 1.0)
        
        obj_data = diff['obj_data']
        bin_data = diff['bin_data']
        mask = diff['mask']
        section_size = min(diff['section_size'], 128)  # Limit display
        
        # Find first mismatch to center view
        start_offset = 0
        if diff['mismatches']:
            first_mm = diff['mismatches'][0]['offset']
            start_offset = max(0, (first_mm // 16) * 16 - 16)  # Start one row before
            if start_offset + 128 > diff['section_size']:
                start_offset = max(0, diff['section_size'] - 128)
        
        for row_start in range(start_offset, min(start_offset + 128, diff['section_size']), 16):
            # Build row display
            imgui.text(f"0x{row_start:04X} ")
            imgui.same_line()
            
            for i in range(16):
                idx = row_start + i
                if idx >= diff['section_size']:
                    break
                
                obj_b = obj_data[idx] if idx < len(obj_data) else 0
                bin_b = bin_data[idx] if idx < len(bin_data) else 0
                is_wildcard = mask[idx] == 0x00
                
                if is_wildcard:
                    # Wildcard - gray
                    imgui.text_colored(f"{obj_b:02X}", 0.4, 0.4, 0.4, 1.0)
                elif obj_b != bin_b:
                    # Mismatch - red for obj, green for bin
                    imgui.text_colored(f"{obj_b:02X}", 1.0, 0.3, 0.3, 1.0)
                else:
                    # Match - white
                    imgui.text(f"{obj_b:02X}")
                
                imgui.same_line()
            
            imgui.text(" | ")
            imgui.same_line()
            
            for i in range(16):
                idx = row_start + i
                if idx >= diff['section_size']:
                    break
                
                obj_b = obj_data[idx] if idx < len(obj_data) else 0
                bin_b = bin_data[idx] if idx < len(bin_data) else 0
                is_wildcard = mask[idx] == 0x00
                
                if is_wildcard:
                    imgui.text_colored(f"{bin_b:02X}", 0.4, 0.4, 0.4, 1.0)
                elif obj_b != bin_b:
                    imgui.text_colored(f"{bin_b:02X}", 0.3, 1.0, 0.3, 1.0)
                else:
                    imgui.text(f"{bin_b:02X}")
                
                imgui.same_line()
            
            imgui.text("")  # End the line
        
        imgui.text_colored("(obj bytes | bin bytes, red=obj mismatch, green=bin mismatch, gray=wildcard)", 0.5, 0.5, 0.5, 1.0)
        
        imgui.unindent()
    
    def render_enrich_tab(self):
        """Render the enrichment and export tab."""
        imgui.text("Enrich scan results with ELF section data and export for Splat")
        imgui.separator()
        
        # Check pyelftools availability
        if not PYELFTOOLS_AVAILABLE:
            imgui.text_colored(
                "pyelftools not installed - run: pip install pyelftools",
                1.0, 0.5, 0.3, 1.0
            )
            imgui.text_colored(
                "This is required for reading ELF object files on all platforms.",
                0.6, 0.6, 0.6, 1.0
            )
            imgui.separator()
        
        # Check if we have scan results
        if not self.scan_results:
            imgui.text_colored(
                "No scan results available. Run a scan in the 'Scan Binary' tab first.",
                0.8, 0.6, 0.3, 1.0
            )
            return
        
        # Show scan summary
        fp_count = sum(
            1 for r in self.scan_results
            if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                self.scan_binary_fingerprint, r.offset, r.library, r.object_name
            )
        )
        ambiguous_count = sum(1 for r in self.scan_results if r.is_ambiguous)
        non_fp_ambiguous = sum(
            1 for r in self.scan_results
            if r.is_ambiguous and not (
                self.scan_binary_fingerprint
                and self.fp_store.is_false_positive(
                    self.scan_binary_fingerprint, r.offset, r.library, r.object_name
                )
            )
        )
        valid_count = len(self.scan_results) - fp_count
        
        imgui.text(f"Scan results: {len(self.scan_results)} objects ({valid_count} valid, {fp_count} marked as FP)")
        
        if non_fp_ambiguous > 0:
            imgui.text_colored(
                f"Warning: {non_fp_ambiguous} ambiguous entries need resolution before Splat export",
                1.0, 0.7, 0.3, 1.0
            )
            imgui.text_colored(
                "Mark false positives (X button) in Scan Binary tab, or filter to a single SDK version",
                0.6, 0.6, 0.6, 1.0
            )
        
        version_filter = None
        if self.scan_version_idx > 0 and self.versions:
            version_filter = self.versions[self.scan_version_idx - 1]
            imgui.text(f"SDK Version filter: {version_filter}")
        else:
            imgui.text_colored(
                "Tip: Select a specific SDK version in Scan Binary tab for best results",
                0.6, 0.6, 0.6, 1.0
            )
        
        imgui.separator()
        
        # === Enrichment Section ===
        imgui.text_colored("Step 1: Enrich with ELF data", 0.4, 0.8, 1.0, 1.0)
        
        imgui.text("PSY-Q Object Files Root:")
        imgui.same_line()
        imgui.text_colored("(?)", 0.5, 0.5, 0.5, 1.0)
        if imgui.is_item_hovered():
            imgui.set_tooltip(
                "Path to directory containing PSY-Q .o files.\n"
                "Expected structures:\n"
                "  {root}/assets/psyq/{version}/obj/{lib}/{obj}.o  (decomp project)\n"
                "  {root}/{version}/obj/{lib}/{obj}.o              (standalone)\n"
                "Example: ~/chrono-cross-decomp or ~/psyq"
            )
        
        _, self.enrich_repo_root = imgui.input_text(
            "##enrich_repo_root", self.enrich_repo_root, 512
        )
        
        # Enrich button
        if PYELFTOOLS_AVAILABLE and self.enrich_repo_root and version_filter:
            if imgui.button("Enrich with ELF data", width=180):
                self._do_enrich()
            
            if self.enrich_data:
                imgui.same_line()
                imgui.text_colored(
                    f"Enriched: {len(self.enrich_data)} objects",
                    0.3, 1.0, 0.3, 1.0
                )
                if self.enrich_errors:
                    imgui.same_line()
                    imgui.text_colored(
                        f"({len(self.enrich_errors)} errors)",
                        1.0, 0.5, 0.3, 1.0
                    )
                    if imgui.is_item_hovered():
                        # Show first few errors in tooltip
                        error_text = "\n".join(self.enrich_errors[:5])
                        if len(self.enrich_errors) > 5:
                            error_text += f"\n... and {len(self.enrich_errors) - 5} more"
                        imgui.set_tooltip(error_text)
        elif not PYELFTOOLS_AVAILABLE:
            imgui.text_colored(
                "Install pyelftools to enable enrichment",
                0.5, 0.5, 0.5, 1.0
            )
        elif not version_filter:
            imgui.text_colored(
                "Select a specific SDK version in Scan Binary tab to enable enrichment",
                0.5, 0.5, 0.5, 1.0
            )
        else:
            imgui.text_colored(
                "Enter PSY-Q object files path above",
                0.5, 0.5, 0.5, 1.0
            )
        
        imgui.separator()
        
        # === Section Ordering (new approach) ===
        if self.data_section_list or self.rdata_section_list:
            imgui.text_colored("Step 2: Data Section Offsets", 0.4, 0.8, 1.0, 1.0)
            imgui.text_colored(
                "Resolve offsets for .data/.rdata sections. Reorder if needed, then search or chain offsets.",
                0.6, 0.6, 0.6, 1.0
            )
            
            # Tabs for .data and .rdata
            if imgui.begin_tab_bar("section_tabs"):
                if imgui.begin_tab_item(".data")[0]:
                    self._render_section_list(".data", self.data_section_list)
                    imgui.end_tab_item()
                
                if imgui.begin_tab_item(".rdata")[0]:
                    self._render_section_list(".rdata", self.rdata_section_list)
                    imgui.end_tab_item()
                
                imgui.end_tab_bar()
            
            imgui.separator()
        
        # === Legacy Block Analysis Section (for transition) ===
        if self.blocks:
            imgui.text_colored("Step 2: Resolve .data/.rdata Block Offsets", 0.4, 0.8, 1.0, 1.0)
            imgui.text_colored(
                f"Found {len(self.blocks)} contiguous block(s). Resolve block start offsets to enable precise .data/.rdata export.",
                0.6, 0.6, 0.6, 1.0
            )
            
            # Count resolved blocks
            data_resolved = len(self.block_data_offsets)
            rdata_resolved = len(self.block_rdata_offsets)
            blocks_with_data = sum(1 for b in self.blocks if b["total_data_size"] > 0)
            blocks_with_rdata = sum(1 for b in self.blocks if b["total_rdata_size"] > 0)
            
            imgui.text(f".data: {data_resolved}/{blocks_with_data} blocks resolved")
            imgui.same_line()
            imgui.text(f"  |  .rdata: {rdata_resolved}/{blocks_with_rdata} blocks resolved")
            
            imgui.separator()
            
            imgui.begin_child("block_analysis", 0, 300, border=True)
            
            for block_idx, block in enumerate(self.blocks):
                block_id = f"block_{block_idx}"
                
                # Block header
                obj_count = len(block["objects"])
                first_obj = block["objects"][0]
                last_obj = block["objects"][-1]
                
                header = f"Block {block_idx + 1}: {obj_count} objects (0x{block['text_start']:X} - 0x{block['text_end']:X})"
                if block["gap_before"] > 0:
                    header += f" [gap: 0x{block['gap_before']:X}]"
                
                expanded, _ = imgui.collapsing_header(header)
                
                if expanded:
                    imgui.indent()
                    
                    # Show objects in this block
                    imgui.text("Objects:")
                    for i, r in enumerate(block["objects"][:5]):  # Show first 5
                        imgui.text_colored(f"  {r.library} / {r.object_name}", 0.6, 0.6, 0.6, 1.0)
                    if obj_count > 5:
                        imgui.text_colored(f"  ... and {obj_count - 5} more", 0.5, 0.5, 0.5, 1.0)
                    
                    imgui.text(f"Total .data size: 0x{block['total_data_size']:X}")
                    imgui.text(f"Total .rdata size: 0x{block['total_rdata_size']:X}")
                    
                    imgui.separator()
                    
                    # .data resolution
                    if block["total_data_size"] > 0:
                        data_offset = self.block_data_offsets.get(block_idx)
                        if data_offset is not None:
                            imgui.text_colored(f".data start: 0x{data_offset:X} ✓", 0.3, 1.0, 0.3, 1.0)
                            imgui.same_line()
                            if imgui.small_button(f"Clear##data_{block_id}"):
                                del self.block_data_offsets[block_idx]
                        else:
                            if imgui.button(f"Search .data##data_{block_id}", width=120):
                                self._search_block_section(block_idx, ".data")
                            
                            imgui.same_line()
                            imgui.text("or enter manually:")
                            imgui.same_line()
                            imgui.set_next_item_width(100)
                            # Manual entry - use a simple approach
                            if imgui.button(f"Set...##setdata_{block_id}"):
                                # For now, use first search result or prompt
                                pass
                    
                    # .rdata resolution
                    if block["total_rdata_size"] > 0:
                        rdata_offset = self.block_rdata_offsets.get(block_idx)
                        if rdata_offset is not None:
                            imgui.text_colored(f".rdata start: 0x{rdata_offset:X} ✓", 0.3, 1.0, 0.3, 1.0)
                            imgui.same_line()
                            if imgui.small_button(f"Clear##rdata_{block_id}"):
                                del self.block_rdata_offsets[block_idx]
                        else:
                            if imgui.button(f"Search .rdata##rdata_{block_id}", width=120):
                                self._search_block_section(block_idx, ".rdata")
                    
                    # Show search results if this is the current block being searched
                    if self.current_block_idx == block_idx and self.block_search_results:
                        imgui.separator()
                        imgui.text(f"Search results for {self.current_section_type}:")
                        
                        for offset, match_pct in self.block_search_results[:10]:
                            if match_pct >= 99.9:
                                color = (0.3, 1.0, 0.3, 1.0)
                            elif match_pct >= 95:
                                color = (0.6, 1.0, 0.3, 1.0)
                            elif match_pct >= 90:
                                color = (0.8, 1.0, 0.3, 1.0)
                            else:
                                color = (1.0, 0.8, 0.3, 1.0)
                            
                            imgui.text_colored(f"  0x{offset:08X} ({match_pct:.1f}%)", *color)
                            imgui.same_line()
                            if imgui.small_button(f"Use##use_{offset}"):
                                self._set_block_offset(block_idx, self.current_section_type, offset)
                                self.block_search_results = []
                            imgui.same_line()
                            if imgui.small_button(f"Debug##dbg_{offset}"):
                                self._dump_block_section_debug(block_idx, self.current_section_type, offset)
                    
                    imgui.unindent()
            
            imgui.end_child()
            
            imgui.separator()
        
        # === Export Section ===
        imgui.text_colored("Step 3: Export", 0.4, 0.8, 1.0, 1.0)
        
        # Export Splat YAML
        can_export_splat = (
            self.scan_results
            and non_fp_ambiguous == 0
        )
        
        # Check if we have resolved offsets for better export
        data_resolved = sum(1 for e in self.data_section_list if e["offset"] is not None)
        rdata_resolved = sum(1 for e in self.rdata_section_list if e["offset"] is not None)
        has_resolved_offsets = data_resolved > 0 or rdata_resolved > 0
        
        if can_export_splat:
            if imgui.button("Export Splat YAML", width=180):
                self._export_splat_yaml()
            imgui.same_line()
            if has_resolved_offsets:
                imgui.text_colored(
                    f"(.text + {data_resolved} .data + {rdata_resolved} .rdata resolved)", 
                    0.3, 1.0, 0.3, 1.0
                )
            else:
                imgui.text_colored("(.text with offsets, .data/.rdata with auto)", 0.5, 0.5, 0.5, 1.0)
        else:
            imgui.text_colored(
                "Resolve all ambiguities to enable Splat export",
                0.5, 0.5, 0.5, 1.0
            )
        
        # Also show enriched JSON export
        if imgui.button("Export Enriched JSON", width=180):
            self._export_scan_results_json()
        imgui.same_line()
        imgui.text_colored("(includes section sizes and symbols if enriched)", 0.5, 0.5, 0.5, 1.0)
        
        imgui.separator()
        
        # === Enrichment Preview (collapsible) ===
        if self.enrich_data:
            expanded, _ = imgui.collapsing_header("Enrichment Preview")
            if expanded:
                imgui.begin_child("enrich_preview", 0, 200, border=True)
                
                # Header
                imgui.columns(6, "enrich_cols")
                imgui.set_column_width(0, 120)  # Library
                imgui.set_column_width(1, 120)  # Object
                imgui.set_column_width(2, 70)   # .text
                imgui.set_column_width(3, 70)   # .data
                imgui.set_column_width(4, 70)   # .rdata
                imgui.set_column_width(5, 70)   # .bss
                imgui.text("Library")
                imgui.next_column()
                imgui.text("Object")
                imgui.next_column()
                imgui.text(".text")
                imgui.next_column()
                imgui.text(".data")
                imgui.next_column()
                imgui.text(".rdata")
                imgui.next_column()
                imgui.text(".bss")
                imgui.columns(1)
                imgui.separator()
                
                # Data rows
                for (lib, obj), info in sorted(self.enrich_data.items()):
                    sizes = info.get("section_sizes", {})
                    imgui.columns(6, f"enrich_{lib}_{obj}")
                    imgui.set_column_width(0, 120)
                    imgui.set_column_width(1, 120)
                    imgui.set_column_width(2, 70)
                    imgui.set_column_width(3, 70)
                    imgui.set_column_width(4, 70)
                    imgui.set_column_width(5, 70)
                    
                    imgui.text(lib if lib else "(loose)")
                    imgui.next_column()
                    imgui.text(obj)
                    imgui.next_column()
                    
                    text_size = sizes.get(".text", 0)
                    data_size = sizes.get(".data", 0)
                    rdata_size = sizes.get(".rdata", 0)
                    bss_size = sizes.get(".bss", 0)
                    
                    imgui.text(f"0x{text_size:X}" if text_size else "-")
                    imgui.next_column()
                    imgui.text(f"0x{data_size:X}" if data_size else "-")
                    imgui.next_column()
                    imgui.text(f"0x{rdata_size:X}" if rdata_size else "-")
                    imgui.next_column()
                    imgui.text(f"0x{bss_size:X}" if bss_size else "-")
                    imgui.columns(1)
                
                imgui.end_child()
    
    def _do_scan_preprocess(self):
        """Preprocess signatures for scanning."""
        library_filter = None
        if self.scan_library_idx > 0 and self.all_libraries:
            library_filter = self.all_libraries[self.scan_library_idx]
        
        version_filter = None
        if self.scan_version_idx > 0 and self.versions:
            version_filter = self.versions[self.scan_version_idx - 1]  # -1 because index 0 is "All Versions"
        
        self.scan_running = True
        filter_parts = []
        if library_filter:
            filter_parts.append(f"library={library_filter}")
        if version_filter:
            filter_parts.append(f"version={version_filter}")
        if self.lib_version_overrides:
            filter_parts.append(f"{len(self.lib_version_overrides)} override(s)")
        filter_msg = f" ({', '.join(filter_parts)})" if filter_parts else ""
        self.status_message = f"Preprocessing signatures{filter_msg}..."
        
        self.scan_engine.preprocess(
            library_filter=library_filter, 
            version_filter=version_filter,
            lib_version_overrides=self.lib_version_overrides
        )
        
        self.scan_preprocessed = True
        self.scan_running = False
        self.status_message = self.scan_engine.progress_message
    
    def _do_scan(self):
        """Perform the full binary scan."""
        if not self.scan_binary_path:
            self.status_message = "Please enter a binary path"
            return
        
        if not os.path.exists(self.scan_binary_path):
            self.status_message = f"File not found: {self.scan_binary_path}"
            return
        
        self.scan_running = True
        self.status_message = "Scanning binary..."
        
        # Compute binary fingerprint for false positive tracking
        self.scan_binary_fingerprint = FalsePositiveStore.fingerprint(self.scan_binary_path)
        
        align = 4 if self.scan_align_to_4 else 1
        
        try:
            self.scan_results = self.scan_engine.scan(self.scan_binary_path, align=align)
            
            # Summary stats
            unique_objects = len(self.scan_results)
            unique_libs = len(set(r.library for r in self.scan_results))
            total_funcs = sum(
                len([l for l in r.labels if l.name.startswith("_") or l.offset == 0])
                for r in self.scan_results
            )
            ambiguous = sum(1 for r in self.scan_results if r.is_ambiguous)
            fp_count = self.fp_store.get_count(self.scan_binary_fingerprint)
            
            ambig_msg = f", {ambiguous} ambiguous" if ambiguous else ""
            fp_msg = f", {fp_count} marked as false positive" if fp_count else ""
            self.status_message = (
                f"Scan complete: {unique_objects} objects found across "
                f"{unique_libs} libraries, {total_funcs} functions identified{ambig_msg}{fp_msg}"
            )
        except Exception as e:
            self.status_message = f"Scan failed: {e}"
            self.scan_results = []
        
        self.scan_running = False
    
    def _export_scan_results(self):
        """Export scan results to CSV, excluding false positives."""
        if not self.scan_results:
            return
        
        # Default export path next to the binary
        if self.scan_binary_path:
            base = os.path.splitext(self.scan_binary_path)[0]
            export_path = f"{base}_psyq_scan.csv"
        else:
            export_path = "psyq_scan.csv"
        
        try:
            exported = 0
            skipped_fp = 0
            with open(export_path, "w") as f:
                f.write("Offset,Library,Object,Size,Ambiguous,SDK Versions,Functions\n")
                for r in self.scan_results:
                    # Skip false positives
                    if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                        self.scan_binary_fingerprint, r.offset, r.library, r.object_name
                    ):
                        skipped_fp += 1
                        continue
                    
                    func_labels = [l for l in r.labels if l.name.startswith("_") or l.offset == 0]
                    funcs_str = "; ".join(
                        f"{l.name} (0x{r.offset + l.offset:08X})" for l in func_labels
                    )
                    
                    if r.is_ambiguous:
                        version_parts = []
                        for vg in r.version_groups:
                            v_str = "+".join(vg.versions)
                            version_parts.append(f"[0x{vg.sig_length:X}] {v_str}")
                        versions_str = " | ".join(version_parts)
                    else:
                        versions_str = "; ".join(r.versions)
                    
                    f.write(
                        f"0x{r.offset:08X},"
                        f"{r.library},"
                        f"{r.object_name},"
                        f"0x{r.sig_length:X},"
                        f"{'YES' if r.is_ambiguous else 'NO'},"
                        f"\"{versions_str}\","
                        f"\"{funcs_str}\"\n"
                    )
                    exported += 1
            
            fp_msg = f" ({skipped_fp} false positives excluded)" if skipped_fp else ""
            self.status_message = f"Exported {exported} results to {export_path}{fp_msg}"
        except Exception as e:
            self.status_message = f"Export failed: {e}"
    
    def _export_scan_results_txt(self):
        """Export scan results to a simple text file with offsets."""
        if not self.scan_results:
            return
        
        # Default export path next to the binary
        if self.scan_binary_path:
            base = os.path.splitext(self.scan_binary_path)[0]
            export_path = f"{base}_psyq_objects.txt"
        else:
            export_path = "psyq_objects.txt"
        
        # Get version filter info for header
        version_info = ""
        if self.scan_version_idx > 0 and self.versions:
            version_info = f"SDK Version: {self.versions[self.scan_version_idx - 1]}\n"
        else:
            version_info = "SDK Version: All\n"
        
        try:
            exported = 0
            skipped_fp = 0
            with open(export_path, "w") as f:
                f.write("# PSY-Q SDK Object Scan Results\n")
                f.write(f"# Binary: {self.scan_binary_path}\n")
                f.write(f"# {version_info}")
                f.write(f"# Objects found: {len(self.scan_results)}\n")
                f.write("#\n")
                f.write(f"# {'Offset':<12} {'Library':<20} {'Object':<25} {'Versions'}\n")
                f.write(f"# {'-'*80}\n")
                
                for r in self.scan_results:
                    # Skip false positives
                    if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                        self.scan_binary_fingerprint, r.offset, r.library, r.object_name
                    ):
                        skipped_fp += 1
                        continue
                    
                    versions_str = ", ".join(r.versions)
                    f.write(f"0x{r.offset:08X}  {r.library:<20} {r.object_name:<25} {versions_str}\n")
                    exported += 1
            
            fp_msg = f" ({skipped_fp} false positives excluded)" if skipped_fp else ""
            self.status_message = f"Exported {exported} results to {export_path}{fp_msg}"
        except Exception as e:
            self.status_message = f"Export failed: {e}"
    
    def _export_scan_results_json(self):
        """Export scan results to JSON format."""
        if not self.scan_results:
            return
        
        # Default export path next to the binary
        if self.scan_binary_path:
            base = os.path.splitext(self.scan_binary_path)[0]
            export_path = f"{base}_psyq_scan.json"
        else:
            export_path = "psyq_scan.json"
        
        # Get version filter info
        version_filter = None
        if self.scan_version_idx > 0 and self.versions:
            version_filter = self.versions[self.scan_version_idx - 1]
        
        try:
            exported = 0
            skipped_fp = 0
            
            results_list = []
            for r in self.scan_results:
                # Skip false positives
                if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                    self.scan_binary_fingerprint, r.offset, r.library, r.object_name
                ):
                    skipped_fp += 1
                    continue
                
                # Build function list
                functions = []
                for lbl in r.labels:
                    if lbl.name.startswith("_") or lbl.offset == 0:
                        functions.append({
                            "name": lbl.name,
                            "offset": r.offset + lbl.offset,
                            "offset_hex": f"0x{r.offset + lbl.offset:08X}",
                            "relative_offset": lbl.offset
                        })
                
                result_obj = {
                    "offset": r.offset,
                    "offset_hex": f"0x{r.offset:08X}",
                    "library": r.library,
                    "object": r.object_name,
                    "size": r.sig_length,
                    "size_hex": f"0x{r.sig_length:X}",
                    "versions": r.versions,
                    "is_ambiguous": r.is_ambiguous,
                    "functions": functions
                }
                
                # Add version groups for ambiguous results
                if r.is_ambiguous and r.version_groups:
                    result_obj["version_groups"] = [
                        {
                            "sig_length": vg.sig_length,
                            "sig_length_hex": f"0x{vg.sig_length:X}",
                            "versions": vg.versions
                        }
                        for vg in r.version_groups
                    ]
                
                # Add enrichment data if available
                key = (r.library, r.object_name)
                if key in self.enrich_data:
                    result_obj["readelf"] = self.enrich_data[key]
                
                results_list.append(result_obj)
                exported += 1
            
            # Build final JSON structure
            output = {
                "binary": self.scan_binary_path,
                "version_filter": version_filter,
                "total_objects": exported,
                "objects": results_list
            }
            
            # Add enrichment metadata if available
            if self.enrich_data:
                output["enriched"] = {
                    "enriched_objects": len(self.enrich_data),
                    "repo_root": self.enrich_repo_root,
                    "obj_root": self.enrich_obj_root,
                    "sections_summary": [".text", ".data", ".rdata", ".bss", ".sdata", ".sbss"],
                    "errors": self.enrich_errors[:10] if self.enrich_errors else [],
                    "notes": "Per-object metadata added under objects[i].readelf"
                }
            
            with open(export_path, "w") as f:
                json.dump(output, f, indent=2)
            
            fp_msg = f" ({skipped_fp} false positives excluded)" if skipped_fp else ""
            self.status_message = f"Exported {exported} results to {export_path}{fp_msg}"
        except Exception as e:
            self.status_message = f"Export failed: {e}"
    
    def _do_enrich(self):
        """Enrich scan results with readelf data from .o files."""
        if not self.enrich_repo_root or not self.scan_results:
            return
        
        # Get base version from scan filter (used as default)
        base_version = None
        if self.scan_version_idx > 0 and self.versions:
            base_version = self.versions[self.scan_version_idx - 1]
        
        if not base_version and not self.lib_version_overrides:
            self.status_message = "Select a base SDK version or set library version overrides"
            return
        
        repo_root = Path(self.enrich_repo_root).expanduser()
        
        self.enrich_data = {}
        self.enrich_errors = []
        self.section_verify_cache.clear()  # Clear verification cache
        enriched = 0
        
        # Cache obj_roots per version
        version_obj_roots: dict[str, Path] = {}
        
        def get_obj_root(version: str) -> Optional[Path]:
            """Get the obj root for a specific version."""
            if version in version_obj_roots:
                return version_obj_roots[version]
            
            # Try multiple path structures
            possible_roots = [
                repo_root / "assets" / "psyq" / version / "obj",
                repo_root / version / "obj",
                repo_root / "obj",
            ]
            
            for candidate in possible_roots:
                if candidate.exists():
                    version_obj_roots[version] = candidate
                    return candidate
            
            return None
        
        for r in self.scan_results:
            # Skip false positives
            if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                self.scan_binary_fingerprint, r.offset, r.library, r.object_name
            ):
                continue
            
            key = (r.library, r.object_name)
            if key in self.enrich_data:
                continue  # Already processed
            
            # Determine version to use for this object
            # Priority: per-library override > base version > first from scan result
            lib_key = r.library if r.library else ""  # Empty string for loose objs
            version = self.lib_version_overrides.get(lib_key) or base_version or (r.versions[0] if r.versions else None)
            
            if not version:
                self.enrich_errors.append(f"No version for {r.library}/{r.object_name}")
                continue
            
            obj_root = get_obj_root(version)
            if not obj_root:
                self.enrich_errors.append(f"No obj root for version {version}")
                continue
            
            # Handle loose OBJ files vs library-contained objects
            # Loose OBJ files have library names like "2MBYTE.OBJ" (not ".LIB")
            is_loose_obj = r.library and r.library.upper().endswith(".OBJ")
            
            if r.library and not is_loose_obj:
                # Library object: {obj_root}/{lib_folder}/{obj_file}
                lib_folder = lib_to_folder(r.library)
                obj_file = obj_to_filename(r.object_name)
                o_path = obj_root / lib_folder / obj_file
            else:
                # Loose object: {obj_root}/{obj_file}
                # For loose OBJ, library and object name are the same
                obj_name = r.library if is_loose_obj else r.object_name
                obj_file = obj_to_filename(obj_name)
                o_path = obj_root / obj_file
            
            info = enrich_object(o_path)
            info["version_used"] = version  # Track which version we used
            self.enrich_data[key] = info
            
            if info.get("errors"):
                self.enrich_errors.extend(info["errors"])
            else:
                enriched += 1
        
        # Store the primary obj root for display
        if base_version:
            self.enrich_obj_root = str(get_obj_root(base_version) or repo_root)
        else:
            self.enrich_obj_root = str(repo_root)
        
        self.status_message = f"Enriched {enriched} objects"
        
        # Initialize section lists from scan results
        self._init_section_lists()
    
    def _init_section_lists(self):
        """Initialize .data and .rdata section lists from scan results."""
        # Get valid (non-FP) results sorted by .text offset
        valid_results = []
        for r in self.scan_results:
            if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                self.scan_binary_fingerprint, r.offset, r.library, r.object_name
            ):
                continue
            if r.is_ambiguous:
                continue
            valid_results.append(r)
        
        valid_results.sort(key=lambda r: r.offset)
        
        # Build .data list (objects that have .data sections)
        self.data_section_list = []
        for r in valid_results:
            key = (r.library, r.object_name)
            info = self.enrich_data.get(key, {})
            data_size = info.get("section_sizes", {}).get(".data", 0)
            if data_size > 0:
                self.data_section_list.append({
                    "library": r.library,
                    "object": r.object_name,
                    "offset": None,  # Not yet resolved
                    "size": data_size,
                })
        
        # Build .rdata list
        self.rdata_section_list = []
        for r in valid_results:
            key = (r.library, r.object_name)
            info = self.enrich_data.get(key, {})
            rdata_size = info.get("section_sizes", {}).get(".rdata", 0)
            if rdata_size > 0:
                self.rdata_section_list.append({
                    "library": r.library,
                    "object": r.object_name,
                    "offset": None,
                    "size": rdata_size,
                })
        
        self.status_message = f"Initialized {len(self.data_section_list)} .data, {len(self.rdata_section_list)} .rdata entries"
    
    def _search_single_section(self, library: str, object_name: str, section: str, search_start: int = 0):
        """
        Search binary for a single object's .data or .rdata section.
        Uses relocation masking for accurate matching.
        """
        if not self.scan_binary_path or not os.path.exists(self.scan_binary_path):
            self.status_message = "Binary file not found"
            return
        
        key = (library, object_name)
        info = self.enrich_data.get(key, {})
        
        if not info:
            self.status_message = f"No enrichment data for {library}/{object_name}"
            return
        
        obj_path = info.get("obj_path", "")
        if not obj_path or not os.path.exists(obj_path):
            self.status_message = f"Object file not found: {obj_path}"
            return
        
        section_info = info.get("sections", {}).get(section, {})
        section_offset = section_info.get("offset", 0)
        section_size = section_info.get("size", 0)
        
        if section_size <= 0:
            self.status_message = f"No {section} section in {library}/{object_name}"
            return
        
        self.section_search_key = (library, object_name, section)
        self.section_searching = True
        self.section_search_results = []
        
        # Get relocations
        relocs = info.get("relocations", {}).get(section, [])
        
        # Read object section data
        try:
            with open(obj_path, "rb") as f:
                f.seek(section_offset)
                obj_data = f.read(section_size)
        except Exception as e:
            self.status_message = f"Failed to read object: {e}"
            self.section_searching = False
            return
        
        # Build mask
        mask = bytearray(b'\xFF' * section_size)
        for reloc_offset in relocs:
            if reloc_offset < section_size:
                for i in range(4):
                    if reloc_offset + i < section_size:
                        mask[reloc_offset + i] = 0x00
        
        # Read binary
        try:
            with open(self.scan_binary_path, "rb") as f:
                binary = f.read()
        except Exception as e:
            self.status_message = f"Failed to read binary: {e}"
            self.section_searching = False
            return
        
        # Build anchor from concrete bytes
        anchor = bytearray()
        anchor_positions = []
        for i in range(len(obj_data)):
            if mask[i] == 0xFF:
                anchor.append(obj_data[i])
                anchor_positions.append(i)
                if len(anchor) >= 16:
                    break
        
        if len(anchor) < 4:
            self.status_message = f"Not enough concrete bytes to search (too many relocations)"
            self.section_searching = False
            return
        
        anchor = bytes(anchor)
        anchor_start_offset = anchor_positions[0] if anchor_positions else 0
        
        candidates = []
        pos = search_start
        binary_len = len(binary)
        
        while pos < binary_len - len(anchor):
            found_pos = binary.find(anchor, pos)
            if found_pos == -1:
                break
            
            section_start = found_pos - anchor_start_offset
            
            if section_start < 0 or section_start % 4 != 0:
                pos = found_pos + 1
                continue
            
            # Verify full pattern
            match_score = 0
            total_concrete = 0
            
            if section_start + section_size <= binary_len:
                for i in range(section_size):
                    if mask[i] == 0xFF:
                        total_concrete += 1
                        if binary[section_start + i] == obj_data[i]:
                            match_score += 1
            
            if total_concrete > 0:
                match_pct = (match_score / total_concrete) * 100
                if match_pct >= 80:
                    candidates.append((section_start, match_pct))
            
            pos = found_pos + 1
            
            if len(candidates) >= 20:
                break
        
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        self.section_search_results = candidates
        self.section_searching = False
        
        reloc_note = f" ({len(relocs)} relocs)" if relocs else ""
        if candidates:
            self.status_message = f"Found {len(candidates)} candidate(s){reloc_note}"
        else:
            self.status_message = f"No matches found{reloc_note}"
    
    def _chain_section_offset(self, section_list: list[dict], idx: int) -> bool:
        """
        Set offset for entry at idx based on previous entry's offset + size.
        Returns True if successful, False if there's no previous offset.
        """
        if idx <= 0:
            self.status_message = "No previous entry to chain from"
            return False
        
        prev = section_list[idx - 1]
        if prev["offset"] is None:
            self.status_message = "Previous entry has no offset set"
            return False
        
        # Compute new offset = prev_offset + prev_size (aligned to 4)
        new_offset = prev["offset"] + prev["size"]
        if new_offset % 4 != 0:
            new_offset += 4 - (new_offset % 4)
        
        section_list[idx]["offset"] = new_offset
        self.status_message = f"Chained: 0x{prev['offset']:X} + 0x{prev['size']:X} = 0x{new_offset:X}"
        return True
    
    def _verify_section_at_offset(self, library: str, object_name: str, section: str, offset: int) -> tuple[float, int, int]:
        """
        Verify a section at a specific offset in the binary.
        Returns (match_pct, matched_bytes, total_concrete_bytes)
        Uses cache to avoid repeated file I/O on every frame.
        """
        # Check cache first
        cache_key = (library, object_name, section, offset)
        if cache_key in self.section_verify_cache:
            return self.section_verify_cache[cache_key]
        
        key = (library, object_name)
        info = self.enrich_data.get(key, {})
        
        if not info:
            return (0.0, 0, 0)
        
        obj_path = info.get("obj_path", "")
        if not obj_path or not os.path.exists(obj_path):
            return (0.0, 0, 0)
        
        section_info = info.get("sections", {}).get(section, {})
        section_offset = section_info.get("offset", 0)
        section_size = section_info.get("size", 0)
        
        if section_size <= 0:
            return (0.0, 0, 0)
        
        # Read object data
        try:
            with open(obj_path, "rb") as f:
                f.seek(section_offset)
                obj_data = f.read(section_size)
        except Exception:
            return (0.0, 0, 0)
        
        # Read binary data
        try:
            with open(self.scan_binary_path, "rb") as f:
                f.seek(offset)
                bin_data = f.read(section_size)
        except Exception:
            return (0.0, 0, 0)
        
        # Build mask
        relocs = info.get("relocations", {}).get(section, [])
        mask = bytearray(b'\xFF' * section_size)
        for reloc_offset in relocs:
            if reloc_offset < section_size:
                for i in range(4):
                    if reloc_offset + i < section_size:
                        mask[reloc_offset + i] = 0x00
        
        # Compare
        match_score = 0
        total_concrete = 0
        for i in range(min(len(obj_data), len(bin_data))):
            if mask[i] == 0xFF:
                total_concrete += 1
                if obj_data[i] == bin_data[i]:
                    match_score += 1
        
        if total_concrete > 0:
            result = (match_score / total_concrete * 100, match_score, total_concrete)
        else:
            result = (0.0, 0, 0)
        
        # Cache the result
        self.section_verify_cache[cache_key] = result
        return result
    
    def _invalidate_section_cache(self, library: str = None, object_name: str = None):
        """Invalidate verification cache entries."""
        if library is None and object_name is None:
            # Clear all
            self.section_verify_cache.clear()
        else:
            # Clear matching entries
            keys_to_remove = [
                k for k in self.section_verify_cache
                if (library is None or k[0] == library) and (object_name is None or k[1] == object_name)
            ]
            for k in keys_to_remove:
                del self.section_verify_cache[k]
    
    def _move_section_entry(self, section_list: list[dict], idx: int, direction: int):
        """Move an entry up (direction=-1) or down (direction=1) in the list."""
        new_idx = idx + direction
        if 0 <= new_idx < len(section_list):
            section_list[idx], section_list[new_idx] = section_list[new_idx], section_list[idx]
    
    def _compute_section_diff(self, library: str, object_name: str, section: str, binary_offset: int):
        """
        Compute detailed diff between the object file section and binary.
        Stores result in self.section_diff_data for inline display.
        """
        key = (library, object_name)
        info = self.enrich_data.get(key, {})
        
        self.section_diff_key = (library, object_name, section, binary_offset)
        self.section_diff_data = None
        
        if not info:
            self.status_message = f"No enrichment data for {library}/{object_name}"
            return
        
        obj_path = info.get("obj_path", "")
        if not obj_path or not os.path.exists(obj_path):
            self.status_message = f"Object file not found: {obj_path}"
            return
        
        section_info = info.get("sections", {}).get(section, {})
        section_offset = section_info.get("offset", 0)
        section_size = section_info.get("size", 0)
        
        if section_size <= 0:
            self.status_message = f"No {section} section in object"
            return
        
        # Read object data
        try:
            with open(obj_path, "rb") as f:
                f.seek(section_offset)
                obj_data = f.read(section_size)
        except Exception as e:
            self.status_message = f"Failed to read object: {e}"
            return
        
        # Read binary data
        try:
            with open(self.scan_binary_path, "rb") as f:
                f.seek(binary_offset)
                bin_data = f.read(section_size)
        except Exception as e:
            self.status_message = f"Failed to read binary: {e}"
            return
        
        # Build mask
        relocs = info.get("relocations", {}).get(section, [])
        mask = bytearray(b'\xFF' * section_size)
        for reloc_offset in relocs:
            if reloc_offset < section_size:
                for i in range(4):
                    if reloc_offset + i < section_size:
                        mask[reloc_offset + i] = 0x00
        
        # Count stats and collect mismatches
        match_count = 0
        mismatch_count = 0
        wildcard_count = 0
        mismatches = []
        
        for i in range(section_size):
            obj_byte = obj_data[i] if i < len(obj_data) else 0
            bin_byte = bin_data[i] if i < len(bin_data) else 0
            is_wildcard = mask[i] == 0x00
            
            if is_wildcard:
                wildcard_count += 1
            elif obj_byte == bin_byte:
                match_count += 1
            else:
                mismatch_count += 1
                mismatches.append({
                    "offset": i,
                    "binary_offset": binary_offset + i,
                    "obj_byte": obj_byte,
                    "bin_byte": bin_byte,
                })
        
        total_concrete = match_count + mismatch_count
        match_pct = (match_count / total_concrete * 100) if total_concrete > 0 else 0
        
        # Store for inline display
        self.section_diff_data = {
            "library": library,
            "object": object_name,
            "section": section,
            "binary_offset": binary_offset,
            "section_size": section_size,
            "version_used": info.get("version_used", "unknown"),
            "relocs": relocs,
            "match_count": match_count,
            "mismatch_count": mismatch_count,
            "wildcard_count": wildcard_count,
            "match_pct": match_pct,
            "mismatches": mismatches[:50],  # Limit for display
            "total_mismatches": len(mismatches),
            "obj_data": obj_data,
            "bin_data": bin_data,
            "mask": bytes(mask),
        }
        
        self.status_message = f"Diff computed: {match_pct:.1f}% match, {mismatch_count} mismatches"
    
    def _compute_blocks(self):
        """
        Compute contiguous blocks of PSYQ objects based on .text gaps.
        
        A gap between consecutive .text segments indicates non-PSYQ code.
        Objects within a block will have contiguous .data/.rdata sections too.
        """
        if not self.enrich_data or not self.scan_results:
            self.blocks = []
            return
        
        # Get valid results sorted by offset
        valid_results = []
        for r in self.scan_results:
            if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                self.scan_binary_fingerprint, r.offset, r.library, r.object_name
            ):
                continue
            if r.is_ambiguous:
                continue
            valid_results.append(r)
        
        valid_results.sort(key=lambda r: r.offset)
        
        if not valid_results:
            self.blocks = []
            return
        
        # Compute blocks by detecting gaps
        blocks = []
        current_block = {
            "objects": [],  # list of scan results
            "text_start": 0,
            "text_end": 0,
            "total_data_size": 0,
            "total_rdata_size": 0,
            "gap_before": 0,  # gap that preceded this block
        }
        
        for i, r in enumerate(valid_results):
            key = (r.library, r.object_name)
            info = self.enrich_data.get(key, {})
            sizes = info.get("section_sizes", {})
            text_size = sizes.get(".text", 0)
            data_size = sizes.get(".data", 0)
            rdata_size = sizes.get(".rdata", 0)
            
            if i == 0:
                # First object starts first block
                current_block["objects"].append(r)
                current_block["text_start"] = r.offset
                current_block["text_end"] = r.offset + text_size
                current_block["total_data_size"] = data_size
                current_block["total_rdata_size"] = rdata_size
            else:
                # Check for gap
                expected_start = current_block["text_end"]
                actual_start = r.offset
                gap = actual_start - expected_start
                
                # Allow small alignment gaps (up to 16 bytes)
                if gap > 16:
                    # Start a new block
                    if current_block["objects"]:
                        blocks.append(current_block)
                    
                    current_block = {
                        "objects": [r],
                        "text_start": r.offset,
                        "text_end": r.offset + text_size,
                        "total_data_size": data_size,
                        "total_rdata_size": rdata_size,
                        "gap_before": gap,
                    }
                else:
                    # Continue current block
                    current_block["objects"].append(r)
                    current_block["text_end"] = r.offset + text_size
                    current_block["total_data_size"] += data_size
                    current_block["total_rdata_size"] += rdata_size
        
        # Don't forget the last block
        if current_block["objects"]:
            blocks.append(current_block)
        
        self.blocks = blocks
        
        # Clear any previous block offset resolutions
        self.block_data_offsets = {}
        self.block_rdata_offsets = {}
        
        self.status_message = f"Found {len(blocks)} contiguous blocks of PSYQ objects"
    
    def _search_block_section(self, block_idx: int, section: str, search_start: int = 0):
        """
        Search binary for a block's .data or .rdata section.
        
        Builds the expected byte pattern from the concatenated section data
        of all objects in the block, applying wildcard masks at relocation
        offsets (since relocated values won't match).
        """
        if block_idx >= len(self.blocks):
            return
        
        if not self.scan_binary_path or not os.path.exists(self.scan_binary_path):
            self.status_message = "Binary file not found"
            return
        
        block = self.blocks[block_idx]
        self.current_block_idx = block_idx
        self.current_section_type = section
        self.block_searching = True
        self.block_search_results = []
        
        # Build expected pattern from ELF section data with relocation masks
        # Each entry: (result, data_bytes, mask_bytes)
        # mask: 0xFF = concrete byte, 0x00 = wildcard (relocation)
        pattern_parts = []
        total_relocs = 0
        
        for r in block["objects"]:
            key = (r.library, r.object_name)
            info = self.enrich_data.get(key, {})
            
            # Get section data from the .o file
            obj_path = info.get("obj_path", "")
            if not obj_path or not os.path.exists(obj_path):
                continue
            
            section_info = info.get("sections", {}).get(section, {})
            section_offset = section_info.get("offset", 0)
            section_size = section_info.get("size", 0)
            
            if section_size <= 0:
                continue
            
            # Get relocations for this section
            relocs = info.get("relocations", {}).get(section, [])
            total_relocs += len(relocs)
            
            try:
                with open(obj_path, "rb") as f:
                    f.seek(section_offset)
                    data = f.read(section_size)
                    
                    # Build mask: 0xFF for concrete bytes, 0x00 for relocated bytes
                    # Relocations are typically 4 bytes on MIPS
                    mask = bytearray(b'\xFF' * section_size)
                    for reloc_offset in relocs:
                        if reloc_offset < section_size:
                            # Wildcard 4 bytes at the relocation offset
                            for i in range(4):
                                if reloc_offset + i < section_size:
                                    mask[reloc_offset + i] = 0x00
                    
                    pattern_parts.append((r, data, bytes(mask)))
            except Exception:
                pass
        
        if not pattern_parts:
            self.status_message = f"No {section} data found in block {block_idx + 1}"
            self.block_searching = False
            return
        
        # Log relocation info
        if total_relocs > 0:
            self.status_message = f"Searching {section} with {total_relocs} relocations masked..."
        
        # Read binary
        try:
            with open(self.scan_binary_path, "rb") as f:
                binary = f.read()
        except Exception as e:
            self.status_message = f"Failed to read binary: {e}"
            self.block_searching = False
            return
        
        # Find a good anchor from the first object's data
        # Use first N concrete (non-wildcard) bytes as search anchor
        first_obj, first_data, first_mask = pattern_parts[0]
        
        # Build anchor from concrete bytes only
        anchor = bytearray()
        anchor_positions = []  # positions in first_data that are in anchor
        for i in range(len(first_data)):
            if first_mask[i] == 0xFF:  # Concrete byte
                anchor.append(first_data[i])
                anchor_positions.append(i)
                if len(anchor) >= 16:  # 16 concrete bytes is enough
                    break
        
        if len(anchor) < 4:
            self.status_message = f"Not enough concrete bytes in {section} to search (too many relocations)"
            self.block_searching = False
            return
        
        anchor = bytes(anchor)
        anchor_start_offset = anchor_positions[0] if anchor_positions else 0
        
        candidates = []
        pos = search_start
        binary_len = len(binary)
        
        while pos < binary_len - len(anchor):
            # Find the anchor in binary
            found_pos = binary.find(anchor, pos)
            if found_pos == -1:
                break
            
            # Calculate the actual start position of the section data
            section_start = found_pos - anchor_start_offset
            
            # Check alignment (4-byte)
            if section_start < 0 or section_start % 4 != 0:
                pos = found_pos + 1
                continue
            
            # Verify the full pattern with masked matching
            match_score = 0
            total_concrete_bytes = 0
            check_offset = section_start
            valid = True
            
            for obj, data, mask in pattern_parts:
                data_len = len(data)
                if check_offset + data_len > binary_len:
                    valid = False
                    break
                
                # Count matching concrete bytes (skip wildcards)
                for i in range(data_len):
                    if mask[i] == 0xFF:  # Only count concrete bytes
                        total_concrete_bytes += 1
                        if binary[check_offset + i] == data[i]:
                            match_score += 1
                
                check_offset += data_len
            
            if valid and total_concrete_bytes > 0:
                match_pct = (match_score / total_concrete_bytes) * 100
                if match_pct >= 80:  # Reasonable threshold
                    candidates.append((section_start, match_pct))
            
            pos = found_pos + 1
            
            # Limit candidates
            if len(candidates) >= 20:
                break
        
        # Sort by match percentage descending
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        self.block_search_results = candidates
        self.block_searching = False
        
        if candidates:
            reloc_note = f" ({total_relocs} relocs masked)" if total_relocs else ""
            self.status_message = f"Found {len(candidates)} candidate(s) for block {block_idx + 1} {section}{reloc_note}"
        else:
            self.status_message = f"No matches found for block {block_idx + 1} {section}"
    
    def _dump_block_section_debug(self, block_idx: int, section: str, binary_offset: int):
        """
        Dump detailed debug info about a block's section matching.
        Writes to a file next to the binary for analysis.
        """
        if block_idx >= len(self.blocks):
            return
        
        block = self.blocks[block_idx]
        
        # Read binary
        try:
            with open(self.scan_binary_path, "rb") as f:
                binary = f.read()
        except Exception as e:
            self.status_message = f"Failed to read binary: {e}"
            return
        
        debug_path = f"{self.scan_binary_path}_block{block_idx + 1}_{section.strip('.')}_debug.txt"
        
        try:
            with open(debug_path, "w") as out:
                out.write(f"=== Block {block_idx + 1} {section} Debug Dump ===\n")
                out.write(f"Binary offset: 0x{binary_offset:X}\n")
                out.write(f"Objects in block: {len(block['objects'])}\n\n")
                
                current_binary_offset = binary_offset
                total_mismatches = 0
                total_concrete = 0
                total_wildcards = 0
                
                for r in block["objects"]:
                    key = (r.library, r.object_name)
                    info = self.enrich_data.get(key, {})
                    
                    obj_path = info.get("obj_path", "")
                    if not obj_path or not os.path.exists(obj_path):
                        out.write(f"\n--- {r.library}/{r.object_name} ---\n")
                        out.write(f"  ERROR: Object file not found: {obj_path}\n")
                        continue
                    
                    section_info = info.get("sections", {}).get(section, {})
                    section_offset = section_info.get("offset", 0)
                    section_size = section_info.get("size", 0)
                    
                    if section_size <= 0:
                        continue
                    
                    # Get relocations from enrichment data
                    relocs = info.get("relocations", {}).get(section, [])
                    
                    out.write(f"\n--- {r.library}/{r.object_name} ---\n")
                    out.write(f"  Object file: {obj_path}\n")
                    out.write(f"  Section {section}: offset=0x{section_offset:X}, size=0x{section_size:X} ({section_size} bytes)\n")
                    out.write(f"  Binary offset: 0x{current_binary_offset:X}\n")
                    out.write(f"  Relocations from enrichment: {relocs}\n")
                    
                    # Re-parse the ELF to get more details
                    if PYELFTOOLS_AVAILABLE:
                        try:
                            with open(obj_path, 'rb') as elf_f:
                                from elftools.elf.elffile import ELFFile
                                from elftools.elf.relocation import RelocationSection
                                elf = ELFFile(elf_f)
                                
                                out.write(f"  ELF sections in file:\n")
                                for sec in elf.iter_sections():
                                    if sec.name:
                                        out.write(f"    {sec.name}: size=0x{sec['sh_size']:X}, offset=0x{sec['sh_offset']:X}\n")
                                
                                out.write(f"  Relocation sections:\n")
                                for sec in elf.iter_sections():
                                    if isinstance(sec, RelocationSection):
                                        out.write(f"    {sec.name}: {sec.num_relocations()} entries\n")
                                        # Show details for the section we care about
                                        target = section
                                        if sec.name == f".rel{section}" or sec.name == f".rela{section}":
                                            out.write(f"      Relocation entries for {section}:\n")
                                            for i, reloc in enumerate(sec.iter_relocations()):
                                                r_offset = reloc['r_offset']
                                                r_info = reloc['r_info']
                                                r_type = r_info & 0xFF
                                                r_sym = r_info >> 8
                                                out.write(f"        [{i}] offset=0x{r_offset:X}, type={r_type}, sym={r_sym}\n")
                        except Exception as e:
                            out.write(f"  ERROR re-parsing ELF: {e}\n")
                    
                    # Read object section data
                    try:
                        with open(obj_path, "rb") as f:
                            f.seek(section_offset)
                            obj_data = f.read(section_size)
                    except Exception as e:
                        out.write(f"  ERROR reading object: {e}\n")
                        continue
                    
                    # Build mask
                    mask = bytearray(b'\xFF' * section_size)
                    for reloc_offset in relocs:
                        if reloc_offset < section_size:
                            for i in range(4):
                                if reloc_offset + i < section_size:
                                    mask[reloc_offset + i] = 0x00
                    
                    # Compare byte by byte
                    mismatches = []
                    wildcards = 0
                    concrete = 0
                    
                    for i in range(section_size):
                        bin_offset = current_binary_offset + i
                        if bin_offset >= len(binary):
                            out.write(f"  ERROR: Binary offset 0x{bin_offset:X} out of range\n")
                            break
                        
                        obj_byte = obj_data[i]
                        bin_byte = binary[bin_offset]
                        is_wildcard = mask[i] == 0x00
                        
                        if is_wildcard:
                            wildcards += 1
                            total_wildcards += 1
                        else:
                            concrete += 1
                            total_concrete += 1
                            if obj_byte != bin_byte:
                                mismatches.append({
                                    "offset_in_section": i,
                                    "binary_offset": bin_offset,
                                    "obj_byte": obj_byte,
                                    "bin_byte": bin_byte,
                                })
                                total_mismatches += 1
                    
                    out.write(f"  Concrete bytes: {concrete}, Wildcards: {wildcards}\n")
                    out.write(f"  Mismatches: {len(mismatches)}\n")
                    
                    if mismatches:
                        out.write(f"  Mismatch details:\n")
                        for mm in mismatches[:50]:  # Limit output
                            out.write(f"    @0x{mm['offset_in_section']:04X} (bin 0x{mm['binary_offset']:08X}): "
                                     f"obj=0x{mm['obj_byte']:02X} bin=0x{mm['bin_byte']:02X}\n")
                        if len(mismatches) > 50:
                            out.write(f"    ... and {len(mismatches) - 50} more\n")
                    
                    # Also dump a hex view of the first few bytes for visual comparison
                    out.write(f"  First 64 bytes comparison (W=wildcard, M=mismatch, .=match):\n")
                    out.write(f"    Offset   Obj                                               Bin                                               Mask\n")
                    for row_start in range(0, min(64, section_size), 16):
                        obj_hex = ""
                        bin_hex = ""
                        mask_str = ""
                        for i in range(16):
                            idx = row_start + i
                            if idx >= section_size:
                                break
                            bin_offset = current_binary_offset + idx
                            obj_b = obj_data[idx] if idx < len(obj_data) else 0
                            bin_b = binary[bin_offset] if bin_offset < len(binary) else 0
                            is_wc = mask[idx] == 0x00
                            
                            obj_hex += f"{obj_b:02X} "
                            bin_hex += f"{bin_b:02X} "
                            if is_wc:
                                mask_str += "W "
                            elif obj_b != bin_b:
                                mask_str += "M "
                            else:
                                mask_str += ". "
                        out.write(f"    0x{row_start:04X}  {obj_hex:<48} {bin_hex:<48} {mask_str}\n")
                    
                    current_binary_offset += section_size
                
                # Summary
                out.write(f"\n=== SUMMARY ===\n")
                out.write(f"Total concrete bytes: {total_concrete}\n")
                out.write(f"Total wildcards: {total_wildcards}\n")
                out.write(f"Total mismatches: {total_mismatches}\n")
                if total_concrete > 0:
                    match_pct = ((total_concrete - total_mismatches) / total_concrete) * 100
                    out.write(f"Match percentage: {match_pct:.2f}%\n")
            
            self.status_message = f"Debug dump written to {debug_path}"
        
        except Exception as e:
            self.status_message = f"Failed to write debug dump: {e}"
    
    def _set_block_offset(self, block_idx: int, section: str, offset: int):
        """Set the resolved offset for a block's section."""
        if section == ".data":
            self.block_data_offsets[block_idx] = offset
        elif section == ".rdata":
            self.block_rdata_offsets[block_idx] = offset
        
        self.status_message = f"Set block {block_idx + 1} {section} start to 0x{offset:X}"
    
    def _compute_section_offsets(self, section: str) -> dict[tuple[str, str], int]:
        """
        Compute per-object offsets for a section based on resolved block starts.
        
        Returns dict of (library, object_name) -> offset
        """
        offsets = {}
        
        block_starts = self.block_data_offsets if section == ".data" else self.block_rdata_offsets
        
        for block_idx, block in enumerate(self.blocks):
            if block_idx not in block_starts:
                continue  # Block not resolved yet
            
            current_offset = block_starts[block_idx]
            
            for r in block["objects"]:
                key = (r.library, r.object_name)
                info = self.enrich_data.get(key, {})
                section_size = info.get("section_sizes", {}).get(section, 0)
                
                if section_size > 0:
                    offsets[key] = current_offset
                    current_offset += section_size
                    # Align to 4 bytes
                    if current_offset % 4 != 0:
                        current_offset += 4 - (current_offset % 4)
        
        return offsets
    
    def _export_splat_yaml(self):
        """Export scan results as Splat YAML subsegments."""
        if not self.scan_results:
            return
        
        # Default export path next to the binary
        if self.scan_binary_path:
            base = os.path.splitext(self.scan_binary_path)[0]
            export_path = f"{base}_splat_subsegments.yaml"
        else:
            export_path = "splat_subsegments.yaml"
        
        # Collect non-FP, non-ambiguous results sorted by offset
        valid_results = []
        for r in self.scan_results:
            if self.scan_binary_fingerprint and self.fp_store.is_false_positive(
                self.scan_binary_fingerprint, r.offset, r.library, r.object_name
            ):
                continue
            if r.is_ambiguous:
                # For ambiguous, check if all but one version group are FP
                non_fp_groups = []
                for vg in r.version_groups:
                    vg_versions_str = ",".join(sorted(vg.versions))
                    if not self.fp_store.is_false_positive(
                        self.scan_binary_fingerprint, r.offset, r.library, r.object_name, vg_versions_str
                    ):
                        non_fp_groups.append(vg)
                
                # If exactly one group remains, use it
                if len(non_fp_groups) == 1:
                    # Create a modified result with just the non-FP group
                    valid_results.append(r)
                # Otherwise skip (still ambiguous)
                continue
            valid_results.append(r)
        
        valid_results.sort(key=lambda r: r.offset)
        
        # Get version filter for comments
        version_filter = None
        if self.scan_version_idx > 0 and self.versions:
            version_filter = self.versions[self.scan_version_idx - 1]
        
        # Build offset dicts from the new section lists
        data_offsets: dict[tuple[str, str], int] = {}
        for entry in self.data_section_list:
            if entry["offset"] is not None:
                data_offsets[(entry["library"], entry["object"])] = entry["offset"]
        
        rdata_offsets: dict[tuple[str, str], int] = {}
        for entry in self.rdata_section_list:
            if entry["offset"] is not None:
                rdata_offsets[(entry["library"], entry["object"])] = entry["offset"]
        
        has_resolved_data = bool(data_offsets)
        has_resolved_rdata = bool(rdata_offsets)
        
        # Build block membership for gap detection
        # Map result offset -> block_idx
        result_to_block: dict[int, int] = {}
        if self.blocks:
            for block_idx, block in enumerate(self.blocks):
                for r in block["objects"]:
                    result_to_block[r.offset] = block_idx
        
        try:
            with open(export_path, "w") as f:
                f.write(f"# PSY-Q Splat Subsegments\n")
                f.write(f"# Binary: {self.scan_binary_path}\n")
                f.write(f"# SDK Version: {version_filter or 'mixed'}\n")
                f.write(f"# Objects: {len(valid_results)}\n")
                f.write(f"# Blocks: {len(self.blocks)}\n")
                if has_resolved_data or has_resolved_rdata:
                    f.write(f"# .data offsets: {'resolved' if has_resolved_data else 'auto'}\n")
                    f.write(f"# .rdata offsets: {'resolved' if has_resolved_rdata else 'auto'}\n")
                f.write(f"#\n")
                f.write(f"# Format: [offset, type, library, object, section]\n")
                f.write(f"#\n\n")
                
                # === .text segments with asm gaps ===
                f.write("      # === .text segments ===\n")
                last_block_idx = -1
                prev_end = None
                
                for r in valid_results:
                    key = (r.library, r.object_name)
                    info = self.enrich_data.get(key, {})
                    text_size = info.get("section_sizes", {}).get(".text", r.sig_length)
                    
                    block_idx = result_to_block.get(r.offset, -1)
                    
                    # Add gap (asm) if there's space between previous end and this offset
                    if prev_end is not None and r.offset > prev_end:
                        gap_size = r.offset - prev_end
                        if gap_size > 0:
                            f.write(f"      - [0x{prev_end:X}, asm]  # gap: 0x{gap_size:X}\n")
                    
                    # Block comment when entering a new block
                    if block_idx != last_block_idx and block_idx >= 0:
                        if self.blocks and block_idx < len(self.blocks):
                            block = self.blocks[block_idx]
                            f.write(f"      # --- PSYQ Block {block_idx + 1} ({len(block['objects'])} objects) ---\n")
                    
                    last_block_idx = block_idx
                    
                    obj_stem = Path(r.object_name).stem
                    lib_name = r.library.replace('.LIB', '') if r.library else "LOOSE"
                    f.write(f"      - [0x{r.offset:X}, lib, {lib_name}, {obj_stem}, .text]\n")
                    
                    prev_end = r.offset + text_size
                
                # Helper function to write section using the section list ordering
                def write_section_from_list(section_name: str, section_list: list[dict], offsets_dict: dict):
                    if not section_list:
                        return
                    
                    # Determine gap type based on section
                    if section_name == ".data":
                        gap_type = "data"
                    elif section_name == ".rdata":
                        gap_type = "rodata"
                    else:
                        gap_type = "data"  # fallback
                    
                    f.write(f"\n      # === {section_name} segments ===\n")
                    
                    prev_end = None
                    
                    for entry in section_list:
                        lib = entry["library"]
                        obj = entry["object"]
                        size = entry["size"]
                        
                        obj_stem = Path(obj).stem
                        lib_name = lib.replace('.LIB', '') if lib else "LOOSE"
                        
                        # Use resolved offset if available
                        key = (lib, obj)
                        if key in offsets_dict:
                            offset = offsets_dict[key]
                            
                            # Add gap entry if there's space between previous end and this offset
                            if prev_end is not None and offset > prev_end:
                                gap_size = offset - prev_end
                                f.write(f"      - [0x{prev_end:X}, {gap_type}]  # gap: 0x{gap_size:X}\n")
                            
                            f.write(f"      - [0x{offset:X}, lib, {lib_name}, {obj_stem}, {section_name}]  # size: 0x{size:X}\n")
                            
                            # Update prev_end (align to 4 bytes)
                            prev_end = offset + size
                            prev_end = (prev_end + 3) & ~3  # align up to 4
                        else:
                            # No resolved offset - can't track gaps
                            f.write(f"      - [auto, lib, {lib_name}, {obj_stem}, {section_name}]  # size: 0x{size:X}\n")
                
                # Write .data and .rdata using the new section lists
                write_section_from_list(".data", self.data_section_list, data_offsets)
                write_section_from_list(".rdata", self.rdata_section_list, rdata_offsets)
                
                # For other sections, use the old approach (still based on .text order)
                def write_section_auto(section_name: str):
                    has_any = any(
                        self.enrich_data.get((r.library, r.object_name), {}).get("section_sizes", {}).get(section_name, 0) > 0
                        for r in valid_results
                    )
                    if not has_any:
                        return
                    
                    f.write(f"\n      # === {section_name} segments ===\n")
                    
                    for r in valid_results:
                        key = (r.library, r.object_name)
                        info = self.enrich_data.get(key, {})
                        size = info.get("section_sizes", {}).get(section_name, 0)
                        if size <= 0:
                            continue
                        
                        obj_stem = Path(r.object_name).stem
                        lib_name = r.library.replace('.LIB', '') if r.library else "LOOSE"
                        
                        f.write(f"      - [auto, lib, {lib_name}, {obj_stem}, {section_name}]  # size: 0x{size:X}\n")
                
                write_section_auto(".sdata")
                write_section_auto(".sbss")
                write_section_auto(".bss")
            
            self.status_message = f"Exported Splat YAML to {export_path}"
        except Exception as e:
            self.status_message = f"Export failed: {e}"
    
    def render_library_explorer_tab(self):
        """Render the library explorer tab."""
        if not self.versions:
            imgui.text("No SDK versions available")
            return
        
        # Top bar: version + library selectors
        imgui.text("SDK Version:")
        imgui.same_line()
        imgui.set_next_item_width(100)
        changed_ver, self.explorer_version_idx = imgui.combo(
            "##explorer_version", self.explorer_version_idx, self.versions
        )
        
        version = self.versions[self.explorer_version_idx]
        libs = self._get_libraries_for_version(version)
        
        imgui.same_line()
        imgui.text("Library:")
        imgui.same_line()
        imgui.set_next_item_width(200)
        if libs:
            changed_lib, self.explorer_lib_idx = imgui.combo(
                "##explorer_lib", self.explorer_lib_idx, libs
            )
            self.explorer_lib_idx = min(self.explorer_lib_idx, len(libs) - 1)
        else:
            changed_lib = False
            imgui.text_colored("(none available)", 0.5, 0.5, 0.5, 1.0)
        
        # Load library if selection changed
        if changed_ver or changed_lib or self.explorer_lib is None:
            if libs:
                self.explorer_lib = self.sdk_manager.fetch_library(
                    version, libs[self.explorer_lib_idx]
                )
                self.explorer_obj_idx = -1
                self.explorer_filter_text = ""
                self._update_explorer_filter()
            else:
                self.explorer_lib = None
        
        if not self.explorer_lib:
            return
        
        lib = self.explorer_lib
        
        imgui.same_line()
        imgui.text_colored(
            f"({len(lib.objects)} objects)",
            0.6, 0.6, 0.6, 1.0
        )
        
        imgui.separator()
        
        # Split: object list on left, details on right
        avail_width = imgui.get_content_region_available_width()
        left_width = min(280, avail_width * 0.3)
        
        # === LEFT PANEL: Object list ===
        imgui.begin_child("explorer_obj_list", left_width, 0, border=True)
        
        # Filter
        imgui.text("Filter:")
        imgui.same_line()
        imgui.set_next_item_width(-1)
        changed_filter, self.explorer_filter_text = imgui.input_text(
            "##explorer_filter", self.explorer_filter_text, 256
        )
        if changed_filter:
            self._update_explorer_filter()
        
        imgui.separator()
        
        filtered = self.explorer_filtered_objects
        for list_pos, obj_idx in enumerate(filtered):
            obj = lib.objects[obj_idx]
            is_selected = (obj_idx == self.explorer_obj_idx)
            
            # Count real labels (skip loc_ / text_)
            func_count = sum(
                1 for l in obj.labels
                if not l.name.startswith("loc_") and not l.name.startswith("text_")
            )
            sig_len = len(parse_signature(obj.sig))
            
            label = f"{obj.name}  ({func_count}f, 0x{sig_len:X}b)"
            
            clicked, _ = imgui.selectable(label, is_selected)
            if clicked:
                self.explorer_obj_idx = obj_idx
        
        imgui.end_child()
        
        imgui.same_line()
        
        # === RIGHT PANEL: Object details ===
        imgui.begin_child("explorer_obj_detail", 0, 0, border=True)
        
        if self.explorer_obj_idx < 0 or self.explorer_obj_idx >= len(lib.objects):
            imgui.text_colored("Select an object from the list", 0.5, 0.5, 0.5, 1.0)
            imgui.end_child()
            return
        
        obj = lib.objects[self.explorer_obj_idx]
        parsed = parse_signature(obj.sig)
        
        # Header
        imgui.text_colored(obj.name, 1.0, 1.0, 0.6, 1.0)
        imgui.same_line()
        imgui.text(f"- {lib.name} (SDK {version})")
        imgui.text(f"Signature: 0x{len(parsed):X} bytes ({len(parsed)} bytes)")
        
        # Count wildcards
        wildcards = sum(1 for _, w in parsed if w)
        concrete = len(parsed) - wildcards
        imgui.same_line()
        imgui.text_colored(
            f"  [{concrete} concrete, {wildcards} wildcard]",
            0.6, 0.6, 0.6, 1.0
        )
        
        imgui.separator()
        
        # --- Labels / Functions section ---
        real_labels = [
            l for l in obj.labels
            if not l.name.startswith("loc_") and not l.name.startswith("text_")
        ]
        all_labels = obj.labels
        
        if imgui.collapsing_header(f"Functions ({len(real_labels)})##funcs", imgui.TREE_NODE_DEFAULT_OPEN)[0]:
            if real_labels:
                imgui.columns(2, "label_cols")
                imgui.set_column_width(0, 250)
                imgui.text_colored("Name", 0.7, 0.7, 0.7, 1.0)
                imgui.next_column()
                imgui.text_colored("Offset", 0.7, 0.7, 0.7, 1.0)
                imgui.columns(1)
                imgui.separator()
                
                for lbl in real_labels:
                    imgui.columns(2, f"lbl_{lbl.name}")
                    imgui.set_column_width(0, 250)
                    imgui.text_colored(lbl.name, 0.5, 0.9, 1.0, 1.0)
                    imgui.next_column()
                    imgui.text(f"0x{lbl.offset:X}")
                    imgui.columns(1)
            else:
                imgui.text_colored("(no function labels)", 0.5, 0.5, 0.5, 1.0)
        
        # Internal labels (loc_, text_) in a collapsed section
        internal_labels = [
            l for l in obj.labels
            if l.name.startswith("loc_") or l.name.startswith("text_")
        ]
        if internal_labels:
            if imgui.collapsing_header(f"Internal Labels ({len(internal_labels)})##internal")[0]:
                for lbl in internal_labels:
                    imgui.text_colored(
                        f"  {lbl.name}",
                        0.5, 0.5, 0.5, 1.0
                    )
                    imgui.same_line()
                    imgui.text(f"@ 0x{lbl.offset:X}")
        
        imgui.separator()
        
        # --- Hex view of signature ---
        if imgui.collapsing_header("Signature Hex View##hexview", imgui.TREE_NODE_DEFAULT_OPEN)[0]:
            self._render_explorer_hex_view(parsed, all_labels)
        
        imgui.end_child()
    
    def _update_explorer_filter(self):
        """Update the filtered object list based on filter text."""
        if not self.explorer_lib:
            self.explorer_filtered_objects = []
            return
        
        filter_lower = self.explorer_filter_text.lower()
        result = []
        for i, obj in enumerate(self.explorer_lib.objects):
            if not filter_lower:
                result.append(i)
                continue
            # Match against object name or any label name
            if filter_lower in obj.name.lower():
                result.append(i)
                continue
            if any(filter_lower in l.name.lower() for l in obj.labels):
                result.append(i)
                continue
        
        self.explorer_filtered_objects = result
    
    def _render_explorer_hex_view(self, parsed: list[tuple[int, bool]], labels: list[Label]):
        """Render a hex view of the signature with label markers."""
        bpr = self.explorer_hex_bytes_per_row
        
        # Build a set of label offsets for quick lookup
        label_map: dict[int, str] = {}
        for lbl in labels:
            if lbl.offset < len(parsed):
                label_map[lbl.offset] = lbl.name
        
        imgui.begin_child("hex_view_scroll", 0, 0, border=False)
        
        for row_start in range(0, len(parsed), bpr):
            row_end = min(row_start + bpr, len(parsed))
            
            # Check if any label starts in this row — show a marker line
            for offset in range(row_start, row_end):
                if offset in label_map:
                    name = label_map[offset]
                    # Display style based on label type
                    if name.startswith("loc_") or name.startswith("text_"):
                        imgui.text_colored(
                            f"  ; --- {name} (0x{offset:X}) ---",
                            0.4, 0.4, 0.4, 1.0
                        )
                    else:
                        imgui.text_colored(
                            f"  >>> {name} (0x{offset:X}) <<<",
                            0.4, 1.0, 0.6, 1.0
                        )
            
            # Offset column
            imgui.text_colored(f"0x{row_start:04X}: ", 0.4, 0.4, 0.4, 1.0)
            imgui.same_line()
            
            # Hex bytes
            for i in range(row_start, row_end):
                byte_val, is_wild = parsed[i]
                hex = "??" if is_wild else f"{byte_val:02X}"
                
                if i in label_map:
                    # First byte of a label — highlight
                    imgui.text_colored(hex, 0.4, 1.0, 0.6, 1.0)
                elif is_wild:
                    imgui.text_colored(hex, 0.4, 0.4, 0.6, 1.0)
                else:
                    imgui.text_colored(hex, 0.8, 0.8, 0.8, 1.0)
                
                if i < row_end - 1:
                    imgui.same_line()
            
            # ASCII column
            imgui.same_line()
            imgui.text_colored("  |", 0.3, 0.3, 0.3, 1.0)
            imgui.same_line()
            
            ascii_str = ""
            for i in range(row_start, row_end):
                byte_val, is_wild = parsed[i]
                if is_wild:
                    ascii_str += "."
                elif 32 <= byte_val <= 126:
                    ascii_str += chr(byte_val)
                else:
                    ascii_str += "."
            
            imgui.text_colored(ascii_str, 0.5, 0.5, 0.5, 1.0)
        
        imgui.end_child()
    
    def render_verify_splat_tab(self):
        """Render the Splat YAML verification tab."""
        imgui.text("Verify Splat YAML against binary and SDK objects")
        imgui.separator()
        
        # Check prerequisites
        if not PYELFTOOLS_AVAILABLE:
            imgui.text_colored(
                "pyelftools not installed - run: pip install pyelftools",
                1.0, 0.5, 0.3, 1.0
            )
            return
        
        # Input: Splat YAML path
        imgui.text("Splat YAML file:")
        _, self.verify_splat_path = imgui.input_text(
            "##verify_splat_path", self.verify_splat_path, 512
        )
        
        # Binary path (reuse from scan)
        imgui.text(f"Binary: {self.scan_binary_path or '(set in Scan Binary tab)'}")
        
        # SDK root (reuse from enrich)
        imgui.text(f"SDK Root: {self.enrich_repo_root or '(set in Enrich & Export tab)'}")
        
        imgui.separator()
        
        # Version overrides info
        if self.lib_version_overrides:
            imgui.text_colored(
                f"Using {len(self.lib_version_overrides)} library version override(s)",
                0.8, 0.8, 0.3, 1.0
            )
        
        # Verify button
        can_verify = (
            self.verify_splat_path 
            and os.path.exists(self.verify_splat_path)
            and self.scan_binary_path
            and os.path.exists(self.scan_binary_path)
            and self.enrich_repo_root
        )
        
        if can_verify:
            if imgui.button("Verify Splat YAML", width=180):
                self._do_verify_splat()
        else:
            imgui.text_colored(
                "Set Splat YAML path, binary path (Scan tab), and SDK root (Enrich tab)",
                0.5, 0.5, 0.5, 1.0
            )
        
        imgui.separator()
        
        # Results
        if self.verify_results:
            # Summary
            total = len(self.verify_results)
            perfect = sum(1 for r in self.verify_results if r.get("match_pct", 0) >= 99.9)
            good = sum(1 for r in self.verify_results if 90 <= r.get("match_pct", 0) < 99.9)
            bad = sum(1 for r in self.verify_results if r.get("match_pct", 0) < 90)
            errors = sum(1 for r in self.verify_results if r.get("error"))
            
            imgui.text(f"Results: {total} entries")
            imgui.same_line()
            imgui.text_colored(f"[{perfect} perfect]", 0.3, 1.0, 0.3, 1.0)
            imgui.same_line()
            imgui.text_colored(f"[{good} good]", 0.8, 1.0, 0.3, 1.0)
            imgui.same_line()
            imgui.text_colored(f"[{bad} bad]", 1.0, 0.5, 0.3, 1.0)
            if errors > 0:
                imgui.same_line()
                imgui.text_colored(f"[{errors} errors]", 1.0, 0.3, 0.3, 1.0)
            
            imgui.begin_child("verify_results", 0, 0, border=True)
            
            # Header
            imgui.columns(6, "verify_cols")
            imgui.set_column_width(0, 90)   # Offset
            imgui.set_column_width(1, 100)  # Library
            imgui.set_column_width(2, 100)  # Object
            imgui.set_column_width(3, 60)   # Section
            imgui.set_column_width(4, 60)   # Match%
            imgui.text("Offset")
            imgui.next_column()
            imgui.text("Library")
            imgui.next_column()
            imgui.text("Object")
            imgui.next_column()
            imgui.text("Section")
            imgui.next_column()
            imgui.text("Match")
            imgui.next_column()
            imgui.text("Status")
            imgui.columns(1)
            imgui.separator()
            
            for result in self.verify_results:
                row_id = f"vfy_{result['offset']}_{result['object']}"
                
                imgui.columns(6, row_id)
                imgui.set_column_width(0, 90)
                imgui.set_column_width(1, 100)
                imgui.set_column_width(2, 100)
                imgui.set_column_width(3, 60)
                imgui.set_column_width(4, 60)
                
                # Offset
                if result.get("error"):
                    imgui.text_colored(f"0x{result['offset']:X}", 1.0, 0.3, 0.3, 1.0)
                else:
                    imgui.text(f"0x{result['offset']:X}")
                imgui.next_column()
                
                # Library
                imgui.text(result.get("library", ""))
                imgui.next_column()
                
                # Object
                imgui.text(result.get("object", ""))
                imgui.next_column()
                
                # Section
                imgui.text(result.get("section", ""))
                imgui.next_column()
                
                # Match percentage
                match_pct = result.get("match_pct", 0)
                if result.get("error"):
                    imgui.text_colored("-", 1.0, 0.3, 0.3, 1.0)
                elif match_pct >= 99.9:
                    imgui.text_colored(f"{match_pct:.1f}%", 0.3, 1.0, 0.3, 1.0)
                elif match_pct >= 90:
                    imgui.text_colored(f"{match_pct:.1f}%", 0.8, 1.0, 0.3, 1.0)
                else:
                    imgui.text_colored(f"{match_pct:.1f}%", 1.0, 0.5, 0.3, 1.0)
                imgui.next_column()
                
                # Status
                if result.get("error"):
                    imgui.text_colored(result["error"], 1.0, 0.3, 0.3, 1.0)
                elif match_pct >= 99.9:
                    imgui.text_colored("OK", 0.3, 1.0, 0.3, 1.0)
                elif match_pct >= 90:
                    imgui.text_colored("Close", 0.8, 1.0, 0.3, 1.0)
                else:
                    imgui.text_colored("Mismatch", 1.0, 0.5, 0.3, 1.0)
                
                imgui.columns(1)
                imgui.separator()
            
            imgui.end_child()
    
    def _do_verify_splat(self):
        """Parse and verify a Splat YAML file."""
        self.verify_results = []
        
        # Parse the YAML
        try:
            import yaml
        except ImportError:
            self.status_message = "PyYAML not installed - run: pip install pyyaml"
            return
        
        try:
            with open(self.verify_splat_path) as f:
                content = f.read()
        except Exception as e:
            self.status_message = f"Failed to read Splat YAML: {e}"
            return
        
        # Parse lib entries manually (the format is list-based, not standard YAML)
        # Format: - [0x1234, lib, LIBNAME, OBJNAME, .section]
        import re
        lib_pattern = re.compile(r'\[\s*0x([0-9A-Fa-f]+)\s*,\s*lib\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*(\.\w+)\s*\]')
        
        entries = []
        for line in content.split('\n'):
            match = lib_pattern.search(line)
            if match:
                offset = int(match.group(1), 16)
                library = match.group(2) + ".LIB"  # Add .LIB back
                obj = match.group(3) + ".OBJ"      # Add .OBJ back
                section = match.group(4)
                entries.append({
                    "offset": offset,
                    "library": library,
                    "object": obj,
                    "section": section,
                })
        
        if not entries:
            self.status_message = "No lib entries found in Splat YAML"
            return
        
        # Get base version
        base_version = None
        if self.scan_version_idx > 0 and self.versions:
            base_version = self.versions[self.scan_version_idx - 1]
        
        repo_root = Path(self.enrich_repo_root).expanduser()
        
        # Cache obj roots per version
        def get_obj_root(version: str) -> Optional[Path]:
            possible_roots = [
                repo_root / "assets" / "psyq" / version / "obj",
                repo_root / version / "obj",
                repo_root / "obj",
            ]
            for candidate in possible_roots:
                if candidate.exists():
                    return candidate
            return None
        
        # Read binary
        try:
            with open(self.scan_binary_path, "rb") as f:
                binary = f.read()
        except Exception as e:
            self.status_message = f"Failed to read binary: {e}"
            return
        
        # Verify each entry
        for entry in entries:
            result = dict(entry)
            
            # Get version for this library
            lib_key = entry["library"]
            version = self.lib_version_overrides.get(lib_key) or base_version
            
            if not version:
                result["error"] = "No version"
                self.verify_results.append(result)
                continue
            
            obj_root = get_obj_root(version)
            if not obj_root:
                result["error"] = f"No obj root for {version}"
                self.verify_results.append(result)
                continue
            
            # Find object file
            # Check if this is a loose OBJ file (library name ends with .OBJ)
            is_loose_obj = entry["library"].upper().endswith(".OBJ")
            
            if is_loose_obj:
                # Loose OBJ: file is at root level
                obj_file = obj_to_filename(entry["library"])  # Use library name as file name
                o_path = obj_root / obj_file
            else:
                # Library object: {obj_root}/{lib_folder}/{obj_file}
                lib_folder = lib_to_folder(entry["library"])
                obj_file = obj_to_filename(entry["object"])
                o_path = obj_root / lib_folder / obj_file
                
                if not o_path.exists():
                    # Fallback: try as loose obj
                    o_path = obj_root / obj_file
            
            if not o_path.exists():
                result["error"] = "Obj not found"
                self.verify_results.append(result)
                continue
            
            # Get ELF section info
            info = enrich_object(o_path)
            if info.get("errors"):
                result["error"] = "ELF error"
                self.verify_results.append(result)
                continue
            
            section_info = info.get("sections", {}).get(entry["section"], {})
            section_offset = section_info.get("offset", 0)
            section_size = section_info.get("size", 0)
            
            if section_size <= 0:
                result["error"] = f"No {entry['section']}"
                self.verify_results.append(result)
                continue
            
            # Read section from object
            try:
                with open(o_path, "rb") as f:
                    f.seek(section_offset)
                    obj_data = f.read(section_size)
            except Exception:
                result["error"] = "Read error"
                self.verify_results.append(result)
                continue
            
            # Get relocations for masking
            relocs = info.get("relocations", {}).get(entry["section"], [])
            mask = bytearray(b'\xFF' * section_size)
            for reloc_offset in relocs:
                if reloc_offset < section_size:
                    for i in range(4):
                        if reloc_offset + i < section_size:
                            mask[reloc_offset + i] = 0x00
            
            # Compare with binary
            bin_offset = entry["offset"]
            if bin_offset + section_size > len(binary):
                result["error"] = "Out of range"
                self.verify_results.append(result)
                continue
            
            match_score = 0
            total_concrete = 0
            for i in range(section_size):
                if mask[i] == 0xFF:
                    total_concrete += 1
                    if binary[bin_offset + i] == obj_data[i]:
                        match_score += 1
            
            if total_concrete > 0:
                result["match_pct"] = (match_score / total_concrete) * 100
            else:
                result["match_pct"] = 100.0  # All wildcards
            
            result["matched"] = match_score
            result["total"] = total_concrete
            result["size"] = section_size
            
            self.verify_results.append(result)
        
        self.status_message = f"Verified {len(entries)} entries"
    
    def render_cache_tab(self):
        """Render the cache management tab."""
        imgui.text("Cache Management")
        imgui.separator()
        
        cache_size = sum(f.stat().st_size for f in CACHE_DIR.rglob("*") if f.is_file()) if CACHE_DIR.exists() else 0
        imgui.text(f"Cache location: {CACHE_DIR}")
        imgui.text(f"Cache size: {cache_size / 1024:.1f} KB")
        
        imgui.separator()
        
        if imgui.button("Clear Cache", width=120):
            self.sdk_manager.clear_cache()
            self.versions = []
            self.libraries = {}
            self.all_libraries = []  # Reset library list so it gets refreshed
            self.func_library_idx = 0
            self.obj_library_idx = 0
            self.obj_objects_list = []
            self.obj_object_idx = 0
            self.find_func_library_idx = 0
            self.find_func_results = []
            self.scan_version_idx = 0
            self.scan_library_idx = 0
            self.scan_preprocessed = False
            self.scan_results = []
            self.enrich_data = {}
            self.enrich_errors = []
            self.enrich_obj_root = ""
            self._init_versions()
            self.status_message = "Cache cleared"
        
        imgui.same_line()
        if imgui.button("Refresh Versions", width=120):
            self._init_versions()
    
    def render(self):
        """Render the main application UI."""
        # Main window
        imgui.set_next_window_position(10, 10, imgui.FIRST_USE_EVER)
        imgui.set_next_window_size(900, 600, imgui.FIRST_USE_EVER)
        
        # Menu bar
        if imgui.begin_menu_bar():
            if imgui.begin_menu("File"):
                if imgui.menu_item("Clear Cache")[0]:
                    self.sdk_manager.clear_cache()
                    self._init_versions()
                if imgui.menu_item("Exit")[0]:
                    return False
                imgui.end_menu()
            if imgui.begin_menu("Help"):
                if imgui.menu_item("About")[0]:
                    self.status_message = "PSY-Q SDK Version Finder - For PS1 Decompilation"
                imgui.end_menu()
            imgui.end_menu_bar()
        
        # Tabs
        if imgui.begin_tab_bar("main_tabs"):
            if imgui.begin_tab_item("Compare Functions")[0]:
                self.render_compare_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Match Function")[0]:
                self.render_match_function_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Match Object")[0]:
                self.render_match_object_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Find Function")[0]:
                self.render_find_function_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Scan Binary")[0]:
                self.render_scan_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Enrich & Export")[0]:
                self.render_enrich_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Verify Splat")[0]:
                self.render_verify_splat_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Library Explorer")[0]:
                self.render_library_explorer_tab()
                imgui.end_tab_item()
            
            if imgui.begin_tab_item("Cache")[0]:
                self.render_cache_tab()
                imgui.end_tab_item()
            
            imgui.end_tab_bar()
        
        # Status bar
        imgui.separator()
        imgui.text(f"Status: {self.status_message}")
        
        return True


def main():
    """Main entry point."""
    # Initialize GLFW
    if not glfw.init():
        print("Failed to initialize GLFW")
        sys.exit(1)

    # Create window
    glfw.window_hint(glfw.CONTEXT_VERSION_MAJOR, 3)
    glfw.window_hint(glfw.CONTEXT_VERSION_MINOR, 3)
    glfw.window_hint(glfw.OPENGL_PROFILE, glfw.OPENGL_CORE_PROFILE)
    glfw.window_hint(glfw.OPENGL_FORWARD_COMPAT, gl.GL_TRUE)

    window = glfw.create_window(1024, 768, "PSY-Q SDK Version Finder", None, None)
    if not window:
        glfw.terminate()
        print("Failed to create window")
        sys.exit(1)

    glfw.make_context_current(window)
    glfw.swap_interval(1)  # Enable vsync

    # Initialize ImGui
    imgui.create_context()
    impl = GlfwRenderer(window)

    # Create application
    app = PSYQApp()

    # Main loop
    while not glfw.window_should_close(window):
        glfw.poll_events()
        impl.process_inputs()

        imgui.new_frame()

        # --- Root fullscreen "app surface" (no floating window chrome) ---
        # Match ImGui to the current GLFW window size every frame
        w, h = glfw.get_framebuffer_size(window)  # framebuffer is safest for GL
        imgui.set_next_window_position(0.0, 0.0)
        imgui.set_next_window_size(float(w), float(h))

        root_flags = (
            imgui.WINDOW_NO_TITLE_BAR |
            imgui.WINDOW_NO_RESIZE |
            imgui.WINDOW_NO_MOVE |
            imgui.WINDOW_NO_COLLAPSE |
            imgui.WINDOW_NO_SAVED_SETTINGS |
            imgui.WINDOW_NO_BRING_TO_FRONT_ON_FOCUS |
            imgui.WINDOW_NO_NAV_FOCUS
        )

        imgui.push_style_var(imgui.STYLE_WINDOW_PADDING, (0.0, 0.0))
        imgui.begin("##Root", True, root_flags)
        imgui.pop_style_var()

        if not app.render():
            imgui.end()
            break

        imgui.end()

        gl.glClearColor(0.1, 0.1, 0.1, 1.0)
        gl.glClear(gl.GL_COLOR_BUFFER_BIT)

        imgui.render()
        impl.render(imgui.get_draw_data())

        glfw.swap_buffers(window)

    # Cleanup
    impl.shutdown()
    glfw.terminate()


if __name__ == "__main__":
    main()