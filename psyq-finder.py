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
        """Get all functions (labels at offset 0 or starting with _) mapped to their object."""
        functions = {}
        for obj in self.objects:
            for label in obj.labels:
                # Include functions at offset 0 or with underscore prefix (common convention)
                if label.offset == 0 or label.name.startswith("_"):
                    functions[label.name] = (obj, label)
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
            # Maybe it's wrapped in a key?
            if "objects" in data:
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
        """Clear all cached files."""
        import shutil
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
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
            
            matching_bytes = 0
            total_concrete_bytes = 0
            
            for i, (expected, is_wildcard) in enumerate(parsed[sig_start:]):
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
    
    def preprocess(self, library_filter: Optional[str] = None) -> None:
        """
        Preprocess all signatures from all SDK versions.
        
        Deduplicates identical signatures across versions so we only scan once
        per unique byte pattern.
        
        Args:
            library_filter: If set, only preprocess this library (faster).
        """
        self._signatures = []
        self._preprocessed = False
        
        versions = self.sdk_manager.discover_versions()
        
        # Key: (library, object_name, data_bytes, mask_bytes) -> ScanSignature
        # This deduplicates identical signatures across versions
        sig_map: dict[tuple[str, str, bytes, bytes], ScanSignature] = {}
        
        # Also store labels per (library, object_name, version) for the results
        labels_map: dict[tuple[str, str, str], list[Label]] = {}
        
        total_steps = len(versions)
        
        for step, version in enumerate(versions):
            self._progress_message = f"Loading SDK {version}..."
            self._progress_pct = step / total_steps
            
            if library_filter:
                lib_names = [library_filter]
            else:
                lib_names = self.sdk_manager.discover_libraries(version)
            
            for lib_name in lib_names:
                lib = self.sdk_manager.fetch_library(version, lib_name)
                if not lib:
                    continue
                
                for obj in lib.objects:
                    if not obj.sig:
                        continue
                    
                    data, mask = signature_to_bytes(obj.sig)
                    if len(data) < self.MIN_ANCHOR_LENGTH:
                        continue  # Too short to scan reliably
                    
                    key = (lib_name, obj.name, data, mask)
                    labels_map[(lib_name, obj.name, version)] = obj.labels
                    
                    if key in sig_map:
                        # Same signature already seen — just add this version
                        sig_map[key].versions.append(version)
                    else:
                        # New unique signature
                        anchor_off, anchor_len = self._find_best_anchor(mask)
                        
                        if anchor_len < self.MIN_ANCHOR_LENGTH:
                            continue  # Not enough concrete bytes for a reliable anchor
                        
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
        self._progress_message = (
            f"Preprocessed {len(self._signatures)} unique signatures "
            f"({total_across_versions} total across versions{subsumption_msg})"
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
        
        self._progress_pct = 1.0
        ambiguous_count = sum(1 for r in results if r.is_ambiguous)
        ambig_msg = f" ({ambiguous_count} ambiguous)" if ambiguous_count else ""
        self._progress_message = f"Scan complete: {len(results)} objects found{ambig_msg}"
        
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
        self.scan_library_idx = 0  # 0 = All Libraries
        self.scan_results: list[ScanResult] = []
        self.scan_running = False
        self.scan_preprocessed = False
        self.scan_align_to_4 = True
        self.scan_export_path = ""
        self.scan_filter_text = ""
        
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
        """Get list of object names for a library (from any SDK version that has it)."""
        # Try to get from any cached version
        for version in self.versions:
            lib = self.sdk_manager.fetch_library(version, library_name)
            if lib and lib.objects:
                return sorted(set(obj.name for obj in lib.objects))
        return []
    
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
            if self.scan_engine.is_preprocessed:
                imgui.text_colored(
                    f"({self.scan_engine.signature_count} unique sigs ready)",
                    0.3, 1.0, 0.3, 1.0
                )
                self.scan_preprocessed = True
            else:
                imgui.text_colored("(Downloads & deduplicates all signatures)", 0.5, 0.5, 0.5, 1.0)
        else:
            imgui.text_colored(
                f"Signatures ready: {self.scan_engine.signature_count} unique patterns",
                0.3, 1.0, 0.3, 1.0
            )
            imgui.same_line()
            if imgui.small_button("Re-preprocess"):
                self.scan_preprocessed = False
        
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
            summary = f"Found {len(self.scan_results)} objects in binary"
            if ambiguous_count:
                summary += f" ({ambiguous_count} ambiguous)"
            imgui.text(summary)
            
            # Filter
            imgui.text("Filter:")
            imgui.same_line()
            _, self.scan_filter_text = imgui.input_text(
                "##scan_filter", self.scan_filter_text, 256
            )
            imgui.same_line()
            if imgui.small_button("Export CSV"):
                self._export_scan_results()
            
            # Filtered results
            filter_lower = self.scan_filter_text.lower()
            filtered = [
                r for r in self.scan_results
                if not filter_lower 
                or filter_lower in r.library.lower()
                or filter_lower in r.object_name.lower()
                or any(filter_lower in v for v in r.versions)
                or any(filter_lower in lbl.name.lower() for lbl in r.labels)
                or (filter_lower == "ambiguous" and r.is_ambiguous)
            ]
            
            imgui.text(f"Showing {len(filtered)} of {len(self.scan_results)} results")
            imgui.same_line()
            imgui.text_colored("(filter 'ambiguous' to show only ambiguous matches)", 0.5, 0.5, 0.5, 1.0)
            
            imgui.begin_child("scan_results", 0, 0, border=True)
            
            # Header
            imgui.columns(5, "scan_columns")
            imgui.set_column_width(0, 90)
            imgui.set_column_width(1, 130)
            imgui.set_column_width(2, 140)
            imgui.set_column_width(3, 80)
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
            
            for result in filtered:
                imgui.columns(5, f"scan_{result.offset:X}_{result.object_name}")
                imgui.set_column_width(0, 90)
                imgui.set_column_width(1, 130)
                imgui.set_column_width(2, 140)
                imgui.set_column_width(3, 80)
                
                # Offset — yellow if ambiguous
                if result.is_ambiguous:
                    imgui.text_colored(f"0x{result.offset:08X}", 1.0, 0.9, 0.3, 1.0)
                else:
                    imgui.text(f"0x{result.offset:08X}")
                imgui.next_column()
                imgui.text(result.library)
                imgui.next_column()
                imgui.text(result.object_name)
                imgui.next_column()
                
                # Size column
                if result.is_ambiguous:
                    # Show range of sizes
                    sizes = sorted(set(vg.sig_length for vg in result.version_groups))
                    if len(sizes) > 1:
                        imgui.text_colored(
                            f"0x{sizes[0]:X}-0x{sizes[-1]:X}",
                            1.0, 0.9, 0.3, 1.0
                        )
                    else:
                        imgui.text(f"0x{sizes[0]:X}")
                else:
                    imgui.text(f"0x{result.sig_length:X}")
                imgui.next_column()
                
                # Versions column
                if result.is_ambiguous:
                    # Show ambiguity warning
                    imgui.text_colored("[AMBIGUOUS - signature prefix overlap]", 1.0, 0.9, 0.3, 1.0)
                    
                    # Show each version group with its sig length
                    for vg in result.version_groups:
                        version_str = ", ".join(vg.versions)
                        imgui.text_colored(
                            f"  0x{vg.sig_length:X} bytes: {version_str}",
                            0.9, 0.85, 0.5, 1.0
                        )
                else:
                    # Normal: single version group
                    version_str = ", ".join(result.versions)
                    imgui.text_wrapped(version_str)
                
                # Show function labels in this object
                func_labels = [l for l in result.labels if l.name.startswith("_") or l.offset == 0]
                if func_labels:
                    for lbl in func_labels:
                        imgui.text_colored(
                            f"  {lbl.name} (+0x{lbl.offset:X} = 0x{result.offset + lbl.offset:08X})",
                            0.5, 0.8, 1.0, 1.0
                        )
                
                imgui.columns(1)
                imgui.separator()
            
            imgui.end_child()
    
    def _do_scan_preprocess(self):
        """Preprocess signatures for scanning."""
        library_filter = None
        if self.scan_library_idx > 0 and self.all_libraries:
            library_filter = self.all_libraries[self.scan_library_idx]
        
        self.scan_running = True
        filter_msg = f" (filtered to {library_filter})" if library_filter else ""
        self.status_message = f"Preprocessing signatures{filter_msg}..."
        
        self.scan_engine.preprocess(library_filter=library_filter)
        
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
            
            ambig_msg = f", {ambiguous} ambiguous" if ambiguous else ""
            self.status_message = (
                f"Scan complete: {unique_objects} objects found across "
                f"{unique_libs} libraries, {total_funcs} functions identified{ambig_msg}"
            )
        except Exception as e:
            self.status_message = f"Scan failed: {e}"
            self.scan_results = []
        
        self.scan_running = False
    
    def _export_scan_results(self):
        """Export scan results to CSV."""
        if not self.scan_results:
            return
        
        # Default export path next to the binary
        if self.scan_binary_path:
            base = os.path.splitext(self.scan_binary_path)[0]
            export_path = f"{base}_psyq_scan.csv"
        else:
            export_path = "psyq_scan.csv"
        
        try:
            with open(export_path, "w") as f:
                f.write("Offset,Library,Object,Size,Ambiguous,SDK Versions,Functions\n")
                for r in self.scan_results:
                    func_labels = [l for l in r.labels if l.name.startswith("_") or l.offset == 0]
                    funcs_str = "; ".join(
                        f"{l.name} (0x{r.offset + l.offset:08X})" for l in func_labels
                    )
                    
                    if r.is_ambiguous:
                        # Show each version group with its size
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
            self.status_message = f"Exported to {export_path}"
        except Exception as e:
            self.status_message = f"Export failed: {e}"
    
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
        
        imgui.begin("PSY-Q SDK Version Finder", flags=imgui.WINDOW_MENU_BAR)
        
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
            
            if imgui.begin_tab_item("Cache")[0]:
                self.render_cache_tab()
                imgui.end_tab_item()
            
            imgui.end_tab_bar()
        
        # Status bar
        imgui.separator()
        imgui.text(f"Status: {self.status_message}")
        
        imgui.end()
        
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
        
        if not app.render():
            break
        
        # Rendering
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