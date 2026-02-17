# PSY-Q SDK Version Finder

A tool for PS1 game decompilers to identify which PSY-Q SDK versions are used in their codebase by comparing function signatures.

## The Problem

When decompiling PS1 games, you often need to identify which version of Sony's PSY-Q SDK was used. This is tricky because:

- Games frequently mix functions from different SDK versions
- Manually comparing bytes against signature databases is tedious
- There are 10+ SDK versions, each with dozens of libraries

This tool speeds up the process by letting you visually diff signatures between versions and match your binary against the signature database.

## Installation

```bash
pip install -r requirements.txt
python psyq-finder.py
```

## Features

### Compare Functions

<img width="826" height="510" alt="image" src="https://github.com/user-attachments/assets/7ac2ffc4-2e8e-4f9b-a774-d4f9da4ee327" />

Select two SDK versions and a library to see a color-coded byte diff of any function:

- **Gray** — identical bytes
- **Blue** — wildcards (`??`)
- **Red/Green** — bytes that differ between versions

Useful for quickly spotting the differences when you've narrowed it down to a few candidate versions.

### Match Function

<img width="824" height="508" alt="image" src="https://github.com/user-attachments/assets/a18fd5e0-3875-458f-babc-3983d3ff35cb" />

Point the tool at your binary, specify an offset and function name, and it searches the signature database to find matching SDK versions.

- Select a specific library (e.g., `LIBSPU.LIB`) to search only that library across all SDK versions
- Results show match percentage so you can see how confident the match is

### Match Object

<img width="826" height="510" alt="image" src="https://github.com/user-attachments/assets/7bb987f0-76ec-4253-895b-1bfa8b595f47" />

Since old compilers linked entire objects (not individual functions), you can match a whole object signature for more reliable results.

- Select a library and object name from dropdowns
- Compares many more bytes than function matching, giving higher confidence results
- Shows matched bytes vs total signature size so you can see exactly how much data was compared

This is generally more reliable than function matching since you're comparing the entire compiled object file.

### Find Function

<img width="823" height="507" alt="image" src="https://github.com/user-attachments/assets/75f02701-54bc-4107-9c34-925a7d1527a6" />

Search for a function by name to see which library and object it lives in across all SDK versions.

- Enter a function name (e.g., `_spu_init`) and optionally filter by library (this will significantly improve performance)
- Results are collated: if a function lives in the same library/object across multiple versions, they're shown in one row
- Useful for understanding when functions were added or moved between objects

Example output for a function that moved between objects:
| Library | Object | SDK Versions |
|---------|--------|--------------|
| LIBSPU.LIB | SPU.OBJ | 330, 340, 350, 360, 400 |
| LIBSPU.LIB | SPU_NEW.OBJ | 410, 420, 430, 440, 446, 451, 460, 470 |

### Scan Binary

<img width="817" height="732" alt="image" src="https://github.com/user-attachments/assets/dbe7c234-c895-4bb9-975e-64ca9192430a" />

Point the tool at your entire PS1 binary and it will find **every** PSY-Q object present, reporting the offset, library, object name, functions within each object, and which SDK versions match.

**How it works:**
1. **Preprocess** — Downloads and caches all SDK signatures, deduplicates identical signatures across versions, and extracts optimized search "anchors" (longest consecutive concrete byte runs) from each.
2. **Scan** — For each unique signature, uses Python's C-optimized `bytes.find()` (Boyer-Moore) to locate anchor candidates in the binary, then verifies full signatures with wildcard masks. Only checks 4-byte aligned offsets (MIPS).
3. **Report** — Shows every matched object with offset, size, SDK versions, and all function labels with their absolute addresses.

**Why it's fast:**
- Signature deduplication: many objects are identical across versions, so we only scan once per unique pattern
- Anchor-based search: `bytes.find()` is C-level fast, and 8+ byte anchors eliminate 99.9%+ of false candidates
- MIPS alignment: only checks every 4th byte, cutting search space by 75%

For a typical 2MB PS1 binary, expect a scan to complete in seconds.

**Export:** Results can be exported to CSV for use in your decompilation project.

**Tip:** Use the library filter during preprocessing if you only care about specific libraries — this speeds up both preprocessing and scanning.

### Library Explorer

<img width="818" height="732" alt="image" src="https://github.com/user-attachments/assets/bb61f619-9cc0-4c23-a15c-1f366d9254f9" />

Browse the raw contents of any PSY-Q library across SDK versions. Select a version and library from the dropdowns to see all objects in that library.

- Left panel: Filterable object list — search by object name or function name
- Right panel: Full details for the selected object including all function labels with offsets, internal labels (collapsed by default), and a hex view of the signature with label markers and ASCII column

Useful for quickly checking what functions live in an object, seeing exact signature bytes, or comparing how a library's structure changed between SDK versions without digging through raw JSON files.

### Caching

Signature JSONs are fetched from [lab313ru/psx_psyq_signatures](https://github.com/lab313ru/psx_psyq_signatures) and cached locally in `~/.cache/psyq_signatures/`. First run will be slower as it downloads what you need; subsequent runs are fast.

## Tips

- **Scan Binary is the most powerful feature** — point it at your binary and get a complete map of all PSY-Q objects, their offsets, versions, and functions
- **Match Object is more reliable than Match Function** — it compares way more bytes, so you get higher confidence matches
- If you know roughly which library a function is from, use the library dropdown to speed up searches
- The Compare Functions tab is great for understanding *what* changed between versions once you've identified candidates
- Object matching reads 64KB from your binary, function matching reads 4KB — make sure your offset is correct
- When scanning, use the library filter during preprocessing if you only need to check specific libraries

## Credits

Signature data from [lab313ru/psx_psyq_signatures](https://github.com/lab313ru/psx_psyq_signatures)
