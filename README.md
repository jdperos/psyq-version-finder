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

Select two SDK versions and a library to see a color-coded byte diff of any function:

- **Gray** — identical bytes
- **Blue** — wildcards (`??`)
- **Red/Green** — bytes that differ between versions

Useful for quickly spotting the differences when you've narrowed it down to a few candidate versions.

### Match Binary

Point the tool at your binary, specify an offset and function name, and it searches the signature database to find matching SDK versions.

- Select a specific library (e.g., `LIBSPU.LIB`) to search only that library across all SDK versions — much faster than searching everything
- Results show match percentage so you can see how confident the match is

### Caching

Signature JSONs are fetched from [lab313ru/psx_psyq_signatures](https://github.com/lab313ru/psx_psyq_signatures) and cached locally in `~/.cache/psyq_signatures/`. First run will be slower as it downloads what you need; subsequent runs are fast.

## Tips

- If you know roughly which library a function is from, use the library dropdown to speed up searches significantly
- Functions at 95%+ match are usually exact matches — lower percentages may indicate version differences or relocation issues
- The Compare Functions tab is great for understanding *what* changed between versions once you've identified candidates

## Credits

Signature data from [lab313ru/psx_psyq_signatures](https://github.com/lab313ru/psx_psyq_signatures)