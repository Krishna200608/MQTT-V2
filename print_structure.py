#!/usr/bin/env python3
"""
print_structure.py
-----------------------------------
Prints a visual tree of the entire project folder structure
starting from the directory this script is placed in.

✅ Works on Windows, Linux, macOS
✅ Automatically skips hidden files and __pycache__
✅ Shows both folders and files in a clear hierarchy
"""

from pathlib import Path

def print_tree(path: Path, prefix: str = ""):
    """Recursively print directory tree structure."""
    contents = sorted([p for p in path.iterdir() if not p.name.startswith(".")])
    pointers = ["├── "] * (len(contents) - 1) + ["└── "]
    
    for pointer, p in zip(pointers, contents):
        print(prefix + pointer + p.name)
        if p.is_dir() and p.name not in {"__pycache__", ".venv", "env", "venv"}:
            extension = "│   " if pointer == "├── " else "    "
            print_tree(p, prefix + extension)

if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    print(f"\n📂 Project structure for: {root}\n")
    print(root.name)
    print_tree(root)
    print("\n✅ Folder structure printed successfully.")
