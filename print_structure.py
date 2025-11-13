#!/usr/bin/env python3
"""
print_structure.py
-----------------------------------
Prints a visual tree of the entire project folder structure
starting from the directory this script is placed in, and
also saves it to tree.txt inside the same folder.

Works on Windows, Linux, macOS.
"""

from pathlib import Path

def build_tree(path: Path, prefix: str = "", lines: list = None):
    """Recursively build directory tree structure and store lines."""
    if lines is None:
        lines = []

    contents = sorted([p for p in path.iterdir() if not p.name.startswith(".")])
    pointers = ["├── "] * (len(contents) - 1) + ["└── "]

    for pointer, p in zip(pointers, contents):
        line = prefix + pointer + p.name
        print(line)
        lines.append(line)

        if p.is_dir() and p.name not in {"__pycache__", ".venv", "env", "venv"}:
            extension = "│   " if pointer == "├── " else "    "
            build_tree(p, prefix + extension, lines)

    return lines


if __name__ == "__main__":
    root = Path(__file__).resolve().parent

    print(f"\n📂 Project structure for: {root}\n")
    print(root.name)

    all_lines = [root.name]
    all_lines += build_tree(root)

    # Save output to tree.txt
    output_file = root / "folder_structure.txt"
    output_file.write_text("\n".join(all_lines), encoding="utf-8")

    print("\n✅ Folder structure saved to tree.txt successfully.")
