#!/usr/bin/env python3
"""Link-safety check: every symbol the import table references must be defined exactly once.

Catches the two failure modes that only show up at link time, after a two-hour compile:
  * a declared import implementation with no definition (undefined reference)
  * the same implementation defined in two translation units (multiple definition)

Run before a full build.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

TABLE = Path("src/rt/imports_table.cpp")
SOURCES = sorted(Path("src").rglob("*.cpp"))


def referenced() -> dict[str, int]:
    """Symbol -> how many descriptors reference it."""
    out: dict[str, int] = defaultdict(int)
    text = TABLE.read_text(encoding="utf-8")
    for m in re.finditer(r"sr::w32::(\w+)", text):
        out[m.group(1)] += 1
    return out


def defined() -> dict[str, list[str]]:
    """Symbol -> files that define it (a definition is a body, not a declaration)."""
    out: dict[str, list[str]] = defaultdict(list)
    decl = re.compile(r"^\s*void\s+(\w+)\s*\(CpuState\*[^;]*\)\s*\{", re.M)
    for path in SOURCES:
        text = path.read_text(encoding="utf-8")
        for m in decl.finditer(text):
            out[m.group(1)].append(str(path))
    return out


def main() -> int:
    refs = referenced()
    defs = defined()

    missing = sorted(s for s in refs if s not in defs)
    dupes = {s: f for s, f in defs.items() if len(f) > 1}
    dupes = {s: f for s, f in dupes.items() if s in refs}

    print(f"import table references {len(refs)} distinct implementations")
    print(f"sources define {len(defs)} implementations")

    rc = 0
    if missing:
        rc = 1
        print(f"\nMISSING DEFINITION ({len(missing)}):")
        for s in missing:
            print(f"  {s}  (referenced {refs[s]}x)")
    if dupes:
        rc = 1
        print(f"\nDUPLICATE DEFINITION ({len(dupes)}):")
        for s, files in sorted(dupes.items()):
            print(f"  {s}:")
            for f in files:
                print(f"    {f}")

    unused = sorted(s for s in defs if s not in refs)
    if unused:
        # Not a failure: these are helpers the lifted code calls directly (aad, mmx_*, ...)
        # and functions that exist for imports a different Spore build might need.
        print(f"\n{len(unused)} definitions are not referenced by the import table "
              f"(helpers or spare implementations):")
        for s in unused[:20]:
            print(f"  {s}")
        if len(unused) > 20:
            print(f"  ... and {len(unused) - 20} more")

    if rc == 0:
        print("\n[check-imports] every referenced implementation has exactly one definition")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
