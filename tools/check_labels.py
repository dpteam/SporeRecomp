#!/usr/bin/env python3
"""Static check on the generated code: every `goto L_xxx` must have a label in the same function,
and no function may be defined twice.

Both errors only surface at link time, after a full rebuild. This catches them in seconds.

Usage: python tools/check_labels.py
Exit code 1 if anything is wrong.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

GEN = Path("recomp/gen")

# `void sub_XXXXXXXX(` or `static void sub_XXXXXXXX_body(` starts a function body.
FUNC_RE = re.compile(r"^(?:static\s+)?void\s+sub_([0-9a-f]{8})(?:_body)?\s*\(")
GOTO_RE = re.compile(r"goto\s+L_([0-9a-f]{8})")
LABEL_RE = re.compile(r"^L_([0-9a-f]{8}):")
DEF_RE = re.compile(r"^(?:static\s+)?void\s+sub_([0-9a-f]{8})(_mid)?\s*\(")


def main() -> int:
    files = sorted(GEN.glob("funcs_*.cpp"))
    if not files:
        print(f"no generated chunks in {GEN}; run tools/lift.py")
        return 1

    problems = 0
    checked = 0

    # Duplicate definitions are a link error: a function emitted by two chunks, which happens
    # when stale chunks from a previous lift survive a re-run.
    defined_in: dict[str, str] = {}
    for path in files:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = DEF_RE.match(line)
            if not m:
                continue
            name = m.group(1) + (m.group(2) or "")
            if name in defined_in:
                problems += 1
                if problems <= 10:
                    print(f"DUPLICATE sub_{name}: {defined_in[name]} and {path.name}")
            else:
                defined_in[name] = path.name
    print(f"definitions: {len(defined_in):,} in {len(files)} chunks")

    for path in files:
        func = None
        defined: set[str] = set()
        used: list[tuple[str, int]] = []

        def flush(fn, defs, uses):
            nonlocal problems
            if fn is None:
                return
            missing = [(u, ln) for u, ln in uses if u not in defs]
            if missing:
                problems += len(missing)
                print(f"{path.name}: function sub_{fn}")
                for label, line in missing[:5]:
                    print(f"  line {line}: goto L_{label} has no label")
                if len(missing) > 5:
                    print(f"  ... and {len(missing) - 5} more")

        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace")
                                       .splitlines(), 1):
            m = FUNC_RE.match(line)
            if m:
                flush(func, defined, used)
                func = m.group(1)
                defined = set()
                used = []
                checked += 1
                continue
            lm = LABEL_RE.match(line)
            if lm:
                defined.add(lm.group(1))
            for gm in GOTO_RE.finditer(line):
                used.append((gm.group(1), lineno))
        flush(func, defined, used)

    print(f"checked {checked:,} function bodies")
    if problems:
        print(f"FAIL: {problems} problem(s)")
        return 1
    print("OK: no dangling labels, no duplicate definitions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
