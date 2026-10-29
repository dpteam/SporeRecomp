"""Coverage check for the function census: how much of .text is claimed by a function,
what the gaps look like, and whether gaps are padding, data or missed code.

Usage: python tools/coverage.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")


def main() -> int:
    pe = PE(EXE.read_bytes())
    t = pe.section(".text")
    tva, tsz = t["va"], t["vsz"]
    tend = tva + tsz
    tbytes = pe.section_bytes(".text")

    funcs = [json.loads(l) for l in Path("analysis/functions.jsonl").read_text().splitlines()]
    claimed = bytearray(tsz)
    for f in funcs:
        lo = f["start"] - tva
        hi = min(f["end"] - tva, tsz)
        if 0 <= lo < hi:
            claimed[lo:hi] = b"\x01" * (hi - lo)
    n_claimed = sum(claimed)
    print(f"functions: {len(funcs):,}")
    print(f".text claimed: {n_claimed:,} / {tsz:,} bytes ({100*n_claimed/tsz:.1f}%)")

    # gap census
    gaps = []
    i = 0
    while i < tsz:
        if claimed[i]:
            i += 1
            continue
        j = i
        while j < tsz and not claimed[j]:
            j += 1
        gaps.append((i, j))
        i = j
    print(f"gaps: {len(gaps):,}; total {sum(b-a for a,b in gaps):,} bytes")
    sizes = Counter()
    for a, b in gaps:
        n = b - a
        sizes["1-4" if n <= 4 else "5-16" if n <= 16 else "17-64" if n <= 64
              else "65-256" if n <= 256 else "257-1k" if n <= 1024
              else ">1k"] += 1
    print("gap size histogram:", dict(sizes))

    # what do the big gaps look like?
    big = sorted(gaps, key=lambda g: -(g[1] - g[0]))[:15]
    print("\nlargest gaps:")
    for a, b in big:
        blob = tbytes[a:b]
        int3 = blob.count(b"\xcc") / max(1, len(blob))
        zero = blob.count(b"\x00") / max(1, len(blob))
        printable = sum(1 for c in blob[:2000] if 32 <= c < 127) / max(1, min(2000, len(blob)))
        print(f"  {tva+a:#08x}..{tva+b:#08x} ({b-a:,} B) int3={int3:.0%} zero={zero:.0%} "
              f"printable={printable:.0%}  first={blob[:12].hex()}")

    # undecodable / suspicious bytes inside claimed regions
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    print("\nre-decoding claimed regions to verify instruction stream ...")
    bad = 0
    insn = 0
    off = 0
    while off < tsz:
        if not claimed[off]:
            off += 1
            continue
        got = None
        for addr, size, mn, op in md.disasm_lite(tbytes[off:off + 16], tva + off):
            got = (addr, size, mn, op)
            break
        if got is None:
            bad += 1
            off += 1
            continue
        off += got[1]
        insn += 1
    print(f"  instructions: {insn:,}, undecodable bytes: {bad:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
