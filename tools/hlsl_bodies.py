"""Finds the shader *bodies* (the actual HLSL functions), not just the declaration fragments.

The previous pass found only struct-field fragments (`float4 position : POSITION0;`) and one
trivial passthrough shader. RenderWare must also carry the bodies, otherwise it has nothing to
compile. This tool looks for HLSL function-shaped text and dumps the whole neighbourhood around
each hit, so the assembly scheme becomes visible.

Usage: python tools/hlsl_bodies.py [--around 400]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
OUT = Path("analysis/hlsl")

# Things only a shader body has.
BODY_MARKERS = [
    rb"\bmain\s*\(",              # a shader entry point
    rb"\breturn\s+(mul|tex|lerp|saturate|normalize|dot|float)",
    rb"\bmul\s*\(",               # matrix/vector multiply
    rb"\btex2D\s*\(",
    rb"\btexCUBE\s*\(",
    rb"\bsaturate\s*\(",
    rb"\bnormalize\s*\(",
    rb"register\s*\(\s*c\d+\s*\)",  # constant declarations at the top of a body
]


def main() -> int:
    around = 400
    if "--around" in sys.argv:
        around = int(sys.argv[sys.argv.index("--around") + 1])

    pe = PE(EXE.read_bytes())
    data = pe.d
    OUT.mkdir(parents=True, exist_ok=True)

    hits: list[tuple[int, bytes, str]] = []
    for pat in BODY_MARKERS:
        for m in re.finditer(pat, data):
            off = m.start()
            # Only consider hits inside printable text.
            start = off
            while start > 0 and 32 <= data[start - 1] < 127:
                start -= 1
            end = off
            while end < len(data) and 32 <= data[end] < 127:
                end += 1
            if end - start < 12:
                continue
            hits.append((off, data[start:end], pat.decode()))

    # De-duplicate by offset.
    uniq: dict[int, tuple[bytes, str]] = {}
    for off, text, pat in hits:
        uniq.setdefault(off, (text, pat))

    print(f"{len(uniq)} distinct body-shaped hits in {EXE.name}\n")

    by_marker: dict[str, int] = {}
    for off, (text, pat) in sorted(uniq.items()):
        by_marker[pat] = by_marker.get(pat, 0) + 1
    for pat, n in sorted(by_marker.items(), key=lambda kv: -kv[1]):
        print(f"  {pat:30s} {n:,}")

    print("\n=== hits (text around each)\n")
    shown = 0
    for off, (text, pat) in sorted(uniq.items()):
        if shown >= 60:
            break
        snippet = text[:160].decode("latin-1", "replace")
        print(f"  0x{off:08x} [{pat}] {snippet!r}")
        shown += 1

    # Dump generous windows so the assembly scheme is visible in the file.
    print(f"\n=== windows of {around} bytes around each hit\n")
    lines = []
    for off, (text, pat) in sorted(uniq.items()):
        lo = max(0, off - around)
        hi = min(len(data), off + around)
        blob = data[lo:hi]
        printable = sum(1 for b in blob if 32 <= b < 127 or b in (9, 10, 13))
        if printable < len(blob) * 0.6:
            continue
        clean = bytes(b if (32 <= b < 127 or b in (9, 10, 13)) else 0x2E for b in blob)
        lines.append(f"--- 0x{off:08x} [{pat}] ---")
        lines.append(clean.decode("latin-1"))
        lines.append("")
    (OUT / "bodies.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {len(lines) // 3} windows to {OUT / 'bodies.txt'}")

    # Look specifically for the shader bodies RenderWare would generate: a body that uses the
    # fragments found earlier. Search for the constant-declaration prelude.
    print("\n=== shader prelude / constant declarations\n")
    prelude = re.compile(rb"(float[234]x?[234]?\s+\w+\s*:\s*register\s*\(\s*c\d+\s*\)\s*;"
                         rb"[ -~\t\r\n]{0,600})")
    seen = set()
    for m in prelude.finditer(data):
        blob = m.group()
        key = blob[:80]
        if key in seen:
            continue
        seen.add(key)
        text = blob.decode("latin-1", "replace")
        print(f"  0x{m.start():08x}  {text[:200]!r}")
        if len(seen) > 20:
            break
    if not seen:
        print("  none found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
