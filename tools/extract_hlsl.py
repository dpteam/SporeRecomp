"""Extracts the HLSL shader sources embedded in SporeApp.exe.

The shader origin question is settled: the sources are in the executable, not in the packages,
and some are assembled with snprintf before compilation (`extern uniform sampler Sampler%d :
register(s%d);`). This tool dumps everything shader-shaped so the required HLSL subset is a
written specification instead of a guess.

Output: analysis/hlsl/ (one file per extracted block) + a summary on stdout.

Usage: python tools/extract_hlsl.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
OUT = Path("analysis/hlsl")

# A shader source block in the binary is a run of printable text that contains HLSL syntax.
HLSL_SYNTAX = re.compile(
    rb"(float[234]x?[234]?\s+\w+\s*:\s*(register|POSITION|NORMAL|COLOR|TEXCOORD|BINORMAL)"
    rb"|struct\s+\w+\s*\{|tex2D\s*\(|sampler\s+\w+\s*:\s*register"
    rb"|return\s+\w+\s*;|float4\s+main\s*\()"
)

# Runs of printable text, long enough to be a shader fragment.
TEXT_RUN = re.compile(rb"[ -~\t\r\n]{24,}")


def looks_like_hlsl(blob: bytes) -> bool:
    if not HLSL_SYNTAX.search(blob):
        return False
    # Require some HLSL-specific vocabulary beyond a single match.
    markers = 0
    for pat in (rb"float[234]", rb":\s*register\s*\(", rb":\s*(POSITION|NORMAL|COLOR|TEXCOORD)",
                rb"\bstruct\b", rb"\breturn\b", rb"\bmain\s*\("):
        if re.search(pat, blob):
            markers += 1
    return markers >= 3


def main() -> int:
    pe = PE(EXE.read_bytes())
    data = pe.d
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.*"):
        old.unlink()

    blocks: list[tuple[int, bytes]] = []
    for m in TEXT_RUN.finditer(data):
        blob = m.group()
        if looks_like_hlsl(blob):
            blocks.append((m.start(), blob))

    print(f"found {len(blocks)} HLSL-shaped blocks in {EXE.name}\n")

    # Group adjacent blocks: shader sources are often split by NULs and small gaps.
    merged: list[tuple[int, bytes]] = []
    for off, blob in blocks:
        if merged and off - (merged[-1][0] + len(merged[-1][1])) < 0x400:
            prev_off, prev = merged[-1]
            gap = data[prev_off + len(prev):off]
            merged[-1] = (prev_off, prev + gap + blob)
        else:
            merged.append((off, blob))

    print(f"after merging adjacent runs: {len(merged)} complete sources\n")

    total_bytes = 0
    for i, (off, blob) in enumerate(merged):
        text = blob.replace(b"\x00", b"")
        name = f"source_{i:03d}_{off:08x}.hlsl"
        (OUT / name).write_bytes(text)
        total_bytes += len(text)
        first_line = text.split(b"\n")[0][:100].decode("latin-1", "replace")
        print(f"  {name}  {len(text):6,d} bytes  {first_line!r}")

    # The fragments: individual HLSL declarations and statements. RenderWare assembles the
    # final shaders from these at runtime, which is why there is only one complete source.
    print("\n=== HLSL fragments (the building blocks RenderWare assembles)\n")
    frag_re = re.compile(
        rb"[ -~]{6,}?(?:"
        rb":\s*(?:register\s*\(\s*[cs]\d+\s*\)|POSITION\d?|NORMAL\d?|COLOR\d?|TEXCOORD\d?|"
        rb"BINORMAL\d?|TANGENT\d?)"
        rb"|^\s*(?:struct|technique|pass|extern|uniform|sampler)\b"
        rb"|float[234]x?[234]?\s+\w+\s*\("
        rb")[ -~]{0,200}"
    )
    frags: list[tuple[int, str]] = []
    seen: set[str] = set()
    for off, text in ((m.start(), m.group().decode("latin-1")) for m in
                      re.finditer(rb"[ -~\t]{6,}", data)):
        if frag_re.search(text.encode("latin-1")) and text not in seen:
            seen.add(text)
            frags.append((off, text))

    for off, text in frags[:80]:
        print(f"  0x{off:08x}  {text[:120]!r}")
    if len(frags) > 80:
        print(f"  ... and {len(frags) - 80} more")
    (OUT / "fragments.txt").write_text(
        "\n".join(f"0x{off:08x}  {text}" for off, text in frags), encoding="utf-8")
    print(f"\nwrote {len(frags)} fragments to {OUT / 'fragments.txt'}")

    print(f"\nwrote {len(merged)} complete sources, {total_bytes:,} bytes")

    # Summarise the HLSL vocabulary that actually appears: that is the subset a translator
    # has to support.
    everything = b"\n".join(t.replace(b"\x00", b"") for _, t in merged)
    everything += b"\n" + "\n".join(t for _, t in frags).encode("latin-1")
    print("\n=== HLSL vocabulary present (what a translator must support)\n")
    checks = {
        "register(c#) constants": rb"register\s*\(\s*c\d+\s*\)",
        "register(s#) samplers": rb"register\s*\(\s*s\d+\s*\)",
        "struct declarations": rb"\bstruct\s+\w+",
        "semantics POSITION": rb":\s*POSITION\d?",
        "semantics NORMAL": rb":\s*NORMAL\d?",
        "semantics COLOR": rb":\s*COLOR\d?",
        "semantics TEXCOORD": rb":\s*TEXCOORD\d?",
        "semantics BINORMAL/TANGENT": rb":\s*(BINORMAL|TANGENT)\d?",
        "tex2D": rb"\btex2D\s*\(",
        "texCUBE": rb"\btexCUBE\s*\(",
        "mul()": rb"\bmul\s*\(",
        "normalize()": rb"\bnormalize\s*\(",
        "dot()": rb"\bdot\s*\(",
        "lerp()": rb"\blerp\s*\(",
        "saturate()": rb"\bsaturate\s*\(",
        "pow()": rb"\bpow\s*\(",
        "if/else": rb"\bif\s*\(",
        "for loops": rb"\bfor\s*\(",
        "static const": rb"\bstatic\s+const\b",
        "matrix types": rb"\bfloat[234]x[234]\b",
        "printf-style sampler name": rb"Sampler%d",
    }
    for label, pat in checks.items():
        n = len(re.findall(pat, everything))
        mark = "yes" if n else "-"
        print(f"  [{mark}] {label:28s} {n:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
