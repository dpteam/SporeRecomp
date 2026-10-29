"""Answers the biggest open question in the plan: does Spore ship pre-compiled shader bytecode,
or does it compile HLSL at runtime?

Every Direct3D shader bytecode blob starts with a version token:

    vs_1_1 0xFFFE0101   vs_2_0 0xFFFE0200   vs_2_sw 0xFFFE02FF   vs_3_0 0xFFFE0300
    ps_1_1 0xFFFF0101   ps_2_0 0xFFFF0200   ps_2_a  0xFFFF0201   ps_3_0 0xFFFF0300

If those tokens appear inside the packages, the shaders are pre-compiled and the renderer can
translate bytecode to GLSL ES. If they do not, the game compiles HLSL at runtime and we need an
HLSL front end — a much bigger job.

Usage: python tools/shader_probe.py [--deep]
"""
from __future__ import annotations

import re
import struct
import sys
from collections import Counter
from pathlib import Path

DATA = Path("../OpenSpore/refs/_Also/SporeGames/SporeRetail/Data")
FALLBACK = Path("refs/gamedata/Data")

TOKENS = {
    0xFFFE0101: "vs_1_1", 0xFFFE0200: "vs_2_0", 0xFFFE0201: "vs_2_x",
    0xFFFE02FF: "vs_2_sw", 0xFFFE0300: "vs_3_0", 0xFFFE0301: "vs_3_sw",
    0xFFFF0101: "ps_1_1", 0xFFFF0102: "ps_1_2", 0xFFFF0103: "ps_1_3",
    0xFFFF0104: "ps_1_4", 0xFFFF0200: "ps_2_0", 0xFFFF0201: "ps_2_a",
    0xFFFF0202: "ps_2_b", 0xFFFF02FF: "ps_2_sw", 0xFFFF0300: "ps_3_0",
    0xFFFF0301: "ps_3_sw",
}

# Also look for the RenderWare shader-code object tag and HLSL source markers.
RW_TAGS = {
    b"RWGOBJECTTYPE_PIXELSHADER": "rw pixel-shader object tag",
    b"RWGOBJECTTYPE_VERTEXSHADER": "rw vertex-shader object tag",
    b"RWGOBJECTTYPE_SHADERCODE": "rw shader-code object tag",
}
HLSL_MARKERS = [b"float4 ", b"sampler2D", b"technique ", b"struct VS_INPUT",
                b"return tex2D", b"uniform "]


def scan_file(path: Path, tokens: Counter, rw: Counter, hlsl: Counter,
              examples: dict) -> None:
    data = path.read_bytes()
    n = len(data)
    # 1) shader version tokens as little-endian u32
    for i in range(0, n - 4, 4):
        v = struct.unpack_from("<I", data, i)[0]
        name = TOKENS.get(v)
        if name:
            tokens[name] += 1
            if name not in examples:
                examples[name] = (path.name, i)
    # 2) RenderWare shader object tags (ASCII, may be NUL-terminated in a name table)
    for tag, label in RW_TAGS.items():
        c = data.count(tag)
        if c:
            rw[label] += c
    # 3) HLSL source text
    for marker in HLSL_MARKERS:
        c = data.count(marker)
        if c:
            hlsl[marker.decode()] += c


def main() -> int:
    data_dir = DATA if DATA.exists() else FALLBACK
    if not data_dir.exists():
        print(f"no package directory found (looked in {DATA} and {FALLBACK})")
        return 1

    packages = sorted(data_dir.glob("*.package"))
    if not packages:
        print(f"no .package files in {data_dir}")
        return 1

    print(f"scanning {len(packages)} packages in {data_dir}")
    total_mb = sum(p.stat().st_size for p in packages) / (1024 * 1024)
    print(f"total {total_mb:,.0f} MB\n")

    tokens: Counter = Counter()
    rw: Counter = Counter()
    hlsl: Counter = Counter()
    examples: dict = {}

    for p in packages:
        before = sum(tokens.values())
        scan_file(p, tokens, rw, hlsl, examples)
        found = sum(tokens.values()) - before
        size_mb = p.stat().st_size / (1024 * 1024)
        print(f"  {p.name:28s} {size_mb:8.1f} MB  shader tokens: {found:,}")

    print("\n=== shader bytecode version tokens")
    if tokens:
        for name, c in tokens.most_common():
            ex = examples.get(name)
            where = f"  (first: {ex[0]} @ 0x{ex[1]:x})" if ex else ""
            print(f"  {name:10s} {c:6,d}{where}")
    else:
        print("  none found")

    print("\n=== RenderWare shader object tags")
    if rw:
        for label, c in rw.most_common():
            print(f"  {label:32s} {c:,}")
    else:
        print("  none found")

    print("\n=== HLSL source markers")
    if hlsl:
        for marker, c in hlsl.most_common():
            print(f"  {marker!r:24s} {c:,}")
    else:
        print("  none found")

    print("\n=== conclusion")
    if tokens:
        print("  Shader bytecode IS present in the packages.")
        print("  => the renderer can translate DX9 bytecode to GLSL ES; no HLSL front end is")
        print("     strictly required for these shaders.")
        print("  Caveat: some shaders may still be compiled at runtime (D3DXCompileShader is")
        print("  imported); the runtime log records every compile request so both cases are")
        print("  measurable once the game boots.")
    elif hlsl:
        print("  HLSL source is present but no bytecode was found.")
        print("  => shaders are compiled at runtime: an HLSL front end (or a D3DX shader")
        print("     compiler replacement) is required.")
    else:
        print("  Neither bytecode nor HLSL source found in the raw package bytes.")
        print("  Most likely the packages are compressed (RefPack) and the payload has to be")
        print("  unpacked before scanning; re-run after unpacking, or check whether")
        print("  CompiledMaterials.package holds them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
