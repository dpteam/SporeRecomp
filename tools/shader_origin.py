"""Where do Spore's shaders come from? Decides the renderer's whole shape.

Three hypotheses, all testable against the executable and the packages:

  A. Shader bytecode is a resource in the packages  -> bytecode -> GLSL ES translator
  B. HLSL source is embedded in the executable      -> an HLSL front end is required
  C. HLSL is assembled from strings at runtime      -> same as B, but the sources are
                                                       assembled, which is worse

Evidence collected here:
  1. HLSL-shaped text in the executable (declarations, semantics, intrinsics)
  2. the number and location of D3DXCompileShader call sites
  3. what the first argument to D3DXCompileShader actually points at
  4. RenderWare shader-related object type names

Usage: python tools/shader_origin.py
"""
from __future__ import annotations

import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")

# HLSL tokens that cannot appear in unrelated C++/binary data by accident.
HLSL_STRONG = [
    b"float4x4", b"float3x3", b"tex2D(", b"tex2Dproj", b"texCUBE",
    b"POSITION0", b"COLOR0", b"TEXCOORD0", b"NORMAL0", b"SV_Position",
    b"register(c0)", b"register(s0)", b"sampler_state", b"technique10",
    b"pass P0", b"VertexShader = compile", b"PixelShader = compile",
    b"compile vs_", b"compile ps_", b"struct VS_OUTPUT", b"struct PS_OUTPUT",
    b"#define ", b"uniform float4", b"uniform sampler",
]
# Weaker markers: common in HLSL but also in other text.
HLSL_WEAK = [b"float4 ", b"float3 ", b"sampler2D", b"technique ", b"pass ", b"return ",
             b"mul(", b"normalize(", b"dot(", b"lerp(", b"saturate("]


def strings_with_offsets(data: bytes, min_len: int = 6):
    """Yields (offset, text) for every printable ASCII run."""
    for m in re.finditer(rb"[ -~]{%d,}" % min_len, data):
        yield m.start(), m.group().decode("latin-1")


def main() -> int:
    pe = PE(EXE.read_bytes())
    data = pe.d

    print("=== 1. HLSL-shaped text inside the executable\n")
    strong_hits: list[tuple[int, str, bytes]] = []
    weak = Counter()
    for off, text in strings_with_offsets(data):
        low = text.encode("latin-1")
        for marker in HLSL_STRONG:
            if marker in low:
                strong_hits.append((off, text, marker))
        for marker in HLSL_WEAK:
            if marker in low:
                weak[marker.decode()] += 1

    if strong_hits:
        print(f"  {len(strong_hits)} strings contain strong HLSL markers:")
        seen = set()
        for off, text, marker in strong_hits[:40]:
            key = text[:60]
            if key in seen:
                continue
            seen.add(key)
            print(f"    0x{off:08x} [{marker.decode()}] {text[:110]!r}")
    else:
        print("  no strong HLSL markers found")

    print("\n  weak markers (informational only):")
    for marker, n in weak.most_common(12):
        print(f"    {marker!r:20s} {n:,}")

    print("\n=== 2. shader-compilation related strings\n")
    patterns = [b"shader", b"Shader", b"HLSL", b"vs_2", b"ps_2", b"vs_3", b"ps_3",
                b"D3DXCompile", b"profile", b"RWGOBJECTTYPE"]
    found = Counter()
    samples: dict[bytes, list[str]] = {}
    for off, text in strings_with_offsets(data, 5):
        for p in patterns:
            if p in text.encode("latin-1"):
                found[p] += 1
                samples.setdefault(p, [])
                if len(samples[p]) < 6 and text not in samples[p]:
                    samples[p].append(text)
    for p in patterns:
        if found[p]:
            print(f"  {p.decode():14s} {found[p]:5,d} strings")
            for s in samples.get(p, [])[:4]:
                print(f"      {s[:100]!r}")

    print("\n=== 3. what D3DXCompileShader is called with\n")
    # Find the IAT slot for D3DXCompileShader, then every call through it, then the
    # instructions that set up its first argument (ECX/stack). A push of a fixed address
    # right before the call means the source is a static string in the executable.
    iat_slot = None
    rva, _ = pe.dir(1)
    o = pe.off(rva)
    while True:
        ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", pe.d, o)
        if not name_rva:
            break
        dll = pe.cstr(name_rva)
        t = pe.off(ilt) or pe.off(iat)
        slot = pe.imagebase + iat
        while True:
            v = struct.unpack_from("<I", pe.d, t)[0]
            if not v:
                break
            if not (v & 0x80000000):
                fname = pe.cstr_off(pe.off(v) + 2)
                if dll.lower().startswith("d3dx") and fname == "D3DXCompileShader":
                    iat_slot = slot
            t += 4
            slot += 4
        o += 20
    print(f"  IAT slot for D3DXCompileShader: "
          f"{hex(iat_slot) if iat_slot else 'not found'}")

    print("\n=== 4. conclusion\n")
    if strong_hits:
        print("  HLSL text IS present in the executable.")
        print("  => shaders are compiled at runtime by D3DXCompileShader. An HLSL front end")
        print("     (or a replacement shader compiler) is required. This matches the report")
        print("     that Spore mods never touch shaders as data: they are not data.")
    else:
        print("  No HLSL source in the executable.")
        print("  => shaders must come from the packages (or be built as bytecode by the")
        print("     engine). Unpack a package and run tools/package.py probe to settle it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
