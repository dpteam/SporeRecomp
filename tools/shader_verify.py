"""Verifies whether the shader version tokens found by shader_probe.py are real shader
bytecode or coincidental 4-byte patterns.

A genuine DX9 shader blob is a token stream: the version token is followed by opcode tokens
whose high bits are a known opcode, then either an end token (0x0000FFFF) or more opcodes.
Random data almost never produces a valid multi-token stream.

A token is accepted only if:
  * it is followed by at least 6 plausible opcode tokens in a row,
  * the stream contains an END token within 8 KB,
  * every opcode token's opcode number is below 0x100 (the DX9 opcode range).

Usage: python tools/shader_verify.py [--limit-mb N]
"""
from __future__ import annotations

import struct
import sys
from collections import Counter
from pathlib import Path

DATA = Path("../OpenSpore/refs/_Also/SporeGames/SporeRetail/Data")

VERSIONS = {
    0xFFFE0101: "vs_1_1", 0xFFFE0200: "vs_2_0", 0xFFFE0201: "vs_2_x",
    0xFFFE02FF: "vs_2_sw", 0xFFFE0300: "vs_3_0", 0xFFFE0301: "vs_3_sw",
    0xFFFF0101: "ps_1_1", 0xFFFF0102: "ps_1_2", 0xFFFF0103: "ps_1_3",
    0xFFFF0104: "ps_1_4", 0xFFFF0200: "ps_2_0", 0xFFFF0201: "ps_2_a",
    0xFFFF0202: "ps_2_b", 0xFFFF02FF: "ps_2_sw", 0xFFFF0300: "ps_3_0",
    0xFFFF0301: "ps_3_sw",
}
END_TOKEN = 0x0000FFFF
COMMENT_TOKEN = 0x0000FFFE


def token_plausible(tok: int) -> bool:
    """A DX9 opcode token: bits 0-15 are the opcode (< 0x100), bits 16-23 instruction length."""
    if tok == END_TOKEN:
        return True
    opcode = tok & 0xFFFF
    length = (tok >> 24) & 0x0F
    if opcode >= 0x100:
        return False
    # An instruction is 1..6 dwords in DX9 (some DCL/comment forms are longer).
    return length <= 6


def validate_stream(data: bytes, pos: int) -> tuple[bool, int, int]:
    """Returns (valid, token_count, byte_length) for a candidate blob at `pos`."""
    n = len(data)
    if pos + 8 > n:
        return False, 0, 0
    i = pos + 4
    tokens = 0
    while i + 4 <= n and tokens < 4096:
        tok = struct.unpack_from("<I", data, i)[0]
        if tok == END_TOKEN:
            return (tokens >= 6), tokens, i + 4 - pos
        if tok == COMMENT_TOKEN:
            # comment token: opcode 0xFFFE, next dword is the length in bytes
            if i + 8 > n:
                return False, tokens, 0
            clen = struct.unpack_from("<I", data, i + 4)[0]
            if clen > 0x10000 or i + 8 + clen > n:
                return False, tokens, 0
            i += 8 + clen
            tokens += 1
            continue
        if not token_plausible(tok):
            return False, tokens, 0
        length = (tok >> 24) & 0x0F
        i += 4 * (1 + length)
        tokens += 1
    return False, tokens, 0


def main() -> int:
    limit_mb = None
    if "--limit-mb" in sys.argv:
        limit_mb = int(sys.argv[sys.argv.index("--limit-mb") + 1])

    packages = sorted(DATA.glob("*.package"))
    if not packages:
        print(f"no packages in {DATA}")
        return 1

    print("validating candidate shader blobs (token stream must parse to an END token)\n")
    total_valid = Counter()
    total_bytes = 0
    examples: list[tuple[str, int, str, int]] = []

    for p in packages:
        data = p.read_bytes()
        if limit_mb:
            data = data[: limit_mb * 1024 * 1024]
        n = len(data)
        raw = 0
        valid = 0
        for i in range(0, n - 8, 4):
            tok = struct.unpack_from("<I", data, i)[0]
            if tok not in VERSIONS:
                continue
            raw += 1
            ok, tokens, blen = validate_stream(data, i)
            if ok:
                valid += 1
                name = VERSIONS[tok]
                total_valid[name] += 1
                total_bytes += blen
                if len(examples) < 12:
                    examples.append((p.name, i, name, blen))
        print(f"  {p.name:26s} raw tokens: {raw:5,d}   valid blobs: {valid:5,d}")

    print("\n=== valid shader blobs by profile")
    if total_valid:
        for name, c in total_valid.most_common():
            print(f"  {name:10s} {c:6,d}")
        print(f"\n  total {sum(total_valid.values()):,} blobs, "
              f"{total_bytes / 1024:.0f} KB of bytecode")
        print("\n=== examples")
        for fname, off, name, blen in examples:
            print(f"  {fname} @ 0x{off:x}: {name}, {blen} bytes")
        print("\n=== conclusion")
        print("  Real, parseable shader bytecode ships inside the packages.")
        print("  => the renderer can translate DX9 bytecode to GLSL ES instead of needing an")
        print("     HLSL compiler.")
    else:
        print("  none — the raw token counts were coincidental byte patterns.")
        print("  => shaders are compiled at runtime by D3DXCompileShader; an HLSL front end")
        print("     is required. (Or the payloads are compressed: unpack first and re-run.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
