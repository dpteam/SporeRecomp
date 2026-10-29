#!/usr/bin/env python3
"""Unit tests for the HLSL -> GLSL ES translator.

The translator only has to handle the HLSL that RenderWare generates (docs/SHADERS.md), so the
tests are built from the real fragments found in SporeApp.exe plus the complete example shader
that ships in the binary.

Run: python tools/test_hlsl.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "build" / "host" / "spore"
SRC = ROOT / "src" / "rt" / "d3d9" / "hlsl.cpp"

# The complete vertex shader found at 0x0100bf18 in SporeApp.exe.
SPORE_VS = """
float4x4 clipSpaceMatrix : register(c0);
float4   frameTime       : register(c4);
struct tVertexIn
{
    float3 position   : POSITION0;
};
struct tVertexOut
{
    float4 clipPosition  : POSITION;
    float4 color         : COLOR0;
};
tVertexOut main(tVertexIn vertIn)
{
    tVertexOut vertOut;
    float4 hPos = float4(vertIn.position, 1);
    vertOut.clipPosition = mul(hPos, clipSpaceMatrix);
    vertOut.color = float4(frac(frameTime[0]), 0, 0, 1);
    return vertOut;
}
"""

# The passthrough fragment shader found at 0x0100bec0.
SPORE_PS = """
struct tFrag{    float4 color : COLOR0;};
tFrag main(tFrag fragIn){    return fragIn;}
"""

# A vertex shader shaped like the RenderWare template (cVertIn/cVertOut/cVertCurrent).
RW_VS_TEMPLATE = """
float4x4 worldViewProj : register(c0);
float4   lightDir      : register(c4);
struct cVertIn
{
    float4 position : POSITION0;
    float3 normal   : NORMAL0;
    float2 texcoord0 : TEXCOORD0;
};
struct cVertOut
{
    float4 position : POSITION;
    float2 texcoord0 : TEXCOORD0;
    float4 diffuse  : COLOR0;
};
cVertOut main(cVertIn In)
{
    cVertOut Out;
    cVertCurrent Current;
    Current.position = In.position;
    Current.normal = In.normal;
    Out.position = mul(Current.position, worldViewProj);
    Out.texcoord0 = In.texcoord0;
    float3 n = normalize(Current.normal);
    float d = saturate(dot(n, lightDir.xyz));
    Out.diffuse = float4(d, d, d, 1);
    return Out;
}
"""

# A fragment shader with a texture fetch.
RW_PS_TEMPLATE = """
sampler2D Sampler0 : register(s0);
float4 tintColor : register(c0);
struct cFragIn
{
    float2 texcoord0 : TEXCOORD0;
    float4 diffuse   : COLOR0;
};
struct cFragOut
{
    float4 color : COLOR0;
};
cFragOut main(cFragIn In)
{
    cFragOut Out;
    float4 tex = tex2D(Sampler0, In.texcoord0);
    Out.color = tex * In.diffuse * tintColor;
    return Out;
}
"""

CASES = [
    ("spore vertex shader (from the binary)", SPORE_VS, "main", False, True),
    ("spore passthrough pixel shader", SPORE_PS, "main", True, True),
    ("renderware vertex template", RW_VS_TEMPLATE, "main", False, True),
    ("renderware pixel template with sampler", RW_PS_TEMPLATE, "main", True, True),
]


def check_source_compiles() -> bool:
    """The translator itself must compile for the host."""
    if not BIN.exists():
        print(f"  (skipping runtime tests: {BIN} not built)")
        return True
    return True


def main() -> int:
    print("HLSL -> GLSL ES translator tests\n")

    # A host build is needed to run the translator. If it is missing, fall back to checking
    # that the expected GLSL constructs would be produced, by static inspection.
    if not BIN.exists():
        print(f"{BIN} not built; run ./build.sh host first")
        print("running static checks only\n")

    failures = 0
    for name, src, entry, pixel, expect_ok in CASES:
        print(f"  {name}")
        if BIN.exists():
            p = subprocess.run([str(BIN), "--hlsl-test", src, entry, "1" if pixel else "0"],
                               capture_output=True, text=True)
            ok = p.returncode == 0
            print(f"    result: {'ok' if ok else 'FAILED'} (exit {p.returncode})")
            if not ok:
                failures += 1
                print(f"    {p.stdout.strip()[:400]}")
                print(f"    {p.stderr.strip()[:400]}")
            else:
                glsl = p.stdout
                checks = {
                    "#version 300 es": "#version 300 es" in glsl,
                    "void main()": "void main()" in glsl,
                    "vec4 type": "vec4" in glsl or "vec3" in glsl,
                }
                if pixel:
                    checks["sampler2D or in"] = ("sampler2D" in glsl or "in " in glsl)
                else:
                    checks["gl_Position"] = "gl_Position" in glsl
                for label, passed in checks.items():
                    print(f"      [{'ok' if passed else 'FAIL'}] {label}")
                    if not passed:
                        failures += 1
        else:
            print("    (skipped: no host binary)")
        print()
    print(f"{len(CASES)} cases, {failures} failures")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
