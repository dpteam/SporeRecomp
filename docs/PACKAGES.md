# Spore package format (.package) — what we know, measured

The packages are the only place the game's assets live, and the open question about shaders
depends on what is inside them. This file records what has actually been verified.

## The 7 retail packages

| File | Size |
|---|---|
| `Spore_Audio1.package` | 971.8 MB |
| `Spore_Audio2.package` | 974.1 MB |
| `Spore_Content.package` | 949.2 MB |
| `Spore_Graphics.package` | 899.2 MB |
| `PatchData.package` | 63.2 MB |
| `Spore_Game.package` | 19.3 MB |
| `Spore_Pack_03.package` | 9.1 MB |
| **total** | **3,886 MB** |

Note there is no separate `DataEP1` package set in this installation: the Galactic Adventures
content is merged into the main packages (`PatchData.package` is the patch overlay).

## Container structure

A `.package` is an **index of resources followed by payloads**:

* the index holds, per resource: a type id, a group id, an instance id, a name, and the offset,
  compressed size and decompressed size of the payload;
* payloads are stored either raw or **RefPack**-compressed (the EA compression used across
  Maxis titles: a byte-oriented LZ with a 24-bit back-reference window);
* the file may also be a "package group" that references other packages by name.

The OpenSpore project already solved RefPack (30,000/30,000 test vectors) and opened all 57
`.package` files across all its data sets — that work is reusable and is *not* being redone here.
The decompressor is the part worth borrowing; everything else in this project is independent.

## What this means for the shader question

`tools/shader_probe.py` scans raw package bytes for DX9 shader version tokens and found 1,747
candidates. `tools/shader_verify.py` then tried to parse each candidate as a real token stream
(version token, plausible opcodes, an `END` token within 8 KB) and found **zero** valid blobs.

Interpretation: there is no *uncompressed* shader bytecode in the packages. The candidates were
random 4-byte patterns — note that 894 of them were in an **audio** package, where no shader can
exist, which is exactly what random coincidence looks like.

Therefore one of these is true, and the cost differs enormously:

| Hypothesis | Consequence |
|---|---|
| Bytecode is inside RefPack-compressed blocks | unpack a package, re-run `shader_verify.py`; if blobs appear, write a DX9 bytecode → GLSL ES translator |
| HLSL is compiled at runtime | `D3DXCompileShader` needs a real implementation: an HLSL front end |

The runtime already logs every `D3DXCompileShader` request with its entry point, target profile
and source length, so the first successful boot answers this. **Do not start the shader work
before that log exists** — the two paths differ by months.

## Next measurement

1. Unpack one package (the OpenSpore unpacker is in `../OpenSpore/tools`), preferring
   `Spore_Graphics.package` or `PatchData.package`.
2. Run `python tools/shader_verify.py --unpacked <dir>` against the extracted resources.
3. Record the answer here and in `docs/PLAN.md` risk #2.
