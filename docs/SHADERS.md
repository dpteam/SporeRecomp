# Shaders — the question is answered

**Verdict: Spore generates HLSL source at runtime and compiles it with `D3DXCompileShader`.**
The shaders are neither assets in the packages nor pre-compiled bytecode. This is why no Spore
mod has ever touched shaders as data — there is no data to touch.

Everything below is measured from `SporeApp.exe` with `tools/shader_origin.py`,
`tools/extract_hlsl.py` and `tools/hlsl_bodies.py`. Extracted material is in `analysis/hlsl/`.

## The evidence

1. **HLSL source text lives in the executable.** 21 strings contain HLSL syntax that cannot
   appear by accident:
   ```
   0x0100acf0  'float4 color : COLOR0;'
   0x0100ad44  'float3 normal : NORMAL0;'
   0x0100ad60  'float4 position : POSITION0;'
   0x0100af68  'extern uniform sampler Sampler%d : register(s%d);'
   0x0100b454  'float%d texcoord%d : TEXCOORD%d;'
   0x0100bec0  'struct tFrag{ float4 color : COLOR0;};tFrag main(tFrag fragIn){ return fragIn;}'
   ```

2. **The `%d` / `%s` in those strings prove they are format templates**, not literals. The engine
   builds the source with `snprintf` before compiling: `extern uniform sampler Sampler%d :
   register(s%d);` becomes `Sampler0 : register(s0)`, and so on.

3. **Complete, compilable sources exist too** — a debug/preview shader pair, verbatim:
   ```hlsl
   float4x4 clipSpaceMatrix : register(c0);
   float4   frameTime       : register(c4);
   struct tVertexIn  { float3 position : POSITION0; };
   struct tVertexOut { float4 clipPosition : POSITION; float4 color : COLOR0; };
   tVertexOut main(tVertexIn vertIn)
   {
       tVertexOut vertOut;
       float4 hPos = float4(vertIn.position, 1);
       vertOut.clipPosition = mul(hPos, clipSpaceMatrix);
       vertOut.color = float4(frac(frameTime[0]), 0, 0, 1);
       return vertOut;
   }
   ```

4. **The bodies are templates with placeholders for the struct names**:
   ```
   cFragOut main( cFragIn In )
   {
       cFragCurrent Current;
       cFragOut Out;
       ...
       return Out;
   }
   ```
   `cFragIn` / `cFragOut` / `cFragCurrent` are filled in per material, and the struct fields come
   from the fragment list (`float4 position : POSITION0;`, `float3 binormal : BINORMAL0;`, …).

5. **RenderWare's own source path is in the binary**, which identifies the component exactly:
   ```
   \Spore\SporeEP1ML\Core\RenderWare\platform\src\graphics\core\device\target\dx9\rwgdrvgraph.cpp
   ```
   RenderWare 4, DX9 target, shader generator. There are also `Graphics/PSDecls` and
   `Graphics/VSDecls` stream names — the *declarations* are package data, but they are RWS
   records describing vertex formats, not shader code.

6. **All shader profiles are referenced**, so the engine picks one at runtime based on device
   capabilities: `vs_1_1`, `vs_2_0`, `vs_2_a`, `vs_3_0`, `ps_1_1`…`ps_1_4`, `ps_2_0`, `ps_2_a`,
   `ps_3_0`. Plus the error string *"Unable to identity pixel shader version 0x%x — using
   MaxTextureBlendStages"*.

7. **No valid shader bytecode anywhere.** `tools/shader_verify.py` found 1,747 candidate version
   tokens in 3.9 GB of package bytes and **zero** that parse as a DX9 token stream; 894 of those
   candidates were in an *audio* package, which is what random coincidence looks like.

## What this means for the port

`D3DXCompileShader` is not a convenience wrapper we can stub — it is the shader compiler, and the
game cannot render a single triangle without it. So it must be implemented for real.

The good news is that the required HLSL subset is **small and fully enumerable**, because the
engine generates every shader from the same templates:

| Feature | Present |
|---|---|
| `struct` declarations with semantics | yes |
| `POSITION`, `NORMAL`, `COLOR`, `TEXCOORD`, `BINORMAL`, `TANGENT`, `BLENDWEIGHT`, `BLENDINDICES`, `PSIZE`, `FOG` semantics | yes |
| `register(cN)` float constants | yes |
| `register(sN)` samplers | yes (`Sampler%d` naming) |
| `mul()` (matrix × vector) | yes |
| `tex2D`, `texCUBE` | yes |
| `frac`, `saturate`, `lerp`, `dot`, `normalize`, `pow` | in the bodies |
| `if` / `for` | in the procedural shaders |
| `static const` | not seen |
| Techniques / passes / effects (`.fx`) | **no** — only vertex and pixel shaders |

So the job is: a small HLSL front end (lexer, expression parser, struct/semantic handling) plus a
GLSL ES 2.0/3.0 emitter, wired into `D3DXCompileShader` and the `CreateVertexShader`/
`CreatePixelShader` path. Order of magnitude: a few thousand lines, not a compiler project.

### The cheaper path, if it works

Because the engine generates from templates, the generated source is highly regular. It may be
enough to recognise the template shape and emit GLSL directly, skipping a general front end. This
should be attempted first: measure the actual sources the game compiles (the runtime already logs
every `D3DXCompileShader` request with entry point, target and source length), then decide.

## How to confirm on the device

The null-backend runtime logs:

```
D3DX: CompileShader entry="main" target="vs_3_0" srclen=NNN
D3DX: source head: <first 240 characters>
```

The first successful boot turns this from inference into a list of exactly which shaders must
compile. **Do not start the shader work before that log exists** — it is the specification.

## Consequences for the plan

* `docs/PLAN.md` risk #2 changes from "unknown, could be months" to "known work, bounded".
* The D3D9 null backend stays useful: it lets the whole game logic run while the compiler is
  written.
* A fixed-function fallback is worth having: RenderWare uses the fixed pipeline for simple
  materials, so a GLES1-style path can draw *something* even before any shader compiles.
