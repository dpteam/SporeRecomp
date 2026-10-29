// SporeRecomp — HLSL to GLSL ES translator.
//
// Spore does not ship shaders. RenderWare 4 generates HLSL source at runtime from templates
// (see docs/SHADERS.md) and compiles it with D3DXCompileShader. The generated subset is small
// and regular, which is what makes a focused translator practical:
//
//   * structs with semantics (POSITION/NORMAL/COLOR/TEXCOORD/BINORMAL/TANGENT/BLENDWEIGHT/
//     BLENDINDICES/PSIZE/FOG)
//   * uniform constants declared as `float4 x : register(cN);`
//   * samplers declared as `sampler2D s : register(sN);`
//   * a single entry point `Out main(In In)` (HLSL "main", GLSL "main")
//   * expressions over float/float2/float3/float4/matrix types
//   * tex2D, texCUBE, mul, dot, normalize, lerp, saturate, frac, pow, min, max, abs, sqrt
//   * simple if/else and for loops
//
// Translation strategy: rather than a full compiler, this is a *source-to-source* rewrite that
// relies on the generated code's regularity. Anything it does not recognise is reported, never
// silently mistranslated — a wrong shader is worse than a missing one.
#pragma once

#include <string>

namespace sr::hlsl {

struct CompileResult {
  bool ok = false;
  std::string glsl;       // the translated source (vertex or fragment GLSL ES)
  std::string error;      // why it failed, for the log
  int line = 0;           // line of the failure
  bool is_pixel = false;  // fragment shader?
};

// Compiles HLSL source for the given profile ("vs_2_0", "ps_3_0", ...).
CompileResult compile(const char* source, const char* entry, const char* profile);

// Exposed for testing: translates source without touching GL.
CompileResult translate(const char* source, const char* entry, bool pixel);

}  // namespace sr::hlsl
