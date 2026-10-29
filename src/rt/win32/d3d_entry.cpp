// SporeRecomp — Direct3D 9 / D3DX / DirectInput / DirectSound entry points.
//
// The D3D9 object model itself lives in d3d9/com.cpp + d3d9/d3d9.cpp. This file only holds
// the flat exported functions the guest imports.
#include <cmath>
#include <cstdio>
#include <cstring>

#include "rt/d3d9/com.h"
#include "rt/d3d9/d3d9.h"
#include "rt/d3d9/hlsl.h"
#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/win32/win32.h"

namespace sr::w32 {

// ---------------------------------------------------------------------------
// d3d9.dll
// ---------------------------------------------------------------------------
void d3d_create9(CpuState* s, const u32* a) {
  // Direct3DCreate9(SDKVersion) — Spore passes 32 (D3D_SDK_VERSION).
  (void)a;
  s->r[0] = d3d::create_d3d9();
}

// ---------------------------------------------------------------------------
// d3dx9_27.dll
//
// Spore has exactly one call site per D3DX function: RenderWare wraps them in a thin adapter.
// The matrix helpers are real math (the guest uses the results), so they are implemented
// properly. D3DXCompileShader is the interesting one: it means HLSL is compiled at runtime.
// Until a shader path exists it returns a failure code, which the guest handles by falling
// back — and the log records every request so we can see exactly which shaders are needed.
// ---------------------------------------------------------------------------
void d3dx_check_version(CpuState* s, const u32* a) {
  // D3DXCheckVersion(D3D SDK version, D3DX SDK version)
  s->r[0] = 1;  // TRUE: versions are compatible
}

void d3dx_get_ps_profile(CpuState* s, const u32* a) {
  // D3DXGetPixelShaderProfile(device) -> const char*
  static u32 str = 0;
  if (!str) {
    str = gmem().heap_alloc(16);
    write_cstr(str, "ps_3_0");
  }
  s->r[0] = str;
}

void d3dx_get_vs_profile(CpuState* s, const u32* a) {
  static u32 str = 0;
  if (!str) {
    str = gmem().heap_alloc(16);
    write_cstr(str, "vs_3_0");
  }
  s->r[0] = str;
}

void d3dx_compile_shader(CpuState* s, const u32* a) {
  // D3DXCompileShader(srcData, srcDataLen, defines, include, entrypoint, target, flags,
  //                   ppShader, ppErrorMsgs, pConstantTable)
  ++d3d::g_stats.shader_compile_requests;
  const char* src = a[0] ? reinterpret_cast<const char*>(gmem().base() + a[0]) : "";
  const char* entry = a[4] ? cstr(a[4]) : "main";
  const char* target = a[5] ? cstr(a[5]) : "vs_2_0";

  // The translator is the real implementation: RenderWare generates HLSL at runtime and needs
  // a working shader compiler (docs/SHADERS.md).
  hlsl::CompileResult res = hlsl::compile(src, entry, target);

  if (d3d::g_stats.shader_compile_requests <= 40 || !res.ok) {
    SR_LOG("D3DX: CompileShader entry=\"%s\" target=\"%s\" srclen=%u -> %s", entry, target,
           a[1], res.ok ? "ok" : "FAILED");
    if (!res.ok) {
      SR_LOG("D3DX:   line %d: %s", res.line, res.error.c_str());
      if (d3d::g_stats.shader_compile_requests <= 3) {
        SR_LOG("D3DX:   source head: %.300s", src);
      }
    }
  }

  if (!res.ok) {
    if (a[7]) store<u32>(a[7], 0);
    if (a[8]) store<u32>(a[8], 0);
    s->r[0] = 0x88760B59u;  // D3DXERR_INVALIDDATA
    return;
  }

  // Hand the GLSL back to the caller as a D3DX buffer. The renderer picks it up from
  // CreateVertexShader / CreatePixelShader, which receive the same pointer.
  u32 bytes = u32(res.glsl.size()) + 1;
  u32 buf = gmem().heap_alloc(16 + bytes);
  if (!buf) { s->r[0] = 0x8007000Eu; return; }
  store<u32>(buf + 0, bytes);   // D3DXBuffer::GetBufferSize layout: size first
  store<u32>(buf + 4, 0);
  __builtin_memcpy(gmem().base() + buf + 16, res.glsl.c_str(), bytes);
  d3d::register_glsl(buf + 16, res.glsl, res.is_pixel);
  if (a[7]) store<u32>(a[7], buf);
  if (a[8]) store<u32>(a[8], 0);
  s->r[0] = 0;
}

// --- matrix helpers -------------------------------------------------------
// D3DX uses column-major matrices with _11.._44 order, same as D3D.
namespace {

inline void load_matrix(u32 addr, float out[16]) {
  for (int i = 0; i < 16; ++i) out[i] = load<float>(addr + u32(i) * 4);
}

inline void store_matrix(u32 addr, const float m[16]) {
  for (int i = 0; i < 16; ++i) store<float>(addr + u32(i) * 4, m[i]);
}

}  // namespace

void d3dx_matrix_multiply(CpuState* s, const u32* a) {
  // D3DXMatrixMultiply(pOut, pA, pB): out = A * B (row-vector convention)
  float A[16], B[16], C[16];
  load_matrix(a[1], A);
  load_matrix(a[2], B);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      float sum = 0;
      for (int k = 0; k < 4; ++k) sum += A[i * 4 + k] * B[k * 4 + j];
      C[i * 4 + j] = sum;
    }
  }
  store_matrix(a[0], C);
  s->r[0] = a[0];
}

void d3dx_matrix_multiply_transpose(CpuState* s, const u32* a) {
  float A[16], B[16], C[16];
  load_matrix(a[1], A);
  load_matrix(a[2], B);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      float sum = 0;
      for (int k = 0; k < 4; ++k) sum += A[k * 4 + i] * B[k * 4 + j];
      C[i * 4 + j] = sum;
    }
  }
  store_matrix(a[0], C);
  s->r[0] = a[0];
}

void d3dx_matrix_transpose(CpuState* s, const u32* a) {
  float A[16], C[16];
  load_matrix(a[1], A);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) C[i * 4 + j] = A[j * 4 + i];
  }
  store_matrix(a[0], C);
  s->r[0] = a[0];
}

void d3dx_vec3_transform(CpuState* s, const u32* a) {
  // D3DXVECTOR4* D3DXVec3Transform(out, pV, pM)
  float v[3], m[16];
  for (int i = 0; i < 3; ++i) v[i] = load<float>(a[1] + u32(i) * 4);
  load_matrix(a[2], m);
  float out[4];
  for (int j = 0; j < 4; ++j) {
    out[j] = v[0] * m[0 * 4 + j] + v[1] * m[1 * 4 + j] + v[2] * m[2 * 4 + j] + m[3 * 4 + j];
  }
  for (int j = 0; j < 4; ++j) store<float>(a[0] + u32(j) * 4, out[j]);
  s->r[0] = a[0];
}

void d3dx_vec3_transform_normal(CpuState* s, const u32* a) {
  // D3DXVECTOR3* D3DXVec3TransformNormal(out, pV, pM): ignores translation
  float v[3], m[16];
  for (int i = 0; i < 3; ++i) v[i] = load<float>(a[1] + u32(i) * 4);
  load_matrix(a[2], m);
  float out[3];
  for (int j = 0; j < 3; ++j) {
    out[j] = v[0] * m[0 * 4 + j] + v[1] * m[1 * 4 + j] + v[2] * m[2 * 4 + j];
  }
  for (int j = 0; j < 3; ++j) store<float>(a[0] + u32(j) * 4, out[j]);
  s->r[0] = a[0];
}

// ---------------------------------------------------------------------------
// DINPUT8 / DSOUND / Winsock
//
// These are honest stubs: they fail cleanly so the guest takes its "no input device" /
// "no network" path instead of dereferencing a fake object. Input, audio and networking each
// get a real implementation once the renderer exists.
// ---------------------------------------------------------------------------
void dinput8_create(CpuState* s, const u32* a) {
  SR_LOG("DInput8: DirectInput8Create -> DIERR_DEVICENOTREG (no input layer yet)");
  if (a[4]) store<u32>(a[4], 0);
  s->r[0] = 0x8007000Eu;  // DIERR_DEVICENOTREG
}

void dsound_create(CpuState* s, const u32* a) {
  SR_LOG("DSound: DirectSoundCreate8 -> DSERR_NODRIVER (no audio layer yet)");
  if (a[2]) store<u32>(a[2], 0);
  s->r[0] = 0x88780082u;  // DSERR_NODRIVER
}

void dsound_noop(CpuState* s, const u32*) { s->r[0] = 0; }
void ws_noop(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFFu; }  // SOCKET_ERROR

}  // namespace sr::w32

