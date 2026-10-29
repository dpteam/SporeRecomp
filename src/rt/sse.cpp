// SporeRecomp — SSE helpers.
#include <cmath>
#include <cstring>

#include "rt/guest.h"

namespace sr {

namespace {
inline float fget(V4 v, int i) {
  float f;
  __builtin_memcpy(&f, &v.u[i], 4);
  return f;
}
inline void fset(V4& v, int i, float f) {
  __builtin_memcpy(&v.u[i], &f, 4);
}
inline V4 v4_broadcast(float f) {
  V4 r;
  for (int i = 0; i < 4; ++i) fset(r, i, f);
  return r;
}
}  // namespace

V4 sse_src(CpuState* s, V4 dst, V4 src) { (void)s; (void)dst; return src; }

V4 sse_movss(CpuState* s, V4 dst, V4 src) {
  (void)s;
  // movss xmm, xmm keeps the upper three lanes of the destination
  V4 r = dst;
  r.u[0] = src.u[0];
  return r;
}

V4 sse_movss_load(CpuState* s, V4 dst, u32 addr) {
  (void)s;
  V4 r = dst;
  r.u[0] = load<u32>(addr);
  return r;
}

void sse_movss_store(CpuState* s, u32 addr, V4 src) {
  (void)s;
  store<u32>(addr, src.u[0]);
}

void sse_xor(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) d.u[i] ^= b.u[i];
}
void sse_and(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) d.u[i] &= b.u[i];
}
void sse_or(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) d.u[i] |= b.u[i];
}
void sse_andn(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) d.u[i] = (~d.u[i]) & b.u[i];
}

void sse_add_ss(CpuState* s, V4& d, V4 b) { (void)s; fset(d, 0, fget(d, 0) + fget(b, 0)); }
void sse_sub_ss(CpuState* s, V4& d, V4 b) { (void)s; fset(d, 0, fget(d, 0) - fget(b, 0)); }
void sse_mul_ss(CpuState* s, V4& d, V4 b) { (void)s; fset(d, 0, fget(d, 0) * fget(b, 0)); }
void sse_div_ss(CpuState* s, V4& d, V4 b) { (void)s; fset(d, 0, fget(d, 0) / fget(b, 0)); }
void sse_min_ss(CpuState* s, V4& d, V4 b) {
  (void)s;
  float x = fget(d, 0), y = fget(b, 0);
  fset(d, 0, (x < y) ? x : y);
}
void sse_max_ss(CpuState* s, V4& d, V4 b) {
  (void)s;
  float x = fget(d, 0), y = fget(b, 0);
  fset(d, 0, (x > y) ? x : y);
}
void sse_sqrt_ss(CpuState* s, V4& d, V4 b) {
  (void)s;
  fset(d, 0, std::sqrt(fget(b, 0)));
}

void sse_add_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) fset(d, i, fget(d, i) + fget(b, i));
}
void sse_sub_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) fset(d, i, fget(d, i) - fget(b, i));
}
void sse_mul_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) fset(d, i, fget(d, i) * fget(b, i));
}
void sse_div_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) fset(d, i, fget(d, i) / fget(b, i));
}
void sse_rcp_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) fset(d, i, 1.0f / fget(b, i));
}
void sse_rsqrt_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) fset(d, i, 1.0f / std::sqrt(fget(b, i)));
}
void sse_sqrt_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) fset(d, i, std::sqrt(fget(b, i)));
}
void sse_min_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) {
    float x = fget(d, i), y = fget(b, i);
    fset(d, i, (x < y) ? x : y);
  }
}
void sse_max_ps(CpuState* s, V4& d, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) {
    float x = fget(d, i), y = fget(b, i);
    fset(d, i, (x > y) ? x : y);
  }
}

V4 sse_cmp_ps(CpuState* s, V4 a, V4 b, u32 pred) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) {
    float x = fget(a, i), y = fget(b, i);
    bool res = false;
    switch (pred) {
      case 0: res = x == y; break;
      case 1: res = x < y; break;
      case 2: res = x <= y; break;
      case 4: res = x != y; break;
      case 5: res = !(x >= y); break;
      default: res = false; break;
    }
    r.u[i] = res ? 0xFFFFFFFFu : 0u;
  }
  return r;
}

V4 sse_shufps(CpuState* s, V4 a, V4 b, u32 imm) {
  (void)s;
  V4 r;
  r.u[0] = a.u[(imm >> 0) & 3];
  r.u[1] = a.u[(imm >> 2) & 3];
  r.u[2] = b.u[(imm >> 4) & 3];
  r.u[3] = b.u[(imm >> 6) & 3];
  return r;
}

V4 sse_unpcklps(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  r.u[0] = a.u[0]; r.u[1] = b.u[0];
  r.u[2] = a.u[1]; r.u[3] = b.u[1];
  return r;
}

V4 sse_unpckhps(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  r.u[0] = a.u[2]; r.u[1] = b.u[2];
  r.u[2] = a.u[3]; r.u[3] = b.u[3];
  return r;
}

V4 sse_pshufd(CpuState* s, V4 a, u32 imm) {
  (void)s;
  V4 r;
  r.u[0] = a.u[(imm >> 0) & 3];
  r.u[1] = a.u[(imm >> 2) & 3];
  r.u[2] = a.u[(imm >> 4) & 3];
  r.u[3] = a.u[(imm >> 6) & 3];
  return r;
}

V4 sse_movhlps(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r = a;
  r.u[0] = b.u[2];
  r.u[1] = b.u[3];
  return r;
}

V4 sse_movlhps(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r = a;
  r.u[2] = b.u[0];
  r.u[3] = b.u[1];
  return r;
}

void sse_comiss(CpuState* s, V4 a, V4 b, int quiet) {
  float x = fget(a, 0), y = fget(b, 0);
  u32 f = get_flags(s);
  f &= ~(kZF | kPF | kCF | kOF);
  if (x != x || y != y) {  // unordered
    f |= kZF | kPF | kCF;
  } else if (x > y) {
    // all clear
  } else if (x < y) {
    f |= kCF;
  } else {
    f |= kZF | kPF;
  }
  (void)quiet;
  s->flags = f;
  s->flag_op = kFlagOpNone;
}

V4 sse_cvtsi2ss(CpuState* s, V4 d, s32 v) {
  (void)s;
  V4 r = d;
  fset(r, 0, static_cast<float>(v));
  return r;
}

s32 sse_cvttss2si(CpuState* s, V4 a) {
  (void)s;
  float x = fget(a, 0);
  if (x != x || x >= 2147483648.0f || x < -2147483648.0f) return static_cast<s32>(0x80000000);
  return static_cast<s32>(x);
}

s32 sse_cvtss2si(CpuState* s, V4 a) {
  (void)s;
  float x = fget(a, 0);
  if (x != x) return static_cast<s32>(0x80000000);
  return static_cast<s32>(std::lrintf(x));
}

V4 sse_movd_in(CpuState* s, u32 v) {
  (void)s;
  V4 r{};
  r.u[0] = v;
  return r;
}

u32 sse_movd_out(CpuState* s, V4 a) {
  (void)s;
  return a.u[0];
}

V4 sse_movq_load(CpuState* s, u32 addr) {
  (void)s;
  V4 r{};
  r.u[0] = load<u32>(addr);
  r.u[1] = load<u32>(addr + 4);
  return r;
}

void sse_movq_store(CpuState* s, u32 addr, V4 a) {
  (void)s;
  store<u32>(addr, a.u[0]);
  store<u32>(addr + 4, a.u[1]);
}

V4 sse_cvttps2dq(CpuState* s, V4 a) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) {
    float x = fget(a, i);
    s32 v = (x != x) ? static_cast<s32>(0x80000000) : static_cast<s32>(x);
    __builtin_memcpy(&r.u[i], &v, 4);
  }
  return r;
}

u32 sse_movmskps(CpuState* s, V4 a) {
  (void)s;
  u32 m = 0;
  for (int i = 0; i < 4; ++i) m |= ((a.u[i] >> 31) & 1u) << i;
  return m;
}

u32 sse_pextrw(CpuState* s, V4 a, u32 idx) {
  (void)s;
  return (a.u[idx] >> ((idx & 1) * 16)) & 0xFFFFu;
}

V4 sse_packssdw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 2; ++i) {
    s32 x;
    __builtin_memcpy(&x, &a.u[i], 4);
    s16 v = x > 32767 ? 32767 : (x < -32768 ? -32768 : static_cast<s16>(x));
    r.u[i] = static_cast<u16>(v);
  }
  for (int i = 0; i < 2; ++i) {
    s32 x;
    __builtin_memcpy(&x, &b.u[i], 4);
    s16 v = x > 32767 ? 32767 : (x < -32768 ? -32768 : static_cast<s16>(x));
    r.u[2 + i] = static_cast<u16>(v);
  }
  return r;
}

V4 sse_pmaddwd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 2; ++i) {
    s16 a0 = static_cast<s16>(a.u[i * 2] & 0xFFFF);
    s16 a1 = static_cast<s16>(a.u[i * 2 + 1] & 0xFFFF);
    s16 b0 = static_cast<s16>(b.u[i * 2] & 0xFFFF);
    s16 b1 = static_cast<s16>(b.u[i * 2 + 1] & 0xFFFF);
    s32 v = s32(a0) * b0 + s32(a1) * b1;
    __builtin_memcpy(&r.u[i], &v, 4);
  }
  return r;
}

void sse_rsqrt_ss(CpuState* s, V4& d, V4 b) {
  (void)s;
  fset(d, 0, 1.0f / std::sqrt(fget(b, 0)));
}

void sse_rcp_ss(CpuState* s, V4& d, V4 b) {
  (void)s;
  fset(d, 0, 1.0f / fget(b, 0));
}

V4 sse_punpcklqdq(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  r.u[0] = a.u[0];
  r.u[1] = a.u[1];
  r.u[2] = b.u[0];
  r.u[3] = b.u[1];
  return r;
}

V4 sse_punpckhqdq(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  r.u[0] = a.u[2];
  r.u[1] = a.u[3];
  r.u[2] = b.u[2];
  r.u[3] = b.u[3];
  return r;
}

s32 sse_cvttsd2si(CpuState* s, V4 a) {
  (void)s;
  double d;
  __builtin_memcpy(&d, &a.u[0], 8);
  if (d != d || d >= 2147483648.0 || d < -2147483648.0) return s32(0x80000000);
  return static_cast<s32>(d);
}

s32 sse_cvtsd2si(CpuState* s, V4 a) {
  (void)s;
  double d;
  __builtin_memcpy(&d, &a.u[0], 8);
  if (d != d) return s32(0x80000000);
  return static_cast<s32>(std::lrint(d));
}

}  // namespace sr
