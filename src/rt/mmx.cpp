// SporeRecomp — MMX / packed-integer and misc helper implementations.
//
// MMX in this binary is used for image/audio byte shuffling, so the packed-integer
// semantics have to be exact (saturating adds, packed shifts, unpack interleaves).
#include <cmath>
#include <cstring>

#include "rt/guest.h"

namespace sr {

namespace {
inline u16 lo16(V4 v, int i) { return u16(v.u[i] & 0xFFFF); }
inline u16 hi16(V4 v, int i) { return u16(v.u[i] >> 16); }
inline void set16(V4& v, int i, u16 x) {
  v.u[i] = (v.u[i] & 0xFFFF0000u) | u32(x);
}
inline void set16lo(V4& v, int i, u16 x) {
  v.u[i] = (v.u[i] & 0xFFFF0000u) | u32(x);
}
inline void set16hi(V4& v, int i, u16 x) {
  v.u[i] = (v.u[i] & 0x0000FFFFu) | (u32(x) << 16);
}
inline u8 lo8(V4 v, int i) { return u8(v.u[i] & 0xFF); }

inline s16 sat16(s32 x) {
  return s16(x > 32767 ? 32767 : (x < -32768 ? -32768 : x));
}
inline s8 sat8(s32 x) {
  return s8(x > 127 ? 127 : (x < -128 ? -128 : x));
}
}  // namespace

// --- saturating / wrapping 16-bit adds -------------------------------------
#define PADD16(name, expr)                                    \
  V4 name(CpuState* s, V4 a, V4 b) {                          \
    (void)s;                                                   \
    V4 r = a;                                                  \
    for (int i = 0; i < 4; ++i) {                              \
      set16lo(r, i, u16(expr(lo16(a, i), lo16(b, i))));        \
      set16hi(r, i, u16(expr(hi16(a, i), hi16(b, i))));        \
    }                                                          \
    return r;                                                  \
  }

#define ADD_SAT(x, y) sat16(s32(x) + s32(y))
#define SUB_SAT(x, y) sat16(s32(x) - s32(y))
#define ADD_WRAP(x, y) (u16(x) + u16(y))
#define SUB_WRAP(x, y) (u16(x) - u16(y))

PADD16(mmx_paddsw, ADD_SAT)
PADD16(mmx_psubsw, SUB_SAT)
PADD16(mmx_paddw, ADD_WRAP)
PADD16(mmx_psubw, SUB_WRAP)

V4 mmx_paddd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) r.u[i] = a.u[i] + b.u[i];
  return r;
}

V4 mmx_psubd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) r.u[i] = a.u[i] - b.u[i];
  return r;
}

V4 mmx_paddsb(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) {
    r.u[i] = 0;
    for (int k = 0; k < 4; ++k) {
      s8 x = s8((a.u[i] >> (k * 8)) & 0xFF), y = s8((b.u[i] >> (k * 8)) & 0xFF);
      u8 v = u8(sat8(s32(x) + y));
      r.u[i] |= u32(v) << (k * 8);
    }
  }
  return r;
}

V4 mmx_paddb(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) {
    r.u[i] = 0;
    for (int k = 0; k < 4; ++k) {
      u8 v = u8(((a.u[i] >> (k * 8)) & 0xFF) + ((b.u[i] >> (k * 8)) & 0xFF));
      r.u[i] |= u32(v) << (k * 8);
    }
  }
  return r;
}

V4 mmx_pmullw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, u16(lo16(a, i) * lo16(b, i)));
    set16hi(r, i, u16(hi16(a, i) * hi16(b, i)));
  }
  return r;
}

V4 mmx_pmulhw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, u16((s32(s16(lo16(a, i))) * s32(s16(lo16(b, i)))) >> 16));
    set16hi(r, i, u16((s32(s16(hi16(a, i))) * s32(s16(hi16(b, i)))) >> 16));
  }
  return r;
}

V4 mmx_pmulhuw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, u16((u32(lo16(a, i)) * u32(lo16(b, i))) >> 16));
    set16hi(r, i, u16((u32(hi16(a, i)) * u32(hi16(b, i))) >> 16));
  }
  return r;
}

V4 mmx_pmaddwd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  for (int i = 0; i < 2; ++i) {
    s32 v = s32(s16(lo16(a, i * 2))) * s16(lo16(b, i * 2)) +
            s32(s16(hi16(a, i * 2))) * s16(hi16(b, i * 2));
    __builtin_memcpy(&r.u[i], &v, 4);
  }
  return r;
}

V4 mmx_pand(CpuState* s, V4 a, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) a.u[i] &= b.u[i];
  return a;
}
V4 mmx_por(CpuState* s, V4 a, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) a.u[i] |= b.u[i];
  return a;
}
V4 mmx_pxor(CpuState* s, V4 a, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) a.u[i] ^= b.u[i];
  return a;
}
V4 mmx_pandn(CpuState* s, V4 a, V4 b) {
  (void)s;
  for (int i = 0; i < 4; ++i) a.u[i] = (~a.u[i]) & b.u[i];
  return a;
}

V4 mmx_packsswb(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r;
  r.u[0] = r.u[1] = r.u[2] = r.u[3] = 0;
  int out = 0;
  for (int half = 0; half < 2; ++half) {
    V4& src = half ? b : a;
    for (int i = 0; i < 4; ++i) {
      for (int k = 0; k < 2; ++k) {
        s16 v = k ? s16(hi16(src, i)) : s16(lo16(src, i));
        u8 c = u8(sat8(v));
        r.u[out / 4] |= u32(c) << ((out % 4) * 8);
        ++out;
      }
    }
  }
  return r;
}

V4 mmx_packuswb(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  int out = 0;
  for (int half = 0; half < 2; ++half) {
    V4& src = half ? b : a;
    for (int i = 0; i < 4; ++i) {
      for (int k = 0; k < 2; ++k) {
        s16 v = k ? s16(hi16(src, i)) : s16(lo16(src, i));
        u8 c = u8(v < 0 ? 0 : (v > 255 ? 255 : v));
        r.u[out / 4] |= u32(c) << ((out % 4) * 8);
        ++out;
      }
    }
  }
  return r;
}

#define PUNPCK(name, step)                                        \
  V4 name(CpuState* s, V4 a, V4 b) {                              \
    (void)s;                                                      \
    V4 r{};                                                       \
    for (int i = 0; i < 2; ++i) {                                 \
      for (int k = 0; k < step; ++k) {                            \
        int byte = i * step + k;                                  \
        r.u[byte / 4] |= ((a.u[byte / 4] >> ((byte % 4) * 8)) & 0xFF) << (((i * step * 2 + k) % 8) * 4); \
      }                                                           \
    }                                                             \
    return r;                                                     \
  }

// The macro above is unreadable for the general case, so the interleaves are written out.
namespace {
inline void put_byte(V4& v, int idx, u8 b) {
  v.u[idx / 4] = (v.u[idx / 4] & ~(0xFFu << ((idx % 4) * 8))) | (u32(b) << ((idx % 4) * 8));
}
inline u8 get_byte(V4 v, int idx) { return u8((v.u[idx / 4] >> ((idx % 4) * 8)) & 0xFF); }
inline u16 get_word(V4 v, int idx) {
  return u16((v.u[idx / 2] >> ((idx % 2) * 16)) & 0xFFFF);
}
inline void put_word(V4& v, int idx, u16 w) {
  v.u[idx / 2] = (v.u[idx / 2] & ~(0xFFFFu << ((idx % 2) * 16))) | (u32(w) << ((idx % 2) * 16));
}
}  // namespace

V4 mmx_punpcklbw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 4; ++i) {
    put_byte(r, i * 2, get_byte(a, i));
    put_byte(r, i * 2 + 1, get_byte(b, i));
  }
  return r;
}

V4 mmx_punpckhbw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 4; ++i) {
    put_byte(r, i * 2, get_byte(a, i + 4));
    put_byte(r, i * 2 + 1, get_byte(b, i + 4));
  }
  return r;
}

V4 mmx_punpcklwd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 2; ++i) {
    put_word(r, i * 2, get_word(a, i));
    put_word(r, i * 2 + 1, get_word(b, i));
  }
  return r;
}

V4 mmx_punpckhwd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 2; ++i) {
    put_word(r, i * 2, get_word(a, i + 2));
    put_word(r, i * 2 + 1, get_word(b, i + 2));
  }
  return r;
}

V4 mmx_punpckldq(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  r.u[0] = a.u[0];
  r.u[1] = b.u[0];
  return r;
}

V4 mmx_punpckhdq(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  r.u[0] = a.u[1];
  r.u[1] = b.u[1];
  return r;
}

#define PCMP(name, width, expr)                                    \
  V4 name(CpuState* s, V4 a, V4 b) {                               \
    (void)s;                                                       \
    V4 r{};                                                        \
    for (int i = 0; i < 2; ++i) {                                  \
      u16 x = width == 16 ? get_word(a, i) : u16(a.u[i]);           \
      u16 y = width == 16 ? get_word(b, i) : u16(b.u[i]);           \
      u16 v = expr ? 0xFFFF : 0x0000;                              \
      if (width == 16) put_word(r, i, v); else r.u[i] = v;          \
    }                                                              \
    return r;                                                      \
  }

V4 mmx_pcmpeqw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, lo16(a, i) == lo16(b, i) ? 0xFFFF : 0);
    set16hi(r, i, hi16(a, i) == hi16(b, i) ? 0xFFFF : 0);
  }
  return r;
}

V4 mmx_pcmpgtw(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, s16(lo16(a, i)) > s16(lo16(b, i)) ? 0xFFFF : 0);
    set16hi(r, i, s16(hi16(a, i)) > s16(hi16(b, i)) ? 0xFFFF : 0);
  }
  return r;
}

V4 mmx_pcmpeqb(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 16; ++i) put_byte(r, i, get_byte(a, i) == get_byte(b, i) ? 0xFF : 0);
  return r;
}

V4 mmx_pcmpeqd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 4; ++i) r.u[i] = (a.u[i] == b.u[i]) ? 0xFFFFFFFFu : 0u;
  return r;
}

V4 mmx_pcmpgtd(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 4; ++i) r.u[i] = (s32(a.u[i]) > s32(b.u[i])) ? 0xFFFFFFFFu : 0u;
  return r;
}

#define PSHIFT(name, fn)                                           \
  V4 name(CpuState* s, V4 a, u32 count) {                          \
    (void)s;                                                       \
    V4 r = a;                                                      \
    for (int i = 0; i < 4; ++i) {                                  \
      set16lo(r, i, u16(fn(lo16(a, i), count)));                   \
      set16hi(r, i, u16(fn(hi16(a, i), count)));                   \
    }                                                              \
    return r;                                                      \
  }

V4 mmx_psraw(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r = a;
  count = count > 15 ? 16 : count;
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, u16(s16(s32(s16(lo16(a, i))) >> count)));
    set16hi(r, i, u16(s16(s32(s16(hi16(a, i))) >> count)));
  }
  return r;
}

V4 mmx_psrlw(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r = a;
  count = count > 15 ? 16 : count;
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, u16(lo16(a, i) >> count));
    set16hi(r, i, u16(hi16(a, i) >> count));
  }
  return r;
}

V4 mmx_psllw(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r = a;
  count = count > 15 ? 16 : count;
  for (int i = 0; i < 4; ++i) {
    set16lo(r, i, u16(lo16(a, i) << count));
    set16hi(r, i, u16(hi16(a, i) << count));
  }
  return r;
}

V4 mmx_psrad(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r;
  count = count > 31 ? 32 : count;
  for (int i = 0; i < 4; ++i) r.u[i] = u32(s32(a.u[i]) >> count);
  return r;
}

V4 mmx_psrld(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r;
  count = count > 31 ? 32 : count;
  for (int i = 0; i < 4; ++i) r.u[i] = a.u[i] >> count;
  return r;
}

V4 mmx_pslld(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r;
  count = count > 31 ? 32 : count;
  for (int i = 0; i < 4; ++i) r.u[i] = a.u[i] << count;
  return r;
}

V4 mmx_psrlq(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r = a;
  if (count > 63) count = 64;
  for (int i = 0; i < 2; ++i) {
    u64 v = (u64(a.u[i * 2 + 1]) << 32) | a.u[i * 2];
    v = count >= 64 ? 0 : (v >> count);
    r.u[i * 2] = u32(v);
    r.u[i * 2 + 1] = u32(v >> 32);
  }
  return r;
}

V4 mmx_psllq(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r = a;
  if (count > 63) count = 64;
  for (int i = 0; i < 2; ++i) {
    u64 v = (u64(a.u[i * 2 + 1]) << 32) | a.u[i * 2];
    v = count >= 64 ? 0 : (v << count);
    r.u[i * 2] = u32(v);
    r.u[i * 2 + 1] = u32(v >> 32);
  }
  return r;
}

// --- SSE <-> MMX conversions ----------------------------------------------
V4 sse_cvtpi2ps(CpuState* s, V4 d, V4 a) {
  (void)s;
  V4 r = d;
  float f0 = float(s32(a.u[0]));
  float f1 = float(s32(a.u[1]));
  __builtin_memcpy(&r.u[0], &f0, 4);
  __builtin_memcpy(&r.u[1], &f1, 4);
  return r;
}

V4 sse_cvtps2pi(CpuState* s, V4 a) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 2; ++i) {
    float f;
    __builtin_memcpy(&f, &a.u[i], 4);
    s32 v = (f != f) ? s32(0x80000000) : s32(std::lrintf(f));
    r.u[i] = u32(v);
  }
  return r;
}

V4 sse_cvttps2pi(CpuState* s, V4 a) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 2; ++i) {
    float f;
    __builtin_memcpy(&f, &a.u[i], 4);
    s32 v = (f != f) ? s32(0x80000000) : s32(f);
    r.u[i] = u32(v);
  }
  return r;
}

// --- misc integer ---------------------------------------------------------
void atomic_cmpxchg8b(CpuState* s, u32 addr) {
  u64* p = reinterpret_cast<u64*>(gmem().base() + addr);
  u64 expected = (u64(s->r[2]) << 32) | s->r[0];
  u64 desired = (u64(s->r[3]) << 32) | s->r[1];
  u64 seen = expected;
  if (__atomic_compare_exchange_n(p, &seen, desired, false, __ATOMIC_SEQ_CST,
                                  __ATOMIC_SEQ_CST)) {
    s->flags |= kZF;
  } else {
    s->flags &= ~kZF;
    s->r[0] = u32(seen);
    s->r[2] = u32(seen >> 32);
  }
}

void rep_scasd(CpuState* s) {
  u32 n = s->r[1];
  int step = (s->flags & kDF) ? -4 : 4;
  while (n) {
    u32 b = load<u32>(s->r[7]);
    s->r[7] += step;
    --n;
    set_sub_flags(s, s->r[0], b, s->r[0] - b);
    if (s->r[0] != b) break;
  }
  s->r[1] = n;
}

void rep_stosw(CpuState* s) {
  u32 n = s->r[1];
  int step = (s->flags & kDF) ? -2 : 2;
  u32 dst = s->r[7];
  for (u32 i = 0; i < n; ++i) {
    store<u16>(dst, u16(s->r[0]));
    dst += step;
  }
  s->r[7] = dst;
  s->r[1] = 0;
}

void lodsb(CpuState* s) {
  u8 v = load<u8>(s->r[6]);
  s->r[6] += (s->flags & kDF) ? -1 : 1;
  s->r[0] = (s->r[0] & 0xFFFFFF00u) | v;
}
void lodsw(CpuState* s) {
  u16 v = load<u16>(s->r[6]);
  s->r[6] += (s->flags & kDF) ? -2 : 2;
  s->r[0] = (s->r[0] & 0xFFFF0000u) | v;
}
void lodsd(CpuState* s) {
  s->r[0] = load<u32>(s->r[6]);
  s->r[6] += (s->flags & kDF) ? -4 : 4;
}

void aam(CpuState* s, u32 base) {
  if (base == 0) {
    unsupported("aam with base 0", s->eip);
    return;
  }
  u8 al = u8(s->r[0]);
  s->r[0] = (s->r[0] & 0xFFFF0000u) | u32((al / base) << 8) | (al % base);
  set_logic_flags(s, s->r[0] & 0xFF);
}

void aad(CpuState* s, u32 base) {
  u8 al = u8(s->r[0]);
  u8 ah = u8(s->r[0] >> 8);
  u8 v = u8(al + ah * base);
  s->r[0] = (s->r[0] & 0xFFFF0000u) | v;
  set_logic_flags(s, v);
}

void load_far_ptr(CpuState* s, u32 addr, int reg) {
  // flat model: the selector is irrelevant, load the 32-bit offset into r[reg]
  s->r[reg] = load<u32>(addr);
}

void far_call(CpuState* s, u32 addr) {
  unsupported("far call/jmp (16-bit segment)", addr);
}

void guest_interrupt(CpuState* s) {
  unsupported("int n (software interrupt)", s->eip);
}

u32 bit_scan_forward(u32 v, int size) {
  u32 mask = size >= 4 ? 0xFFFFFFFFu : ((1u << (size * 8)) - 1);
  v &= mask;
  if (!v) return 0xFFFFFFFFu;
  return u32(__builtin_ctz(v));
}

u32 bit_scan_reverse(u32 v, int size) {
  u32 mask = size >= 4 ? 0xFFFFFFFFu : ((1u << (size * 8)) - 1);
  v &= mask;
  if (!v) return 0xFFFFFFFFu;
  return u32(31 - __builtin_clz(v));
}

V4 sse_movd_load(CpuState* s, u32 addr) {
  (void)s;
  V4 r{};
  r.u[0] = load<u32>(addr);
  return r;
}

V4 sse_psrldq(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r{};
  if (count > 15) return r;
  for (int i = 0; i < 16; ++i) {
    int src = i + int(count);
    u8 b = src < 16 ? u8((a.u[src / 4] >> ((src % 4) * 8)) & 0xFF) : 0u;
    r.u[i / 4] |= u32(b) << ((i % 4) * 8);
  }
  return r;
}

V4 sse_pslldq(CpuState* s, V4 a, u32 count) {
  (void)s;
  V4 r{};
  if (count > 15) return r;
  for (int i = 0; i < 16; ++i) {
    int src = i - int(count);
    u8 b = src >= 0 ? u8((a.u[src / 4] >> ((src % 4) * 8)) & 0xFF) : 0u;
    r.u[i / 4] |= u32(b) << ((i % 4) * 8);
  }
  return r;
}

V4 mmx_pminub(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 16; ++i) {
    u8 x = u8((a.u[i / 4] >> ((i % 4) * 8)) & 0xFF);
    u8 y = u8((b.u[i / 4] >> ((i % 4) * 8)) & 0xFF);
    u8 v = x < y ? x : y;
    r.u[i / 4] |= u32(v) << ((i % 4) * 8);
  }
  return r;
}

V4 mmx_pmaxub(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 16; ++i) {
    u8 x = u8((a.u[i / 4] >> ((i % 4) * 8)) & 0xFF);
    u8 y = u8((b.u[i / 4] >> ((i % 4) * 8)) & 0xFF);
    u8 v = x > y ? x : y;
    r.u[i / 4] |= u32(v) << ((i % 4) * 8);
  }
  return r;
}

V4 mmx_pshufw(CpuState* s, V4 a, u32 imm) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 4; ++i) {
    int sel = (imm >> (i * 2)) & 3;
    u16 v = get_word(a, sel);
    put_word(r, i, v);
  }
  return r;
}

V4 mmx_paddusb(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 16; ++i) {
    u32 x = get_byte(a, i), y = get_byte(b, i);
    u32 v = x + y;
    put_byte(r, i, u8(v > 255 ? 255 : v));
  }
  return r;
}

V4 mmx_psubusb(CpuState* s, V4 a, V4 b) {
  (void)s;
  V4 r{};
  for (int i = 0; i < 16; ++i) {
    u32 x = get_byte(a, i), y = get_byte(b, i);
    put_byte(r, i, u8(x > y ? x - y : 0));
  }
  return r;
}

}  // namespace sr
