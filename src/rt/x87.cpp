// SporeRecomp — x87 helper implementations.
//
// The x87 stack is modelled as eight 80-bit registers with a rotating top-of-stack, which
// is what the original code assumes. Values are converted to/from double for arithmetic:
// Spore's 65k `fld` sites are all 32/64-bit memory or st(i) operands, so the 64-bit
// mantissa is never the limiting factor for game behaviour.
#include <cmath>
#include <cstring>

#include "rt/guest.h"

namespace sr {

namespace {

inline int phys(CpuState* s, int i) { return (int(s->fpu_top) + i) & 7; }

inline double read80(const X87Reg& r) {
  // Decode x86 80-bit extended precision into a double.
  u64 mantissa;
  u16 se;
  __builtin_memcpy(&mantissa, r.bytes, 8);
  __builtin_memcpy(&se, r.bytes + 8, 2);
  int sign = (se >> 15) & 1;
  int exp = se & 0x7FFF;
  if (exp == 0 && mantissa == 0) return sign ? -0.0 : 0.0;
  if (exp == 0x7FFF) {
    if (mantissa == 0x8000000000000000ull) return sign ? -INFINITY : INFINITY;
    return NAN;
  }
  double m = static_cast<double>(mantissa) / 9223372036854775808.0;  // /2^63
  double v = std::ldexp(m, exp - 16383);
  return sign ? -v : v;
}

inline void write80(X87Reg& r, double v) {
  std::memset(r.bytes, 0, 10);
  if (v == 0.0) {
    u16 se = std::signbit(v) ? 0x8000 : 0x0000;
    __builtin_memcpy(r.bytes + 8, &se, 2);
    return;
  }
  if (std::isnan(v)) {
    u64 m = 0xC000000000000000ull;
    u16 se = 0x7FFF;
    __builtin_memcpy(r.bytes, &m, 8);
    __builtin_memcpy(r.bytes + 8, &se, 2);
    return;
  }
  if (std::isinf(v)) {
    u64 m = 0x8000000000000000ull;
    u16 se = 0x7FFF | (v < 0 ? 0x8000 : 0);
    __builtin_memcpy(r.bytes, &m, 8);
    __builtin_memcpy(r.bytes + 8, &se, 2);
    return;
  }
  int e;
  double m = std::frexp(std::fabs(v), &e);  // m in [0.5,1)
  int exp = e - 1 + 16383;
  u64 mant = static_cast<u64>(std::ldexp(m, 64));
  u16 se = static_cast<u16>(exp) | (v < 0 ? 0x8000 : 0);
  __builtin_memcpy(r.bytes, &mant, 8);
  __builtin_memcpy(r.bytes + 8, &se, 2);
}

inline double get(CpuState* s, int i) { return read80(s->st[phys(s, i)]); }
inline void put(CpuState* s, int i, double v) { write80(s->st[phys(s, i)], v); }

inline void push(CpuState* s, double v) {
  s->fpu_top = (s->fpu_top + 7) & 7;
  write80(s->st[s->fpu_top], v);
}

inline double pop(CpuState* s) {
  double v = read80(s->st[s->fpu_top]);
  s->fpu_top = (s->fpu_top + 1) & 7;
  return v;
}

inline void set_compare_flags(CpuState* s, double a, double b, bool unordered_ok) {
  u32 f = get_flags(s);
  f &= ~(kZF | kPF | kCF);
  if (a != a || b != b) {
    f |= kZF | kPF | kCF;
  } else if (a > b) {
    // clear
  } else if (a < b) {
    f |= kCF;
  } else {
    f |= kZF | kPF;
  }
  (void)unordered_ok;
  s->flags = f;
  s->flag_op = kFlagOpNone;
}

inline double read_mem(u32 addr, int size) {
  if (size == 4) return static_cast<double>(load<float>(addr));
  if (size == 8) return load<double>(addr);
  if (size == 10) {
    X87Reg r;
    __builtin_memcpy(r.bytes, gmem().base() + addr, 10);
    return read80(r);
  }
  return 0.0;
}

inline void write_mem(u32 addr, int size, double v) {
  if (size == 4) store<float>(addr, static_cast<float>(v));
  else if (size == 8) store<double>(addr, v);
  else {
    X87Reg r;
    write80(r, v);
    __builtin_memcpy(gmem().base() + addr, r.bytes, 10);
  }
}

inline double operand(CpuState* s, X87Op op, int size) {
  return op.st >= 0 ? get(s, op.st) : read_mem(op.addr, size);
}

inline double read_int(u32 addr, int size) {
  switch (size) {
    case 2: return static_cast<double>(load<s16>(addr));
    case 4: return static_cast<double>(load<s32>(addr));
    case 8: return static_cast<double>(load<s64>(addr));
    default: return 0.0;
  }
}

}  // namespace

void x87_push(CpuState* s, double v) { push(s, v); }
void x87_push_const(CpuState* s, double v) { push(s, v); }

void x87_load(CpuState* s, X87Op op, int size) {
  push(s, operand(s, op, size));
}

void x87_store(CpuState* s, X87Op op, int size) {
  if (op.st >= 0) put(s, op.st, get(s, 0));
  else write_mem(op.addr, size, get(s, 0));
}

void x87_pop_store(CpuState* s, X87Op op, int size) {
  double v = get(s, 0);
  if (op.st >= 0) put(s, op.st, v);
  else write_mem(op.addr, size, v);
  pop(s);
}

void x87_load_int(CpuState* s, X87Op op, int size) {
  double v = 0;
  switch (size) {
    case 2: v = static_cast<double>(load<s16>(op.addr)); break;
    case 4: v = static_cast<double>(load<s32>(op.addr)); break;
    case 8: v = static_cast<double>(load<s64>(op.addr)); break;
    default: break;
  }
  push(s, v);
}

void x87_pop_store_int(CpuState* s, X87Op op, int size) {
  double v = get(s, 0);
  switch (size) {
    case 2: store<s16>(op.addr, static_cast<s16>(std::lrint(v))); break;
    case 4: store<s32>(op.addr, static_cast<s32>(std::lrint(v))); break;
    case 8: store<s64>(op.addr, static_cast<s64>(std::llrint(v))); break;
    default: break;
  }
  pop(s);
}

void x87_add(CpuState* s, X87Op a, X87Op b) { put(s, a.st, operand(s, a, 8) + operand(s, b, 8)); }
void x87_sub(CpuState* s, X87Op a, X87Op b) { put(s, a.st, operand(s, a, 8) - operand(s, b, 8)); }
void x87_mul(CpuState* s, X87Op a, X87Op b) { put(s, a.st, operand(s, a, 8) * operand(s, b, 8)); }
void x87_div(CpuState* s, X87Op a, X87Op b) { put(s, a.st, operand(s, a, 8) / operand(s, b, 8)); }
void x87_subr(CpuState* s, X87Op a, X87Op b) { put(s, a.st, operand(s, b, 8) - operand(s, a, 8)); }
void x87_divr(CpuState* s, X87Op a, X87Op b) { put(s, a.st, operand(s, b, 8) / operand(s, a, 8)); }

void x87_addp(CpuState* s, X87Op a, X87Op b) {
  double r = operand(s, a, 8) + operand(s, b, 8);
  put(s, a.st, r);
  pop(s);
}
void x87_subp(CpuState* s, X87Op a, X87Op b) {
  double r = operand(s, a, 8) - operand(s, b, 8);
  put(s, a.st, r);
  pop(s);
}
void x87_subrp(CpuState* s, X87Op a, X87Op b) {
  double r = operand(s, b, 8) - operand(s, a, 8);
  put(s, a.st, r);
  pop(s);
}
void x87_mulp(CpuState* s, X87Op a, X87Op b) {
  double r = operand(s, a, 8) * operand(s, b, 8);
  put(s, a.st, r);
  pop(s);
}
void x87_divp(CpuState* s, X87Op a, X87Op b) {
  double r = operand(s, a, 8) / operand(s, b, 8);
  put(s, a.st, r);
  pop(s);
}
void x87_divrp(CpuState* s, X87Op a, X87Op b) {
  double r = operand(s, b, 8) / operand(s, a, 8);
  put(s, a.st, r);
  pop(s);
}

void x87_com(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), false);
}
void x87_comp(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), false);
  pop(s);
}
void x87_ucom(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), true);
}
void x87_ucomp(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), true);
  pop(s);
}
void x87_compp(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), false);
  pop(s);
  pop(s);
}
void x87_ucompp(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), true);
  pop(s);
  pop(s);
}

void x87_chs(CpuState* s) { put(s, 0, -get(s, 0)); }
void x87_abs(CpuState* s) { put(s, 0, std::fabs(get(s, 0))); }
void x87_sqrt(CpuState* s) { put(s, 0, std::sqrt(get(s, 0))); }

void x87_fxch(CpuState* s, int n) {
  int i = phys(s, 0), j = phys(s, n);
  X87Reg t = s->st[i];
  s->st[i] = s->st[j];
  s->st[j] = t;
}

void x87_free(CpuState* s) { pop(s); }

void x87_prem(CpuState* s, int round) {
  double a = get(s, 0), b = get(s, 1);
  double q = a / b;
  double r;
  if (round == 1) {
    r = a - std::round(q) * b;
  } else {
    r = a - std::trunc(q) * b;
  }
  put(s, 0, r);
}

void x87_rndint(CpuState* s) { put(s, 0, std::nearbyint(get(s, 0))); }

void x87_sin(CpuState* s) { put(s, 0, std::sin(get(s, 0))); }
void x87_cos(CpuState* s) { put(s, 0, std::cos(get(s, 0))); }

void x87_sincos(CpuState* s) {
  double x = get(s, 0);
  double sn = std::sin(x), cs = std::cos(x);
  put(s, 0, sn);
  push(s, cs);  // fsin-cos pushes cos above sin, per the SDM
}

void x87_tan(CpuState* s) {
  double x = get(s, 0);
  put(s, 0, std::tan(x));
  push(s, 1.0);  // fptan always pushes 1.0
}

void x87_atan2(CpuState* s) {
  double y = get(s, 0), x = get(s, 1);
  double r = std::atan2(y, x);
  pop(s);
  put(s, 0, r);
}

void x87_2xm1(CpuState* s) { put(s, 0, std::exp2(get(s, 0)) - 1.0); }

void x87_yl2x(CpuState* s) {
  double y = get(s, 0), x = get(s, 1);
  double r = y * std::log2(x);
  pop(s);
  put(s, 0, r);
}

void x87_yl2xp1(CpuState* s) {
  double y = get(s, 0), x = get(s, 1);
  double r = y * std::log2(x + 1.0);
  pop(s);
  put(s, 0, r);
}

void x87_fiadd(CpuState* s, u32 addr, int size) {
  put(s, 0, get(s, 0) + read_int(addr, size));
}
void x87_fisub(CpuState* s, u32 addr, int size) {
  put(s, 0, get(s, 0) - read_int(addr, size));
}
void x87_fimul(CpuState* s, u32 addr, int size) {
  put(s, 0, get(s, 0) * read_int(addr, size));
}
void x87_fidiv(CpuState* s, u32 addr, int size) {
  put(s, 0, get(s, 0) / read_int(addr, size));
}

void x87_fisubr(CpuState* s, u32 addr, int size) {
  put(s, 0, read_int(addr, size) - get(s, 0));
}

void x87_fidivr(CpuState* s, u32 addr, int size) {
  put(s, 0, read_int(addr, size) / get(s, 0));
}

void x87_fcmov(CpuState* s, X87Op op) {
  put(s, 0, operand(s, op, 8));
}

void x87_ficom(CpuState* s, u32 addr, int size) {
  set_compare_flags(s, get(s, 0), read_int(addr, size), false);
}

void x87_ficomp(CpuState* s, u32 addr, int size) {
  set_compare_flags(s, get(s, 0), read_int(addr, size), false);
  pop(s);
}
void x87_scale(CpuState* s) {
  put(s, 0, std::ldexp(get(s, 0), static_cast<int>(std::trunc(get(s, 1)))));
}

void x87_compi(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), false);
  pop(s);
}

void x87_ucompi(CpuState* s, X87Op a, X87Op b) {
  set_compare_flags(s, operand(s, a, 8), operand(s, b, 8), true);
  pop(s);
}

void x87_save_state(CpuState* s, u32 addr) {
  // Minimal FXSAVE layout: control/status/top, the x87 register file and the XMM bank.
  store<u16>(addr + 0, s->fpu_ctrl);
  store<u16>(addr + 2, s->fpu_status);
  store<u8>(addr + 4, static_cast<u8>(0xFF));  // tag word: "all valid"
  store<u32>(addr + 24, s->fpu_top);
  for (int i = 0; i < 8; ++i) {
    __builtin_memcpy(gmem().base() + addr + 32 + i * 16, s->st[i].bytes, 10);
  }
  V4* xmm[8] = {&s->x0, &s->x1, &s->x2, &s->x3, &s->x4, &s->x5, &s->x6, &s->x7};
  for (int i = 0; i < 8; ++i) {
    __builtin_memcpy(gmem().base() + addr + 160 + i * 16, xmm[i], 16);
  }
}

void x87_restore_state(CpuState* s, u32 addr) {
  s->fpu_ctrl = load<u16>(addr + 0);
  s->fpu_status = load<u16>(addr + 2);
  s->fpu_top = load<u32>(addr + 24) & 7;
  for (int i = 0; i < 8; ++i) {
    __builtin_memcpy(s->st[i].bytes, gmem().base() + addr + 32 + i * 16, 10);
  }
  V4* xmm[8] = {&s->x0, &s->x1, &s->x2, &s->x3, &s->x4, &s->x5, &s->x6, &s->x7};
  for (int i = 0; i < 8; ++i) {
    __builtin_memcpy(xmm[i], gmem().base() + addr + 160 + i * 16, 16);
  }
}

}  // namespace sr
