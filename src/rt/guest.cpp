// SporeRecomp — helper implementations for lifted code.
#include "rt/guest.h"

#include <cstdio>
#include <cstring>

#include "rt/d3d9/com.h"
#include "rt/imports.h"
#include "rt/mem.h"
#include "rt/shim.h"

namespace sr {

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
GuestFn find_function(u32 addr) {
  unsigned lo = 0, hi = g_function_count;
  while (lo < hi) {
    unsigned mid = (lo + hi) / 2;
    if (g_functions[mid].addr == addr) return g_functions[mid].fn;
    if (g_functions[mid].addr < addr) lo = mid + 1; else hi = mid;
  }
  return nullptr;
}

void guest_call_indirect(CpuState* s, u32 addr) {
  // D3D9 COM methods (vtable dispatch) — checked before the plain function table because the
  // stub range is small and the comparison is cheap.
  if (addr >= d3d::kComStubBase && addr < d3d::kComStubBase +
      d3d::kComMaxKinds * d3d::kComMaxMethods * d3d::kComStubStride) {
    if (d3d::com_dispatch(s, addr)) return;
  }
  // Import stubs come next: the IAT is full of them, so this is the hot path for every
  // Win32 call the guest makes.
  const imports::Desc* desc = nullptr;
  if (imports::HostFn imp = imports::resolve_stub(addr, &desc)) {
    imports::invoke(desc, s);
    return;
  }
  GuestFn fn = find_function(addr);
  if (!fn) {
    unsupported("indirect call to unmapped guest address", addr);
    return;
  }
  fn(s);
}

void guest_tail(CpuState* s, u32 addr) {
  const imports::Desc* desc = nullptr;
  if (imports::HostFn imp = imports::resolve_stub(addr, &desc)) {
    imports::invoke(desc, s);
    return;
  }
  GuestFn fn = find_function(addr);
  if (!fn) {
    unsupported("tail call to unmapped guest address", addr);
    return;
  }
  fn(s);
}

void guest_jump_indirect(CpuState* s, u32 addr) {
  guest_tail(s, addr);
}

void guest_return(CpuState* s, u32 ret_addr) {
  // A lifted function returns by jumping to the guest return address. If that address is
  // inside a lifted function we continue there; if it is the sentinel the caller planted,
  // we simply stop.
  if (ret_addr == 0xFFFFFFFFu) return;
  GuestFn fn = find_function(ret_addr);
  if (fn) {
    fn(s);
    return;
  }
  unsupported("return to unmapped guest address", ret_addr);
}

// ---------------------------------------------------------------------------
// pushad / popad / enter
// ---------------------------------------------------------------------------
void pushad(CpuState* s) {
  u32 sp = s->r[4];
  u32 orig = sp;
  for (int i = 0; i < 8; ++i) {
    sp -= 4;
    store<u32>(sp, s->r[i]);
  }
  (void)orig;
  s->r[4] = sp;
}

void popad(CpuState* s) {
  u32 sp = s->r[4];
  for (int i = 7; i >= 0; --i) {
    if (i != 4) s->r[i] = load<u32>(sp);
    sp += 4;
  }
  s->r[4] = sp;
}

void enter_frame(CpuState* s, u32 size, u32 level) {
  s->r[4] -= 4;
  store<u32>(s->r[4], s->r[5]);
  u32 frame = s->r[4];
  if (level > 0) {
    u32 bp = s->r[5];
    for (u32 i = 1; i < level; ++i) {
      bp -= 4;
      u32 v = load<u32>(bp);
      s->r[4] -= 4;
      store<u32>(s->r[4], v);
    }
    s->r[4] -= 4;
    store<u32>(s->r[4], frame);
  }
  s->r[5] = frame;
  s->r[4] -= size;
}

// ---------------------------------------------------------------------------
// String ops
// ---------------------------------------------------------------------------
namespace {
inline int dir_step(CpuState* s, int bytes) {
  return (s->flags & kDF) ? -bytes : bytes;
}
}  // namespace

void rep_movsd(CpuState* s) {
  u32 n = s->r[1];
  if (!n) return;
  int step = dir_step(s, 4);
  u32 src = s->r[6], dst = s->r[7];
  if (step > 0) {
    __builtin_memmove(gmem().base() + dst, gmem().base() + src, size_t(n) * 4);
    src += n * 4;
    dst += n * 4;
  } else {
    for (u32 i = 0; i < n; ++i) {
      store<u32>(dst, load<u32>(src));
      src += step;
      dst += step;
    }
  }
  s->r[6] = src;
  s->r[7] = dst;
  s->r[1] = 0;
}

void rep_movsb(CpuState* s) {
  u32 n = s->r[1];
  if (!n) return;
  int step = dir_step(s, 1);
  u32 src = s->r[6], dst = s->r[7];
  if (step > 0) {
    __builtin_memmove(gmem().base() + dst, gmem().base() + src, n);
    src += n;
    dst += n;
  } else {
    for (u32 i = 0; i < n; ++i) {
      gmem().base()[dst] = gmem().base()[src];
      src += step;
      dst += step;
    }
  }
  s->r[6] = src;
  s->r[7] = dst;
  s->r[1] = 0;
}

void rep_stosd(CpuState* s) {
  u32 n = s->r[1];
  u32 v = s->r[0];
  int step = dir_step(s, 4);
  u32 dst = s->r[7];
  if (!n) return;
  if (step > 0) {
    for (u32 i = 0; i < n; ++i) {
      store<u32>(dst, v);
      dst += 4;
    }
  } else {
    for (u32 i = 0; i < n; ++i) {
      store<u32>(dst, v);
      dst -= 4;
    }
  }
  s->r[7] = dst;
  s->r[1] = 0;
}

void rep_stosb(CpuState* s) {
  u32 n = s->r[1];
  u8 v = static_cast<u8>(s->r[0]);
  int step = dir_step(s, 1);
  u32 dst = s->r[7];
  if (!n) return;
  __builtin_memset(gmem().base() + dst, v, n);
  s->r[7] = dst + step * n;
  s->r[1] = 0;
}

void rep_cmpsb(CpuState* s) {
  u32 n = s->r[1];
  int step = dir_step(s, 1);
  while (n) {
    u8 a = gmem().base()[s->r[6]];
    u8 b = gmem().base()[s->r[7]];
    s->r[6] += step;
    s->r[7] += step;
    --n;
    set_sub_flags(s, a, b, u32(a) - u32(b));
    if (a != b) break;
  }
  s->r[1] = n;
}

void rep_cmpsd(CpuState* s) {
  u32 n = s->r[1];
  int step = dir_step(s, 4);
  while (n) {
    u32 a = load<u32>(s->r[6]);
    u32 b = load<u32>(s->r[7]);
    s->r[6] += step;
    s->r[7] += step;
    --n;
    set_sub_flags(s, a, b, a - b);
    if (a != b) break;
  }
  s->r[1] = n;
}

void rep_scasb(CpuState* s) {
  u32 n = s->r[1];
  int step = dir_step(s, 1);
  u8 al = static_cast<u8>(s->r[0]);
  while (n) {
    u8 b = gmem().base()[s->r[7]];
    s->r[7] += step;
    --n;
    set_sub_flags(s, al, b, u32(al) - u32(b));
    if (al != b) break;
  }
  s->r[1] = n;
}

// ---------------------------------------------------------------------------
// Flag helpers
// ---------------------------------------------------------------------------
void set_shift_flags(CpuState* s, u32 a, u32 count, u32 result, int bits) {
  u32 f = get_flags(s);
  if (count == 0) return;
  u32 mask = bits >= 32 ? 0xFFFFFFFFu : ((1u << bits) - 1);
  u32 cf = (a >> (count - 1)) & 1u;
  f = (f & ~kCF) | (cf ? kCF : 0);
  f = (f & ~(kZF | kSF | kPF));
  u32 res = result & mask;
  if (res == 0) f |= kZF;
  if (res & (1u << (bits - 1))) f |= kSF;
  f |= parity(res);
  // OF is only defined for count == 1
  if (count == 1) {
    f &= ~kOF;
    u32 msb = (result >> (bits - 1)) & 1u;
    if (msb != cf) f |= kOF;
  }
  s->flags = f;
  s->flag_op = kFlagOpNone;
  s->flags_mask = 0xFFFFFFFFu;
}

void bt_op(CpuState* s, u32 base, u32 bit, int size, int op) {
  u32 bits = u32(size) * 8;
  u32 idx = (bit / bits);
  u32 off = bit % bits;
  u32 addr = base + idx * u32(size);
  u32 v = load<u32>(addr) & (size == 4 ? 0xFFFFFFFFu : ((1u << bits) - 1));
  bool set = (v >> off) & 1u;
  u32 f = get_flags(s);
  f = (f & ~kCF) | (set ? kCF : 0);
  s->flags = f;
  s->flag_op = kFlagOpNone;
  if (op == 1) v |= (1u << off);
  else if (op == 2) v &= ~(1u << off);
  else if (op == 3) v ^= (1u << off);
  if (op) store<u32>(addr, v);
}

void shld(CpuState* s, u32 dst, u32 src, u32 count, int size, int right) {
  u32 bits = u32(size) * 8;
  count &= 31;
  u32 r = dst;
  if (count) {
    if (bits == 32) {
      r = right ? ((dst >> count) | (src << (32 - count)))
                : ((dst << count) | (src >> (32 - count)));
    } else {
      u32 mask = (1u << bits) - 1;
      dst &= mask; src &= mask;
      r = right ? ((dst >> count) | (src << (bits - count)))
                : ((dst << count) | (src >> (bits - count)));
      r &= mask;
    }
  }
  u32 f = get_flags(s);
  f = (f & ~(kCF | kZF | kSF | kPF));
  if (count) {
    u32 cf = right ? ((dst >> (count - 1)) & 1u) : ((dst >> (bits - count)) & 1u);
    if (cf) f |= kCF;
  }
  if (r == 0) f |= kZF;
  if (r & (1u << (bits - 1))) f |= kSF;
  f |= parity(r);
  s->flags = f;
  s->flag_op = kFlagOpNone;
  store<u32>(s->r[4], r);  // caller re-reads via write_op; see lifter note
}

void imul_1(CpuState* s, int size) {
  if (size == 4) {
    s64 r = s64(s32(s->r[0])) * s64(s32(s->r[0]));
    s->r[0] = u32(r);
    s->r[2] = u32(u64(r) >> 32);
  } else {
    s32 r = s32(s16(s->r[0])) * s32(s16(s->r[0]));
    s->r[0] = u32(u16(r));
    s->r[2] = u32(u16(r >> 16));
  }
}

void mul_1(CpuState* s, u32 v, int size) {
  if (size == 4) {
    u64 r = u64(s->r[0]) * v;
    s->r[0] = u32(r);
    s->r[2] = u32(r >> 32);
  } else {
    u32 r = u32(u16(s->r[0])) * u32(u16(v));
    s->r[0] = r & 0xFFFF;
    s->r[2] = (r >> 16) & 0xFFFF;
  }
}

void div_1(CpuState* s, u32 v, int size, bool is_signed) {
  if (v == 0) {
    unsupported("divide by zero", s->eip);
    return;
  }
  if (size == 4) {
    if (is_signed) {
      s64 num = (s64(s32(s->r[2])) << 32) | s->r[0];
      s32 d = s32(v);
      s->r[0] = u32(num / d);
      s->r[2] = u32(num % d);
    } else {
      u64 num = (u64(s->r[2]) << 32) | s->r[0];
      s->r[0] = u32(num / v);
      s->r[2] = u32(num % v);
    }
  } else {
    u32 num = (u32(u16(s->r[2])) << 16) | u16(s->r[0]);
    if (is_signed) {
      s32 n = s32(s16(num));
      s16 d = s16(v);
      s->r[0] = u32(u16(n / d));
      s->r[2] = u32(u16(n % d));
    } else {
      s->r[0] = (num / (v & 0xFFFF)) & 0xFFFF;
      s->r[2] = (num % (v & 0xFFFF)) & 0xFFFF;
    }
  }
}

u32 bswap32(u32 v) {
  return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | (v >> 24);
}

void rotate_carry(CpuState* s, u32 count, int size, int left) {
  (void)s; (void)count; (void)size; (void)left;
  unsupported("rcl/rcr", s->eip);
}

// ---------------------------------------------------------------------------
// Atomics: the guest is single-threaded per thread object, but the game spins on these,
// so they must be real atomics on the host.
// ---------------------------------------------------------------------------
void atomic_xadd(CpuState* s, u32 addr, int size) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + addr);
  u32 old = __atomic_fetch_add(p, s->r[0], __ATOMIC_SEQ_CST);
  if (size == 4) {
    s->r[0] = old;
  } else {
    s->r[0] = old & 0xFFFF;
    s->r[2] = (old >> 16) & 0xFFFF;
  }
  u32 f = get_flags(s);
  f &= ~(kCF | kZF | kSF | kPF | kOF);
  if (old + s->r[0] == 0) f |= kZF;
  s->flags = f;
}

void atomic_cmpxchg(CpuState* s, u32 addr, int size) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + addr);
  u32 expected = s->r[0];
  __atomic_compare_exchange_n(p, &expected, s->r[2], false, __ATOMIC_SEQ_CST,
                              __ATOMIC_SEQ_CST);
  u32 f = get_flags(s);
  if (expected == s->r[0]) f |= kZF; else f &= ~kZF;
  s->r[0] = expected;
  s->flags = f;
}

void atomic_add(CpuState* s, u32 addr, int size, u32 v) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + addr);
  u32 old = __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST);
  set_add_flags(s, old, v, old + v);
}

void atomic_or(CpuState* s, u32 addr, int size, u32 v) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + addr);
  u32 old = __atomic_fetch_or(p, v, __ATOMIC_SEQ_CST);
  set_logic_flags(s, old | v);
}

void atomic_xor(CpuState* s, u32 addr, int size, u32 v) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + addr);
  u32 old = __atomic_fetch_xor(p, v, __ATOMIC_SEQ_CST);
  set_logic_flags(s, old ^ v);
}

// ---------------------------------------------------------------------------
// Ports: Spore pokes the VGA/vendor space a few times; make them no-ops.
// ---------------------------------------------------------------------------
void port_in(CpuState* s, u32 port) { (void)port; s->r[0] = 0xFFFFFFFFu; }
void port_out(CpuState* s, u32 port) { (void)port; }

// ---------------------------------------------------------------------------
// Deterministic platform shims
// ---------------------------------------------------------------------------
namespace {
u64 g_tsc_base = 0;
}

void guest_rdtsc(CpuState* s) {
  // Deterministic and monotonic: the game uses rdtsc for timing, not for crypto.
  static u64 counter = 0x1000;
  counter += 1;
  s->r[0] = u32(counter);
  s->r[2] = u32(counter >> 32);
  (void)g_tsc_base;
}

void guest_cpuid(CpuState* s) {
  u32 leaf = s->r[0];
  switch (leaf) {
    case 0:
      s->r[0] = 1;
      s->r[1] = 0x756E6547;  // "Genu"
      s->r[2] = 0x49656E69;  // "ineI"
      s->r[3] = 0x6C65746E;  // "ntel"
      break;
    case 1:
      s->r[0] = 0x000006F2;  // family 6, model 15
      s->r[1] = 0;
      s->r[2] = 0x00000001;  // SSE
      s->r[3] = 0x00000000;
      break;
    default:
      s->r[0] = s->r[1] = s->r[2] = s->r[3] = 0;
      break;
  }
}

void debug_break(CpuState* s) {
  std::fprintf(stderr, "[guest] int3 at 0x%08x\n", s->eip);
}

void unsupported(const char* what, u32 addr) {
  std::fprintf(stderr, "[guest] UNSUPPORTED %s at 0x%08x\n", what, addr);
}

}  // namespace sr
