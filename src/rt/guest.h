// SporeRecomp — helpers the lifted code calls.
//
// Everything that is not a plain register operation lives here: guest stack handling,
// indirect dispatch, SSE and x87 helpers, and the "unsupported" trap.
#pragma once

#include <cstdint>

#include "rt/cpu.h"
#include "rt/mem.h"

namespace sr {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using s8 = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;

using GuestFn = void (*)(CpuState*);

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
struct GuestEntry {
  u32 addr;
  GuestFn fn;
};
extern GuestEntry g_functions[];
extern const unsigned g_function_count;

GuestFn find_function(u32 addr);   // binary search over g_functions

// Calls a guest function by address (indirect call sites, vtables, callbacks).
void guest_call_indirect(CpuState* s, u32 addr);
// Tail call: the callee returns to *our* caller.
void guest_tail(CpuState* s, u32 addr);
void guest_jump_indirect(CpuState* s, u32 addr);
// Returns from a lifted function: unwinds to the return address on the guest stack.
void guest_return(CpuState* s, u32 ret_addr);

// ---------------------------------------------------------------------------
// Guest stack
// ---------------------------------------------------------------------------
inline void guest_push_ret(CpuState* s, u32 ret) {
  s->r[4] -= 4;
  store<u32>(s->r[4], ret);
}
inline u32 guest_pop_ret(CpuState* s) {
  u32 v = load<u32>(s->r[4]);
  s->r[4] += 4;
  return v;
}
void pushad(CpuState* s);
void popad(CpuState* s);

// ---------------------------------------------------------------------------
// String ops (rep prefix): DF-aware, exactly like the hardware.
// ---------------------------------------------------------------------------
void rep_movsd(CpuState* s);
void rep_movsb(CpuState* s);
void rep_stosd(CpuState* s);
void rep_stosb(CpuState* s);

// ---------------------------------------------------------------------------
// Flags helpers the lifter emits
// ---------------------------------------------------------------------------
void set_shift_flags(CpuState* s, u32 a, u32 count, u32 result, int bits);
void bt_op(CpuState* s, u32 base, u32 bit, int size, int op);  // 0=bt 1=bts 2=btr 3=btc
void shld(CpuState* s, u32 dst, u32 src, u32 count, int size, int right);
void imul_1(CpuState* s, int size);
void mul_1(CpuState* s, u32 v, int size);
void div_1(CpuState* s, u32 v, int size, bool is_signed);
u32 bswap32(u32 v);

// ---------------------------------------------------------------------------
// SSE
// ---------------------------------------------------------------------------
inline V4 load_v4(u32 addr) {
  V4 v;
  __builtin_memcpy(&v, gmem().base() + addr, 16);
  return v;
}
inline void store_v4(u32 addr, V4 v) {
  __builtin_memcpy(gmem().base() + addr, &v, 16);
}

V4 sse_src(CpuState* s, V4 dst, V4 src);
V4 sse_movss(CpuState* s, V4 dst, V4 src);
V4 sse_movss_load(CpuState* s, V4 dst, u32 addr);
void sse_movss_store(CpuState* s, u32 addr, V4 src);

void sse_xor(CpuState* s, V4& d, V4 b);
void sse_and(CpuState* s, V4& d, V4 b);
void sse_or(CpuState* s, V4& d, V4 b);
void sse_andn(CpuState* s, V4& d, V4 b);
void sse_add_ss(CpuState* s, V4& d, V4 b);
void sse_sub_ss(CpuState* s, V4& d, V4 b);
void sse_mul_ss(CpuState* s, V4& d, V4 b);
void sse_div_ss(CpuState* s, V4& d, V4 b);
void sse_min_ss(CpuState* s, V4& d, V4 b);
void sse_max_ss(CpuState* s, V4& d, V4 b);
void sse_sqrt_ss(CpuState* s, V4& d, V4 b);
void sse_add_ps(CpuState* s, V4& d, V4 b);
void sse_sub_ps(CpuState* s, V4& d, V4 b);
void sse_mul_ps(CpuState* s, V4& d, V4 b);
void sse_div_ps(CpuState* s, V4& d, V4 b);
void sse_rcp_ps(CpuState* s, V4& d, V4 b);
void sse_rsqrt_ps(CpuState* s, V4& d, V4 b);
void sse_sqrt_ps(CpuState* s, V4& d, V4 b);
V4 sse_shufps(CpuState* s, V4 a, V4 b, u32 imm);
void sse_comiss(CpuState* s, V4 a, V4 b, int quiet);
V4 sse_cvtsi2ss(CpuState* s, V4 d, s32 v);
s32 sse_cvttss2si(CpuState* s, V4 a);
s32 sse_cvtss2si(CpuState* s, V4 a);
void sse_min_ps(CpuState* s, V4& d, V4 b);
void sse_max_ps(CpuState* s, V4& d, V4 b);
V4 sse_movq_load(CpuState* s, u32 addr);
void sse_movq_store(CpuState* s, u32 addr, V4 a);
V4 sse_cvttps2dq(CpuState* s, V4 a);
u32 sse_movmskps(CpuState* s, V4 a);
u32 sse_pextrw(CpuState* s, V4 a, u32 idx);
V4 sse_packssdw(CpuState* s, V4 a, V4 b);
V4 sse_pmaddwd(CpuState* s, V4 a, V4 b);
V4 sse_cmp_ps(CpuState* s, V4 a, V4 b, u32 pred);
V4 sse_unpcklps(CpuState* s, V4 a, V4 b);
V4 sse_unpckhps(CpuState* s, V4 a, V4 b);
V4 sse_pshufd(CpuState* s, V4 a, u32 imm);
V4 sse_movhlps(CpuState* s, V4 a, V4 b);
V4 sse_movlhps(CpuState* s, V4 a, V4 b);
V4 sse_movd_in(CpuState* s, u32 v);
u32 sse_movd_out(CpuState* s, V4 a);

// ---------------------------------------------------------------------------
// x87. An operand is either st(i) (`st` >= 0) or a memory location (`st` == -1).
// The lifter emits `sr::X87Op{i, 0u}` / `sr::X87Op{-1, addr}` directly.
// ---------------------------------------------------------------------------
struct X87Op {
  int st;
  u32 addr;
};

void x87_push(CpuState* s, double v);
void x87_push_const(CpuState* s, double v);
void x87_load(CpuState* s, X87Op op, int size);
void x87_store(CpuState* s, X87Op op, int size);
void x87_pop_store(CpuState* s, X87Op op, int size);
void x87_load_int(CpuState* s, X87Op op, int size);
void x87_pop_store_int(CpuState* s, X87Op op, int size);
void x87_add(CpuState* s, X87Op a, X87Op b);
void x87_sub(CpuState* s, X87Op a, X87Op b);
void x87_mul(CpuState* s, X87Op a, X87Op b);
void x87_div(CpuState* s, X87Op a, X87Op b);
void x87_addp(CpuState* s, X87Op a, X87Op b);
void x87_subp(CpuState* s, X87Op a, X87Op b);
void x87_subrp(CpuState* s, X87Op a, X87Op b);
void x87_mulp(CpuState* s, X87Op a, X87Op b);
void x87_divp(CpuState* s, X87Op a, X87Op b);
void x87_divrp(CpuState* s, X87Op a, X87Op b);
void x87_com(CpuState* s, X87Op a, X87Op b);
void x87_comp(CpuState* s, X87Op a, X87Op b);
void x87_ucom(CpuState* s, X87Op a, X87Op b);
void x87_ucomp(CpuState* s, X87Op a, X87Op b);
void x87_compp(CpuState* s, X87Op a, X87Op b);
void x87_ucompp(CpuState* s, X87Op a, X87Op b);
void x87_chs(CpuState* s);
void x87_abs(CpuState* s);
void x87_sqrt(CpuState* s);
void x87_fxch(CpuState* s, int n);
void x87_free(CpuState* s);
void x87_prem(CpuState* s, int round);
void x87_rndint(CpuState* s);
void x87_scale(CpuState* s);

// ---------------------------------------------------------------------------
// Deterministic platform shims
// ---------------------------------------------------------------------------
void guest_rdtsc(CpuState* s);
void guest_cpuid(CpuState* s);
void x87_subr(CpuState* s, X87Op a, X87Op b);
void x87_divr(CpuState* s, X87Op a, X87Op b);
void x87_compi(CpuState* s, X87Op a, X87Op b);
void x87_ucompi(CpuState* s, X87Op a, X87Op b);
void x87_save_state(CpuState* s, u32 addr);
void x87_restore_state(CpuState* s, u32 addr);
void atomic_xadd(CpuState* s, u32 addr, int size);
void atomic_cmpxchg(CpuState* s, u32 addr, int size);
void atomic_add(CpuState* s, u32 addr, int size, u32 v);
void atomic_or(CpuState* s, u32 addr, int size, u32 v);
void atomic_xor(CpuState* s, u32 addr, int size, u32 v);
void rotate_carry(CpuState* s, u32 count, int size, int left);
void enter_frame(CpuState* s, u32 size, u32 level);
void port_in(CpuState* s, u32 port);
void port_out(CpuState* s, u32 port);
void rep_cmpsb(CpuState* s);
void rep_cmpsd(CpuState* s);
void rep_scasb(CpuState* s);
void x87_sin(CpuState* s);
void x87_cos(CpuState* s);
void x87_sincos(CpuState* s);
void x87_tan(CpuState* s);
void x87_atan2(CpuState* s);
void x87_2xm1(CpuState* s);
void x87_yl2x(CpuState* s);
void x87_yl2xp1(CpuState* s);
void x87_fiadd(CpuState* s, u32 addr, int size);
void x87_fisub(CpuState* s, u32 addr, int size);
void x87_fimul(CpuState* s, u32 addr, int size);
void x87_fidiv(CpuState* s, u32 addr, int size);

// MMX / packed integer
V4 mmx_paddsw(CpuState* s, V4 a, V4 b);
V4 mmx_paddw(CpuState* s, V4 a, V4 b);
V4 mmx_paddd(CpuState* s, V4 a, V4 b);
V4 mmx_paddsb(CpuState* s, V4 a, V4 b);
V4 mmx_paddb(CpuState* s, V4 a, V4 b);
V4 mmx_psubsw(CpuState* s, V4 a, V4 b);
V4 mmx_psubw(CpuState* s, V4 a, V4 b);
V4 mmx_psubd(CpuState* s, V4 a, V4 b);
V4 mmx_pmullw(CpuState* s, V4 a, V4 b);
V4 mmx_pmulhw(CpuState* s, V4 a, V4 b);
V4 mmx_pmulhuw(CpuState* s, V4 a, V4 b);
V4 mmx_pmaddwd(CpuState* s, V4 a, V4 b);
V4 mmx_pand(CpuState* s, V4 a, V4 b);
V4 mmx_por(CpuState* s, V4 a, V4 b);
V4 mmx_pxor(CpuState* s, V4 a, V4 b);
V4 mmx_pandn(CpuState* s, V4 a, V4 b);
V4 mmx_packsswb(CpuState* s, V4 a, V4 b);
V4 mmx_packuswb(CpuState* s, V4 a, V4 b);
V4 mmx_punpcklbw(CpuState* s, V4 a, V4 b);
V4 mmx_punpcklwd(CpuState* s, V4 a, V4 b);
V4 mmx_punpckldq(CpuState* s, V4 a, V4 b);
V4 mmx_punpckhbw(CpuState* s, V4 a, V4 b);
V4 mmx_punpckhwd(CpuState* s, V4 a, V4 b);
V4 mmx_punpckhdq(CpuState* s, V4 a, V4 b);
V4 mmx_pcmpeqb(CpuState* s, V4 a, V4 b);
V4 mmx_pcmpeqw(CpuState* s, V4 a, V4 b);
V4 mmx_pcmpeqd(CpuState* s, V4 a, V4 b);
V4 mmx_pcmpgtw(CpuState* s, V4 a, V4 b);
V4 mmx_pcmpgtd(CpuState* s, V4 a, V4 b);
V4 mmx_psraw(CpuState* s, V4 a, u32 count);
V4 mmx_psrad(CpuState* s, V4 a, u32 count);
V4 mmx_psrlw(CpuState* s, V4 a, u32 count);
V4 mmx_psrld(CpuState* s, V4 a, u32 count);
V4 mmx_psrlq(CpuState* s, V4 a, u32 count);
V4 mmx_psllw(CpuState* s, V4 a, u32 count);
V4 mmx_pslld(CpuState* s, V4 a, u32 count);
V4 mmx_psllq(CpuState* s, V4 a, u32 count);
V4 sse_cvtpi2ps(CpuState* s, V4 d, V4 a);
V4 sse_cvtps2pi(CpuState* s, V4 a);
V4 sse_cvttps2pi(CpuState* s, V4 a);
void atomic_cmpxchg8b(CpuState* s, u32 addr);
void rep_scasd(CpuState* s);
void rep_stosw(CpuState* s);
void lodsb(CpuState* s);
void lodsw(CpuState* s);
void lodsd(CpuState* s);
void aam(CpuState* s, u32 base);
void aad(CpuState* s, u32 base);
void load_far_ptr(CpuState* s, u32 addr, int reg);
void far_call(CpuState* s, u32 addr);
void guest_interrupt(CpuState* s);
u32 bit_scan_forward(u32 v, int size);
u32 bit_scan_reverse(u32 v, int size);
V4 sse_movd_load(CpuState* s, u32 addr);
V4 sse_psrldq(CpuState* s, V4 a, u32 count);
V4 sse_pslldq(CpuState* s, V4 a, u32 count);
V4 mmx_pminub(CpuState* s, V4 a, V4 b);
V4 mmx_pmaxub(CpuState* s, V4 a, V4 b);
V4 mmx_pshufw(CpuState* s, V4 a, u32 imm);
V4 mmx_paddusb(CpuState* s, V4 a, V4 b);
V4 mmx_psubusb(CpuState* s, V4 a, V4 b);
void x87_fisubr(CpuState* s, u32 addr, int size);
void x87_fidivr(CpuState* s, u32 addr, int size);
void x87_fcmov(CpuState* s, X87Op op);
void x87_ficom(CpuState* s, u32 addr, int size);
void x87_ficomp(CpuState* s, u32 addr, int size);
void sse_rsqrt_ss(CpuState* s, V4& d, V4 b);
void sse_rcp_ss(CpuState* s, V4& d, V4 b);
V4 sse_punpcklqdq(CpuState* s, V4 a, V4 b);
V4 sse_punpckhqdq(CpuState* s, V4 a, V4 b);
s32 sse_cvttsd2si(CpuState* s, V4 a);
s32 sse_cvtsd2si(CpuState* s, V4 a);
inline void fence() { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
void debug_break(CpuState* s);
void unsupported(const char* what, u32 addr);

}  // namespace sr

