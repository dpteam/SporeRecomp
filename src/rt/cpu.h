// SporeRecomp — guest CPU state and lazy x86 flags.
//
// The lifted code keeps the eight GPRs in locals inside each function and syncs them to
// this struct around guest calls, so this header defines the ABI between lifted functions
// and the runtime.
#pragma once

#include <cstdint>
#include <cstring>

namespace sr {

enum Reg32 : int { EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI };

// x86 flag bits inside EFLAGS
enum : uint32_t {
  kCF = 1u << 0,
  kPF = 1u << 2,
  kAF = 1u << 4,
  kZF = 1u << 6,
  kSF = 1u << 7,
  kTF = 1u << 8,
  kIF = 1u << 9,
  kDF = 1u << 10,
  kOF = 1u << 11,
};

// Arithmetic ops whose flags can be deferred. `kFlagOpNone` means `flags` is authoritative.
enum FlagOp : uint8_t {
  kFlagOpNone = 0,
  kFlagOpAdd,   // a + b
  kFlagOpSub,   // a - b
  kFlagOpCmp,   // a - b (result discarded, operands preserved)
  kFlagOpAdc,   // a + b + carry_in
  kFlagOpSbb,   // a - b - carry_in
  kFlagOpInc,   // a + 1
  kFlagOpDec,   // a - 1
  kFlagOpNeg,   // 0 - a
  kFlagOpLogic, // and/or/xor/test: CF=OF=0, AF undefined
  kFlagOpShift, // shifts: only CF/OF/ZF/SF/PF meaningful
  kFlagOpMul,   // CF=OF set from result
};

struct X87Reg {
  uint8_t bytes[10];  // 80-bit extended, little endian
};

// Portable 128-bit vector register (16 bytes, 16-byte aligned). On aarch64 the
// compiler lowers the float paths to NEON.
struct alignas(16) V4 {
  uint32_t u[4];
  float& f(int i) { return reinterpret_cast<float*>(u)[i]; }
  const float& f(int i) const { return reinterpret_cast<const float*>(u)[i]; }
};

struct CpuState {
  uint32_t r[8];        // EAX..EDI
  uint32_t eip;
  uint32_t flags;       // materialised EFLAGS (valid when flag_op == kFlagOpNone)
  uint32_t flags_mask;  // which bits of `flags` are currently valid

  // lazy flag state
  uint8_t flag_op;
  uint8_t flag_shift;
  uint8_t flag_carry_in;
  uint8_t pad_;
  uint32_t flag_a, flag_b, flag_res;

  // x87 (Spore uses fld/fmul/faddp heavily: 65k fld in the binary)
  X87Reg st[8];
  uint16_t fpu_ctrl;
  uint16_t fpu_status;
  uint16_t fpu_tag;
  uint16_t pad2_;
  uint32_t fpu_top;   // 0..7, rotates on push/pop

  // SSE
  V4 x0, x1, x2, x3, x4, x5, x6, x7;

  // segment bases (flat model, only FS is meaningful: it holds the TEB)
  uint32_t fs_base;
  uint32_t gs_base;

  uint32_t mxcsr;   // SSE control/status

  // Win32 TEB / thread bookkeeping
  uint32_t last_error;
  uint32_t teb;          // guest address of this thread's TEB
  uint32_t stack_base;
  uint32_t stack_limit;

  // exception bookkeeping (FS:[0] chain)
  uint32_t seh_frame;

  void* host_thread;     // back pointer to the runtime Thread object
};

// ---------------------------------------------------------------------------
// Lazy flag materialisation. Kept inline and branch-light: the hot path is "the
// instruction just set flag_op, and the next consumer asks for one or two bits".
// ---------------------------------------------------------------------------
inline uint32_t parity(uint32_t v) {
  v &= 0xFF;
  v ^= v >> 4;
  v ^= v >> 2;
  v ^= v >> 1;
  return (~v) & 1u ? kPF : 0u;
}

uint32_t materialise_flags(const CpuState* s);

// Returns the value of EFLAGS, computing any deferred bits.
inline uint32_t get_flags(const CpuState* s) {
  if (s->flag_op == kFlagOpNone) return s->flags;
  return materialise_flags(s);
}

// Forces the deferred state into `flags` so subsequent reads are cheap.
inline void sync_flags(CpuState* s) {
  if (s->flag_op != kFlagOpNone) {
    s->flags = materialise_flags(s);
    s->flag_op = kFlagOpNone;
    s->flags_mask = 0xFFFFFFFFu;
  }
}

inline void set_flags(CpuState* s, uint32_t v) {
  s->flags = v;
  s->flag_op = kFlagOpNone;
  s->flags_mask = 0xFFFFFFFFu;
}

inline bool flag_cf(const CpuState* s) { return (get_flags(s) & kCF) != 0; }
inline bool flag_zf(const CpuState* s) { return (get_flags(s) & kZF) != 0; }
inline bool flag_sf(const CpuState* s) { return (get_flags(s) & kSF) != 0; }
inline bool flag_of(const CpuState* s) { return (get_flags(s) & kOF) != 0; }
inline bool flag_pf(const CpuState* s) { return (get_flags(s) & kPF) != 0; }

// Condition-code evaluation used by Jcc/SETcc/CMOVcc.
bool eval_cc(const CpuState* s, int cc);

// ---------------------------------------------------------------------------
// Lazy-flag setters. `result` is stored so that ZF/SF/PF can be read without
// redoing the arithmetic.
// ---------------------------------------------------------------------------
inline void set_add_flags(CpuState* s, uint32_t a, uint32_t b, uint32_t res) {
  s->flag_op = kFlagOpAdd;
  s->flag_a = a; s->flag_b = b; s->flag_res = res;
}
inline void set_sub_flags(CpuState* s, uint32_t a, uint32_t b, uint32_t res) {
  s->flag_op = kFlagOpSub;
  s->flag_a = a; s->flag_b = b; s->flag_res = res;
}
inline void set_cmp_flags(CpuState* s, uint32_t a, uint32_t b) {
  s->flag_op = kFlagOpCmp;
  s->flag_a = a; s->flag_b = b; s->flag_res = a - b;
}
inline void set_logic_flags(CpuState* s, uint32_t res) {
  s->flag_op = kFlagOpLogic;
  s->flag_res = res;
  s->flag_a = s->flag_b = 0;
}

}  // namespace sr
