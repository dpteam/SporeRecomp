// SporeRecomp — lazy flag materialisation and condition codes.
#include "cpu.h"

namespace sr {

uint32_t materialise_flags(const CpuState* s) {
  uint32_t out = s->flags;
  uint32_t a = s->flag_a, b = s->flag_b, r = s->flag_res;
  switch (s->flag_op) {
    case kFlagOpAdd:
    case kFlagOpAdc: {
      uint32_t carry = (s->flag_op == kFlagOpAdc) ? (s->flags & kCF) : 0u;
      uint64_t wide = (uint64_t)a + b + carry;
      out &= ~(kCF | kOF | kAF);
      if (wide >> 32) out |= kCF;
      if (~(a ^ b) & (a ^ (uint32_t)wide) & 0x80000000u) out |= kOF;
      if ((a ^ b ^ (uint32_t)wide) & 0x10u) out |= kAF;
      break;
    }
    case kFlagOpSub:
    case kFlagOpCmp:
    case kFlagOpSbb: {
      uint32_t borrow = (s->flag_op == kFlagOpSbb) ? (s->flags & kCF) : 0u;
      uint64_t wide = (uint64_t)a - b - borrow;
      out &= ~(kCF | kOF | kAF);
      if ((uint64_t)a < (uint64_t)b + borrow) out |= kCF;
      if ((a ^ b) & (a ^ (uint32_t)wide) & 0x80000000u) out |= kOF;
      if ((a ^ b ^ (uint32_t)wide) & 0x10u) out |= kAF;
      break;
    }
    case kFlagOpInc:
    case kFlagOpDec:
    case kFlagOpNeg:
    case kFlagOpMul:
    case kFlagOpShift:
    case kFlagOpLogic:
    case kFlagOpNone:
      break;
  }
  // ZF / SF / PF come straight from the stored result for every op.
  if (s->flag_op != kFlagOpNone) {
    out &= ~(kZF | kSF | kPF);
    if (r == 0) out |= kZF;
    if (r & 0x80000000u) out |= kSF;
    out |= parity(r);
  }
  return out;
}

bool eval_cc(const CpuState* s, int cc) {
  uint32_t f = get_flags(s);
  bool cf = (f & kCF) != 0, zf = (f & kZF) != 0, sf = (f & kSF) != 0, of = (f & kOF) != 0;
  bool pf = (f & kPF) != 0;
  switch (cc) {
    case 0x0: return of;                    // o
    case 0x1: return !of;                   // no
    case 0x2: return cf;                    // b/c/nae
    case 0x3: return !cf;                   // ae/nb/nc
    case 0x4: return zf;                    // e/z
    case 0x5: return !zf;                   // ne/nz
    case 0x6: return cf || zf;              // be/na
    case 0x7: return !cf && !zf;            // a/nbe
    case 0x8: return sf;                    // s
    case 0x9: return !sf;                   // ns
    case 0xA: return pf;                    // p/pe
    case 0xB: return !pf;                   // np/po
    case 0xC: return sf != of;              // l/nge
    case 0xD: return sf == of;              // ge/nl
    case 0xE: return zf || (sf != of);      // le/ng
    case 0xF: return !zf && (sf == of);     // g/nle
  }
  return false;
}

}  // namespace sr
