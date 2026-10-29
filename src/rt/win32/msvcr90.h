// SporeRecomp — control-flow exceptions raised by the CRT shims.
#pragma once

#include <cstdint>

namespace sr::w32 {

// Thrown by longjmp(): the only way to abandon the native frames between the longjmp and the
// setjmp that created the jump buffer. Caught at the guest entry point.
struct Longjmp {
  uint32_t target;
  uint32_t value;
};

}  // namespace sr::w32
