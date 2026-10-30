// SporeRecomp — Win32 structured exception handling.
//
// The guest installs handlers on the FS:[0] chain and expects a fault to be dispatched through
// them. This is the interface the fault path (fault.cpp) and the shims use.
#pragma once

#include <cstdint>

#include "rt/cpu.h"

namespace sr::seh {

struct ExceptionRecord {
  uint32_t code;
  uint32_t flags;
  uint32_t record;
  uint32_t address;
  uint32_t num_params;
  uint32_t params[15];
};

// Walks the guest's exception chain, calling each handler. Returns true if a handler took the
// exception (and, for ExceptionContinueExecution, restored the CPU context).
bool dispatch(CpuState* s, const ExceptionRecord& rec);

// Thrown by the fault path when a handler asked to continue execution: unwinds the native
// stack back to the guest entry point, which resumes at the restored address.
struct GuestResume {
  uint32_t eip;
};

}  // namespace sr::seh
