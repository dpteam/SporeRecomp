// SporeRecomp — guest memory access primitives.
//
// This header is included by the ~416 generated translation units, so it must stay tiny and
// stable: any change here forces a full re-lift rebuild (20+ minutes). Everything else about
// the allocator lives in mem.h, which the generated code does NOT include.
#pragma once

#include <cstdint>

namespace sr {

class GuestMemory;

// Defined in mem.cpp. Only the address of the window is needed to read guest memory.
GuestMemory& gmem();

// The base of the 4 GB guest window. Lifted code adds the guest address to this.
const uint8_t* guest_base();

// Fault handling. A guest access to an uncommitted page is a Windows access violation: the
// process must dispatch it through the SEH chain (Spore installs one and relies on it), not
// die. `guest_fault` is noreturn: it either resumes inside a handler or aborts with a report.
[[noreturn]] void guest_fault(uint32_t addr, uint32_t size, bool write);

// True when bounds checking is enabled (SR_CHECK_MEM=1). Off by default: the check costs a
// bitmap probe per access, and the fault path below is the correct behaviour either way.
bool check_mem();

// Little-endian loads/stores used by lifted code. The guest is x86 and every supported host is
// little-endian, so a memcpy is both correct and the fastest thing the compiler can emit.
template <typename T>
inline T load(uint32_t addr) {
  T v;
  __builtin_memcpy(&v, guest_base() + addr, sizeof(T));
  return v;
}

template <typename T>
inline void store(uint32_t addr, T v) {
  __builtin_memcpy(const_cast<uint8_t*>(guest_base()) + addr, &v, sizeof(T));
}

}  // namespace sr

