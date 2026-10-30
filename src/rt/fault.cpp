// SporeRecomp — guest access-violation handling.
//
// On Windows an access violation inside a __try block is *not* fatal: the SEH chain gets it and
// execution continues at the handler's continuation. Spore installs a CRT handler
// (_except_handler4 at FS:[0]) and relies on this, so a runtime that just dies on SIGSEGV
// cannot run the game.
//
// The fault happens deep inside lifted code, so it cannot be resumed in place. Instead the
// handler unwinds the native stack with an exception (the same technique longjmp uses) and the
// guest entry point continues at the address the SEH handler restored.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "rt/access.h"
#include "rt/crash.h"
#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/seh.h"
#include "rt/shim.h"

namespace sr {

namespace {
bool g_in_fault = false;
}

[[noreturn]] void guest_fault(uint32_t addr, uint32_t size, bool write) {
  if (g_in_fault) {
    std::fprintf(stderr, "\n[guest] nested fault at 0x%08x while handling a fault\n", addr);
    std::abort();
  }
  g_in_fault = true;

  CpuState* s = shim::current();
  if (!s) {
    std::fprintf(stderr, "\n[guest] fault at 0x%08x with no CPU state\n", addr);
    std::abort();
  }

  SR_LOG("guest access violation: %s at 0x%08x (eip 0x%08x)",
         write ? "write" : "read", addr, s->eip);

  // Dispatch through the guest's own SEH chain, exactly like Windows would.
  seh::ExceptionRecord rec{};
  rec.code = 0xC0000005u;  // EXCEPTION_ACCESS_VIOLATION
  rec.flags = 0;
  rec.address = s->eip;
  rec.num_params = 2;
  rec.params[0] = write ? 1u : 0u;
  rec.params[1] = addr;

  bool handled = seh::dispatch(s, rec);
  g_in_fault = false;

  if (handled) {
    // A handler restored the CPU context. Unwind to the guest entry point, which resumes at
    // s->eip — returning here would resume the faulting instruction and loop forever.
    throw seh::GuestResume{s->eip};
  }

  std::fprintf(stderr,
               "\n[guest] UNHANDLED access violation (%s) at 0x%08x, eip 0x%08x\n"
               "        the guest's SEH chain had no handler for it\n",
               write ? "write" : "read", addr, s->eip);
  crash::dump_current();
  std::abort();
}

}  // namespace sr
