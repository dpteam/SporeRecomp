// SporeRecomp — crash reporting.
//
// A segfault inside lifted code is the hardest failure to debug on a handheld: there is no
// debugger and no core file worth reading. So the runtime installs handlers that print the
// guest's own state — EIP, registers, and the guest call chain taken from the guest stack.
// That is usually enough to name the exact lifted function and the caller.
#include <csignal>
#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <execinfo.h>
#include <unistd.h>

#include "rt/crash.h"
#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/seh.h"
#include "rt/shim.h"
#include "rt/win32/msvcr90.h"

namespace sr::crash {

namespace {

void dump_guest_state();

// A handled guest access violation resumes here: the signal handler cannot return to the
// faulting instruction, so it jumps back to the guest entry point with the restored context.
sigjmp_buf g_resume;
volatile sig_atomic_t g_resume_ready = 0;

constexpr int kMaxFrames = 48;

void dump_guest_state() {
  CpuState* s = shim::current();
  char buf[2048];
  int n = 0;
  n += std::snprintf(buf + n, sizeof(buf) - size_t(n),
                     "\n=== guest state at crash ===\n"
                     "eip=0x%08x  eflags=0x%08x\n"
                     "eax=0x%08x ecx=0x%08x edx=0x%08x ebx=0x%08x\n"
                     "esp=0x%08x ebp=0x%08x esi=0x%08x edi=0x%08x\n"
                     "fs=0x%08x\n",
                     s->eip, get_flags(s), s->r[0], s->r[1], s->r[2], s->r[3], s->r[4],
                     s->r[5], s->r[6], s->r[7], s->fs_base);
  (void)write(2, buf, size_t(n));

  // The guest stack still holds the return addresses of every guest frame: walking it gives
  // the call chain even though the native frames are opaque.
  n = 0;
  n += std::snprintf(buf + n, sizeof(buf) - size_t(n), "guest stack (esp..+0x80):\n");
  (void)write(2, buf, size_t(n));
  for (u32 i = 0; i < 0x80; i += 4) {
    u32 v = 0;
    if (gmem().base()) v = load<u32>(s->r[4] + i);
    n = std::snprintf(buf, sizeof(buf), "  [esp+0x%02x] = 0x%08x\n", i, v);
    (void)write(2, buf, size_t(n));
  }

  // Which lifted function were we in?
  const FunctionRange* r = find_range(s->eip);
  if (r) {
    n = std::snprintf(buf, sizeof(buf),
                      "guest function containing eip: 0x%08x..0x%08x\n", r->start, r->end);
  } else {
    n = std::snprintf(buf, sizeof(buf), "eip is not inside any lifted function\n");
  }
  (void)write(2, buf, size_t(n));

  // The basic block that faulted. eip is written at every block start, so this is the block
  // containing the faulting instruction (not the function entry, which is what an earlier
  // version of this report printed and which sent debugging down the wrong path).
  n = std::snprintf(buf, sizeof(buf),
                    "faulting basic block starts at 0x%08x\n", s->eip);
  (void)write(2, buf, size_t(n));

  // If the crash happened inside the C++ initialiser walk, say which initialiser was running:
  // Spore has ~31,000 of them, so the index is the whole answer.
  if (w32::initterm_total()) {
    n = std::snprintf(buf, sizeof(buf),
                      "inside initterm: initialiser %u of %u, currently at 0x%08x\n",
                      w32::initterm_index(), w32::initterm_total(),
                      w32::initterm_current());
    (void)write(2, buf, size_t(n));
  }

  // Memory around the pointers involved. A crash inside a table walk is almost always about
  // *content*, not control flow, and the content is invisible from registers alone.
  if (gmem().base()) {
    const u32 probe[] = {s->r[3], s->r[5], s->r[2], s->r[6], s->r[7]};
    for (u32 base : probe) {
      if (base < 0x1000) continue;
      n = std::snprintf(buf, sizeof(buf), "memory at 0x%08x (ebx/ebp/edx/esi/edi):\n", base);
      (void)write(2, buf, size_t(n));
      for (u32 i = 0; i < 0x20; i += 16) {
        n = std::snprintf(buf, sizeof(buf), "  +0x%02x: %08x %08x %08x %08x\n", i,
                          load<u32>(base + i), load<u32>(base + i + 4),
                          load<u32>(base + i + 8), load<u32>(base + i + 12));
        (void)write(2, buf, size_t(n));
      }
    }
  }

  // Raw bytes at the faulting block, so the instruction stream can be decoded offline without
  // needing the guest image on the analysis machine.
  if (gmem().base()) {
    n = std::snprintf(buf, sizeof(buf), "  bytes at eip: ");
    (void)write(2, buf, size_t(n));
    char hex[4];
    for (int i = 0; i < 32; ++i) {
      std::snprintf(hex, sizeof(hex), "%02x", load<uint8_t>(s->eip + u32(i)));
      (void)write(2, hex, 2);
    }
    (void)write(2, "\n", 1);
  }
}


}  // namespace

void dump_current() { dump_guest_state(); }

namespace {

void dump_native_frames() {
  void* frames[kMaxFrames];
  int count = backtrace(frames, kMaxFrames);
  char buf[128];
  int n = std::snprintf(buf, sizeof(buf), "\n=== native frames ===\n");
  (void)write(2, buf, size_t(n));
  backtrace_symbols_fd(frames, count, 2);
}

void on_fatal(int sig, siginfo_t* info, void* ucontext) {
  const char* name = "unknown";
  switch (sig) {
    case SIGSEGV: name = "SIGSEGV"; break;
    case SIGBUS: name = "SIGBUS"; break;
    case SIGILL: name = "SIGILL"; break;
    case SIGFPE: name = "SIGFPE"; break;
    case SIGABRT: name = "SIGABRT"; break;
    default: break;
  }
  char buf[256];
  int n = std::snprintf(buf, sizeof(buf), "\n*** %s ***\n", name);
  (void)write(2, buf, size_t(n));

  // The faulting address is the single most useful piece of information: it says whether the
  // guest touched an unmapped page, a null pointer, or ran off the end of its stack.
  uintptr_t fault = reinterpret_cast<uintptr_t>(info ? info->si_addr : nullptr);
  uintptr_t base = reinterpret_cast<uintptr_t>(gmem().base());
  n = std::snprintf(buf, sizeof(buf), "fault address: 0x%08lx (guest 0x%08x%s)\n",
                    (unsigned long)fault,
                    fault >= base ? unsigned(fault - base) : 0u,
                    fault >= base && fault < base + 0x100000000ull ? "" : " OUTSIDE guest space");
  (void)write(2, buf, size_t(n));

  // A fault inside the guest window is a Windows access violation. Dispatch it through the
  // guest's own SEH chain first; only an unhandled violation is fatal.
  if (sig == SIGSEGV && fault >= base && fault < base + 0x100000000ull &&
      g_resume_ready && shim::current()) {
    CpuState* s = shim::current();
    seh::ExceptionRecord rec{};
    rec.code = 0xC0000005u;
    rec.address = s->eip;
    rec.num_params = 2;
    rec.params[0] = 0;  // read or write is not distinguished by the hardware fault address
    rec.params[1] = unsigned(fault - base);
    if (seh::dispatch(s, rec)) {
      // The handler restored the context: jump back to the entry point and continue.
      g_resume_ready = 0;
      siglongjmp(g_resume, 1);
    }
  }

  dump_guest_state();
  dump_native_frames();
  // Do not return: the state is inconsistent and continuing would produce a worse report.
  signal(sig, SIG_DFL);
  raise(sig);
}

}  // namespace

void install() {
  struct sigaction sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = on_fatal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
  sigaction(SIGSEGV, &sa, nullptr);
  sigaction(SIGBUS, &sa, nullptr);
  sigaction(SIGILL, &sa, nullptr);
  sigaction(SIGFPE, &sa, nullptr);
  sigaction(SIGABRT, &sa, nullptr);
}

bool arm_resume() {
  g_resume_ready = 1;
  return sigsetjmp(g_resume, 1) == 0;
}

}  // namespace sr::crash




