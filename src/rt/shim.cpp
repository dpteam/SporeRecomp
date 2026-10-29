// SporeRecomp — shim core: logging, process/thread setup, import registry.
#include "rt/shim.h"

#include <cstdarg>
#include <cstring>

#include "rt/guest.h"
#include "rt/imports.h"
#include "rt/d3d9/d3d9.h"
#include "rt/threads.h"
#include "rt/win32/msvcr90.h"

#include <exception>

namespace sr::shim {

namespace {
Config g_cfg;
FILE* g_log = nullptr;
CpuState* g_cpu = nullptr;

// Guest layout (mirrors a 32-bit Windows process):
//   0x00400000  image
//   0x20000000  guest heap arena (grows up)
//   0x71000000  import stubs
//   0x72000000  COM method stubs
//   0x73000000  COM objects and vtables
//   0x7FEC0000  default thread stack (1 MB, grows down from 0x7FFC0000)
//   0x7FFD0000  PEB
//   0x7FFDF000  TEB   <- below the stack, so the stack can never overwrite it
constexpr uint32_t kStackTop = 0x7FFC0000;
constexpr uint32_t kStackSize = 0x00100000;
constexpr uint32_t kTebBase = 0x7FFDF000;
constexpr uint32_t kPebBase = 0x7FFD0000;
}  // namespace

const Config& config() { return g_cfg; }
CpuState* current() { return g_cpu; }

void* resolve_import(const char* dll, const char* name, uint16_t ordinal) {
  // The PE loader asks for a host pointer; the actual dispatch goes through the guest stub
  // table in imports.cpp. Returning the implementation pointer here is enough for the loader's
  // bookkeeping (it stores the stub address in the IAT, not this pointer).
  const imports::Desc* d = imports::find(dll, name, ordinal);
  if (!d || !d->fn) return nullptr;
  return reinterpret_cast<void*>(d->fn);
}

void init(const Config& cfg) {
  g_cfg = cfg;
  g_log = std::fopen(cfg.log_path.c_str(), "w");
  if (!g_log) g_log = stderr;
}

void shutdown() {
  d3d::shutdown();
  threads::shutdown_all();
  if (g_log && g_log != stderr) {
    std::fclose(g_log);
    g_log = nullptr;
  }
}

void log(const char* fmt, ...) {
  if (!g_log) g_log = stderr;
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(g_log, fmt, ap);
  va_end(ap);
  std::fputc('\n', g_log);
  std::fflush(g_log);
}

void log_verbose(const char* fmt, ...) {
  if (!g_cfg.verbose) return;
  if (!g_log) g_log = stderr;
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(g_log, fmt, ap);
  va_end(ap);
  std::fputc('\n', g_log);
}

bool setup_process(PeImage* img) {
  auto& mem = gmem();

  if (!d3d::init()) {
    SR_LOG("WARNING: D3D shim init failed; the guest will not get a device");
  }

  // Thread stack: reserve and commit the whole thing (1 MB is cheap and Spore's CRT probes
  // guard pages during _resetstkoflw).
  if (!mem.map(kStackTop - kStackSize, kStackSize)) {
    SR_LOG("cannot map guest stack");
    return false;
  }
  // TEB: 4 KB is enough for the fields Spore touches (SEH chain, TLS array, stack bounds).
  if (!mem.map(kTebBase, 0x1000)) {
    SR_LOG("cannot map TEB");
    return false;
  }

  g_cpu = new CpuState();
  std::memset(g_cpu, 0, sizeof(CpuState));
  g_cpu->teb = kTebBase;
  g_cpu->fs_base = kTebBase;
  g_cpu->stack_base = kStackTop;
  g_cpu->stack_limit = kStackTop - kStackSize;
  g_cpu->r[4] = kStackTop - 0x100;  // ESP
  g_cpu->fpu_ctrl = 0x027F;          // default x87 control word
  g_cpu->flags = kIF | 0x2;          // interrupts enabled, bit 1 always set

  // TEB fields the CRT reads: NT_TIB.ExceptionList at +0, StackBase at +4, StackLimit at +8.
  store<uint32_t>(kTebBase + 0x00, 0xFFFFFFFFu);  // exception list: end of chain
  store<uint32_t>(kTebBase + 0x04, kStackTop);
  store<uint32_t>(kTebBase + 0x08, kStackTop - kStackSize);
  store<uint32_t>(kTebBase + 0x18, kTebBase);     // Self
  store<uint32_t>(kTebBase + 0x20, 1);            // ClientId.UniqueProcess
  store<uint32_t>(kTebBase + 0x24, 1);            // ClientId.UniqueThread

  // The CRT also wants the PEB pointer in the TEB at +0x30.
  if (!mem.map(kPebBase, 0x1000)) {
    SR_LOG("cannot map PEB");
    return false;
  }
  store<uint32_t>(kTebBase + 0x30, kPebBase);
  store<uint32_t>(kPebBase + 0x08, kTebBase);  // PEB.ImageBaseAddress is at +0x08

  SR_LOG("thread: stack 0x%08x..0x%08x, TEB 0x%08x, PEB 0x%08x", kStackTop - kStackSize,
         kStackTop, kTebBase, kPebBase);
  return true;
}

void run_guest(const PeImage& img) {
  GuestFn entry = find_function(img.base + img.entry_point);
  if (!entry) {
    // The entry point is not lifted (yet). Report precisely so the lifter can be extended.
    SR_LOG("FATAL: entry point 0x%08x is not in the lifted function table",
           img.base + img.entry_point);
    return;
  }
  try {
    entry(g_cpu);
  } catch (const w32::Longjmp& lj) {
    SR_LOG("guest stack unwound by longjmp to 0x%08x (value %u)", lj.target, lj.value);
  } catch (const std::exception& e) {
    SR_LOG("FATAL: host exception escaped the guest: %s", e.what());
  }
}

}  // namespace sr::shim


