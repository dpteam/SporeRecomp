// SporeRecomp — import dispatch core.
#include "rt/imports.h"

#include <cstdio>
#include <cstring>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"

namespace sr::imports {

namespace {

// Guest address range used for import stubs. It sits above the image and the heap arena,
// below the stack, and is never claimed by a lifted function.
constexpr u32 kStubBase = 0x71000000;
constexpr u32 kStubStride = 16;
constexpr u32 kStubMax = 4096;

u32 g_next_stub = 0;
const Desc* g_stub_owner[kStubMax]{};
unsigned g_missing = 0;

}  // namespace

const Desc* find(const char* dll, const char* name, uint16_t ordinal) {
  for (const Desc* d = g_import_table; d->dll; ++d) {
    if (std::strcmp(d->dll, dll) != 0) continue;
    if (!name || !*name) {
      if (d->ordinal == ordinal) return d;
    } else if (d->name && std::strcmp(d->name, name) == 0) {
      return d;
    }
  }
  return nullptr;
}

u32 make_stub(const Desc* d) {
  if (g_next_stub >= kStubMax) {
    SR_LOG("FATAL: import stub table exhausted");
    return 0;
  }
  u32 addr = kStubBase + g_next_stub * kStubStride;
  g_stub_owner[g_next_stub] = d;
  ++g_next_stub;
  return addr;
}

HostFn resolve_stub(u32 addr, const Desc** desc_out) {
  if (addr < kStubBase || addr >= kStubBase + kStubMax * kStubStride) return nullptr;
  if ((addr - kStubBase) % kStubStride) return nullptr;
  unsigned idx = (addr - kStubBase) / kStubStride;
  if (idx >= g_next_stub) return nullptr;
  const Desc* d = g_stub_owner[idx];
  if (desc_out) *desc_out = d;
  return d->fn;
}

void report_missing() {
  SR_LOG("imports: %u of %u declared functions are unimplemented", g_missing, g_next_stub);
}

unsigned missing_count() { return g_missing; }

void note_missing(const Desc* d) {
  ++g_missing;
  SR_LOG("MISSING IMPORT %s!%s (%u args, %s)", d->dll,
         d->name && *d->name ? d->name : "#ordinal",
         unsigned(d->nargs), d->stdcall ? "stdcall" : "cdecl");
}

// Called from the dispatch path: runs an import implementation with the guest stack as
// argument storage, then applies the calling convention.
void invoke(const Desc* d, CpuState* s) {
  if (!d->fn) {
    static unsigned logged = 0;
    if (logged < 200) {
      SR_LOG("unimplemented import called: %s!%s at guest 0x%08x", d->dll,
             d->name && *d->name ? d->name : "#ordinal", s->eip);
      ++logged;
    }
    s->r[0] = 0;
  } else {
    u32 args[16]{};
    u32 n = d->nargs > 16 ? 16 : d->nargs;
    for (u32 i = 0; i < n; ++i) args[i] = load<u32>(s->r[4] + 4 + i * 4);
    d->fn(s, args);
  }
  // ESP currently points at the return address. Popping it always happens; stdcall
  // additionally pops the arguments (that is the whole difference between the two).
  s->r[4] += 4;
  if (d->stdcall) s->r[4] += 4 * u32(d->nargs);
}

}  // namespace sr::imports
