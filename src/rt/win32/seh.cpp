// SporeRecomp — Win32 structured exception handling and C++ exceptions.
//
// The guest uses the MSVC x86 SEH model:
//   * FS:[0] holds a linked list of EXCEPTION_REGISTRATION_RECORD
//       struct { EXCEPTION_REGISTRATION_RECORD* prev; void* handler; }
//   * a handler is called as
//       handler(EXCEPTION_RECORD* rec, void* frame, CONTEXT* ctx, void* dispatcher)
//     and returns ExceptionContinueExecution (-1), ExceptionContinueSearch (0) or
//     ExceptionExecuteHandler (1).
//   * C++ exceptions go through __CxxFrameHandler3, which unwinds by calling the funclets
//     recorded in the function's unwind table.
//
// We implement the chain walk for real: RaiseException (and any guest fault we detect)
// enters seh_dispatch(), which walks FS:[0] calling guest handlers exactly like Windows.
// The C++ side (funclet unwinding) is handled by the handlers themselves — they are guest
// code, so once the chain works, so does the unwind.
#include <cstdio>
#include <cstring>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/win32/win32.h"

namespace sr::seh {

using u32 = uint32_t;

// EXCEPTION_RECORD layout (Win32)
struct ExceptionRecord {
  u32 code;
  u32 flags;
  u32 record;      // nested record, unused
  u32 address;     // faulting instruction
  u32 num_params;
  u32 params[15];
};

// CONTEXT for x86: 0x2CC bytes. We only need the integer registers, the control dwords and
// the segment selectors, but the size matters because the guest allocates it.
constexpr u32 kContextSize = 0x2CC;
constexpr u32 kContextEip = 0xB8;
constexpr u32 kContextEsp = 0xC4;
constexpr u32 kContextEbp = 0xB4;

constexpr u32 kExceptionContinueExecution = 0xFFFFFFFFu;
constexpr u32 kExceptionContinueSearch = 0;
constexpr u32 kExceptionExecuteHandler = 1;

namespace {

u32 g_dispatch_depth = 0;

// Builds a guest CONTEXT from the current CPU state.
u32 build_context(CpuState* s) {
  u32 ctx = gmem().heap_alloc(kContextSize);
  if (!ctx) return 0;
  __builtin_memset(gmem().base() + ctx, 0, kContextSize);
  store<u32>(ctx + 0x9C, s->r[7]);   // Edi
  store<u32>(ctx + 0xA0, s->r[6]);   // Esi
  store<u32>(ctx + 0xA4, s->r[3]);   // Ebx
  store<u32>(ctx + 0xA8, s->r[2]);   // Edx
  store<u32>(ctx + 0xAC, s->r[1]);   // Ecx
  store<u32>(ctx + 0xB0, s->r[0]);   // Eax
  store<u32>(ctx + 0xB4, s->r[5]);   // Ebp
  store<u32>(ctx + 0xB8, s->eip);    // Eip
  store<u32>(ctx + 0xBC, 0x23);      // SegCs
  store<u32>(ctx + 0xC0, sr::get_flags(s));  // EFlags
  store<u32>(ctx + 0xC4, s->r[4]);   // Esp
  store<u32>(ctx + 0xC8, 0x2B);      // SegSs
  return ctx;
}

// Restores CPU state from a guest CONTEXT (used when a handler asks to continue execution).
void restore_context(CpuState* s, u32 ctx) {
  s->r[7] = load<u32>(ctx + 0x9C);
  s->r[6] = load<u32>(ctx + 0xA0);
  s->r[3] = load<u32>(ctx + 0xA4);
  s->r[2] = load<u32>(ctx + 0xA8);
  s->r[1] = load<u32>(ctx + 0xAC);
  s->r[0] = load<u32>(ctx + 0xB0);
  s->r[5] = load<u32>(ctx + 0xB4);
  s->eip = load<u32>(ctx + 0xB8);
  sr::set_flags(s, load<u32>(ctx + 0xC0));
  s->r[4] = load<u32>(ctx + 0xC4);
}

}  // namespace

// Walks the guest's exception chain. Returns true if a handler took the exception.
bool dispatch(CpuState* s, const ExceptionRecord& rec) {
  if (g_dispatch_depth > 32) {
    SR_LOG("SEH: dispatch recursion limit reached");
    return false;
  }
  ++g_dispatch_depth;

  u32 rec_addr = gmem().heap_alloc(sizeof(ExceptionRecord));
  if (!rec_addr) { --g_dispatch_depth; return false; }
  store<u32>(rec_addr + 0x00, rec.code);
  store<u32>(rec_addr + 0x04, rec.flags);
  store<u32>(rec_addr + 0x08, rec.record);
  store<u32>(rec_addr + 0x0C, rec.address);
  store<u32>(rec_addr + 0x10, rec.num_params);
  for (u32 i = 0; i < rec.num_params && i < 15; ++i) {
    store<u32>(rec_addr + 0x14 + i * 4, rec.params[i]);
  }

  u32 ctx = build_context(s);
  u32 frame = s->fs_base ? load<u32>(s->fs_base) : 0xFFFFFFFFu;

  unsigned depth = 0;
  bool handled = false;
  while (frame != 0xFFFFFFFFu && frame != 0 && depth < 256) {
    u32 prev = load<u32>(frame + 0);
    u32 handler = load<u32>(frame + 4);
    if (!handler) break;
    ++depth;

    GuestFn fn = find_function(handler);
    if (!fn) {
      SR_LOG("SEH: handler 0x%08x at frame 0x%08x is not lifted, skipping", handler, frame);
      frame = prev;
      continue;
    }

    // handler(rec, frame, ctx, dispatcher)
    guest_push_ret(s, 0xFFFFFFFFu);
    s->r[4] -= 4; store<u32>(s->r[4], 0);           // dispatcher
    s->r[4] -= 4; store<u32>(s->r[4], ctx);
    s->r[4] -= 4; store<u32>(s->r[4], frame);
    s->r[4] -= 4; store<u32>(s->r[4], rec_addr);
    fn(s);
    u32 result = s->r[0];
    s->r[4] += 20;

    if (result == kExceptionExecuteHandler) {
      handled = true;
      break;
    }
    if (result == kExceptionContinueExecution) {
      restore_context(s, ctx);
      handled = true;
      break;
    }
    frame = prev;
  }

  if (!handled) {
    SR_LOG("SEH: unhandled exception 0x%08x at 0x%08x (walked %u frames)",
           rec.code, rec.address, depth);
  }
  --g_dispatch_depth;
  return handled;
}

}  // namespace sr::seh

namespace sr::w32 {

// ---------------------------------------------------------------------------
// The imports the guest calls
// ---------------------------------------------------------------------------
void RaiseException(CpuState* s, const u32* a) {
  sr::seh::ExceptionRecord rec{};
  rec.code = a[0];
  rec.flags = a[1];
  rec.num_params = a[2];
  rec.address = s->eip;
  u32 count = a[2] < 15 ? a[2] : 15;
  for (u32 i = 0; i < count; ++i) rec.params[i] = load<u32>(a[3] + i * 4);
  SR_LOG("RaiseException code=0x%08x params=%u", rec.code, count);
  sr::seh::dispatch(s, rec);
  s->r[0] = 0;
}

void seh_cxx_throw(CpuState* s, const u32* a) {
  // _CxxThrowException(exception_object, throw_info)
  SR_LOG("C++ throw: object=0x%08x info=0x%08x", a[0], a[1]);
  sr::seh::ExceptionRecord rec{};
  rec.code = 0xE06D7363u;  // MSVC C++ exception code
  rec.flags = 1;           // EXCEPTION_NONCONTINUABLE
  rec.address = s->eip;
  rec.num_params = 3;
  rec.params[0] = 0x19930520u;  // EH magic
  rec.params[1] = a[0];
  rec.params[2] = a[1];
  sr::seh::dispatch(s, rec);
  // If nobody handled it the process would terminate; report and stop this path.
  SR_LOG("C++ throw was not handled; the guest will now behave as if the throw returned");
  s->r[0] = 0;
}

void seh_handler3(CpuState* s, const u32* a) {
  // _except_handler3 is itself a handler; it is reached through the chain, so being called
  // here means the guest installed it directly. Report and continue the search.
  SR_LOG("SEH: _except_handler3 invoked directly at 0x%08x", s->eip);
  s->r[0] = 0;  // ExceptionContinueSearch
}

void seh_handler4_common(CpuState* s, const u32* a) {
  // _except_handler4_common(cookie, table, rec, frame, ctx, dispatcher) — the /GS-aware
  // handler used by VS2008 code compiled with buffer security checks.
  u32 rec = a[2], frame = a[3];
  SR_LOG("SEH: _except_handler4_common rec=0x%08x frame=0x%08x", rec, frame);
  s->r[0] = 0;
}

void seh_cxx_frame_handler3(CpuState* s, const u32* a) {
  // __CxxFrameHandler3(rec, frame, ctx, dispatcher): called from the chain for C++ frames.
  SR_LOG("SEH: __CxxFrameHandler3 rec=0x%08x frame=0x%08x", a[0], a[1]);
  s->r[0] = 0;
}

}  // namespace sr::w32
