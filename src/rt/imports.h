// SporeRecomp — Win32 import dispatch.
//
// The guest is a Windows PE: every external call goes through an IAT slot. We give each
// import a unique *guest* address (a stub inside a reserved page) and fill the IAT with it,
// so `call dword ptr [IAT]` becomes an indirect call to that address. `guest_call_indirect`
// recognises the address and runs the host implementation instead.
//
// Arguments are read from the guest stack at ESP+4 (ESP points at the return address),
// which is exactly what the original code expects. stdcall imports pop their own arguments;
// cdecl ones leave that to the caller (the lifted code already handles its own ESP).
#pragma once

#include <cstdint>

#include "rt/cpu.h"

namespace sr::imports {

using u32 = uint32_t;
using s32 = int32_t;

// A host implementation. `args` points at the guest stack arguments (args[0] = first
// argument at ESP+4). The implementation writes its return value into s->r[0].
using HostFn = void (*)(CpuState* s, const u32* args);

struct Desc {
  const char* dll;
  const char* name;   // "" for ordinal imports
  uint16_t ordinal;
  uint8_t nargs;      // number of 32-bit arguments
  bool stdcall;       // true: the callee pops the arguments
  HostFn fn;          // nullptr while unimplemented
};

// Looks up a descriptor by (dll, name/ordinal).
const Desc* find(const char* dll, const char* name, uint16_t ordinal);

// The full table, terminated by an entry with dll == nullptr.
extern const Desc g_import_table[];

// Allocates a unique guest stub address for a descriptor and returns it.
u32 make_stub(const Desc* d);

// Resolves a guest stub address to its implementation. Returns nullptr if `addr` is not an
// import stub (the caller then treats it as a lifted guest function).
HostFn resolve_stub(u32 addr, const Desc** desc_out);

// Runs an import implementation against the current guest stack and applies the calling
// convention (return-address pop plus argument pop for stdcall).
void invoke(const Desc* d, CpuState* s);

// Diagnostics.
void note_missing(const Desc* d);
void report_missing();
unsigned missing_count();

}  // namespace sr::imports
