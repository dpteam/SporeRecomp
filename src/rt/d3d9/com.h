// SporeRecomp — COM object support for the D3D9 shim.
//
// The guest talks to Direct3D through COM vtables: `device->lpVtbl->DrawPrimitive(device, ...)`.
// On x86 that is `mov eax,[device]` / `mov eax,[eax]` / `call [eax + 4*n]` — an indirect call
// through a function pointer read from guest memory.
//
// We satisfy this by building a *guest-resident* vtable for every object: an array of u32
// stub addresses. Each stub address encodes (interface kind, method index); when the guest
// calls it, guest_call_indirect() recognises the range and dispatches to the host handler.
//
// This gives exact COM semantics (vtbl layout, this-pointer as first stack argument, refcounts)
// without generating one C++ function per method per object.
#pragma once

#include <cstdint>

#include "rt/cpu.h"

namespace sr::d3d {

using u32 = uint32_t;

// Stub address space for COM methods. Distinct from import stubs (0x71000000) and from any
// guest code, and inside the reserved guest window.
constexpr u32 kComStubBase = 0x72000000;
constexpr u32 kComStubStride = 8;
constexpr u32 kComMaxMethods = 512;   // per interface kind
constexpr u32 kComMaxKinds = 64;

// Interface kinds. Keep this list in sync with the vtable tables in d3d9.cpp.
enum ComKind : u32 {
  kKindNone = 0,
  kKindD3D9,
  kKindDevice9,
  kKindTexture9,
  kKindCubeTexture9,
  kKindVolumeTexture9,
  kKindSurface9,
  kKindVertexBuffer9,
  kKindIndexBuffer9,
  kKindVertexShader9,
  kKindPixelShader9,
  kKindStateBlock9,
  kKindQuery9,
  kKindSwapChain9,
  kKindD3DXBuffer,
  kKindD3DXEffect,
  kKindCount,
};

// A COM object living in guest memory: its vtbl pointer is at `guest_addr`.
struct ComObject {
  u32 guest_addr;   // where the guest sees the object (first dword = vtbl)
  u32 vtbl_addr;    // guest address of the vtable
  u32 kind;
  u32 refcount;
  void* host;       // host-side state (device resources, GL handles, ...)
  ComObject* next;
};

// Registers the stub ranges and returns true on success.
bool com_init();

// Allocates a guest object with a vtable of `nmethods` entries for `kind`.
// Returns the guest address (the `this` pointer the guest will use).
u32 com_create(u32 kind, u32 nmethods, void* host);

// Frees the guest memory of an object (host state is the caller's business).
void com_destroy(u32 guest_addr);

// Looks up an object by its guest `this` pointer.
ComObject* com_lookup(u32 guest_addr);

// True if `addr` is a COM method stub; dispatches it and returns true.
bool com_dispatch(CpuState* s, u32 addr);

// Registers the handler table for one interface kind. `handlers[i]` handles method i;
// null entries return D3D_OK (S_OK) with the return value set to 0.
using ComHandler = void (*)(CpuState* s, const u32* args, ComObject* self);
void com_set_handlers(u32 kind, const ComHandler* handlers, u32 count);

// Reads argument i (0 = `this`) from the current guest call frame.
inline u32 arg(const u32* args, int i) { return args[i]; }

// Standard COM refcount bookkeeping shared by all interfaces.
void com_addref(CpuState* s, const u32* args, ComObject* self);
void com_release(CpuState* s, const u32* args, ComObject* self);
void com_query_interface(CpuState* s, const u32* args, ComObject* self);

}  // namespace sr::d3d
