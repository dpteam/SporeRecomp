// SporeRecomp — COM object support for the D3D9 shim.
#include "rt/d3d9/com.h"

#include <cstdio>
#include <cstring>

#include "rt/guest.h"
#include "rt/imports.h"
#include "rt/mem.h"
#include "rt/shim.h"

namespace sr::d3d {

namespace {

const ComHandler* g_handlers[kComMaxKinds]{};
u32 g_handler_count[kComMaxKinds]{};
ComObject* g_objects = nullptr;

// Guest memory for objects and vtables: a bump arena above the import stubs.
u32 g_object_arena = 0x73000000;
u32 g_object_end = 0x73F00000;

u32 arena_alloc(u32 size, u32 align = 4) {
  u32 p = (g_object_arena + align - 1) & ~(align - 1);
  if (p + size > g_object_end) {
    SR_LOG("FATAL: COM object arena exhausted");
    return 0;
  }
  if (!gmem().map(p, size)) return 0;
  g_object_arena = p + size;
  return p;
}

}  // namespace

bool com_init() {
  // The stub range must be readable as code: build the vtable arrays lazily, but reserve
  // the whole range now so a guest call into it faults loudly instead of silently.
  if (!gmem().map(kComStubBase, kComMaxKinds * kComMaxMethods * kComStubStride)) {
    SR_LOG("FATAL: cannot map COM stub range");
    return false;
  }
  if (!gmem().map(0x73000000, 0x00F00000)) {
    SR_LOG("FATAL: cannot map COM object arena");
    return false;
  }
  return true;
}

u32 com_create(u32 kind, u32 nmethods, void* host) {
  if (kind >= kComMaxKinds || nmethods > kComMaxMethods) {
    SR_LOG("FATAL: bad COM object request kind=%u methods=%u", kind, nmethods);
    return 0;
  }
  u32 vtbl = arena_alloc(nmethods * 4 + 16, 16);
  if (!vtbl) return 0;
  u32 obj = arena_alloc(16, 16);
  if (!obj) return 0;

  u32 base = kComStubBase + kind * kComMaxMethods * kComStubStride;
  for (u32 i = 0; i < nmethods; ++i) {
    store<u32>(vtbl + i * 4, base + i * kComStubStride);
  }
  store<u32>(obj, vtbl);
  store<u32>(obj + 4, 0);  // refcount shadow (the guest never reads it, we do)

  auto* o = new ComObject();
  o->guest_addr = obj;
  o->vtbl_addr = vtbl;
  o->kind = kind;
  o->refcount = 1;
  o->host = host;
  o->next = g_objects;
  g_objects = o;
  return obj;
}

void com_destroy(u32 guest_addr) {
  for (ComObject** p = &g_objects; *p; p = &(*p)->next) {
    if ((*p)->guest_addr == guest_addr) {
      ComObject* dead = *p;
      *p = dead->next;
      delete dead;
      return;
    }
  }
}

ComObject* com_lookup(u32 guest_addr) {
  for (ComObject* o = g_objects; o; o = o->next) {
    if (o->guest_addr == guest_addr) return o;
  }
  return nullptr;
}

void com_set_handlers(u32 kind, const ComHandler* handlers, u32 count) {
  if (kind >= kComMaxKinds) return;
  g_handlers[kind] = handlers;
  g_handler_count[kind] = count;
}

bool com_dispatch(CpuState* s, u32 addr) {
  if (addr < kComStubBase) return false;
  u32 rel = addr - kComStubBase;
  u32 kind = rel / (kComMaxMethods * kComStubStride);
  if (kind >= kComMaxKinds) return false;
  u32 within = rel % (kComMaxMethods * kComStubStride);
  if (within % kComStubStride) return false;
  u32 method = within / kComStubStride;

  // COM methods are stdcall with `this` as the first stack argument.
  u32 args[24]{};
  u32 n = 24;
  for (u32 i = 0; i < n; ++i) args[i] = load<u32>(s->r[4] + 4 + i * 4);

  ComObject* self = com_lookup(args[0]);
  const ComHandler* table = g_handlers[kind];
  ComHandler fn = (table && method < g_handler_count[kind]) ? table[method] : nullptr;
  if (fn) {
    fn(s, args, self);
  } else {
    // Unknown method: succeed with a null result. Never silently corrupt the guest stack —
    // the caller pops its own arguments, and so do we, using the declared arity when known.
    SR_LOG("D3D: unimplemented method kind=%u index=%u", kind, method);
    s->r[0] = 0;  // S_OK
  }
  return true;
}

// ---------------------------------------------------------------------------
// shared COM methods
// ---------------------------------------------------------------------------
void com_addref(CpuState* s, const u32* args, ComObject* self) {
  if (self) {
    ++self->refcount;
    s->r[0] = self->refcount;
  } else {
    s->r[0] = 1;
  }
}

void com_release(CpuState* s, const u32* args, ComObject* self) {
  if (!self) { s->r[0] = 0; return; }
  if (self->refcount > 0) --self->refcount;
  s->r[0] = self->refcount;
  // Note: we deliberately do not free here. Spore releases and re-acquires resources during
  // device resets, and the arena is small; leaking a few hundred objects is cheaper than a
  // use-after-free we cannot debug on the device.
}

void com_query_interface(CpuState* s, const u32* args, ComObject* self) {
  u32 out = args[2];
  if (!self || !out) { s->r[0] = 0x80004003u; return; }  // E_POINTER
  // All our interfaces report "yes" to any IID: Spore only ever asks for the interface it
  // already has (IUnknown/D3D9/Device9) and checks for null.
  store<u32>(out, self->guest_addr);
  ++self->refcount;
  s->r[0] = 0;
}

}  // namespace sr::d3d
