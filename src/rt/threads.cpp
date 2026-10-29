// SporeRecomp — guest threads.
#include "rt/threads.h"

#include <pthread.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"

namespace sr::threads {

namespace {

std::unordered_map<u32, GuestThread*> g_threads;  // handle -> thread
u32 g_next_id = 2;
u32 g_created = 0;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// Guest layout for thread stacks: below the main thread's stack, growing down.
u32 g_next_stack = 0x7E000000;
constexpr u32 kStackRegion = 0x00400000;  // 4 MB of address space per thread slot

void install_teb(GuestThread* t) {
  auto& mem = gmem();
  u32 teb = t->teb;
  store<u32>(teb + 0x00, 0xFFFFFFFFu);  // NT_TIB.ExceptionList: empty chain
  store<u32>(teb + 0x04, t->stack_top);
  store<u32>(teb + 0x08, t->stack_top - kThreadStackSize);
  store<u32>(teb + 0x18, teb);         // Self
  store<u32>(teb + 0x20, 1);           // UniqueProcess
  store<u32>(teb + 0x24, t->id);       // UniqueThread
  // PEB pointer, shared with the main thread.
  store<u32>(teb + 0x30, 0x7FFD0000);
}

void* thread_main(void* arg) {
  auto* t = static_cast<GuestThread*>(arg);
  CpuState* s = t->state;
  install_teb(t);

  GuestFn fn = find_function(t->entry);
  if (!fn) {
    SR_LOG("thread %u: entry 0x%08x is not a lifted function", t->id, t->entry);
    t->finished = 1;
    return nullptr;
  }

  SR_LOG("thread %u: running entry 0x%08x (param 0x%08x)", t->id, t->entry, t->param);

  // stdcall entry: one argument on the stack, plus a sentinel return address.
  s->r[4] = t->stack_top - 0x40;
  store<u32>(s->r[4], 0xFFFFFFFFu);   // return address sentinel
  store<u32>(s->r[4] + 4, t->param);  // the thread's argument

  try {
    fn(s);
  } catch (...) {
    SR_LOG("thread %u: host exception escaped the guest", t->id);
  }
  t->finished = 1;
  SR_LOG("thread %u: exited", t->id);
  return nullptr;
}

}  // namespace

u32 create(u32 entry, u32 param, u32 stack_size, bool start_suspended) {
  if (stack_size < 0x10000) stack_size = kThreadStackSize;
  if (stack_size > kStackRegion) stack_size = kStackRegion;

  pthread_mutex_lock(&g_lock);
  u32 slot_top = g_next_stack;
  g_next_stack -= kStackRegion;
  pthread_mutex_unlock(&g_lock);

  if (g_next_stack < 0x71000000u) {
    SR_LOG("FATAL: out of guest thread stack space");
    return 0;
  }

  auto& mem = gmem();
  if (!mem.map(slot_top - kThreadStackSize, kThreadStackSize)) {
    SR_LOG("thread: cannot map guest stack at 0x%08x", slot_top - kThreadStackSize);
    return 0;
  }
  u32 teb = slot_top + 0x1000;
  if (!mem.map(teb, 0x1000)) {
    SR_LOG("thread: cannot map TEB");
    return 0;
  }

  auto* t = new GuestThread();
  t->id = g_next_id++;
  t->handle = 0x80000000u | t->id;
  t->entry = entry;
  t->param = param;
  t->stack_top = slot_top;
  t->teb = teb;
  t->finished = 0;
  t->exit_code = 0;

  auto* s = new CpuState();
  std::memset(s, 0, sizeof(CpuState));
  s->teb = teb;
  s->fs_base = teb;
  s->stack_base = slot_top;
  s->stack_limit = slot_top - kThreadStackSize;
  s->r[4] = slot_top - 0x40;
  s->fpu_ctrl = 0x027F;
  s->flags = kIF | 0x2;
  s->mxcsr = 0x1F80;
  t->state = s;

  pthread_mutex_lock(&g_lock);
  g_threads[t->handle] = t;
  ++g_created;
  pthread_mutex_unlock(&g_lock);

  if (start_suspended) {
    SR_LOG("thread %u: created suspended (entry 0x%08x)", t->id, entry);
    return t->handle;
  }

  pthread_t* tid = new pthread_t();
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 1u << 20);
  if (pthread_create(tid, &attr, thread_main, t) != 0) {
    pthread_attr_destroy(&attr);
    delete tid;
    SR_LOG("thread %u: pthread_create failed", t->id);
    return 0;
  }
  pthread_attr_destroy(&attr);
  t->native = tid;
  return t->handle;
}

GuestThread* find(u32 handle) {
  auto it = g_threads.find(handle);
  return it == g_threads.end() ? nullptr : it->second;
}

bool join(u32 handle, u32 timeout_ms) {
  GuestThread* t = find(handle);
  if (!t) return false;
  if (!t->native) {
    // Created suspended and never resumed: treat as finished for wait purposes.
    return true;
  }
  (void)timeout_ms;
  pthread_t* tid = static_cast<pthread_t*>(t->native);
  pthread_join(*tid, nullptr);
  return true;
}

void shutdown_all() {
  pthread_mutex_lock(&g_lock);
  for (auto& kv : g_threads) {
    GuestThread* t = kv.second;
    if (t->native && !t->finished) {
      pthread_t* tid = static_cast<pthread_t*>(t->native);
      pthread_join(*tid, nullptr);
    }
    delete static_cast<pthread_t*>(t->native);
    delete t->state;
    delete t;
  }
  g_threads.clear();
  pthread_mutex_unlock(&g_lock);
}

u32 created_count() { return g_created; }

void resume(GuestThread* t) {
  if (!t || t->native) return;
  pthread_t* tid = new pthread_t();
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 1u << 20);
  if (pthread_create(tid, &attr, thread_main, t) != 0) {
    pthread_attr_destroy(&attr);
    delete tid;
    SR_LOG("thread %u: pthread_create failed on resume", t->id);
    return;
  }
  pthread_attr_destroy(&attr);
  t->native = tid;
  SR_LOG("thread %u: resumed", t->id);
}

}  // namespace sr::threads
