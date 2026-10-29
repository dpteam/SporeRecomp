// SporeRecomp — guest threads.
//
// Spore is heavily multi-threaded: streaming, audio, and the resource manager all run on
// worker threads created through CreateThread. Each guest thread needs:
//   * its own CpuState (registers, x87 stack, SSE bank, last-error, FS base)
//   * its own TEB and guest stack
//   * a native thread to run on
//
// The lifted code calls guest functions natively, so a guest thread is simply a native thread
// whose entry point is a lifted function. Nothing else is needed: the guest's own stack
// discipline is preserved, which is what makes SEH and __alloca work per thread.
#pragma once

#include <cstdint>

#include "rt/cpu.h"

namespace sr::threads {

using u32 = uint32_t;

// Default stack for a guest thread: 1 MB, matching what the CRT asks for.
constexpr u32 kThreadStackSize = 0x00100000;

struct GuestThread {
  u32 id;
  u32 handle;          // the guest-visible handle
  u32 entry;           // guest entry point
  u32 param;           // guest argument
  CpuState* state;
  u32 stack_top;
  u32 teb;
  void* native;        // pthread_t*
  volatile int finished;
  u32 exit_code;
};

// Creates and starts a guest thread. Returns the guest handle, or 0 on failure.
u32 create(u32 entry, u32 param, u32 stack_size, bool start_suspended);

// Waits for a thread to finish. Returns true if it finished within the timeout.
bool join(u32 handle, u32 timeout_ms);

// Waits for the calling thread's turn (used by WaitForSingleObject on a thread handle).
GuestThread* find(u32 handle);

// Starts a thread that was created suspended.
void resume(GuestThread* t);

// Terminates every thread and frees their guest stacks (called at shutdown).
void shutdown_all();

// Total guest threads ever created (for the log).
u32 created_count();

}  // namespace sr::threads
