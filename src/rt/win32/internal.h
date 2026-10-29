// SporeRecomp — helpers shared between the Win32 shim translation units.
#pragma once

#include <cstdint>
#include <string>

#include "rt/cpu.h"
#include "rt/mem.h"

namespace sr::w32 {

struct Handle {
  enum Kind { kFree, kFile, kEvent, kMutex, kSemaphore, kThread, kProcess } kind = kFree;
  void* file = nullptr;      // FILE*
  std::string path;
  int signalled = 0;
  bool manual_reset = false;
  void* mutex = nullptr;     // pthread_mutex_t*
  void* cond = nullptr;      // pthread_cond_t*
  int count = 0;
  int max_count = 0;
  uint32_t guest_thread = 0;
};

// Handle table (small integer handles, Windows style: value / 4 is the index).
uint32_t new_handle(Handle::Kind kind);
Handle* handle_of(uint32_t h);

// Guest path ("C:\\foo\\bar", "foo/bar") -> host path under the game directory.
std::string to_host_path(const char* guest_path);

// Recursive critical section per guest address.
void critsec_lock(uint32_t addr);
void critsec_unlock(uint32_t addr);
bool critsec_trylock(uint32_t addr);
void critsec_destroy(uint32_t addr);

// Windows creation disposition -> stdio mode.
const char* file_mode(uint32_t access, uint32_t disposition);

}  // namespace sr::w32
