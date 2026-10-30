// SporeRecomp — guest memory.
//
// The guest is a 32-bit Windows process: its whole address space is 4 GB. We reserve that
// much *virtual* space once (MAP_NORESERVE) and commit pages on demand, because the RG 35
// XX H has 1 GB of physical RAM and the game will happily reserve far more than that.
//
// Guest address -> host address is a fixed offset, so the lifted code and the shims can
// use raw pointers and a single base addition.
//
// NOTE: the ~416 generated translation units include `rt/access.h`, not this header. Keep the
// two in sync only where it matters (`gmem()` and the base pointer); anything added here is
// free to change without triggering a full re-lift rebuild.
#pragma once

#include <cstddef>
#include <cstdint>

#include "rt/access.h"

namespace sr {

constexpr uint64_t kGuestSpaceSize = 0x1'0000'0000ull;
constexpr uint32_t kImageBase = 0x00400000;

// Guest heap arena: used by the CRT shim (malloc/free) and by the loader's own allocations.
// Spore manages its own memory on top of VirtualAlloc, so this arena must NOT overlap the
// range the game reserves for itself — the two allocators used to fight over the same pages,
// which corrupted a free list and crashed static initialisation.
//
// Layout:
//   0x0010_0000 .. 0x0F00_0000   CRT heap arena (this allocator)
//   0x1000_0000 .. 0x7000_0000   left to the guest's own VirtualAlloc calls
constexpr uint32_t kHeapStart = 0x0010'0000;
constexpr uint32_t kHeapEnd = 0x0F00'0000;

class GuestMemory {
 public:
  static GuestMemory& instance();

  bool init();
  uint8_t* base() const { return base_; }

  // Commits (zero-filled) pages covering [addr, addr+size).
  bool map(uint32_t addr, uint32_t size);

  // Releases pages but keeps the address space valid for a later map().
  void release(uint32_t addr, uint32_t size);

  // True if the page containing `addr` is committed. VirtualQuery and the guest's own
  // allocator depend on this being accurate.
  bool is_committed(uint32_t addr) const;

  // Marks a range executable (the image and JIT-ed thunks need it).
  bool make_executable(uint32_t addr, uint32_t size);

  // Growable heap on top of the same window. Returns 0 on failure.
  // A real allocator: size-class free lists over the arena, so repeated alloc/free cycles
  // (which Spore does constantly) reuse memory instead of growing the arena forever.
  uint32_t heap_alloc(uint32_t size, uint32_t align = 16);
  void heap_free(uint32_t addr);
  uint32_t heap_realloc(uint32_t addr, uint32_t size);
  // Bytes currently handed out to the guest (for the memory report).
  uint64_t heap_in_use() const { return heap_used_; }

  // Total committed bytes (for the memory report).
  uint64_t committed() const { return committed_; }

  // Byte-oriented view, for the C-string and file APIs.
  char* chars() const { return reinterpret_cast<char*>(base_); }
  char16_t* wchars() const { return reinterpret_cast<char16_t*>(base_); }

  // Diagnostics: dumps a range as hex+ascii (used by crash reports and the log).
  void hexdump(uint32_t addr, uint32_t len, char* out, size_t out_size) const;

 private:
  GuestMemory() = default;
  uint8_t* base_ = nullptr;
  uint64_t committed_ = 0;

  // Bump pointer for the arena and a set of size-class free lists.
  uint32_t heap_ptr_ = kHeapStart;
  uint64_t heap_used_ = 0;
  // One free list per 16-byte size class up to 64 KB; larger blocks are kept in a sorted
  // list so they can be split or coalesced.
  static constexpr uint32_t kClasses = 4096;              // 16 bytes .. 64 KB
  static constexpr uint32_t kClassShift = 4;              // size >> 4
  uint32_t free_lists_[kClasses]{};
  uint32_t big_free_head_ = 0;                            // linked list of large free blocks

  // One bit per 4 KB page: 4 GB / 4 KB / 8 = 128 KB of metadata. Cheap, and it is what makes
  // is_committed() exact.
  static constexpr uint32_t kPages = kGuestSpaceSize / 4096;
  static constexpr uint32_t kPageWords = kPages / 32;
  uint32_t committed_pages_[kPageWords]{};
};

// gmem(), load<> and store<> live in rt/access.h (included above) because the generated
// code depends on them and must not be rebuilt when the allocator changes.

}  // namespace sr
