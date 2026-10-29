// SporeRecomp — guest memory.
//
// The guest is a 32-bit Windows process: its whole address space is 4 GB. We reserve that
// much *virtual* space once (MAP_NORESERVE) and commit pages on demand, because the RG 35
// XX H has 1 GB of physical RAM and the game will happily reserve far more than that.
//
// Guest address -> host address is a fixed offset, so the lifted code and the shims can
// use raw pointers and a single base addition.
#pragma once

#include <cstddef>
#include <cstdint>

namespace sr {

constexpr uint64_t kGuestSpaceSize = 0x1'0000'0000ull;
constexpr uint32_t kImageBase = 0x00400000;

// Guest heap arena: 1.5 GB of *virtual* space. Nothing is committed until it is used, so the
// 1 GB of physical RAM on the device is not touched by the reservation itself.
constexpr uint32_t kHeapStart = 0x1000'0000;
constexpr uint32_t kHeapEnd = 0x7000'0000;

class GuestMemory {
 public:
  static GuestMemory& instance();

  bool init();
  uint8_t* base() const { return base_; }

  // Commits (zero-filled) pages covering [addr, addr+size).
  bool map(uint32_t addr, uint32_t size);

  // Releases pages but keeps the address space valid for a later map().
  void release(uint32_t addr, uint32_t size);

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
};

inline GuestMemory& gmem() { return GuestMemory::instance(); }

// Little-endian loads/stores used by lifted code. The guest is x86, the host is aarch64:
// both are little-endian, so a memcpy is the correct and fastest thing.
template <typename T>
inline T load(uint32_t addr) {
  T v;
  __builtin_memcpy(&v, gmem().base() + addr, sizeof(T));
  return v;
}
template <typename T>
inline void store(uint32_t addr, T v) {
  __builtin_memcpy(gmem().base() + addr, &v, sizeof(T));
}

}  // namespace sr
