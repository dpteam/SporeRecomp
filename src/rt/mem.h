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
  uint32_t heap_alloc(uint32_t size, uint32_t align = 16);
  void heap_free(uint32_t addr);
  uint32_t heap_realloc(uint32_t addr, uint32_t size);

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

  // bump allocator for the guest heap
  uint32_t heap_ptr_ = 0x2000'0000;  // start of the heap arena
  uint32_t heap_end_ = 0x3F00'0000;  // grows up towards the stack
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
