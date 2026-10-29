// SporeRecomp — guest memory implementation.
#include "rt/mem.h"

#include <sys/mman.h>

#include <cstdio>
#include <cstring>

namespace sr {

namespace {
constexpr size_t kPage = 4096;
constexpr size_t kPageMask = kPage - 1;
inline uint32_t page_down(uint32_t a) { return a & ~uint32_t(kPageMask); }
inline uint32_t page_up(uint32_t a) { return (a + uint32_t(kPageMask)) & ~uint32_t(kPageMask); }
}  // namespace

GuestMemory& GuestMemory::instance() {
  static GuestMemory m;
  return m;
}

bool GuestMemory::init() {
  if (base_) return true;
  void* p = mmap(nullptr, size_t(kGuestSpaceSize), PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (p == MAP_FAILED) {
    std::fprintf(stderr, "[mem] failed to reserve the 4 GB guest window\n");
    return false;
  }
  base_ = static_cast<uint8_t*>(p);
  std::fprintf(stderr, "[mem] guest window at %p\n", p);
  return true;
}

bool GuestMemory::map(uint32_t addr, uint32_t size) {
  if (!size) return true;
  uint32_t lo = page_down(addr);
  uint32_t hi = page_up(addr + size);
  if (hi <= lo) return false;
  if (mprotect(base_ + lo, size_t(hi - lo), PROT_READ | PROT_WRITE) != 0) {
    std::fprintf(stderr, "[mem] map 0x%08x+0x%x failed\n", lo, hi - lo);
    return false;
  }
  committed_ += hi - lo;
  return true;
}

void GuestMemory::release(uint32_t addr, uint32_t size) {
  uint32_t lo = page_down(addr);
  uint32_t hi = page_up(addr + size);
  if (hi <= lo) return;
  // Drop the physical pages, keep the address range reserved.
  madvise(base_ + lo, size_t(hi - lo), MADV_DONTNEED);
  mprotect(base_ + lo, size_t(hi - lo), PROT_NONE);
  committed_ -= hi - lo;
}

bool GuestMemory::make_executable(uint32_t addr, uint32_t size) {
  uint32_t lo = page_down(addr);
  uint32_t hi = page_up(addr + size);
  return mprotect(base_ + lo, size_t(hi - lo),
                  PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

uint32_t GuestMemory::heap_alloc(uint32_t size, uint32_t align) {
  if (align < 16) align = 16;
  uint32_t start = (heap_ptr_ + align - 1) & ~(align - 1);
  uint32_t end = start + size;
  if (end > heap_end_) {
    std::fprintf(stderr, "[mem] guest heap exhausted at 0x%08x\n", heap_ptr_);
    return 0;
  }
  if (!map(start, size)) return 0;
  heap_ptr_ = page_up(end);
  return start;
}

void GuestMemory::heap_free(uint32_t addr) { (void)addr; }

uint32_t GuestMemory::heap_realloc(uint32_t addr, uint32_t size) {
  (void)addr;
  return heap_alloc(size);
}

void GuestMemory::hexdump(uint32_t addr, uint32_t len, char* out, size_t out_size) const {
  size_t o = 0;
  for (uint32_t i = 0; i < len && o + 80 < out_size; i += 16) {
    o += std::snprintf(out + o, out_size - o, "%08x  ", addr + i);
    for (uint32_t j = 0; j < 16 && i + j < len; ++j) {
      o += std::snprintf(out + o, out_size - o, "%02x ", base_[addr + i + j]);
    }
    o += std::snprintf(out + o, out_size - o, " |");
    for (uint32_t j = 0; j < 16 && i + j < len; ++j) {
      unsigned char c = base_[addr + i + j];
      o += std::snprintf(out + o, out_size - o, "%c", (c >= 32 && c < 127) ? c : '.');
    }
    o += std::snprintf(out + o, out_size - o, "|\n");
  }
}

}  // namespace sr
