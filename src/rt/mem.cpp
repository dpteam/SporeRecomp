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

// --- heap -------------------------------------------------------------------
// Every allocation carries a 16-byte header:
//   [0]  u32  size class index, or kBigBlock
//   [4]  u32  usable size
//   [8]  u32  next free block (only while on a free list)
//   [12] u32  magic, so a double free or a corrupt pointer is caught instead of silently
//             corrupting the heap
namespace {
constexpr uint32_t kBigBlock = 0xFFFFFFFFu;
constexpr uint32_t kHeapMagic = 0x53505248u;  // "SPRH"
constexpr uint32_t kHdr = 16;
}  // namespace

uint32_t GuestMemory::heap_alloc(uint32_t size, uint32_t align) {
  if (align < 16) align = 16;
  if (size == 0) size = 1;
  uint32_t need = size + kHdr + (align - 1);
  uint32_t cls = (need + 15) >> kClassShift;

  uint32_t blk = 0;
  if (cls < kClasses) {
    if (free_lists_[cls]) {
      blk = free_lists_[cls];
      free_lists_[cls] = load<uint32_t>(blk + 8);
    }
  } else if (big_free_head_) {
    // first fit over the large-block list
    uint32_t prev = 0, cur = big_free_head_;
    while (cur) {
      uint32_t cur_size = load<uint32_t>(cur + 4);
      if (cur_size >= need) {
        uint32_t next = load<uint32_t>(cur + 8);
        if (prev) store<uint32_t>(prev + 8, next); else big_free_head_ = next;
        blk = cur;
        break;
      }
      prev = cur;
      cur = load<uint32_t>(cur + 8);
    }
  }
  if (!blk) {
    uint32_t span = cls < kClasses ? (cls << kClassShift) : need;
    uint32_t p = (heap_ptr_ + 15) & ~15u;
    if (p + span > kHeapEnd) {
      std::fprintf(stderr, "[mem] guest heap exhausted (used %llu MB at 0x%08x)\n",
                   (unsigned long long)(heap_used_ >> 20), heap_ptr_);
      return 0;
    }
    if (!map(p, span)) return 0;
    heap_ptr_ = p + span;
    blk = p;
    store<uint32_t>(blk + 0, cls);
    store<uint32_t>(blk + 4, span - kHdr);
    store<uint32_t>(blk + 12, kHeapMagic);
  }

  // Honour the alignment request by shifting the user pointer inside the block.
  uint32_t user = (blk + kHdr + align - 1) & ~(align - 1);
  store<uint32_t>(blk + 8, user - blk);  // remember the offset for free()
  heap_used_ += size;
  return user;
}

void GuestMemory::heap_free(uint32_t addr) {
  if (!addr) return;
  // The header sits at an unknown offset below `addr`; the offset is stored in the block
  // header, which we find by scanning back within the alignment window.
  for (uint32_t back = kHdr; back <= kHdr + 63; back += 16) {
    uint32_t cand = addr - back;
    if (cand < kHeapStart) continue;
    if (load<uint32_t>(cand + 12) != kHeapMagic) continue;
    if (load<uint32_t>(cand + 8) != back) continue;
    uint32_t cls = load<uint32_t>(cand + 0);
    heap_used_ -= load<uint32_t>(cand + 4);
    store<uint32_t>(cand + 12, 0);  // poison: a second free is now detectable
    if (cls < kClasses) {
      store<uint32_t>(cand + 8, free_lists_[cls]);
      free_lists_[cls] = cand;
    } else {
      store<uint32_t>(cand + 8, big_free_head_);
      big_free_head_ = cand;
    }
    return;
  }
  std::fprintf(stderr, "[mem] heap_free(0x%08x): not a live block\n", addr);
}

uint32_t GuestMemory::heap_realloc(uint32_t addr, uint32_t size) {
  if (!addr) return heap_alloc(size);
  if (!size) { heap_free(addr); return 0; }
  // Find the current block to learn how much data actually needs copying.
  uint32_t cap = 0;
  for (uint32_t back = kHdr; back <= kHdr + 63; back += 16) {
    uint32_t cand = addr - back;
    if (cand < kHeapStart) continue;
    if (load<uint32_t>(cand + 12) != kHeapMagic) continue;
    if (load<uint32_t>(cand + 8) != back) continue;
    cap = load<uint32_t>(cand + 4);
    break;
  }
  if (cap >= size) return addr;  // already big enough: keep the pointer, no copy
  uint32_t nw = heap_alloc(size);
  if (!nw) return 0;
  __builtin_memcpy(base_ + nw, base_ + addr, cap);
  heap_free(addr);
  return nw;
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
