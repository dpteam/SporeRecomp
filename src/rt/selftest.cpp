// SporeRecomp — deterministic single-function self test.
#include "rt/selftest.h"

#include <cstdio>
#include <cstring>

#include "rt/guest.h"
#include "rt/mem.h"

namespace sr::selftest {

namespace {

// xorshift32: identical sequence to the Python harness (tools/validate.py).
struct Rng {
  uint32_t s;
  explicit Rng(uint32_t seed) : s(seed ? seed : 0x9E3779B9u) {}
  uint32_t next() {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
  }
  uint32_t below(uint32_t n) { return next() % n; }
};

constexpr uint32_t kStackTop = 0x7FFE0000;
constexpr uint32_t kStackSize = 0x00100000;
constexpr uint32_t kHeap = 0x20000000;
constexpr uint32_t kHeapSize = 0x00100000;
constexpr uint32_t kSentinel = 0xDEADBEEFu;

}  // namespace

int run(const PeImage* img, unsigned addr, unsigned seed) {
  auto& mem = gmem();
  if (!mem.map(kHeap, kHeapSize)) return 1;
  if (!mem.map(kStackTop - kStackSize, kStackSize)) return 1;

  Rng rng(seed);
  auto rnd = [&]() -> uint32_t {
    uint32_t r = rng.below(100);
    if (r < 35) return (kHeap + rng.below(kHeapSize - 0x100)) & ~3u;
    if (r < 50) {
      static const uint32_t specials[] = {0u, 1u, 2u, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u};
      return specials[rng.below(6)];
    }
    return rng.next();
  };

  CpuState* s = new CpuState();
  std::memset(s, 0, sizeof(CpuState));
  s->flags = 0x202;
  s->fpu_ctrl = 0x027F;
  s->fs_base = 0x7FFDF000;
  s->stack_base = kStackTop;
  s->stack_limit = kStackTop - kStackSize;
  for (int i = 0; i < 8; ++i) {
    if (i == 4) continue;  // ESP is set below
    s->r[i] = rnd();
  }
  uint32_t esp = kStackTop - 0x1000;
  s->r[4] = esp;
  store<uint32_t>(esp, kSentinel);
  for (int i = 0; i < 16; ++i) store<uint32_t>(esp + 4 + i * 4, rnd());
  for (uint32_t i = 0; i < 0x4000; ++i) gmem().base()[kHeap + i] = uint8_t(rng.next());

  GuestFn fn = find_function(addr);
  if (!fn) {
    std::printf("error=not-lifted\n");
    return 1;
  }
  s->eip = addr;
  fn(s);

  // The harness compares the state the guest would leave behind.
  std::printf("eax=%08x ecx=%08x edx=%08x ebx=%08x ebp=%08x esi=%08x edi=%08x esp=%08x\n",
              s->r[0], s->r[1], s->r[2], s->r[3], s->r[5], s->r[6], s->r[7], s->r[4]);
  std::printf("eflags=%08x\n", get_flags(s));
  // checksum of the heap so the whole touched region is covered without huge output
  uint32_t h = 2166136261u;
  for (uint32_t i = 0; i < 0x4000; ++i) {
    h ^= gmem().base()[kHeap + i];
    h *= 16777619u;
  }
  std::printf("heap_fnv1a=%08x\n", h);
  uint32_t sh = 2166136261u;
  for (uint32_t i = 0; i < 0x100; ++i) {
    sh ^= gmem().base()[esp + i];
    sh *= 16777619u;
  }
  std::printf("stack_fnv1a=%08x\n", sh);
  delete s;
  return 0;
}

}  // namespace sr::selftest
