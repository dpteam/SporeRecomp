// SporeRecomp — guest call trace.
#include "rt/trace.h"

#include <cstdio>
#include <unistd.h>

namespace sr::trace {

namespace {

constexpr int kSize = 256;  // power of two
uint32_t g_ring[kSize];
uint32_t g_pos = 0;
uint32_t g_count = 0;

}  // namespace

void enter(uint32_t addr) {
  g_ring[g_pos & (kSize - 1)] = addr;
  ++g_pos;
  if (g_count < kSize) ++g_count;
}

void reset() {
  g_pos = 0;
  g_count = 0;
}

void dump(int n) {
  if (n > int(g_count)) n = int(g_count);
  if (n <= 0) return;

  char buf[64];
  int len = std::snprintf(buf, sizeof(buf), "\n=== last %d guest functions entered ===\n", n);
  (void)write(2, buf, size_t(len));

  // Oldest first: the ring holds the most recent entries.
  for (int i = n; i > 0; --i) {
    uint32_t idx = (g_pos - uint32_t(i)) & (kSize - 1);
    len = std::snprintf(buf, sizeof(buf), "  0x%08x\n", g_ring[idx]);
    (void)write(2, buf, size_t(len));
  }
}

}  // namespace sr::trace
