// SporeRecomp — guest call trace.
//
// A crash report tells us where we died, but not how we got there. The lifted code runs on the
// native stack, so the guest call chain is not walkable. This keeps a small ring buffer of the
// last N function entries instead: one store per call, and any crash report can print the path.
#pragma once

#include <cstdint>

namespace sr::trace {

// Records that a lifted function is being entered. Cheap enough to leave on always.
void enter(uint32_t addr);

// Prints the last `n` entries to stderr, oldest first.
void dump(int n = 48);

// Clears the buffer (used by the self test).
void reset();

}  // namespace sr::trace
