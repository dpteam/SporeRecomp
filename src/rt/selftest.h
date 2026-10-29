// SporeRecomp — deterministic single-function self test.
//
// Runs one lifted function with the same pseudo-random inputs the Python validator feeds to
// Unicorn, then prints the resulting state so the two can be compared. Keeping the input
// generator in one place (here) and mirroring it in tools/validate.py is what makes the
// comparison meaningful.
#pragma once

#include <cstdint>

#include "rt/pe.h"

namespace sr::selftest {

// Returns 0 when the function ran, non-zero on failure. Output goes to stdout in a stable
// key=value format that tools/validate.py parses.
int run(const PeImage* img, unsigned addr, unsigned seed);

}  // namespace sr::selftest
