// SporeRecomp — crash reporting.
#pragma once

namespace sr::crash {

// Installs handlers for the fatal signals. They print the guest state (EIP, registers, the
// guest call chain from the guest stack) and the native backtrace, then re-raise.
void install();

}  // namespace sr::crash
