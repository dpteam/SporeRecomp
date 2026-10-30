// SporeRecomp — crash reporting.
#pragma once

namespace sr::crash {

// Installs handlers for the fatal signals. They print the guest state (EIP, registers, the
// guest call chain from the guest stack) and the native backtrace, then re-raise.
void install();

// Prints the current guest state to stderr. Called by the crash handler and by the
// access-violation path in fault.cpp.
void dump_current();

// Arms the resume point used when a guest access violation is handled by the SEH chain.
// Returns true on the initial call and false after a longjmp back from the signal handler.
bool arm_resume();

}  // namespace sr::crash
