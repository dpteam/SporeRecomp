// SporeRecomp — Win32 shim layer: registry, logging, process/thread setup.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "rt/cpu.h"
#include "rt/mem.h"
#include "rt/pe.h"

namespace sr::shim {

struct Config {
  std::string game_dir;
  std::string log_path;
  bool verbose = false;
  bool trace_imports = false;
};

void init(const Config& cfg);
void shutdown();
const Config& config();

// Resolves a Win32 import to a host function pointer. Returns nullptr when unimplemented
// (the loader logs it and the first call traps instead of silently corrupting state).
void* resolve_import(const char* dll, const char* name, uint16_t ordinal);

// Creates the TEB, the guest stack and the process heap, then prepares the first thread.
bool setup_process(PeImage* img);

// Runs the guest from its entry point until it returns.
void run_guest(const PeImage& img);

// Access to the current thread's CPU state (the shims run on the guest's thread).
CpuState* current();

// --- logging ---------------------------------------------------------------
void log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_verbose(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

#define SR_LOG(...) ::sr::shim::log(__VA_ARGS__)
#define SR_LOGV(...) ::sr::shim::log_verbose(__VA_ARGS__)

}  // namespace sr::shim
