// SporeRecomp — entry point.
//
// Boot ladder (each step is logged so a device log tells us exactly how far we got):
//   1. guest memory + PE mapping
//   2. import binding through the shim registry
//   3. TLS block + stack setup
//   4. jump to the guest entry point (CRT _WinMainCRTStartup)
#include <cstdio>
#include <cstring>
#include <string>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/pe.h"
#include "rt/d3d9/hlsl.h"
#include "rt/shim.h"
#include "rt/selftest.h"

namespace {

const char* kDefaultExe = "gamedata/SporeApp.exe";

void usage(const char* argv0) {
  std::fprintf(stderr,
               "SporeRecomp — Spore on aarch64 Linux\n"
               "usage: %s [options] [game-dir]\n"
               "  --exe PATH      guest executable (default: <game-dir>/SporeApp.exe)\n"
               "  --log PATH      write the log here (default: log.txt)\n"
               "  -v, --verbose   log every guest import call\n"
               "  --trace-imports log the first call of every import\n"
               "  --stop-at ADDR  stop when the guest reaches ADDR (hex)\n"
               "  --selftest ADDR --seed N   run one lifted function and dump state\n",
               argv0);
}

}  // namespace

int main(int argc, char** argv) {
  std::string game_dir = "gamedata";
  std::string exe;
  std::string log_path = "log.txt";
  bool verbose = false;
  bool trace_imports = false;
  bool selftest = false;
  unsigned selftest_addr = 0;
  unsigned selftest_seed = 1;
  bool hlsl_test = false;
  std::string hlsl_src, hlsl_entry;
  bool hlsl_pixel = false;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--exe" && i + 1 < argc) exe = argv[++i];
    else if (a == "--log" && i + 1 < argc) log_path = argv[++i];
    else if (a == "-v" || a == "--verbose") verbose = true;
    else if (a == "--trace-imports") trace_imports = true;
    else if (a == "--selftest" && i + 1 < argc) {
      selftest = true;
      selftest_addr = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 0));
    } else if (a == "--seed" && i + 1 < argc) {
      selftest_seed = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 0));
    } else if (a == "--hlsl-test" && i + 3 < argc) {
      // --hlsl-test <source> <entry> <is_pixel>
      hlsl_test = true;
      hlsl_src = argv[++i];
      hlsl_entry = argv[++i];
      hlsl_pixel = std::strtoul(argv[++i], nullptr, 0) != 0;
    } else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else if (!a.empty() && a[0] != '-') game_dir = a;
  }
  if (exe.empty()) exe = game_dir + "/SporeApp.exe";

  if (hlsl_test) {
    // Translator self test: print the generated GLSL, or the error, and exit.
    sr::hlsl::CompileResult r = sr::hlsl::translate(hlsl_src.c_str(), hlsl_entry.c_str(),
                                                    hlsl_pixel);
    if (!r.ok) {
      std::fprintf(stderr, "line %d: %s\n", r.line, r.error.c_str());
      return 1;
    }
    std::fputs(r.glsl.c_str(), stdout);
    return 0;
  }

  sr::shim::Config cfg;
  cfg.game_dir = game_dir;
  cfg.log_path = log_path;
  cfg.verbose = verbose;
  cfg.trace_imports = trace_imports;
  sr::shim::init(cfg);

  SR_LOG("SporeRecomp starting");
  SR_LOG("game dir: %s", game_dir.c_str());
  SR_LOG("guest exe: %s", exe.c_str());

  if (!sr::gmem().init()) {
    SR_LOG("FATAL: cannot reserve guest memory");
    return 1;
  }

  sr::PeImage img;
  std::string err;
  if (!sr::pe_parse(exe.c_str(), img, err)) {
    SR_LOG("FATAL: %s", err.c_str());
    return 1;
  }
  SR_LOG("PE parsed: %zu sections, %zu imports, %zu relocations", img.sections.size(),
         img.imports.size(), img.relocs.size());

  if (!sr::pe_load(img, sr::shim::resolve_import, err)) {
    SR_LOG("FATAL: %s", err.c_str());
    return 1;
  }

  if (selftest) {
    return sr::selftest::run(&img, selftest_addr, selftest_seed);
  }

  if (!sr::shim::setup_process(&img)) {
    SR_LOG("FATAL: process setup failed");
    return 1;
  }

  SR_LOG("entering guest at 0x%08x", img.base + img.entry_point);
  sr::shim::run_guest(img);

  SR_LOG("guest returned");
  sr::shim::shutdown();
  return 0;
}

