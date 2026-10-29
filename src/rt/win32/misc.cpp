// SporeRecomp — the small Win32 DLLs: winmm, psapi, version, ole32, shell32, advapi32,
// dbghelp, usp10, imm32, steam_api, and the CRT's exception machinery.
#include <ctime>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/win32/internal.h"
#include "rt/win32/win32.h"

#include <cmath>
#include <cstdlib>
#include <cstring>

namespace sr::w32 {

// wsprintfA/W live in user32 but share the CRT's formatter.
void wsprintfA_impl(CpuState* s, const u32* a);
void wsprintfW_impl(CpuState* s, const u32* a);

// ---------------------------------------------------------------------------
// WINMM
// ---------------------------------------------------------------------------
void timeBeginPeriod(CpuState* s, const u32*) { s->r[0] = 0; }
void timeEndPeriod(CpuState* s, const u32*) { s->r[0] = 0; }

void timeGetTime(CpuState* s, const u32*) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  s->r[0] = u32(u64(ts.tv_sec) * 1000ull + u64(ts.tv_nsec) / 1000000ull);
}

// ---------------------------------------------------------------------------
// PSAPI
// ---------------------------------------------------------------------------
void GetModuleInformation(CpuState* s, const u32* a) {
  // MODULEINFO: lpBaseOfDll, SizeOfImage, EntryPoint
  u32 out = a[2];
  if (out) {
    store<u32>(out + 0, kImageBase);
    store<u32>(out + 4, 0x01800000);
    store<u32>(out + 8, kImageBase + 0x00DE11E1u);
  }
  s->r[0] = 1;
}

// ---------------------------------------------------------------------------
// steam_api
// ---------------------------------------------------------------------------
void steam_init(CpuState* s, const u32*) {
  SR_LOG("SteamAPI_Init -> false (running without Steam)");
  s->r[0] = 0;
}
void steam_noop(CpuState* s, const u32*) { s->r[0] = 0; }
void steam_apps(CpuState* s, const u32*) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// VERSION
// ---------------------------------------------------------------------------
void version_size(CpuState* s, const u32*) { s->r[0] = 0; }
void version_noop(CpuState* s, const u32*) { s->r[0] = 0; }
void version_query(CpuState* s, const u32* a) {
  if (a[2]) store<u32>(a[2], 0);
  if (a[3]) store<u32>(a[3], 0);
  s->r[0] = 0;
}

// ---------------------------------------------------------------------------
// ole32 / SHELL32 / drag & drop: Spore uses these for file drag-drop only
// ---------------------------------------------------------------------------
void ole_init(CpuState* s, const u32*) { s->r[0] = 0; }
void ole_noop(CpuState* s, const u32*) { s->r[0] = 0; }

void sh_get_folder_path(CpuState* s, const u32* a) {
  std::string p = shim::config().game_dir;
  s->r[0] = write_wstr(a[4], p.c_str(), 260);
}

void shell_execute(CpuState* s, const u32*) { s->r[0] = 0; }
void drag_query_file(CpuState* s, const u32*) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// ADVAPI32: registry. Spore keeps its settings here, so a real key/value store matters.
// ---------------------------------------------------------------------------
namespace {
struct RegKey {
  std::string path;
  std::unordered_map<std::string, std::string> values;
};
std::unordered_map<u32, RegKey*> g_regkeys;
u32 g_next_regkey = 0x1000;

// A single in-memory registry seeded with what Spore expects to find on a fresh install.
RegKey g_root;
bool g_root_ready = false;

void seed_root() {
  if (g_root_ready) return;
  g_root_ready = true;
  g_root.path = "HKEY_CURRENT_USER\\Software\\Electronic Arts\\SPORE";
}

std::string reg_path(u32 hkey, const char* sub) {
  if (hkey == 0x80000001u) return std::string("HKEY_CURRENT_USER\\") + (sub ? sub : "");
  if (hkey == 0x80000002u) return std::string("HKEY_LOCAL_MACHINE\\") + (sub ? sub : "");
  auto it = g_regkeys.find(hkey);
  if (it != g_regkeys.end()) return it->second->path + "\\" + (sub ? sub : "");
  return sub ? sub : "";
}
}  // namespace

void advapi_get_user_name(CpuState* s, const u32* a) {
  write_cstr(a[0], "spore");
  if (a[1]) store<u32>(a[1], 5);
  s->r[0] = 1;
}

void advapi_get_user_name_w(CpuState* s, const u32* a) {
  write_wstr(a[0], "spore", 64);
  if (a[1]) store<u32>(a[1], 5);
  s->r[0] = 1;
}

void reg_open_key(CpuState* s, const u32* a) {
  seed_root();
  u32 hkey = a[0];
  std::string sub;
  if (hkey == 0x80000001u || hkey == 0x80000002u) sub = cstr(a[1]);
  else sub = wstr_utf8(a[1]);
  std::string full = reg_path(hkey, sub.c_str());
  for (auto& kv : g_regkeys) {
    if (kv.second->path == full) {
      if (a[4]) store<u32>(a[4], kv.first);
      s->r[0] = 0;
      return;
    }
  }
  auto* key = new RegKey();
  key->path = full;
  u32 h = g_next_regkey++;
  g_regkeys[h] = key;
  if (a[4]) store<u32>(a[4], h);
  s->r[0] = 0;
}

void reg_query_value(CpuState* s, const u32* a) {
  auto it = g_regkeys.find(a[0]);
  if (it == g_regkeys.end()) { s->r[0] = 2; return; }  // ERROR_FILE_NOT_FOUND
  std::string name;
  if (a[1]) name = (a[1] && load<u16>(a[1]) < 0x100) ? cstr(a[1]) : wstr_utf8(a[1]);
  auto vit = it->second->values.find(name);
  if (vit == it->second->values.end()) { s->r[0] = 2; return; }
  if (a[3]) {
    std::memcpy(gmem().base() + a[3], vit->second.data(), vit->second.size());
  }
  if (a[4]) store<u32>(a[4], u32(vit->second.size()));
  if (a[5]) store<u32>(a[5], 1);  // REG_SZ
  s->r[0] = 0;
}

void reg_set_value(CpuState* s, const u32* a) {
  auto it = g_regkeys.find(a[0]);
  if (it == g_regkeys.end()) { s->r[0] = 6; return; }
  std::string name = a[1] ? cstr(a[1]) : "";
  const char* data = reinterpret_cast<const char*>(gmem().base() + a[4]);
  it->second->values[name] = std::string(data, a[5]);
  s->r[0] = 0;
}

void reg_close_key(CpuState* s, const u32* a) {
  auto it = g_regkeys.find(a[0]);
  if (it != g_regkeys.end()) {
    delete it->second;
    g_regkeys.erase(it);
  }
  s->r[0] = 0;
}

void reg_enum_key(CpuState* s, const u32*) { s->r[0] = 259; }  // ERROR_NO_MORE_ITEMS
void reg_event_noop(CpuState* s, const u32*) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// dbghelp / usp10 / imm32: Spore's crash handler, text shaping and IME
// ---------------------------------------------------------------------------
void dbghelp_noop(CpuState* s, const u32*) { s->r[0] = 1; }
void usp_noop(CpuState* s, const u32*) { s->r[0] = 0; }
void imm_noop(CpuState* s, const u32*) { s->r[0] = 0; }
void imm_get_context(CpuState* s, const u32*) { s->r[0] = 0; }

void crt_noop(CpuState* s, const u32*) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// SEH / C++ exceptions
//
// The guest installs a frame at FS:[0] (a linked list of EXCEPTION_REGISTRATION records) and
// the CRT's _except_handler4_common walks it. We emulate the parts Spore actually uses:
// the /GS cookie check and the __try/__except filters that guard asset loading.
// ---------------------------------------------------------------------------
void seh_handler3(CpuState* s, const u32* a) {
  // _except_handler3(record, frame, context, dispatcher)
  SR_LOG("SEH: _except_handler3 reached (exception during guest execution)");
  s->r[0] = 1;  // ExceptionContinueSearch
}

void seh_handler4_common(CpuState* s, const u32* a) {
  SR_LOG("SEH: _except_handler4_common reached");
  s->r[0] = 1;
}

void seh_cxx_frame_handler3(CpuState* s, const u32* a) {
  SR_LOG("SEH: __CxxFrameHandler3 reached (a C++ exception was thrown)");
  s->r[0] = 1;
}

void seh_cxx_throw(CpuState* s, const u32* a) {
  SR_LOG("SEH: _CxxThrowException(0x%08x)", a[0]);
  s->r[0] = 0;
}

}  // namespace sr::w32

