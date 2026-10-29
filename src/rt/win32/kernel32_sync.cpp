// SporeRecomp — kernel32: synchronisation, threads, TLS, files.
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/threads.h"
#include "rt/win32/internal.h"
#include "rt/win32/win32.h"

namespace sr::w32 {

namespace {

Handle g_handles[512];
uint32_t g_next_handle = 4;

struct CritSec {
  pthread_mutex_t m;
};
std::unordered_map<uint32_t, CritSec*> g_critsecs;

constexpr uint32_t kMaxTls = 64;
thread_local uint32_t g_tls_values[kMaxTls];

}  // namespace

uint32_t new_handle(Handle::Kind kind) {
  for (uint32_t i = g_next_handle; i < 512; ++i) {
    if (g_handles[i].kind == Handle::kFree) {
      g_handles[i] = Handle();
      g_handles[i].kind = kind;
      g_next_handle = i + 1;
      return i * 4;
    }
  }
  return 0;
}

Handle* handle_of(uint32_t h) {
  uint32_t idx = h / 4;
  if (idx < 512 && g_handles[idx].kind != Handle::kFree) return &g_handles[idx];
  return nullptr;
}

std::string to_host_path(const char* guest_path) {
  std::string p = guest_path ? guest_path : "";
  for (char& c : p) if (c == '\\') c = '/';
  if (p.size() >= 2 && p[1] == ':') p = p.substr(2);
  while (!p.empty() && p[0] == '/') p = p.substr(1);
  const std::string& dir = shim::config().game_dir;
  if (p.empty()) return dir;
  return dir + "/" + p;
}

const char* file_mode(uint32_t access, uint32_t disposition) {
  bool want_read = (access & 0x80000000u) != 0;
  bool want_write = (access & 0x40000000u) != 0;
  switch (disposition) {
    case 1: return "wb";                                  // CREATE_NEW
    case 2: return "wb";                                  // CREATE_ALWAYS
    case 3: return want_read && want_write ? "r+b" : "rb"; // OPEN_EXISTING
    case 4: return "r+b";                                 // OPEN_ALWAYS
    case 5: return want_write ? "r+b" : "rb";             // TRUNCATE_EXISTING
    default: return "rb";
  }
}

namespace {
CritSec* critsec(uint32_t addr) {
  auto it = g_critsecs.find(addr);
  if (it != g_critsecs.end()) return it->second;
  auto* cs = new CritSec();
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&cs->m, &attr);
  pthread_mutexattr_destroy(&attr);
  g_critsecs[addr] = cs;
  return cs;
}
}  // namespace

void critsec_lock(uint32_t addr) { pthread_mutex_lock(&critsec(addr)->m); }
void critsec_unlock(uint32_t addr) { pthread_mutex_unlock(&critsec(addr)->m); }
bool critsec_trylock(uint32_t addr) { return pthread_mutex_trylock(&critsec(addr)->m) == 0; }
void critsec_destroy(uint32_t addr) {
  auto it = g_critsecs.find(addr);
  if (it != g_critsecs.end()) {
    pthread_mutex_destroy(&it->second->m);
    delete it->second;
    g_critsecs.erase(it);
  }
}

// ---------------------------------------------------------------------------
// critical sections
// ---------------------------------------------------------------------------
void InitializeCriticalSection(CpuState* s, const u32* a) {
  critsec(a[0]);
  s->r[0] = 0;
}

void InitializeCriticalSectionAndSpinCount(CpuState* s, const u32* a) {
  critsec(a[0]);
  s->r[0] = 1;
}

void DeleteCriticalSection(CpuState* s, const u32* a) {
  critsec_destroy(a[0]);
  s->r[0] = 0;
}

void EnterCriticalSection(CpuState* s, const u32* a) {
  critsec_lock(a[0]);
  s->r[0] = 0;
}

void LeaveCriticalSection(CpuState* s, const u32* a) {
  critsec_unlock(a[0]);
  s->r[0] = 0;
}

void TryEnterCriticalSection(CpuState* s, const u32* a) {
  s->r[0] = critsec_trylock(a[0]) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// interlocked
// ---------------------------------------------------------------------------
void InterlockedIncrement(CpuState* s, const u32* a) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + a[0]);
  s->r[0] = __atomic_add_fetch(p, 1u, __ATOMIC_SEQ_CST);
}

void InterlockedDecrement(CpuState* s, const u32* a) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + a[0]);
  s->r[0] = __atomic_sub_fetch(p, 1u, __ATOMIC_SEQ_CST);
}

void InterlockedExchange(CpuState* s, const u32* a) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + a[0]);
  s->r[0] = __atomic_exchange_n(p, a[1], __ATOMIC_SEQ_CST);
}

void InterlockedExchangeAdd(CpuState* s, const u32* a) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + a[0]);
  s->r[0] = __atomic_fetch_add(p, a[1], __ATOMIC_SEQ_CST);
}

void InterlockedCompareExchange(CpuState* s, const u32* a) {
  u32* p = reinterpret_cast<u32*>(gmem().base() + a[0]);
  u32 expected = a[2];
  __atomic_compare_exchange_n(p, &expected, a[1], false, __ATOMIC_SEQ_CST,
                              __ATOMIC_SEQ_CST);
  s->r[0] = expected;
}

// ---------------------------------------------------------------------------
// events / mutexes / semaphores / waits
// ---------------------------------------------------------------------------
void CreateEventA(CpuState* s, const u32* a) {
  u32 h = new_handle(Handle::kEvent);
  Handle* o = handle_of(h);
  if (o) {
    o->manual_reset = a[2] != 0;
    o->signalled = a[3] != 0 ? 1 : 0;
  }
  s->r[0] = h;
}

void SetEvent(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (o) o->signalled = 1;
  s->r[0] = 1;
}

void CreateMutexA(CpuState* s, const u32* a) {
  u32 h = new_handle(Handle::kMutex);
  Handle* o = handle_of(h);
  if (o) o->signalled = a[2] ? 0 : 1;
  s->r[0] = h;
}

void ReleaseMutex(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (o) o->signalled = 1;
  s->r[0] = 1;
}

void CreateSemaphoreA(CpuState* s, const u32* a) {
  u32 h = new_handle(Handle::kSemaphore);
  Handle* o = handle_of(h);
  if (o) { o->count = int(a[1]); o->max_count = int(a[2]); }
  s->r[0] = h;
}

void ReleaseSemaphore(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (o) {
    if (a[2]) store<u32>(a[2], u32(o->count));
    o->count += int(a[1]);
  }
  s->r[0] = 1;
}

void WaitForSingleObject(CpuState* s, const u32* a) {
  // A thread handle waits for the guest thread to finish.
  if (a[0] & 0x80000000u) {
    s->r[0] = threads::join(a[0], a[1]) ? 0 : 0x102;
    return;
  }
  Handle* o = handle_of(a[0]);
  if (!o) { s->r[0] = 0; return; }
  if (o->kind == Handle::kSemaphore) {
    if (o->count > 0) { --o->count; s->r[0] = 0; return; }
    s->r[0] = 0x102;  // WAIT_TIMEOUT
    return;
  }
  if (o->signalled) {
    if (!o->manual_reset) o->signalled = 0;
    s->r[0] = 0;  // WAIT_OBJECT_0
    return;
  }
  // Not signalled: the single-threaded runtime cannot block, so report a timeout and let the
  // guest loop. This is the same behaviour as a 0 ms wait, which Spore tolerates.
  s->r[0] = 0x102;
}

void WaitForMultipleObjects(CpuState* s, const u32* a) {
  u32 count = a[0], list = a[1], wait_all = a[2];
  if (count > 64) { s->r[0] = 0xFFFFFFFFu; return; }
  u32 ready = 0;
  for (u32 i = 0; i < count; ++i) {
    u32 h = load<u32>(list + i * 4);
    Handle* o = handle_of(h);
    bool signalled = o && (o->kind == Handle::kSemaphore ? o->count > 0 : o->signalled != 0);
    if (signalled) {
      ++ready;
      if (!wait_all) {
        if (o->kind == Handle::kSemaphore) --o->count;
        else if (!o->manual_reset) o->signalled = 0;
        s->r[0] = i;
        return;
      }
    }
  }
  if (wait_all && ready == count) { s->r[0] = 0; return; }
  s->r[0] = 0x102;
}

void WaitForMultipleObjectsEx(CpuState* s, const u32* a) {
  WaitForMultipleObjects(s, a);
}

void CloseHandle(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (o) {
    if (o->file) std::fclose(static_cast<FILE*>(o->file));
    *o = Handle();
  }
  s->r[0] = 1;
}

void DuplicateHandle(CpuState* s, const u32* a) {
  if (a[3]) store<u32>(a[3], a[1]);
  s->r[0] = 1;
}

// ---------------------------------------------------------------------------
// threads
// ---------------------------------------------------------------------------
void CreateThread(CpuState* s, const u32* a) {
  // CreateThread(attrs, stackSize, startAddr, param, flags, pThreadId)
  u32 handle = threads::create(a[2], a[3], a[1], (a[4] & 0x4) != 0);
  if (handle) {
    SR_LOG("CreateThread entry=0x%08x param=0x%08x -> handle 0x%08x", a[2], a[3], handle);
  } else {
    SR_LOG("CreateThread entry=0x%08x FAILED", a[2]);
  }
  if (a[5]) store<u32>(a[5], handle ? (handle & 0x7FFFFFFF) : 0);
  s->r[0] = handle;
}

void ResumeThread(CpuState* s, const u32* a) {
  // Threads created suspended were never started; start them now.
  if (threads::GuestThread* t = threads::find(a[0])) {
    if (!t->native) {
      // Re-create it as a running thread. The guest expects the handle to stay valid, so the
      // thread is restarted in place rather than replaced.
      threads::resume(t);
    }
  }
  s->r[0] = 1;
}
void SetThreadPriority(CpuState* s, const u32*) { s->r[0] = 1; }
void GetThreadPriority(CpuState* s, const u32*) { s->r[0] = 0; }
void SetPriorityClass(CpuState* s, const u32*) { s->r[0] = 1; }
void GetPriorityClass(CpuState* s, const u32*) { s->r[0] = 0x20; }
void SetThreadAffinityMask(CpuState* s, const u32*) { s->r[0] = 1; }
void SetProcessAffinityMask(CpuState* s, const u32*) { s->r[0] = 1; }
void GetProcessAffinityMask(CpuState* s, const u32* a) {
  if (a[1]) store<u32>(a[1], 1);
  if (a[2]) store<u32>(a[2], 1);
  s->r[0] = 1;
}
void SetThreadIdealProcessor(CpuState* s, const u32*) { s->r[0] = 0; }
void QueueUserAPC(CpuState* s, const u32*) { s->r[0] = 0; }
void OpenProcess(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFFu; }

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------
void TlsAlloc(CpuState* s, const u32*) {
  static uint32_t next = 0;
  if (next >= kMaxTls) { s->r[0] = 0xFFFFFFFFu; return; }
  s->r[0] = next++;
}

void TlsFree(CpuState* s, const u32* a) {
  if (a[0] < kMaxTls) g_tls_values[a[0]] = 0;
  s->r[0] = 1;
}

void TlsSetValue(CpuState* s, const u32* a) {
  if (a[0] < kMaxTls) g_tls_values[a[0]] = a[1];
  s->r[0] = 1;
}

void TlsGetValue(CpuState* s, const u32* a) {
  s->r[0] = a[0] < kMaxTls ? g_tls_values[a[0]] : 0;
}

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------
namespace {
u32 open_file(const char* guest_path, u32 access, u32 disposition) {
  std::string host = to_host_path(guest_path);
  const char* mode = file_mode(access, disposition);
  FILE* f = std::fopen(host.c_str(), mode);
  if (!f && mode[0] == 'r' && mode[1] == '+') f = std::fopen(host.c_str(), "rb");
  if (!f) {
    SR_LOGV("open(%s) failed (host %s)", guest_path, host.c_str());
    return 0xFFFFFFFFu;
  }
  u32 h = new_handle(Handle::kFile);
  Handle* o = handle_of(h);
  if (o) { o->file = f; o->path = host; }
  return h;
}
}  // namespace

void CreateFileA(CpuState* s, const u32* a) {
  u32 h = open_file(cstr(a[0]), a[1], a[4]);
  if (h == 0xFFFFFFFFu) s->last_error = 2;
  s->r[0] = h;
}

void CreateFileW(CpuState* s, const u32* a) {
  u32 h = open_file(wstr_utf8(a[0]), a[1], a[4]);
  if (h == 0xFFFFFFFFu) s->last_error = 2;
  s->r[0] = h;
}

void ReadFile(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (!o || !o->file) { s->r[0] = 0; return; }
  size_t n = std::fread(gmem().base() + a[1], 1, a[2], static_cast<FILE*>(o->file));
  if (a[3]) store<u32>(a[3], u32(n));
  s->r[0] = 1;
}

void WriteFile(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (!o || !o->file) { s->r[0] = 1; return; }
  size_t n = std::fwrite(gmem().base() + a[1], 1, a[2], static_cast<FILE*>(o->file));
  if (a[3]) store<u32>(a[3], u32(n));
  s->r[0] = 1;
}

void SetFilePointer(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (!o || !o->file) { s->r[0] = 0xFFFFFFFFu; return; }
  FILE* f = static_cast<FILE*>(o->file);
  int whence = SEEK_SET;
  if (a[3] == 1) whence = SEEK_CUR;
  else if (a[3] == 2) whence = SEEK_END;
  std::fseek(f, long(a[1]), whence);
  s->r[0] = u32(std::ftell(f));
}

void GetFileSize(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (!o || !o->file) { s->r[0] = 0xFFFFFFFFu; return; }
  FILE* f = static_cast<FILE*>(o->file);
  long cur = std::ftell(f);
  std::fseek(f, 0, SEEK_END);
  long size = std::ftell(f);
  std::fseek(f, cur, SEEK_SET);
  if (a[1]) store<u32>(a[1], 0);
  s->r[0] = u32(size);
}

void SetEndOfFile(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (o && o->file) {
    FILE* f = static_cast<FILE*>(o->file);
    long pos = std::ftell(f);
    std::fflush(f);
    if (truncate(o->path.c_str(), pos) != 0) { /* best effort */ }
  }
  s->r[0] = 1;
}

void FlushFileBuffers(CpuState* s, const u32* a) {
  Handle* o = handle_of(a[0]);
  if (o && o->file) std::fflush(static_cast<FILE*>(o->file));
  s->r[0] = 1;
}

void CloseHandleFile(CpuState* s, const u32* a) { CloseHandle(s, a); }

void DeleteFileA(CpuState* s, const u32* a) {
  s->r[0] = remove(to_host_path(cstr(a[0])).c_str()) == 0 ? 1 : 0;
}

void DeleteFileW(CpuState* s, const u32* a) {
  s->r[0] = remove(to_host_path(wstr_utf8(a[0])).c_str()) == 0 ? 1 : 0;
}

void MoveFileA(CpuState* s, const u32* a) {
  s->r[0] = rename(to_host_path(cstr(a[0])).c_str(),
                   to_host_path(cstr(a[1])).c_str()) == 0 ? 1 : 0;
}

void MoveFileExW(CpuState* s, const u32* a) {
  s->r[0] = rename(to_host_path(wstr_utf8(a[0])).c_str(),
                   to_host_path(wstr_utf8(a[1])).c_str()) == 0 ? 1 : 0;
}

void CopyFileW(CpuState* s, const u32* a) {
  std::string src = to_host_path(wstr_utf8(a[0])), dst = to_host_path(wstr_utf8(a[1]));
  FILE* in = std::fopen(src.c_str(), "rb");
  if (!in) { s->r[0] = 0; return; }
  FILE* out = std::fopen(dst.c_str(), "wb");
  if (!out) { std::fclose(in); s->r[0] = 0; return; }
  char buf[65536];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof buf, in)) > 0) std::fwrite(buf, 1, n, out);
  std::fclose(in);
  std::fclose(out);
  s->r[0] = 1;
}

void GetFileAttributesW(CpuState* s, const u32* a) {
  std::string p = to_host_path(wstr_utf8(a[0]));
  struct stat st;
  if (stat(p.c_str(), &st) != 0) { s->r[0] = 0xFFFFFFFFu; return; }
  s->r[0] = S_ISDIR(st.st_mode) ? 0x10u : 0x80u;
}

void SetFileAttributesW(CpuState* s, const u32*) { s->r[0] = 1; }

void CreateDirectoryA(CpuState* s, const u32* a) {
  mkdir(to_host_path(cstr(a[0])).c_str(), 0755);
  s->r[0] = 1;
}

void CreateDirectoryW(CpuState* s, const u32* a) {
  mkdir(to_host_path(wstr_utf8(a[0])).c_str(), 0755);
  s->r[0] = 1;
}

void RemoveDirectoryA(CpuState* s, const u32* a) {
  s->r[0] = rmdir(to_host_path(cstr(a[0])).c_str()) == 0 ? 1 : 0;
}

void RemoveDirectoryW(CpuState* s, const u32* a) {
  s->r[0] = rmdir(to_host_path(wstr_utf8(a[0])).c_str()) == 0 ? 1 : 0;
}

void GetLongPathNameW(CpuState* s, const u32* a) {
  s->r[0] = write_wstr(a[1], wstr_utf8(a[0]), a[2]);
}

void GetVolumeInformationW(CpuState* s, const u32* a) {
  if (a[2]) store<u32>(a[2], 0x12345678);
  if (a[3]) store<u32>(a[3], 255);
  if (a[4]) store<u32>(a[4], 0x3F);
  if (a[5]) store<u32>(a[5], 0xFFFFFFFFu);
  write_wstr(a[1], "SPORE", 32);
  s->r[0] = 1;
}

void GetVolumeInformationA(CpuState* s, const u32* a) {
  if (a[2]) store<u32>(a[2], 0x12345678);
  if (a[3]) store<u32>(a[3], 255);
  write_cstr(a[1], "SPORE");
  s->r[0] = 1;
}

void GetVolumePathNameW(CpuState* s, const u32* a) {
  s->r[0] = write_wstr(a[1], "C:\\", a[2]);
}

void GetDiskFreeSpaceExA(CpuState* s, const u32* a) {
  u64 free_bytes = 4ull * 1024 * 1024 * 1024;
  if (a[1]) store<u64>(a[1], free_bytes);
  if (a[2]) store<u64>(a[2], free_bytes);
  if (a[3]) store<u64>(a[3], free_bytes);
  s->r[0] = 1;
}

void GetDriveTypeA(CpuState* s, const u32*) { s->r[0] = 3; }
void GetLogicalDrives(CpuState* s, const u32*) { s->r[0] = 0x4; }
// --- directory enumeration -------------------------------------------------
// Spore lists save games, packages and mods, so this has to actually work rather than
// return "nothing found": a wrong answer here means the game cannot see its own data.
namespace {

struct FindState {
  std::vector<std::string> names;   // matching entries
  size_t index = 0;
  std::string dir;                  // host directory being listed
  bool is_wide = false;
};

std::unordered_map<uint32_t, FindState*> g_finds;
uint32_t g_next_find = 0x000A0000;

// Matches a Windows wildcard pattern ("*.package", "*.*") against a file name.
bool wildcard_match(const char* pat, const char* name) {
  while (*pat) {
    if (*pat == '*') {
      ++pat;
      if (!*pat) return true;
      for (const char* p = name; *p; ++p) {
        if (wildcard_match(pat, p)) return true;
      }
      return false;
    }
    if (*pat == '?') {
      if (!*name) return false;
      ++pat;
      ++name;
      continue;
    }
    if (std::tolower(static_cast<unsigned char>(*pat)) !=
        std::tolower(static_cast<unsigned char>(*name))) {
      return false;
    }
    ++pat;
    ++name;
  }
  return *name == 0;
}

void fill_find_data(uint32_t out, const std::string& host_dir, const std::string& name,
                    bool is_wide) {
  std::string full = host_dir.empty() ? name : host_dir + "/" + name;
  struct stat st;
  bool have = stat(full.c_str(), &st) == 0;

  __builtin_memset(gmem().base() + out, 0, is_wide ? 592 : 320);
  store<uint32_t>(out + 0, have && S_ISDIR(st.st_mode) ? 0x10u : 0x80u);
  if (have) {
    uint64_t ns = uint64_t(st.st_mtime) * 1000000000ull;
    uint64_t ft = (ns / 100) + 116444736000000000ull;
    store<uint64_t>(out + 12, ft);  // creation
    store<uint64_t>(out + 20, ft);  // access
    store<uint64_t>(out + 28, ft);  // write
    store<uint32_t>(out + 36, uint32_t(uint64_t(st.st_size) >> 32));
    store<uint32_t>(out + 40, uint32_t(uint64_t(st.st_size)));
  }
  if (is_wide) {
    write_wstr(out + 44, name.c_str(), 260);
  } else {
    write_cstr(out + 44, name.c_str());
  }
}

uint32_t start_find(const char* guest_pattern, uint32_t out, bool is_wide) {
  std::string pattern = guest_pattern ? guest_pattern : "";
  for (char& c : pattern) if (c == '\\') c = '/';
  std::string dir = ".";
  std::string mask = pattern;
  size_t slash = pattern.find_last_of('/');
  if (slash != std::string::npos) {
    dir = pattern.substr(0, slash);
    mask = pattern.substr(slash + 1);
  }
  std::string host = to_host_path(dir.c_str());

  auto* st = new FindState();
  st->dir = host;
  st->is_wide = is_wide;
  DIR* d = opendir(host.c_str());
  if (!d) {
    SR_LOGV("FindFirstFile(%s): cannot open host dir %s", guest_pattern, host.c_str());
    delete st;
    return 0xFFFFFFFFu;
  }
  if (mask.empty()) mask = "*";
  struct dirent* e;
  while ((e = readdir(d)) != nullptr) {
    if (e->d_name[0] == '.' && (e->d_name[1] == 0 ||
        (e->d_name[1] == '.' && e->d_name[2] == 0))) {
      continue;
    }
    if (!wildcard_match(mask.c_str(), e->d_name)) continue;
    st->names.push_back(e->d_name);
  }
  closedir(d);
  if (st->names.empty()) {
    delete st;
    return 0xFFFFFFFFu;
  }
  uint32_t h = g_next_find++;
  g_finds[h] = st;
  fill_find_data(out, st->dir, st->names[0], is_wide);
  st->index = 1;
  return h;
}

bool next_find(uint32_t handle, uint32_t out) {
  auto it = g_finds.find(handle);
  if (it == g_finds.end()) return false;
  FindState* st = it->second;
  if (st->index >= st->names.size()) return false;
  fill_find_data(out, st->dir, st->names[st->index], st->is_wide);
  ++st->index;
  return true;
}

}  // namespace

void FindFirstFileA(CpuState* s, const u32* a) {
  s->r[0] = start_find(cstr(a[0]), a[1], false);
}

void FindFirstFileW(CpuState* s, const u32* a) {
  s->r[0] = start_find(wstr_utf8(a[0]), a[1], true);
}

void FindNextFileA(CpuState* s, const u32* a) {
  s->r[0] = next_find(a[0], a[1]) ? 1 : 0;
}

void FindNextFileW(CpuState* s, const u32* a) {
  s->r[0] = next_find(a[0], a[1]) ? 1 : 0;
}

void FindClose(CpuState* s, const u32* a) {
  auto it = g_finds.find(a[0]);
  if (it != g_finds.end()) {
    delete it->second;
    g_finds.erase(it);
  }
  s->r[0] = 1;
}
void FindFirstChangeNotificationW(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFFu; }
void FindNextChangeNotification(CpuState* s, const u32*) { s->r[0] = 0; }
void FindCloseChangeNotification(CpuState* s, const u32*) { s->r[0] = 1; }
void CancelIo(CpuState* s, const u32*) { s->r[0] = 1; }
void DeviceIoControl(CpuState* s, const u32*) { s->r[0] = 0; }
void EnumResourceNamesA(CpuState* s, const u32*) { s->r[0] = 1; }
void LoadLibraryA(CpuState* s, const u32*) { s->r[0] = kImageBase; }
void LoadLibraryW(CpuState* s, const u32*) { s->r[0] = kImageBase; }
void FreeLibrary(CpuState* s, const u32*) { s->r[0] = 1; }

}  // namespace sr::w32

