// SporeRecomp — kernel32: memory, time, version, strings.
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/win32/internal.h"
#include "rt/win32/win32.h"

namespace sr::w32 {

namespace {

u64 g_qpc_freq = 1000000000ull;

u64 now_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return u64(ts.tv_sec) * 1000000000ull + u64(ts.tv_nsec);
}

}  // namespace

// ---------------------------------------------------------------------------
// guest string helpers
// ---------------------------------------------------------------------------
const char* cstr(u32 guest_addr) {
  if (!guest_addr) return "";
  return reinterpret_cast<const char*>(gmem().base() + guest_addr);
}

void wstr(u32 guest_addr, char16_t* out, int max_chars) {
  if (!guest_addr) { out[0] = 0; return; }
  const char16_t* p = reinterpret_cast<const char16_t*>(gmem().base() + guest_addr);
  int i = 0;
  for (; i < max_chars - 1 && p[i]; ++i) out[i] = p[i];
  out[i] = 0;
}

u32 write_cstr(u32 guest_addr, const char* text) {
  if (!guest_addr) return 0;
  char* p = reinterpret_cast<char*>(gmem().base() + guest_addr);
  std::strcpy(p, text);
  return guest_addr;
}

const char* wstr_utf8(u32 guest_addr) {
  static std::string buf;
  buf.clear();
  if (!guest_addr) return buf.c_str();
  const char16_t* p = reinterpret_cast<const char16_t*>(gmem().base() + guest_addr);
  for (int i = 0; i < 4096 && p[i]; ++i) {
    u32 c = p[i];
    if (c < 0x80) buf += char(c);
    else if (c < 0x800) {
      buf += char(0xC0 | (c >> 6));
      buf += char(0x80 | (c & 0x3F));
    } else {
      buf += char(0xE0 | (c >> 12));
      buf += char(0x80 | ((c >> 6) & 0x3F));
      buf += char(0x80 | (c & 0x3F));
    }
  }
  return buf.c_str();
}

u32 write_wstr(u32 guest_addr, const char* utf8, u32 max_chars) {
  if (!guest_addr) return 0;
  char16_t* out = reinterpret_cast<char16_t*>(gmem().base() + guest_addr);
  u32 n = 0;
  const unsigned char* p = reinterpret_cast<const unsigned char*>(utf8);
  while (*p && n + 1 < max_chars) {
    u32 c = *p++;
    if (c >= 0xF0) {
      c = ((c & 0x07) << 18) | ((p[0] & 0x3F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
      p += 3;
      // surrogate pair
      c -= 0x10000;
      out[n++] = char16_t(0xD800 + (c >> 10));
      if (n + 1 < max_chars) out[n++] = char16_t(0xDC00 + (c & 0x3FF));
    } else if (c >= 0xE0) {
      c = ((c & 0x0F) << 12) | ((p[0] & 0x3F) << 6) | (p[1] & 0x3F);
      p += 2;
      out[n++] = char16_t(c);
    } else if (c >= 0xC0) {
      c = ((c & 0x1F) << 6) | (p[0] & 0x3F);
      p += 1;
      out[n++] = char16_t(c);
    } else {
      out[n++] = char16_t(c);
    }
  }
  out[n] = 0;
  return n;
}

u32 guest_alloc(u32 size) { return gmem().heap_alloc(size ? size : 1); }
void guest_free(u32 addr) { gmem().heap_free(addr); }

// ---------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------
void GetProcessHeap(CpuState* s, const u32*) { s->r[0] = 0x00150000; }

void HeapAlloc(CpuState* s, const u32* a) {
  s->r[0] = guest_alloc(a[2]);
  if (a[1] & 0x8) {  // HEAP_ZERO_MEMORY
    if (s->r[0]) __builtin_memset(gmem().base() + s->r[0], 0, a[2]);
  }
}

void HeapFree(CpuState* s, const u32* a) {
  guest_free(a[2]);
  s->r[0] = 1;
}

void HeapReAlloc(CpuState* s, const u32* a) {
  // Preserve contents: Spore reallocates growing buffers and expects the data to survive.
  u32 old = a[2], size = a[3], flags = a[1];
  u32 nw = guest_alloc(size);
  if (nw && old) {
    // Copy as much as fits. The old block's size is not tracked precisely, so copy `size`
    // bytes; the allocator never hands out a smaller block than requested.
    __builtin_memcpy(gmem().base() + nw, gmem().base() + old, size);
  }
  if (nw && (flags & 0x8)) __builtin_memset(gmem().base() + nw, 0, size);
  s->r[0] = nw;
}

void VirtualAlloc(CpuState* s, const u32* a) {
  u32 addr = a[0], size = a[1];
  if (!addr) {
    s->r[0] = guest_alloc(size);
  } else {
    if (gmem().map(addr, size)) s->r[0] = addr; else s->r[0] = 0;
  }
}

void VirtualFree(CpuState* s, const u32* a) {
  if (a[2] == 0x8000) {  // MEM_RELEASE
    gmem().release(a[0], 0x1000);
  }
  s->r[0] = 1;
}

void VirtualQuery(CpuState* s, const u32* a) {
  // MEMORY_BASIC_INFORMATION: BaseAddress, AllocationBase, Protect, RegionSize, State...
  u32 out = a[1];
  if (out) {
    u32 base = a[0] & ~0xFFFu;
    store<u32>(out + 0, base);
    store<u32>(out + 4, base);
    store<u32>(out + 8, 0x04);        // PAGE_READWRITE
    store<u32>(out + 12, 0x1000);     // RegionSize
    store<u32>(out + 16, 0x1000);     // MEM_COMMIT
    store<u32>(out + 20, 0x04);
  }
  s->r[0] = out ? 28 : 0;
}

void GlobalAlloc(CpuState* s, const u32* a) { s->r[0] = guest_alloc(a[1]); }
void GlobalFree(CpuState* s, const u32* a) { guest_free(a[0]); s->r[0] = 0; }
void GlobalLock(CpuState* s, const u32* a) { s->r[0] = a[0]; }
void GlobalUnlock(CpuState* s, const u32* a) { s->r[0] = 1; }
void GlobalSize(CpuState* s, const u32* a) { (void)a; s->r[0] = 0x10000; }
void LocalAlloc(CpuState* s, const u32* a) { s->r[0] = guest_alloc(a[1]); }
void LocalFree(CpuState* s, const u32* a) { guest_free(a[0]); s->r[0] = 0; }

void GlobalMemoryStatusEx(CpuState* s, const u32* a) {
  u32 p = a[0];
  if (p) {
    store<u32>(p + 0, 64);
    store<u32>(p + 4, 60);              // dwMemoryLoad %
    store<u64>(p + 8, 1024ull * 1024 * 1024);   // total phys (the device has 1 GB)
    store<u64>(p + 16, 400ull * 1024 * 1024);   // avail phys
    store<u64>(p + 24, 0x7FFFFFFFull);          // total page file
    store<u64>(p + 32, 0x7FFFFFFFull);
    store<u64>(p + 40, 0xFFFFFFFFull);          // total virtual
    store<u64>(p + 48, 0xFFFF0000ull);
  }
  s->r[0] = 1;
}

void GlobalMemoryStatus(CpuState* s, const u32* a) {
  u32 p = a[0];
  if (p) {
    store<u32>(p + 0, 32);
    store<u32>(p + 4, 60);
    store<u32>(p + 8, 1024);
    store<u32>(p + 12, 400);
    store<u32>(p + 16, 0xFFFFFFFFu);
    store<u32>(p + 20, 0xFFFF0000u);
  }
  s->r[0] = 1;
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------
void QueryPerformanceFrequency(CpuState* s, const u32* a) {
  if (a[0]) store<u64>(a[0], g_qpc_freq);
  s->r[0] = 1;
}

void QueryPerformanceCounter(CpuState* s, const u32* a) {
  if (a[0]) store<u64>(a[0], now_ns());
  s->r[0] = 1;
}

void GetTickCount(CpuState* s, const u32*) {
  s->r[0] = u32(now_ns() / 1000000ull);
}

void GetSystemTimeAsFileTime(CpuState* s, const u32* a) {
  // FILETIME: 100 ns intervals since 1601-01-01
  u64 ns = now_ns() + 11644473600ull * 1000000000ull;
  if (a[0]) store<u64>(a[0], ns / 100);
}

void GetSystemTime(CpuState* s, const u32* a) {
  u32 p = a[0];
  time_t t = time(nullptr);
  struct tm tmv;
  gmtime_r(&t, &tmv);
  if (p) {
    store<u16>(p + 0, u16(tmv.tm_year + 1900));
    store<u16>(p + 2, u16(tmv.tm_mon + 1));
    store<u16>(p + 4, u16(tmv.tm_wday));
    store<u16>(p + 6, u16(tmv.tm_mday));
    store<u16>(p + 8, u16(tmv.tm_hour));
    store<u16>(p + 10, u16(tmv.tm_min));
    store<u16>(p + 12, u16(tmv.tm_sec));
    store<u16>(p + 14, 0);
  }
}

void SystemTimeToFileTime(CpuState* s, const u32* a) {
  u32 p = a[0];
  struct tm tmv{};
  tmv.tm_year = load<u16>(p + 0) - 1900;
  tmv.tm_mon = load<u16>(p + 2) - 1;
  tmv.tm_mday = load<u16>(p + 6);
  tmv.tm_hour = load<u16>(p + 8);
  tmv.tm_min = load<u16>(p + 10);
  tmv.tm_sec = load<u16>(p + 12);
  time_t t = timegm(&tmv);
  u64 ft = (u64(t) + 11644473600ull) * 10000000ull;
  if (a[1]) store<u64>(a[1], ft);
  s->r[0] = 1;
}

// ---------------------------------------------------------------------------
// version / system info
// ---------------------------------------------------------------------------
void GetVersionExA(CpuState* s, const u32* a) {
  u32 p = a[0];
  if (p) {
    store<u32>(p + 0, 276);       // dwOSVersionInfoSize
    store<u32>(p + 4, 5);         // major
    store<u32>(p + 8, 1);         // minor
    store<u32>(p + 12, 2600);     // build
    store<u32>(p + 16, 2);        // VER_PLATFORM_WIN32_NT
    write_cstr(p + 20, "Service Pack 3");
  }
  s->r[0] = 1;
}

void GetVersionExW(CpuState* s, const u32* a) {
  u32 p = a[0];
  if (p) {
    store<u32>(p + 0, 276);
    store<u32>(p + 4, 5);
    store<u32>(p + 8, 1);
    store<u32>(p + 12, 2600);
    store<u32>(p + 16, 2);
    write_wstr(p + 20, "Service Pack 3", 64);
  }
  s->r[0] = 1;
}

void GetVersion(CpuState* s, const u32*) {
  s->r[0] = 0x0A280105u;  // 5.1 build 2600
}

void GetSystemInfo(CpuState* s, const u32* a) {
  u32 p = a[0];
  if (p) {
    __builtin_memset(gmem().base() + p, 0, 36);
    store<u16>(p + 0, 0);       // processor architecture: INTEL
    store<u32>(p + 4, 0x1000);  // page size
    store<u32>(p + 8, 0x400000);  // min app address
    store<u32>(p + 12, 0x7FFE0000);  // max app address
    store<u32>(p + 16, 0x80000000u);  // active processor mask
    store<u32>(p + 20, 1);      // number of processors
    store<u32>(p + 24, 1);      // processor type
    store<u32>(p + 28, 0x1000); // allocation granularity
    store<u16>(p + 32, 6);      // processor level
    store<u16>(p + 34, 0x0F00); // processor revision
  }
}

void GetSystemDirectoryW(CpuState* s, const u32* a) {
  write_wstr(a[0], "C:\\windows\\system32", a[1]);
  s->r[0] = 21;
}

void GetWindowsDirectoryW(CpuState* s, const u32* a) {
  write_wstr(a[0], "C:\\windows", a[1]);
  s->r[0] = 10;
}

void GetTempPathW(CpuState* s, const u32* a) {
  write_wstr(a[0], "/tmp/", a[1]);
  s->r[0] = 5;
}

void GetModuleFileNameA(CpuState* s, const u32* a) {
  std::string p = shim::config().game_dir + "/SporeApp.exe";
  write_cstr(a[1], p.c_str());
  s->r[0] = u32(p.size());
}

void GetModuleFileNameW(CpuState* s, const u32* a) {
  std::string p = shim::config().game_dir + "/SporeApp.exe";
  s->r[0] = write_wstr(a[1], p.c_str(), a[2]);
}

void GetModuleHandleA(CpuState* s, const u32*) { s->r[0] = kImageBase; }
void GetModuleHandleW(CpuState* s, const u32*) { s->r[0] = kImageBase; }
void GetProcAddress(CpuState* s, const u32*) { s->r[0] = 0; }

void GetCommandLineA(CpuState* s, const u32*) {
  static u32 addr = 0;
  if (!addr) {
    addr = guest_alloc(256);
    write_cstr(addr, "SporeApp.exe");
  }
  s->r[0] = addr;
}

void GetCurrentProcess(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFFu; }
void GetCurrentProcessId(CpuState* s, const u32*) { s->r[0] = 1; }
void GetCurrentThread(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFEu; }
void GetCurrentThreadId(CpuState* s, const u32*) { s->r[0] = 1; }
void GetLastError(CpuState* s, const u32*) { s->r[0] = s->last_error; }
void SetLastError(CpuState* s, const u32* a) { s->last_error = a[0]; s->r[0] = 0; }
void IsDebuggerPresent(CpuState* s, const u32*) { s->r[0] = 0; }
void GetACP(CpuState* s, const u32*) { s->r[0] = 1252; }
void GetSystemDefaultLCID(CpuState* s, const u32*) { s->r[0] = 0x0409; }

void OutputDebugStringA(CpuState* s, const u32* a) {
  SR_LOGV("[guest dbg] %s", cstr(a[0]));
  s->r[0] = 0;
}

void GetStartupInfoA(CpuState* s, const u32* a) {
  if (a[0]) __builtin_memset(gmem().base() + a[0], 0, 68);
  s->r[0] = 0;
}

void GetEnvironmentVariableA(CpuState* s, const u32* a) {
  const char* v = getenv(cstr(a[0]));
  if (!v) { s->r[0] = 0; return; }
  write_cstr(a[1], v);
  s->r[0] = u32(std::strlen(v));
}

void SetEnvironmentVariableA(CpuState* s, const u32* a) {
  setenv(cstr(a[0]), cstr(a[1]), 1);
  s->r[0] = 1;
}

void GetCurrentDirectoryA(CpuState* s, const u32* a) {
  std::string p = shim::config().game_dir;
  write_cstr(a[1], p.c_str());
  s->r[0] = u32(p.size());
}

void GetFullPathNameA(CpuState* s, const u32* a) {
  std::string p = to_host_path(cstr(a[0]));
  write_cstr(a[2], p.c_str());
  s->r[0] = u32(p.size());
}

void GetFullPathNameW(CpuState* s, const u32* a) {
  std::string p = to_host_path(wstr_utf8(a[0]));
  s->r[0] = write_wstr(a[2], p.c_str(), a[1]);
}

void GetComputerNameA(CpuState* s, const u32* a) {
  write_cstr(a[0], "SPORE");
  if (a[1]) store<u32>(a[1], 5);
  s->r[0] = 1;
}

void GetComputerNameExA(CpuState* s, const u32* a) {
  write_cstr(a[1], "SPORE");
  if (a[2]) store<u32>(a[2], 5);
  s->r[0] = 1;
}

void GetLocaleInfoW(CpuState* s, const u32* a) {
  write_wstr(a[2], "en-US", a[3]);
  s->r[0] = 6;
}

void CompareStringW(CpuState* s, const u32* a) {
  std::string x = wstr_utf8(a[2]), y = wstr_utf8(a[3]);
  int r = x.compare(y);
  s->r[0] = r < 0 ? 1 : (r == 0 ? 2 : 3);
}

void LCMapStringW(CpuState* s, const u32* a) {
  std::string x = wstr_utf8(a[2]);
  s->r[0] = write_wstr(a[4], x.c_str(), a[3]);
}

void MultiByteToWideChar(CpuState* s, const u32* a) {
  const char* src = cstr(a[2]);
  int len = a[3] < 0 ? int(std::strlen(src)) : int(a[3]);
  std::string tmp(src, len);
  if (a[4] == 0) {
    s->r[0] = u32(tmp.size() + 1);
    return;
  }
  s->r[0] = write_wstr(a[4], tmp.c_str(), a[5]);
}

void WideCharToMultiByte(CpuState* s, const u32* a) {
  const char* src = wstr_utf8(a[2]);
  u32 len = a[3] < 0 ? u32(std::strlen(src)) : a[3];
  if (a[4] == 0) { s->r[0] = len + 1; return; }
  std::string tmp(src, len);
  write_cstr(a[4], tmp.c_str());
  s->r[0] = len;
}

void Sleep(CpuState* s, const u32* a) {
  usleep(a[0] * 1000);
  s->r[0] = 0;
}

void SleepEx(CpuState* s, const u32* a) {
  usleep(a[0] * 1000);
  s->r[0] = 0;
}

void SetThreadExecutionState(CpuState* s, const u32*) { s->r[0] = 0x80000000u; }
void FormatMessageA(CpuState* s, const u32* a) {
  write_cstr(a[3], "error");
  s->r[0] = 5;
}

void GetStdHandle(CpuState* s, const u32* a) {
  // stdin/stdout/stderr: distinct pseudo-handles; the file layer treats them as /dev/null
  s->r[0] = a[0] == 0xFFFFFFF6u ? 0xFFFFFFF6u : 0xFFFFFFF5u;
}

void GetFileType(CpuState* s, const u32*) { s->r[0] = 2; }  // FILE_TYPE_CHAR

void SetUnhandledExceptionFilter(CpuState* s, const u32*) { s->r[0] = 0; }
void UnhandledExceptionFilter(CpuState* s, const u32*) { s->r[0] = 1; }
void RaiseException(CpuState* s, const u32* a) {
  SR_LOG("guest RaiseException code=0x%08x flags=0x%x", a[0], a[1]);
  s->r[0] = 0;
}
void TerminateProcess(CpuState* s, const u32* a) {
  SR_LOG("guest TerminateProcess(exit=%u)", a[1]);
  exit(int(a[1]));
}
void GetExitCodeThread(CpuState* s, const u32* a) {
  if (a[1]) store<u32>(a[1], 0);
  s->r[0] = 1;
}
void GetProcessTimes(CpuState* s, const u32* a) {
  for (int i = 0; i < 4; ++i) if (a[1 + i]) store<u64>(a[1 + i], 0);
  s->r[0] = 1;
}

}  // namespace sr::w32
