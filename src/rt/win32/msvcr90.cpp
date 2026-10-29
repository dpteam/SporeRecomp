// SporeRecomp — MSVCR90 shim (the VS2008 C runtime).
//
// SporeApp.exe links the CRT dynamically, so every malloc/printf/qsort in the game lands
// here. Most of these forward to the host libc; the interesting ones are:
//   * the allocator (guest heap, because the pointers must live in guest memory),
//   * the variadic printf/scanf family (arguments are read from the guest stack),
//   * __iob_func / _initterm / __getmainargs (CRT startup handshake),
//   * setjmp/longjmp and the C++ exception machinery (see seh.cpp).
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwctype>
#include <sys/stat.h>
#include <unistd.h>
#include <string>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/win32/internal.h"
#include "rt/win32/win32.h"

namespace sr::w32 {

namespace {

// Reads guest argument `i` (0-based) from the current call's stack frame. Only valid while
// an import implementation is running: ESP still points at the return address.
inline u32 garg(CpuState* s, int i) { return load<u32>(s->r[4] + 4 + u32(i) * 4); }

// Guest FILE* stand-ins for stdin/stdout/stderr.
u32 g_iob = 0;
constexpr u32 kFileStructSize = 32;

FILE* host_stream(u32 guest_file) {
  if (!g_iob || !guest_file) return nullptr;
  if (guest_file == g_iob + 0 * kFileStructSize) return stdin;
  if (guest_file == g_iob + 1 * kFileStructSize) return stdout;
  if (guest_file == g_iob + 2 * kFileStructSize) return stderr;
  return nullptr;
}

// Formats a guest variadic call. `first_var` is the index of the first variadic argument.
std::string format_guest(CpuState* s, const char* fmt, int first_var) {
  std::string out;
  out.reserve(256);
  int arg = first_var;
  for (const char* p = fmt; *p; ++p) {
    if (*p != '%') { out += *p; continue; }
    ++p;
    if (*p == '%') { out += '%'; continue; }
    // parse flags/width/precision
    std::string spec = "%";
    while (*p && std::strchr("-+ #0", *p)) spec += *p++;
    while (*p && (std::isdigit(static_cast<unsigned char>(*p)) || *p == '*')) {
      if (*p == '*') { spec += std::to_string(int(garg(s, arg++))); ++p; }
      else spec += *p++;
    }
    if (*p == '.') {
      spec += *p++;
      if (*p == '*') { spec += std::to_string(int(garg(s, arg++))); ++p; }
      else while (*p && std::isdigit(static_cast<unsigned char>(*p))) spec += *p++;
    }
    while (*p && std::strchr("hlLqjzt", *p)) spec += *p++;
    if (!*p) break;
    char conv = *p;
    char buf[512];
    switch (conv) {
      case 'd': case 'i': case 'u': case 'x': case 'X': case 'o': case 'c': {
        long long v;
        if (spec.find('l') != std::string::npos && spec.find("ll") == std::string::npos)
          v = long(garg(s, arg++));
        else if (spec.find("ll") != std::string::npos)
          v = (long long)((u64(garg(s, arg + 1)) << 32) | garg(s, arg)), arg += 2;
        else
          v = int(garg(s, arg++));
        std::string full = spec + "ll" + conv;
        if (conv == 'c') std::snprintf(buf, sizeof buf, (spec + "c").c_str(), int(v));
        else std::snprintf(buf, sizeof buf, full.c_str(), v);
        out += buf;
        break;
      }
      case 's': {
        const char* v = cstr(garg(s, arg++));
        std::snprintf(buf, sizeof buf, (spec + "s").c_str(), v ? v : "");
        out += buf;
        break;
      }
      case 'f': case 'e': case 'E': case 'g': case 'G': {
        double v;
        u64 raw = (u64(garg(s, arg + 1)) << 32) | garg(s, arg);
        __builtin_memcpy(&v, &raw, 8);
        arg += 2;
        std::snprintf(buf, sizeof buf, (spec + conv).c_str(), v);
        out += buf;
        break;
      }
      case 'p': {
        std::snprintf(buf, sizeof buf, "%p", reinterpret_cast<void*>(uintptr_t(garg(s, arg++))));
        out += buf;
        break;
      }
      case 'n': {
        arg++;
        break;
      }
      default:
        out += conv;
        break;
    }
  }
  return out;
}

}  // namespace

std::string format_guest_args(CpuState* s, const char* fmt, int first_var) {
  return format_guest(s, fmt, first_var);
}

void wsprintfA_impl(CpuState* s, const u32* a) {
  std::string out = format_guest(s, cstr(a[1]), 2);
  write_cstr(a[0], out.c_str());
  s->r[0] = u32(out.size());
}

void wsprintfW_impl(CpuState* s, const u32* a) {
  std::string out = format_guest(s, wstr_utf8(a[1]), 2);
  s->r[0] = write_wstr(a[0], out.c_str(), 1024);
}

// ---------------------------------------------------------------------------
// allocator
// ---------------------------------------------------------------------------
void crt_malloc(CpuState* s, const u32* a) { s->r[0] = gmem().heap_alloc(a[0] ? a[0] : 1); }

void crt_free(CpuState* s, const u32* a) {
  gmem().heap_free(a[0]);
  s->r[0] = 0;
}

void crt_realloc(CpuState* s, const u32* a) {
  u32 old = a[0], size = a[1];
  if (!old) { s->r[0] = gmem().heap_alloc(size); return; }
  if (!size) { gmem().heap_free(old); s->r[0] = 0; return; }
  u32 nw = gmem().heap_alloc(size);
  if (nw) __builtin_memcpy(gmem().chars() + nw, gmem().chars() + old, size);
  gmem().heap_free(old);
  s->r[0] = nw;
}

void crt_aligned_malloc(CpuState* s, const u32* a) {
  u32 size = a[0], align = a[1] ? a[1] : 16;
  s->r[0] = gmem().heap_alloc(size + align, align);
}

void crt_aligned_free(CpuState* s, const u32* a) {
  gmem().heap_free(a[0]);
  s->r[0] = 0;
}

void crt_aligned_realloc(CpuState* s, const u32* a) { crt_realloc(s, a); }

// ---------------------------------------------------------------------------
// CRT startup handshake
// ---------------------------------------------------------------------------
void crt_initterm(CpuState* s, const u32* a) {
  // Walks a table of function pointers calling each one: the C++ static initialisers.
  u32 first = a[0], last = a[1];
  unsigned n = 0;
  for (u32 p = first; p < last; p += 4) {
    u32 fn = load<u32>(p);
    if (!fn) continue;
    GuestFn f = find_function(fn);
    if (!f) {
      SR_LOG("initterm: initialiser 0x%08x is not lifted", fn);
      continue;
    }
    guest_push_ret(s, 0xFFFFFFFFu);
    f(s);
    ++n;
  }
  SR_LOG("initterm: ran %u initialisers", n);
  s->r[0] = 0;
}

void crt_initterm_e(CpuState* s, const u32* a) {
  crt_initterm(s, a);
}

void crt_getmainargs(CpuState* s, const u32* a) {
  // int __getmainargs(int* argc, char*** argv, char*** envp, int doWildCard, _startupinfo*)
  u32 argc_p = a[0], argv_p = a[1], envp_p = a[2];
  u32 argv_buf = gmem().heap_alloc(16 * 4);
  u32 str = gmem().heap_alloc(64);
  write_cstr(str, "SporeApp.exe");
  store<u32>(argv_buf, str);
  store<u32>(argv_buf + 4, 0);
  u32 env_buf = gmem().heap_alloc(4);
  store<u32>(env_buf, 0);
  if (argc_p) store<u32>(argc_p, 1);
  if (argv_p) store<u32>(argv_p, argv_buf);
  if (envp_p) store<u32>(envp_p, env_buf);
  s->r[0] = 0;
}

void crt_iob_func(CpuState* s, const u32*) {
  if (!g_iob) {
    g_iob = gmem().heap_alloc(3 * kFileStructSize);
    __builtin_memset(gmem().chars() + g_iob, 0, 3 * kFileStructSize);
  }
  s->r[0] = g_iob;
}

void crt_acmdln(CpuState* s, const u32*) {
  static u32 p = 0;
  if (!p) { p = gmem().heap_alloc(4); store<u32>(p, 0); }
  s->r[0] = p;
}

void crt_p_fmode(CpuState* s, const u32*) {
  static u32 p = 0;
  if (!p) { p = gmem().heap_alloc(4); store<u32>(p, 0x4000); }
  s->r[0] = p;
}

void crt_p_commode(CpuState* s, const u32*) {
  static u32 p = 0;
  if (!p) { p = gmem().heap_alloc(4); store<u32>(p, 0); }
  s->r[0] = p;
}

void crt_errno(CpuState* s, const u32*) {
  static u32 p = 0;
  if (!p) { p = gmem().heap_alloc(4); store<u32>(p, 0); }
  s->r[0] = p;
}

void crt_set_app_type(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_setusermatherr(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_configthreadlocale(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_adjust_fdiv(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_setmbcp(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_ismbblead(CpuState* s, const u32* a) { s->r[0] = 0; (void)a; }

void crt_onexit(CpuState* s, const u32* a) { s->r[0] = a[0]; }
void crt_dllonexit(CpuState* s, const u32* a) { s->r[0] = a[0]; }
void crt_lock(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_unlock(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_encode_pointer(CpuState* s, const u32* a) { s->r[0] = a[0]; }
void crt_decode_pointer(CpuState* s, const u32* a) { s->r[0] = a[0]; }

void crt_exit(CpuState* s, const u32* a) {
  SR_LOG("guest exit(%d)", int(a[0]));
  std::exit(int(a[0]));
}

void crt_cexit(CpuState* s, const u32*) {
  SR_LOG("guest _cexit");
  std::exit(0);
}

void crt_amsg_exit(CpuState* s, const u32* a) {
  SR_LOG("guest _amsg_exit(%u)", a[0]);
  std::exit(1);
}

void crt_abort(CpuState* s, const u32*) {
  SR_LOG("guest abort()");
  std::abort();
}

void crt_purecall(CpuState* s, const u32*) {
  SR_LOG("guest _purecall()");
  std::abort();
}

void crt_invoke_watson(CpuState* s, const u32* a) {
  SR_LOG("guest _invoke_watson(%s)", cstr(a[0]));
  std::abort();
}

void crt_crt_debugger_hook(CpuState* s, const u32*) { s->r[0] = 0; }

void crt_controlfp(CpuState* s, const u32* a) {
  u32 newbits = a[0], mask = a[1];
  u32 old = s->fpu_ctrl;
  s->fpu_ctrl = u16((old & ~mask) | (newbits & mask));
  s->r[0] = old;
}

void crt_controlfp_s(CpuState* s, const u32* a) {
  u32 cur_p = a[0], newbits = a[1], mask = a[2];
  u32 old = s->fpu_ctrl;
  u32 updated = (old & ~mask) | (newbits & mask);
  s->fpu_ctrl = u16(updated);
  if (cur_p) store<u32>(cur_p, updated);
  s->r[0] = 0;  // success
}

void crt_control87(CpuState* s, const u32* a) { crt_controlfp(s, a); }

// ---------------------------------------------------------------------------
// printf family (variadic: arguments come off the guest stack)
// ---------------------------------------------------------------------------
void crt_printf(CpuState* s, const u32* a) {
  std::string out = format_guest(s, cstr(a[0]), 1);
  std::fwrite(out.data(), 1, out.size(), stdout);
  s->r[0] = u32(out.size());
}

void crt_fprintf(CpuState* s, const u32* a) {
  std::string out = format_guest(s, cstr(a[1]), 2);
  FILE* f = host_stream(a[0]);
  if (!f) f = stdout;
  std::fwrite(out.data(), 1, out.size(), f);
  s->r[0] = u32(out.size());
}

void crt_sprintf(CpuState* s, const u32* a) {
  std::string out = format_guest(s, cstr(a[1]), 2);
  write_cstr(a[0], out.c_str());
  s->r[0] = u32(out.size());
}

void crt_snprintf(CpuState* s, const u32* a) {
  std::string out = format_guest(s, cstr(a[2]), 3);
  u32 cap = a[1];
  if (cap) {
    if (out.size() + 1 > cap) out.resize(cap - 1);
    write_cstr(a[0], out.c_str());
  }
  s->r[0] = u32(out.size());
}

void crt_vsnprintf(CpuState* s, const u32* a) { crt_snprintf(s, a); }
void crt_vsprintf(CpuState* s, const u32* a) { crt_sprintf(s, a); }
void crt_vfprintf(CpuState* s, const u32* a) { crt_fprintf(s, a); }

void crt_sscanf(CpuState* s, const u32* a) {
  s->r[0] = u32(std::sscanf(cstr(a[0]), cstr(a[1])));
}

void crt_swscanf(CpuState* s, const u32* a) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// string / character
// ---------------------------------------------------------------------------
#define CRT_STR1(name, expr) void name(CpuState* s, const u32* a) { s->r[0] = (expr); }

void crt_strlen(CpuState* s, const u32* a) { s->r[0] = u32(std::strlen(cstr(a[0]))); }
void crt_strcmp(CpuState* s, const u32* a) {
  s->r[0] = u32(std::strcmp(cstr(a[0]), cstr(a[1])));
}
void crt_strncmp(CpuState* s, const u32* a) {
  s->r[0] = u32(std::strncmp(cstr(a[0]), cstr(a[1]), a[2]));
}
void crt_stricmp(CpuState* s, const u32* a) {
  s->r[0] = u32(strcasecmp(cstr(a[0]), cstr(a[1])));
}
void crt_strnicmp(CpuState* s, const u32* a) {
  s->r[0] = u32(strncasecmp(cstr(a[0]), cstr(a[1]), a[2]));
}
void crt_strcpy(CpuState* s, const u32* a) {
  std::strcpy(gmem().chars() + a[0], cstr(a[1]));
  s->r[0] = a[0];
}
void crt_strncpy(CpuState* s, const u32* a) {
  std::strncpy(gmem().chars() + a[0], cstr(a[1]), a[2]);
  s->r[0] = a[0];
}
void crt_strcat(CpuState* s, const u32* a) {
  std::strcat(gmem().chars() + a[0], cstr(a[1]));
  s->r[0] = a[0];
}
void crt_strncat(CpuState* s, const u32* a) {
  std::strncat(gmem().chars() + a[0], cstr(a[1]), a[2]);
  s->r[0] = a[0];
}
void crt_strchr(CpuState* s, const u32* a) {
  const char* r = std::strchr(cstr(a[0]), int(a[1]));
  s->r[0] = r ? u32(r - gmem().chars()) : 0;
}
void crt_strrchr(CpuState* s, const u32* a) {
  const char* r = std::strrchr(cstr(a[0]), int(a[1]));
  s->r[0] = r ? u32(r - gmem().chars()) : 0;
}
void crt_strstr(CpuState* s, const u32* a) {
  const char* r = std::strstr(cstr(a[0]), cstr(a[1]));
  s->r[0] = r ? u32(r - gmem().chars()) : 0;
}
void crt_strpbrk(CpuState* s, const u32* a) {
  const char* r = std::strpbrk(cstr(a[0]), cstr(a[1]));
  s->r[0] = r ? u32(r - gmem().chars()) : 0;
}
void crt_strspn(CpuState* s, const u32* a) { s->r[0] = u32(std::strspn(cstr(a[0]), cstr(a[1]))); }
void crt_strcspn(CpuState* s, const u32* a) { s->r[0] = u32(std::strcspn(cstr(a[0]), cstr(a[1]))); }
void crt_strlwr(CpuState* s, const u32* a) {
  char* p = reinterpret_cast<char*>(gmem().chars() + a[0]);
  for (; *p; ++p) *p = char(std::tolower(static_cast<unsigned char>(*p)));
  s->r[0] = a[0];
}
void crt_strupr(CpuState* s, const u32* a) {
  char* p = reinterpret_cast<char*>(gmem().chars() + a[0]);
  for (; *p; ++p) *p = char(std::toupper(static_cast<unsigned char>(*p)));
  s->r[0] = a[0];
}

void crt_memcpy(CpuState* s, const u32* a) {
  __builtin_memcpy(gmem().chars() + a[0], gmem().chars() + a[1], a[2]);
  s->r[0] = a[0];
}
void crt_memmove(CpuState* s, const u32* a) {
  __builtin_memmove(gmem().chars() + a[0], gmem().chars() + a[1], a[2]);
  s->r[0] = a[0];
}
void crt_memset(CpuState* s, const u32* a) {
  __builtin_memset(gmem().chars() + a[0], int(a[1]), a[2]);
  s->r[0] = a[0];
}
void crt_memcmp(CpuState* s, const u32* a) {
  s->r[0] = u32(std::memcmp(gmem().chars() + a[0], gmem().chars() + a[1], a[2]));
}
void crt_memchr(CpuState* s, const u32* a) {
  const void* r = std::memchr(gmem().chars() + a[0], int(a[1]), a[2]);
  s->r[0] = r ? u32(uintptr_t(r) - uintptr_t(gmem().base())) : 0;
}

void crt_qsort(CpuState* s, const u32* a) {
  // qsort(base, count, size, compar). The comparator is guest code, so we implement a simple
  // insertion sort calling back into the guest. Spore sorts small arrays (resource tables).
  u32 base = a[0], count = a[1], size = a[2], cmp = a[3];
  GuestFn fn = find_function(cmp);
  if (!fn || !size) { s->r[0] = 0; return; }
  u8* b = gmem().base() + base;
  std::vector<u8> tmp(size);
  for (u32 i = 1; i < count; ++i) {
    std::memcpy(tmp.data(), b + i * size, size);
    u32 j = i;
    while (j > 0) {
      guest_push_ret(s, 0xFFFFFFFFu);
      s->r[4] -= 4; store<u32>(s->r[4], base + (j - 1) * size);
      s->r[4] -= 4; store<u32>(s->r[4], base + i * size);
      fn(s);
      // re-read: the comparator may have swapped nothing, we compare the temp value
      s->r[4] += 12;
      if (s->r[0] <= 0) break;
      std::memmove(b + j * size, b + (j - 1) * size, size);
      --j;
    }
    std::memcpy(b + j * size, tmp.data(), size);
  }
  s->r[0] = 0;
}

// ---------------------------------------------------------------------------
// numeric conversion
// ---------------------------------------------------------------------------
void crt_atoi(CpuState* s, const u32* a) { s->r[0] = u32(std::atoi(cstr(a[0]))); }
void crt_atol(CpuState* s, const u32* a) { s->r[0] = u32(std::atol(cstr(a[0]))); }
void crt_strtol(CpuState* s, const u32* a) {
  char* end = nullptr;
  long v = std::strtol(cstr(a[0]), &end, int(a[2]));
  if (a[1]) store<u32>(a[1], u32(uintptr_t(end) - uintptr_t(gmem().base())));
  s->r[0] = u32(v);
}
void crt_strtoul(CpuState* s, const u32* a) {
  char* end = nullptr;
  unsigned long v = std::strtoul(cstr(a[0]), &end, int(a[2]));
  if (a[1]) store<u32>(a[1], u32(uintptr_t(end) - uintptr_t(gmem().base())));
  s->r[0] = u32(v);
}
void crt_atof(CpuState* s, const u32* a) {
  double v = std::atof(cstr(a[0]));
  store<double>(s->r[4] + 0x100, v);  // scratch: the ABI returns floats in st(0)
  s->r[0] = u32(u64(0));              // caller reads st(0); see note in lift.py
  x87_push(s, v);
}

void crt_strtod(CpuState* s, const u32* a) {
  char* end = nullptr;
  double v = std::strtod(cstr(a[0]), &end);
  if (a[1]) store<u32>(a[1], u32(uintptr_t(end) - uintptr_t(gmem().base())));
  x87_push(s, v);
  s->r[0] = 0;
}

void crt_itoa(CpuState* s, const u32* a) {
  // _itoa(value, buffer, radix)
  char buf[64];
  long v = long(a[0]);
  int radix = int(a[2]);
  if (radix == 10) std::snprintf(buf, sizeof buf, "%ld", v);
  else if (radix == 16) std::snprintf(buf, sizeof buf, "%lx", (unsigned long)v);
  else std::snprintf(buf, sizeof buf, "%ld", v);
  write_cstr(a[1], buf);
  s->r[0] = a[1];
}

void crt_ultoa(CpuState* s, const u32* a) {
  char buf[64];
  std::snprintf(buf, sizeof buf, "%lu", (unsigned long)a[0]);
  write_cstr(a[1], buf);
  s->r[0] = a[1];
}

void crt_fcvt(CpuState* s, const u32* a) {
  // _fcvt(value, count, dec, sign)
  double v;
  u64 raw = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&v, &raw, 8);
  int count = int(a[2]);
  char buf[64];
  std::snprintf(buf, sizeof buf, "%.*f", count, std::fabs(v));
  std::string digits;
  for (const char* p = buf; *p; ++p) if (*p != '.') digits += *p;
  int dec = int(std::strchr(buf, '.') ? std::strchr(buf, '.') - buf : std::strlen(buf));
  u32 out = gmem().heap_alloc(64);
  write_cstr(out, digits.c_str());
  if (a[3]) store<u32>(a[3], u32(dec));
  if (a[4]) store<u32>(a[4], v < 0 ? 1 : 0);
  s->r[0] = out;
}

void crt_ecvt(CpuState* s, const u32* a) {
  double v;
  u64 raw = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&v, &raw, 8);
  int count = int(a[2]);
  char buf[64];
  std::snprintf(buf, sizeof buf, "%.*e", count > 0 ? count - 1 : 0, std::fabs(v));
  std::string digits;
  for (const char* p = buf; *p && *p != 'e'; ++p) if (*p != '.') digits += *p;
  u32 out = gmem().heap_alloc(64);
  write_cstr(out, digits.c_str());
  if (a[3]) store<u32>(a[3], u32(count));
  if (a[4]) store<u32>(a[4], v < 0 ? 1 : 0);
  s->r[0] = out;
}

// ---------------------------------------------------------------------------
// math
// ---------------------------------------------------------------------------
void crt_pow(CpuState* s, const u32* a) {
  double x, y;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  u64 ry = (u64(garg(s, 3)) << 32) | garg(s, 2);
  __builtin_memcpy(&x, &rx, 8);
  __builtin_memcpy(&y, &ry, 8);
  x87_push(s, std::pow(x, y));
  s->r[0] = 0;
}

void crt_floor(CpuState* s, const u32* a) {
  double x;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &rx, 8);
  x87_push(s, std::floor(x));
  s->r[0] = 0;
}

void crt_ceil(CpuState* s, const u32* a) {
  double x;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &rx, 8);
  x87_push(s, std::ceil(x));
  s->r[0] = 0;
}

void crt_modf(CpuState* s, const u32* a) {
  double x;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &rx, 8);
  double ip = 0;
  double fp = std::modf(x, &ip);
  if (a[2]) store<double>(a[2], ip);
  x87_push(s, fp);
  s->r[0] = 0;
}

void crt_ldexp(CpuState* s, const u32* a) {
  double x;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &rx, 8);
  x87_push(s, std::ldexp(x, int(garg(s, 2))));
  s->r[0] = 0;
}

void crt_isnan(CpuState* s, const u32* a) {
  double x;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &rx, 8);
  s->r[0] = std::isnan(x) ? 1 : 0;
}

void crt_finite(CpuState* s, const u32* a) {
  double x;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &rx, 8);
  s->r[0] = std::isfinite(x) ? 1 : 0;
}

// The _CI* intrinsics are 387 helper calls the compiler emits for float math.
void crt_ci_cos(CpuState* s, const u32* a) {
  double x; u64 r = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &r, 8);
  x87_push(s, std::cos(x)); s->r[0] = 0;
}
void crt_ci_sin(CpuState* s, const u32* a) {
  double x; u64 r = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &r, 8);
  x87_push(s, std::sin(x)); s->r[0] = 0;
}
void crt_ci_sqrt(CpuState* s, const u32* a) {
  double x; u64 r = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &r, 8);
  x87_push(s, std::sqrt(x)); s->r[0] = 0;
}
void crt_ci_log(CpuState* s, const u32* a) {
  double x; u64 r = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &r, 8);
  x87_push(s, std::log(x)); s->r[0] = 0;
}
void crt_ci_asin(CpuState* s, const u32* a) {
  double x; u64 r = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &r, 8);
  x87_push(s, std::asin(x)); s->r[0] = 0;
}
void crt_ci_acos(CpuState* s, const u32* a) {
  double x; u64 r = (u64(garg(s, 1)) << 32) | a[0];
  __builtin_memcpy(&x, &r, 8);
  x87_push(s, std::acos(x)); s->r[0] = 0;
}
void crt_ci_fmod(CpuState* s, const u32* a) {
  double x, y;
  u64 rx = (u64(garg(s, 1)) << 32) | a[0];
  u64 ry = (u64(garg(s, 3)) << 32) | garg(s, 2);
  __builtin_memcpy(&x, &rx, 8);
  __builtin_memcpy(&y, &ry, 8);
  x87_push(s, std::fmod(x, y)); s->r[0] = 0;
}

// ---------------------------------------------------------------------------
// random
// ---------------------------------------------------------------------------
void crt_rand(CpuState* s, const u32*) {
  // Deterministic LCG with the MSVC constants, so runs are reproducible.
  static u32 seed = 1;
  seed = seed * 214013u + 2531011u;
  s->r[0] = (seed >> 16) & 0x7FFF;
}

void crt_srand(CpuState* s, const u32* a) {
  (void)a;
  s->r[0] = 0;
}

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------
void crt_time64(CpuState* s, const u32* a) {
  time_t t = time(nullptr);
  if (a[0]) store<u64>(a[0], u64(t));
  s->r[0] = u32(t);
}

void crt_time32(CpuState* s, const u32* a) { crt_time64(s, a); }

void crt_localtime64(CpuState* s, const u32* a) {
  time_t t = time_t(load<u64>(a[0]));
  struct tm tmv;
  localtime_r(&t, &tmv);
  static u32 buf = 0;
  if (!buf) buf = gmem().heap_alloc(64);
  store<u32>(buf + 0, u32(tmv.tm_sec));
  store<u32>(buf + 4, u32(tmv.tm_min));
  store<u32>(buf + 8, u32(tmv.tm_hour));
  store<u32>(buf + 12, u32(tmv.tm_mday));
  store<u32>(buf + 16, u32(tmv.tm_mon));
  store<u32>(buf + 20, u32(tmv.tm_year));
  store<u32>(buf + 24, u32(tmv.tm_wday));
  store<u32>(buf + 28, u32(tmv.tm_yday));
  store<u32>(buf + 32, u32(tmv.tm_isdst));
  s->r[0] = buf;
}

void crt_gmtime64(CpuState* s, const u32* a) {
  time_t t = time_t(load<u64>(a[0]));
  struct tm tmv;
  gmtime_r(&t, &tmv);
  static u32 buf = 0;
  if (!buf) buf = gmem().heap_alloc(64);
  store<u32>(buf + 0, u32(tmv.tm_sec));
  store<u32>(buf + 4, u32(tmv.tm_min));
  store<u32>(buf + 8, u32(tmv.tm_hour));
  store<u32>(buf + 12, u32(tmv.tm_mday));
  store<u32>(buf + 16, u32(tmv.tm_mon));
  store<u32>(buf + 20, u32(tmv.tm_year));
  store<u32>(buf + 24, u32(tmv.tm_wday));
  store<u32>(buf + 28, u32(tmv.tm_yday));
  store<u32>(buf + 32, u32(tmv.tm_isdst));
  s->r[0] = buf;
}

void crt_mktime64(CpuState* s, const u32* a) {
  u32 p = a[0];
  struct tm tmv{};
  tmv.tm_sec = int(load<u32>(p + 0));
  tmv.tm_min = int(load<u32>(p + 4));
  tmv.tm_hour = int(load<u32>(p + 8));
  tmv.tm_mday = int(load<u32>(p + 12));
  tmv.tm_mon = int(load<u32>(p + 16));
  tmv.tm_year = int(load<u32>(p + 20));
  tmv.tm_isdst = int(load<u32>(p + 32));
  time_t t = mktime(&tmv);
  s->r[0] = u32(t);
  s->r[2] = u32(u64(t) >> 32);
}

void crt_strftime(CpuState* s, const u32* a) {
  u32 buf = a[0], maxlen = a[1], fmt = a[2], tmp = a[3];
  struct tm tmv{};
  tmv.tm_sec = int(load<u32>(tmp + 0));
  tmv.tm_min = int(load<u32>(tmp + 4));
  tmv.tm_hour = int(load<u32>(tmp + 8));
  tmv.tm_mday = int(load<u32>(tmp + 12));
  tmv.tm_mon = int(load<u32>(tmp + 16));
  tmv.tm_year = int(load<u32>(tmp + 20));
  size_t n = std::strftime(reinterpret_cast<char*>(gmem().chars() + buf), maxlen, cstr(fmt), &tmv);
  s->r[0] = u32(n);
}

// ---------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------
void crt_fopen(CpuState* s, const u32* a) {
  std::string path = to_host_path(cstr(a[0]));
  FILE* f = std::fopen(path.c_str(), cstr(a[1]));
  if (!f) { s->r[0] = 0; return; }
  u32 h = gmem().heap_alloc(kFileStructSize);
  __builtin_memset(gmem().chars() + h, 0, kFileStructSize);
  // stash the host FILE* in the guest struct; the CRT never inspects it
  store<u64>(h + 8, u64(uintptr_t(f)));
  s->r[0] = h;
}

namespace {
FILE* file_of(u32 guest_file) {
  if (!guest_file) return nullptr;
  FILE* host = host_stream(guest_file);
  if (host) return host;
  return reinterpret_cast<FILE*>(uintptr_t(load<u64>(guest_file + 8)));
}
}  // namespace

void crt_fclose(CpuState* s, const u32* a) {
  FILE* f = file_of(a[0]);
  s->r[0] = (f && f != stdin && f != stdout && f != stderr) ? u32(std::fclose(f)) : 0;
}

void crt_fread(CpuState* s, const u32* a) {
  FILE* f = file_of(a[3]);
  if (!f) { s->r[0] = 0; return; }
  s->r[0] = u32(std::fread(gmem().chars() + a[0], a[1], a[2], f));
}

void crt_fwrite(CpuState* s, const u32* a) {
  FILE* f = file_of(a[3]);
  if (!f) { s->r[0] = 0; return; }
  s->r[0] = u32(std::fwrite(gmem().chars() + a[0], a[1], a[2], f));
}

void crt_fseek(CpuState* s, const u32* a) {
  FILE* f = file_of(a[0]);
  s->r[0] = f ? u32(std::fseek(f, long(a[1]), int(a[2]))) : 0xFFFFFFFFu;
}

void crt_ftell(CpuState* s, const u32* a) {
  FILE* f = file_of(a[0]);
  s->r[0] = f ? u32(std::ftell(f)) : 0xFFFFFFFFu;
}

void crt_fflush(CpuState* s, const u32* a) {
  FILE* f = file_of(a[0]);
  s->r[0] = f ? u32(std::fflush(f)) : 0;
}

void crt_feof(CpuState* s, const u32* a) {
  FILE* f = file_of(a[0]);
  s->r[0] = (f && std::feof(f)) ? 1 : 0;
}

void crt_ferror(CpuState* s, const u32* a) {
  FILE* f = file_of(a[0]);
  s->r[0] = (f && std::ferror(f)) ? 1 : 0;
}

void crt_fgets(CpuState* s, const u32* a) {
  FILE* f = file_of(a[2]);
  if (!f) { s->r[0] = 0; return; }
  char* r = std::fgets(reinterpret_cast<char*>(gmem().chars() + a[0]), int(a[1]), f);
  s->r[0] = r ? a[0] : 0;
}

void crt_fputs(CpuState* s, const u32* a) {
  FILE* f = file_of(a[1]);
  s->r[0] = f ? u32(std::fputs(cstr(a[0]), f)) : 0;
}

void crt_tmpfile(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_getch(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFFu; }

void crt_signal(CpuState* s, const u32*) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// wide-character helpers (Spore uses them for paths and locale)
// ---------------------------------------------------------------------------
void crt_wcslen(CpuState* s, const u32* a) {
  const char16_t* p = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  u32 n = 0;
  while (p[n]) ++n;
  s->r[0] = n;
}

void crt_wcscpy(CpuState* s, const u32* a) {
  char16_t* d = reinterpret_cast<char16_t*>(gmem().chars() + a[0]);
  const char16_t* ssrc = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  while ((*d++ = *ssrc++)) {}
  s->r[0] = a[0];
}

void crt_wcsncpy(CpuState* s, const u32* a) {
  char16_t* d = reinterpret_cast<char16_t*>(gmem().chars() + a[0]);
  const char16_t* ssrc = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  u32 n = a[2];
  u32 i = 0;
  for (; i < n && ssrc[i]; ++i) d[i] = ssrc[i];
  for (; i < n; ++i) d[i] = 0;
  s->r[0] = a[0];
}

void crt_wcscat(CpuState* s, const u32* a) {
  char16_t* d = reinterpret_cast<char16_t*>(gmem().chars() + a[0]);
  const char16_t* ssrc = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  while (*d) ++d;
  while ((*d++ = *ssrc++)) {}
  s->r[0] = a[0];
}

void crt_wcsncat(CpuState* s, const u32* a) {
  char16_t* d = reinterpret_cast<char16_t*>(gmem().chars() + a[0]);
  const char16_t* ssrc = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  u32 n = a[2];
  while (*d) ++d;
  for (u32 i = 0; i < n && ssrc[i]; ++i) *d++ = ssrc[i];
  *d = 0;
  s->r[0] = a[0];
}

void crt_wcscmp(CpuState* s, const u32* a) {
  const char16_t* x = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  const char16_t* y = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  while (*x && *x == *y) { ++x; ++y; }
  s->r[0] = u32(int(*x) - int(*y));
}

void crt_wcsncmp(CpuState* s, const u32* a) {
  const char16_t* x = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  const char16_t* y = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  u32 n = a[2];
  for (u32 i = 0; i < n; ++i) {
    if (x[i] != y[i]) { s->r[0] = u32(int(x[i]) - int(y[i])); return; }
    if (!x[i]) break;
  }
  s->r[0] = 0;
}

void crt_wcsicmp(CpuState* s, const u32* a) {
  const char16_t* x = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  const char16_t* y = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  while (*x && std::towlower(*x) == std::towlower(*y)) { ++x; ++y; }
  s->r[0] = u32(int(std::towlower(*x)) - int(std::towlower(*y)));
}

void crt_wcsnicmp(CpuState* s, const u32* a) {
  const char16_t* x = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  const char16_t* y = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  u32 n = a[2];
  for (u32 i = 0; i < n; ++i) {
    int a1 = std::towlower(x[i]), b1 = std::towlower(y[i]);
    if (a1 != b1) { s->r[0] = u32(a1 - b1); return; }
    if (!x[i]) break;
  }
  s->r[0] = 0;
}

void crt_wcschr(CpuState* s, const u32* a) {
  const char16_t* p = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  char16_t c = char16_t(a[1]);
  for (; *p; ++p) if (*p == c) { s->r[0] = u32(uintptr_t(p) - uintptr_t(gmem().base())); return; }
  s->r[0] = 0;
}

void crt_wcsrchr(CpuState* s, const u32* a) {
  const char16_t* p = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  char16_t c = char16_t(a[1]);
  const char16_t* last = nullptr;
  for (; *p; ++p) if (*p == c) last = p;
  s->r[0] = last ? u32(uintptr_t(last) - uintptr_t(gmem().base())) : 0;
}

void crt_wcsstr(CpuState* s, const u32* a) {
  const char16_t* hay = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  const char16_t* needle = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  for (const char16_t* p = hay; *p; ++p) {
    const char16_t* x = p; const char16_t* y = needle;
    while (*x && *y && *x == *y) { ++x; ++y; }
    if (!*y) { s->r[0] = u32(uintptr_t(p) - uintptr_t(gmem().base())); return; }
  }
  s->r[0] = 0;
}

void crt_wcscspn(CpuState* s, const u32* a) {
  const char16_t* x = reinterpret_cast<const char16_t*>(gmem().chars() + a[0]);
  const char16_t* set = reinterpret_cast<const char16_t*>(gmem().chars() + a[1]);
  u32 n = 0;
  for (; x[n]; ++n) {
    bool found = false;
    for (const char16_t* p = set; *p; ++p) if (*p == x[n]) { found = true; break; }
    if (found) break;
  }
  s->r[0] = n;
}

void crt_wcslwr(CpuState* s, const u32* a) {
  char16_t* p = reinterpret_cast<char16_t*>(gmem().chars() + a[0]);
  for (; *p; ++p) *p = char16_t(std::towlower(*p));
  s->r[0] = a[0];
}

void crt_wtoupper(CpuState* s, const u32* a) { s->r[0] = u32(std::towupper(a[0])); }
void crt_towlower(CpuState* s, const u32* a) { s->r[0] = u32(std::towlower(a[0])); }
void crt_iswctype(CpuState* s, const u32* a) { s->r[0] = 1; }

void crt_wcstol(CpuState* s, const u32* a) {
  std::string tmp = wstr_utf8(a[0]);
  s->r[0] = u32(std::strtol(tmp.c_str(), nullptr, int(a[2])));
}

void crt_wcstoul(CpuState* s, const u32* a) {
  std::string tmp = wstr_utf8(a[0]);
  s->r[0] = u32(std::strtoul(tmp.c_str(), nullptr, int(a[2])));
}

void crt_wcstod(CpuState* s, const u32* a) {
  std::string tmp = wstr_utf8(a[0]);
  x87_push(s, std::strtod(tmp.c_str(), nullptr));
  s->r[0] = 0;
}

void crt_wtol(CpuState* s, const u32* a) {
  std::string tmp = wstr_utf8(a[0]);
  s->r[0] = u32(std::strtol(tmp.c_str(), nullptr, 10));
}

void crt_ltow(CpuState* s, const u32* a) {
  char buf[64];
  std::snprintf(buf, sizeof buf, "%ld", long(a[0]));
  write_wstr(a[1], buf, 64);
  s->r[0] = a[1];
}

void crt_ultow(CpuState* s, const u32* a) {
  char buf[64];
  std::snprintf(buf, sizeof buf, "%lu", (unsigned long)a[0]);
  write_wstr(a[1], buf, 64);
  s->r[0] = a[1];
}

void crt_wgetcwd(CpuState* s, const u32* a) {
  s->r[0] = write_wstr(a[0], shim::config().game_dir.c_str(), a[1]);
}

void crt_wgetdcwd(CpuState* s, const u32* a) {
  s->r[0] = write_wstr(a[1], shim::config().game_dir.c_str(), a[2]);
}

void crt_getdrive(CpuState* s, const u32*) { s->r[0] = 3; }
void crt_searchenv(CpuState* s, const u32* a) { write_cstr(a[2], ""); s->r[0] = 0; }
void crt_wsearchenv(CpuState* s, const u32* a) { s->r[0] = 0; }

void crt_stat64i32(CpuState* s, const u32* a) {
  // _stat64i32(path, struct_stat*): Spore checks whether files exist.
  std::string p = to_host_path(cstr(a[0]));
  struct stat st;
  if (stat(p.c_str(), &st) != 0) { s->r[0] = 0xFFFFFFFFu; return; }
  u32 out = a[1];
  if (out) {
    store<u32>(out + 0, u32(st.st_dev));
    store<u16>(out + 4, u16(st.st_ino));
    store<u16>(out + 6, u16(st.st_mode));
    store<s16>(out + 8, s16(st.st_nlink));
    store<s16>(out + 10, 0);
    store<s16>(out + 12, 0);
    store<s32>(out + 16, s32(st.st_size));
    store<s32>(out + 20, s32(st.st_mtime));
  }
  s->r[0] = 0;
}

void crt_wstat64i32(CpuState* s, const u32* a) {
  std::string p = to_host_path(wstr_utf8(a[0]));
  struct stat st;
  if (stat(p.c_str(), &st) != 0) { s->r[0] = 0xFFFFFFFFu; return; }
  u32 out = a[1];
  if (out) {
    store<u32>(out + 0, u32(st.st_dev));
    store<u16>(out + 6, u16(st.st_mode));
    store<s32>(out + 16, s32(st.st_size));
    store<s32>(out + 20, s32(st.st_mtime));
  }
  s->r[0] = 0;
}

void crt_beginthreadex(CpuState* s, const u32* a) {
  SR_LOG("_beginthreadex start=0x%08x arg=0x%08x", a[2], a[3]);
  if (a[5]) store<u32>(a[5], 1);
  s->r[0] = 4;
}

void crt_spawnv(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFFu; }
void crt_wspawnv(CpuState* s, const u32*) { s->r[0] = 0xFFFFFFFFu; }

// ---------------------------------------------------------------------------
// character classification
// ---------------------------------------------------------------------------
#define CRT_CTYPE(name, fn) \
  void name(CpuState* s, const u32* a) { s->r[0] = fn(int(a[0])) ? 1 : 0; }
CRT_CTYPE(crt_isalpha, std::isalpha)
CRT_CTYPE(crt_isdigit, std::isdigit)
CRT_CTYPE(crt_isspace, std::isspace)
CRT_CTYPE(crt_isalnum, std::isalnum)
CRT_CTYPE(crt_isupper, std::isupper)
CRT_CTYPE(crt_isprint, std::isprint)
CRT_CTYPE(crt_isxdigit, std::isxdigit)
CRT_CTYPE(crt_islower, std::islower)

void crt_toupper(CpuState* s, const u32* a) { s->r[0] = u32(std::toupper(int(a[0]))); }
void crt_tolower(CpuState* s, const u32* a) { s->r[0] = u32(std::tolower(int(a[0]))); }
void crt_setlocale(CpuState* s, const u32*) { s->r[0] = 0; }
void crt_getenv(CpuState* s, const u32* a) {
  static u32 buf = 0;
  const char* v = std::getenv(cstr(a[0]));
  if (!v) { s->r[0] = 0; return; }
  if (!buf) buf = gmem().heap_alloc(512);
  write_cstr(buf, v);
  s->r[0] = buf;
}

void crt_setjmp3(CpuState* s, const u32* a) {
  // _setjmp3(buf, count, ...) — stores the register set in the guest buffer.
  u32 buf = a[0];
  store<u32>(buf + 0, s->r[5]);   // ebp
  store<u32>(buf + 4, s->r[3]);   // ebx
  store<u32>(buf + 8, s->r[6]);   // esi
  store<u32>(buf + 12, s->r[7]);  // edi
  store<u32>(buf + 16, load<u32>(s->r[4]));  // return address
  store<u32>(buf + 20, s->r[4] + 4);         // esp after return
  s->r[0] = 0;
}

void crt_longjmp(CpuState* s, const u32* a) {
  u32 buf = a[0];
  s->r[5] = load<u32>(buf + 0);
  s->r[3] = load<u32>(buf + 4);
  s->r[6] = load<u32>(buf + 8);
  s->r[7] = load<u32>(buf + 12);
  u32 ret = load<u32>(buf + 16);
  s->r[4] = load<u32>(buf + 20);
  s->r[0] = a[1] ? a[1] : 1;
  guest_return(s, ret);
}

}  // namespace sr::w32





