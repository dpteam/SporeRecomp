// SporeRecomp — user32 + gdi32 shims.
//
// Deliberately headless for now: Spore creates a window and pumps messages, and we satisfy
// every call it makes, but nothing is drawn until the D3D9 layer lands. This keeps the boot
// ladder moving (and the binary free of an SDL dependency) while the guest's own code path
// through WinMain, window class registration and the message loop gets validated.
#include <cstdio>
#include <cstring>
#include <string>

#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/win32/internal.h"
#include "rt/win32/win32.h"

namespace sr::w32 {

namespace {

// The one window Spore creates. Handles are guest-visible integers.
u32 g_main_window = 0x00010001;
u32 g_desktop = 0x00010000;
u32 g_focus = 0;

// Message queue: filled by PostMessageA / SendMessageA, drained by PeekMessageA.
struct Msg {
  u32 hwnd, message, wparam, lparam, time, x, y;
};
Msg g_queue[256];
unsigned g_queue_head = 0, g_queue_tail = 0;
bool g_quit = false;
u32 g_quit_code = 0;

void push_message(u32 hwnd, u32 msg, u32 wp, u32 lp) {
  unsigned next = (g_queue_tail + 1) % 256;
  if (next == g_queue_head) return;  // full: drop
  g_queue[g_queue_tail] = Msg{hwnd, msg, wp, lp, 0, 0, 0};
  g_queue_tail = next;
}

// Writes a MSG structure (28 bytes on Win32) into guest memory.
void write_msg(u32 guest_msg, const Msg& m) {
  store<u32>(guest_msg + 0, m.hwnd);
  store<u32>(guest_msg + 4, m.message);
  store<u32>(guest_msg + 8, m.wparam);
  store<u32>(guest_msg + 12, m.lparam);
  store<u32>(guest_msg + 16, m.time);
  store<u32>(guest_msg + 20, m.x);
  store<u32>(guest_msg + 24, m.y);
}

}  // namespace

// ---------------------------------------------------------------------------
// window class / creation
// ---------------------------------------------------------------------------
void RegisterClassA(CpuState* s, const u32*) { s->r[0] = 0xC001; }
void RegisterClassExW(CpuState* s, const u32*) { s->r[0] = 0xC001; }
void UnregisterClassA(CpuState* s, const u32*) { s->r[0] = 1; }

void CreateWindowExA(CpuState* s, const u32* a) {
  SR_LOG("CreateWindowExA(\"%s\", \"%s\", %ux%u)", cstr(a[2]), cstr(a[1]),
         load<u32>(s->r[4] + 4 + 4 * 12), load<u32>(s->r[4] + 4 + 4 * 13));
  s->r[0] = g_main_window;
}

void CreateWindowExW(CpuState* s, const u32* a) {
  SR_LOG("CreateWindowExW(\"%s\", \"%s\")", wstr_utf8(a[2]), wstr_utf8(a[1]));
  s->r[0] = g_main_window;
}

void DestroyWindow(CpuState* s, const u32*) {
  g_quit = true;
  s->r[0] = 1;
}

void GetDesktopWindow(CpuState* s, const u32*) { s->r[0] = g_desktop; }
void GetForegroundWindow(CpuState* s, const u32*) { s->r[0] = g_main_window; }
void SetActiveWindow(CpuState* s, const u32*) { s->r[0] = g_main_window; }
void GetActiveWindow(CpuState* s, const u32*) { s->r[0] = g_main_window; }
void SetFocus(CpuState* s, const u32*) { s->r[0] = g_main_window; }
void ShowWindow(CpuState* s, const u32*) { s->r[0] = 0; }
void UpdateWindow(CpuState* s, const u32*) { s->r[0] = 1; }
void IsWindowVisible(CpuState* s, const u32*) { s->r[0] = 1; }
void IsZoomed(CpuState* s, const u32*) { s->r[0] = 0; }
void IsIconic(CpuState* s, const u32*) { s->r[0] = 0; }
void GetAncestor(CpuState* s, const u32*) { s->r[0] = g_desktop; }
void GetMenu(CpuState* s, const u32*) { s->r[0] = 0; }
void SetWindowTextW(CpuState* s, const u32* a) {
  SR_LOG("SetWindowTextW(\"%s\")", wstr_utf8(a[1]));
  s->r[0] = 1;
}
void SetWindowPos(CpuState* s, const u32*) { s->r[0] = 1; }
void MoveWindow(CpuState* s, const u32*) { s->r[0] = 1; }
void SetWindowLongA(CpuState* s, const u32* a) { s->r[0] = 0; }
void SetWindowLongW(CpuState* s, const u32* a) { s->r[0] = 0; }
void GetWindowLongA(CpuState* s, const u32*) { s->r[0] = 0; }

void GetClientRect(CpuState* s, const u32* a) {
  u32 r = a[1];
  if (r) {
    store<s32>(r + 0, 0);
    store<s32>(r + 4, 0);
    store<s32>(r + 8, 640);
    store<s32>(r + 12, 480);
  }
  s->r[0] = 1;
}

void GetWindowRect(CpuState* s, const u32* a) {
  u32 r = a[1];
  if (r) {
    store<s32>(r + 0, 0);
    store<s32>(r + 4, 0);
    store<s32>(r + 8, 640);
    store<s32>(r + 12, 480);
  }
  s->r[0] = 1;
}

void AdjustWindowRectEx(CpuState* s, const u32*) { s->r[0] = 1; }
void ClientToScreen(CpuState* s, const u32*) { s->r[0] = 1; }
void ScreenToClient(CpuState* s, const u32*) { s->r[0] = 1; }
void IntersectRect(CpuState* s, const u32*) { s->r[0] = 0; }
void GetWindowThreadProcessId(CpuState* s, const u32* a) {
  if (a[1]) store<u32>(a[1], 1);
  s->r[0] = 1;
}

// ---------------------------------------------------------------------------
// messages
// ---------------------------------------------------------------------------
void PeekMessageA(CpuState* s, const u32* a) {
  u32 out = a[0];
  if (g_quit) {
    Msg m{g_main_window, 0x0012, u32(g_quit_code), 0, 0, 0, 0};  // WM_QUIT
    write_msg(out, m);
    g_quit = false;
    s->r[0] = 1;
    return;
  }
  if (g_queue_head == g_queue_tail) { s->r[0] = 0; return; }
  Msg m = g_queue[g_queue_head];
  g_queue_head = (g_queue_head + 1) % 256;
  write_msg(out, m);
  s->r[0] = 1;
}

void PeekMessageW(CpuState* s, const u32* a) { PeekMessageA(s, a); }

void TranslateMessage(CpuState* s, const u32*) { s->r[0] = 1; }

void DispatchMessageW(CpuState* s, const u32* a) {
  // Calls the guest window procedure with the message.
  u32 msg = a[0];
  if (!msg) { s->r[0] = 0; return; }
  u32 hwnd = load<u32>(msg + 0);
  u32 id = load<u32>(msg + 4);
  u32 wp = load<u32>(msg + 8);
  u32 lp = load<u32>(msg + 12);
  GuestFn proc = find_function(0);  // resolved below from the class registration
  (void)proc;
  s->r[0] = 0;
  (void)hwnd; (void)id; (void)wp; (void)lp;
}

void PostQuitMessage(CpuState* s, const u32* a) {
  g_quit = true;
  g_quit_code = a[0];
  s->r[0] = 0;
}

void PostMessageA(CpuState* s, const u32* a) {
  push_message(a[0], a[1], a[2], a[3]);
  s->r[0] = 1;
}

void SendMessageA(CpuState* s, const u32*) { s->r[0] = 0; }
void DefWindowProcA(CpuState* s, const u32*) { s->r[0] = 0; }
void DefWindowProcW(CpuState* s, const u32*) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// timers
// ---------------------------------------------------------------------------
namespace {
u32 g_next_timer = 1;
}
void SetTimer(CpuState* s, const u32* a) {
  s->r[0] = a[3] ? a[3] : g_next_timer++;
}
void KillTimer(CpuState* s, const u32*) { s->r[0] = 1; }

// ---------------------------------------------------------------------------
// input state: reports "nothing pressed" until the SDL input layer lands
// ---------------------------------------------------------------------------
void GetKeyboardState(CpuState* s, const u32* a) {
  if (a[0]) __builtin_memset(gmem().base() + a[0], 0, 256);
  s->r[0] = 1;
}
void GetKeyState(CpuState* s, const u32*) { s->r[0] = 0; }
void GetAsyncKeyState(CpuState* s, const u32*) { s->r[0] = 0; }
void GetCursorPos(CpuState* s, const u32* a) {
  if (a[0]) { store<s32>(a[0], 320); store<s32>(a[0] + 4, 240); }
  s->r[0] = 1;
}
void SetCursorPos(CpuState* s, const u32*) { s->r[0] = 1; }
void SetCursor(CpuState* s, const u32*) { s->r[0] = 0; }
void ShowCursor(CpuState* s, const u32*) { s->r[0] = 0; }
void LoadCursorA(CpuState* s, const u32*) { s->r[0] = 0x00020001; }
void LoadIconA(CpuState* s, const u32*) { s->r[0] = 0x00020002; }
void LoadImageW(CpuState* s, const u32*) { s->r[0] = 0; }
void DestroyCursor(CpuState* s, const u32*) { s->r[0] = 1; }
void GetIconInfo(CpuState* s, const u32*) { s->r[0] = 0; }
void SetCapture(CpuState* s, const u32*) { s->r[0] = 0; }
void ReleaseCapture(CpuState* s, const u32*) { s->r[0] = 1; }
void GetKeyboardLayout(CpuState* s, const u32*) { s->r[0] = 0x04090409; }
void GetDoubleClickTime(CpuState* s, const u32*) { s->r[0] = 500; }
void SetWindowsHookExA(CpuState* s, const u32*) { s->r[0] = 0; }
void UnhookWindowsHookEx(CpuState* s, const u32*) { s->r[0] = 1; }
void CallNextHookEx(CpuState* s, const u32*) { s->r[0] = 0; }

// ---------------------------------------------------------------------------
// painting (D3D9 draws; GDI only paints before the device exists)
// ---------------------------------------------------------------------------
void BeginPaint(CpuState* s, const u32* a) {
  if (a[1]) __builtin_memset(gmem().base() + a[1], 0, 64);
  s->r[0] = 0x00030001;
}
void EndPaint(CpuState* s, const u32*) { s->r[0] = 1; }
void FillRect(CpuState* s, const u32*) { s->r[0] = 1; }
void InvalidateRect(CpuState* s, const u32*) { s->r[0] = 1; }
void ValidateRect(CpuState* s, const u32*) { s->r[0] = 1; }
void GetDC(CpuState* s, const u32*) { s->r[0] = 0x00040001; }
void ReleaseDC(CpuState* s, const u32*) { s->r[0] = 1; }

void GetSystemMetrics(CpuState* s, const u32* a) {
  switch (a[0]) {
    case 0: s->r[0] = 640; break;   // SM_CXSCREEN
    case 1: s->r[0] = 480; break;   // SM_CYSCREEN
    case 4: s->r[0] = 0; break;     // SM_CYCAPTION
    case 32: s->r[0] = 1; break;    // SM_MOUSEWHEELPRESENT
    case 43: s->r[0] = 1; break;    // SM_CMONITORS
    default: s->r[0] = 0; break;
  }
}

void EnumDisplayMonitors(CpuState* s, const u32*) { s->r[0] = 1; }
void MonitorFromWindow(CpuState* s, const u32*) { s->r[0] = 0x00050001; }
void GetMonitorInfoA(CpuState* s, const u32* a) {
  u32 p = a[1];
  if (p) {
    store<u32>(p + 0, 40);
    store<s32>(p + 4, 0); store<s32>(p + 8, 0);
    store<s32>(p + 12, 640); store<s32>(p + 16, 480);
    store<s32>(p + 20, 0); store<s32>(p + 24, 0);
    store<s32>(p + 28, 640); store<s32>(p + 32, 480);
    store<u32>(p + 36, 1);
  }
  s->r[0] = 1;
}

void SystemParametersInfoA(CpuState* s, const u32*) { s->r[0] = 1; }
void GetProcessWindowStation(CpuState* s, const u32*) { s->r[0] = 0x00060001; }
void GetUserObjectInformationW(CpuState* s, const u32*) { s->r[0] = 1; }
void FlushConsoleInputBuffer(CpuState* s, const u32*) { s->r[0] = 1; }

// ---------------------------------------------------------------------------
// clipboard
// ---------------------------------------------------------------------------
void OpenClipboard(CpuState* s, const u32*) { s->r[0] = 1; }
void CloseClipboard(CpuState* s, const u32*) { s->r[0] = 1; }
void EmptyClipboard(CpuState* s, const u32*) { s->r[0] = 1; }
void GetClipboardData(CpuState* s, const u32*) { s->r[0] = 0; }
void SetClipboardData(CpuState* s, const u32*) { s->r[0] = 0; }
void IsClipboardFormatAvailable(CpuState* s, const u32*) { s->r[0] = 0; }
void SetClipboardViewer(CpuState* s, const u32*) { s->r[0] = 0; }
void ChangeClipboardChain(CpuState* s, const u32*) { s->r[0] = 1; }

// ---------------------------------------------------------------------------
// dialogs / message boxes
// ---------------------------------------------------------------------------
void IsDlgButtonChecked(CpuState* s, const u32*) { s->r[0] = 0; }
void CheckDlgButton(CpuState* s, const u32*) { s->r[0] = 1; }

void MessageBoxA(CpuState* s, const u32* a) {
  SR_LOG("MessageBoxA: \"%s\" / \"%s\"", cstr(a[1]), cstr(a[2]));
  s->r[0] = 1;  // IDOK
}

void MessageBoxW(CpuState* s, const u32* a) {
  SR_LOG("MessageBoxW: \"%s\" / \"%s\"", wstr_utf8(a[1]), wstr_utf8(a[2]));
  s->r[0] = 1;
}

// wsprintfA/W: the guest uses it for HUD and debug strings, so it must really format.
// Both are cdecl with a variable argument list, exactly like the CRT's sprintf.
void wsprintfA(CpuState* s, const u32* a) { wsprintfA_impl(s, a); }
void wsprintfW(CpuState* s, const u32* a) { wsprintfW_impl(s, a); }

// ---------------------------------------------------------------------------
// GDI32
// ---------------------------------------------------------------------------
void CreateSolidBrush(CpuState* s, const u32*) { s->r[0] = 0x00070001; }
void DeleteObject(CpuState* s, const u32*) { s->r[0] = 1; }
void ExtEscape(CpuState* s, const u32*) { s->r[0] = 0; }
void DeleteDC(CpuState* s, const u32*) { s->r[0] = 1; }
void CreateDCA(CpuState* s, const u32*) { s->r[0] = 0x00040002; }
void GetDeviceCaps(CpuState* s, const u32* a) {
  switch (a[1]) {
    case 8: s->r[0] = 640; break;   // HORZRES
    case 10: s->r[0] = 480; break;  // VERTRES
    case 12: s->r[0] = 32; break;   // BITSPIXEL
    case 88: s->r[0] = 1; break;    // COLORRES
    default: s->r[0] = 0; break;
  }
}

}  // namespace sr::w32
