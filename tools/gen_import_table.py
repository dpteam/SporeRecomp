"""Emits src/rt/imports_table.cpp: the descriptor table the runtime dispatches through.

Input:  analysis/imports_resolved.json  (nargs + calling convention inferred from call sites)
        the IMPL map below               (which host function implements what)

Every import in the PE appears in the output exactly once. Imports without an implementation
get `nullptr`, which the runtime logs when called — that is how we find the next thing to
implement instead of guessing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from import_sig import SIG  # noqa: E402

# D3D / D3DX / DInput / DSound / Winsock signatures.
EXTRA_SIG = {
    ("d3d9.dll", "Direct3DCreate9"): (1, True),
    ("d3dx9_27.dll", "D3DXCheckVersion"): (2, True),
    ("d3dx9_27.dll", "D3DXGetPixelShaderProfile"): (1, True),
    ("d3dx9_27.dll", "D3DXGetVertexShaderProfile"): (1, True),
    ("d3dx9_27.dll", "D3DXCompileShader"): (10, True),
    ("d3dx9_27.dll", "D3DXMatrixMultiply"): (3, True),
    ("d3dx9_27.dll", "D3DXMatrixMultiplyTranspose"): (3, True),
    ("d3dx9_27.dll", "D3DXMatrixTranspose"): (2, True),
    ("d3dx9_27.dll", "D3DXVec3Transform"): (3, True),
    ("d3dx9_27.dll", "D3DXVec3TransformNormal"): (3, True),
    ("DINPUT8.dll", "DirectInput8Create"): (5, True),
    ("DSOUND.dll", "#1"): (3, True),
    ("DSOUND.dll", "#9"): (0, True),
}
SIG.update(EXTRA_SIG)

RESOLVED = Path("analysis/imports_resolved.json")
OUT = Path("src/rt/imports_table.cpp")

# (dll, name) -> C++ function name in namespace sr::w32
IMPL = {
    # ---- kernel32: memory ----
    ("KERNEL32.dll", "GetProcessHeap"): "GetProcessHeap",
    ("KERNEL32.dll", "HeapAlloc"): "HeapAlloc",
    ("KERNEL32.dll", "HeapFree"): "HeapFree",
    ("KERNEL32.dll", "VirtualAlloc"): "VirtualAlloc",
    ("KERNEL32.dll", "VirtualFree"): "VirtualFree",
    ("KERNEL32.dll", "VirtualQuery"): "VirtualQuery",
    ("KERNEL32.dll", "GlobalAlloc"): "GlobalAlloc",
    ("KERNEL32.dll", "GlobalFree"): "GlobalFree",
    ("KERNEL32.dll", "GlobalLock"): "GlobalLock",
    ("KERNEL32.dll", "GlobalUnlock"): "GlobalUnlock",
    ("KERNEL32.dll", "GlobalSize"): "GlobalSize",
    ("KERNEL32.dll", "LocalAlloc"): "LocalAlloc",
    ("KERNEL32.dll", "LocalFree"): "LocalFree",
    ("KERNEL32.dll", "GlobalMemoryStatusEx"): "GlobalMemoryStatusEx",
    ("KERNEL32.dll", "GlobalMemoryStatus"): "GlobalMemoryStatus",
    # ---- kernel32: time ----
    ("KERNEL32.dll", "QueryPerformanceFrequency"): "QueryPerformanceFrequency",
    ("KERNEL32.dll", "QueryPerformanceCounter"): "QueryPerformanceCounter",
    ("KERNEL32.dll", "GetTickCount"): "GetTickCount",
    ("KERNEL32.dll", "GetSystemTimeAsFileTime"): "GetSystemTimeAsFileTime",
    ("KERNEL32.dll", "GetSystemTime"): "GetSystemTime",
    ("KERNEL32.dll", "SystemTimeToFileTime"): "SystemTimeToFileTime",
    # ---- kernel32: version / system ----
    ("KERNEL32.dll", "GetVersionExA"): "GetVersionExA",
    ("KERNEL32.dll", "GetVersionExW"): "GetVersionExW",
    ("KERNEL32.dll", "GetVersion"): "GetVersion",
    ("KERNEL32.dll", "GetSystemInfo"): "GetSystemInfo",
    ("KERNEL32.dll", "GetSystemDirectoryW"): "GetSystemDirectoryW",
    ("KERNEL32.dll", "GetWindowsDirectoryW"): "GetWindowsDirectoryW",
    ("KERNEL32.dll", "GetTempPathW"): "GetTempPathW",
    ("KERNEL32.dll", "GetModuleFileNameA"): "GetModuleFileNameA",
    ("KERNEL32.dll", "GetModuleFileNameW"): "GetModuleFileNameW",
    ("KERNEL32.dll", "GetModuleHandleA"): "GetModuleHandleA",
    ("KERNEL32.dll", "GetModuleHandleW"): "GetModuleHandleW",
    ("KERNEL32.dll", "GetProcAddress"): "GetProcAddress",
    ("KERNEL32.dll", "GetCommandLineA"): "GetCommandLineA",
    ("KERNEL32.dll", "GetCurrentProcess"): "GetCurrentProcess",
    ("KERNEL32.dll", "GetCurrentProcessId"): "GetCurrentProcessId",
    ("KERNEL32.dll", "GetCurrentThread"): "GetCurrentThread",
    ("KERNEL32.dll", "GetCurrentThreadId"): "GetCurrentThreadId",
    ("KERNEL32.dll", "GetLastError"): "GetLastError",
    ("KERNEL32.dll", "SetLastError"): "SetLastError",
    ("KERNEL32.dll", "IsDebuggerPresent"): "IsDebuggerPresent",
    ("KERNEL32.dll", "OutputDebugStringA"): "OutputDebugStringA",
    ("KERNEL32.dll", "GetACP"): "GetACP",
    ("KERNEL32.dll", "GetStartupInfoA"): "GetStartupInfoA",
    ("KERNEL32.dll", "GetEnvironmentVariableA"): "GetEnvironmentVariableA",
    ("KERNEL32.dll", "SetEnvironmentVariableA"): "SetEnvironmentVariableA",
    ("KERNEL32.dll", "GetCurrentDirectoryA"): "GetCurrentDirectoryA",
    ("KERNEL32.dll", "GetFullPathNameA"): "GetFullPathNameA",
    ("KERNEL32.dll", "GetFullPathNameW"): "GetFullPathNameW",
    ("KERNEL32.dll", "GetComputerNameA"): "GetComputerNameA",
    ("KERNEL32.dll", "GetComputerNameExA"): "GetComputerNameExA",
    ("KERNEL32.dll", "GetLocaleInfoW"): "GetLocaleInfoW",
    ("KERNEL32.dll", "GetSystemDefaultLCID"): "GetSystemDefaultLCID",
    ("KERNEL32.dll", "CompareStringW"): "CompareStringW",
    ("KERNEL32.dll", "LCMapStringW"): "LCMapStringW",
    ("KERNEL32.dll", "MultiByteToWideChar"): "MultiByteToWideChar",
    ("KERNEL32.dll", "WideCharToMultiByte"): "WideCharToMultiByte",
    ("KERNEL32.dll", "Sleep"): "Sleep",
    ("KERNEL32.dll", "SleepEx"): "SleepEx",
    ("KERNEL32.dll", "SetThreadExecutionState"): "SetThreadExecutionState",
    ("KERNEL32.dll", "FormatMessageA"): "FormatMessageA",
    ("KERNEL32.dll", "GetStdHandle"): "GetStdHandle",
    ("KERNEL32.dll", "GetFileType"): "GetFileType",
    ("KERNEL32.dll", "SetUnhandledExceptionFilter"): "SetUnhandledExceptionFilter",
    ("KERNEL32.dll", "UnhandledExceptionFilter"): "UnhandledExceptionFilter",
    ("KERNEL32.dll", "RaiseException"): "RaiseException",
    ("KERNEL32.dll", "TerminateProcess"): "TerminateProcess",
    ("KERNEL32.dll", "GetExitCodeThread"): "GetExitCodeThread",
    ("KERNEL32.dll", "GetProcessTimes"): "GetProcessTimes",
    # ---- kernel32: sync / threads / TLS ----
    ("KERNEL32.dll", "InitializeCriticalSection"): "InitializeCriticalSection",
    ("KERNEL32.dll", "InitializeCriticalSectionAndSpinCount"): "InitializeCriticalSectionAndSpinCount",
    ("KERNEL32.dll", "DeleteCriticalSection"): "DeleteCriticalSection",
    ("KERNEL32.dll", "EnterCriticalSection"): "EnterCriticalSection",
    ("KERNEL32.dll", "LeaveCriticalSection"): "LeaveCriticalSection",
    ("KERNEL32.dll", "TryEnterCriticalSection"): "TryEnterCriticalSection",
    ("KERNEL32.dll", "InterlockedIncrement"): "InterlockedIncrement",
    ("KERNEL32.dll", "InterlockedDecrement"): "InterlockedDecrement",
    ("KERNEL32.dll", "InterlockedExchange"): "InterlockedExchange",
    ("KERNEL32.dll", "InterlockedExchangeAdd"): "InterlockedExchangeAdd",
    ("KERNEL32.dll", "InterlockedCompareExchange"): "InterlockedCompareExchange",
    ("KERNEL32.dll", "CreateEventA"): "CreateEventA",
    ("KERNEL32.dll", "SetEvent"): "SetEvent",
    ("KERNEL32.dll", "CreateMutexA"): "CreateMutexA",
    ("KERNEL32.dll", "ReleaseMutex"): "ReleaseMutex",
    ("KERNEL32.dll", "CreateSemaphoreA"): "CreateSemaphoreA",
    ("KERNEL32.dll", "ReleaseSemaphore"): "ReleaseSemaphore",
    ("KERNEL32.dll", "WaitForSingleObject"): "WaitForSingleObject",
    ("KERNEL32.dll", "WaitForMultipleObjects"): "WaitForMultipleObjects",
    ("KERNEL32.dll", "WaitForMultipleObjectsEx"): "WaitForMultipleObjectsEx",
    ("KERNEL32.dll", "CloseHandle"): "CloseHandle",
    ("KERNEL32.dll", "DuplicateHandle"): "DuplicateHandle",
    ("KERNEL32.dll", "CreateThread"): "CreateThread",
    ("KERNEL32.dll", "ResumeThread"): "ResumeThread",
    ("KERNEL32.dll", "SetThreadPriority"): "SetThreadPriority",
    ("KERNEL32.dll", "GetThreadPriority"): "GetThreadPriority",
    ("KERNEL32.dll", "SetPriorityClass"): "SetPriorityClass",
    ("KERNEL32.dll", "GetPriorityClass"): "GetPriorityClass",
    ("KERNEL32.dll", "SetThreadAffinityMask"): "SetThreadAffinityMask",
    ("KERNEL32.dll", "GetProcessAffinityMask"): "GetProcessAffinityMask",
    ("KERNEL32.dll", "SetProcessAffinityMask"): "SetProcessAffinityMask",
    ("KERNEL32.dll", "SetThreadIdealProcessor"): "SetThreadIdealProcessor",
    ("KERNEL32.dll", "QueueUserAPC"): "QueueUserAPC",
    ("KERNEL32.dll", "OpenProcess"): "OpenProcess",
    ("KERNEL32.dll", "TlsAlloc"): "TlsAlloc",
    ("KERNEL32.dll", "TlsFree"): "TlsFree",
    ("KERNEL32.dll", "TlsSetValue"): "TlsSetValue",
    ("KERNEL32.dll", "TlsGetValue"): "TlsGetValue",
    # ---- kernel32: files ----
    ("KERNEL32.dll", "CreateFileA"): "CreateFileA",
    ("KERNEL32.dll", "CreateFileW"): "CreateFileW",
    ("KERNEL32.dll", "ReadFile"): "ReadFile",
    ("KERNEL32.dll", "WriteFile"): "WriteFile",
    ("KERNEL32.dll", "SetFilePointer"): "SetFilePointer",
    ("KERNEL32.dll", "GetFileSize"): "GetFileSize",
    ("KERNEL32.dll", "SetEndOfFile"): "SetEndOfFile",
    ("KERNEL32.dll", "FlushFileBuffers"): "FlushFileBuffers",
    ("KERNEL32.dll", "DeleteFileA"): "DeleteFileA",
    ("KERNEL32.dll", "DeleteFileW"): "DeleteFileW",
    ("KERNEL32.dll", "MoveFileA"): "MoveFileA",
    ("KERNEL32.dll", "MoveFileExW"): "MoveFileExW",
    ("KERNEL32.dll", "CopyFileW"): "CopyFileW",
    ("KERNEL32.dll", "GetFileAttributesW"): "GetFileAttributesW",
    ("KERNEL32.dll", "SetFileAttributesW"): "SetFileAttributesW",
    ("KERNEL32.dll", "CreateDirectoryA"): "CreateDirectoryA",
    ("KERNEL32.dll", "CreateDirectoryW"): "CreateDirectoryW",
    ("KERNEL32.dll", "RemoveDirectoryA"): "RemoveDirectoryA",
    ("KERNEL32.dll", "RemoveDirectoryW"): "RemoveDirectoryW",
    ("KERNEL32.dll", "GetLongPathNameW"): "GetLongPathNameW",
    ("KERNEL32.dll", "GetVolumeInformationW"): "GetVolumeInformationW",
    ("KERNEL32.dll", "GetVolumeInformationA"): "GetVolumeInformationA",
    ("KERNEL32.dll", "GetVolumePathNameW"): "GetVolumePathNameW",
    ("KERNEL32.dll", "GetDiskFreeSpaceExA"): "GetDiskFreeSpaceExA",
    ("KERNEL32.dll", "GetDriveTypeA"): "GetDriveTypeA",
    ("KERNEL32.dll", "GetLogicalDrives"): "GetLogicalDrives",
    ("KERNEL32.dll", "FindFirstFileA"): "FindFirstFileA",
    ("KERNEL32.dll", "FindFirstFileW"): "FindFirstFileW",
    ("KERNEL32.dll", "FindNextFileW"): "FindNextFileW",
    ("KERNEL32.dll", "FindClose"): "FindClose",
    ("KERNEL32.dll", "FindFirstChangeNotificationW"): "FindFirstChangeNotificationW",
    ("KERNEL32.dll", "FindNextChangeNotification"): "FindNextChangeNotification",
    ("KERNEL32.dll", "FindCloseChangeNotification"): "FindCloseChangeNotification",
    ("KERNEL32.dll", "CancelIo"): "CancelIo",
    ("KERNEL32.dll", "DeviceIoControl"): "DeviceIoControl",
    ("KERNEL32.dll", "EnumResourceNamesA"): "EnumResourceNamesA",
    ("KERNEL32.dll", "LoadLibraryA"): "LoadLibraryA",
    ("KERNEL32.dll", "LoadLibraryW"): "LoadLibraryW",
    ("KERNEL32.dll", "FreeLibrary"): "FreeLibrary",
}

# ---- MSVCR90 ----
MSVCR = {
    "malloc": "crt_malloc", "free": "crt_free", "realloc": "crt_realloc",
    "_aligned_malloc": "crt_aligned_malloc", "_aligned_free": "crt_aligned_free",
    "_aligned_realloc": "crt_aligned_realloc",
    "_initterm": "crt_initterm", "_initterm_e": "crt_initterm_e",
    "__getmainargs": "crt_getmainargs", "__iob_func": "crt_iob_func",
    "_acmdln": "crt_acmdln", "__p__fmode": "crt_p_fmode", "__p__commode": "crt_p_commode",
    "_errno": "crt_errno",
    "__set_app_type": "crt_set_app_type", "__setusermatherr": "crt_setusermatherr",
    "_configthreadlocale": "crt_configthreadlocale", "_adjust_fdiv": "crt_adjust_fdiv",
    "_setmbcp": "crt_setmbcp", "_ismbblead": "crt_ismbblead",
    "_onexit": "crt_onexit", "__dllonexit": "crt_dllonexit",
    "_lock": "crt_lock", "_unlock": "crt_unlock",
    "_encode_pointer": "crt_encode_pointer", "_decode_pointer": "crt_decode_pointer",
    "exit": "crt_exit", "_exit": "crt_exit", "_cexit": "crt_cexit",
    "_amsg_exit": "crt_amsg_exit", "abort": "crt_abort", "_purecall": "crt_purecall",
    "_invoke_watson": "crt_invoke_watson", "_crt_debugger_hook": "crt_crt_debugger_hook",
    "_controlfp": "crt_controlfp", "_controlfp_s": "crt_controlfp_s",
    "_control87": "crt_control87",
    "printf": "crt_printf", "fprintf": "crt_fprintf", "sprintf": "crt_sprintf",
    "_snprintf": "crt_snprintf", "_vsnprintf": "crt_vsnprintf", "vsprintf": "crt_vsprintf",
    "vfprintf": "crt_vfprintf", "sscanf": "crt_sscanf", "swscanf": "crt_swscanf",
    "strlen": "crt_strlen", "strcmp": "crt_strcmp", "strncmp": "crt_strncmp",
    "_stricmp": "crt_stricmp", "_strnicmp": "crt_strnicmp",
    "strcpy": "crt_strcpy", "strncpy": "crt_strncpy", "strcat": "crt_strcat",
    "strncat": "crt_strncat", "strchr": "crt_strchr", "strrchr": "crt_strrchr",
    "strstr": "crt_strstr", "strpbrk": "crt_strpbrk", "strspn": "crt_strspn",
    "strcspn": "crt_strcspn", "_strlwr": "crt_strlwr",
    "memcpy": "crt_memcpy", "memmove": "crt_memmove", "memset": "crt_memset",
    "memcmp": "crt_memcmp", "memchr": "crt_memchr", "qsort": "crt_qsort",
    "atoi": "crt_atoi", "atol": "crt_atol", "atof": "crt_atof",
    "strtol": "crt_strtol", "strtoul": "crt_strtoul", "strtod": "crt_strtod",
    "_ultoa": "crt_ultoa", "_ltoa": "crt_itoa", "_fcvt": "crt_fcvt", "_ecvt": "crt_ecvt",
    "_CIpow": "crt_pow", "_CIsqrt": "crt_ci_sqrt", "_CIlog": "crt_ci_log",
    "_CIcos": "crt_ci_cos", "_CIsin": "crt_ci_sin", "_CIasin": "crt_ci_asin",
    "_CIacos": "crt_ci_acos", "_CIfmod": "crt_ci_fmod",
    "floor": "crt_floor", "ceil": "crt_ceil", "modf": "crt_modf", "ldexp": "crt_ldexp",
    "_isnan": "crt_isnan", "_finite": "crt_finite",
    "rand": "crt_rand", "_time64": "crt_time64", "_time32": "crt_time32",
    "_localtime64": "crt_localtime64", "_gmtime64": "crt_gmtime64",
    "_mktime64": "crt_mktime64", "strftime": "crt_strftime",
    "fopen": "crt_fopen", "fclose": "crt_fclose", "fread": "crt_fread",
    "fwrite": "crt_fwrite", "fseek": "crt_fseek", "ftell": "crt_ftell",
    "fflush": "crt_fflush", "feof": "crt_feof", "ferror": "crt_ferror",
    "fgets": "crt_fgets", "fputs": "crt_fputs", "tmpfile": "crt_tmpfile",
    "_getch": "crt_getch", "signal": "crt_signal",
    "wcslen": "crt_wcslen", "wcscpy": "crt_wcscpy", "wcsncpy": "crt_wcsncpy",
    "wcscat": "crt_wcscat", "wcsncat": "crt_wcsncat", "wcscmp": "crt_wcscmp",
    "wcsncmp": "crt_wcsncmp", "_wcsicmp": "crt_wcsicmp", "_wcsnicmp": "crt_wcsnicmp",
    "wcschr": "crt_wcschr", "wcsrchr": "crt_wcsrchr", "wcsstr": "crt_wcsstr",
    "wcscspn": "crt_wcscspn", "_wcslwr": "crt_wcslwr", "towupper": "crt_wtoupper",
    "towlower": "crt_towlower", "iswctype": "crt_iswctype",
    "wcstol": "crt_wcstol", "wcstoul": "crt_wcstoul", "wcstod": "crt_wcstod",
    "_wtol": "crt_wtol", "_ltow": "crt_ltow", "_ultow": "crt_ultow",
    "_wgetcwd": "crt_wgetcwd", "_wgetdcwd": "crt_wgetdcwd", "_getdrive": "crt_getdrive",
    "_searchenv": "crt_searchenv", "_wsearchenv": "crt_wsearchenv",
    "_stat64i32": "crt_stat64i32", "_wstat64i32": "crt_wstat64i32",
    "_beginthreadex": "crt_beginthreadex", "_spawnv": "crt_spawnv",
    "_wspawnv": "crt_wspawnv",
    "isalpha": "crt_isalpha", "isdigit": "crt_isdigit", "isspace": "crt_isspace",
    "isalnum": "crt_isalnum", "isupper": "crt_isupper", "isprint": "crt_isprint",
    "isxdigit": "crt_isxdigit", "toupper": "crt_toupper", "tolower": "crt_tolower",
    "setlocale": "crt_setlocale", "getenv": "crt_getenv",
    "_setjmp3": "crt_setjmp3", "longjmp": "crt_longjmp",
}

for _name, _fn in MSVCR.items():
    IMPL[("MSVCR90.dll", _name)] = _fn

# Exceptions and SEH are implemented in seh.cpp.
IMPL[("MSVCR90.dll", "_except_handler3")] = "seh_handler3"
IMPL[("MSVCR90.dll", "_except_handler4_common")] = "seh_handler4_common"
IMPL[("MSVCR90.dll", "__CxxFrameHandler3")] = "seh_cxx_frame_handler3"
IMPL[("MSVCR90.dll", "_CxxThrowException")] = "seh_cxx_throw"
IMPL[("MSVCR90.dll", "?_type_info_dtor_internal_method@type_info@@QAEXXZ")] = "crt_noop"
IMPL[("MSVCR90.dll", "?terminate@@YAXXZ")] = "crt_abort"
IMPL[("MSVCR90.dll", "_XcptFilter")] = "crt_noop"

# ---- other DLLs ----
IMPL.update({
    ("WINMM.dll", "timeBeginPeriod"): "timeBeginPeriod",
    ("WINMM.dll", "timeEndPeriod"): "timeEndPeriod",
    ("WINMM.dll", "timeGetTime"): "timeGetTime",
    ("PSAPI.DLL", "GetModuleInformation"): "GetModuleInformation",
    ("steam_api.dll", "SteamAPI_Init"): "steam_init",
    ("steam_api.dll", "SteamAPI_Shutdown"): "steam_noop",
    ("steam_api.dll", "SteamApps"): "steam_apps",
    ("VERSION.dll", "GetFileVersionInfoSizeA"): "version_size",
    ("VERSION.dll", "GetFileVersionInfoSizeW"): "version_size",
    ("VERSION.dll", "GetFileVersionInfoA"): "version_noop",
    ("VERSION.dll", "GetFileVersionInfoW"): "version_noop",
    ("VERSION.dll", "VerQueryValueA"): "version_query",
    ("VERSION.dll", "VerQueryValueW"): "version_query",
    ("ole32.dll", "OleInitialize"): "ole_init",
    ("ole32.dll", "OleUninitialize"): "ole_noop",
    ("ole32.dll", "RegisterDragDrop"): "ole_noop",
    ("ole32.dll", "RevokeDragDrop"): "ole_noop",
    ("ole32.dll", "CoLockObjectExternal"): "ole_noop",
    ("ole32.dll", "ReleaseStgMedium"): "ole_noop",
    ("SHELL32.dll", "SHGetFolderPathW"): "sh_get_folder_path",
    ("SHELL32.dll", "ShellExecuteW"): "shell_execute",
    ("SHELL32.dll", "DragQueryFileW"): "drag_query_file",
    ("ADVAPI32.dll", "GetUserNameA"): "advapi_get_user_name",
    ("ADVAPI32.dll", "GetUserNameW"): "advapi_get_user_name_w",
    ("ADVAPI32.dll", "RegOpenKeyExA"): "reg_open_key",
    ("ADVAPI32.dll", "RegOpenKeyExW"): "reg_open_key",
    ("ADVAPI32.dll", "RegQueryValueExA"): "reg_query_value",
    ("ADVAPI32.dll", "RegQueryValueExW"): "reg_query_value",
    ("ADVAPI32.dll", "RegSetValueExA"): "reg_set_value",
    ("ADVAPI32.dll", "RegCloseKey"): "reg_close_key",
    ("ADVAPI32.dll", "RegEnumKeyExW"): "reg_enum_key",
    ("ADVAPI32.dll", "RegisterEventSourceA"): "reg_event_noop",
    ("ADVAPI32.dll", "ReportEventA"): "reg_event_noop",
    ("ADVAPI32.dll", "DeregisterEventSource"): "reg_event_noop",
    ("dbghelp.dll", "SymInitialize"): "dbghelp_noop",
    ("dbghelp.dll", "SymCleanup"): "dbghelp_noop",
    ("dbghelp.dll", "SymSetOptions"): "dbghelp_noop",
    ("dbghelp.dll", "SymLoadModule64"): "dbghelp_noop",
    ("dbghelp.dll", "SymGetSymFromAddr64"): "dbghelp_noop",
    ("dbghelp.dll", "SymGetLineFromAddr64"): "dbghelp_noop",
    ("dbghelp.dll", "UnDecorateSymbolName"): "dbghelp_noop",
    ("USP10.dll", "ScriptItemize"): "usp_noop",
    ("USP10.dll", "ScriptBreak"): "usp_noop",
    ("IMM32.dll", "ImmDisableTextFrameService"): "imm_noop",
    ("IMM32.dll", "ImmGetContext"): "imm_get_context",
    ("IMM32.dll", "ImmReleaseContext"): "imm_noop",
    ("IMM32.dll", "ImmGetOpenStatus"): "imm_noop",
    ("IMM32.dll", "ImmSetOpenStatus"): "imm_noop",
    ("IMM32.dll", "ImmNotifyIME"): "imm_noop",
    ("IMM32.dll", "ImmGetConversionStatus"): "imm_noop",
    ("IMM32.dll", "ImmSetConversionStatus"): "imm_noop",
    ("IMM32.dll", "ImmGetCompositionStringW"): "imm_noop",
    ("IMM32.dll", "ImmSetCompositionStringW"): "imm_noop",
    ("IMM32.dll", "ImmSimulateHotKey"): "imm_noop",
    ("IMM32.dll", "ImmGetCandidateListW"): "imm_noop",
})

# ---- Direct3D / D3DX / DInput / DSound / Winsock ----
IMPL.update({
    ("d3d9.dll", "Direct3DCreate9"): "d3d_create9",
    ("d3dx9_27.dll", "D3DXCheckVersion"): "d3dx_check_version",
    ("d3dx9_27.dll", "D3DXGetPixelShaderProfile"): "d3dx_get_ps_profile",
    ("d3dx9_27.dll", "D3DXGetVertexShaderProfile"): "d3dx_get_vs_profile",
    ("d3dx9_27.dll", "D3DXCompileShader"): "d3dx_compile_shader",
    ("d3dx9_27.dll", "D3DXMatrixMultiply"): "d3dx_matrix_multiply",
    ("d3dx9_27.dll", "D3DXMatrixMultiplyTranspose"): "d3dx_matrix_multiply_transpose",
    ("d3dx9_27.dll", "D3DXMatrixTranspose"): "d3dx_matrix_transpose",
    ("d3dx9_27.dll", "D3DXVec3Transform"): "d3dx_vec3_transform",
    ("d3dx9_27.dll", "D3DXVec3TransformNormal"): "d3dx_vec3_transform_normal",
    ("DINPUT8.dll", "DirectInput8Create"): "dinput8_create",
    ("DSOUND.dll", "#1"): "dsound_create",
    ("DSOUND.dll", "#9"): "dsound_noop",
    ("WSOCK32.dll", "#1"): "ws_noop",
    ("WSOCK32.dll", "#2"): "ws_noop",
    ("WSOCK32.dll", "#3"): "ws_noop",
    ("WSOCK32.dll", "#4"): "ws_noop",
    ("WSOCK32.dll", "#5"): "ws_noop",
    ("WSOCK32.dll", "#6"): "ws_noop",
    ("WSOCK32.dll", "#7"): "ws_noop",
    ("WSOCK32.dll", "#10"): "ws_noop",
    ("WSOCK32.dll", "#12"): "ws_noop",
    ("WSOCK32.dll", "#13"): "ws_noop",
    ("WSOCK32.dll", "#16"): "ws_noop",
    ("WSOCK32.dll", "#17"): "ws_noop",
    ("WSOCK32.dll", "#18"): "ws_noop",
    ("WSOCK32.dll", "#19"): "ws_noop",
    ("WSOCK32.dll", "#20"): "ws_noop",
    ("WSOCK32.dll", "#21"): "ws_noop",
    ("WSOCK32.dll", "#22"): "ws_noop",
    ("WSOCK32.dll", "#23"): "ws_noop",
    ("WSOCK32.dll", "#52"): "ws_noop",
    ("WSOCK32.dll", "#111"): "ws_noop",
    ("WSOCK32.dll", "#115"): "ws_noop",
    ("WSOCK32.dll", "#116"): "ws_noop",
    ("WSOCK32.dll", "#151"): "ws_noop",
    ("WS2_32.dll", "WSAIoctl"): "ws_noop",
    ("WS2_32.dll", "#112"): "ws_noop",
    ("WS2_32.dll", "WSASocketA"): "ws_noop",
})

# Default argument counts for functions the inference could not see (no call sites).
DEFAULT_NARGS = {
    "GetProcessHeap": 0, "GetCurrentProcess": 0, "GetCurrentThread": 0,
    "GetLastError": 0, "GetVersion": 0, "GetTickCount": 0, "GetACP": 0,
    "IsDebuggerPresent": 0, "GetCommandLineA": 0, "GetLogicalDrives": 0,
    "GetDriveTypeA": 1, "TlsAlloc": 0, "GetSystemDefaultLCID": 0,
}


def main() -> int:
    if RESOLVED.exists():
        resolved = json.loads(RESOLVED.read_text(encoding="utf-8"))
    else:
        # Fallback so the tree still links while the (slow) inference pass is running.
        # Argument counts default to 0; the call-site inference in tools/imports.py fills
        # them in and this generator is re-run.
        import re
        print(f"[table] {RESOLVED} missing, using PE import list with default arity",
              file=sys.stderr)
        resolved = []
        text = Path("analysis/imports.txt").read_text(encoding="utf-8")
        cur = None
        for line in text.splitlines():
            m = re.match(r"=== (\S+) \((\d+)\)", line)
            if m:
                cur = m.group(1)
                continue
            if cur and line.startswith("  ") and line.strip():
                for nm in line.strip().split(", "):
                    if not nm:
                        continue
                    if nm.startswith("#"):
                        resolved.append(dict(dll=cur, name="", ordinal=int(nm[1:]),
                                             nargs=0, stdcall=True, sites=0))
                    else:
                        resolved.append(dict(dll=cur, name=nm, ordinal=0,
                                             nargs=0, stdcall=True, sites=0))

    lines = []
    w = lines.append
    w("// generated by tools/gen_import_table.py -- do not edit")
    w("//")
    w("// One descriptor per imported function. `nargs` and `stdcall` were inferred from the")
    w("// guest's own call sites (tools/imports.py); `fn` is the host implementation, or")
    w("// nullptr when it is not written yet (the runtime logs those when called).")
    w('#include "rt/imports.h"')
    w('#include "rt/win32/win32.h"')
    w("")
    w("namespace sr::w32 {")
    for fn in sorted(set(IMPL.values())):
        w(f"void {fn}(CpuState* s, const u32* a);")
    w("}  // namespace sr::w32")
    w("")
    w("namespace sr::imports {")
    w("")
    w("const Desc g_import_table[] = {")
    missing = 0
    for r in resolved:
        dll, name, ordinal = r["dll"], r["name"], r["ordinal"]
        nargs = r["nargs"]
        stdcall = r["stdcall"]
        # Authoritative signature wins over the call-site inference.
        sig = SIG.get((dll, name))
        if sig is None:
            sig = SIG.get((dll, f"#{ordinal}"))
        if sig is not None:
            nargs, stdcall = sig
        key = (dll, name)
        fn = IMPL.get(key)
        if fn is None and not name:
            fn = IMPL.get((dll, f"#{ordinal}"))
        nargs = DEFAULT_NARGS.get(name, nargs)
        label = name if name else f"#{ordinal}"
        if fn:
            w(f'  {{"{dll}", "{label}", {ordinal}, {nargs}, '
              f'{"true" if stdcall else "false"}, sr::w32::{fn}}},')
        else:
            missing += 1
            w(f'  {{"{dll}", "{label}", {ordinal}, {nargs}, '
              f'{"true" if stdcall else "false"}, nullptr}},')
    w("  {nullptr, nullptr, 0, 0, false, nullptr},")
    w("};")
    w("")
    w("}  // namespace sr::imports")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[table] {len(resolved)} imports, {len(resolved) - missing} implemented, "
          f"{missing} stubs -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
