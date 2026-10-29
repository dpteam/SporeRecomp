# Status

Measured facts, not estimates. Every number below comes from a tool in `tools/` and a report
in `analysis/`.

## Numbers

| Piece | Value |
|---|---|
| `.text` | 16,559,914 bytes at VA 0x401000 |
| Instructions decoded | 5,496,576 (457 undecodable bytes, 0.003%) |
| Instructions assigned to a function | 4,763,173 (86.66%) |
| Functions recovered | **108,528** (102,913 real + 5,615 orphan data groups) |
| Basic blocks | 235,256 |
| Instructions lifted to C++ | **4,747,722** |
| Unhandled mnemonics | **0** |
| Imported functions | 495 across 20 DLLs |
| Imports implemented | 397 (98 remain, all in subsystems not started) |
| Generated code | 412 chunks, ~460 MB of C++ |

## What is implemented

**Analysis** — `tools/pe_report.py`, `census.py`, `imports.py`. Function boundaries come from
a linear instruction sweep (the binary decodes almost perfectly) partitioned by reachability
from strong roots, not from heuristic seeds. Everything is keyed by **guest virtual address**,
because the guest's own code pointers (vtables, callbacks, data tables) are VAs.

**Lifter** — `tools/lift.py`. x86-32 → C++, one C++ function per guest function.
* every instruction has a counterpart; an unhandled one is a *build-time* error, never a
  runtime surprise
* direct calls become native calls, indirect calls go through the dispatch table
* jump tables become `goto`/`switch` labels inside the function
* SSE, x87 (80-bit stack), MMX, and the saturating/packed integer ops are all modelled
* lazy EFLAGS: only `jcc`/`setcc`/`adc`/`sbb` materialise them

**Runtime** — `src/rt/`
* 4 GB guest window reserved with `MAP_NORESERVE`, committed page by page
* guest heap: size-class free lists with 16-byte headers and magic words, so a double free is
  reported instead of silently corrupting memory
* `CpuState`: GPRs, lazy flags, x87 stack with rotating top, SSE bank, MXCSR, FS/GS bases, TEB
* PE loader: maps at 0x400000, walks relocations, binds imports
* import dispatch: every import gets a unique guest stub address; arguments are read straight
  off the guest stack; `nargs` and calling convention come from documented Win32 signatures
  (cross-checked against call-site inference)
* **COM dispatch**: D3D9 objects are built *in guest memory* with real vtables of stub
  addresses, so `device->lpVtbl->DrawPrimitive(...)` works exactly as on Windows
* SEH: walks the guest's real `FS:[0]` chain calling guest handlers
* Win32 shims: kernel32, user32, gdi32, advapi32 (registry), msvcr90 (CRT), winmm, psapi,
  version, ole32, shell32, dbghelp, usp10, imm32, steam_api
* D3D9: `IDirect3D9`, `IDirect3DDevice9` (all 119 methods), `IDirect3DTexture9`,
  `IDirect3DVertexBuffer9`/`IndexBuffer9`, shaders, with real host-side resource records.
  Currently a **null backend**: it counts every call, keeps real resource objects, and returns
  success so the guest's own logic can run end to end.
* D3DX: real matrix/vector math; `D3DXCompileShader` logs every request and fails cleanly

## Bugs found and fixed during bring-up

These are worth recording because each one would have cost a debugging session on the device:

1. **Return addresses are mid-function.** The first design dispatched `ret` by looking up the
   return address in the function table — but a return address points *inside* the caller, not
   at its start. Every `ret` would have failed. Control flow now uses the native call stack;
   the guest return address is still pushed so ESP stays balanced for the guest's own stack
   walking.
2. **Stack overlapped the TEB.** The thread stack ran up to 0x7FFE0000 while the TEB sat at
   0x7FFDF000. The first deep call chain would have overwritten the TEB. The stack now tops out
   at 0x7FFC0000, below the PEB and TEB.
3. **RVA vs VA.** The census keyed functions by RVA while the guest's pointers are VAs. Fixing
   this turned 41,527 "orphan data groups" into real reachable functions — the count went from
   53,596 to 102,913.
4. **`heap_free` was a no-op.** With a bump allocator, Spore's constant alloc/free churn would
   have exhausted the arena in minutes. Replaced with a real allocator.
5. **`ret n` popped the wrong amount.** stdcall returns must pop the return address *and* the
   arguments.

## What is not started

| Subsystem | State |
|---|---|
| GLES renderer behind D3D9 | not started (null backend in place) |
| Shader path (`D3DXCompileShader`) | logged, fails cleanly — needs an HLSL front end or bytecode translation |
| Real guest threads | `CreateThread` returns a handle; no native thread yet |
| Input (DInput8) | fails cleanly so the guest takes its no-device path |
| Audio (DSound) | fails cleanly |
| Networking (Winsock) | stubs |
| Device performance work | not started |

## Next steps, in order

1. Link and run on the device. The log will name the first real failure.
2. Fix CRT startup in the order the log reports it (`_initterm`, `__getmainargs`, SEH setup).
3. Real guest threads: Spore's streaming threads need their own `CpuState` and guest stack.
4. Measure the shader situation: how many `D3DXCompileShader` requests, and whether the
   packages also carry pre-compiled bytecode. This decides the size of the renderer job.
5. GLES backend behind the existing D3D9 interface.

## Known limitations

* `rcl`/`rcr` call `unsupported()` (2 sites in 4.7M instructions).
* `retf`/`iret`/`iretd` are traps (4+3 sites).
* MMX registers have their own storage instead of aliasing x87. The binary uses MMX ~1,500
  times, all in byte shuffling; architecturally inexact but safe here.
* `longjmp` unwinds the whole guest native stack instead of resuming the target frame; it is
  reported loudly when it happens.
* `fcomi`/`fucomi` without an explicit second operand default to `st(0)` (the disassembler
  omits the implicit operand).
