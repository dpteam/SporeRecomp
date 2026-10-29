# SporeRecomp — plan

Goal: run **Spore (SporeApp.exe, GA release, x86-32 PE)** on **Anbernic RG 35 XX H / H700,
Linux ARM64, muOS** by **static binary recompilation** — same method as the working
`refs/NFSU2_Template`: lift every guest function to native C++, ship a native runtime that
replaces Windows + D3D9 + DInput + DSound, cross-compile to aarch64. Not a reimplementation,
not an emulator, not Wine.

## Method (4 pieces)

1. **Lifter** (`tools/lift.py`, Python)
   Recursive-descent disassembly of the 16.5 MB `.text` → one C++ function per guest function.
   Direct `call rel32` → native call; `jmp`/`call` through memory → guest-address dispatch table;
   jump tables resolved from `.rdata`/`.data` pointer arrays; `int3` padding + `.reloc` +
   beta-PDB names used as boundary/name evidence. Guest registers live in a per-thread
   `CpuState`; flags are materialised lazily; SSE maps to NEON/scalar intrinsics.

2. **Runtime** (`src/`, C++17, SDL2 + GLES2/3)
   * PE mapper, guest 4 GB virtual space, heap ownership handoff (realloc-preserving)
   * guest thread scheduler: one native thread per guest thread, full per-thread state
     (GPR, flags, x87, XMM, FS/TLS, last-error) — Spore is heavily multi-threaded
   * SEH: `FS:[0]` chain + `_except_handler4` emulation over `setjmp`/signal
   * Win32 shims: kernel32, user32, gdi32, advapi32, ole32, ws2_32, winmm, psapi, version,
     imm32, usp10, dbghelp, shell32, steam_api, **MSVCR90** (159 imports)
   * D3D9: `Direct3DCreate9` + COM vtables (Device9, Texture9, Cube/Volume, VB/IB, VertexShader9,
     PixelShader9, StateBlock9, Query9, Surface9) → GLES2/3; RW4 shader bytecode → GLSL ES
   * DInput8 → SDL2 gamepad (`.gptk`-style mapping), DSound → SDL2 audio

3. **Differential validation** (`tests/`)
   For any lifted function: run the original x86 code under **Unicorn** with random inputs and
   compare against the lifted native code (registers, flags, memory, exceptions). This is how a
   100k-function lift stays correct without hand-reading every function — NFSU2's log shows the
   same idea ("Real lifted sub_00401000 passed 7 copy/cdecl stack cases on a 64-bit host").

4. **Boot ladder** (`docs/STATUS.md`)
   Each milestone is "the guest gets one step further, proven by `log.txt`".

## Milestones

| # | Target | Proof |
|---|---|---|
| M0 | analysis + scaffold + toolchain | `docs/ANALYSIS.md`, aarch64 toolchain builds |
| M1 | PE loader + CpuState + call ABI | differential tests green on host and aarch64 (qemu) |
| M2 | full `.text` lifted, all imports implemented, guest reaches `WinMain` | **done** — 4,747,729 instructions, 0 unhandled, 495/495 imports |
| M3 | CRT + config + package I/O + D3D9 device + RW4 texture/UI draw | **main menu rendered** |
| M4 | input, audio, menu navigation, save files | menu fully usable |
| M5 | Cell/Creature stage | playable creature stage |
| M6 | Tribe/Civilization/Space | playable |
| M7 | device performance work (NFSU2 needed v10→v37 of this) | 15–30 FPS on H700 |

## Honest risk register

1. **Size**: 16.5 MB of code, 108,528 recovered functions. Lifter quality (jump tables, SEH,
   indirect calls) is the whole game — but it is done: 4,747,729 instructions lifted with zero
   unhandled mnemonics.
2. **D3D9 + RW4 shaders on Mali-G31 (GLES2/3)** — **measured and closed** (see
   `docs/SHADERS.md`). Spore does **not** ship shader bytecode; RenderWare 4 generates HLSL from
   templates at runtime (`\Spore\SporeEP1ML\Core\RenderWare\platform\src\graphics\core\device\target\dx9\rwgdrvgraph.cpp`)
   and compiles it with `D3DXCompileShader`. Verified: 1,747 candidate version tokens in 3.9 GB of
   packages, **zero** parse as a DX9 token stream. So `D3DXCompileShader` must be implemented for
   real — but the HLSL subset is small and fully enumerable (structs with POSITION/NORMAL/COLOR/
   TEXCOORD/BINORMAL/TANGENT semantics, `register(cN)` constants, `register(sN)` samplers, `mul`,
   `tex2D`, `texCUBE`, `frac/saturate/lerp/dot/normalize/pow`, simple `if`/`for`). A few thousand
   lines of HLSL front end + GLSL ES emitter, not a compiler project.
3. **Memory**: RG 35 XX H has 1 GB total, muOS has no swap. Spore's PC working set is in the same
   ballpark and its assets are ~3.9 GB of packages. Needs aggressive trimming (mip limits, Galaxy
   textures on demand, package streaming) — real risk, possibly the hardest non-code problem.
4. **CPU**: H700 = 4× Cortex-A53 @1.5 GHz. NFSU2 (2004, D3D8) needed 37 releases of optimisation to
   hit 30–60 FPS on the weaker RK3326. Spore (2008, D3D9, procedural animation) will be slower;
   target is "playable, not pretty".
5. **Windows-only details**: 673 `rdtsc`, 40 `cpuid`, VS2008 CRT quirks, registry-based config,
   Steam API presence.

## Non-goals

* No reimplementation of gameplay/game systems (that is what OpenSpore does).
* No x86 emulator in the shipped binary (only in tests, for validation).
* No Wine/Box86/FEX dependency on the device.
