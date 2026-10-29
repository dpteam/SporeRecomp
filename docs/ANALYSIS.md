# SporeApp.exe — binary facts (measured, not guessed)

Source: `refs/SporeBin/SporeApp.exe.unpacked.exe`
(byte-identical in size to OpenSpore `refs/bins/ReleaseGA/SporeApp.exe.unpacked.exe`).

| Property | Value |
|---|---|
| File size | 24,895,528 bytes |
| SHA-256 | `086f299216f6a70d2c23be0fb04b4b7c570d3bbd94ca0b26bcad53681b3e9fe7` |
| Machine | i386 (0x14C), PE32, GUI subsystem 5.0 |
| Linker timestamp | 1727737552 → 2024-09-30 (repacked/unpacked build of the 2008 release) |
| Image base | 0x00400000 |
| Entry point | RVA 0x00DE11E1 (CRT `_WinMainCRTStartup`) |
| `.text` | RVA 0x00001000, 16,558,890 bytes (0xFC AF 2A) |
| `.rdata` | 20.9 MB logical (1.3 MB on disk) |
| `.data` | 2.17 MB logical |
| `.rsrc` | 5.27 MB (icons/manifest/version — mostly junk for us) |
| `.reloc` | 938 KB → usable as a **ground-truth list of code pointers** |
| TLS directory | present at RVA 0x10F9090 |
| Debug dir | CodeView RSDS, `SporeEP1_RL` build, PDB **not** shipped |
| Imports | 495 functions across 20 DLLs |

## Import surface (what the runtime has to fake)

| DLL | # | Notes |
|---|---|---|
| MSVCR90.dll | 159 | VS2008 CRT — must be reimplemented (no Win CRT on ARM64 Linux) |
| KERNEL32.dll | 148 | threads, files, memory, crit sections, locale |
| USER32.dll | 89 | window, messages, clipboard, dialogs |
| WSOCK32.dll / WS2_32.dll | 23 + 3 | ordinals — Spore's own netcode (Galaxy/Sporepedia) |
| ADVAPI32.dll | 12 | registry (config lives there) |
| IMM32.dll | 12 | IME |
| d3dx9_27.dll | 9 | **D3DXCompileShader**, D3DXGet{Pixel,Vertex}ShaderProfile, matrix helpers |
| dbghelp.dll | 7 | in-game crash handler |
| GDI32.dll | 6 | 6 calls only (bitmap font fallback) |
| ole32.dll | 6 | drag & drop, OLE init |
| VERSION.dll | 5 | version check |
| SHELL32.dll | 3 | folder paths, ShellExecute |
| WINMM.dll | 3 | timeBeginPeriod/GetTime |
| steam_api.dll | 3 | Steam build: SteamAPI_Init/Shutdown/SteamApps |
| PSAPI.DLL | 1 | GetModuleInformation |
| DINPUT8.dll | 1 | DirectInput8Create (all devices via COM) |
| USP10.dll | 2 | Uniscribe text shaping |
| DSOUND.dll | 2 | ordinals 1 and 9 |
| **d3d9.dll** | **1** | **`Direct3DCreate9` only** — everything else is COM vtables |

Consequence: the graphics work is "implement IDirect3D9 + IDirect3DDevice9 + resource
interfaces", not "implement 200 functions". Same shape as the NFSU2 template's D3D8 layer.

## Code shape

* ~105,239 candidate function starts (OpenSpore `analysis/functions_stats.json`,
  union of E8/E9 rel32 targets, `.rdata`/`.data` code pointers and prologues).
  NFSU2's template lifts **27,758** functions → Spore is ≈4× that.
* 12,984 classic `55 8B EC` / `55 89 E5` frame prologues; 83,114 `int3` pad runs
  (MSVC /Gy-style function padding, usable as a boundary hint).
* SSE is used heavily: 128,547 `movups`, 128,355 `movss`, 30,839 `movaps`, 15,248 `xorps`,
  3,529 `divps`. x87 is rare. → SSE must be lifted properly (NEON or scalar), not emulated.
* 40 `cpuid`, 673 `rdtsc` sites → need deterministic shims.
* RenderWare 4 is the renderer (`RWGOBJECTTYPE_SHADERCODE`, `Terrain/ShaderManager/cTerrainShaderMgr`,
  `ps_2_0`/`vs_2_0`/`ps_3_0`/`vs_3_0` profiles) — shaders are HLSL, compiled at runtime via
  `D3DXCompileShader` unless the packages already carry compiled bytecode (open question, see PLAN).

## Useful existing assets (from the OpenSpore project)

* `refs/bins/Beta190208/SporeApp.pdb` — 134 MB **beta** PDB: symbol names for ~everything.
  Transferable to the release build by signature/string matching → gives the lifter readable
  names instead of `sub_XXXXXXXX`.
* Ghidra project `OpenSporeOracle` (function boundaries + call graph already recovered).
* `analysis/pdb_names.txt` (6 MB), `analysis/formats.md`, RW4/package/UI documentation.
* This is a large head start on *naming and semantics*, not on *execution*.
