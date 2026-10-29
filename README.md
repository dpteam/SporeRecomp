# SporeRecomp

Static binary recompilation of **Spore (SporeApp.exe, GA release, Win32 PE)** for
**Anbernic RG 35 XX H / H700 — Linux aarch64, muOS**.

Method is the same one that produced `refs/NFSU2_Template`: lift the guest x86-32 code to
native C++, replace Windows/D3D9/DInput/DSound with a native runtime, cross-compile to aarch64,
ship a static binary. The game's own code does the game logic; we never rewrite it.

## Status

| Phase | State |
|---|---|
| Binary analysis | done — see `docs/ANALYSIS.md`, `analysis/disasm_report.md` |
| Function recovery | in progress — see `analysis/` |
| Lifter | not started |
| Runtime (Win32/D3D9 shims) | not started |
| Boot ladder | not started |

## Layout

```
refs/                  reference material (gitignored): SporeApp.exe, NFSU2 template, game data
docs/                  ANALYSIS.md (measured facts), PLAN.md (milestones, risks)
tools/                 Python: PE reader, census, disassembler, lifter, validation harness
analysis/              generated reports + disassembly cache (gitignored except reports)
src/                   C++ runtime (PE loader, guest CPU state, Win32/D3D9/DInput/DSound shims)
tests/                 differential tests (Unicorn vs lifted code)
```

## Quick start

```bash
python tools/pe_report.py --out     # headers, imports, code shape -> docs/pe_report.md
python tools/disasm.py              # recover functions -> analysis/disasm/
python tools/disasm.py --stats      # summarise an existing pass
```

## Target device

RG 35 XX H: Allwinner H700, 4x Cortex-A53 @1.5 GHz (AArch64, NEON), 1 GB RAM, no swap,
Mali-G31 (GLES 2.0/3.x via `libMali`), muOS 2606 "ANDROMEDA" (glibc 2.44, SDL2 2.28).
