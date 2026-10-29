# Status

## What works right now

| Piece | State |
|---|---|
| PE analysis | **done** — headers, sections, imports, relocations, TLS, debug dir (`docs/ANALYSIS.md`, `docs/pe_report.md`) |
| Function census | **done** — 5,496,576 instructions decoded, 100,738 functions (53,596 real + 47,142 orphan data groups), 86.7% of `.text` claimed by real functions (`analysis/census_report.md`) |
| Lifter | **done for the whole binary** — 4,077,456 instructions → 53,596 C++ functions, **0 unhandled mnemonics** (`analysis/lift_report.md`) |
| Guest memory | done — 4 GB reserved, committed on demand, guest heap arena |
| CPU state | done — GPRs, lazy EFLAGS, x87 stack, SSE bank, MXCSR, FS/GS bases, TEB fields |
| SSE / x87 / MMX helpers | done — scalar and packed, saturating, shifts, converts |
| PE loader | done — maps at 0x400000, walks relocations, binds imports |
| Import dispatch | mechanism done (stub page + stack-based argument marshalling), table being generated |
| Win32 shims | in progress — kernel32 (memory/time/version/strings/sync/threads/TLS/files) and MSVCR90 (allocator, printf family, strings, math, time, stdio, wide chars, setjmp) written |
| D3D9 / DInput / DSound | **not started** |
| Build | 215 generated chunks compile individually; full link pending |

## How the numbers were obtained

Nothing here is estimated. Each claim has a reproducible tool behind it:

```bash
python tools/pe_report.py --out     # docs/pe_report.md
python tools/census.py              # analysis/census_report.md + analysis/census/
python tools/lift.py                # recomp/gen/ (215 chunks) + analysis/lift_report.md
python tools/imports.py             # analysis/imports_resolved.json
```

## Design decisions worth knowing

**The lifter has no interpreter fallback.** If an instruction is not handled, the build
report says so; the shipped binary never silently degrades. This is why "0 unhandled" is a
meaningful milestone rather than a rounding error.

**Function boundaries come from an instruction stream, not from seeds.** The first attempt
(seeds + recursive descent) produced 14,285 functions that "hit a decode limit", i.e. it was
merging unrelated code. The census now decodes `.text` linearly (only 457 bytes of 16.5 MB
are undecodable), then partitions that instruction stream by reachability from strong roots
(call targets + entry). Tail calls stop at another function's entry instead of absorbing it.

**Orphan groups are not lifted.** 47,142 groups of decodable-but-unreachable instructions are
jump tables and data that happen to decode as x86. Lifting them would add ~1.4M instructions
of garbage.

**Guest addresses are host addresses.** The whole 4 GB guest space is one `mmap` reservation
with a fixed offset, so lifted code and shims use plain pointers. On a 1 GB device nothing is
committed until the game asks for it.

**Imports get real guest addresses.** Each import is a stub inside a reserved page; the IAT is
filled with those addresses. `call dword ptr [IAT]` therefore lands in `guest_call_indirect`,
which dispatches to the host implementation. Arguments are read straight off the guest stack,
and `nargs` + calling convention are **inferred from the guest's own call sites** (walk back
over the contiguous `push` sequence; stdcall if the code after the call does not adjust ESP)
rather than typed in from memory.

## Next steps, in order

1. Finish the import table and link the binary. Boot and read `log.txt`.
2. The first failures will be CRT startup (`_initterm`, `__getmainargs`, SEH setup). Fix in
   the order the log reports them.
3. SEH: `FS:[0]` chain + `_except_handler3/4` + `__CxxFrameHandler3`. Spore's C++ code throws
   and catches; the exception path must work before the app gets far.
4. Multi-threading: `CreateThread` currently logs and returns a handle. Spore's streaming
   threads need real native threads with their own `CpuState`.
5. D3D9 → GLES: the largest remaining subsystem (see `docs/PLAN.md` risk #2).
6. Package I/O: `CreateFileW` maps to the game directory, but Spore reads `.package` files
   with its own code, so this may already work once file I/O is right.

## Known limitations of the current lift

* `fcomi`/`fucomi`/`fcompp` without explicit operands compare st(0) against st(0); the
  disassembler omits the implicit operand, so the lifter defaults to `st(0)`.
* MMX registers are given their own storage in the XMM bank instead of aliasing x87. The
  binary uses MMX 1,500 times, all in byte-shuffling paths, so this is safe in practice but
  not architecturally exact.
* `rcl`/`rcr` call `unsupported()`; they appear twice in 4M instructions.
* `enter`/`leave` are supported, but `retf`/`iret` are traps (4 and 3 sites).
* `bsr`/`bsf` zero-result flag handling is implemented; `bsr`'s destination-undefined case is
  not (it leaves the register untouched, as documented for modern Intel).
