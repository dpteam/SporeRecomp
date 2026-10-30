#!/usr/bin/env python3
"""Replay a captured guest state through the ORIGINAL x86 code in Unicorn.

This is the decisive experiment when the lifted build crashes: take the register/stack state
from the crash report, run the original function under Unicorn from that exact state, and see
whether it also fails.

  * original fails too  -> the state was already wrong; the bug is upstream
  * original succeeds   -> the lift of this function is wrong; the bug is here

Usage:
  python tools/replay.py --eip 0x694cd0 --esp 0x7ffbfe28 \
      --eax 0x05344d71 --ebx 0x0150d100 --ecx 0x0d111185 --edx 0x35951714 \
      --esi 0x01be0257 --edi 0xffffffff --ebp 0x0150d31c \
      --stack "0x0150d100,0x01be0257,0x7ffbfefc,0x0150d31c,0x006950d8"

Or with a crash-report file:
  python tools/replay.py --from-crash crash.txt
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
STACK_TOP = 0x7FFC0000
STACK_SIZE = 0x00100000
HEAP = 0x10000000
HEAP_SIZE = 0x00400000


def parse_crash(text: str) -> dict:
    """Extracts the guest state from a crash report produced by src/rt/crash.cpp."""
    out: dict = {"stack": []}
    m = re.search(r"eip=0x([0-9a-f]+)\s+eflags=0x([0-9a-f]+)", text)
    if m:
        out["eip"] = int(m.group(1), 16)
        out["eflags"] = int(m.group(2), 16)
    for reg in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"):
        m = re.search(rf"\b{reg}=0x([0-9a-f]+)", text)
        if m:
            out[reg] = int(m.group(1), 16)
    for m in re.finditer(r"\[esp\+0x([0-9a-f]+)\]\s*=\s*0x([0-9a-f]+)", text):
        out["stack"].append((int(m.group(1), 16), int(m.group(2), 16)))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-crash")
    ap.add_argument("--eip", type=lambda s: int(s, 0))
    ap.add_argument("--esp", type=lambda s: int(s, 0))
    ap.add_argument("--eflags", type=lambda s: int(s, 0), default=0x202)
    for r in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"):
        ap.add_argument(f"--{r}", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--stack", help="comma-separated dwords starting at esp")
    ap.add_argument("--max-insns", type=int, default=2_000_000)
    args = ap.parse_args()

    state: dict = {}
    if args.from_crash:
        state = parse_crash(Path(args.from_crash).read_text(encoding="utf-8", errors="replace"))
        print(f"parsed crash state: eip={state.get('eip', 0):#x} "
              f"esp={state.get('esp', 0):#x} ({len(state['stack'])} stack dwords)")
    else:
        state = {"eip": args.eip, "esp": args.esp, "eflags": args.eflags,
                 "eax": args.eax, "ebx": args.ebx, "ecx": args.ecx, "edx": args.edx,
                 "esi": args.esi, "edi": args.edi, "ebp": args.ebp,
                 "stack": [(i * 4, v) for i, v in enumerate(
                     int(x, 0) for x in (args.stack or "").split(",") if x.strip())]}

    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
        from unicorn.x86_const import (
            UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
            UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
            UC_X86_REG_EFLAGS,
        )
    except ImportError:
        print("unicorn not installed: pip install unicorn", file=sys.stderr)
        return 1

    pe = PE(EXE.read_bytes())
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    img_end = pe.section(".reloc")["va"] + pe.section(".reloc")["vsz"]
    img_size = (img_end + 0xFFF) & ~0xFFF
    uc.mem_map(pe.imagebase, img_size)
    # Copy each section to its virtual address. Writing the file linearly is wrong: sections
    # live at different file offsets (the same mistake that made the first PE loader walk
    # garbage), and it makes Unicorn execute bytes that are not the function under test.
    for s in pe.sections:
        if s["rsz"] == 0:
            continue
        uc.mem_write(pe.imagebase + s["va"], pe.d[s["roff"]:s["roff"] + s["rsz"]])
    uc.mem_map(HEAP, HEAP_SIZE)
    uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE)
    # Import stubs: a page of `ret` so a call into the IAT returns harmlessly and is logged.
    STUB = 0x70000000
    uc.mem_map(STUB, 0x1000)
    uc.mem_write(STUB, b"\xc3" * 0x1000)

    # Restore the stack exactly as reported.
    esp = state["esp"]
    for off, val in state["stack"]:
        uc.mem_write(esp + off, struct.pack("<I", val))

    text_lo = pe.imagebase + pe.section(".text")["va"]
    text_hi = text_lo + pe.section(".text")["vsz"]

    # The crash dump is captured mid-function (after the prologue pushed registers), while a
    # replay has to start at the function's first instruction. If the dword at esp is not a
    # return address into .text, walk up until it is.
    def looks_like_ret(v: int) -> bool:
        return text_lo <= v < text_hi

    first = struct.unpack("<I", uc.mem_read(esp, 4))[0]
    if not looks_like_ret(first):
        for adjust in (4, 8, 12, 16, 20, 24, 28, 32):
            cand = esp + adjust
            val = struct.unpack("<I", uc.mem_read(cand, 4))[0]
            if looks_like_ret(val):
                print(f"entry esp adjusted +{adjust}: 0x{esp:#x} -> 0x{cand:#x} "
                      f"(return address 0x{val:#x})")
                esp = cand
                break
        else:
            print("WARNING: no return address found on the stack; replaying anyway")

    for name, const in (("eax", UC_X86_REG_EAX), ("ecx", UC_X86_REG_ECX),
                        ("edx", UC_X86_REG_EDX), ("ebx", UC_X86_REG_EBX),
                        ("ebp", UC_X86_REG_EBP), ("esi", UC_X86_REG_ESI),
                        ("edi", UC_X86_REG_EDI)):
        uc.reg_write(const, state.get(name, 0))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EFLAGS, state.get("eflags", 0x202))

    # Stop when the function returns to its caller.
    ret_addr = 0
    for off, val in state["stack"]:
        if off == 0:
            ret_addr = val
            break

    trace: list[str] = []
    count = 0
    faults: list[tuple[int, int]] = []

    def on_code(uc_, address, size, user):
        nonlocal count
        count += 1
        if len(trace) < 4000:
            trace.append(f"{address:#010x}")

    uc.hook_add(UC_HOOK_CODE, on_code)

    print(f"running original at {state['eip']:#x} (return to {ret_addr:#x})")
    err = None
    try:
        uc.emu_start(state["eip"], ret_addr if ret_addr else 0xFFFFFFFF,
                     count=args.max_insns)
    except Exception as e:  # noqa: BLE001
        err = str(e)

    print(f"instructions executed: {count:,}")
    if err:
        print(f"ORIGINAL FAULTED: {err}")
        print("=> the state was already wrong before this function: look upstream")
    else:
        print("ORIGINAL COMPLETED")
        for name, const in (("eax", UC_X86_REG_EAX), ("ecx", UC_X86_REG_ECX),
                            ("edx", UC_X86_REG_EDX), ("ebx", UC_X86_REG_EBX),
                            ("esi", UC_X86_REG_ESI), ("edi", UC_X86_REG_EDI),
                            ("esp", UC_X86_REG_ESP)):
            print(f"  {name} = {uc.reg_read(const):#010x}")
        print("=> if the lifted build failed here, the LIFT of this function is wrong")

    if trace:
        print("\nfirst 40 executed addresses:")
        for t in trace[:40]:
            print(f"  {t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
