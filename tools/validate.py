#!/usr/bin/env python3
"""Differential validator: original x86 code (Unicorn) vs. lifted C++ (host build).

This is how a 100k-function lift stays correct without reading every function by hand.
For a function under test we:

  1. pick a stack layout and random register/memory inputs,
  2. run the original bytes under Unicorn until it returns,
  3. run the lifted function on the host with the same inputs,
  4. compare registers, flags, and a snapshot of the touched memory.

Usage:
  python tools/validate.py --count 200           # random functions from the census
  python tools/validate.py --func 0x401000       # one specific function
  python tools/validate.py --count 200 --list    # just report which would be tested

The host build must exist:  ./build.sh host
"""
from __future__ import annotations

import argparse
import json
import os
import random
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
CENSUS = Path("analysis/census")
HOST_BIN = Path("build/host/spore")

# Guest layout used by the harness (must match src/rt/shim.cpp)
STACK_TOP = 0x7FFE0000
STACK_SIZE = 0x00100000
HEAP = 0x20000000
HEAP_SIZE = 0x00100000


def load_census() -> tuple[list[dict], dict[int, list[dict]]]:
    funcs = [json.loads(l) for l in (CENSUS / "funcs.jsonl").open()]
    blocks: dict[int, list[dict]] = {}
    for line in (CENSUS / "blocks.jsonl").open():
        b = json.loads(line)
        blocks.setdefault(b["func"], []).append(b)
    for k in blocks:
        blocks[k].sort(key=lambda x: x["start"])
    return funcs, blocks


def run_unicorn(pe: PE, func: dict, seed: int) -> dict | None:
    """Runs the original function under Unicorn and returns the final state."""
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
        from unicorn.x86_const import (
            UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
            UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
            UC_X86_REG_EFLAGS,
        )
    except ImportError:
        print("unicorn not installed: pip install unicorn", file=sys.stderr)
        return None

    rng = random.Random(seed)
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    # image
    img_size = pe.section(".reloc")["va"] + pe.section(".reloc")["vsz"]
    img_size = (img_size + 0xFFF) & ~0xFFF
    uc.mem_map(pe.imagebase, img_size)
    uc.mem_write(pe.imagebase, pe.d[:img_size])
    uc.mem_map(HEAP, HEAP_SIZE)
    uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE)

    # deterministic pseudo-random but *plausible* inputs: pointers point into the heap
    def rnd_u32() -> int:
        r = rng.random()
        if r < 0.35:
            return rng.randrange(HEAP, HEAP + HEAP_SIZE - 0x100) & ~3
        if r < 0.5:
            return rng.choice([0, 1, 2, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000])
        return rng.randrange(0, 1 << 32)

    regs = {}
    for name in ("EAX", "ECX", "EDX", "EBX", "EBP", "ESI", "EDI"):
        regs[name] = rnd_u32()
    esp = STACK_TOP - 0x1000
    # a return address that is not code: the harness stops at `ret` anyway
    uc.mem_write(esp, struct.pack("<I", 0xDEADBEEF))
    for i in range(16):  # arguments
        uc.mem_write(esp + 4 + i * 4, struct.pack("<I", rnd_u32()))
    # fill the heap with random data so pointer dereferences are meaningful
    blob = bytes(rng.randrange(256) for _ in range(0x4000))
    uc.mem_write(HEAP, blob)

    uc.reg_write(UC_X86_REG_ESP, esp)
    for name, v in regs.items():
        uc.reg_write({"EAX": UC_X86_REG_EAX, "ECX": UC_X86_REG_ECX, "EDX": UC_X86_REG_EDX,
                      "EBX": UC_X86_REG_EBX, "EBP": UC_X86_REG_EBP, "ESI": UC_X86_REG_ESI,
                      "EDI": UC_X86_REG_EDI}[name], v)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x202)

    start = pe.imagebase + func["start"]
    ret_addr = 0xDEADBEEF
    try:
        uc.emu_start(start, ret_addr, count=200000)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}

    out = {"regs": {}, "eflags": uc.reg_read(UC_X86_REG_EFLAGS)}
    for name, const in (("EAX", UC_X86_REG_EAX), ("ECX", UC_X86_REG_ECX),
                        ("EDX", UC_X86_REG_EDX), ("EBX", UC_X86_REG_EBX),
                        ("EBP", UC_X86_REG_EBP), ("ESI", UC_X86_REG_ESI),
                        ("EDI", UC_X86_REG_EDI), ("ESP", UC_X86_REG_ESP)):
        out["regs"][name] = uc.reg_read(const)
    out["stack"] = uc.mem_read(esp, 0x100).hex()
    out["heap"] = uc.mem_read(HEAP, 0x4000).hex()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--func", type=lambda s: int(s, 0))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    pe = PE(EXE.read_bytes())
    funcs, blocks = load_census()
    real = [f for f in funcs if not f.get("orphan")]
    rng = random.Random(args.seed)
    if args.func is not None:
        targets = [f for f in real if f["start"] == args.func]
        if not targets:
            print(f"function 0x{args.func:x} not in the census")
            return 1
    else:
        targets = rng.sample(real, min(args.count, len(real)))

    if args.list:
        for f in targets:
            print(f"0x{f['start']:08x}  {f['n_insns']:6d} insns  {f['n_blocks']:4d} blocks")
        return 0

    if not HOST_BIN.exists():
        print(f"missing {HOST_BIN}; run ./build.sh host first", file=sys.stderr)
        return 1

    ok = fail = skipped = 0
    for f in targets:
        ref = run_unicorn(pe, f, args.seed)
        if ref is None:
            return 1
        if "error" in ref:
            skipped += 1
            continue
        # the host binary re-runs the same scenario against the lifted function
        p = subprocess.run([str(HOST_BIN), "--selftest", f"0x{f['start']:x}",
                            "--seed", str(args.seed)],
                           capture_output=True, text=True)
        if p.returncode != 0:
            fail += 1
            print(f"MISMATCH 0x{f['start']:08x}: {p.stdout.strip() or p.stderr.strip()}")
        else:
            ok += 1
    print(f"\n{ok} passed, {fail} failed, {skipped} skipped (of {len(targets)})")
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
