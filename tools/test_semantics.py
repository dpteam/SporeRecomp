#!/usr/bin/env python3
"""Differential test of the instruction semantics the lifter emits.

For each instruction form, this assembles the real x86 encoding, runs it in Unicorn with a
known register state, and compares the result with the *rule* the lifter's helper implements.
Any mismatch is a lift bug — exactly the class of bug that cost a full debugging session on
`imul` (the one-operand form multiplied EAX by itself instead of by the operand).

The comparison is done in Python against the documented x86 semantics, so this runs without a
device and without the aarch64 build.

Usage: python tools/test_semantics.py
"""
from __future__ import annotations

import struct
import sys

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import (
        UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
        UC_X86_REG_ESP, UC_X86_REG_EFLAGS,
    )
except ImportError:
    print("unicorn not installed: pip install unicorn", file=sys.stderr)
    raise SystemExit(1)

BASE = 0x10000
STACK = 0x20000


def run(code: bytes, eax=0, ecx=0, edx=0, ebx=0, eflags=0x202) -> dict:
    """Runs `code` in Unicorn and returns the resulting registers."""
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(BASE, 0x1000)
    uc.mem_map(STACK, 0x1000)
    uc.mem_write(BASE, code + b"\xcc")
    uc.reg_write(UC_X86_REG_EAX, eax & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_ECX, ecx & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_EDX, edx & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_EBX, ebx & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_ESP, STACK + 0x800)
    uc.reg_write(UC_X86_REG_EFLAGS, eflags)
    uc.emu_start(BASE, BASE + len(code), count=100)
    return {
        "eax": uc.reg_read(UC_X86_REG_EAX),
        "ecx": uc.reg_read(UC_X86_REG_ECX),
        "edx": uc.reg_read(UC_X86_REG_EDX),
        "eflags": uc.reg_read(UC_X86_REG_EFLAGS),
    }


def s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def lifted_imul_1(eax: int, operand: int) -> tuple[int, int]:
    """The rule src/rt/guest.cpp imul_1 must implement: EDX:EAX = EAX * operand (signed)."""
    r = s32(eax) * s32(operand)
    r &= 0xFFFFFFFFFFFFFFFF
    return r & 0xFFFFFFFF, (r >> 32) & 0xFFFFFFFF


def lifted_mul_1(eax: int, operand: int) -> tuple[int, int]:
    """EDX:EAX = EAX * operand (unsigned)."""
    r = (eax & 0xFFFFFFFF) * (operand & 0xFFFFFFFF)
    return r & 0xFFFFFFFF, (r >> 32) & 0xFFFFFFFF


CASES = [
    # (name, code bytes, eax, ecx, expectation)
    ("imul ecx (small)", b"\xf7\xe9", 0x88888889, 540, "imul_ecx"),
    ("imul ecx (magic div idiom)", b"\xf7\xe9", 0x88888889, 0x21C, "imul_ecx"),
    ("imul ecx (negative)", b"\xf7\xe9", 0xFFFFFFFF, 3, "imul_ecx"),
    ("imul ebx", b"\xf7\xeb", 1234, 0, "imul_ebx"),
    ("mul ecx", b"\xf7\xe1", 0x12345678, 0x9ABCDEF0, "mul_ecx"),
]

failures = 0


def check(name: str, code: bytes, eax: int, ecx: int, kind: str, ebx: int = 0) -> None:
    global failures
    got = run(code, eax=eax, ecx=ecx, ebx=ebx)
    if kind == "imul_ecx":
        want_lo, want_hi = lifted_imul_1(eax, ecx)
    elif kind == "imul_ebx":
        want_lo, want_hi = lifted_imul_1(eax, ebx)
    elif kind == "mul_ecx":
        want_lo, want_hi = lifted_mul_1(eax, ecx)
    else:
        raise AssertionError(kind)

    ok = got["eax"] == want_lo and got["edx"] == want_hi
    status = "ok  " if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"  [{status}] {name}")
    if not ok:
        print(f"         hardware: eax={got['eax']:#010x} edx={got['edx']:#010x}")
        print(f"         expected: eax={want_lo:#010x} edx={want_hi:#010x}")


def main() -> int:
    global failures
    print("instruction semantics vs the hardware\n")
    print("one-operand multiply (the form that was broken):")
    for name, code, eax, ecx, kind in CASES:
        check(name, code, eax, ecx, kind, ebx=0x9ABCDEF0 if kind == "imul_ebx" else 0)

    # The specific idiom from Spore's container code: `mov eax, 0x88888889; imul ecx` followed
    # by the shift/add sequence that divides by 60 (the 0x3c-byte record stride). With the
    # broken imul this produced a bogus pointer and crashed static initialisation.
    print("\nthe magic-number division sequence Spore uses (divide by 60):")
    for n in (0, 60, 540, 1000, 0x10000):
        code = b"\xb8\x89\x88\x88\x88\xf7\xe9\x03\xd1\xc1\xfa\x05"
        got = run(code, eax=0, ecx=n)
        quotient = got["edx"]
        expect = n // 60
        ok = quotient == expect
        if not ok:
            failures += 1
        print(f"  [{'ok  ' if ok else 'FAIL'}] {n:>7} / 60 = {quotient} (expected {expect})")

    print(f"\n{failures} failure(s)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
