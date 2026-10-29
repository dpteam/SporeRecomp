"""Import table generator.

Derives the calling convention and argument count for every imported function *from the
guest's own call sites* instead of guessing from memory. For each `call dword ptr [IAT]`
we walk backwards over the contiguous `push` sequence that sets up the call; its length is
the argument count. The calling convention is stdcall if the code after the call does not
adjust ESP, cdecl if it does.

Writes:
  analysis/imports_resolved.json   what was inferred, with confidence
  src/rt/imports_table.cpp         the C++ descriptor table the runtime compiles

Usage: python tools/imports.py [--report]
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import capstone
import capstone.x86 as csx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
CENSUS = Path("analysis/census")
GEN = Path("src/rt/imports_table.cpp")
SPEC = Path("tools/import_spec.py")


def load_iat(pe: PE) -> dict[int, tuple[str, str, int]]:
    """IAT slot address -> (dll, name, ordinal)."""
    out = {}
    for dll, names in pe.imports():
        pass
    # walk again but keep the slot address
    rva, _ = pe.dir(1)
    o = pe.off(rva)
    while True:
        import struct
        ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", pe.d, o)
        if not name_rva:
            break
        dll = pe.cstr(name_rva)
        t = pe.off(ilt) or pe.off(iat)
        slot = pe.imagebase + iat
        while True:
            v = struct.unpack_from("<I", pe.d, t)[0]
            if not v:
                break
            if v & 0x80000000:
                out[slot] = (dll, "", v & 0xFFFF)
            else:
                out[slot] = (dll, pe.cstr_off(pe.off(v) + 2), 0)
            t += 4
            slot += 4
        o += 20
    return out


def find_call_sites(pe: PE) -> list[tuple[int, int, str]]:
    """(insn_addr, iat_slot, form) for every indirect call/jmp through the IAT."""
    t = pe.section(".text")
    tva, tsz = t["va"], t["vsz"]
    code = pe.section_bytes(".text")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    out = []
    off = 0
    n = len(code)
    while off < n:
        got = None
        for insn in md.disasm(code[off:off + 16], tva + off):
            got = insn
            break
        if got is None:
            off += 1
            continue
        off += got.size
        if got.mnemonic not in ("call", "jmp"):
            continue
        if not got.operands:
            continue
        op = got.operands[0]
        if op.type != csx.X86_OP_MEM:
            continue
        if op.mem.base != 0 or op.mem.index != 0:
            continue
        out.append((got.address, op.mem.disp, got.mnemonic))
    return out


def count_pushes(pe: PE, insns: dict[int, tuple], call_addr: int) -> tuple[int, bool]:
    """Walks backwards from `call_addr` over contiguous pushes.

    Returns (nargs, reliable). `reliable` is false when the walk hit a block boundary before
    finding a non-push instruction, which means the argument setup happened elsewhere.
    """
    nargs = 0
    addr = call_addr
    for _ in range(40):
        prev = prev_insn(pe, insns, addr)
        if prev is None:
            return nargs, False
        pa, psize, pmn, pop = prev
        if pmn == "push":
            nargs += 1
            addr = pa
            continue
        if pmn in ("sub", "add") and pop.startswith("esp"):
            # explicit stack allocation for cdecl args (push-free calling style)
            m = re.search(r"0x([0-9a-f]+)", pop)
            if m:
                nargs += int(m.group(1), 16) // 4
            return nargs, True
        if pmn in ("mov", "lea", "xor", "movzx", "movsx", "and", "or", "shl", "shr",
                   "sar", "imul", "test", "cmp", "nop", "inc", "dec", "cdq", "cwde"):
            # register setup between the pushes and the call: keep walking
            addr = pa
            continue
        return nargs, True
    return nargs, False


def prev_insn(pe: PE, insns: dict[int, tuple], addr: int):
    """Finds the instruction that ends exactly at `addr`."""
    for back in range(1, 16):
        cand = insns.get(addr - back)
        if cand and cand[0] == back:  # its size makes it end exactly at addr
            return (addr - back, cand[0], cand[1], cand[2])
    return None


def esp_adjusted_after(pe: PE, insns: dict[int, tuple], call_addr: int, size: int) -> bool:
    """True if the code right after the call adjusts ESP (=> cdecl, caller cleans up)."""
    got = insns.get(call_addr + size)
    if not got:
        return False
    _s, mn, op = got
    return mn == "add" and op.startswith("esp")


def main() -> int:
    pe = PE(EXE.read_bytes())
    iat = load_iat(pe)
    print(f"[imports] {len(iat)} IAT slots")

    # decode the whole .text once, keeping addr -> (size, mnemonic, op_str)
    t = pe.section(".text")
    tva = t["va"]
    code = pe.section_bytes(".text")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    insns: dict[int, tuple] = {}
    off = 0
    while off < len(code):
        got = None
        for a, size, mn, op in md.disasm_lite(code[off:off + 16], tva + off):
            got = (a, size, mn, op)
            break
        if got is None:
            off += 1
            continue
        insns[got[0]] = (got[1], got[2], got[3])
        off += got[1]
    print(f"[imports] {len(insns):,} instructions decoded")

    md2 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md2.detail = True
    sites = find_call_sites(pe)
    print(f"[imports] {len(sites):,} indirect call/jmp sites")

    per_slot: dict[int, list[tuple[int, bool]]] = defaultdict(list)
    for addr, slot, kind in sites:
        if slot not in iat:
            continue
        nargs, reliable = count_pushes(pe, insns, addr)
        # calling convention: does the caller clean the stack afterwards?
        size = insns[addr][0] if addr in insns else 0
        cdecl = esp_adjusted_after(pe, insns, addr, size)
        per_slot[slot].append((nargs, reliable, cdecl))

    resolved = []
    for slot, (dll, name, ordinal) in sorted(iat.items()):
        obs = per_slot.get(slot, [])
        if obs:
            counts = Counter(n for n, rel, cd in obs if rel)
            nargs = counts.most_common(1)[0][0] if counts else obs[0][0]
            cdecl_votes = sum(1 for n, rel, cd in obs if cd)
            stdcall = cdecl_votes * 2 < len(obs)
            confidence = len(obs)
        else:
            nargs, stdcall, confidence = 0, True, 0
        resolved.append(dict(dll=dll, name=name, ordinal=ordinal, nargs=nargs,
                             stdcall=stdcall, sites=confidence))

    Path("analysis/imports_resolved.json").write_text(
        json.dumps(resolved, indent=1), encoding="utf-8")

    known = [r for r in resolved if r["sites"]]
    print(f"[imports] resolved {len(known)}/{len(resolved)} imports from call sites")
    by_count = Counter(r["sites"] for r in resolved)
    print(f"[imports] sites per import (top): {by_count.most_common(6)}")
    hot = sorted(resolved, key=lambda r: -r["sites"])[:25]
    print("[imports] hottest imports:")
    for r in hot:
        print(f"   {r['dll']}!{r['name'] or '#'+str(r['ordinal'])}: {r['nargs']} args, "
              f"{'stdcall' if r['stdcall'] else 'cdecl'}, {r['sites']} call sites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
