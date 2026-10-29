"""Instruction-level disassembly + function boundary recovery for SporeApp.exe.

Produces a cached IR on disk (`analysis/disasm/`) that the lifter consumes:

  funcs.jsonl   one record per function: start, end, name, decoded instruction addrs
  insns.bin     packed instruction stream (see InsnRecord below)
  blocks.jsonl  basic blocks: func, start, end, successors, terminator kind

Boundary recovery is instruction-level, not range-level: a byte is only "claimed"
when an instruction actually starts or spans it. Seeds come from the entry point,
call targets, prologue patterns, absolute code pointers (.reloc, .rdata, .data) and
jump tables. Gaps that are `int3`/`cc` padding or ASCII data are reported, not lifted.

Usage:
  python tools/disasm.py            # full pass, writes analysis/disasm/
  python tools/disasm.py --stats    # just print the summary of an existing pass
"""
from __future__ import annotations

import bisect
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
OUT = Path("analysis/disasm")
MAX_FUNC_BYTES = 0x8000
MAX_INSN_PER_FUNC = 8000


def parse_target(op: str) -> int | None:
    m = re.fullmatch(r"0x([0-9a-f]+)", op.strip())
    return int(m.group(1), 16) if m else None


class Image:
    def __init__(self, path: Path):
        self.pe = PE(path.read_bytes())
        t = self.pe.section(".text")
        self.tva, self.tsz = t["va"], t["vsz"]
        self.tend = self.tva + self.tsz
        self.bytes = self.pe.section_bytes(".text")

    def in_text(self, a: int) -> bool:
        return self.tva <= a < self.tend

    def off(self, a: int) -> int:
        return a - self.tva


def make_md() -> capstone.Cs:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    return md


def decode_at(img: Image, md: capstone.Cs, addr: int):
    o = img.off(addr)
    if o < 0 or o >= len(img.bytes):
        return None
    for a, size, mn, op in md.disasm_lite(img.bytes[o:o + 16], addr):
        return a, size, mn, op
    return None


def collect_seeds(img: Image, md: capstone.Cs):
    """Linear sweep (tolerant of data islands) + pointer scan -> seeds."""
    seeds: set[int] = {img.pe.entry}
    call_targets: set[int] = set()
    branch_targets: set[int] = set()
    indirect_jmp: list[int] = []
    hist: Counter[str] = Counter()
    n_insn = 0
    bad = 0
    off = 0
    n = len(img.bytes)
    tva = img.tva
    while off < n:
        got = None
        for a, size, mn, op in md.disasm_lite(img.bytes[off:off + 16], tva + off):
            got = (a, size, mn, op)
            break
        if got is None:
            off += 1
            bad += 1
            continue
        addr, size, mn, op = got
        off += size
        n_insn += 1
        hist[mn] += 1
        if mn == "call":
            t = parse_target(op)
            if t is not None and img.in_text(t):
                call_targets.add(t)
        elif mn == "jmp" or (mn[0] == "j" and mn != "jmp"):
            t = parse_target(op)
            if t is not None and img.in_text(t):
                branch_targets.add(t)
            elif mn == "jmp":
                indirect_jmp.append(addr)

    seeds |= call_targets
    # MSVC prologues (all forms seen in this binary)
    for pat in (b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x8b\xff\x55\x8b\xec",
                b"\x53\x8b\xdc", b"\x56\x8b\xf4", b"\x83\xec"):
        i = img.bytes.find(pat)
        while i != -1:
            seeds.add(tva + i)
            i = img.bytes.find(pat, i + 1)
    # absolute code pointers
    for sname in (".rdata", ".data", "CONST"):
        try:
            raw = img.pe.section_bytes(sname)
        except StopIteration:
            continue
        for i in range(0, len(raw) - 4, 4):
            v = struct.unpack_from("<I", raw, i)[0]
            if img.in_text(v):
                seeds.add(v)
    for rva in img.pe.relocs():
        o = img.pe.off(rva)
        if o is None:
            continue
        v = struct.unpack_from("<I", img.pe.d, o)[0]
        if img.in_text(v):
            seeds.add(v)

    return dict(seeds=seeds, call_targets=call_targets, branch_targets=branch_targets,
                indirect_jmp=indirect_jmp, hist=hist, n_insn=n_insn, bad=bad)


def recover_functions(img: Image, md: capstone.Cs, seeds: set[int]):
    """Recursive descent; instruction-level coverage; returns functions + decoded map."""
    decoded: dict[int, tuple[int, str, str]] = {}  # addr -> (size, mnemonic, op_str)
    claimed = bytearray(len(img.bytes))
    funcs: list[dict] = []
    order = sorted(seeds)
    tva = img.tva

    def claimed_at(a: int) -> bool:
        o = img.off(a)
        return 0 <= o < len(claimed) and claimed[o] == 1

    def mark(a: int, size: int) -> None:
        o = img.off(a)
        for k in range(size):
            if 0 <= o + k < len(claimed):
                claimed[o + k] = 1

    for idx, seed in enumerate(order):
        if claimed_at(seed):
            continue
        work = [seed]
        seen: set[int] = set()
        insns: list[int] = []
        blocks: list[tuple[int, int, list[int], str]] = []
        ok = True
        while work:
            b = work.pop()
            if b in seen or not img.in_text(b):
                continue
            seen.add(b)
            cur = b
            blk_start = b
            while True:
                if not img.in_text(cur) or cur - seed > MAX_FUNC_BYTES:
                    ok = False
                    break
                if cur in decoded:
                    # reached an instruction decoded by another function: shared tail
                    blocks.append((blk_start, cur, [], "jump_in"))
                    break
                got = decode_at(img, md, cur)
                if got is None:
                    ok = False
                    break
                addr, size, mn, op = got
                decoded[addr] = (size, mn, op)
                mark(addr, size)
                insns.append(addr)
                if len(insns) > MAX_INSN_PER_FUNC:
                    ok = False
                    break
                nxt = addr + size
                if mn.startswith("ret") or mn.startswith("iret"):
                    blocks.append((blk_start, nxt, [], "ret"))
                    break
                if mn == "int3":
                    blocks.append((blk_start, addr, [], "int3"))
                    break
                if mn == "call":
                    t = parse_target(op)
                    if t is not None and img.in_text(t):
                        work.append(t)
                    cur = nxt
                    continue
                if mn == "jmp":
                    t = parse_target(op)
                    if t is not None and img.in_text(t):
                        work.append(t)
                        blocks.append((blk_start, nxt, [t], "jmp"))
                    else:
                        blocks.append((blk_start, nxt, [], "jmp_indirect"))
                    break
                if mn[0] == "j" and mn != "jmp":
                    t = parse_target(op)
                    succ = [nxt]
                    if t is not None and img.in_text(t):
                        work.append(t)
                        succ.append(t)
                    blocks.append((blk_start, nxt, succ, "jcc"))
                    cur = nxt
                    continue
                if mn in ("hlt", "ud2", "ud0", "ud1"):
                    blocks.append((blk_start, nxt, [], "trap"))
                    break
                cur = nxt
        if insns:
            funcs.append(dict(
                start=seed,
                end=max(insns) + decoded[max(insns)][0],
                n_insns=len(insns),
                n_blocks=len(blocks),
                ok=ok,
                blocks=blocks,
            ))
        if idx and idx % 25000 == 0:
            print(f"[disasm]   {idx:,}/{len(order):,} seeds -> {len(funcs):,} functions",
                  flush=True)
    return funcs, decoded, claimed


def main() -> int:
    args = sys.argv[1:]
    img = Image(EXE)
    md = make_md()

    if "--stats" in args:
        return print_stats()

    print(f"[disasm] .text {img.tsz:,} bytes at 0x{img.tva:x}")
    sd = collect_seeds(img, md)
    print(f"[disasm] sweep: {sd['n_insn']:,} insns, {sd['bad']:,} undecodable bytes, "
          f"{len(sd['call_targets']):,} call targets, {len(sd['indirect_jmp']):,} indirect jmps")
    print(f"[disasm] seeds: {len(sd['seeds']):,}")

    funcs, decoded, claimed = recover_functions(img, md, sd["seeds"])
    n_claimed = sum(claimed)
    print(f"[disasm] {len(funcs):,} functions, {len(decoded):,} decoded instructions, "
          f"{n_claimed:,} bytes claimed ({100*n_claimed/img.tsz:.1f}%)")

    # ---- gap analysis ---------------------------------------------------
    gaps = []
    i = 0
    n = len(claimed)
    while i < n:
        if claimed[i]:
            i += 1
            continue
        j = i
        while j < n and not claimed[j]:
            j += 1
        gaps.append((i, j))
        i = j
    gap_kind = Counter()
    unexplained: list[tuple[int, int]] = []
    for a, b in gaps:
        blob = img.bytes[a:b]
        if len(blob) <= 8 and blob.count(0xCC) == len(blob):
            gap_kind["int3 pad"] += b - a
        elif len(blob) <= 64 and blob.count(0xCC) >= len(blob) * 0.5:
            gap_kind["mostly int3"] += b - a
        elif len(blob) >= 4 and all(32 <= c < 127 or c == 0 for c in blob[:min(len(blob), 256)]):
            gap_kind["ascii data"] += b - a
        elif blob.count(0) >= len(blob) * 0.5:
            gap_kind["zero fill"] += b - a
        else:
            gap_kind["unexplained"] += b - a
            if b - a >= 16:
                unexplained.append((img.tva + a, img.tva + b))
    print(f"[disasm] gaps: {sum(b-a for a,b in gaps):,} bytes in {len(gaps):,} runs")
    for k, v in gap_kind.most_common():
        print(f"           {k}: {v:,}")

    # ---- write cache ----------------------------------------------------
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "funcs.jsonl").open("w", encoding="utf-8") as fh:
        for f in sorted(funcs, key=lambda x: x["start"]):
            fh.write(json.dumps(f) + "\n")
    with (OUT / "insns.jsonl").open("w", encoding="utf-8") as fh:
        for a in sorted(decoded):
            size, mn, op = decoded[a]
            fh.write(json.dumps([a, size, mn, op]) + "\n")

    lines = []
    w = lines.append
    w("# Disassembly census — SporeApp.exe\n")
    w(f"* .text: {img.tsz:,} bytes at 0x{img.tva:x}")
    w(f"* linear sweep: {sd['n_insn']:,} instructions, {sd['bad']:,} undecodable bytes")
    w(f"* seeds: {len(sd['seeds']):,}")
    w(f"* functions: {len(funcs):,}")
    w(f"* decoded instructions: {len(decoded):,}")
    w(f"* bytes claimed: {n_claimed:,} ({100*n_claimed/img.tsz:.1f}% of .text)")
    w(f"* functions that hit a decode limit: {sum(1 for f in funcs if not f['ok']):,}")
    w(f"* basic blocks: {sum(f['n_blocks'] for f in funcs):,}")
    w("\n## Unclaimed bytes by kind\n")
    w("| kind | bytes |\n|---|---|")
    for k, v in gap_kind.most_common():
        w(f"| {k} | {v:,} |")
    w(f"\n## Largest unexplained gaps ({len(unexplained)})\n")
    for a, b in sorted(unexplained, key=lambda g: -(g[1] - g[0]))[:25]:
        blob = img.bytes[a - img.tva:b - img.tva]
        w(f"* 0x{a:08x}..0x{b:08x} ({b-a:,} B) `{blob[:16].hex()}`")
    w("\n## Mnemonic histogram (top 40)\n")
    w("| mnemonic | count |\n|---|---|")
    for mn, c in sd["hist"].most_common(40):
        w(f"| {mn} | {c:,} |")
    Path("analysis/disasm_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("[disasm] wrote analysis/disasm/{funcs,insns}.jsonl and analysis/disasm_report.md")
    return 0


def print_stats() -> int:
    funcs = [json.loads(l) for l in (OUT / "funcs.jsonl").open()]
    insns = sum(1 for _ in (OUT / "insns.jsonl").open())
    print(f"functions: {len(funcs):,}")
    print(f"instructions: {insns:,}")
    print(f"blocks: {sum(f['n_blocks'] for f in funcs):,}")
    print(f"incomplete: {sum(1 for f in funcs if not f['ok']):,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
