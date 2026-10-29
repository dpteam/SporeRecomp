"""Function discovery + control-flow census for SporeApp.exe.

Pass A: linear sweep of .text (fast, mnemonics only) -> call/jmp targets, mnemonic histogram.
Pass B: recursive descent from every seed -> function ranges, basic blocks, indirect jumps.
Writes analysis/functions.jsonl and analysis/scan_report.md.

Usage: python tools/scan.py [--exe PATH] [--limit N]
"""
from __future__ import annotations

import json
import re
import struct
import sys
import bisect
from collections import Counter
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
TEXT = ".text"
MAX_FUNC = 0x20000
MAX_INSN_PER_FUNC = 20000


def parse_target(op_str: str) -> int | None:
    """'0x401000' -> 0x401000 (absolute), None otherwise."""
    m = re.fullmatch(r"0x([0-9a-f]+)", op_str.strip())
    return int(m.group(1), 16) if m else None


def main() -> int:
    args = sys.argv[1:]
    exe = Path(args[args.index("--exe") + 1]) if "--exe" in args else EXE
    pe = PE(exe.read_bytes())
    tsec = pe.section(TEXT)
    tva, tsz = tsec["va"], tsec["vsz"]
    tbytes = pe.section_bytes(TEXT)
    tend = tva + tsz

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False

    # ---------- pass A: linear sweep -------------------------------------
    # disasm_lite() stops at the first undecodable byte, so sweep manually and
    # skip one byte on failure (data islands inside .text are common in MSVC).
    print(f"[scan] sweeping {tsz:,} bytes of .text ...", flush=True)
    hist: Counter[str] = Counter()
    call_targets: set[int] = set()
    jmp_targets: set[int] = set()
    indirect_jmp_sites = 0
    n_insn = 0
    bad_bytes = 0
    off = 0
    n = len(tbytes)
    while off < n:
        got = None
        for addr, size, mn, op in md.disasm_lite(tbytes[off:off + 16], tva + off):
            got = (addr, size, mn, op)
            break
        if got is None:
            off += 1
            bad_bytes += 1
            continue
        addr, size, mn, op = got
        off += size
        n_insn += 1
        hist[mn] += 1
        if mn in ("call", "jmp") or (mn[0] == "j" and mn != "jmp"):
            t = parse_target(op)
            if t is None:
                if mn == "jmp":
                    indirect_jmp_sites += 1
                continue
            if tva <= t < tend:
                (call_targets if mn == "call" else jmp_targets).add(t)
    print(f"[scan] undecodable bytes skipped: {bad_bytes:,}")
    print(f"[scan] {n_insn:,} instructions, {len(call_targets):,} call targets, "
          f"{len(jmp_targets):,} branch targets, {indirect_jmp_sites:,} indirect jmp sites")

    # ---------- seeds ----------------------------------------------------
    seeds: set[int] = set()
    seeds.add(pe.entry)
    seeds |= call_targets
    # classic MSVC prologues
    for pat in (b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x8b\xff\x55\x8b\xec"):
        i = tbytes.find(pat)
        while i != -1:
            seeds.add(tva + i)
            i = tbytes.find(pat, i + 1)
    # absolute pointers into .text from .reloc / .rdata / .data
    ptr_sections = (".reloc", ".rdata", ".data")
    for sname in ptr_sections:
        if sname == ".reloc":
            continue
        s = pe.section(sname)
        raw = pe.section_bytes(sname)
        for i in range(0, len(raw) - 4, 4):
            v = struct.unpack_from("<I", raw, i)[0]
            if tva <= v < tend:
                seeds.add(v)
    for rva in pe.relocs():
        o = pe.off(rva)
        if o is None:
            continue
        v = struct.unpack_from("<I", pe.d, o)[0]
        if tva <= v < tend:
            seeds.add(v)
    print(f"[scan] {len(seeds):,} seeds")

    # ---------- pass B: recursive descent -------------------------------
    funcs: list[dict] = []
    covered: list[tuple[int, int]] = []  # sorted, merged ranges
    unsupported_indirect: Counter[str] = Counter()

    def decode_func(start: int) -> dict:
        work = [start]
        seen_blocks: set[int] = set()
        end = start
        insns = 0
        blocks = 0
        ind = 0
        calls = 0
        jump_tables = 0
        ok = True
        while work:
            b = work.pop()
            if b in seen_blocks or not (tva <= b < tend):
                continue
            seen_blocks.add(b)
            blocks += 1
            cur = b
            while True:
                o = pe.off(cur)
                if o is None or cur < start or cur - start > MAX_FUNC:
                    ok = False
                    break
                got = None
                for addr, size, mn, op in md.disasm_lite(pe.d[o:o + 16], cur):
                    got = (addr, size, mn, op)
                    break
                if got is None:
                    ok = False
                    break
                addr, size, mn, op = got
                insns += 1
                if insns > MAX_INSN_PER_FUNC:
                    ok = False
                    break
                end = max(end, addr + size)
                nxt = addr + size
                if mn == "ret" or mn.startswith("retn") or mn.startswith("iret"):
                    break
                if mn == "int3" or mn == "int 3":
                    break
                if mn == "call":
                    t = parse_target(op)
                    if t is not None and tva <= t < tend:
                        calls += 1
                        work.append(t)
                    cur = nxt
                    continue
                if mn == "jmp":
                    t = parse_target(op)
                    if t is not None and tva <= t < tend:
                        work.append(t)
                    else:
                        ind += 1
                        if "*" in op and "4" in op:
                            jump_tables += 1
                    break
                if mn[0] == "j" and mn != "jmp":
                    t = parse_target(op)
                    if t is not None and tva <= t < tend:
                        work.append(t)
                    cur = nxt
                    continue
                if mn in ("hlt", "ud2"):
                    break
                cur = nxt
        return dict(start=start, end=end, insns=insns, blocks=blocks,
                    indirect_jmps=ind, calls=calls, jump_tables=jump_tables, ok=ok)

    def covered_at(a: int) -> bool:
        i = bisect.bisect_right(covered, (a, 1 << 32)) - 1
        return i >= 0 and covered[i][0] <= a < covered[i][1]

    def add_covered(lo: int, hi: int) -> None:
        """Insert a range and merge neighbours so `covered` stays disjoint+sorted."""
        i = bisect.bisect_left(covered, (lo, 0))
        if i > 0 and covered[i - 1][1] >= lo:
            i -= 1
            lo = min(lo, covered[i][0])
            hi = max(hi, covered[i][1])
            covered.pop(i)
        while i < len(covered) and covered[i][0] <= hi:
            hi = max(hi, covered[i][1])
            covered.pop(i)
        covered.insert(i, (lo, hi))

    seeds_sorted = sorted(seeds)
    print(f"[scan] recursive descent over {len(seeds_sorted):,} seeds ...", flush=True)
    for i, s in enumerate(seeds_sorted):
        if covered_at(s):
            continue
        f = decode_func(s)
        if f["insns"] == 0:
            continue
        funcs.append(f)
        add_covered(f["start"], f["end"])
        if i and i % 20000 == 0:
            print(f"[scan]   {i:,}/{len(seeds_sorted):,} seeds, {len(funcs):,} functions",
                  flush=True)

    # ---------- report ---------------------------------------------------
    total_insn = sum(f["insns"] for f in funcs)
    out = Path("analysis")
    out.mkdir(exist_ok=True)
    with (out / "functions.jsonl").open("w", encoding="utf-8") as fh:
        for f in sorted(funcs, key=lambda x: x["start"]):
            fh.write(json.dumps(f) + "\n")

    lines = []
    w = lines.append
    w("# Function discovery — SporeApp.exe\n")
    w(f"* linear sweep: {n_insn:,} instructions in .text ({tsz:,} bytes)")
    w(f"* seeds: {len(seeds):,} (entry + call targets + prologues + code pointers)")
    w(f"* functions recovered: {len(funcs):,}")
    w(f"* instructions inside functions: {total_insn:,}")
    w(f"* call targets: {len(call_targets):,}; branch targets: {len(jmp_targets):,}")
    w(f"* indirect `jmp` sites in sweep: {indirect_jmp_sites:,}")
    w(f"* functions with indirect jmp: {sum(1 for f in funcs if f['indirect_jmps']):,}")
    w(f"* functions with jump-table-shaped indirect jmp: "
      f"{sum(1 for f in funcs if f['jump_tables']):,}")
    w(f"* largest functions: " + ", ".join(
        f"0x{f['start']:x} ({f['insns']:,} insn)"
        for f in sorted(funcs, key=lambda x: -x["insns"])[:5]))
    w("\n## Mnemonic histogram (top 60)\n")
    w("| mnemonic | count |\n|---|---|")
    for mn, c in hist.most_common(60):
        w(f"| {mn} | {c:,} |")
    odd = ("in", "out", "sysenter", "sysexit", "hlt", "ud2", "lcall", "ljmp", "fwait",
           "insb", "outsb", "pushad", "popad", "xlatb", "enter", "aaa", "aas", "daa", "das")
    w("\n## Rare / risky mnemonics\n")
    for mn in odd:
        if hist.get(mn):
            w(f"* {mn}: {hist[mn]:,}")
    (out / "scan_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:12]))
    print(f"[scan] wrote analysis/functions.jsonl ({len(funcs):,} funcs), analysis/scan_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
