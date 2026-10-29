"""Instruction census for SporeApp.exe — the ground truth the lifter builds on.

Method: linear sweep with re-sync. The binary decodes almost perfectly (only a few hundred
undecodable bytes out of 16.5 MB), so a sweep gives us a near-complete map of instruction
starts. Function recovery then works *on top of* that map instead of re-decoding from
heuristic seeds, which avoids the classic problem of bogus seeds claiming bytes that belong
to real functions.

Outputs (analysis/census/):
  insns.bin     packed: u32 addr, u8 len, u8 mnemonic_id, u8 nops, u8 flags, u32 ops[3]
  mnemonics.txt mnemonic id -> text
  funcs.jsonl   one record per recovered function
  blocks.jsonl  basic blocks with successors
  census_report.md

Usage: python tools/census.py [--report-only]
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
OUT = Path("analysis/census")
INS_REC = struct.Struct("<IBBHIIII")  # addr, len, nops, mn_id, flags, op0, op1, op2

FLAG_HAS_ABS = 1  # operand is an absolute address inside the image (needs relocation)


def parse_imm(op: str) -> int | None:
    m = re.fullmatch(r"0x([0-9a-f]+)", op.strip())
    return int(m.group(1), 16) if m else None


def split_ops(op_str: str) -> list[str]:
    """Split 'eax, dword ptr [0x401000]' respecting brackets."""
    out, depth, cur = [], 0, ""
    for ch in op_str:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


class Census:
    def __init__(self):
        self.pe = PE(EXE.read_bytes())
        t = self.pe.section(".text")
        # Everything in this tool works in *guest virtual addresses*: the guest's own code
        # pointers (vtables, callbacks, jump tables in data) are VAs, so keying the function
        # table by VA is the only way the runtime can match them without conversion bugs.
        self.tva = self.pe.va(t["va"])
        self.tsz = t["vsz"]
        self.tend = self.tva + self.tsz
        self.code = self.pe.section_bytes(".text")
        # instruction map: address -> index into arrays
        self.addrs: list[int] = []
        self.lens: list[int] = []
        self.mns: list[str] = []
        self.ops: list[list[str]] = []

    # ------------------------------------------------------------------
    def sweep(self) -> None:
        cache = OUT / "sweep.pkl"
        if cache.exists():
            import pickle
            with cache.open("rb") as fh:
                d = pickle.load(fh)
            self.addrs, self.lens, self.mns, self.ops, self.bad_bytes = (
                d["addrs"], d["lens"], d["mns"], d["ops"], d["bad"])
            print(f"[census] {len(self.addrs):,} instructions (cached sweep)", flush=True)
            return
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = False
        bad = 0
        off = 0
        n = len(self.code)
        tva = self.tva
        addrs, lens, mns, ops = self.addrs, self.lens, self.mns, self.ops
        while off < n:
            got = None
            for a, size, mn, op in md.disasm_lite(self.code[off:off + 16], tva + off):
                got = (a, size, mn, op)
                break
            if got is None:
                off += 1
                bad += 1
                continue
            a, size, mn, op = got
            addrs.append(a)
            lens.append(size)
            mns.append(mn)
            ops.append(split_ops(op) if op else [])
            off += size
        self.bad_bytes = bad
        print(f"[census] {len(addrs):,} instructions, {bad:,} undecodable bytes", flush=True)
        OUT.mkdir(parents=True, exist_ok=True)
        import pickle
        with cache.open("wb") as fh:
            pickle.dump(dict(addrs=addrs, lens=lens, mns=mns, ops=ops, bad=bad), fh,
                        protocol=pickle.HIGHEST_PROTOCOL)

    # ------------------------------------------------------------------
    def analyse(self) -> None:
        addrs, lens, mns, ops = self.addrs, self.lens, self.mns, self.ops
        self.index = {a: i for i, a in enumerate(addrs)}
        self.hist = Counter(mns)
        self.call_targets: set[int] = set()
        self.branch_targets: set[int] = set()
        self.jump_tables: list[tuple[int, int]] = []  # (insn addr, table addr) guesses
        self.bad_targets = 0
        for i, a in enumerate(addrs):
            mn = mns[i]
            if mn not in ("call", "jmp") and not (mn[0] == "j" and mn != "jmp"):
                continue
            o = ops[i]
            if not o:
                if mn == "jmp" and "ptr [" in " ".join(o):
                    pass
                continue
            t = parse_imm(o[0])
            if t is None:
                continue
            if not (self.tva <= t < self.tend):
                continue
            if t not in self.index:
                self.bad_targets += 1
                continue
            (self.call_targets if mn == "call" else self.branch_targets).add(t)

    # ------------------------------------------------------------------
    def _is_function_boundary(self, addr: int) -> bool:
        """True if `addr` starts a new function rather than continuing the current one.

        MSVC emits functions back to back: the previous one ends with `ret`, followed by
        `int3` padding, then the next prologue. A `jmp` can land exactly on such a prologue,
        so without this test the reachability walk merges two functions into one — and then a
        legitimate `jmp` looks like a jump into the middle of a function.
        """
        i = self.index.get(addr)
        if i is None or i == 0:
            return False
        prev = self.mns[i - 1]
        # Only the unambiguous markers: padding, or an explicit return. A preceding `jmp` is
        # *not* a boundary — jump-table tails are followed by more of the same function.
        return prev == "int3" or prev.startswith("ret") or prev.startswith("iret")

    def boundary_addresses(self) -> set[int]:
        """Every address that follows int3 padding or a return."""
        out: set[int] = set()
        addrs, mns = self.addrs, self.mns
        for i in range(1, len(addrs)):
            prev = mns[i - 1]
            if prev == "int3" or prev.startswith("ret") or prev.startswith("iret"):
                out.add(addrs[i])
        return out

    def recover_functions(self) -> None:
        """Partition the instruction stream into functions by reachability.

        Roots: entry, call targets, code pointers, prologues. Everything reachable is
        assigned to exactly one function; unreachable but decodable instructions are grouped
        into 'orphan' functions so that no instruction is left untranslated.
        """
        addrs, lens, mns, ops = self.addrs, self.lens, self.mns, self.ops
        idx = self.index
        owner: dict[int, int] = {}  # insn addr -> function start
        funcs: list[dict] = []

        # ---- roots -----------------------------------------------------
        roots: list[int] = [self.pe.va(self.pe.entry)]
        roots.extend(sorted(self.call_targets))
        # prologue-looking instruction starts
        for i, a in enumerate(addrs):
            mn = mns[i]
            o = ops[i]
            if mn == "push" and o and o[0] == "ebp":
                if i + 1 < len(addrs) and mns[i + 1] == "mov" and ops[i + 1] == ["ebp", "esp"]:
                    roots.append(a)
                elif i + 1 < len(addrs) and mns[i + 1] == "mov" and ops[i + 1] == ["ebp", "esi"]:
                    roots.append(a)
            elif mn == "sub" and o and o[0] == "esp":
                roots.append(a)
            elif mn == "mov" and o and o[0] == "edi" and o[1] == "edi":
                roots.append(a)
        # absolute code pointers in data sections and relocation table
        for sname in (".rdata", ".data", "CONST"):
            try:
                raw = self.pe.section_bytes(sname)
            except StopIteration:
                continue
            for i in range(0, len(raw) - 4, 4):
                v = struct.unpack_from("<I", raw, i)[0]
                if v in idx:
                    roots.append(v)
        for rva in self.pe.relocs():
            o = self.pe.off(rva)
            if o is None:
                continue
            v = struct.unpack_from("<I", self.pe.d, o)[0]
            if v in idx:
                roots.append(v)

        # Code that follows int3 padding or a return is a function start even if nothing calls
        # it directly (SEH prologues, _initterm tables). Adding them as roots is what keeps the
        # "stop at a boundary" rule from turning real functions into orphans.
        boundaries = self.boundary_addresses()
        roots.extend(sorted(boundaries))
        self.boundary_count = len(boundaries)

        root_set = sorted({r for r in roots if r in idx})
        # Strong roots: entry, call targets, code pointers. A walk stops when it reaches
        # one of these, so tail-called functions do not get merged into their caller.
        strong: set[int] = set(self.call_targets)
        strong.add(self.pe.va(self.pe.entry))
        for r in root_set:
            if r in strong:
                continue
            # pointer/prologue roots stay weak: they only start a walk, they do not end one
        print(f"[census] {len(root_set):,} function roots ({len(strong):,} strong)",
              flush=True)

        # ---- reachability per root -------------------------------------
        for n, root in enumerate(root_set):
            if root in owner:
                continue
            work = [root]
            insns: list[int] = []
            blocks: list[list] = []
            while work:
                b = work.pop()
                if b in owner or b not in idx:
                    continue
                cur = b
                blk: list[int] = []
                succ: list[int] = []
                kind = "fall"
                while True:
                    if cur in owner or cur not in idx:
                        kind = "shared"
                        break
                    if cur != root and cur in strong:
                        # reached another function's entry point (tail call / fallthrough
                        # into the next function): this function ends here
                        kind = "shared"
                        break
                    if cur != root and self._is_function_boundary(cur):
                        # MSVC lays functions out as ...ret / int3-padding / new prologue.
                        # A jmp can land on such a prologue (the CRT does this for _initterm
                        # callbacks and SEH prologues), and without this check the walk
                        # absorbs the next function into the previous one.
                        kind = "shared"
                        break
                    i = idx[cur]
                    mn, o = mns[i], ops[i]
                    if mn == "int3":
                        kind = "int3"
                        break
                    owner[cur] = root
                    blk.append(cur)
                    nxt = cur + lens[i]
                    if mn.startswith("ret") or mn.startswith("iret"):
                        kind = "ret"
                        break
                    if mn == "call":
                        # the callee is its own function: never walk into it
                        cur = nxt
                        continue
                    if mn == "jmp":
                        t = parse_imm(o[0]) if o else None
                        if t is not None and t in idx and t not in strong:
                            work.append(t)
                            succ.append(t)
                            kind = "jmp"
                        elif t is not None and t in idx:
                            succ.append(t)
                            kind = "tailcall"
                        else:
                            kind = "jmp_indirect"
                        break
                    if mn[0] == "j" and mn != "jmp":
                        t = parse_imm(o[0]) if o else None
                        if t is not None and t in idx and t not in strong:
                            work.append(t)
                            succ.append(t)
                        elif t is not None and t in idx:
                            succ.append(t)
                        succ.append(nxt)
                        kind = "jcc"
                        cur = nxt
                        continue
                    if mn in ("hlt", "ud2", "ud0", "ud1"):
                        kind = "trap"
                        break
                    cur = nxt
                if blk:
                    blocks.append([blk[0], blk[-1] + lens[idx[blk[-1]]], succ, kind])
                    insns.extend(blk)
            if insns:
                funcs.append(dict(start=root, n_insns=len(insns), n_blocks=len(blocks),
                                  blocks=blocks))
            if n and n % 20000 == 0:
                print(f"[census]   {n:,}/{len(root_set):,} roots, {len(funcs):,} functions, "
                      f"{len(owner):,} insns owned", flush=True)

        # ---- orphans: decodable code not reachable from any root --------
        # int3 padding is not code: it never forms an orphan function, and it is not
        # counted as an instruction that needs lifting.
        orphans = 0
        i = 0
        while i < len(addrs):
            if addrs[i] in owner or mns[i] == "int3":
                i += 1
                continue
            start = addrs[i]
            blk = []
            while (i < len(addrs) and addrs[i] not in owner and mns[i] != "int3"
                   and (not blk or addrs[i] == blk[-1] + lens[idx[blk[-1]]])):
                owner[addrs[i]] = start
                blk.append(addrs[i])
                i += 1
            if blk:
                orphans += len(blk)
                funcs.append(dict(start=start, n_insns=len(blk), n_blocks=1, orphan=True,
                                  blocks=[[blk[0], blk[-1] + lens[idx[blk[-1]]], [], "orphan"]]))
        self.funcs = funcs
        self.owner = owner
        self.orphan_insns = orphans

    # ------------------------------------------------------------------
    def write(self) -> None:
        OUT.mkdir(parents=True, exist_ok=True)
        mn_list = sorted(self.hist)
        mn_id = {m: i for i, m in enumerate(mn_list)}
        (OUT / "mnemonics.txt").write_text("\n".join(mn_list) + "\n", encoding="utf-8")
        with (OUT / "insns.bin").open("wb") as fh:
            for i, a in enumerate(self.addrs):
                o = self.ops[i]
                vals = [0, 0, 0]
                flags = 0
                for k in range(min(3, len(o))):
                    v = parse_imm(o[k].split("[")[-1].rstrip("]")) if "[" in o[k] else parse_imm(o[k])
                    if v is None:
                        m = re.search(r"0x([0-9a-f]+)", o[k])
                        v = int(m.group(1), 16) if m else 0
                    vals[k] = v
                fh.write(INS_REC.pack(a, self.lens[i], len(o), mn_id[self.mns[i]], flags,
                                      vals[0], vals[1], vals[2]))
        with (OUT / "funcs.jsonl").open("w", encoding="utf-8") as fh:
            for f in self.funcs:
                fh.write(json.dumps({k: v for k, v in f.items() if k != "blocks"}) + "\n")
        with (OUT / "blocks.jsonl").open("w", encoding="utf-8") as fh:
            for f in self.funcs:
                for b in f["blocks"]:
                    fh.write(json.dumps(dict(func=f["start"], start=b[0], end=b[1],
                                             succ=b[2], kind=b[3])) + "\n")

        total = len(self.addrs)
        owned = len(self.owner)
        lines = []
        w = lines.append
        w("# Instruction census — SporeApp.exe\n")
        w(f"* .text: {self.tsz:,} bytes at VA 0x{self.tva:x} (image base 0x{self.pe.imagebase:x})")
        w(f"* instructions: {total:,} ({self.bad_bytes:,} undecodable bytes)")
        w(f"* instructions assigned to a function: {owned:,} ({100*owned/total:.2f}%)")
        w(f"* orphan (unreachable but decodable) instructions: {self.orphan_insns:,}")
        w(f"* functions: {len(self.funcs):,} "
          f"({sum(1 for f in self.funcs if f.get('orphan')):,} orphan groups)")
        w(f"* basic blocks: {sum(f['n_blocks'] for f in self.funcs):,}")
        w(f"* call targets: {len(self.call_targets):,}")
        w(f"* branch targets: {len(self.branch_targets):,}")
        w(f"* branch targets not on an instruction boundary: {self.bad_targets:,}")
        sizes = Counter()
        for f in self.funcs:
            n = f["n_insns"]
            sizes["1" if n == 1 else "2-4" if n <= 4 else "5-16" if n <= 16
                  else "17-64" if n <= 64 else "65-256" if n <= 256
                  else "257-1k" if n <= 1024 else ">1k"] += 1
        w("\n## Function size histogram (instructions)\n")
        w("| insns | functions |\n|---|---|")
        for k in ("1", "2-4", "5-16", "17-64", "65-256", "257-1k", ">1k"):
            if sizes.get(k):
                w(f"| {k} | {sizes[k]:,} |")
        w("\n## Largest functions\n")
        for f in sorted(self.funcs, key=lambda x: -x["n_insns"])[:15]:
            w(f"* 0x{f['start']:08x}: {f['n_insns']:,} insns, {f['n_blocks']:,} blocks")
        w("\n## Mnemonic histogram (top 80)\n")
        w("| mnemonic | count |\n|---|---|")
        for mn, c in self.hist.most_common(80):
            w(f"| {mn} | {c:,} |")
        w(f"\n## All mnemonics ({len(mn_list)})\n")
        w(", ".join(f"`{m}`" for m in mn_list))
        Path("analysis/census_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[census] wrote {OUT}/ and analysis/census_report.md")


def main() -> int:
    c = Census()
    c.sweep()
    c.analyse()
    c.recover_functions()
    c.write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
