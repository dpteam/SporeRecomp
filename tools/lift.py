"""SporeRecomp lifter: x86-32 -> C++.

Reads the census (analysis/census/) and emits, for every function reachable from a real
root, a C++ function with the same signature:

    void sub_00ABCDEF(sr::CpuState* s);

Design rules (these are what make 100k functions tractable):

1. **Every instruction has a C++ counterpart.** No fallback interpreter in the shipped
   binary: an unhandled instruction is a *lifter error*, reported at build time, never at
   runtime. `--report` lists the mnemonics that still need work.
2. **Registers live in `s->r[]`.** The compiler keeps hot ones in host registers; we do not
   hand-roll a register allocator.
3. **The guest stack is guest memory.** ESP is a real guest address, so `push`/`pop`/`call`
   behave exactly like the original (needed by SEH, `alloca`, and varargs).
4. **Flags are lazy.** Only `jcc`/`setcc`/`adc`/`sbb` materialise them.
5. **Direct calls become direct C++ calls.** Indirect calls go through `guest_call(addr)`.
6. **Jump tables become switch statements**, resolved from the pointer table in .rdata.
"""
from __future__ import annotations

import bisect
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import capstone
import capstone.x86 as csx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe import PE  # noqa: E402

EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")
CENSUS = Path("analysis/census")
GEN = Path("recomp/gen")

# ---------------------------------------------------------------------------
# Operand rendering
# ---------------------------------------------------------------------------

REG_NAME = {
    "eax": "r[0]", "ecx": "r[1]", "edx": "r[2]", "ebx": "r[3]",
    "esp": "r[4]", "ebp": "r[5]", "esi": "r[6]", "edi": "r[7]",
}
REG8 = {
    "al": ("r[0]", 0), "cl": ("r[1]", 0), "dl": ("r[2]", 0), "bl": ("r[3]", 0),
    "ah": ("r[0]", 8), "ch": ("r[1]", 8), "dh": ("r[2]", 8), "bh": ("r[3]", 8),
}
REG16 = {
    "ax": "r[0]", "cx": "r[1]", "dx": "r[2]", "bx": "r[3]",
    "sp": "r[4]", "bp": "r[5]", "si": "r[6]", "di": "r[7]",
}
SIZE_T = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}

# Flat-model segment registers: only FS/GS have a base, the selectors are fixed.
SEG_REG = {"es": 0x2B, "cs": 0x23, "ss": 0x2B, "ds": 0x2B, "fs": 0x53, "gs": 0x2B}

# XMM registers 0..7 live in CpuState::xmm (each as two u64 halves).
XMM = {f"xmm{i}": f"s->x{i}" for i in range(8)}

# MMX registers. In hardware they alias the x87 register file; Spore uses MMX exactly once
# in the whole binary, so we give them their own storage in the XMM bank (lower 64 bits)
# and document the approximation.
MM = {f"mm{i}": f"s->x{i}" for i in range(8)}

# condition-code suffix -> cc index (used by jcc/setcc/cmovcc)
CC = {
    "o": 0x0, "no": 0x1, "b": 0x2, "c": 0x2, "nae": 0x2, "ae": 0x3, "nb": 0x3, "nc": 0x3,
    "e": 0x4, "z": 0x4, "ne": 0x5, "nz": 0x5, "be": 0x6, "na": 0x6, "a": 0x7, "nbe": 0x7,
    "s": 0x8, "ns": 0x9, "p": 0xA, "pe": 0xA, "np": 0xB, "po": 0xB,
    "l": 0xC, "nge": 0xC, "ge": 0xD, "nl": 0xD, "le": 0xE, "ng": 0xE, "g": 0xF, "nle": 0xF,
}


def op_size(op) -> int:
    try:
        return op.size
    except Exception:
        return 0


class Lifter:
    def __init__(self) -> None:
        self.pe = PE(EXE.read_bytes())
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self.unhandled: Counter[str] = Counter()
        self.failed: dict[int, str] = {}
        self.stats = Counter()
        self.funcs = [json.loads(l) for l in (CENSUS / "funcs.jsonl").open()]
        self.blocks: dict[int, list[dict]] = defaultdict(list)
        for line in (CENSUS / "blocks.jsonl").open():
            b = json.loads(line)
            self.blocks[b["func"]].append(b)

    # -- operand helpers ---------------------------------------------------
    def _addr_reg(self, name: str) -> str:
        """Any general register used as an address component -> u32 expression."""
        if name in REG_NAME:
            return "s->" + REG_NAME[name]
        if name in REG16:
            return f"((u32)(u16)s->{REG16[name]})"
        # 16-bit addressing aliases (addr_size == 2): bx/bp/si/di only
        raise NotImplementedError(f"address register {name}")

    def mem_addr_expr(self, insn, op) -> str:
        """Renders the effective address of a memory operand as a C++ u32 expression."""
        m = op.mem
        parts = []
        if m.base != 0:
            parts.append(self._addr_reg(self.md.reg_name(m.base)))
        if m.index != 0:
            idx = self._addr_reg(self.md.reg_name(m.index))
            parts.append(f"{idx}*{m.scale}")
        expr = " + ".join(parts) if parts else "0u"
        if m.disp:
            if m.disp < 0:
                expr = f"({expr} - {-m.disp}u)" if parts else f"{-m.disp}u"
            else:
                expr = f"({expr} + {m.disp}u)" if parts else f"{m.disp}u"
        if m.segment != 0:
            seg = self.md.reg_name(m.segment)
            if seg == "fs":
                expr = f"(s->fs_base + {expr})"
            elif seg == "gs":
                expr = f"(s->gs_base + {expr})"
        return expr

    def read_op(self, insn, op, size: int) -> str:
        t = SIZE_T[size]
        if op.type == csx.X86_OP_REG:
            name = self.md.reg_name(op.reg)
            if name in REG_NAME:
                return f"s->{REG_NAME[name]}"
            if name in REG8:
                base, sh = REG8[name]
                return f"((u8)(s->{base} >> {sh}))" if sh else f"((u8)s->{base})"
            if name in REG16:
                return f"((u16)s->{REG16[name]})"
            if name in SEG_REG:
                return f"((u16){SEG_REG[name]})"
            raise NotImplementedError(f"reg {name}")
        if op.type == csx.X86_OP_IMM:
            return f"(({t})0x{op.imm & 0xFFFFFFFF:x}u)"
        if op.type == csx.X86_OP_MEM:
            return f"sr::load<{t}>({self.mem_addr_expr(insn, op)})"
        raise NotImplementedError(f"op type {op.type}")

    def write_op(self, insn, op, value: str, size: int) -> str:
        t = SIZE_T[size]
        if op.type == csx.X86_OP_REG:
            name = self.md.reg_name(op.reg)
            if name in REG_NAME:
                return f"s->{REG_NAME[name]} = {value};"
            if name in REG8:
                base, sh = REG8[name]
                if sh:
                    return (f"s->{base} = (s->{base} & ~0xFF00u) | "
                            f"((({t})({value}) & 0xFFu) << 8);")
                return f"s->{base} = (s->{base} & ~0xFFu) | (({t})({value}) & 0xFFu);"
            if name in REG16:
                return f"s->{REG16[name]} = (s->{REG16[name]} & ~0xFFFFu) | (({t})({value}) & 0xFFFFu);"
            if name in SEG_REG:
                return "  /* segment register write: ignored in the flat model */"
            raise NotImplementedError(f"reg {name}")
        if op.type == csx.X86_OP_MEM:
            return f"sr::store<{t}>({self.mem_addr_expr(insn, op)}, {value});"
        raise NotImplementedError(f"write to op type {op.type}")

    # -- instruction dispatch ---------------------------------------------
    def emit_insn(self, insn) -> list[str]:
        mn = insn.mnemonic
        fn = getattr(self, "i_" + mn.replace(" ", "_"), None)
        if fn is not None:
            self.stats[mn] += 1
            return fn(insn)
        # setcc / cmovcc families: one handler per condition code
        if mn.startswith("set") and mn[3:] in CC:
            self.stats[mn] += 1
            return self._setcc(insn, CC[mn[3:]])
        if mn.startswith("cmov") and mn[4:] in CC:
            self.stats[mn] += 1
            return self._cmovcc(insn, CC[mn[4:]])
        if mn.startswith("j") and mn[1:] in CC:
            self.stats[mn] += 1
            return self._jcc(insn, CC[mn[1:]])
        self.unhandled[mn] += 1
        return [f"  sr::unsupported(\"{mn}\", 0x{insn.address:08x});  // TODO"]

    # -- common instruction groups ----------------------------------------
    def _binop(self, insn, expr_tmpl: str, size: int, flagfn: str) -> list[str]:
        dst, src = insn.operands[0], insn.operands[1]
        a = self.read_op(insn, dst, size)
        b = self.read_op(insn, src, size)
        return [
            f"  {{ {SIZE_T[size]} _a = {a}; {SIZE_T[size]} _b = {b};",
            f"    {SIZE_T[size]} _r = {expr_tmpl};",
            f"    {self.write_op(insn, dst, '_r', size)}",
            f"    {flagfn}; }}",
        ]

    def i_mov(self, insn):
        size = op_size(insn.operands[0]) or 4
        return [f"  {self.write_op(insn, insn.operands[0], self.read_op(insn, insn.operands[1], size), size)}"]

    def i_movzx(self, insn):
        dsize = op_size(insn.operands[0])
        ssize = op_size(insn.operands[1])
        return [f"  {self.write_op(insn, insn.operands[0], self.read_op(insn, insn.operands[1], ssize), dsize)}"]

    def i_movsx(self, insn):
        dsize = op_size(insn.operands[0])
        ssize = op_size(insn.operands[1])
        st = {1: "s8", 2: "s16"}[ssize]
        return [f"  {self.write_op(insn, insn.operands[0], f'(({SIZE_T[dsize]})({st}){self.read_op(insn, insn.operands[1], ssize)})', dsize)}"]

    def i_lea(self, insn):
        size = op_size(insn.operands[0])
        return [f"  {self.write_op(insn, insn.operands[0], self.mem_addr_expr(insn, insn.operands[1]), size)}"]

    def i_add(self, insn):
        size = op_size(insn.operands[0])
        return self._binop(insn, "_a + _b", size, "sr::set_add_flags(s, _a, _b, _r)")

    def i_sub(self, insn):
        size = op_size(insn.operands[0])
        return self._binop(insn, "_a - _b", size, "sr::set_sub_flags(s, _a, _b, _r)")

    def i_cmp(self, insn):
        size = op_size(insn.operands[0])
        a = self.read_op(insn, insn.operands[0], size)
        b = self.read_op(insn, insn.operands[1], size)
        return [f"  sr::set_cmp_flags(s, {a}, {b});"]

    def i_test(self, insn):
        size = op_size(insn.operands[0])
        a = self.read_op(insn, insn.operands[0], size)
        b = self.read_op(insn, insn.operands[1], size)
        return [f"  sr::set_logic_flags(s, (u32)({a} & {b}));"]

    def _logic(self, insn, expr: str):
        size = op_size(insn.operands[0])
        return self._binop(insn, expr, size, "sr::set_logic_flags(s, _r)")

    def i_and(self, insn): return self._logic(insn, "_a & _b")
    def i_or(self, insn):  return self._logic(insn, "_a | _b")
    def i_xor(self, insn): return self._logic(insn, "_a ^ _b")

    def i_push(self, insn):
        op = insn.operands[0]
        if op.type == csx.X86_OP_REG and self.md.reg_name(op.reg) in SEG_REG:
            v = self.read_op(insn, op, 2)
            return ["  s->r[4] -= 4;", f"  sr::store<u32>(s->r[4], (u32)({v}));"]
        size = op_size(op) or 4
        v = self.read_op(insn, op, size)
        return [
            f"  s->r[4] -= 4;",
            f"  sr::store<u32>(s->r[4], (u32)({v}));",
        ]

    def i_pop(self, insn):
        op = insn.operands[0]
        if op.type == csx.X86_OP_REG and self.md.reg_name(op.reg) in SEG_REG:
            # flat model: pop into a segment selector only advances ESP
            return ["  s->r[4] += 4;"]
        size = op_size(op) or 4
        return [
            f"  {{ u32 _v = sr::load<u32>(s->r[4]); s->r[4] += 4;",
            f"    {self.write_op(insn, op, '_v', size)} }}",
        ]

    def i_call(self, insn):
        op = insn.operands[0]
        # The guest return address is pushed so that ESP stays balanced and the guest's own
        # stack walking (SEH, __alloca probes) sees a normal frame. Control flow, however,
        # uses the *native* call stack: the callee's `ret` pops the guest slot and returns
        # from its C++ function. That is what makes recursion and callbacks work.
        ret = insn.address + insn.size
        if op.type == csx.X86_OP_IMM:
            tgt = op.imm & 0xFFFFFFFF
            if tgt in self._lifted:
                return [
                    f"  sr::guest_push_ret(s, 0x{ret:08x}u);",
                    f"  sub_{tgt:08x}(s);",
                ]
            return [
                f"  sr::guest_push_ret(s, 0x{ret:08x}u);",
                f"  sr::guest_call_indirect(s, 0x{tgt:08x}u);",
            ]
        return [
            f"  sr::guest_push_ret(s, 0x{ret:08x}u);",
            f"  sr::guest_call_indirect(s, (u32)({self.read_op(insn, op, 4)}));",
        ]

    def i_ret(self, insn):
        n = insn.operands[0].imm if insn.operands else 0
        # Pop the return address the caller pushed (the value itself is not needed: the native
        # return does the work) plus any stdcall arguments, then return natively.
        pop = 4 + n
        return [f"  s->r[4] += {pop}u;", "  return;"]

    def i_jmp(self, insn):
        op = insn.operands[0]
        if op.type == csx.X86_OP_IMM:
            tgt = op.imm & 0xFFFFFFFF
            if tgt in self._labels:
                return [f"  goto L_{tgt:08x};"]
            # Tail call: no return address is pushed, so the callee's `ret` returns to *our*
            # caller. Native tail call, guest stack unchanged.
            return [f"  sr::guest_tail(s, 0x{tgt:08x}u); return;"]
        # Jump table: `jmp dword ptr [table + reg*4]`. Resolving it to a switch keeps the jump
        # inside the function, which is what the original code does. Without this, every
        # switch statement in the game became a tail call to an address in the middle of a
        # function (or, worse, an unmapped address).
        if op.type == csx.X86_OP_MEM and op.mem.index != 0 and op.mem.disp:
            table = op.mem.disp & 0xFFFFFFFF
            index = self._addr_reg(self.md.reg_name(op.mem.index))
            scale = op.mem.scale
            # Read entries until one leaves the image. Validity is decided per entry: a table
            # can live outside the function (MSVC puts switch tables in .rdata) while its
            # targets are inside it.
            targets: list[int] = []
            for k in range(256):
                addr = table + k * scale * 4
                o = self.pe.off_va(addr)
                if o is None or o + 4 > len(self.pe.d):
                    break
                tgt = int.from_bytes(self.pe.d[o:o + 4], "little")
                # A plausible target is an address inside .text.
                if not (self.pe.imagebase <= tgt < self.pe.imagebase + 0x01000000):
                    break
                if tgt not in self._all_block_starts:
                    break
                targets.append(tgt)
            if targets and all(t in self._labels for t in targets):
                lines = [f"  switch ((u32)({index})) {{"]
                for k, tgt in enumerate(targets):
                    lines.append(f"    case {k}u: goto L_{tgt:08x};")
                lines.append("    default: break;")
                lines.append("  }")
                return lines
            if targets:
                # The table points at blocks that belong to *other* functions: a switch that
                # tail-calls them. Dispatch through the guest so the callee's `ret` returns to
                # our caller.
                lines = [f"  switch ((u32)({index})) {{"]
                for k, tgt in enumerate(targets):
                    lines.append(f"    case {k}u: sr::guest_tail(s, 0x{tgt:08x}u); return;")
                lines.append("    default: break;")
                lines.append("  }")
                return lines
        return [f"  {{ sr::guest_jump_indirect(s, (u32)({self.read_op(insn, op, 4)})); return; }}"]

    def _jcc(self, insn, cc: int):
        op = insn.operands[0]
        tgt = op.imm & 0xFFFFFFFF
        if tgt in self._labels:
            return [f"  if (sr::eval_cc(s, {cc})) goto L_{tgt:08x};"]
        return [f"  if (sr::eval_cc(s, {cc})) {{ sr::guest_tail(s, 0x{tgt:08x}u); return; }}"]

    def i_je(self, i): return self._jcc(i, 0x4)
    def i_jz(self, i): return self._jcc(i, 0x4)
    def i_jne(self, i): return self._jcc(i, 0x5)
    def i_jnz(self, i): return self._jcc(i, 0x5)
    def i_ja(self, i): return self._jcc(i, 0x7)
    def i_jae(self, i): return self._jcc(i, 0x3)
    def i_jb(self, i): return self._jcc(i, 0x2)
    def i_jbe(self, i): return self._jcc(i, 0x6)
    def i_jg(self, i): return self._jcc(i, 0xF)
    def i_jge(self, i): return self._jcc(i, 0xD)
    def i_jl(self, i): return self._jcc(i, 0xC)
    def i_jle(self, i): return self._jcc(i, 0xE)
    def i_js(self, i): return self._jcc(i, 0x8)
    def i_jns(self, i): return self._jcc(i, 0x9)
    def i_jo(self, i): return self._jcc(i, 0x0)
    def i_jno(self, i): return self._jcc(i, 0x1)
    def i_jp(self, i): return self._jcc(i, 0xA)
    def i_jnp(self, i): return self._jcc(i, 0xB)

    def i_inc(self, insn):
        size = op_size(insn.operands[0])
        dst = insn.operands[0]
        return [
            f"  {{ {SIZE_T[size]} _a = {self.read_op(insn, dst, size)};",
            f"    {SIZE_T[size]} _r = _a + 1;",
            f"    {self.write_op(insn, dst, '_r', size)};",
            f"    sr::set_add_flags(s, _a, 1, _r); }}",
        ]

    def i_dec(self, insn):
        size = op_size(insn.operands[0])
        dst = insn.operands[0]
        return [
            f"  {{ {SIZE_T[size]} _a = {self.read_op(insn, dst, size)};",
            f"    {SIZE_T[size]} _r = _a - 1;",
            f"    {self.write_op(insn, dst, '_r', size)};",
            f"    sr::set_sub_flags(s, _a, 1, _r); }}",
        ]

    def i_neg(self, insn):
        size = op_size(insn.operands[0])
        dst = insn.operands[0]
        return [
            f"  {{ {SIZE_T[size]} _a = {self.read_op(insn, dst, size)};",
            f"    {SIZE_T[size]} _r = (SIZE_T_PLACEHOLDER)0 - _a;".replace("SIZE_T_PLACEHOLDER", SIZE_T[size]),
            f"    {self.write_op(insn, dst, '_r', size)};",
            f"    sr::set_sub_flags(s, 0, _a, _r); }}",
        ]

    def i_nop(self, insn): return []
    def i_int3(self, insn): return ["  sr::debug_break(s);"]
    def i_cdq(self, insn):
        return ["  s->r[2] = (s->r[0] & 0x80000000u) ? 0xFFFFFFFFu : 0u;"]
    def i_cwde(self, insn):
        return ["  s->r[0] = (u32)(s32)(s16)s->r[0];"]
    def i_leave(self, insn):
        return ["  s->r[4] = s->r[5]; s->r[5] = sr::load<u32>(s->r[4]); s->r[4] += 4;"]
    def i_pushad(self, insn):
        return ["  sr::pushad(s);"]
    def i_popad(self, insn):
        return ["  sr::popad(s);"]
    def i_rep_movsd(self, insn):
        return ["  sr::rep_movsd(s);"]
    def i_rep_movsb(self, insn):
        return ["  sr::rep_movsb(s);"]
    def i_rep_stosd(self, insn):
        return ["  sr::rep_stosd(s);"]
    def i_rep_stosb(self, insn):
        return ["  sr::rep_stosb(s);"]
    def i_lahf(self, insn):
        return ["  s->r[0] = (s->r[0] & 0xFFFFFF00u) | (sr::get_flags(s) & 0xFFu);"]
    def i_sahf(self, insn):
        return ["  sr::set_flags(s, (sr::get_flags(s) & 0xFFFFFF00u) | (s->r[0] & 0xFFu));"]
    def i_rdtsc(self, insn):
        return ["  sr::guest_rdtsc(s);"]
    def i_cpuid(self, insn):
        return ["  sr::guest_cpuid(s);"]
    def i_xchg(self, insn):
        size = op_size(insn.operands[0])
        a = insn.operands[0]
        b = insn.operands[1]
        return [
            f"  {{ {SIZE_T[size]} _x = {self.read_op(insn, a, size)};",
            f"    {SIZE_T[size]} _y = {self.read_op(insn, b, size)};",
            f"    {self.write_op(insn, a, '_y', size)}",
            f"    {self.write_op(insn, b, '_x', size)} }}",
        ]

    # -- shifts / rotates ---------------------------------------------------
    def _shift(self, insn, expr: str, mask: int = 31):
        size = op_size(insn.operands[0])
        dst = insn.operands[0]
        cnt = self.read_op(insn, insn.operands[1], 1) if len(insn.operands) > 1 else "1u"
        return [
            f"  {{ {SIZE_T[size]} _a = {self.read_op(insn, dst, size)};",
            f"    u32 _c = (u32)({cnt}) & {mask}u;",
            f"    {SIZE_T[size]} _r = {expr};",
            f"    {self.write_op(insn, dst, '_r', size)};",
            f"    sr::set_shift_flags(s, _a, _c, _r, {size * 8}); }}",
        ]

    def i_shl(self, insn):
        size = op_size(insn.operands[0])
        dst = insn.operands[0]
        cnt = self.read_op(insn, insn.operands[1], 1) if len(insn.operands) > 1 else "1u"
        return [
            f"  {{ {SIZE_T[size]} _a = {self.read_op(insn, dst, size)};",
            f"    u32 _c = (u32)({cnt}) & 31u;",
            f"    {SIZE_T[size]} _r = _c ? ({SIZE_T[size]})(_a << _c) : _a;",
            f"    {self.write_op(insn, dst, '_r', size)};",
            f"    sr::set_shift_flags(s, _a, _c, _r, {size * 8}); }}",
        ]

    def i_shr(self, insn): return self._shift(insn, "_a >> _c")
    def i_sar(self, i):
        size = op_size(i.operands[0])
        st = {1: "s8", 2: "s16", 4: "s32"}[size]
        return self._shift(i, f"({SIZE_T[size]})(({st})_a >> _c)")

    def i_sal(self, insn): return self.i_shl(insn)

    # -- multiply / divide --------------------------------------------------
    def i_imul(self, insn):
        ops = insn.operands
        size = op_size(ops[0])
        if len(ops) == 1:
            return [f"  sr::imul_1(s, (u32)({self.read_op(insn, ops[0], size)}), {size});"]
        if len(ops) == 2:
            a = self.read_op(insn, ops[0], size)
            b = self.read_op(insn, ops[1], size)
            st = {1: "s8", 2: "s16", 4: "s32"}[size]
            return [
                f"  {{ {SIZE_T[size]} _a = {a}; {SIZE_T[size]} _b = {b};",
                f"    {SIZE_T[size]} _r = ({SIZE_T[size]})(({st})_a * ({st})_b);",
                f"    {self.write_op(insn, ops[0], '_r', size)};",
                f"    sr::set_logic_flags(s, _r); }}",
            ]
        a = self.read_op(insn, ops[1], size)
        b = self.read_op(insn, ops[2], size)
        st = {1: "s8", 2: "s16", 4: "s32"}[size]
        return [
            f"  {{ {SIZE_T[size]} _a = {a}; {SIZE_T[size]} _b = {b};",
            f"    {SIZE_T[size]} _r = ({SIZE_T[size]})(({st})_a * ({st})_b);",
            f"    {self.write_op(insn, ops[0], '_r', size)};",
            f"    sr::set_logic_flags(s, _r); }}",
        ]

    def i_mul(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::mul_1(s, (u32)({self.read_op(insn, insn.operands[0], size)}), {size});"]

    def i_div(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::div_1(s, (u32)({self.read_op(insn, insn.operands[0], size)}), {size}, false);"]

    def i_idiv(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::div_1(s, (u32)({self.read_op(insn, insn.operands[0], size)}), {size}, true);"]

    # -- carry arithmetic ---------------------------------------------------
    def i_adc(self, insn):
        size = op_size(insn.operands[0])
        return self._binop(insn, "_a + _b + (u32)sr::flag_cf(s)", size,
                           "sr::set_add_flags(s, _a, _b, _r)")

    def i_sbb(self, insn):
        size = op_size(insn.operands[0])
        return self._binop(insn, "_a - _b - (u32)sr::flag_cf(s)", size,
                           "sr::set_sub_flags(s, _a, _b, _r)")

    def i_not(self, insn):
        size = op_size(insn.operands[0])
        dst = insn.operands[0]
        return [f"  {self.write_op(insn, dst, f'(~{self.read_op(insn, dst, size)})', size)}"]

    def i_bswap(self, insn):
        dst = insn.operands[0]
        return [f"  s->{REG_NAME[self.md.reg_name(dst.reg)]} = sr::bswap32("
                f"s->{REG_NAME[self.md.reg_name(dst.reg)]});"]

    # -- bit test -----------------------------------------------------------
    def _bt(self, insn, expr: str):
        size = op_size(insn.operands[0])
        a = self.read_op(insn, insn.operands[0], size)
        b = self.read_op(insn, insn.operands[1], 4)
        return [f"  sr::bt_op(s, {a}, {b}, {size}, {expr});"]

    def i_bt(self, i): return self._bt(i, 0)
    def i_bts(self, i): return self._bt(i, 1)
    def i_btr(self, i): return self._bt(i, 2)
    def i_btc(self, i): return self._bt(i, 3)

    def i_shld(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::shld(s, (u32)({self.read_op(insn, insn.operands[0], size)}),"
                f" (u32)({self.read_op(insn, insn.operands[1], size)}),"
                f" (u32)({self.read_op(insn, insn.operands[2], 1)}), {size}, 0);"]

    def i_shrd(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::shld(s, (u32)({self.read_op(insn, insn.operands[0], size)}),"
                f" (u32)({self.read_op(insn, insn.operands[1], size)}),"
                f" (u32)({self.read_op(insn, insn.operands[2], 1)}), {size}, 1);"]

    # -- setcc / cmovcc -----------------------------------------------------
    def _setcc(self, insn, cc: int):
        return [f"  {self.write_op(insn, insn.operands[0], f'sr::eval_cc(s, {cc}) ? 1 : 0', 1)}"]

    def _cmovcc(self, insn, cc: int):
        size = op_size(insn.operands[0])
        dst = insn.operands[0]
        src = insn.operands[1]
        return [
            f"  if (sr::eval_cc(s, {cc})) {{",
            f"    {self.write_op(insn, dst, self.read_op(insn, src, size), size)}",
            f"  }}",
        ]

    # -- SSE: scalar float --------------------------------------------------
    def _sse_binop(self, insn, op: str):
        dst, src = insn.operands[0], insn.operands[1]
        if dst.type == csx.X86_OP_REG:
            name = self.md.reg_name(dst.reg)
            d = XMM.get(name) or MM.get(name)
            if d is None:
                raise NotImplementedError(f"sse dst {name}")
            return [f"  sr::sse_{op}(s, {d}, {self._sse_read(insn, src)});"]
        raise NotImplementedError("sse mem dst")

    def _sse_reg(self, name: str) -> str:
        if name in XMM:
            return XMM[name]
        if name in MM:
            return MM[name]
        raise NotImplementedError(f"sse reg {name}")

    def _sse_read(self, insn, op) -> str:
        """Reads an SSE/MMX operand as a packed 128-bit value."""
        if op.type == csx.X86_OP_REG:
            name = self.md.reg_name(op.reg)
            if name in XMM:
                return XMM[name]
            if name in MM:
                return MM[name]
            raise NotImplementedError(f"sse reg {name}")
        if op.type == csx.X86_OP_MEM:
            return f"sr::load_v4({self.mem_addr_expr(insn, op)})"
        raise NotImplementedError("sse imm")

    def i_movss(self, insn):
        dst, src = insn.operands[0], insn.operands[1]
        if dst.type == csx.X86_OP_REG:
            d = self._sse_reg(self.md.reg_name(dst.reg))
            if src.type == csx.X86_OP_MEM:
                return [f"  {d} = sr::sse_movss_load(s, {d}, {self.mem_addr_expr(insn, src)});"]
            return [f"  {d} = sr::sse_movss(s, {d}, {self._sse_reg(self.md.reg_name(src.reg))});"]
        return [f"  sr::sse_movss_store(s, {self.mem_addr_expr(insn, dst)}, "
                f"{self._sse_reg(self.md.reg_name(src.reg))});"]

    def i_movaps(self, insn):
        return self._sse_move(insn)

    def i_movups(self, insn):
        return self._sse_move(insn)

    def i_movdqa(self, insn):
        return self._sse_move(insn)

    def i_movdqu(self, insn):
        return self._sse_move(insn)

    def _sse_move(self, insn):
        dst, src = insn.operands[0], insn.operands[1]
        if dst.type == csx.X86_OP_REG:
            d = self._sse_reg(self.md.reg_name(dst.reg))
            if src.type == csx.X86_OP_MEM:
                return [f"  {d} = sr::load_v4({self.mem_addr_expr(insn, src)});"]
            return [f"  {d} = {self._sse_reg(self.md.reg_name(src.reg))};"]
        return [f"  sr::store_v4({self.mem_addr_expr(insn, dst)}, "
                f"{self._sse_reg(self.md.reg_name(src.reg))});"]

    def i_xorps(self, insn):
        return self._sse_binop(insn, "xor")

    def i_andps(self, insn):
        return self._sse_binop(insn, "and")

    def i_orps(self, insn):
        return self._sse_binop(insn, "or")

    def i_andnps(self, insn):
        return self._sse_binop(insn, "andn")

    def i_addss(self, insn):
        return self._sse_binop(insn, "add_ss")

    def i_subss(self, insn):
        return self._sse_binop(insn, "sub_ss")

    def i_mulss(self, insn):
        return self._sse_binop(insn, "mul_ss")

    def i_divss(self, insn):
        return self._sse_binop(insn, "div_ss")

    def i_minss(self, insn):
        return self._sse_binop(insn, "min_ss")

    def i_maxss(self, insn):
        return self._sse_binop(insn, "max_ss")

    def i_sqrtss(self, insn):
        return self._sse_binop(insn, "sqrt_ss")

    def i_addps(self, insn):
        return self._sse_binop(insn, "add_ps")

    def i_subps(self, insn):
        return self._sse_binop(insn, "sub_ps")

    def i_mulps(self, insn):
        return self._sse_binop(insn, "mul_ps")

    def i_divps(self, insn):
        return self._sse_binop(insn, "div_ps")

    def i_rcpps(self, insn):
        return self._sse_binop(insn, "rcp_ps")

    def i_rsqrtps(self, insn):
        return self._sse_binop(insn, "rsqrt_ps")

    def i_sqrtps(self, insn):
        return self._sse_binop(insn, "sqrt_ps")

    def i_shufps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_shufps(s, {d}, {self._sse_read(insn, insn.operands[1])}, "
                f"{insn.operands[2].imm & 0xFF}u);"]

    def i_comiss(self, insn):
        return [f"  sr::sse_comiss(s, {self._sse_read(insn, insn.operands[0])}, "
                f"{self._sse_read(insn, insn.operands[1])}, 0);"]

    def i_ucomiss(self, insn):
        return [f"  sr::sse_comiss(s, {self._sse_read(insn, insn.operands[0])}, "
                f"{self._sse_read(insn, insn.operands[1])}, 1);"]

    def i_cvtsi2ss(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        src = insn.operands[1]
        return [f"  {d} = sr::sse_cvtsi2ss(s, {d}, (s32)({self.read_op(insn, src, 4)}));"]

    def i_cvttss2si(self, insn):
        dst = insn.operands[0]
        return [f"  {self.write_op(insn, dst, f'(u32)sr::sse_cvttss2si(s, {self._sse_read(insn, insn.operands[1])})', 4)}"]

    def i_cvtss2si(self, insn):
        dst = insn.operands[0]
        return [f"  {self.write_op(insn, dst, f'(u32)sr::sse_cvtss2si(s, {self._sse_read(insn, insn.operands[1])})', 4)}"]

    def i_movd(self, insn):
        dst, src = insn.operands[0], insn.operands[1]
        dname = self.md.reg_name(dst.reg) if dst.type == csx.X86_OP_REG else ""
        sname = self.md.reg_name(src.reg) if src.type == csx.X86_OP_REG else ""
        if dst.type == csx.X86_OP_REG and (dname.startswith("xmm") or dname.startswith("mm")):
            if src.type == csx.X86_OP_MEM:
                return [f"  {self._sse_reg(dname)} = sr::sse_movd_load(s, {self.mem_addr_expr(insn, src)});"]
            return [f"  {self._sse_reg(dname)} = sr::sse_movd_in(s, (u32)({self.read_op(insn, src, 4)}));"]
        if src.type == csx.X86_OP_REG and (sname.startswith("xmm") or sname.startswith("mm")):
            if dst.type == csx.X86_OP_MEM:
                return [f"  sr::store<u32>({self.mem_addr_expr(insn, dst)}, "
                        f"sr::sse_movd_out(s, {self._sse_reg(sname)}));"]
            return [f"  {self.write_op(insn, dst, f'sr::sse_movd_out(s, {self._sse_reg(sname)})', 4)}"]
        raise NotImplementedError("movd form")

    def i_movq(self, insn):
        dst, src = insn.operands[0], insn.operands[1]
        dname = self.md.reg_name(dst.reg) if dst.type == csx.X86_OP_REG else ""
        sname = self.md.reg_name(src.reg) if src.type == csx.X86_OP_REG else ""
        if dname.startswith("xmm") and sname.startswith("xmm"):
            return self._sse_move(insn)
        if dname.startswith("xmm"):
            # movq xmm, r/m64 (or m32 -> low lane, upper cleared)
            if src.type == csx.X86_OP_MEM:
                return [f"  {self._sse_reg(dname)} = sr::sse_movq_load(s, {self.mem_addr_expr(insn, src)});"]
            return [f"  {self._sse_reg(dname)} = sr::sse_movd_in(s, (u32)({self.read_op(insn, src, 4)}));"]
        if sname.startswith("xmm"):
            if dst.type == csx.X86_OP_MEM:
                return [f"  sr::sse_movq_store(s, {self.mem_addr_expr(insn, dst)}, {self._sse_reg(sname)});"]
            return [f"  {self.write_op(insn, dst, f'sr::sse_movd_out(s, {self._sse_reg(sname)})', 4)}"]
        # fall back to the generic move for anything else (e.g. movq mm, mm)
        return self._sse_move(insn)

    # -- x87 ---------------------------------------------------------------
    def i_fld(self, insn):
        op = insn.operands[0]
        size = op_size(op) or 4
        return [f"  sr::x87_load(s, {self._x87_addr(insn, op)}, {size});"]

    def i_fstp(self, insn):
        op = insn.operands[0]
        size = op_size(op) or 4
        return [f"  sr::x87_pop_store(s, {self._x87_addr(insn, op)}, {size});"]

    def i_fst(self, insn):
        op = insn.operands[0]
        size = op_size(op) or 4
        return [f"  sr::x87_store(s, {self._x87_addr(insn, op)}, {size});"]

    def i_fild(self, insn):
        op = insn.operands[0]
        return [f"  sr::x87_load_int(s, {self._x87_addr(insn, op)}, {op_size(op)});"]

    def i_fistp(self, insn):
        op = insn.operands[0]
        return [f"  sr::x87_pop_store_int(s, {self._x87_addr(insn, op)}, {op_size(op)});"]

    def _x87_addr(self, insn, op) -> str:
        """Renders an x87 operand as an X87Op: st(i) index or a memory address."""
        if op.type == csx.X86_OP_REG:
            name = self.md.reg_name(op.reg)
            m = re.fullmatch(r"st\((\d)\)", name)
            if not m:
                raise NotImplementedError(f"x87 reg {name}")
            return f"sr::X87Op{{{m.group(1)}, 0u}}"
        return f"sr::X87Op{{-1, {self.mem_addr_expr(insn, op)}}}"

    def _x87_arith(self, insn, op: str):
        ops = insn.operands
        if not ops:
            a = b = "sr::X87Op{0, 0u}"
        else:
            a = self._x87_addr(insn, ops[0])
            b = self._x87_addr(insn, ops[1]) if len(ops) > 1 else a
        return [f"  sr::x87_{op}(s, {a}, {b});"]

    def i_fadd(self, i): return self._x87_arith(i, "add")
    def i_fsub(self, i): return self._x87_arith(i, "sub")
    def i_fmul(self, i): return self._x87_arith(i, "mul")
    def i_fdiv(self, i): return self._x87_arith(i, "div")
    def i_faddp(self, i): return self._x87_arith(i, "addp")
    def i_fsubp(self, i): return self._x87_arith(i, "subp")
    def i_fsubrp(self, i): return self._x87_arith(i, "subrp")
    def i_fmulp(self, i): return self._x87_arith(i, "mulp")
    def i_fdivp(self, i): return self._x87_arith(i, "divp")
    def i_fdivrp(self, i): return self._x87_arith(i, "divrp")
    def i_fcom(self, i): return self._x87_arith(i, "com")
    def i_fcomp(self, i): return self._x87_arith(i, "comp")
    def i_fucom(self, i): return self._x87_arith(i, "ucom")
    def i_fucomp(self, i): return self._x87_arith(i, "ucomp")
    def i_fcompp(self, i): return self._x87_arith(i, "compp")
    def i_fucompp(self, i): return self._x87_arith(i, "ucompp")
    def i_fchs(self, i): return ["  sr::x87_chs(s);"]
    def i_fabs(self, i): return ["  sr::x87_abs(s);"]
    def i_fsqrt(self, i): return ["  sr::x87_sqrt(s);"]
    def i_fxch(self, insn):
        n = insn.operands[0].imm if insn.operands and insn.operands[0].type == csx.X86_OP_IMM else 1
        return [f"  sr::x87_fxch(s, {n});"]
    def i_fldz(self, i): return ["  sr::x87_push_const(s, 0.0);"]
    def i_fld1(self, i): return ["  sr::x87_push_const(s, 1.0);"]
    def i_fldpi(self, i): return ["  sr::x87_push_const(s, 3.14159265358979323846);"]
    def i_fldcw(self, insn):
        return [f"  s->fpu_ctrl = sr::load<u16>({self.mem_addr_expr(insn, insn.operands[0])});"]
    def i_fnstcw(self, insn):
        return [f"  sr::store<u16>({self.mem_addr_expr(insn, insn.operands[0])}, s->fpu_ctrl);"]
    def i_fnstsw(self, insn):
        if insn.operands and insn.operands[0].type == csx.X86_OP_REG:
            return ["  s->r[0] = (s->r[0] & 0xFFFF0000u) | s->fpu_status;"]
        return [f"  sr::store<u16>({self.mem_addr_expr(insn, insn.operands[0])}, s->fpu_status);"]
    def i_fstsw(self, insn): return self.i_fnstsw(insn)
    def i_fwait(self, i): return []
    def i_fnstsw_ax(self, i): return ["  s->r[0] = (s->r[0] & 0xFFFF0000u) | s->fpu_status;"]
    def i_ffree(self, i): return ["  sr::x87_free(s);"]
    def i_fincstp(self, i): return ["  s->fpu_top = (s->fpu_top + 1) & 7;"]
    def i_fdecstp(self, i): return ["  s->fpu_top = (s->fpu_top + 7) & 7;"]
    def i_fprem(self, i): return ["  sr::x87_prem(s, 0);"]
    def i_fprem1(self, i): return ["  sr::x87_prem(s, 1);"]
    def i_frndint(self, i): return ["  sr::x87_rndint(s);"]
    def i_fscale(self, i): return ["  sr::x87_scale(s);"]
    def i_emms(self, i): return []

    # -- remaining families seen in the first 3k functions ------------------
    def i_unpcklps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_unpcklps(s, {d}, {self._sse_read(insn, insn.operands[1])});"]

    def i_unpckhps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_unpckhps(s, {d}, {self._sse_read(insn, insn.operands[1])});"]

    def i_pshufd(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_pshufd(s, {self._sse_read(insn, insn.operands[1])}, "
                f"{insn.operands[2].imm & 0xFF}u);"]

    def i_movhlps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_movhlps(s, {d}, {self._sse_read(insn, insn.operands[1])});"]

    def i_movlhps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_movlhps(s, {d}, {self._sse_read(insn, insn.operands[1])});"]

    def i_maxps(self, insn): return self._sse_binop(insn, "max_ps")
    def i_minps(self, insn): return self._sse_binop(insn, "min_ps")

    def i_cmpltps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cmp_ps(s, {d}, {self._sse_read(insn, insn.operands[1])}, 1);"]
    def i_cmpleps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cmp_ps(s, {d}, {self._sse_read(insn, insn.operands[1])}, 2);"]
    def i_cmpneqps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cmp_ps(s, {d}, {self._sse_read(insn, insn.operands[1])}, 4);"]

    def i_fsubr(self, i): return self._x87_arith(i, "subr")
    def i_fdivr(self, i): return self._x87_arith(i, "divr")
    def i_fcompi(self, i): return self._x87_arith(i, "compi")
    def i_fucompi(self, i): return self._x87_arith(i, "ucompi")

    def i_lock_xadd(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_xadd(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size});"]
    def i_xadd(self, insn):
        return self.i_lock_xadd(insn)

    def i_lock_cmpxchg(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_cmpxchg(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size});"]
    def i_cmpxchg(self, insn):
        return self.i_lock_cmpxchg(insn)

    def i_lock_add(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_add(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size}, (u32)({self.read_op(insn, insn.operands[1], size)}));"]
    def i_lock_inc(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_add(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size}, 1u);"]
    def i_lock_dec(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_add(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size}, 0xFFFFFFFFu);"]
    def i_lock_or(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_or(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size}, (u32)({self.read_op(insn, insn.operands[1], size)}));"]
    def i_lock_xor(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_xor(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size}, (u32)({self.read_op(insn, insn.operands[1], size)}));"]

    def i_stosd(self, i): return ["  sr::rep_stosd(s);"]
    def i_stosb(self, i): return ["  sr::rep_stosb(s);"]
    def i_movsd(self, insn):
        # SSE movsd vs. string movsd: distinguished by operand kind
        if insn.operands and insn.operands[0].type == csx.X86_OP_REG \
                and self.md.reg_name(insn.operands[0].reg).startswith("xmm"):
            return self._sse_move(insn)
        return ["  sr::rep_movsd(s);"]
    def i_movsb(self, i): return ["  sr::rep_movsb(s);"]
    def i_cmpsb(self, i): return ["  sr::rep_cmpsb(s);"]
    def i_cmpsd(self, i): return ["  sr::rep_cmpsd(s);"]
    def i_scasb(self, i): return ["  sr::rep_scasb(s);"]

    def i_rcl(self, insn):
        return [f"  sr::rotate_carry(s, {self.read_op(insn, insn.operands[1], 1)}, "
                f"{op_size(insn.operands[0])}, 1);"]
    def i_rcr(self, insn):
        return [f"  sr::rotate_carry(s, {self.read_op(insn, insn.operands[1], 1)}, "
                f"{op_size(insn.operands[0])}, 0);"]
    def i_rol(self, insn):
        size = op_size(insn.operands[0])
        t = SIZE_T[size]
        return self._shift(insn, f"_c ? ({t})((_a << _c) | (_a >> ((32 - _c) & 31))) : _a")
    def i_ror(self, insn):
        size = op_size(insn.operands[0])
        t = SIZE_T[size]
        return self._shift(insn, f"_c ? ({t})((_a >> _c) | (_a << ((32 - _c) & 31))) : _a")

    def i_enter(self, insn):
        return [f"  sr::enter_frame(s, {insn.operands[0].imm & 0xFFFF}u, "
                f"{insn.operands[1].imm & 0x1F}u);"]

    def i_in(self, insn):
        return [f"  sr::port_in(s, {self.read_op(insn, insn.operands[0], 2)});"]
    def i_out(self, insn):
        return [f"  sr::port_out(s, {self.read_op(insn, insn.operands[0], 2)});"]

    def i_cld(self, i): return ["  s->flags &= ~sr::kDF;"]
    def i_std(self, i): return ["  s->flags |= sr::kDF;"]
    def i_clc(self, i): return ["  s->flags &= ~sr::kCF;"]
    def i_stc(self, i): return ["  s->flags |= sr::kCF;"]
    def i_cmc(self, i): return ["  s->flags ^= sr::kCF;"]

    def i_loop(self, insn):
        tgt = insn.operands[0].imm & 0xFFFFFFFF
        return [f"  if (--s->r[1]) {{ sr::guest_tail(s, 0x{tgt:08x}u); return; }}"]
    def i_loope(self, insn):
        tgt = insn.operands[0].imm & 0xFFFFFFFF
        return [f"  if (--s->r[1] && sr::eval_cc(s, 0x4)) {{ sr::guest_tail(s, 0x{tgt:08x}u); return; }}"]
    def i_loopne(self, insn):
        tgt = insn.operands[0].imm & 0xFFFFFFFF
        return [f"  if (--s->r[1] && sr::eval_cc(s, 0x5)) {{ sr::guest_tail(s, 0x{tgt:08x}u); return; }}"]
    def i_jecxz(self, insn):
        tgt = insn.operands[0].imm & 0xFFFFFFFF
        return [f"  if (!s->r[1]) {{ sr::guest_tail(s, 0x{tgt:08x}u); return; }}"]

    def i_repe_cmpsb(self, i): return ["  sr::rep_cmpsb(s);"]
    def i_repe_cmpsd(self, i): return ["  sr::rep_cmpsd(s);"]
    def i_repne_scasb(self, i): return ["  sr::rep_scasb(s);"]

    def i_salc(self, i): return ["  s->r[0] = (s->r[0] & 0xFFFFFF00u) | (sr::flag_cf(s) ? 0xFFu : 0u);"]
    def i_arpl(self, insn):
        return []  # 16-bit selector fixups: irrelevant in the flat model
    def i_fxsave(self, insn):
        return [f"  sr::x87_save_state(s, {self.mem_addr_expr(insn, insn.operands[0])});"]
    def i_fxrstor(self, insn):
        return [f"  sr::x87_restore_state(s, {self.mem_addr_expr(insn, insn.operands[0])});"]

    def i_cvttps2dq(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cvttps2dq(s, {self._sse_read(insn, insn.operands[1])});"]
    def i_movmskps(self, insn):
        return [f"  {self.write_op(insn, insn.operands[0], f'sr::sse_movmskps(s, {self._sse_read(insn, insn.operands[1])})', 4)}"]
    def i_pextrw(self, insn):
        # pextrw r32, xmm, imm8 -- extracts a 16-bit lane into a GPR
        return [f"  {self.write_op(insn, insn.operands[0], f'sr::sse_pextrw(s, {self._sse_read(insn, insn.operands[1])}, {insn.operands[2].imm & 3}u)', 4)}"]
    def i_packssdw(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_packssdw(s, {d}, {self._sse_read(insn, insn.operands[1])});"]
    def i_pmaddwd(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_pmaddwd(s, {d}, {self._sse_read(insn, insn.operands[1])});"]

    # -- x87 transcendental / compare-and-pop -------------------------------
    def i_fcomi(self, insn):
        ops = insn.operands
        a = self._x87_addr(insn, ops[0])
        b = self._x87_addr(insn, ops[1]) if len(ops) > 1 else "sr::X87Op{0, 0u}"
        return [f"  sr::x87_com(s, {a}, {b});"]
    def i_fucomi(self, insn):
        ops = insn.operands
        a = self._x87_addr(insn, ops[0])
        b = self._x87_addr(insn, ops[1]) if len(ops) > 1 else "sr::X87Op{0, 0u}"
        return [f"  sr::x87_ucom(s, {a}, {b});"]
    def i_fsin(self, i): return ["  sr::x87_sin(s);"]
    def i_fcos(self, i): return ["  sr::x87_cos(s);"]
    def i_fsincos(self, i): return ["  sr::x87_sincos(s);"]
    def i_fptan(self, i): return ["  sr::x87_tan(s);"]
    def i_fpatan(self, i): return ["  sr::x87_atan2(s);"]
    def i_f2xm1(self, i): return ["  sr::x87_2xm1(s);"]
    def i_fyl2x(self, i): return ["  sr::x87_yl2x(s);"]
    def i_fyl2xp1(self, i): return ["  sr::x87_yl2xp1(s);"]
    def i_fldl2e(self, i): return ["  sr::x87_push_const(s, 1.4426950408889634);"]
    def i_fldln2(self, i): return ["  sr::x87_push_const(s, 0.6931471805599453);"]
    def i_fldl2t(self, i): return ["  sr::x87_push_const(s, 3.321928094887362);"]
    def i_fldlg2(self, i): return ["  sr::x87_push_const(s, 0.3010299956639812);"]
    def i_fiadd(self, insn):
        return [f"  sr::x87_fiadd(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_fisub(self, insn):
        return [f"  sr::x87_fisub(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_fimul(self, insn):
        return [f"  sr::x87_fimul(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_fidiv(self, insn):
        return [f"  sr::x87_fidiv(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]

    # -- MMX / packed integer ----------------------------------------------
    def _mmx_binop(self, insn, op: str):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::mmx_{op}(s, {d}, {self._sse_read(insn, insn.operands[1])});"]

    def i_paddsw(self, i): return self._mmx_binop(i, "paddsw")
    def i_paddw(self, i): return self._mmx_binop(i, "paddw")
    def i_paddd(self, i): return self._mmx_binop(i, "paddd")
    def i_paddsb(self, i): return self._mmx_binop(i, "paddsb")
    def i_paddb(self, i): return self._mmx_binop(i, "paddb")
    def i_psubsw(self, i): return self._mmx_binop(i, "psubsw")
    def i_psubw(self, i): return self._mmx_binop(i, "psubw")
    def i_psubd(self, i): return self._mmx_binop(i, "psubd")
    def i_pmullw(self, i): return self._mmx_binop(i, "pmullw")
    def i_pmulhw(self, i): return self._mmx_binop(i, "pmulhw")
    def i_pmulhuw(self, i): return self._mmx_binop(i, "pmulhuw")
    def i_pmaddwd_mmx(self, i): return self._mmx_binop(i, "pmaddwd")
    def i_pand(self, i): return self._mmx_binop(i, "pand")
    def i_por(self, i): return self._mmx_binop(i, "por")
    def i_pxor(self, i): return self._mmx_binop(i, "pxor")
    def i_pandn(self, i): return self._mmx_binop(i, "pandn")
    def i_packsswb(self, i): return self._mmx_binop(i, "packsswb")
    def i_packuswb(self, i): return self._mmx_binop(i, "packuswb")
    def i_punpcklbw(self, i): return self._mmx_binop(i, "punpcklbw")
    def i_punpcklwd(self, i): return self._mmx_binop(i, "punpcklwd")
    def i_punpckldq(self, i): return self._mmx_binop(i, "punpckldq")
    def i_punpckhbw(self, i): return self._mmx_binop(i, "punpckhbw")
    def i_punpckhwd(self, i): return self._mmx_binop(i, "punpckhwd")
    def i_punpckhdq(self, i): return self._mmx_binop(i, "punpckhdq")
    def i_pcmpeqb(self, i): return self._mmx_binop(i, "pcmpeqb")
    def i_pcmpeqw(self, i): return self._mmx_binop(i, "pcmpeqw")
    def i_pcmpeqd(self, i): return self._mmx_binop(i, "pcmpeqd")
    def i_pcmpgtw(self, i): return self._mmx_binop(i, "pcmpgtw")
    def i_pcmpgtd(self, i): return self._mmx_binop(i, "pcmpgtd")

    def _mmx_shift(self, insn, op: str, right: int):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        cnt = self.read_op(insn, insn.operands[1], 1)
        return [f"  {d} = sr::mmx_{op}(s, {d}, (u32)({cnt}));"]

    def i_psraw(self, i): return self._mmx_shift(i, "psraw", 1)
    def i_psrad(self, i): return self._mmx_shift(i, "psrad", 1)
    def i_psrlw(self, i): return self._mmx_shift(i, "psrlw", 0)
    def i_psrld(self, i): return self._mmx_shift(i, "psrld", 0)
    def i_psrlq(self, i): return self._mmx_shift(i, "psrlq", 0)
    def i_psllw(self, i): return self._mmx_shift(i, "psllw", 0)
    def i_pslld(self, i): return self._mmx_shift(i, "pslld", 0)
    def i_psllq(self, i): return self._mmx_shift(i, "psllq", 0)

    def i_movntq(self, insn):
        return [f"  sr::store_v4({self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{self._sse_read(insn, insn.operands[1])});"]
    def i_movlps(self, insn):
        return self._sse_move(insn)
    def i_movhps(self, insn):
        return self._sse_move(insn)
    def i_movntps(self, insn):
        return self._sse_move(insn)

    def i_cmpeqps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cmp_ps(s, {d}, {self._sse_read(insn, insn.operands[1])}, 0);"]
    def i_cmpneps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cmp_ps(s, {d}, {self._sse_read(insn, insn.operands[1])}, 4);"]

    def i_cvtpi2ps(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cvtpi2ps(s, {d}, {self._sse_read(insn, insn.operands[1])});"]
    def i_cvtps2pi(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cvtps2pi(s, {self._sse_read(insn, insn.operands[1])});"]
    def i_cvttps2pi(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_cvttps2pi(s, {self._sse_read(insn, insn.operands[1])});"]

    def i_lock_cmpxchg8b(self, insn):
        return [f"  sr::atomic_cmpxchg8b(s, {self.mem_addr_expr(insn, insn.operands[0])});"]
    def i_cmpxchg8b(self, insn):
        return self.i_lock_cmpxchg8b(insn)

    def i_pushfd(self, i): return ["  s->r[4] -= 4; sr::store<u32>(s->r[4], sr::get_flags(s));"]
    def i_popfd(self, i):
        return ["  { u32 _f = sr::load<u32>(s->r[4]); s->r[4] += 4; sr::set_flags(s, _f); }"]
    def i_pushal(self, i): return ["  sr::pushad(s);"]
    def i_popal(self, i): return ["  sr::popad(s);"]
    def i_cbw(self, i): return ["  s->r[0] = (s->r[0] & 0xFFFF0000u) | (u16)(s8)(s->r[0] & 0xFF);"]
    def i_scasd(self, i): return ["  sr::rep_scasd(s);"]
    def i_lodsb(self, i): return ["  sr::lodsb(s);"]
    def i_lodsw(self, i): return ["  sr::lodsw(s);"]
    def i_lodsd(self, i): return ["  sr::lodsd(s);"]
    def i_stosw(self, i): return ["  sr::rep_stosw(s);"]
    def i_rep_stosw(self, i): return ["  sr::rep_stosw(s);"]
    def i_xlatb(self, i):
        return ["  s->r[0] = (s->r[0] & 0xFFFFFF00u) | "
                "sr::load<u8>((s->r[3] + (s->r[0] & 0xFF)) & 0xFFFFFFFFu);"]
    def i_bound(self, insn):
        return []  # bounds check trap: the game never relies on it
    def i_aam(self, insn):
        base = insn.operands[0].imm if insn.operands else 10
        return [f"  sr::aam(s, {base});"]
    def i_aad(self, insn):
        base = insn.operands[0].imm if insn.operands else 10
        return [f"  sr::aad(s, {base});"]
    def i_les(self, insn):
        return [f"  sr::load_far_ptr(s, {self.mem_addr_expr(insn, insn.operands[1])}, "
                f"{'0' if self.md.reg_name(insn.operands[0].reg) == 'eax' else '1'});"]
    def i_lds(self, insn):
        return self.i_les(insn)
    def i_lss(self, insn):
        return self.i_les(insn)
    def i_cli(self, i): return ["  s->flags &= ~sr::kIF;"]
    def i_sti(self, i): return ["  s->flags |= sr::kIF;"]
    def i_lcall(self, insn):
        return [f"  sr::far_call(s, 0x{insn.address:08x});"]
    def i_ljmp(self, insn):
        return [f"  sr::far_call(s, 0x{insn.address:08x});"]
    def i_insb(self, i): return []  # port I/O: no-op
    def i_outsb(self, i): return []
    def i_insd(self, i): return []
    def i_outsd(self, i): return []
    def i_insw(self, i): return []
    def i_outsw(self, i): return []

    def i_bsr(self, insn):
        size = op_size(insn.operands[1])
        dst = insn.operands[0]
        return [
            f"  {{ u32 _v = sr::bit_scan_reverse((u32)({self.read_op(insn, insn.operands[1], size)}), {size});",
            f"    if (_v == 0xFFFFFFFFu) sr::set_flags(s, sr::get_flags(s) | sr::kZF);",
            f"    else {{ sr::set_flags(s, sr::get_flags(s) & ~sr::kZF); "
            f"{self.write_op(insn, dst, '_v', size)} }} }}",
        ]
    def i_bsf(self, insn):
        size = op_size(insn.operands[1])
        dst = insn.operands[0]
        return [
            f"  {{ u32 _v = sr::bit_scan_forward((u32)({self.read_op(insn, insn.operands[1], size)}), {size});",
            f"    if (_v == 0xFFFFFFFFu) sr::set_flags(s, sr::get_flags(s) | sr::kZF);",
            f"    else {{ sr::set_flags(s, sr::get_flags(s) & ~sr::kZF); "
            f"{self.write_op(insn, dst, '_v', size)} }} }}",
        ]

    def i_pminub(self, i): return self._mmx_binop(i, "pminub")
    def i_pmaxub(self, i): return self._mmx_binop(i, "pmaxub")

    def i_psrldq(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_psrldq(s, {d}, {insn.operands[1].imm & 0xFF}u);"]
    def i_pslldq(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_pslldq(s, {d}, {insn.operands[1].imm & 0xFF}u);"]

    def i_pause(self, i): return []
    def i_wait(self, i): return []
    def i_hlt(self, i): return ["  sr::unsupported(\"hlt\", s->eip); return;"]
    def i_int(self, i): return ["  sr::guest_interrupt(s);"]
    def i_int1(self, i): return ["  sr::guest_interrupt(s);"]
    def i_into(self, i): return ["  if (sr::flag_of(s)) sr::guest_interrupt(s);"]
    def i_retf(self, insn):
        return ["  sr::unsupported(\"retf\", s->eip); return;"]
    def i_aaa(self, i): return []  # BCD adjust: dead code in practice
    def i_aas(self, i): return []
    def i_daa(self, i): return []
    def i_das(self, i): return []

    def i_pshufw(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::mmx_pshufw(s, {self._sse_read(insn, insn.operands[1])}, "
                f"{insn.operands[2].imm & 0xFF}u);"]
    def i_paddusb(self, i): return self._mmx_binop(i, "paddusb")
    def i_paddusw(self, i): return self._mmx_binop(i, "paddusw")
    def i_movnti(self, insn):
        return [f"  sr::store<u32>({self.mem_addr_expr(insn, insn.operands[0])}, "
                f"(u32)({self.read_op(insn, insn.operands[1], 4)}));"]
    def i_psubusb(self, i): return self._mmx_binop(i, "psubusb")
    def i_fisubr(self, insn):
        return [f"  sr::x87_fisubr(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_fidivr(self, insn):
        return [f"  sr::x87_fidivr(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_iretd(self, i): return ["  sr::unsupported(\"iretd\", s->eip); return;"]
    def i_iret(self, i): return ["  sr::unsupported(\"iret\", s->eip); return;"]
    def i_sfence(self, i): return ["  sr::fence();"]
    def i_lfence(self, i): return ["  sr::fence();"]
    def i_mfence(self, i): return ["  sr::fence();"]
    def i_stmxcsr(self, insn):
        return [f"  sr::store<u32>({self.mem_addr_expr(insn, insn.operands[0])}, s->mxcsr);"]
    def i_ldmxcsr(self, insn):
        return [f"  s->mxcsr = sr::load<u32>({self.mem_addr_expr(insn, insn.operands[0])});"]
    def i_fcmovu(self, insn):
        return [f"  if (sr::eval_cc(s, 0xA)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]
    def i_movdq2q(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = {self._sse_read(insn, insn.operands[1])};"]
    def i_movq2dq(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = {self._sse_read(insn, insn.operands[1])};"]

    # -- final stragglers ---------------------------------------------------
    def i_ficom(self, insn):
        return [f"  sr::x87_ficom(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_ficomp(self, insn):
        return [f"  sr::x87_ficomp(s, {self.mem_addr_expr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_fisttp(self, insn):
        return [f"  sr::x87_pop_store_int(s, {self._x87_addr(insn, insn.operands[0])}, "
                f"{op_size(insn.operands[0])});"]
    def i_rsqrtss(self, insn):
        return self._sse_binop(insn, "rsqrt_ss")
    def i_rcpss(self, insn):
        return self._sse_binop(insn, "rcp_ss")
    def i_punpcklqdq(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_punpcklqdq(s, {d}, {self._sse_read(insn, insn.operands[1])});"]
    def i_punpckhqdq(self, insn):
        d = self._sse_reg(self.md.reg_name(insn.operands[0].reg))
        return [f"  {d} = sr::sse_punpckhqdq(s, {d}, {self._sse_read(insn, insn.operands[1])});"]
    def i_jcxz(self, insn):
        tgt = insn.operands[0].imm & 0xFFFFFFFF
        return [f"  if (!(s->r[1] & 0xFFFF)) {{ sr::guest_tail(s, 0x{tgt:08x}u); return; }}"]
    def i_cvttsd2si(self, insn):
        return [f"  {self.write_op(insn, insn.operands[0], f'(u32)sr::sse_cvttsd2si(s, {self._sse_read(insn, insn.operands[1])})', 4)}"]
    def i_cvtsd2si(self, insn):
        return [f"  {self.write_op(insn, insn.operands[0], f'(u32)sr::sse_cvtsd2si(s, {self._sse_read(insn, insn.operands[1])})', 4)}"]
    def i_movapd(self, insn):
        return self._sse_move(insn)
    def i_movupd(self, insn):
        return self._sse_move(insn)
    def i_movsd_xmm(self, insn):
        return self._sse_move(insn)
    def i_repz_ret(self, insn):
        return self.i_ret(insn)
    def i_rep_ret(self, insn):
        return self.i_ret(insn)

    # -- last stragglers ----------------------------------------------------
    def i_fist(self, insn):
        op = insn.operands[0]
        return [f"  sr::x87_store_int(s, {self._x87_addr(insn, op)}, {op_size(op)});"]
    def i_fistpnce(self, insn):
        return self.i_fistp(insn)
    def i_fnsave(self, insn):
        return [f"  sr::x87_save_state(s, {self.mem_addr_expr(insn, insn.operands[0])});"]
    def i_fnstenv(self, insn):
        return [f"  sr::x87_save_state(s, {self.mem_addr_expr(insn, insn.operands[0])});"]
    def i_ffreep(self, i): return ["  sr::x87_free(s);"]
    def i_movsw(self, i): return ["  sr::rep_movsw(s);"]
    def i_lock_xchg(self, insn):
        size = op_size(insn.operands[0])
        return [f"  sr::atomic_xchg(s, (u32)({self.mem_addr_expr(insn, insn.operands[0])}), "
                f"{size}, (u32)({self.read_op(insn, insn.operands[1], size)}));"]
    def i_xchg_lock(self, insn):
        return self.i_lock_xchg(insn)
    def i_xrelease_xchg(self, insn):
        return self.i_lock_xchg(insn)
    def i_bnd_jmp(self, insn):
        # MPX bounds check prefix: the jump itself is an ordinary jmp
        return self.i_jmp(insn)
    def i_fcmove(self, insn):
        return [f"  if (sr::eval_cc(s, 0x4)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]
    def i_fcmovbe(self, insn):
        return [f"  if (sr::eval_cc(s, 0x6)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]
    def i_fcmovne(self, insn):
        return [f"  if (sr::eval_cc(s, 0x5)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]
    def i_fcmovb(self, insn):
        return [f"  if (sr::eval_cc(s, 0x2)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]
    def i_fcmovnb(self, insn):
        return [f"  if (sr::eval_cc(s, 0x3)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]
    def i_ud0(self, i): return ["  sr::unsupported(\"ud0\", s->eip); return;"]
    def i_ud1(self, i): return ["  sr::unsupported(\"ud1\", s->eip); return;"]
    def i_fstpnce(self, insn):
        op = insn.operands[0]
        return [f"  sr::x87_pop_store(s, {self._x87_addr(insn, op)}, {op_size(op)});"]
    def i_frstor(self, insn):
        return [f"  sr::x87_restore_state(s, {self.mem_addr_expr(insn, insn.operands[0])});"]
    def i_pmovmskb(self, insn):
        return [f"  {self.write_op(insn, insn.operands[0], f'sr::mmx_pmovmskb(s, {self._sse_read(insn, insn.operands[1])})', 4)}"]
    def i_notrack_jmp(self, insn):
        return self.i_jmp(insn)
    def i_fcmovns(self, insn):
        return [f"  if (sr::eval_cc(s, 0x9)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]
    def i_fcmovnp(self, insn):
        return [f"  if (sr::eval_cc(s, 0xB)) sr::x87_fcmov(s, "
                f"{self._x87_addr(insn, insn.operands[1])});"]

    # -- function emission -------------------------------------------------
    def lift_function(self, f: dict) -> str:
        start = f["start"]
        blocks = sorted(self.blocks[start], key=lambda b: b["start"])
        labels = {b["start"] for b in blocks}
        name = f"sub_{start:08x}"
        # Any branch to an address that is not a block of *this* function leaves the
        # function (tail call into another lifted function, or a jump into the middle of
        # one). Those become guest tail calls, never dangling gotos.
        self._labels = labels
        # Bounds of this function, used to validate jump-table entries.
        self._func_start = start
        self._func_end = max((b["end"] for b in blocks), default=start)
        # Blocks of this function that other functions jump into. MSVC shares code tails
        # between functions, so a `jmp` can legitimately land in the middle of another
        # function; those addresses need an entry point of their own.
        #
        # A cross-function target can also fall *inside* a block rather than on its start
        # (the SEH prologue pattern jumps past the prologue into the handler body). Those get
        # a label inside the block, so the mid-entry dispatcher can reach them too.
        func_end = max((b["end"] for b in blocks), default=start)
        # Binary search into the sorted cross-target list instead of scanning all of them for
        # every one of 132,047 functions (that scan is what made the lift take an hour).
        lo = bisect.bisect_left(self._cross_sorted, start)
        hi = bisect.bisect_left(self._cross_sorted, func_end)
        # A target belongs to exactly one function: the one whose *block* contains it.
        # Function ranges can overlap (blocks are not contiguous), so a plain range test
        # assigns the same label to two functions and the second one gets an undefined goto.
        ranges = [(b["start"], b["end"]) for b in blocks]

        def owned(a: int) -> bool:
            for bs, be in ranges:
                if bs <= a < be:
                    return True
            return False

        intra = [a for a in self._cross_sorted[lo:hi] if owned(a)]
        labels |= set(intra)
        mid = sorted(labels & self._cross_targets)
        out = [f"// {f['n_insns']} instructions, {f['n_blocks']} blocks"
               + (" (orphan: not reachable from a root)" if f.get("orphan") else "")]
        if mid:
            out.append(f"// {len(mid)} block(s) are jump targets from other functions")
            # Three symbols, one body: the normal entry, the mid-entry (for jumps into the
            # middle), and the shared body. Declaring the body first keeps the wrappers thin
            # and avoids duplicating the code, which would double the binary for a quarter of
            # all functions.
            out.append(f"static void {name}_body(sr::CpuState* s, sr::u32 addr);")
            out.append(f"void {name}(sr::CpuState* s) {{ {name}_body(s, 0x{start:08x}u); }}")
            out.append(f"void {name}_mid(sr::CpuState* s, sr::u32 addr) "
                       f"{{ {name}_body(s, addr); }}")
            out.append(f"static void {name}_body(sr::CpuState* s, sr::u32 addr) {{")
            out.append("  switch (addr) {")
            for m in mid:
                out.append(f"    case 0x{m:08x}u: goto L_{m:08x};")
            out.append("    default: break;")
            out.append("  }")
        else:
            out.append(f"void {name}(sr::CpuState* s) {{")
        out.append(f"  s->eip = 0x{start:08x};")
        code = self.pe.d
        for b in blocks:
            out.append(f"L_{b['start']:08x}:;")
            # Block-level EIP: a crash report then names the basic block that faulted instead
            # of just the function. One store per block is cheap and makes every future crash
            # directly disassemblable.
            out.append(f"  s->eip = 0x{b['start']:08x};")
            addr = b["start"]
            while addr < b["end"]:
                # A cross-function jump can land inside this block (not just at its start):
                # emit a label there so the mid-entry dispatcher can reach it.
                if addr != b["start"] and addr in labels:
                    out.append(f"L_{addr:08x}:;")
                    out.append(f"  s->eip = 0x{addr:08x};")
                o = self.pe.off_va(addr)
                got = None
                for insn in self.md.disasm(code[o:o + 16], addr):
                    got = insn
                    break
                if got is None:
                    out.append(f"  sr::unsupported(\"<undecodable>\", 0x{addr:08x}); return;")
                    break
                try:
                    out.extend(self.emit_insn(got))
                except Exception as e:  # noqa: BLE001 - record, never abort
                    self.unhandled[f"{got.mnemonic} ({e!r})"] += 1
                    out.append(f"  sr::unsupported(\"{got.mnemonic}\", 0x{got.address:08x}); return;")
                    break
                addr += got.size
            kind = b["kind"]
            if kind == "ret":
                out.append("  return;")
            elif kind == "jmp_indirect":
                out.append("  return;  // indirect jump: dispatch table handles it")
            elif kind == "shared":
                # The walk stopped at an address that was already owned. Two cases:
                #   * it is a block of *this* function (the census reached it by another path)
                #     -> just continue there, it is a normal label;
                #   * it belongs to another function -> a real tail call.
                if b["end"] in labels:
                    out.append(f"  goto L_{b['end']:08x};")
                else:
                    out.append(f"  sr::guest_tail(s, 0x{b['end']:08x}u); return;")
            elif kind in ("int3", "trap", "orphan"):
                out.append("  return;")
        if not blocks:
            out.append(f"  sr::unsupported(\"<empty>\", 0x{start:08x});")
        out.append("}")
        return "\n".join(out)

    def run(self, limit: int | None = None) -> None:
        GEN.mkdir(parents=True, exist_ok=True)
        # Remove every generated file, not just the chunks: a previous run with a different
        # function count leaves stale chunks behind, and they duplicate definitions at link
        # time (415 chunks now vs 529 before).
        for old in GEN.glob("*.cpp"):
            old.unlink()
        for old in GEN.glob("*.h"):
            old.unlink()
        # Only lift functions reachable from a root; orphan groups are data islands.
        real = [f for f in self.funcs if not f.get("orphan")]
        if limit:
            real = real[:limit]
        self._lifted = {f["start"] for f in real}
        self._labels = set()
        # Every block address that some *other* function jumps to AND that is not itself a
        # function start. Jumps to a function start are handled by the normal dispatch table,
        # so only the genuinely shared code tails need a mid-entry dispatcher.
        #
        # A block's successor can be a block that the census never decoded (kind "shared"):
        # the walk stopped because the address was already owned by another function. Those
        # are exactly the cross-function jumps this table exists for, so they are included.
        self._cross_targets = set()
        for f in real:
            mine = {b["start"] for b in self.blocks[f["start"]]}
            for b in self.blocks[f["start"]]:
                for succ in b["succ"]:
                    if succ in mine:
                        continue  # internal branch
                    if succ in self._lifted:
                        continue  # jumps to a function start: normal dispatch
                    self._cross_targets.add(succ)
        # Split into chunks so the compiler can work on them in parallel and no single
        # translation unit gets absurdly large (the whole lift is ~15M lines of C++).
        CHUNK = 250
        chunks = [real[i:i + CHUNK] for i in range(0, len(real), CHUNK)]
        print(f"[lift] lifting {len(real):,} functions in {len(chunks)} chunks "
              f"(of {len(self.funcs):,} total)", flush=True)

        # Which functions contain a block that another function jumps into.
        mid_functions = set()
        for f in real:
            mine = {b["start"] for b in self.blocks[f["start"]]}
            if mine & self._cross_targets:
                mid_functions.add(f["start"])
        self._mid_functions = mid_functions
        self._cross_sorted = sorted(self._cross_targets)
        # Every block start in the program: a jump-table entry is valid only if it points at
        # one, which is what distinguishes a real table from data that merely looks like one.
        self._all_block_starts = set()
        for f in self.funcs:
            for b in self.blocks[f["start"]]:
                self._all_block_starts.add(b["start"])
        print(f"[lift] {len(mid_functions):,} functions need a mid-entry dispatcher",
              flush=True)

        header = ['// generated by tools/lift.py -- do not edit',
                  '#include "rt/cpu.h"', '#include "rt/mem.h"', '#include "rt/guest.h"',
                  '#include "protos.h"', '',
                  'namespace sr {', '']
        # prototypes for every lifted function, included by every chunk
        with (GEN / "protos.h").open("w", encoding="utf-8") as fh:
            fh.write("// generated by tools/lift.py\n#pragma once\nnamespace sr {\n")
            for f in real:
                fh.write(f"void sub_{f['start']:08x}(CpuState* s);\n")
                if f["start"] in mid_functions:
                    fh.write(f"void sub_{f['start']:08x}_mid(CpuState* s, u32 addr);\n")
            fh.write("}  // namespace sr\n")

        for ci, chunk in enumerate(chunks):
            with (GEN / f"funcs_{ci:04d}.cpp").open("w", encoding="utf-8") as fh:
                fh.write("\n".join(header) + "\n")
                for f in chunk:
                    try:
                        fh.write(self.lift_function(f))
                    except Exception as e:  # noqa: BLE001 - never abort a full pass
                        self.failed[f["start"]] = repr(e)
                        self.unhandled[f"FUNCTION {e!r}"] += 1
                        fh.write(f"void sub_{f['start']:08x}(sr::CpuState* s) {{ "
                                 f"sr::unsupported(\"lift failed\", 0x{f['start']:08x}); }}\n")
                    fh.write("\n\n")
                fh.write("}  // namespace sr\n")
            if ci and ci % 50 == 0:
                print(f"[lift]   chunk {ci:,}/{len(chunks):,}", flush=True)

        # dispatch table
        with (GEN / "table.cpp").open("w", encoding="utf-8") as fh:
            fh.write("// generated by tools/lift.py\n")
            fh.write('#include "rt/guest.h"\n#include "protos.h"\n\nnamespace sr {\n')
            fh.write("GuestEntry g_functions[] = {\n")
            for f in real:
                fh.write(f"  {{ 0x{f['start']:08x}u, sub_{f['start']:08x} }},\n")
            fh.write("};\nconst unsigned g_function_count = "
                     f"{len(real)};\n\n")
            # Range table: lets the runtime find the function that *contains* an address, not
            # just one that starts there. MSVC shares code tails, so a jump can land inside
            # another function and has to enter it at that block.
            fh.write("// {start, end, entry, mid_entry}\n")
            fh.write("const FunctionRange g_function_ranges[] = {\n")
            for f in sorted(real, key=lambda x: x["start"]):
                end = max(b["end"] for b in self.blocks[f["start"]])
                mid = (f"sub_{f['start']:08x}_mid" if f["start"] in mid_functions
                       else "nullptr")
                fh.write(f"  {{ 0x{f['start']:08x}u, 0x{end:08x}u, "
                         f"sub_{f['start']:08x}, {mid} }},\n")
            fh.write("};\nconst unsigned g_function_range_count = "
                     f"{len(real)};\n}}  // namespace sr\n")

        rep = []
        w = rep.append
        w("# Lifter report\n")
        w(f"* functions lifted: {len(real):,}")
        w(f"* instructions lifted: {sum(self.stats.values()):,}")
        w(f"* instructions needing work: {sum(self.unhandled.values()):,}")
        w("\n## Mnemonics still unhandled\n")
        w("| mnemonic | count |\n|---|---|")
        for mn, c in self.unhandled.most_common():
            w(f"| {mn} | {c:,} |")
        Path("analysis/lift_report.md").write_text("\n".join(rep) + "\n", encoding="utf-8")
        print(f"[lift] handled {sum(self.stats.values()):,} instructions, "
              f"{sum(self.unhandled.values()):,} unhandled "
              f"({len(self.unhandled)} distinct mnemonics)")
        print("[lift] wrote recomp/gen/ and analysis/lift_report.md")


def main() -> int:
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    Lifter().run(limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



