#!/usr/bin/env python3
"""SporeApp.exe PE report — headers, sections, imports, code-shape statistics.

Usage:  python tools/pe_report.py [path-to-exe]
Writes a markdown report to stdout (and docs/pe_report.md with --out).
Pure stdlib; no dependencies.
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys
from collections import Counter
from pathlib import Path

DEFAULT_EXE = Path("refs/SporeBin/SporeApp.exe.unpacked.exe")

DIR_NAMES = [
    "export", "import", "resource", "exception", "security", "basereloc", "debug",
    "arch", "globalptr", "tls", "loadconfig", "boundimport", "iat", "delayimport",
    "clr", "reserved",
]


class PE:
    def __init__(self, data: bytes):
        self.d = data
        self.e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.e:self.e + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        (self.machine, self.nsec, self.timestamp, _psym, _nsym,
         self.optsz, self.chars) = struct.unpack_from("<HHIIIHH", data, self.e + 4)
        self.opt = self.e + 24
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        if self.magic != 0x10B:
            raise ValueError("expected PE32")
        self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
        self.imagebase = struct.unpack_from("<I", data, self.opt + 28)[0]
        self.subsystem = struct.unpack_from("<H", data, self.opt + 68)[0]
        self.dllchars = struct.unpack_from("<H", data, self.opt + 70)[0]
        self.ndirs = struct.unpack_from("<I", data, self.opt + 92)[0]
        self.ddir = self.opt + 96
        self.sections = []
        sec = self.e + 24 + self.optsz
        for i in range(self.nsec):
            o = sec + 40 * i
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
            ch = struct.unpack_from("<I", data, o + 36)[0]
            self.sections.append(dict(name=name, va=va, vsz=vsz, roff=roff, rsz=rsz, chars=ch))

    def dir(self, i: int) -> tuple[int, int]:
        return struct.unpack_from("<II", self.d, self.ddir + 8 * i)

    def section(self, name: str) -> dict:
        return next(s for s in self.sections if s["name"] == name)

    def off(self, rva: int) -> int | None:
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsz"], s["rsz"]):
                return s["roff"] + (rva - s["va"])
        return None

    def cstr(self, rva: int) -> str:
        o = self.off(rva)
        return self.d[o:self.d.index(b"\0", o)].decode("latin-1")

    def imports(self) -> list[tuple[str, list[str]]]:
        rva, _ = self.dir(1)
        o = self.off(rva)
        out = []
        while True:
            ilt, _ts, _fc, name, iat = struct.unpack_from("<IIIII", self.d, o)
            if not name:
                break
            dll = self.cstr(name)
            t = self.off(ilt) or self.off(iat)
            names = []
            while True:
                v = struct.unpack_from("<I", self.d, t)[0]
                if not v:
                    break
                names.append("#%d" % (v & 0xFFFF) if v & 0x80000000
                             else self.cstr(self.off(v) + 2))
                t += 4
            out.append((dll, names))
            o += 20
        return out


def code_stats(code: bytes) -> dict:
    pats = {
        "movaps": b"\x0f\x28", "movaps_store": b"\x0f\x29", "movups": b"\x0f\x10",
        "movups_store": b"\x0f\x11", "movss": b"\xf3\x0f\x10", "movdqa": b"\x66\x0f\x6f",
        "xorps": b"\x0f\x57", "xorpd": b"\x66\x0f\x57", "pxor": b"\x66\x0f\xef",
        "divps": b"\x0f\x5e", "mulps": b"\x0f\x59", "addps": b"\x0f\x58",
        "cpuid": b"\x0f\xa2", "rdtsc": b"\x0f\x31", "fxsave_ldmxcsr": b"\x0f\xae",
    }
    stats = {k: code.count(v) for k, v in pats.items()}
    stats["prologue_55_8b_ec"] = code.count(b"\x55\x8b\xec")
    stats["prologue_55_89_e5"] = code.count(b"\x55\x89\xe5")
    stats["int3_pad_runs"] = len(re.findall(rb"\xcc{2,}", code))
    stats["ret_c2"] = len(re.findall(rb"\xc2[\x00-\xff][\x00-\xff]", code))
    stats["ret_c3"] = code.count(b"\xc3")
    return stats


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    exe = Path(args[0]) if args else DEFAULT_EXE
    data = exe.read_bytes()
    pe = PE(data)
    text = pe.section(".text")
    code = data[text["roff"]:text["roff"] + text["vsz"]]

    out = []
    w = out.append
    w(f"# PE report: `{exe.name}`\n")
    w(f"* size: {len(data):,} bytes")
    w(f"* sha256: `{hashlib.sha256(data).hexdigest()}`")
    w(f"* machine: 0x{pe.machine:04x}, PE32, subsystem {pe.subsystem}, imagebase 0x{pe.imagebase:x}")
    w(f"* timestamp: {pe.timestamp}")
    w(f"* entry RVA: 0x{pe.entry:08x} -> VA 0x{pe.imagebase + pe.entry:08x}\n")
    w("## Sections\n")
    w("| name | VA | vsize | raw size | chars |")
    w("|---|---|---|---|---|")
    for s in pe.sections:
        w(f"| {s['name']} | 0x{s['va']:08x} | {s['vsz']:,} | {s['rsz']:,} | 0x{s['chars']:08x} |")
    w("\n## Data directories\n")
    for i in range(pe.ndirs):
        rva, sz = pe.dir(i)
        if rva or sz:
            w(f"* {DIR_NAMES[i] if i < len(DIR_NAMES) else i}: RVA 0x{rva:08x} size {sz:,}")
    imps = pe.imports()
    w("\n## Imports\n")
    w(f"* {sum(len(n) for _, n in imps)} functions from {len(imps)} DLLs\n")
    w("| DLL | count |")
    w("|---|---|")
    for dll, names in sorted(imps, key=lambda x: -len(x[1])):
        w(f"| {dll} | {len(names)} |")
    st = code_stats(code)
    w("\n## Code shape (.text)\n")
    w(f"* .text vsize: {text['vsz']:,} bytes")
    for k, v in sorted(st.items(), key=lambda kv: -kv[1]):
        w(f"* {k}: {v:,}")
    txt = "\n".join(out) + "\n"
    sys.stdout.write(txt)
    if "--out" in sys.argv:
        p = Path("docs/pe_report.md")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")
        print(f"\n[written] {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
