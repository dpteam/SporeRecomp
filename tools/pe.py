"""Minimal PE32 reader shared by the SporeRecomp tools (stdlib only)."""
from __future__ import annotations

import struct

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
        self.sections: list[dict] = []
        sec = self.e + 24 + self.optsz
        for i in range(self.nsec):
            o = sec + 40 * i
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
            ch = struct.unpack_from("<I", data, o + 36)[0]
            self.sections.append(dict(name=name, va=va, vsz=vsz, roff=roff, rsz=rsz, chars=ch))

    # ---- addressing -------------------------------------------------------
    def section(self, name: str) -> dict:
        return next(s for s in self.sections if s["name"] == name)

    def off(self, rva: int) -> int | None:
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsz"], s["rsz"]):
                return s["roff"] + (rva - s["va"])
        return None

    def in_section(self, rva: int, name: str) -> bool:
        s = self.section(name)
        return s["va"] <= rva < s["va"] + max(s["vsz"], s["rsz"])

    def dir(self, i: int) -> tuple[int, int]:
        return struct.unpack_from("<II", self.d, self.ddir + 8 * i)

    def cstr(self, rva: int) -> str:
        o = self.off(rva)
        return self.d[o:self.d.index(b"\0", o)].decode("latin-1")

    def section_bytes(self, name: str) -> bytes:
        s = self.section(name)
        return self.d[s["roff"]:s["roff"] + s["vsz"]]

    # ---- structures -------------------------------------------------------
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

    def relocs(self) -> list[int]:
        """RVAs that carry an absolute 32-bit pointer (HIGHLOW relocations)."""
        rva, size = self.dir(5)
        o = self.off(rva)
        end = o + size
        out: list[int] = []
        while o < end:
            page, chunk = struct.unpack_from("<II", self.d, o)
            if page == 0 and chunk == 0:
                break
            n = (chunk - 8) // 2
            for i in range(n):
                ent = struct.unpack_from("<H", self.d, o + 8 + 2 * i)[0]
                if (ent >> 12) == 3:  # IMAGE_REL_BASED_HIGHLOW
                    out.append(page + (ent & 0xFFF))
            o += chunk
        return out
