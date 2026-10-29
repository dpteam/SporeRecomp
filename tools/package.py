"""Spore package reader: DBPF index + RefPack decompression.

Written from the measured format (magic "DBPF", 0x60-byte header, index at header+0x40 with a
fallback at +0x28, per-record offset/packed/unpacked sizes) and the RefPack decoder semantics.
This is the minimum needed to answer questions about package *contents* — for example whether
shader bytecode exists at all.

Usage:
  python tools/package.py list  <package> [--limit N]      # list resources
  python tools/package.py types <package>                  # type ids and counts
  python tools/package.py dump  <package> <outdir> [--type T] [--limit N]
  python tools/package.py probe <package>                  # scan decompressed payloads for
                                                           # shader bytecode
"""
from __future__ import annotations

import struct
import sys
from collections import Counter
from pathlib import Path

DBPF = 0x46504244  # "DBPF"
HDR_SIZE = 0x60


# ---------------------------------------------------------------------------
# RefPack
# ---------------------------------------------------------------------------
def is_refpack(data: bytes) -> bool:
    if len(data) < 2:
        return False
    word = (data[0] << 8) | data[1]
    return (word & 0x1FFF) == 0x10FB


def refpack_decode(src: bytes, expected: int = 0) -> bytes | None:
    """Decodes a RefPack stream. Returns None on any inconsistency (never partial data)."""
    if not is_refpack(src):
        return None
    word = (src[0] << 8) | src[1]
    nlen = 4 if (word & 0x8000) else 3
    if len(src) < 2 + nlen:
        return None
    size = 0
    for i in range(nlen):
        size = (size << 8) | src[2 + i]  # big-endian
    if expected and size != expected:
        return None

    out = bytearray()
    i = 2 + nlen
    n = len(src)
    while True:
        if i >= n:
            return None
        c = src[i]
        i += 1
        if c < 0x80:
            if i >= n:
                return None
            b1 = src[i]
            i += 1
            lits = c & 3
            length = ((c >> 2) & 7) + 3
            dist = ((c & 0x60) << 3) + b1 + 1
        elif c < 0xC0:
            if i + 1 >= n:
                return None
            b0, b1 = src[i], src[i + 1]
            i += 2
            lits = b0 >> 6
            length = (c & 0x3F) + 4
            dist = ((b0 & 0x3F) << 8) + b1 + 1
        elif c < 0xE0:
            if i + 2 >= n:
                return None
            b0, b1, b2 = src[i], src[i + 1], src[i + 2]
            i += 3
            lits = c & 3
            length = ((c & 0x0C) << 6) + b2 + 5
            dist = ((c & 0x10) << 12) + (b0 << 8) + b1 + 1
        else:
            length = ((c & 0x1F) << 2) + 4
            if length > 0x70:
                lits = c & 3
                if i + lits > n or len(out) + lits > size:
                    return None
                out += src[i:i + lits]
                break
            if i + length > n or len(out) + length > size:
                return None
            dist = ((c & 0x60) << 3) + src[i] + 1
            i += 1
            if dist > len(out):
                return None
            for _ in range(length):
                out.append(out[-dist])
            continue
        # literal run followed by a back reference
        if i + lits > n or len(out) + lits > size:
            return None
        out += src[i:i + lits]
        i += lits
        if dist > len(out) or len(out) + length > size:
            return None
        for _ in range(length):
            out.append(out[-dist])
    return bytes(out)


# ---------------------------------------------------------------------------
# DBPF index
# ---------------------------------------------------------------------------
class Package:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < HDR_SIZE:
            raise ValueError("smaller than the 0x60-byte header")
        hdr = self.data
        magic = struct.unpack_from("<I", hdr, 0x00)[0]
        if magic != DBPF:
            raise ValueError(f"magic is 0x{magic:08x}, expected DBPF")
        self.version = struct.unpack_from("<I", hdr, 0x04)[0]
        self.count = struct.unpack_from("<I", hdr, 0x24)[0]
        self.index_size = struct.unpack_from("<I", hdr, 0x2C)[0]
        alt = struct.unpack_from("<I", hdr, 0x28)[0]
        ioff = struct.unpack_from("<I", hdr, 0x40)[0]
        self.index_offset = ioff or alt
        self.records: list[dict] = []
        self._parse_index()

    def _parse_index(self) -> None:
        base = self.index_offset
        if base + self.index_size > len(self.data):
            raise ValueError("index out of range")
        # The index starts with a "kind" dword; the record stride follows from the index size.
        # Derive the candidates from the numbers instead of guessing a fixed list.
        kind = struct.unpack_from("<I", self.data, base)[0]
        self.kind = kind
        found = None
        if self.count:
            for prefix in (0, 4, 8, 12, 16):
                rem = self.index_size - prefix
                if rem <= 0:
                    continue
                if rem % self.count == 0:
                    stride = rem // self.count
                    if 16 <= stride <= 40:
                        found = (prefix, stride)
                        break
        if not found:
            raise ValueError(
                f"unknown index layout: kind=0x{kind:08x} count={self.count} "
                f"index_size={self.index_size}")
        self.prefix, self.stride = found
        # A record is at least: type, group, instance, offset, packed, unpacked (24 bytes).
        if self.stride < 24:
            raise ValueError(f"index stride {self.stride} is too small for a resource record")
        extra = self.stride - 24
        off = base + self.prefix
        for i in range(self.count):
            o = off + i * self.stride
            type_id, group, instance = struct.unpack_from("<III", self.data, o)
            pos = o + 12 + extra
            offset, packed, unpacked = struct.unpack_from("<III", self.data, pos)
            self.records.append(dict(type=type_id, group=group, instance=instance,
                                     offset=offset, packed=packed, unpacked=unpacked,
                                     index=i))

    def read(self, rec: dict) -> bytes | None:
        raw = self.data[rec["offset"]:rec["offset"] + rec["packed"]]
        if rec["packed"] == rec["unpacked"]:
            return raw
        out = refpack_decode(raw, rec["unpacked"])
        if out is None:
            # Some records store a compressed stream without a matching size field.
            out = refpack_decode(raw, 0)
        return out


# ---------------------------------------------------------------------------
# shader probing (same validation rules as tools/shader_verify.py)
# ---------------------------------------------------------------------------
VERSIONS = {
    0xFFFE0101: "vs_1_1", 0xFFFE0200: "vs_2_0", 0xFFFE0201: "vs_2_x",
    0xFFFE02FF: "vs_2_sw", 0xFFFE0300: "vs_3_0", 0xFFFE0301: "vs_3_sw",
    0xFFFF0101: "ps_1_1", 0xFFFF0102: "ps_1_2", 0xFFFF0103: "ps_1_3",
    0xFFFF0104: "ps_1_4", 0xFFFF0200: "ps_2_0", 0xFFFF0201: "ps_2_a",
    0xFFFF0202: "ps_2_b", 0xFFFF02FF: "ps_2_sw", 0xFFFF0300: "ps_3_0",
    0xFFFF0301: "ps_3_sw",
}
END_TOKEN = 0x0000FFFF
COMMENT_TOKEN = 0x0000FFFE


def validate_stream(data: bytes, pos: int) -> tuple[bool, int]:
    n = len(data)
    if pos + 8 > n:
        return False, 0
    i = pos + 4
    tokens = 0
    while i + 4 <= n and tokens < 4096:
        tok = struct.unpack_from("<I", data, i)[0]
        if tok == END_TOKEN:
            return tokens >= 6, i + 4 - pos
        if tok == COMMENT_TOKEN:
            if i + 8 > n:
                return False, 0
            clen = struct.unpack_from("<I", data, i + 4)[0]
            if clen > 0x10000 or i + 8 + clen > n:
                return False, 0
            i += 8 + clen
            tokens += 1
            continue
        opcode = tok & 0xFFFF
        if opcode >= 0x100:
            return False, 0
        length = (tok >> 24) & 0x0F
        if length > 6:
            return False, 0
        i += 4 * (1 + length)
        tokens += 1
    return False, 0


def probe_payload(payload: bytes) -> Counter:
    found: Counter = Counter()
    n = len(payload)
    for i in range(0, n - 8, 4):
        tok = struct.unpack_from("<I", payload, i)[0]
        if tok in VERSIONS:
            ok, _ = validate_stream(payload, i)
            if ok:
                found[VERSIONS[tok]] += 1
    return found


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd, path = sys.argv[1], Path(sys.argv[2])
    pkg = Package(path)
    print(f"{path.name}: DBPF v{pkg.version}, {pkg.count:,} resources, "
          f"index kind=0x{pkg.kind:08x} stride={pkg.stride}")

    if cmd == "list":
        limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else 40
        for r in pkg.records[:limit]:
            print(f"  0x{r['type']:08x} 0x{r['group']:08x} 0x{r['instance']:08x} "
                  f"off=0x{r['offset']:08x} {r['packed']:,} -> {r['unpacked']:,}")
        return 0

    if cmd == "types":
        c = Counter(r["type"] for r in pkg.records)
        print(f"{len(c)} distinct type ids")
        for t, n in c.most_common(30):
            print(f"  0x{t:08x} {n:6,d}")
        return 0

    if cmd == "probe":
        total: Counter = Counter()
        scanned = failed = 0
        for r in pkg.records:
            payload = pkg.read(r)
            if payload is None:
                failed += 1
                continue
            scanned += 1
            total.update(probe_payload(payload))
        print(f"scanned {scanned:,} payloads ({failed:,} could not be decoded)")
        if total:
            print("shader bytecode found:")
            for name, n in total.most_common():
                print(f"  {name:10s} {n:,}")
            print("\n=> shaders ship as pre-compiled bytecode: translate to GLSL ES.")
        else:
            print("no shader bytecode in the decompressed payloads")
            print("=> shaders are compiled at runtime: an HLSL front end is required.")
        return 0

    if cmd == "dump":
        outdir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("unpacked")
        outdir.mkdir(parents=True, exist_ok=True)
        want = None
        if "--type" in sys.argv:
            want = int(sys.argv[sys.argv.index("--type") + 1], 0)
        limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else 10**9
        n = 0
        for r in pkg.records:
            if want is not None and r["type"] != want:
                continue
            if n >= limit:
                break
            payload = pkg.read(r)
            if payload is None:
                continue
            name = f"{r['type']:08x}_{r['group']:08x}_{r['instance']:08x}.bin"
            (outdir / name).write_bytes(payload)
            n += 1
        print(f"wrote {n} resources to {outdir}")
        return 0

    print(f"unknown command {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
