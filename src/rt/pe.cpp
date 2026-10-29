// SporeRecomp — PE32 loader implementation.
//
// The C++ side and tools/pe.py must agree exactly: the tools compute function addresses from
// the same structures the loader maps. When they disagree, the loader silently walks garbage
// (236,862 "imports" instead of 495), so every loop here is bounded and every field is checked.
#include "rt/pe.h"

#include <cstdio>
#include <cstring>
#include <unordered_map>

#include "rt/imports.h"
#include "rt/mem.h"

namespace sr {

namespace {

template <typename T>
T rd(const std::vector<uint8_t>& d, size_t off) {
  T v{};
  if (off + sizeof(T) <= d.size()) __builtin_memcpy(&v, d.data() + off, sizeof(T));
  return v;
}

// RVA -> file offset, using the section table. Returns 0 when the RVA is not mapped.
uint32_t rva_to_off(const std::vector<PeSection>& secs, uint32_t rva) {
  for (const auto& s : secs) {
    uint32_t span = s.vsize > s.raw_size ? s.vsize : s.raw_size;
    if (rva >= s.va && rva < s.va + span) {
      return s.raw_off + (rva - s.va);
    }
  }
  return 0;
}

std::string cstr_at(const std::vector<uint8_t>& d, size_t off, size_t max_len = 256) {
  std::string out;
  for (size_t i = 0; i < max_len && off + i < d.size() && d[off + i]; ++i) {
    out += char(d[off + i]);
  }
  return out;
}

}  // namespace

bool pe_parse(const char* path, PeImage& img, std::string& err) {
  FILE* f = std::fopen(path, "rb");
  if (!f) {
    err = std::string("cannot open ") + path;
    return false;
  }
  std::fseek(f, 0, SEEK_END);
  long size = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (size <= 0) {
    std::fclose(f);
    err = "empty file";
    return false;
  }
  img.file_data.resize(size_t(size));
  if (std::fread(img.file_data.data(), 1, size_t(size), f) != size_t(size)) {
    std::fclose(f);
    err = "short read";
    return false;
  }
  std::fclose(f);
  img.path = path;

  auto& d = img.file_data;
  if (d.size() < 0x40 || d[0] != 'M' || d[1] != 'Z') {
    err = "not an MZ file";
    return false;
  }
  uint32_t pe_off = rd<uint32_t>(d, 0x3C);
  if (pe_off + 24 > d.size() || std::memcmp(d.data() + pe_off, "PE\0\0", 4) != 0) {
    err = "not a PE file";
    return false;
  }
  uint16_t machine = rd<uint16_t>(d, pe_off + 4);
  uint16_t nsec = rd<uint16_t>(d, pe_off + 6);
  uint16_t opt_size = rd<uint16_t>(d, pe_off + 20);
  size_t opt = pe_off + 24;
  uint16_t magic = rd<uint16_t>(d, opt);
  if (machine != 0x14C || magic != 0x10B) {
    err = "expected a 32-bit x86 PE";
    return false;
  }
  img.entry_point = rd<uint32_t>(d, opt + 16);
  img.base = rd<uint32_t>(d, opt + 28);
  img.size_of_image = rd<uint32_t>(d, opt + 56);
  img.checksum = rd<uint32_t>(d, opt + 64);
  img.subsystem = rd<uint16_t>(d, opt + 68);
  img.dll_characteristics = rd<uint16_t>(d, opt + 70);
  size_t dir = opt + 96;

  img.tls_rva = rd<uint32_t>(d, dir + 9 * 8);
  img.tls_size = rd<uint32_t>(d, dir + 9 * 8 + 4);

  size_t sec = opt + size_t(opt_size);
  if (sec + size_t(nsec) * 40 > d.size()) {
    err = "section table out of range";
    return false;
  }
  for (uint16_t i = 0; i < nsec; ++i) {
    size_t o = sec + size_t(i) * 40;
    PeSection s;
    char name[9]{};
    __builtin_memcpy(name, d.data() + o, 8);
    s.name = name;
    s.vsize = rd<uint32_t>(d, o + 8);
    s.va = rd<uint32_t>(d, o + 12);
    s.raw_size = rd<uint32_t>(d, o + 16);
    s.raw_off = rd<uint32_t>(d, o + 20);
    s.characteristics = rd<uint32_t>(d, o + 36);
    img.sections.push_back(s);
  }

  // ---- imports ----------------------------------------------------------
  // IMPORTANT: the import directory holds *RVAs*, and every pointer inside it is an RVA too.
  // The first version of this code used them as file offsets, which made the walk run off into
  // arbitrary data (236,862 "imports"). Everything goes through rva_to_off now.
  uint32_t imp_rva = rd<uint32_t>(d, dir + 1 * 8);
  uint32_t imp_size = rd<uint32_t>(d, dir + 1 * 8 + 4);
  if (imp_rva) {
    size_t o = rva_to_off(img.sections, imp_rva);
    if (!o) {
      err = "import directory is not mapped";
      return false;
    }
    // Bound the walk by the directory size as well as by the terminator.
    size_t end = o + (imp_size ? imp_size : 4096);
    if (end > d.size()) end = d.size();
    while (o + 20 <= end) {
      uint32_t ilt = rd<uint32_t>(d, o + 0);
      uint32_t name_rva = rd<uint32_t>(d, o + 12);
      uint32_t iat = rd<uint32_t>(d, o + 16);
      if (!name_rva && !iat) break;
      std::string dll = cstr_at(d, rva_to_off(img.sections, name_rva));
      uint32_t thunk_rva = ilt ? ilt : iat;
      size_t t = rva_to_off(img.sections, thunk_rva);
      uint32_t slot = 0;
      unsigned guard = 0;
      while (t && t + 4 <= d.size() && guard++ < 8192) {
        uint32_t v = rd<uint32_t>(d, t);
        if (!v) break;
        PeImport imp;
        imp.dll = dll;
        imp.iat_rva = iat + slot;
        if (v & 0x80000000u) {
          imp.ordinal = uint16_t(v & 0xFFFF);
        } else {
          imp.name = cstr_at(d, rva_to_off(img.sections, v) + 2);
        }
        img.imports.push_back(imp);
        t += 4;
        slot += 4;
      }
      o += 20;
    }
  }

  // ---- relocations ------------------------------------------------------
  uint32_t rel_rva = rd<uint32_t>(d, dir + 5 * 8);
  uint32_t rel_size = rd<uint32_t>(d, dir + 5 * 8 + 4);
  if (rel_rva) {
    size_t o = rva_to_off(img.sections, rel_rva);
    size_t end = o + rel_size;
    if (end > d.size()) end = d.size();
    while (o && o + 8 <= end) {
      uint32_t page = rd<uint32_t>(d, o);
      uint32_t chunk = rd<uint32_t>(d, o + 4);
      if (!page && !chunk) break;
      if (chunk < 8 || chunk > 0x10000) break;
      size_t n = (chunk - 8) / 2;
      for (size_t i = 0; i < n && o + 8 + i * 2 + 2 <= d.size(); ++i) {
        uint16_t e = rd<uint16_t>(d, o + 8 + i * 2);
        if ((e >> 12) == 3) img.relocs.push_back(page + (e & 0xFFF));
      }
      o += chunk;
    }
  }

  if (img.imports.size() > 2000) {
    err = "import table looks corrupt (" + std::to_string(img.imports.size()) + " entries)";
    return false;
  }
  if (img.imports.empty()) {
    err = "no imports parsed";
    return false;
  }
  std::fprintf(stderr, "[pe] parsed %zu imports, %zu relocations, %zu sections\n",
               img.imports.size(), img.relocs.size(), img.sections.size());
  return true;
}

bool pe_load(PeImage& img, ImportResolver resolve, std::string& err) {
  auto& mem = gmem();
  if (!mem.init()) {
    err = "guest memory init failed";
    return false;
  }
  if (!mem.map(img.base, img.size_of_image)) {
    err = "cannot map image";
    return false;
  }
  auto& d = img.file_data;
  for (auto& s : img.sections) {
    if (!s.raw_size) continue;
    if (size_t(s.raw_off) + s.raw_size > d.size()) {
      err = "section raw data out of range: " + s.name;
      return false;
    }
    __builtin_memcpy(mem.base() + img.base + s.va, d.data() + s.raw_off, s.raw_size);
  }
  // The image is loaded at its preferred base, so relocations are a no-op. They are still
  // parsed (pe_parse) because the relocation list is ground truth for which dwords are
  // pointers, which the census uses.
  unsigned bound = 0, missing = 0;
  for (auto& imp : img.imports) {
    const imports::Desc* desc = imports::find(imp.dll.c_str(), imp.name.c_str(), imp.ordinal);
    if (!desc) {
      std::fprintf(stderr, "[pe] no descriptor for %s!%s\n", imp.dll.c_str(),
                   imp.name.empty() ? ("#" + std::to_string(imp.ordinal)).c_str()
                                    : imp.name.c_str());
      store<uint32_t>(img.base + imp.iat_rva, 0);
      ++missing;
      continue;
    }
    if (!desc->fn) {
      imports::note_missing(desc);
      ++missing;
    } else {
      ++bound;
    }
    store<uint32_t>(img.base + imp.iat_rva, imports::make_stub(desc));
    imp.resolved = reinterpret_cast<void*>(desc->fn);
  }
  mem.make_executable(img.base, img.size_of_image);
  std::fprintf(stderr,
               "[pe] %s: base=0x%08x size=0x%x entry=0x%08x, %u imports implemented, "
               "%u stubbed\n",
               img.path.c_str(), img.base, img.size_of_image, img.base + img.entry_point,
               bound, missing);
  return true;
}

}  // namespace sr
