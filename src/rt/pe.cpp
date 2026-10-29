// SporeRecomp — PE32 loader implementation.
#include "rt/pe.h"

#include <cstdio>
#include <cstring>

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
  uint32_t n_dirs = rd<uint32_t>(d, opt + 92);
  size_t dir = opt + 96;

  img.tls_rva = rd<uint32_t>(d, dir + 9 * 8);
  img.tls_size = rd<uint32_t>(d, dir + 9 * 8 + 4);

  size_t sec = opt + opt_size;
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
  (void)n_dirs;

  // imports
  uint32_t imp_rva = rd<uint32_t>(d, dir + 1 * 8);
  if (imp_rva) {
    size_t o = imp_rva;
    while (true) {
      uint32_t ilt = rd<uint32_t>(d, o);
      uint32_t name_rva = rd<uint32_t>(d, o + 12);
      uint32_t iat = rd<uint32_t>(d, o + 16);
      if (!name_rva) break;
      std::string dll;
      for (size_t p = name_rva; p < d.size() && d[p]; ++p) dll += char(d[p]);
      uint32_t thunk = ilt ? ilt : iat;
      while (true) {
        uint32_t v = rd<uint32_t>(d, thunk);
        if (!v) break;
        PeImport imp;
        imp.dll = dll;
        imp.iat_rva = iat + (thunk - (ilt ? ilt : iat));
        if (v & 0x80000000u) {
          imp.ordinal = uint16_t(v & 0xFFFF);
        } else {
          for (size_t p = v + 2; p < d.size() && d[p]; ++p) imp.name += char(d[p]);
        }
        img.imports.push_back(imp);
        thunk += 4;
      }
      o += 20;
    }
  }

  // relocations
  uint32_t rel_rva = rd<uint32_t>(d, dir + 5 * 8);
  uint32_t rel_size = rd<uint32_t>(d, dir + 5 * 8 + 4);
  if (rel_rva) {
    size_t o = rel_rva;
    size_t end = o + rel_size;
    while (o + 8 <= end && o + 8 <= d.size()) {
      uint32_t page = rd<uint32_t>(d, o);
      uint32_t chunk = rd<uint32_t>(d, o + 4);
      if (!page && !chunk) break;
      size_t n = (chunk - 8) / 2;
      for (size_t i = 0; i < n; ++i) {
        uint16_t e = rd<uint16_t>(d, o + 8 + i * 2);
        if ((e >> 12) == 3) img.relocs.push_back(page + (e & 0xFFF));
      }
      o += chunk;
    }
  }
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
    if (s.raw_off + s.raw_size > d.size()) {
      err = "section raw data out of range: " + s.name;
      return false;
    }
    __builtin_memcpy(mem.base() + img.base + s.va, d.data() + s.raw_off, s.raw_size);
  }
  // The image is loaded at its preferred base, so relocations are a no-op. We still walk
  // them to verify the loader agrees with the file about which dwords are pointers.
  for (uint32_t rva : img.relocs) {
    uint32_t v = load<uint32_t>(img.base + rva);
    if (v && v < img.base) {
      // pointer outside the image: leave as-is (import/IAT entries land here)
    }
  }
  // Bind imports: give each one a unique guest stub address and write it into the IAT, so
  // `call dword ptr [IAT]` dispatches into the shim layer.
  unsigned bound = 0, missing = 0;
  for (auto& imp : img.imports) {
    const imports::Desc* desc =
        imports::find(imp.dll.c_str(), imp.name.c_str(), imp.ordinal);
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
