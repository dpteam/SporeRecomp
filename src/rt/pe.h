// SporeRecomp — PE32 image loader.
//
// Loads the guest SporeApp.exe into the guest address space at its preferred base
// (0x400000), applies base relocations, resolves imports through the shim registry and
// sets up the TLS block. No Win32 loader is involved: we are the loader.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sr {

struct PeSection {
  std::string name;
  uint32_t va = 0;
  uint32_t vsize = 0;
  uint32_t raw_size = 0;
  uint32_t raw_off = 0;
  uint32_t characteristics = 0;
};

struct PeImport {
  std::string dll;
  std::string name;   // function name, or "" for ordinal imports
  uint16_t ordinal = 0;
  uint32_t iat_rva = 0;
  void* resolved = nullptr;
};

struct PeImage {
  std::string path;
  uint32_t base = 0;            // preferred/actual load base
  uint32_t size_of_image = 0;
  uint32_t entry_point = 0;     // RVA
  uint32_t checksum = 0;
  uint16_t subsystem = 0;
  uint16_t dll_characteristics = 0;
  uint32_t tls_rva = 0;
  uint32_t tls_size = 0;
  std::vector<PeSection> sections;
  std::vector<PeImport> imports;
  std::vector<uint32_t> relocs;  // RVAs that hold absolute pointers
  std::vector<uint8_t> file_data;
};

// Parses the file (does not touch guest memory yet).
bool pe_parse(const char* path, PeImage& out, std::string& err);

// Maps the image into guest memory, applies relocations and writes the import thunks.
// `resolve` is called for every import; returning nullptr leaves the IAT entry zero
// (the shim layer logs those and the first call traps).
using ImportResolver = void* (*)(const char* dll, const char* name, uint16_t ordinal);
bool pe_load(PeImage& img, ImportResolver resolve, std::string& err);

}  // namespace sr
