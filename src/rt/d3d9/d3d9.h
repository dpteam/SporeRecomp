// SporeRecomp — Direct3D 9 shim.
//
// The guest imports exactly one function from d3d9.dll (Direct3DCreate9); everything else goes
// through COM vtables. Spore renders with RenderWare 4, which uses the fixed-function pipeline
// for the world and vertex/pixel shaders (vs_2_0 / ps_3_0) for effects.
//
// Two backends live behind the same interface:
//   * NullBackend — counts every call and returns success. Used to get the guest's own game
//     logic running before any pixels exist.
//   * GlesBackend — translates state and draw calls to GLES2/3 (added once the boot ladder
//     reaches the first frame).
#pragma once

#include <cstdint>

#include "rt/cpu.h"

namespace sr::d3d {

using u32 = uint32_t;
using u64 = uint64_t;

// Device capabilities the guest asks for. Spore checks for shader model 2 and 3.
struct Caps {
  u32 max_texture_width = 2048;
  u32 max_texture_height = 2048;
  u32 max_texture_stages = 8;
  u32 max_streams = 16;
  u32 max_vertex_shader_const = 256;
  u32 max_pixel_shader_const = 224;
  u32 pixel_shader_version = 0xFFFF0300;  // 3.0
  u32 vertex_shader_version = 0xFFFF0300;  // 3.0
  u32 num_simultaneous_rendertargets = 4;
};

extern Caps g_caps;

// Statistics, reported in the log so we can see what the game actually asks for.
struct Stats {
  u64 draws = 0;
  u64 draw_indexed = 0;
  u64 primitives = 0;
  u64 textures_created = 0;
  u64 vb_created = 0;
  u64 ib_created = 0;
  u64 vs_created = 0;
  u64 ps_created = 0;
  u64 state_changes = 0;
  u64 presents = 0;
  u64 clears = 0;
  u64 shader_compile_requests = 0;
};
extern Stats g_stats;
void report_stats();

// Registers the COM method tables and creates the singleton IDirect3D9.
bool init();
void shutdown();

// Implements d3d9.dll!Direct3DCreate9(SDK version) -> IDirect3D9*.
u32 create_d3d9();

// --- host-side resource records -------------------------------------------
struct Texture {
  u32 width = 0, height = 0, levels = 0, format = 0, usage = 0;
  u32 gl_id = 0;          // GLES texture name (0 until uploaded)
  u32 bytes = 0;
  bool render_target = false;
  bool dynamic = false;
};

struct Buffer {
  u32 size = 0, fvf = 0, usage = 0;
  u32 gl_id = 0;
  bool is_index = false;
  u32 guest_data = 0;     // where the guest's copy lives (for the null backend)
};

struct Shader {
  u32 guest_code = 0;
  u32 size = 0;
  u32 gl_program = 0;
  bool is_pixel = false;
};

}  // namespace sr::d3d

