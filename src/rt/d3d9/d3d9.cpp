// SporeRecomp — Direct3D 9 shim implementation.
//
// Backend: "null" for now (counts calls, returns success, keeps real host-side records for
// every resource). This is deliberate: it lets the guest's own game logic run end to end
// before any pixels exist, so the next failures we see are logic failures rather than
// "the renderer is half-written".
#include "rt/d3d9/d3d9.h"

#include <cstdio>
#include <cstring>

#include "rt/d3d9/com.h"
#include "rt/d3d9/d3d9.h"
#include "rt/guest.h"
#include "rt/mem.h"
#include "rt/shim.h"
#include "rt/win32/win32.h"

namespace sr::d3d {

using w32::write_cstr;

Caps g_caps;
Stats g_stats;

void report_stats() {
  SR_LOG("D3D: %llu presents, %llu clears, %llu draws (%llu indexed), %llu primitives",
         (unsigned long long)g_stats.presents, (unsigned long long)g_stats.clears,
         (unsigned long long)g_stats.draws, (unsigned long long)g_stats.draw_indexed,
         (unsigned long long)g_stats.primitives);
  SR_LOG("D3D: %llu textures, %llu vertex buffers, %llu index buffers, %llu vs, %llu ps",
         (unsigned long long)g_stats.textures_created,
         (unsigned long long)g_stats.vb_created, (unsigned long long)g_stats.ib_created,
         (unsigned long long)g_stats.vs_created, (unsigned long long)g_stats.ps_created);
  SR_LOG("D3D: %llu state changes, %llu shader compile requests",
         (unsigned long long)g_stats.state_changes,
         (unsigned long long)g_stats.shader_compile_requests);
}

namespace {

// Compiled GLSL from D3DXCompileShader, keyed by guest buffer address.
std::unordered_map<u32, std::string> g_glsl;

}  // namespace

void register_glsl(u32 guest_addr, const std::string& glsl, bool is_pixel) {
  (void)is_pixel;
  g_glsl[guest_addr] = glsl;
}

const std::string* find_glsl(u32 guest_addr) {
  auto it = g_glsl.find(guest_addr);
  return it == g_glsl.end() ? nullptr : &it->second;
}

namespace {

// ---------------------------------------------------------------------------
// IDirect3D9
// ---------------------------------------------------------------------------
u32 g_d3d9_object = 0;
u32 g_device_object = 0;

void d3d_query_interface(CpuState* s, const u32* a, ComObject* self) {
  com_query_interface(s, a, self);
}
void d3d_addref(CpuState* s, const u32* a, ComObject* self) { com_addref(s, a, self); }
void d3d_release(CpuState* s, const u32* a, ComObject* self) { com_release(s, a, self); }

void d3d_register_software_device(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void d3d_get_adapter_count(CpuState* s, const u32*, ComObject*) { s->r[0] = 1; }

void d3d_get_adapter_identifier(CpuState* s, const u32* a, ComObject*) {
  // D3DADAPTER_IDENTIFIER9: Driver, Description, DeviceName strings + ids
  u32 out = a[2];
  if (out) {
    __builtin_memset(gmem().base() + out, 0, 0x400);
    write_cstr(out + 0x000, "spore_recomp");       // Driver
    write_cstr(out + 0x200, "SporeRecomp GLES2");  // Description
    write_cstr(out + 0x400 - 0x200, "\\\\.\\DISPLAY1");  // DeviceName
    store<u32>(out + 0x400 - 0x100 + 0x00, 0x10DE);  // VendorId
    store<u32>(out + 0x400 - 0x100 + 0x04, 0x0000);  // DeviceId
    store<u32>(out + 0x400 - 0x100 + 0x08, 0);       // SubSysId
    store<u32>(out + 0x400 - 0x100 + 0x0C, 0);       // Revision
    store<u32>(out + 0x400 - 0x100 + 0x10, 0);       // DeviceIdentifier
    store<u32>(out + 0x400 - 0x100 + 0x14, 0);       // WHQLLevel
  }
  s->r[0] = 0;
}

void d3d_get_adapter_mode_count(CpuState* s, const u32*, ComObject*) { s->r[0] = 1; }

void d3d_enum_adapter_modes(CpuState* s, const u32* a, ComObject*) {
  // D3DDISPLAYMODE: Width, Height, RefreshRate, Format
  u32 out = a[3];
  if (out) {
    store<u32>(out + 0, 640);
    store<u32>(out + 4, 480);
    store<u32>(out + 8, 60);
    store<u32>(out + 12, 22);  // D3DFMT_X8R8G8B8
  }
  s->r[0] = 0;
}

void d3d_get_adapter_display_mode(CpuState* s, const u32* a, ComObject*) {
  u32 out = a[2];
  if (out) {
    store<u32>(out + 0, 640);
    store<u32>(out + 4, 480);
    store<u32>(out + 8, 60);
    store<u32>(out + 12, 22);  // D3DFMT_X8R8G8B8
  }
  s->r[0] = 0;
}

void d3d_check_device_type(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void d3d_check_device_format(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void d3d_check_device_multisample(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void d3d_check_depth_stencil_match(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void d3d_check_device_format_conversion(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void d3d_get_device_caps(CpuState* s, const u32* a, ComObject*) {
  // D3DCAPS9 is 0x10C bytes. Spore reads a handful of fields; fill the ones that matter.
  u32 out = a[3];
  if (out) {
    __builtin_memset(gmem().base() + out, 0, 0x10C);
    store<u32>(out + 0x00, 1);                 // DeviceType: HAL
    store<u32>(out + 0x04, 0x0000000B);        // Caps
    store<u32>(out + 0x08, 0x00010000);        // Caps2
    store<u32>(out + 0x0C, 0x00000001);        // Caps3
    store<u32>(out + 0x10, 0);                 // PresentationIntervals
    store<u32>(out + 0x14, 0x00000101);        // CursorCaps
    store<u32>(out + 0x18, 0x0000000F);        // DevCaps
    store<u32>(out + 0x1C, 0x00000000);        // PrimitiveMiscCaps
    store<u32>(out + 0x20, 0x00000000);        // RasterCaps
    store<u32>(out + 0x24, 0x00000000);        // ZCmpCaps
    store<u32>(out + 0x28, 0x000000FF);        // SrcBlendCaps
    store<u32>(out + 0x2C, 0x000000FF);        // DestBlendCaps
    store<u32>(out + 0x30, 0x0000000F);        // AlphaCmpCaps
    store<u32>(out + 0x34, 0x00000007);        // ShadeCaps
    store<u32>(out + 0x38, 0x0000000F);        // TextureCaps
    store<u32>(out + 0x3C, 0x00000000);        // TextureFilterCaps
    store<u32>(out + 0x40, 0x00000000);        // CubeTextureFilterCaps
    store<u32>(out + 0x44, 0x00000000);        // VolumeTextureFilterCaps
    store<u32>(out + 0x48, 0x00000000);        // TextureAddressCaps
    store<u32>(out + 0x4C, 0x00000000);        // VolumeTextureAddressCaps
    store<u32>(out + 0x50, 0x00000000);        // LineCaps
    store<u32>(out + 0x54, 2048);              // MaxTextureWidth
    store<u32>(out + 0x58, 2048);              // MaxTextureHeight
    store<u32>(out + 0x5C, 2048);              // MaxVolumeExtent
    store<u32>(out + 0x60, 4096);              // MaxTextureRepeat
    store<u32>(out + 0x64, 1);                 // MaxTextureAspectRatio
    store<u32>(out + 0x68, 1);                 // MaxAnisotropy
    store<u32>(out + 0x6C, 1.0f);              // MaxVertexW
    store<u32>(out + 0x70, 0);                 // GuardBandLeft
    store<u32>(out + 0x74, 0);                 // GuardBandTop
    store<u32>(out + 0x78, 0);                 // GuardBandRight
    store<u32>(out + 0x7C, 0);                 // GuardBandBottom
    store<u32>(out + 0x80, 0);                 // ExtentsAdjust
    store<u32>(out + 0x84, 0x00000001);        // StencilCaps
    store<u32>(out + 0x88, 0x00000000);        // FVFCaps
    store<u32>(out + 0x8C, 0x00000000);        // TextureOpCaps
    store<u32>(out + 0x90, 8);                 // MaxTextureBlendStages
    store<u32>(out + 0x94, 8);                 // MaxSimultaneousTextures
    store<u32>(out + 0x98, 0x00000000);        // VertexProcessingCaps
    store<u32>(out + 0x9C, 256);               // MaxActiveLights
    store<u32>(out + 0xA0, 16);                // MaxUserClipPlanes
    store<u32>(out + 0xA4, 1);                 // MaxVertexBlendMatrices
    store<u32>(out + 0xA8, 0);                 // MaxVertexBlendMatrixIndex
    store<u32>(out + 0xAC, 0);                 // MaxPointSize
    store<u32>(out + 0xB0, 8);                 // MaxPrimitiveCount
    store<u32>(out + 0xB4, 16);                // MaxVertexIndex
    store<u32>(out + 0xB8, 16);                // MaxStreams
    store<u32>(out + 0xBC, 16);                // MaxStreamStride
    store<u32>(out + 0xC0, g_caps.vertex_shader_version);  // VertexShaderVersion
    store<u32>(out + 0xC4, 256);               // MaxVertexShaderConst
    store<u32>(out + 0xC8, g_caps.pixel_shader_version);   // PixelShaderVersion
    store<u32>(out + 0xCC, 0);                 // PixelShader1xMaxValue
    store<u32>(out + 0xD0, 0);                 // DevCaps2
    store<u32>(out + 0xD4, 0);                 // MaxNpatchTessellationLevel
    store<u32>(out + 0xD8, 0);                 // Reserved
    store<u32>(out + 0xDC, 0);                 // MasterAdapterOrdinal
    store<u32>(out + 0xE0, 0);                 // AdapterOrdinalInGroup
    store<u32>(out + 0xE4, 0);                 // NumberOfAdaptersInGroup
    store<u32>(out + 0xE8, 4);                 // NumSimultaneousRTs
    store<u32>(out + 0xEC, 0);                 // StretchRectFilterCaps
    store<u32>(out + 0xF0, 0);                 // VS20Caps
    store<u32>(out + 0xF4, 0);                 // PS20Caps
    store<u32>(out + 0xF8, 0);                 // VertexTextureFilterCaps
    store<u32>(out + 0xFC, 8);                 // MaxVShaderInstructionsExecuted
    store<u32>(out + 0x100, 8);                // MaxPShaderInstructionsExecuted
    store<u32>(out + 0x104, 0xFFFF);           // MaxVertexShader30InstructionSlots
    store<u32>(out + 0x108, 0xFFFF);           // MaxPixelShader30InstructionSlots
  }
  s->r[0] = 0;
}

void d3d_get_adapter_monitor(CpuState* s, const u32*, ComObject*) {
  s->r[0] = 0x00050001;  // HMONITOR pseudo-handle
}

void d3d_create_device(CpuState* s, const u32* a, ComObject*);

// ---------------------------------------------------------------------------
// IDirect3DDevice9
// ---------------------------------------------------------------------------
void dev_query_interface(CpuState* s, const u32* a, ComObject* self) {
  com_query_interface(s, a, self);
}
void dev_addref(CpuState* s, const u32* a, ComObject* self) { com_addref(s, a, self); }
void dev_release(CpuState* s, const u32* a, ComObject* self) { com_release(s, a, self); }

void dev_test_cooperative_level(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_available_texture_mem(CpuState* s, const u32*, ComObject*) {
  s->r[0] = 128u * 1024 * 1024;
}

void dev_get_direct3d(CpuState* s, const u32* a, ComObject*) {
  if (a[1]) store<u32>(a[1], g_d3d9_object);
  s->r[0] = 0;
}

void dev_get_caps(CpuState* s, const u32* a, ComObject*) {
  // Same layout as d3d_get_device_caps, without the adapter/type arguments.
  u32 saved[8];
  for (int i = 0; i < 8; ++i) saved[i] = a[i];
  u32 fake[8] = {a[0], 0, 0, a[1], 0, 0, 0, 0};
  d3d_get_device_caps(s, fake, nullptr);
}

void dev_get_display_mode(CpuState* s, const u32* a, ComObject*) {
  u32 out = a[1];
  if (out) {
    store<u32>(out + 0, 640);
    store<u32>(out + 4, 480);
    store<u32>(out + 8, 60);
    store<u32>(out + 12, 22);
  }
  s->r[0] = 0;
}

void dev_get_creation_parameters(CpuState* s, const u32* a, ComObject*) {
  u32 out = a[1];
  if (out) {
    __builtin_memset(gmem().base() + out, 0, 20);
    store<u32>(out + 0, 0);      // AdapterOrdinal
    store<u32>(out + 4, 1);      // DeviceType: HAL
    store<u32>(out + 8, 0x40);   // BehaviorFlags: SOFTWARE_VERTEXPROCESSING
    store<u32>(out + 12, 640);
    store<u32>(out + 16, 480);
  }
  s->r[0] = 0;
}

void dev_set_cursor_properties(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_cursor_position(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_show_cursor(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_create_additional_swap_chain(CpuState* s, const u32*, ComObject*) {
  s->r[0] = 0x8876086Cu;  // D3DERR_INVALIDCALL
}

void dev_get_swap_chain(CpuState* s, const u32* a, ComObject*) {
  if (a[1]) store<u32>(a[1], g_device_object);
  s->r[0] = 0;
}

void dev_get_number_of_swap_chains(CpuState* s, const u32*, ComObject*) { s->r[0] = 1; }

void dev_reset(CpuState* s, const u32*, ComObject*) {
  SR_LOG("D3D: Reset");
  s->r[0] = 0;
}

void dev_present(CpuState* s, const u32*, ComObject*) {
  ++g_stats.presents;
  if (g_stats.presents % 300 == 1) {
    SR_LOG("D3D: present #%llu", (unsigned long long)g_stats.presents);
  }
  s->r[0] = 0;
}

void dev_get_back_buffer(CpuState* s, const u32* a, ComObject*) {
  u32 out = a[4];
  if (out) store<u32>(out, 0);
  s->r[0] = 0;
}

void dev_get_raster_status(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_dialog_box_mode(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_begin_scene(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_end_scene(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_clear(CpuState* s, const u32*, ComObject*) {
  ++g_stats.clears;
  s->r[0] = 0;
}

void dev_set_transform(CpuState* s, const u32*, ComObject*) {
  ++g_stats.state_changes;
  s->r[0] = 0;
}

void dev_get_transform(CpuState* s, const u32* a, ComObject*) {
  u32 out = a[2];
  if (out) {
    // Identity, column-major 4x4 (D3DMATRIX layout: _11.._44).
    static const float ident[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    __builtin_memcpy(gmem().base() + out, ident, sizeof ident);
  }
  s->r[0] = 0;
}

void dev_multiply_transform(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_set_viewport(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_viewport(CpuState* s, const u32* a, ComObject*) {
  u32 out = a[1];
  if (out) {
    store<u32>(out + 0, 0); store<u32>(out + 4, 0);
    store<u32>(out + 8, 640); store<u32>(out + 12, 480);
    store<float>(out + 16, 0.0f); store<float>(out + 20, 1.0f);
  }
  s->r[0] = 0;
}

void dev_set_material(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_material(CpuState* s, const u32* a, ComObject*) {
  if (a[1]) __builtin_memset(gmem().base() + a[1], 0, 68);
  s->r[0] = 0;
}
void dev_set_light(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_light(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_light_enable(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_light_enable(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_clip_plane(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_clip_plane(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_set_render_state(CpuState* s, const u32*, ComObject*) {
  ++g_stats.state_changes;
  s->r[0] = 0;
}

void dev_get_render_state(CpuState* s, const u32* a, ComObject*) {
  if (a[2]) store<u32>(a[2], 0);
  s->r[0] = 0;
}

void dev_create_state_block(CpuState* s, const u32*, ComObject*) { s->r[0] = 0x8876086Cu; }
void dev_begin_state_block(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_end_state_block(CpuState* s, const u32* a, ComObject*) {
  if (a[1]) store<u32>(a[1], 0);
  s->r[0] = 0x8876086Cu;
}

void dev_set_clip_status(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_clip_status(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_get_texture(CpuState* s, const u32* a, ComObject*) {
  if (a[2]) store<u32>(a[2], 0);
  s->r[0] = 0;
}

void dev_set_texture(CpuState* s, const u32*, ComObject*) {
  ++g_stats.state_changes;
  s->r[0] = 0;
}

void dev_get_texture_stage_state(CpuState* s, const u32* a, ComObject*) {
  if (a[3]) store<u32>(a[3], 0);
  s->r[0] = 0;
}

void dev_set_texture_stage_state(CpuState* s, const u32*, ComObject*) {
  ++g_stats.state_changes;
  s->r[0] = 0;
}

void dev_get_sampler_state(CpuState* s, const u32* a, ComObject*) {
  if (a[3]) store<u32>(a[3], 0);
  s->r[0] = 0;
}

void dev_set_sampler_state(CpuState* s, const u32*, ComObject*) {
  ++g_stats.state_changes;
  s->r[0] = 0;
}

void dev_validate_device(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_palette_entries(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_palette_entries(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_current_texture_palette(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_current_texture_palette(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_scissor_rect(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_scissor_rect(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_software_vertex_processing(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_software_vertex_processing(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_npatch_mode(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_npatch_mode(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

// --- draws ----------------------------------------------------------------
void dev_draw_primitive(CpuState* s, const u32* a, ComObject*) {
  ++g_stats.draws;
  g_stats.primitives += a[3];
  s->r[0] = 0;
}

void dev_draw_indexed_primitive(CpuState* s, const u32* a, ComObject*) {
  ++g_stats.draw_indexed;
  g_stats.primitives += a[6];
  s->r[0] = 0;
}

void dev_draw_primitive_up(CpuState* s, const u32* a, ComObject*) {
  ++g_stats.draws;
  g_stats.primitives += a[3];
  s->r[0] = 0;
}

void dev_draw_indexed_primitive_up(CpuState* s, const u32* a, ComObject*) {
  ++g_stats.draw_indexed;
  g_stats.primitives += a[7];
  s->r[0] = 0;
}

void dev_process_vertices(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_create_vertex_declaration(CpuState* s, const u32* a, ComObject*) {
  u32 out = a[2];
  if (out) store<u32>(out, 0x7F000001);
  s->r[0] = 0;
}

void dev_set_vertex_declaration(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_vertex_declaration(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_fvf(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_fvf(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_create_vertex_shader(CpuState* s, const u32* a, ComObject*);
void dev_set_vertex_shader(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_vertex_shader(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_vertex_shader_constant_f(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_vertex_shader_constant_f(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_vertex_shader_constant_i(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_vertex_shader_constant_i(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_vertex_shader_constant_b(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_vertex_shader_constant_b(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_set_stream_source(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_stream_source(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_stream_source_freq(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_stream_source_freq(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_indices(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_indices(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_create_pixel_shader(CpuState* s, const u32* a, ComObject*);
void dev_set_pixel_shader(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_pixel_shader(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_pixel_shader_constant_f(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_pixel_shader_constant_f(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_pixel_shader_constant_i(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_pixel_shader_constant_i(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_pixel_shader_constant_b(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_pixel_shader_constant_b(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_draw_rect_patch(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_draw_tri_patch(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_delete_patch(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_create_query(CpuState* s, const u32*, ComObject*) { s->r[0] = 0x8876086Cu; }

void dev_create_texture(CpuState* s, const u32* a, ComObject*);
void dev_create_volume_texture(CpuState* s, const u32*, ComObject*) { s->r[0] = 0x8876086Cu; }
void dev_create_cube_texture(CpuState* s, const u32* a, ComObject*);
void dev_create_render_target(CpuState* s, const u32*, ComObject*) { s->r[0] = 0x8876086Cu; }
void dev_create_depth_stencil_surface(CpuState* s, const u32*, ComObject*) {
  s->r[0] = 0x8876086Cu;
}
void dev_create_offscreen_plain_surface(CpuState* s, const u32*, ComObject*) {
  s->r[0] = 0x8876086Cu;
}
void dev_update_surface(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_update_texture(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_render_target_data(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_stretch_rect(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_color_fill(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_create_depth_stencil_surface_ex(CpuState* s, const u32*, ComObject*) {
  s->r[0] = 0x8876086Cu;
}
void dev_set_render_target(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_render_target(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_depth_stencil_surface(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_depth_stencil_surface(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_render_targets(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_render_targets(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_set_depth_stencil_surfaces(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_get_depth_stencil_surfaces(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void dev_create_vertex_buffer(CpuState* s, const u32* a, ComObject*);
void dev_create_index_buffer(CpuState* s, const u32* a, ComObject*);
void dev_create_vertex_shader_ex(CpuState* s, const u32* a, ComObject*);
void dev_create_pixel_shader_ex(CpuState* s, const u32* a, ComObject*);
void dev_create_state_block_ex(CpuState* s, const u32*, ComObject*) { s->r[0] = 0x8876086Cu; }
void dev_create_swap_chain(CpuState* s, const u32*, ComObject*) { s->r[0] = 0x8876086Cu; }
void dev_set_conversion_mode(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_create_effect(CpuState* s, const u32*, ComObject*) { s->r[0] = 0x8876086Cu; }
void dev_get_rt_data(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void dev_create_offscreen_plain_surface_ex(CpuState* s, const u32*, ComObject*) {
  s->r[0] = 0x8876086Cu;
}

// Method table for IDirect3DDevice9, in vtable order (119 entries).
const ComHandler kDevice9[] = {
    dev_query_interface, dev_addref, dev_release,                     // 0-2
    dev_test_cooperative_level, dev_get_available_texture_mem,        // 3-4
    nullptr,                                                          // 5 EvictManagedResources
    dev_get_direct3d, dev_get_caps, dev_get_display_mode,             // 6-8
    dev_get_creation_parameters,                                      // 9
    dev_set_cursor_properties, dev_set_cursor_position, dev_show_cursor,  // 10-12
    dev_create_additional_swap_chain, dev_get_swap_chain,             // 13-14
    dev_get_number_of_swap_chains, dev_reset, dev_present,            // 15-17
    dev_get_back_buffer, dev_get_raster_status, dev_set_dialog_box_mode,  // 18-20
    dev_begin_scene, dev_end_scene, dev_clear,                        // 21-23
    dev_set_transform, dev_get_transform, dev_multiply_transform,     // 24-26
    dev_set_viewport, dev_get_viewport,                               // 27-28
    dev_set_material, dev_get_material,                               // 29-30
    dev_set_light, dev_get_light, dev_light_enable, dev_get_light_enable,  // 31-34
    dev_set_clip_plane, dev_get_clip_plane,                           // 35-36
    dev_set_render_state, dev_get_render_state,                       // 37-38
    dev_create_state_block, dev_begin_state_block, dev_end_state_block,  // 39-41
    dev_set_clip_status, dev_get_clip_status,                         // 42-43
    dev_get_texture, dev_set_texture,                                 // 44-45
    dev_get_texture_stage_state, dev_set_texture_stage_state,         // 46-47
    dev_get_sampler_state, dev_set_sampler_state,                     // 48-49
    dev_validate_device,                                              // 50
    dev_set_palette_entries, dev_get_palette_entries,                 // 51-52
    dev_set_current_texture_palette, dev_get_current_texture_palette, // 53-54
    dev_set_scissor_rect, dev_get_scissor_rect,                       // 55-56
    dev_set_software_vertex_processing, dev_get_software_vertex_processing,  // 57-58
    dev_set_npatch_mode, dev_get_npatch_mode,                         // 59-60
    dev_draw_primitive, dev_draw_indexed_primitive,                   // 61-62
    dev_draw_primitive_up, dev_draw_indexed_primitive_up,             // 63-64
    dev_process_vertices,                                             // 65
    dev_create_vertex_declaration, dev_set_vertex_declaration,        // 66-67
    dev_get_vertex_declaration,                                       // 68
    dev_get_fvf, dev_set_fvf,                                         // 69-70
    dev_create_vertex_shader, dev_set_vertex_shader, dev_get_vertex_shader,  // 71-73
    dev_set_vertex_shader_constant_f, dev_get_vertex_shader_constant_f,      // 74-75
    dev_set_vertex_shader_constant_i, dev_get_vertex_shader_constant_i,      // 76-77
    dev_set_vertex_shader_constant_b, dev_get_vertex_shader_constant_b,      // 78-79
    dev_set_stream_source, dev_get_stream_source,                     // 80-81
    dev_set_stream_source_freq, dev_get_stream_source_freq,           // 82-83
    dev_set_indices, dev_get_indices,                                 // 84-85
    dev_create_pixel_shader, dev_set_pixel_shader, dev_get_pixel_shader,     // 86-88
    dev_set_pixel_shader_constant_f, dev_get_pixel_shader_constant_f,        // 89-90
    dev_set_pixel_shader_constant_i, dev_get_pixel_shader_constant_i,        // 91-92
    dev_set_pixel_shader_constant_b, dev_get_pixel_shader_constant_b,        // 93-94
    dev_draw_rect_patch, dev_draw_tri_patch, dev_delete_patch,        // 95-97
    dev_create_query,                                                 // 98
    dev_create_texture, dev_create_volume_texture, dev_create_cube_texture,  // 99-101
    dev_create_render_target, dev_create_depth_stencil_surface,       // 102-103
    dev_create_offscreen_plain_surface, dev_update_surface,           // 104-105
    dev_update_texture, dev_get_render_target_data, dev_stretch_rect, // 106-108
    dev_color_fill, dev_create_depth_stencil_surface_ex,              // 109-110
    dev_set_render_target, dev_get_render_target,                     // 111-112
    dev_set_depth_stencil_surface, dev_get_depth_stencil_surface,     // 113-114
    dev_set_render_targets, dev_get_render_targets,                   // 115-116
    dev_set_depth_stencil_surfaces, dev_get_depth_stencil_surfaces,   // 117-118
};

const ComHandler kD3D9[] = {
    d3d_query_interface, d3d_addref, d3d_release,                     // 0-2
    d3d_register_software_device, d3d_get_adapter_count,              // 3-4
    d3d_get_adapter_identifier, d3d_get_adapter_mode_count,           // 5-6
    d3d_enum_adapter_modes, d3d_get_adapter_display_mode,             // 7-8
    d3d_check_device_type, d3d_check_device_format,                   // 9-10
    d3d_check_device_multisample, d3d_check_depth_stencil_match,      // 11-12
    d3d_check_device_format_conversion, d3d_get_device_caps,          // 13-14
    d3d_get_adapter_monitor, d3d_create_device,                       // 15-16
};

void d3d_create_device(CpuState* s, const u32* a, ComObject*) {
  // CreateDevice(adapter, type, hFocusWindow, behaviorFlags, pPresentationParameters,
  //              ppReturnedDeviceInterface)
  u32 pp = a[6];
  u32 dev = com_create(kKindDevice9, 119, nullptr);
  g_device_object = dev;
  if (pp) store<u32>(pp, dev);
  SR_LOG("D3D: CreateDevice -> 0x%08x (behavior=0x%x)", dev, a[4]);
  s->r[0] = 0;
}

void dev_create_texture(CpuState* s, const u32* a, ComObject*) {
  // CreateTexture(w, h, levels, usage, format, pool, ppTexture, pSharedHandle)
  auto* t = new Texture();
  t->width = a[1];
  t->height = a[2];
  t->levels = a[3];
  t->usage = a[4];
  t->format = a[5];
  t->render_target = (a[4] & 0x00000001u) != 0;
  t->dynamic = (a[6] == 1);  // D3DPOOL_DEFAULT
  u32 tex = com_create(kKindTexture9, 22, t);
  if (a[7]) store<u32>(a[7], tex);
  ++g_stats.textures_created;
  if (g_stats.textures_created <= 20) {
    SR_LOG("D3D: CreateTexture %ux%u levels=%u fmt=%u usage=0x%x -> 0x%08x",
           t->width, t->height, t->levels, t->format, t->usage, tex);
  }
  s->r[0] = 0;
}

void dev_create_cube_texture(CpuState* s, const u32* a, ComObject*) {
  auto* t = new Texture();
  t->width = t->height = a[1];
  t->levels = a[2];
  t->format = a[4];
  u32 tex = com_create(kKindCubeTexture9, 22, t);
  if (a[7]) store<u32>(a[7], tex);
  ++g_stats.textures_created;
  s->r[0] = 0;
}

void dev_create_vertex_buffer(CpuState* s, const u32* a, ComObject*) {
  // CreateVertexBuffer(length, usage, fvf, pool, ppVB, pSharedHandle)
  auto* b = new Buffer();
  b->size = a[1];
  b->usage = a[2];
  b->fvf = a[3];
  b->is_index = false;
  u32 vb = com_create(kKindVertexBuffer9, 14, b);
  if (a[5]) store<u32>(a[5], vb);
  ++g_stats.vb_created;
  s->r[0] = 0;
}

void dev_create_index_buffer(CpuState* s, const u32* a, ComObject*) {
  auto* b = new Buffer();
  b->size = a[1];
  b->usage = a[2];
  b->fvf = a[4];  // format: D3DFMT_INDEX16 / INDEX32
  b->is_index = true;
  u32 ib = com_create(kKindIndexBuffer9, 14, b);
  if (a[5]) store<u32>(a[5], ib);
  ++g_stats.ib_created;
  s->r[0] = 0;
}

void dev_create_vertex_shader(CpuState* s, const u32* a, ComObject*) {
  auto* sh = new Shader();
  sh->guest_code = a[1];
  sh->is_pixel = false;
  // The pointer is a compiled D3DX buffer from D3DXCompileShader; look up its GLSL.
  if (const std::string* glsl = find_glsl(a[1])) {
    sh->glsl = *glsl;
    SR_LOGV("D3D: CreateVertexShader from %u bytes of GLSL", u32(glsl->size()));
  }
  u32 h = com_create(kKindVertexShader9, 5, sh);
  if (a[2]) store<u32>(a[2], h);
  ++g_stats.vs_created;
  s->r[0] = 0;
}

void dev_create_pixel_shader(CpuState* s, const u32* a, ComObject*) {
  auto* sh = new Shader();
  sh->guest_code = a[1];
  sh->is_pixel = true;
  if (const std::string* glsl = find_glsl(a[1])) {
    sh->glsl = *glsl;
    SR_LOGV("D3D: CreatePixelShader from %u bytes of GLSL", u32(glsl->size()));
  }
  u32 h = com_create(kKindPixelShader9, 5, sh);
  if (a[2]) store<u32>(a[2], h);
  ++g_stats.ps_created;
  s->r[0] = 0;
}

void dev_create_vertex_shader_ex(CpuState* s, const u32* a, ComObject*) {
  // The _ex variant passes a function table that the runtime is expected to call to compile
  // the shader. We accept the shader and never call back: the null backend does not need it.
  auto* sh = new Shader();
  sh->guest_code = a[1];
  sh->is_pixel = false;
  u32 h = com_create(kKindVertexShader9, 5, sh);
  if (a[2]) store<u32>(a[2], h);
  ++g_stats.vs_created;
  s->r[0] = 0;
}

void dev_create_pixel_shader_ex(CpuState* s, const u32* a, ComObject*) {
  auto* sh = new Shader();
  sh->guest_code = a[1];
  sh->is_pixel = true;
  u32 h = com_create(kKindPixelShader9, 5, sh);
  if (a[2]) store<u32>(a[2], h);
  ++g_stats.ps_created;
  s->r[0] = 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// IDirect3DTexture9 / buffers / shaders: mostly QueryInterface/AddRef/Release plus
// GetLevelDesc / LockRect / UnlockRect, which RenderWare uses to upload texels.
// ---------------------------------------------------------------------------
namespace {

void res_query_interface(CpuState* s, const u32* a, ComObject* self) {
  com_query_interface(s, a, self);
}
void res_addref(CpuState* s, const u32* a, ComObject* self) { com_addref(s, a, self); }
void res_release(CpuState* s, const u32* a, ComObject* self) { com_release(s, a, self); }

void tex_get_level_desc(CpuState* s, const u32* a, ComObject* self) {
  // D3DSURFACE_DESC: Format, Type, Usage, Pool, MultiSampleType, MultiSampleQuality,
  //                  Width, Height
  u32 out = a[2];
  auto* t = self ? static_cast<Texture*>(self->host) : nullptr;
  if (out) {
    store<u32>(out + 0, t ? t->format : 22);
    store<u32>(out + 4, 1);   // D3DRTYPE_TEXTURE
    store<u32>(out + 8, t ? t->usage : 0);
    store<u32>(out + 12, 0);  // D3DPOOL_DEFAULT
    store<u32>(out + 16, 0);
    store<u32>(out + 20, 0);
    store<u32>(out + 24, t ? t->width : 0);
    store<u32>(out + 28, t ? t->height : 0);
  }
  s->r[0] = 0;
}

void tex_get_level_count(CpuState* s, const u32*, ComObject* self) {
  auto* t = self ? static_cast<Texture*>(self->host) : nullptr;
  s->r[0] = t ? t->levels : 1;
}

void tex_lock_rect(CpuState* s, const u32* a, ComObject* self) {
  // LockRect(level, pLockedRect, pRect, flags). We hand back a scratch guest buffer that the
  // backend reads on UnlockRect; that is enough for the null backend and for the GLES upload
  // path (which copies from it).
  auto* t = self ? static_cast<Texture*>(self->host) : nullptr;
  u32 out = a[2];
  u32 bytes = t ? t->width * t->height * 4 : 0x1000;
  if (bytes > 16u * 1024 * 1024) bytes = 16u * 1024 * 1024;
  u32 buf = gmem().heap_alloc(bytes ? bytes : 0x1000);
  if (out) {
    store<u32>(out + 0, u32(t ? t->width * 4 : 256));  // Pitch
    store<u32>(out + 4, buf);                          // pBits
  }
  s->r[0] = 0;
}

void tex_unlock_rect(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void tex_add_dirty_rect(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }

void tex_get_surface_level(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void tex_get_level_desc_plain(CpuState* s, const u32* a, ComObject* self) {
  tex_get_level_desc(s, a, self);
}

void buf_lock(CpuState* s, const u32* a, ComObject* self) {
  // Lock(offset, size, ppbData, flags)
  auto* b = self ? static_cast<Buffer*>(self->host) : nullptr;
  u32 out = a[3];
  u32 size = b ? b->size : 0x1000;
  u32 buf = gmem().heap_alloc(size ? size : 0x1000);
  if (b) b->guest_data = buf;
  if (out) store<u32>(out, buf);
  s->r[0] = 0;
}

void buf_unlock(CpuState* s, const u32*, ComObject*) { s->r[0] = 0; }
void buf_get_desc(CpuState* s, const u32* a, ComObject* self) {
  auto* b = self ? static_cast<Buffer*>(self->host) : nullptr;
  u32 out = a[1];
  if (out) {
    __builtin_memset(gmem().base() + out, 0, 40);
    store<u32>(out + 0, b ? b->size : 0);   // Format (index buffers) / FVF (vertex buffers)
    store<u32>(out + 4, 1);                 // Type
    store<u32>(out + 8, b ? b->usage : 0);
    store<u32>(out + 12, 0);                // Pool
    store<u32>(out + 16, b ? b->size : 0);  // Size
  }
  s->r[0] = 0;
}

void shader_get_function(CpuState* s, const u32* a, ComObject* self) {
  auto* sh = self ? static_cast<Shader*>(self->host) : nullptr;
  if (a[1]) store<u32>(a[1], sh ? sh->guest_code : 0);
  s->r[0] = 0;
}

// IDirect3DTexture9 has 22 methods; the ones RenderWare uses are GetLevelCount, GetLevelDesc,
// LockRect/UnlockRect (texture upload) and GetSurfaceLevel.
const ComHandler kTexture9[] = {
    res_query_interface, res_addref, res_release,        // 0-2
    nullptr,                                             // 3  GetDevice
    nullptr, nullptr, nullptr,                           // 4-6  private data
    nullptr, nullptr,                                    // 7-8  priority
    nullptr,                                             // 9  PreLoad
    nullptr,                                             // 10 GetType
    nullptr, nullptr,                                    // 11-12 LOD
    tex_get_level_count,                                 // 13 GetLevelCount
    nullptr, nullptr,                                    // 14-15 auto-gen filter
    nullptr,                                             // 16 GenerateMipSubLevels
    tex_get_level_desc,                                  // 17 GetLevelDesc
    tex_get_surface_level,                               // 18 GetSurfaceLevel
    tex_lock_rect, tex_unlock_rect,                      // 19-20
    tex_add_dirty_rect,                                  // 21 AddDirtyRect
};

// IDirect3DVertexBuffer9 / IDirect3DIndexBuffer9 have 14 methods with an identical layout.
const ComHandler kBuffer9[] = {
    res_query_interface, res_addref, res_release,        // 0-2
    nullptr,                                             // 3  GetDevice
    nullptr, nullptr, nullptr,                           // 4-6  private data
    nullptr, nullptr,                                    // 7-8  priority
    nullptr,                                             // 9  PreLoad
    nullptr,                                             // 10 GetType
    buf_lock, buf_unlock,                                // 11-12
    buf_get_desc,                                        // 13 GetDesc
};

// IDirect3DVertexShader9 / IDirect3DPixelShader9 have 5 methods.
const ComHandler kShader9[] = {
    res_query_interface, res_addref, res_release,        // 0-2
    nullptr,                                             // 3  GetDevice
    shader_get_function,                                 // 4  GetFunction
};

}  // namespace

bool init() {
  if (!com_init()) return false;
  com_set_handlers(kKindD3D9, kD3D9, sizeof(kD3D9) / sizeof(kD3D9[0]));
  com_set_handlers(kKindDevice9, kDevice9, sizeof(kDevice9) / sizeof(kDevice9[0]));
  com_set_handlers(kKindTexture9, kTexture9, sizeof(kTexture9) / sizeof(kTexture9[0]));
  com_set_handlers(kKindCubeTexture9, kTexture9, sizeof(kTexture9) / sizeof(kTexture9[0]));
  com_set_handlers(kKindVertexBuffer9, kBuffer9, sizeof(kBuffer9) / sizeof(kBuffer9[0]));
  com_set_handlers(kKindIndexBuffer9, kBuffer9, sizeof(kBuffer9) / sizeof(kBuffer9[0]));
  com_set_handlers(kKindVertexShader9, kShader9, sizeof(kShader9) / sizeof(kShader9[0]));
  com_set_handlers(kKindPixelShader9, kShader9, sizeof(kShader9) / sizeof(kShader9[0]));
  SR_LOG("D3D: shim initialised (null backend, vs/ps 3.0 advertised)");
  return true;
}

void shutdown() {
  report_stats();
}

u32 create_d3d9() {
  if (g_d3d9_object) return g_d3d9_object;
  g_d3d9_object = com_create(kKindD3D9, 17, nullptr);
  SR_LOG("D3D: Direct3DCreate9 -> 0x%08x", g_d3d9_object);
  return g_d3d9_object;
}

}  // namespace sr::d3d

