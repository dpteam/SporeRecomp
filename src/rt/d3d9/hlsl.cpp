// SporeRecomp — HLSL to GLSL ES translator.
//
// Scope: exactly the HLSL that RenderWare's shader generator emits (docs/SHADERS.md). This is a
// rewriter over a regular input, not a general compiler. Design rule: every construct either
// translates exactly or fails with a line number. A shader that renders wrongly is far more
// expensive to debug on the device than one that reports "unsupported".
#include "rt/d3d9/hlsl.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace sr::hlsl {

namespace {

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------
enum class Tk { End, Ident, Number, Punct, String };

struct Token {
  Tk kind = Tk::End;
  std::string text;
  int line = 1;
};

bool is_ident_start(char c) { return std::isalpha(static_cast<unsigned char>(c)) || c == '_'; }
bool is_ident_char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

std::vector<Token> lex(const char* src, std::string& err) {
  std::vector<Token> out;
  int line = 1;
  const char* p = src;
  while (*p) {
    if (*p == '\n') { ++line; ++p; continue; }
    if (std::isspace(static_cast<unsigned char>(*p))) { ++p; continue; }
    // comments
    if (p[0] == '/' && p[1] == '/') {
      while (*p && *p != '\n') ++p;
      continue;
    }
    if (p[0] == '/' && p[1] == '*') {
      p += 2;
      while (*p && !(p[0] == '*' && p[1] == '/')) {
        if (*p == '\n') ++line;
        ++p;
      }
      if (*p) p += 2;
      continue;
    }
    Token t;
    t.line = line;
    if (is_ident_start(*p)) {
      const char* s = p;
      while (is_ident_char(*p)) ++p;
      t.kind = Tk::Ident;
      t.text.assign(s, size_t(p - s));
      out.push_back(t);
      continue;
    }
    if (std::isdigit(static_cast<unsigned char>(*p)) ||
        (*p == '.' && std::isdigit(static_cast<unsigned char>(p[1])))) {
      const char* s = p;
      while (std::isdigit(static_cast<unsigned char>(*p)) || *p == '.') ++p;
      if (*p == 'f' || *p == 'F' || *p == 'h' || *p == 'H') ++p;
      t.kind = Tk::Number;
      t.text.assign(s, size_t(p - s));
      out.push_back(t);
      continue;
    }
    if (*p == '"') {
      ++p;
      const char* s = p;
      while (*p && *p != '"') ++p;
      t.kind = Tk::String;
      t.text.assign(s, size_t(p - s));
      if (*p) ++p;
      out.push_back(t);
      continue;
    }
    // multi-character operators
    static const char* two[] = {"==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=",
                                "*=", "/=", "::"};
    bool matched = false;
    for (const char* op : two) {
      if (p[0] == op[0] && p[1] == op[1]) {
        t.kind = Tk::Punct;
        t.text.assign(op, 2);
        out.push_back(t);
        p += 2;
        matched = true;
        break;
      }
    }
    if (matched) continue;
    t.kind = Tk::Punct;
    t.text = std::string(1, *p);
    out.push_back(t);
    ++p;
  }
  (void)err;
  out.push_back(Token{Tk::End, "", line});
  return out;
}

// ---------------------------------------------------------------------------
// Type and semantic knowledge
// ---------------------------------------------------------------------------
struct TypeInfo {
  const char* hlsl;
  const char* glsl;
  int components;
};

const TypeInfo kTypes[] = {
    {"float", "float", 1},   {"float2", "vec2", 2},  {"float3", "vec3", 3},
    {"float4", "vec4", 4},   {"int", "int", 1},      {"int2", "ivec2", 2},
    {"int3", "ivec3", 3},    {"int4", "ivec4", 4},   {"bool", "bool", 1},
    {"half", "float", 1},    {"half2", "vec2", 2},   {"half3", "vec3", 3},
    {"half4", "vec4", 4},    {"float2x2", "mat2", 4}, {"float3x3", "mat3", 9},
    {"float4x4", "mat4", 16}, {"float4x3", "mat4x3", 12}, {"float3x4", "mat3x4", 12},
};

const TypeInfo* find_type(const std::string& name) {
  for (const auto& t : kTypes) {
    if (name == t.hlsl) return &t;
  }
  return nullptr;
}

// HLSL intrinsic -> GLSL equivalent. Anything not here is reported.
struct IntrinsicMap {
  const char* hlsl;
  const char* glsl;
};

const IntrinsicMap kIntrinsics[] = {
    {"frac", "fract"},
    {"saturate", "saturate"},   // emitted as a helper function
    {"lerp", "mix"},
    {"rsqrt", "inversesqrt"},
    {"atan2", "atan"},
    {"ddx", "dFdx"},
    {"ddy", "dFdy"},
    {"fmod", "mod"},
};

const char* map_intrinsic(const std::string& name) {
  for (const auto& m : kIntrinsics) {
    if (name == m.hlsl) return m.glsl;
  }
  return nullptr;
}

// Semantics that become varyings between the vertex and fragment stage.
struct SemanticInfo {
  const char* hlsl;
  const char* glsl;   // varying name used in both stages
  bool builtin;       // true: gl_Position / gl_PointSize, not a varying
};

const SemanticInfo kSemantics[] = {
    {"POSITION", "v_position", false},
    {"NORMAL", "v_normal", false},
    {"BINORMAL", "v_binormal", false},
    {"TANGENT", "v_tangent", false},
    {"COLOR", "v_color", false},
    {"TEXCOORD", "v_texcoord", false},
    {"BLENDWEIGHT", "v_blendweight", false},
    {"BLENDINDICES", "v_blendindices", false},
    {"PSIZE", "gl_PointSize", true},
    {"FOG", "v_fog", false},
};

// Strips the trailing index from a semantic ("TEXCOORD0" -> ("TEXCOORD", 0)).
std::pair<std::string, int> split_semantic(const std::string& s) {
  size_t i = s.size();
  while (i > 0 && std::isdigit(static_cast<unsigned char>(s[i - 1]))) --i;
  if (i == s.size()) return {s, 0};
  return {s.substr(0, i), std::atoi(s.c_str() + i)};
}

const SemanticInfo* find_semantic(const std::string& name) {
  for (const auto& s : kSemantics) {
    if (name == s.hlsl) return &s;
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Parser / emitter
// ---------------------------------------------------------------------------
struct Field {
  std::string type;
  std::string name;
  std::string semantic;
  int semantic_index = 0;
  std::string register_class;  // "c" or "s" for uniforms/samplers
  int register_index = 0;
};

struct StructDecl {
  std::string name;
  std::vector<Field> fields;
};

struct Uniform {
  Field field;
};

class Translator {
 public:
  Translator(const char* src, bool pixel) : pixel_(pixel) {
    std::string lex_err;
    toks_ = lex(src, lex_err);
  }

  CompileResult run(const std::string& entry) {
    CompileResult r;
    r.is_pixel = pixel_;
    if (!parse_top_level()) return fail(r);
    if (!emit(entry)) return fail(r);
    r.ok = true;
    r.glsl = out_;
    return r;
  }

 private:
  std::vector<Token> toks_;
  size_t pos_ = 0;
  bool pixel_;
  std::vector<StructDecl> structs_;
  std::vector<Field> uniforms_;
  std::vector<Field> samplers_;
  std::string out_;
  std::string error_;
  int error_line_ = 0;
  int indent_ = 0;

  // ---- token helpers ----
  const Token& peek(int n = 0) const {
    size_t i = pos_ + size_t(n);
    return i < toks_.size() ? toks_[i] : toks_.back();
  }
  const Token& next() {
    const Token& t = peek();
    if (pos_ < toks_.size() - 1) ++pos_;
    return t;
  }
  bool at(Tk k, const char* text = nullptr) const {
    if (peek().kind != k) return false;
    return !text || peek().text == text;
  }
  bool accept(const char* text) {
    if (peek().kind == Tk::Punct && peek().text == text) { next(); return true; }
    return false;
  }
  bool expect(const char* text) {
    if (accept(text)) return true;
    set_error(std::string("expected '") + text + "' but found '" + peek().text + "'");
    return false;
  }
  void set_error(const std::string& msg) {
    if (error_.empty()) {
      error_ = msg;
      error_line_ = peek().line;
    }
  }
  CompileResult fail(CompileResult& r) {
    r.ok = false;
    r.error = error_;
    r.line = error_line_;
    return r;
  }

  void line(const std::string& s) {
    for (int i = 0; i < indent_; ++i) out_ += "    ";
    out_ += s;
    out_ += '\n';
  }

  // ---- parsing ----
  bool parse_top_level() {
    while (!at(Tk::End)) {
      if (accept(";")) continue;
      // struct NAME { ... } ;
      if (at(Tk::Ident, "struct")) {
        if (!parse_struct()) return false;
        continue;
      }
      // uniform declaration: TYPE NAME : register(CLASSn) ;
      const TypeInfo* ty = find_type(peek().text);
      if (ty) {
        Field f;
        f.type = next().text;
        if (!at(Tk::Ident)) { set_error("expected a name after the type"); return false; }
        f.name = next().text;
        if (accept(":")) {
          if (!parse_register(f)) return false;
        }
        if (!expect(";")) return false;
        if (f.register_class == "s") {
          samplers_.push_back(f);
        } else {
          uniforms_.push_back(f);
        }
        continue;
      }
      if (at(Tk::Ident, "sampler") || at(Tk::Ident, "sampler2D") || at(Tk::Ident, "samplerCUBE")) {
        Field f;
        f.type = next().text;
        if (!at(Tk::Ident)) { set_error("expected a sampler name"); return false; }
        f.name = next().text;
        if (accept(":")) {
          if (!parse_register(f)) return false;
        }
        if (!expect(";")) return false;
        f.register_class = "s";
        samplers_.push_back(f);
        continue;
      }
      // A function definition is handled by emit(); stop parsing declarations here.
      if (at(Tk::Ident) && peek(1).kind == Tk::Ident && peek(2).text == "(") {
        return true;
      }
      if (at(Tk::Ident, "technique") || at(Tk::Ident, "technique10") ||
          at(Tk::Ident, "pass")) {
        // Techniques are not used by Spore (only plain vs/ps). Skip to the matching brace.
        skip_block();
        continue;
      }
      set_error("unrecognised top-level construct: '" + peek().text + "'");
      return false;
    }
    return true;
  }

  bool parse_register(Field& f) {
    if (!at(Tk::Ident, "register")) { set_error("expected 'register'"); return false; }
    next();
    if (!expect("(")) return false;
    if (!at(Tk::Ident)) { set_error("expected a register class"); return false; }
    std::string reg = next().text;
    if (reg.size() < 2) { set_error("malformed register name"); return false; }
    f.register_class = reg.substr(0, 1);
    f.register_index = std::atoi(reg.c_str() + 1);
    if (!expect(")")) return false;
    return true;
  }

  bool parse_struct() {
    next();  // struct
    if (!at(Tk::Ident)) { set_error("expected a struct name"); return false; }
    StructDecl sd;
    sd.name = next().text;
    if (!expect("{")) return false;
    while (!accept("}")) {
      if (at(Tk::End)) { set_error("unterminated struct"); return false; }
      Field f;
      const TypeInfo* ty = find_type(peek().text);
      if (!ty) {
        // `int4 indices2 : BLENDINDICES1;` and friends are covered; anything else is an error.
        set_error("unsupported field type '" + peek().text + "' in struct " + sd.name);
        return false;
      }
      f.type = next().text;
      if (!at(Tk::Ident)) { set_error("expected a field name"); return false; }
      f.name = next().text;
      if (accept(":")) {
        if (!at(Tk::Ident)) { set_error("expected a semantic"); return false; }
        f.semantic = next().text;
        auto [base, idx] = split_semantic(f.semantic);
        f.semantic = base;
        f.semantic_index = idx;
      }
      if (!expect(";")) return false;
      sd.fields.push_back(f);
    }
    accept(";");
    structs_.push_back(sd);
    return true;
  }

  void skip_block() {
    int depth = 0;
    while (!at(Tk::End)) {
      if (peek().kind == Tk::Punct && peek().text == "{") ++depth;
      if (peek().kind == Tk::Punct && peek().text == "}") {
        --depth;
        next();
        if (depth <= 0) return;
        continue;
      }
      next();
    }
  }

  const StructDecl* find_struct(const std::string& name) const {
    for (const auto& s : structs_) {
      if (s.name == name) return &s;
    }
    return nullptr;
  }

  // ---- emitting ----
  bool emit(const std::string& entry_name) {
    // Version and precision.
    out_ += pixel_ ? "#version 300 es\n" : "#version 300 es\n";
    out_ += "precision highp float;\n";
    out_ += "precision highp int;\n";
    out_ += "precision highp sampler2D;\n";
    out_ += "precision highp samplerCube;\n\n";
    line("// generated by SporeRecomp from RenderWare HLSL");

    // Uniforms.
    if (!uniforms_.empty()) {
      line("// constants");
      for (const auto& u : uniforms_) {
        const TypeInfo* ty = find_type(u.type);
        line(std::string(ty ? ty->glsl : "vec4") + " " + u.name + ";  // " + u.type +
             " register(c" + std::to_string(u.register_index) + ")");
      }
    }
    if (!samplers_.empty()) {
      line("// samplers");
      for (const auto& s : samplers_) {
        const char* t = (s.type == "samplerCUBE") ? "samplerCube" : "sampler2D";
        line(std::string(t) + " " + s.name + ";  // register(s" +
             std::to_string(s.register_index) + ")");
      }
    }
    out_ += '\n';

    // saturate helper (GLSL ES 3.0 has no saturate).
    line("float4 saturate(float4 v) { return clamp(v, 0.0, 1.0); }");
    line("float3 saturate(float3 v) { return clamp(v, 0.0, 1.0); }");
    line("float2 saturate(float2 v) { return clamp(v, 0.0, 1.0); }");
    line("float saturate(float v) { return clamp(v, 0.0, 1.0); }");
    out_ += '\n';

    // Find the entry function: `RET main( PARAM In ) { ... }`
    while (!at(Tk::End)) {
      if (at(Tk::Ident) && peek(1).kind == Tk::Ident && peek(2).text == "(") {
        break;
      }
      next();
    }
    if (at(Tk::End)) { set_error("no entry point found"); return false; }

    std::string ret_type = next().text;
    std::string fn_name = next().text;
    if (fn_name != entry_name && fn_name != "main") {
      set_error("entry point '" + fn_name + "' does not match the requested '" + entry_name +
                "'");
      return false;
    }
    if (!expect("(")) return false;
    std::string param_type;
    if (!at(Tk::Ident, "void")) {
      if (!at(Tk::Ident)) { set_error("expected a parameter type"); return false; }
      param_type = next().text;
      if (at(Tk::Ident)) next();  // parameter name
    }
    if (!expect(")")) return false;
    if (!expect("{")) return false;

    const StructDecl* in_struct = find_struct(param_type);
    const StructDecl* out_struct = find_struct(ret_type);
    if (!in_struct) {
      set_error("input struct '" + param_type + "' was not declared");
      return false;
    }
    if (!out_struct) {
      set_error("output struct '" + ret_type + "' was not declared");
      return false;
    }

    // Declare the varyings. The vertex stage writes them, the fragment stage reads them.
    if (!emit_varyings(*in_struct, *out_struct)) return false;

    // Local variables mirroring the HLSL structs.
    line("void main() {");
    ++indent_;
    // The HLSL entry receives `In`; in GLSL the varyings are globals.
    line(param_type + " In;");
    for (const auto& f : in_struct->fields) {
      const SemanticInfo* sem = find_semantic(f.semantic);
      if (!sem) { set_error("unknown input semantic '" + f.semantic + "'"); return false; }
      std::string varying = std::string(sem->glsl) + "_in" + std::to_string(f.semantic_index);
      const TypeInfo* ty = find_type(f.type);
      if (ty && ty->components > 1) {
        line(f.type + " tmp_" + f.name + " = " + varying + ";");
        line("In." + f.name + " = tmp_" + f.name + ";");
      } else {
        line("In." + f.name + " = " + varying + ";");
      }
    }
    line(ret_type + " Out;");
    line(ret_type + " Current;");

    // The body: translated statement by statement.
    if (!emit_body()) return false;

    // Write the outputs.
    for (const auto& f : out_struct->fields) {
      const SemanticInfo* sem = find_semantic(f.semantic);
      if (!sem) { set_error("unknown output semantic '" + f.semantic + "'"); return false; }
      if (sem->builtin) {
        line(std::string(sem->glsl) + " = Out." + f.name + ";");
      } else {
        line(std::string(sem->glsl) + "_out" + std::to_string(f.semantic_index) + " = Out." +
             f.name + ";");
      }
    }
    --indent_;
    line("}");
    return true;
  }

  bool emit_varyings(const StructDecl& in_s, const StructDecl& out_s) {
    if (!pixel_) {
      // Vertex shader: declare outputs for the semantics the fragment stage will read.
      line("// vertex outputs");
      for (const auto& f : out_s.fields) {
        const SemanticInfo* sem = find_semantic(f.semantic);
        if (!sem) { set_error("unknown semantic '" + f.semantic + "'"); return false; }
        if (sem->builtin) continue;
        const TypeInfo* ty = find_type(f.type);
        line(std::string("out ") + (ty ? ty->glsl : "vec4") + " " + sem->glsl + "_out" +
             std::to_string(f.semantic_index) + ";");
      }
    } else {
      line("// fragment inputs");
      for (const auto& f : in_s.fields) {
        const SemanticInfo* sem = find_semantic(f.semantic);
        if (!sem) { set_error("unknown semantic '" + f.semantic + "'"); return false; }
        const TypeInfo* ty = find_type(f.type);
        line(std::string("in ") + (ty ? ty->glsl : "vec4") + " " + sem->glsl + "_in" +
             std::to_string(f.semantic_index) + ";");
      }
    }
    out_ += '\n';
    return true;
  }

  // Translates statements until the matching closing brace of the entry function.
  bool emit_body() {
    int depth = 1;
    std::string stmt;
    while (!at(Tk::End)) {
      const Token& t = peek();
      if (t.kind == Tk::Punct && t.text == "{") {
        ++depth;
        flush_statement(stmt);
        line("{");
        ++indent_;
        next();
        continue;
      }
      if (t.kind == Tk::Punct && t.text == "}") {
        --depth;
        flush_statement(stmt);
        if (depth == 0) { next(); return true; }
        --indent_;
        line("}");
        next();
        continue;
      }
      if (t.kind == Tk::Punct && t.text == ";") {
        flush_statement(stmt);
        next();
        continue;
      }
      stmt += t.text;
      if (t.kind == Tk::Ident || t.kind == Tk::Number) stmt += ' ';
      next();
    }
    set_error("unterminated function body");
    return false;
  }

  void flush_statement(const std::string& raw) {
    if (raw.empty()) return;
    std::string s = translate_statement(raw);
    line(s + ";");
  }

  // Rewrites one HLSL statement into GLSL.
  std::string translate_statement(const std::string& in) {
    std::string s = in;
    s = rewrite_types(s);
    s = rewrite_intrinsics(s);
    s = rewrite_tex(s);
    s = rewrite_mul(s);
    s = rewrite_swizzle_index(s);
    // Trim trailing spaces before punctuation produced by the tokeniser.
    std::string cleaned;
    for (size_t i = 0; i < s.size(); ++i) {
      if (s[i] == ' ' && i + 1 < s.size() &&
          (s[i + 1] == ';' || s[i + 1] == ',' || s[i + 1] == ')' || s[i + 1] == ']')) {
        continue;
      }
      if (s[i] == ' ' && !cleaned.empty() && (cleaned.back() == '(' || cleaned.back() == '.')) {
        continue;
      }
      cleaned += s[i];
    }
    return cleaned;
  }

  std::string rewrite_types(const std::string& s) {
    std::string out;
    size_t i = 0;
    while (i < s.size()) {
      if (is_ident_start(s[i])) {
        size_t j = i;
        while (j < s.size() && is_ident_char(s[j])) ++j;
        std::string word = s.substr(i, j - i);
        const TypeInfo* ty = find_type(word);
        out += ty ? std::string(ty->glsl) : word;
        i = j;
        continue;
      }
      out += s[i++];
    }
    return out;
  }

  std::string rewrite_intrinsics(const std::string& s) {
    std::string out;
    size_t i = 0;
    while (i < s.size()) {
      if (is_ident_start(s[i])) {
        size_t j = i;
        while (j < s.size() && is_ident_char(s[j])) ++j;
        std::string word = s.substr(i, j - i);
        const char* mapped = map_intrinsic(word);
        out += mapped ? std::string(mapped) : word;
        i = j;
        continue;
      }
      out += s[i++];
    }
    return out;
  }

  // tex2D(s, uv) -> texture(s, uv);  texCUBE(s, dir) -> texture(s, dir)
  std::string rewrite_tex(const std::string& s) {
    std::string out = s;
    for (const char* fn : {"tex2D", "texCUBE", "tex2Dlod", "tex2Dproj"}) {
      size_t p = 0;
      while ((p = out.find(fn, p)) != std::string::npos) {
        out.replace(p, std::strlen(fn), "texture");
        p += 7;
      }
    }
    return out;
  }

  // mul(a, b) -> (a * b) with the correct matrix/vector order for GLSL.
  // HLSL mul(v, M) is row-vector * matrix; GLSL is column-major, so it becomes M * v.
  std::string rewrite_mul(const std::string& s) {
    std::string out = s;
    size_t p = 0;
    while ((p = out.find("mul(", p)) != std::string::npos) {
      // find the matching ')'
      size_t start = p + 4;
      int depth = 1;
      size_t i = start;
      while (i < out.size() && depth > 0) {
        if (out[i] == '(') ++depth;
        else if (out[i] == ')') --depth;
        ++i;
      }
      if (depth != 0) break;
      std::string args = out.substr(start, i - 1 - start);
      // split at the top-level comma
      int d = 0;
      size_t comma = std::string::npos;
      for (size_t k = 0; k < args.size(); ++k) {
        if (args[k] == '(') ++d;
        else if (args[k] == ')') --d;
        else if (args[k] == ',' && d == 0) { comma = k; break; }
      }
      std::string repl;
      if (comma == std::string::npos) {
        repl = "(" + args + ")";
      } else {
        std::string a = args.substr(0, comma);
        std::string b = args.substr(comma + 1);
        // Trim spaces.
        auto trim = [](std::string v) {
          while (!v.empty() && v.front() == ' ') v.erase(v.begin());
          while (!v.empty() && v.back() == ' ') v.pop_back();
          return v;
        };
        a = trim(a);
        b = trim(b);
        // Heuristic: if the second argument looks like a matrix (a name declared as mat),
        // swap so the matrix is on the left, which is GLSL's column-major convention.
        if (is_matrix_name(b)) {
          repl = "(" + b + " * " + a + ")";
        } else if (is_matrix_name(a)) {
          repl = "(" + b + " * " + a + ")";
        } else {
          repl = "(" + a + " * " + b + ")";
        }
      }
      out.replace(p, i - p, repl);
      p += repl.size();
    }
    return out;
  }

  bool is_matrix_name(const std::string& n) const {
    for (const auto& u : uniforms_) {
      const TypeInfo* ty = find_type(u.type);
      if (u.name == n && ty && ty->components >= 4 &&
          (u.type.find('x') != std::string::npos)) {
        return true;
      }
    }
    return false;
  }

  // frameTime[0] -> frameTime.x  (HLSL allows array indexing on vectors)
  std::string rewrite_swizzle_index(const std::string& s) {
    std::string out = s;
    static const char* comps = "xyzw";
    for (size_t i = 0; i + 3 < out.size(); ++i) {
      if (out[i] == '[' && std::isdigit(static_cast<unsigned char>(out[i + 1])) &&
          out[i + 2] == ']') {
        // Find the identifier before the bracket.
        size_t j = i;
        while (j > 0 && (is_ident_char(out[j - 1]) || out[j - 1] == '.')) --j;
        std::string ident = out.substr(j, i - j);
        if (!ident.empty() && is_vector_name(ident)) {
          int idx = out[i + 1] - '0';
          if (idx >= 0 && idx < 4) {
            out.replace(i, 3, std::string(".") + comps[idx]);
            continue;
          }
        }
      }
    }
    return out;
  }

  bool is_vector_name(const std::string& n) const {
    std::string base = n;
    if (base.rfind("In.", 0) == 0 || base.rfind("Out.", 0) == 0 ||
        base.rfind("Current.", 0) == 0) {
      base = base.substr(base.find('.') + 1);
    }
    for (const auto& u : uniforms_) {
      if (u.name == base) return true;
    }
    for (const auto& sd : structs_) {
      for (const auto& f : sd.fields) {
        if (f.name == base) return true;
      }
    }
    return false;
  }
};

}  // namespace

CompileResult translate(const char* source, const char* entry, bool pixel) {
  Translator t(source, pixel);
  return t.run(entry && *entry ? entry : "main");
}

CompileResult compile(const char* source, const char* entry, const char* profile) {
  bool pixel = profile && (profile[0] == 'p');
  CompileResult r = translate(source, entry, pixel);
  if (!r.ok) {
    std::fprintf(stderr, "[hlsl] translate failed at line %d: %s\n", r.line, r.error.c_str());
  }
  return r;
}

}  // namespace sr::hlsl
