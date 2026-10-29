# SporeRecomp — what a symbol the linker complains about actually means

The link step is where a 102,913-function lift finally has to agree with the runtime. These are
the failure modes seen so far and what each one indicates.

## `undefined reference to sr::g_functions` / `sr::g_function_count`

The generated dispatch table (`recomp/gen/table.cpp`) was not compiled or not linked. Check:

* `build.sh` includes `recomp/gen/table.cpp` in its source list (it does: `GEN_FILES` globs both
  `funcs_*.cpp` and `table.cpp`);
* `tools/lift.py` wrote the file — it only does so at the very end of a successful pass.

This is a *build configuration* failure, not a code failure: the table is generated, not written.

## `undefined reference to sr::shim::resolve_import`

`pe.cpp` calls the resolver through a function pointer; `shim.cpp` must define it. It is a thin
adapter over `imports::find`, because the real dispatch happens through guest stub addresses, not
host pointers.

## `undefined reference to sub_00XXXXXX`

A lifted function calls a function that was never emitted. `tools/check_imports.py` cannot see
this (it only covers imports), but `prelink.sh` can:

```bash
grep -ho 'sub_[0-9a-f]\{8\}(s)' recomp/gen/funcs_*.cpp | sed 's/(s)//' | sort -u > /tmp/calls
grep -ho '^void sub_[0-9a-f]\{8\}' recomp/gen/funcs_*.cpp | sed 's/^void //' | sort -u > /tmp/defs
comm -23 /tmp/calls /tmp/defs        # must be empty
```

If it is not empty, the census produced a call target that is not a function start — a lifter bug
worth fixing rather than papering over.

## `multiple definition of sub_00XXXXXX`

Two chunks emit the same function. That means the census assigned one address to two functions,
which would also mean the *wrong* function runs at runtime. Fix the census, never the generated
output.

## Warnings worth reading

* `used but never defined` for a `ComHandler` — a D3D method was put in a vtable without an
  implementation. The COM dispatcher then returns S_OK with a zero result, which is usually fine
  for query-style methods but wrong for resource creation. Worth fixing as they appear.
* `narrowing conversion` in `imports_table.cpp` — an argument count does not fit its field. The
  field is `uint16_t` now, so this indicates a bogus inferred arity: check `imports_sig.py`.
