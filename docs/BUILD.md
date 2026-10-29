# SporeRecomp — build notes

## Requirements

* aarch64 cross toolchain: `apt install g++-aarch64-linux-gnu`
* Python 3.10+ with `capstone` (`pip install capstone`)
* For the differential tests: `pip install unicorn`, plus a host build
* For device smoke tests: `apt install qemu-user-static`

## Full build from scratch

```bash
python tools/pe_report.py --out     # docs/pe_report.md
python tools/census.py              # analysis/census/  (the disassembly cache)
python tools/imports.py             # analysis/imports_resolved.json
python tools/lift.py                # recomp/gen/  (215 chunks, ~240 MB of C++)
python tools/gen_import_table.py    # src/rt/imports_table.cpp
./build.sh aarch64                  # build/aarch64/spore
```

`tools/census.py` caches its linear sweep in `analysis/census/sweep.pkl` (176 MB); delete it
to force a re-sweep.

## Incremental

* Runtime sources only: `./check.sh` (syntax-check everything, seconds).
* After touching the lifter: `python tools/lift.py` regenerates all chunks. This takes about
  ten minutes for the full binary and rewrites 240 MB, so iterate with `--limit N` while
  developing.
* After touching the import table: `python tools/gen_import_table.py`, then rebuild.

## Build timings (32-core WSL2 host)

| Step | Time |
|---|---|
| census (cold) | ~14 min |
| lift (full) | ~11 min |
| one generated chunk at `-O2` | ~30-60 s |
| full aarch64 build | ~2 h wall (215 chunks in parallel, memory-bound) |

## Deployment to the device

```bash
ssh root@192.168.1.216 mkdir -p /roms/ports/spore/gamedata
scp build/aarch64/spore       root@192.168.1.216:/roms/ports/spore/
scp -r <game data>            root@192.168.1.216:/roms/ports/spore/gamedata/
ssh root@192.168.1.216 /roms/ports/spore/spore /roms/ports/spore/gamedata
```

The device is muOS 2606 (glibc 2.44, SDL2 2.28, Mali-G31 via `libMali`). Logs go to `log.txt`
in the working directory.

## Why the binary is not one huge translation unit

4 million lifted instructions is ~9 million lines of C++. One file that size makes the
compiler's memory use quadratic in practice and kills any chance of parallel compilation.
Splitting into 250-function chunks also means an incremental rebuild after a lifter fix only
recompiles the chunks that changed.

## Linking notes

The final link should use `-Wl,--gc-sections` once the reachability analysis is in place: a
large part of the lifted code is never called from the boot path, and the device has 1 GB of
RAM and a slow SD card. Until then, everything is kept so that nothing is missing at runtime.
