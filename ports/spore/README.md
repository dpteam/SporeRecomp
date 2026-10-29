# Spore — RG 35 XX H / muOS port

A **native static binary recompilation** of Spore (SporeApp.exe, Galactic Adventures) for
ARM64 Linux handhelds. Not an emulator, not Wine, not a reimplementation: the game's own
x86 code is translated to native aarch64 C++ and runs directly, with a native replacement for
Windows, Direct3D 9, DirectInput and DirectSound.

---

## Installation

Copy to your SD card (either the `ROMS` partition or the port data partition):

```text
/roms/ports/
├── spore.sh                    <- launcher
└── spore/                      <- port folder
    ├── spore                   <- the binary
    ├── spore.cfg               <- settings (optional)
    ├── spore.gptk              <- gamepad profile
    ├── port.json               <- PortMaster metadata
    └── gamedata/               <- YOUR PC GAME FILES GO HERE
        ├── SporeApp.exe
        └── Data/               <- Spore_*.package, PatchData.package
```

> [!IMPORTANT]
> **No copyrighted game assets are bundled.** You need your own legitimate retail PC copy
> of Spore. Copy `SporeApp.exe` and the whole `Data/` folder from the installation.
>
> The recompilation was lifted from the **24,895,528-byte** `SporeApp.exe` (the Galactic
> Adventures release, unpacked). Other builds load, but the log will report where they
> diverge.

On muOS the card is mounted at `/mnt/mmc`, so the same layout appears as
`/mnt/mmc/ports/spore/`. The launcher checks both, plus the union mount muOS uses for
PortMaster data.

---

## Status

**Work in progress — this port does not render yet.** What works:

* the whole executable is recompiled: 4,747,729 instructions into 102,913 native functions,
  with **zero** unhandled instructions
* the PE is loaded, imports bound, CRT startup runs, the game reaches its own `WinMain`
* the Direct3D 9 object model is in place (device, textures, buffers, shaders) as a
  **null backend**: it answers every call and records what the game asks for, but draws nothing
* Win32, the VS2008 CRT, the registry, threads, file I/O and SEH are implemented

`log.txt` is written every run and says exactly how far the guest got. That log is the most
useful thing you can send back.

---

## Controls

Currently keyboard-only (see `spore.gptk`). Direct gamepad support arrives with the input
layer.

| Button | Key |
|:---|:---|
| **A** | Space |
| **B** | Enter |
| **X** | Escape |
| **Y** | Tab |
| **D-Pad** | Arrow keys |
| **L1 / R1** | Q / E |
| **Start** | Enter |
| **Select + Start** | Quit to the system menu |

---

## Settings (`spore.cfg`)

| Setting | Effect |
|---|---|
| `SPORE_VERBOSE=1` | log every guest import call (noisy; use when something is wrong) |
| `SPORE_TRACE=1` | log the first call of every import |
| `SPORE_RENDER=854x480` | exact render size |
| `SPORE_SCREEN=640x480` | panel size, only if detection is wrong |
| `SPORE_RENDER_SCALE=0.75` | render below the panel resolution and upscale |
| `SPORE_ROTATE=90` | panel mounted rotated |

---

## Troubleshooting

* **"port folder was not found"** — the launcher could not find `spore/` next to the script.
  Check that the folder is named `spore` (lowercase) and contains the `spore` binary.
* **"SporeApp.exe not found"** — the game data is missing. See Installation.
* **"SporeApp.exe is N bytes"** — you have a different build than the one this was lifted
  from. It may still work; check `log.txt`.
* **It exits immediately** — read `log.txt`. The last line names the subsystem that stopped
  it. The previous run's log is kept as `log.prev.txt`.

---

## How it works

```
tools/census.py    decode 16.5 MB of x86, recover 108,528 function bodies
tools/lift.py      emit 4.7M instructions as C++ (412 translation units)
tools/imports.py   infer calling conventions from the guest's own call sites
src/rt/            native runtime: memory, CPU state, PE loader, Win32/D3D9 shims
```

The recompiled code keeps the guest's own stack layout, calling conventions and exception
chain, so the game's logic — asset loading, simulation, UI — runs unmodified. Only the
platform underneath it is new.
