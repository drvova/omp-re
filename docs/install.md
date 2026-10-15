# Install

## rizin

omp-re **does not ship rizin**. It spawns whatever `rizin` is on your `PATH`
(or the binary `OMPRE_RIZIN_PATH` points at) and talks to it over its `-q0`
pipe protocol, using only stock commands (`aaa`, `aflj`, `afij`, `pdfj`,
`axtj`, `afvlj`, `afs`, `CC`, `%v`, …). That keeps rizin under your control:
your package manager updates it (rizin parses hostile files, so security
fixes matter), the plugins you already installed keep working, and the plugin
stays small and platform-independent.

It is tested against **rizin 0.9.1**, the latest release; older releases are
untested. Prefer your OS package manager or an official release build; build
from source only when neither has a current version.

### macOS

```bash
brew install rizin
```

### Linux

Arch (`pacman -S rizin`) and Fedora (`dnf install rizin`) package it.
Ubuntu 24.04's apt has **no** rizin package; use a release build from
[rizin's GitHub releases](https://github.com/rizinorg/rizin/releases). As a
last resort, build it from source (Meson + Ninja, a few minutes on 4 cores):

```bash
git clone --depth 1 --branch v0.9.1 https://github.com/rizinorg/rizin.git
cd rizin
meson setup build --buildtype=release
ninja -C build
sudo ninja -C build install
```

If you install to a non-default prefix (e.g. `--prefix=/opt/rizin`), either
put `<prefix>/bin` on `PATH` or point omp-re at the binary with
`OMPRE_RIZIN_PATH=/opt/rizin/bin/rizin`.

### Windows

Use the installer from the releases page; set `OMPRE_RIZIN_PATH` if
`rizin.exe` is not on `PATH`.

### Verify

```bash
rizin -v
```

## Decompiler plugins (optional, strongly recommended)

rizin itself has no decompiler. Without a plugin, `decompile_function` and
the code viewer's `d` key return annotated disassembly whose output begins
`(disassembly only — no decompiler plugin available) `, so it is never
mistaken for decompiled code. omp-re probes for, in order:

| Plugin | Command | Notes |
| --- | --- | --- |
| [rz-ghidra](https://github.com/rizinorg/rz-ghidra) | `pdg` | Ghidra's decompiler as a rizin plugin. Preferred. |
| [jsdec](https://github.com/rizinorg/jsdec) | `pdd` | Lighter JavaScript-based decompiler; used when rz-ghidra is absent. |

Set `OMPRE_DECOMPILER` to a comma-separated list of decompiler commands to
change the order or add another plugin's command (`OMPRE_DECOMPILER=pdd` to
prefer jsdec; `OMPRE_DECOMPILER=mydec` for a plugin omp-re doesn't know).
`pdg` and `pdd` stay as a fallback, and `/re status` reports what it found.

Build rz-ghidra against the rizin you installed (its tag tracks rizin's minor
version; v0.9.0 builds against rizin 0.9.1):

```bash
git clone --depth 1 --branch v0.9.0 --recurse-submodules --shallow-submodules https://github.com/rizinorg/rz-ghidra.git
cd rz-ghidra
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$(rizin -H RZ_PREFIX)" \
  -DBUILD_CUTTER_PLUGIN=OFF -DBUILD_SLEIGH_PLUGIN=OFF
cmake --build build -j
sudo cmake --install build
```

The plugin lands in `rizin -H RZ_LIB_PLUGINS`. To install for your user only,
copy `core_ghidra.so` and the `rz_ghidra_sleigh/` directory into
`rizin -H RZ_USER_PLUGINS` instead.

### Verify

```bash
rizin -qc 'aaa; pdg @ main' /bin/ls
```

Expected shape: a typed C function such as `int main(int argc, char **argv)
{ ... }`. An error like `Error while executing command: pdg` means the
plugin isn't loaded. Inside omp, `/re status` reports the decompiler omp-re
found.

## Dynamic analysis (the debugger, opt-in)

`rizin_debug` runs the sample under rizin's debugger. Because that executes
the binary, it is **off by default**: set `OMPRE_ENABLE_DEBUGGER=1` before
starting omp to register it. rizin's debugger uses `ptrace`, so it needs a
host that permits it (most Linux; a container must be started with it
allowed). Only ever enable this inside a disposable VM or container — see
[`SECURITY.md`](../SECURITY.md#rizin_debug). `OMPRE_DEBUG_TIMEOUT_MS` (default
60000) bounds a single continue/step.

## Optional triage binaries

Each is independently probed on PATH when the plugin loads, and its tool is
simply not registered if the binary is absent — no configuration needed
either way.

| Binary | Tool | Install |
| --- | --- | --- |
| `capa` | `triage_capa` | See [capa's releases](https://github.com/mandiant/capa/releases). |
| `floss` | `triage_floss` | See [FLOSS's releases](https://github.com/mandiant/flare-floss/releases). |
| `diec` | `triage_die` | See [Detect It Easy's releases](https://github.com/horsicq/Detect-It-Easy/releases) — the CLI binary is named `diec`, not `die`. |
| `yara` | `triage_yara` | `apt install yara` / `brew install yara`. No default ruleset ships; `triage_yara` requires an explicit `rules_path`. |

## Installing omp-re itself

```bash
omp plugin marketplace add drvova/omp-re
omp plugin install omp-re@drvova
```

See the [README](../README.md#install) for the dev-load alternative and the
marketplace-name-vs-GitHub-owner distinction.

## Upgrading from 0.1.x

0.1.x used the radare2 backend; 0.2.0 onward uses rizin exclusively. If you are
upgrading: install rizin (above), rename `OMPRE_R2_PATH` → `OMPRE_RIZIN_PATH`
and `OMPRE_R2_ANALYSIS_TIMEOUT_MS` → `OMPRE_ANALYSIS_TIMEOUT_MS`, and install a
rizin decompiler plugin (rz-ghidra or jsdec). Evidence and annotations recorded
by 0.1.x sessions are preserved and replayed into rizin on resume; any rizin
rejects are listed in a warning rather than silently dropped.

## Verify the full stack

```bash
rizin -v                                # rizin present
rizin -qc 'aaa; pdg @ main' /bin/ls     # rz-ghidra producing typed C
omp plugin list                         # omp-re installed
```

Then inside omp: `/re open /bin/ls`, `/re status`, `alt+g`, open `main`,
press `d`. If the decompiled view's title reads `decompile` (not
`decompile (disassembly only)`), the full stack is working.
