# Install

omp-re needs three things it does not ship: **SBCL**, the **cl-ppcre** library,
and **rizin**. Under omp all three are yours to install. Under nodecode the
engine is loaded into nodecode's own Lisp image, so the SBCL steps below do
not apply there; see [`nodecode.md`](nodecode.md#install) for cl-ppcre.

| | Required | Found by |
| --- | --- | --- |
| SBCL | yes (omp) | `sbcl` on `PATH`, or `OMPRE_SBCL_PATH` |
| cl-ppcre | yes | ASDF's default places, or (omp) Quicklisp in `~/quicklisp/` |
| rizin (tested with 0.9.1) | yes | `rizin` on `PATH`, or `OMPRE_RIZIN_PATH`, or the common install locations |
| rz-ghidra or jsdec | no | rizin's plugin directory |
| capa, floss, diec, yara | no | `PATH` |

Linux is where this is developed and tested. The Windows and macOS steps below
are what the code looks for, written from the code; the authors had not run
the engine on either system when this was written.

## SBCL and cl-ppcre

The engine is Common Lisp. Under omp the extension starts it as

```
sbcl --noinform --no-sysinit --no-userinit --disable-debugger --load <plugin>/stdio/serve.lisp
```

Two things follow from that command line. SBCL is started without a shell and
by the name `sbcl`, so it must be on the `PATH` omp was started with — or set
`OMPRE_SBCL_PATH` to the executable. And `--no-userinit` means your
`~/.sbclrc` is **not** read, so a library path or a Quicklisp location that
only `~/.sbclrc` sets up is not seen. cl-ppcre is looked for in exactly these
places:

1. wherever ASDF looks by default: the system's Common Lisp source directory
   (`/usr/share/common-lisp/source/` on Debian and Ubuntu, which is where the
   `cl-ppcre` package installs), `~/common-lisp/`, and
   `~/.local/share/common-lisp/source/`, plus anything your ASDF configuration
   files or `CL_SOURCE_REGISTRY` add;
2. Quicklisp, when `~/quicklisp/setup.lisp` exists. It is loaded for this, so
   a cl-ppcre that Quicklisp has already installed is found. Nothing is
   downloaded at start: run `(ql:quickload "cl-ppcre")` once yourself.

### Debian, Ubuntu

```bash
sudo apt install sbcl cl-ppcre
```

This is what CI and the authors use.

### Other Linux distributions

Install `sbcl` with your package manager. If it has no cl-ppcre package, use
one of the two ways under macOS.

### macOS

```bash
brew install sbcl
```

Then cl-ppcre, either through Quicklisp:

```bash
curl -O https://beta.quicklisp.org/quicklisp.lisp
sbcl --non-interactive --load quicklisp.lisp \
     --eval '(quicklisp-quickstart:install)' \
     --eval '(ql:quickload "cl-ppcre")'
```

(that installs Quicklisp to `~/quicklisp/`, the one location omp-re checks), or
as a plain checkout where ASDF looks:

```bash
git clone --depth 1 https://github.com/edicl/cl-ppcre ~/common-lisp/cl-ppcre
```

A desktop launch of omp may not have Homebrew's directory on its `PATH`. rizin
is looked for in the usual install locations as well; **SBCL is not**. If omp
says SBCL was not found although `sbcl` works in your terminal, set
`OMPRE_SBCL_PATH="$(which sbcl)"`.

### Windows

Install SBCL with the installer from [sbcl.org](https://www.sbcl.org/platform-table.html)
(or `choco install sbcl`), and make sure `sbcl.exe` is on `PATH` or set
`OMPRE_SBCL_PATH` to its full path. Name the executable itself: the engine is
started without a shell, so a `.cmd` or `.bat` wrapper cannot be run and is
reported as SBCL not found. Then put cl-ppcre under your user
directory, where ASDF looks:

```powershell
git clone --depth 1 https://github.com/edicl/cl-ppcre "$HOME\common-lisp\cl-ppcre"
```

That is what the Windows leg of this repository's CI does. Quicklisp installed
to `%USERPROFILE%\quicklisp\` works too.

### Verify

From a checkout of this repository:

```bash
sbcl --noinform --no-sysinit --no-userinit --disable-debugger --load stdio/serve.lisp < /dev/null
```

(`< NUL` in `cmd.exe`.) It prints `{"ready":1}` and exits when the engine
loaded, or `{"fatal":"…"}` with what to install. Inside omp, a missing SBCL or
cl-ppcre shows as the extension failing to load, with a message that names
what is missing and how to install it.

### The first start compiles

The first omp start after installing or upgrading omp-re compiles the engine
(and cl-ppcre, if it was never compiled): a few seconds — about 3 s on the
machine it was measured on. The compiled files go to ASDF's cache in your home
directory (`~/.cache/common-lisp/` on Linux), and later starts take a fraction
of a second. That cache must be writable. The cost is once per omp process,
not per session.

A start is given two minutes. One that takes longer is ended, and the error
says what to check: that the SBCL named answers `--version`, that
`~/quicklisp/setup.lisp` (loaded when it exists, to find cl-ppcre) asks
nothing, and that the cache can be written. Whatever the engine writes to its
standard error, then and later, goes to omp's log as `omp-re engine: …`; the
end of it is quoted in the error when the engine process ends unasked.

## rizin

omp-re **does not ship rizin**. It spawns whatever `rizin` is on your `PATH`
(or the binary `OMPRE_RIZIN_PATH` points at) and talks to it over its `-q0`
pipe protocol, using only stock commands (`aaa`, `aflj`, `afij`, `pdfj`,
`axtj`, `afvlj`, `afs`, `CC`, `%v`, …). That keeps rizin under your control:
your package manager updates it (rizin parses hostile files, so security
fixes matter), the plugins you already installed keep working, and the plugin
stays small and platform-independent.

It is tested against **rizin 0.9.1**; older releases are untested. Prefer your OS package manager or an official release build; build
from source only when neither has a current version.

### macOS

```bash
brew install rizin
```

### Linux

Arch (`pacman -S rizin`) and Fedora (`dnf install rizin`) package it.
Ubuntu 24.04's apt has **no** rizin package. The portable static build on
[rizin's GitHub releases](https://github.com/rizinorg/rizin/releases)
(`rizin-v0.9.1-static-x86_64.tar.xz`) runs omp-re's tools, but **it cannot
load plugins** — it is a fully static executable with no shared `librz` to
load a `.so` into — so it can never use rz-ghidra, and decompilation falls back
to labeled disassembly. For a decompiler, build rizin from source instead.

`scripts/install-rizin.sh` does both builds below — rizin as shared libraries,
then rz-ghidra against it — in one step (about 6 minutes on 4 cores). It
is idempotent, exiting at once when the right versions are already installed,
so it also works as a container setup script or a session start hook:

```bash
scripts/install-rizin.sh                   # into /usr/local (sudo if needed)
PREFIX=$HOME/.local scripts/install-rizin.sh
INSTALL_DEPS=1 scripts/install-rizin.sh    # apt-get the build tools first
```

By hand, build rizin from source (Meson + Ninja, a few minutes on 4 cores):

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

### If omp-re "loads but can't find rizin"

A desktop/GUI launch of omp often starts with a minimal `PATH` that omits
`/opt/homebrew/bin`, `/usr/local/bin`, etc. — so `rizin` works in your
terminal but omp-re's lookup can't see it. omp-re handles the common case by
also checking the usual install locations (Homebrew, `/usr/local/bin`,
`/usr/bin`, `/opt/rizin/bin`, `/snap/bin`, `~/.local/bin`; `C:\Program Files\rizin\bin`
on Windows). If your rizin is anywhere else, set `OMPRE_RIZIN_PATH` to its full
path — on macOS/Linux, the output of `which rizin` in your shell:

```bash
OMPRE_RIZIN_PATH="$(which rizin)"   # e.g. in ~/.omp/agent/config.yml env, or your shell profile
```

## Decompiler plugins (optional, strongly recommended)

rizin itself has no decompiler. Without a plugin, `pdg`/`pdd` (via
`rizin_command`) error and the code viewer's `d` key falls back to annotated
disassembly (`pdf`), so it is never mistaken for decompiled code. omp-re probes
for, in order:

| Plugin | Command | Notes |
| --- | --- | --- |
| [rz-ghidra](https://github.com/rizinorg/rz-ghidra) | `pdg` | Ghidra's decompiler as a rizin plugin. Preferred. |
| [jsdec](https://github.com/rizinorg/jsdec) | `pdd` | Lighter JavaScript-based decompiler; used when rz-ghidra is absent. |

Set `OMPRE_DECOMPILER` to a comma-separated list of decompiler commands to
change the order or add another plugin's command (`OMPRE_DECOMPILER=pdd` to
prefer jsdec; `OMPRE_DECOMPILER=mydec` for a plugin omp-re doesn't know).
`pdg` and `pdd` stay as a fallback, and `/re status` reports what it found.

Build rz-ghidra against the rizin you installed (its tag tracks rizin's minor
version; v0.9.0 builds against rizin 0.9.1). It needs a shared rizin — a
package, or the source build above, not the static release build.
`scripts/install-rizin.sh` runs these steps for you:

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

Each is independently probed on PATH when a session starts, and its tool is
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

Update an installed copy to the latest published version. `omp plugin upgrade`
reinstalls from a **local cache** of the marketplace catalog, so refresh that
cache first — otherwise the upgrade reinstalls the version you already have and
appears to do nothing:

```bash
omp plugin marketplace update drvova   # re-fetch the drvova catalog (omit the name to refresh all)
omp plugin upgrade omp-re@drvova       # `omp plugin list` shows the installed version
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
sbcl --version                          # SBCL present
rizin -v                                # rizin present
rizin -qc 'aaa; pdg @ main' /bin/ls     # rz-ghidra producing typed C
omp plugin list                         # omp-re installed
```

Then inside omp: `/re status` (it answers only if the engine started, and says
which rizin and decompiler it found), `/re open /bin/ls`, `alt+g`, open `main`,
press `d`. If the decompiled view's title reads `decompile` (not
`decompile (disassembly only)`), the full stack is working.
