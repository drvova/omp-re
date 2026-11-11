# Install

omp-re needs three things it does not ship: **SBCL**, the **cl-ppcre** library,
and **rizin**. Under omp all three are yours to install. Under nodecode the
engine is loaded into nodecode's own Lisp image, so the SBCL steps below do
not apply there; see [`nodecode.md`](nodecode.md#install) for cl-ppcre.

| | Required | Found by |
| --- | --- | --- |
| SBCL | yes (omp), unless you run a prebuilt [engine image](#the-engine-image) | `sbcl` on `PATH`, or `OMPRE_SBCL_PATH` |
| cl-ppcre | yes, with the same exception | ASDF's default places, or (omp) Quicklisp in `~/quicklisp/` |
| rizin (tested with 0.9.1) | yes | `rizin` on `PATH`, or `OMPRE_RIZIN_PATH`, or the common install locations |
| rz-ghidra or jsdec | no | rizin's plugin directory |
| capa, floss, diec, yara | no | `PATH` |

Linux is where this is developed and tested. The Windows and macOS steps below
are what the code looks for, written from the code; the authors had not run
the engine on either system when this was written.

## SBCL and cl-ppcre

The engine is Common Lisp. Under omp the extension runs a saved image of it
when it has one, and builds that image with your SBCL the first time
([The engine image](#the-engine-image)). Where it has none and can build
none, it loads the engine from source:

```
sbcl --noinform --no-sysinit --no-userinit --disable-debugger --load <plugin>/stdio/serve.lisp
```

Building the image starts SBCL the same way, so two things follow for both.
SBCL is started without a shell and
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

(`< NUL` in `cmd.exe`.) It prints `{"ready":3}` and exits when the engine
loaded, or `{"fatal":"…"}` with what to install. Inside omp, a missing SBCL or
cl-ppcre shows as the extension failing to load, with a message that names
what is missing and how to install it.

### The first start compiles, and saves an image

The first omp start after installing or upgrading omp-re compiles the engine
(and cl-ppcre, if it was never compiled) and saves an image of it: about
3.3 s on the machine it was measured on. The compiled files go to ASDF's cache in
your home directory (`~/.cache/common-lisp/` on Linux) and the image to
omp-re's own cache (below); both must be writable for the image to be kept.
Every later start runs the image. The cost of a start is once per omp
process, not per session.

A start is given two minutes. One that takes longer is ended, and the error
says what to check: that the SBCL named answers `--version`, that
`~/quicklisp/setup.lisp` (loaded when it exists, to find cl-ppcre) asks
nothing, and that the cache can be written. Whatever the engine writes to its
standard error, then and later, goes to omp's log as `omp-re engine: …`; the
end of it is quoted in the error when the engine process ends unasked.

### The engine image

SBCL can save a running Lisp as one executable. An image of the engine is
that: SBCL's runtime and the engine, loaded. Started, it is serving omp at
once, and it needs no SBCL, no cl-ppcre and no source beside it. Measured on
one Linux machine with SBCL 2.2.9, from starting the process to its `ready`:

| Start | Time |
| --- | --- |
| the image | 2.4 ms |
| the source, already compiled | 240 ms |
| the source, compiled first | 1.9 s |

Through omp's side, which first hashes the source and asks SBCL its version,
a start from the image took 10 ms. The first start, which compiles and then
saves, took 3.3 s: a second and a half more than loading the source it had
just compiled, paid once for each version.

An image is 48 MB and is not compressed. SBCL can compress one to 11 MB, and
that image took 63 ms to start, on every start, to save disk once.

omp's side looks for an engine in this order, and takes the first that starts
(`extensions/re/image.ts`):

1. **`OMPRE_ENGINE_IMAGE`**, when set: the image at that path, run as it is.
   Nothing checks what it was built from; that is yours to know. If it does
   not start, the extension fails to load and the error names the variable:
   nothing else is tried.
2. **An image shipped with the plugin**:
   `<plugin>/dist/omp-re-engine-<platform>-<arch>`, with `.exe` on Windows.
   `<platform>` and `<arch>` are what Node calls them: `linux`, `darwin` or
   `win32`, and `x64` or `arm64`. The image is asked whether it was built
   from this plugin's source and is passed over when it was not, so one left
   from another version does no harm.
3. **An image built here.** With none of the above, the first start builds
   one with your SBCL from the plugin's source and keeps it in the cache;
   later starts run it. A cached image that does not start is deleted and
   built again.
4. **The source**, as before, when no image could be built (no writable
   cache, a full disk). omp's log says why: `omp-re engine: no engine image
   could be built at … (…); loading the engine from source`.

Nothing in this is fetched from the network.

**The cache** is one directory:

| System | Directory |
| --- | --- |
| Linux | `$XDG_CACHE_HOME/omp-re`, or `~/.cache/omp-re` |
| macOS | `$XDG_CACHE_HOME/omp-re` when that is set, or `~/Library/Caches/omp-re` |
| Windows | `%LOCALAPPDATA%\omp-re\cache` |

`OMPRE_CACHE_DIR` names another. An image there is called
`omp-re-engine-<version>-<platform>-<arch>-<hash>`, the hash being of
everything that makes another image necessary: the plugin's version, the
text of its Lisp source (`engine/`, `stdio/`, the two `.asd` files,
`stdio/protocol.json`), what your `sbcl --version` says, and the system. So
an upgrade of omp-re or of SBCL, or an edit to the engine in a checkout,
builds a new image at the next start. A build keeps the image it made and
the two used most recently beside it, and deletes older ones.

To clear the cache, delete the directory (`rm -r ~/.cache/omp-re`). It is
safe at any time: the next start builds the image again. Do that after
upgrading cl-ppcre, which the hash does not see.

**A prebuilt image.** Each release on GitHub carries images built on a Linux,
a macOS and a Windows runner, named as in step 2. To use one, download the
file for your system from the release of the version you have installed
(`omp plugin list` shows it), make it executable (`chmod +x`), and either

- put it at `<plugin>/dist/` under its own name — an installed plugin is
  under `~/.omp/plugins/cache/plugins/`; an upgrade of the plugin replaces
  that folder, and the image with it; or
- put it anywhere and set `OMPRE_ENGINE_IMAGE` to its path.

With either, omp-re needs neither SBCL nor cl-ppcre. An image is for one
operating system and processor, and holds the C library calls of the SBCL
that built it: a Linux image built on a newer distribution may not start on
an older one. In `dist/` that only costs a line in the log (step 3 follows);
under `OMPRE_ENGINE_IMAGE` it is the error. On macOS a downloaded executable
is quarantined until you clear it (`xattr -d com.apple.quarantine <file>`).

To build an image yourself, from a checkout:

```bash
bun run build:image              # into the cache, where a start looks for it
bun run build:image -- --dist    # dist/omp-re-engine-<platform>-<arch>, as a release ships it
```

The release images come from `.github/workflows/release.yml`, which had not
run when this was written; the image has been built and run on Linux only.

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
sbcl --version                          # SBCL present (not needed with a prebuilt engine image)
rizin -v                                # rizin present
rizin -qc 'aaa; pdg @ main' /bin/ls     # rz-ghidra producing typed C
omp plugin list                         # omp-re installed
```

Then inside omp: `/re status` (it answers only if the engine started, and says
which rizin and decompiler it found), `/re open /bin/ls`, `alt+g`, open `main`,
press `d`. If the decompiled view's title reads `decompile` (not
`decompile (disassembly only)`), the full stack is working.
