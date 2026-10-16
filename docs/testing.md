# Testing

Three tiers: `bun test` (unit + rizin integration), `bash test/tui.sh` (fast
TUI smoke), `bash test/tui-qa.sh` (full tmux QA). Run from the repo root after
`bun install --ignore-scripts`.

## Unit and integration tests — `bun test`

```bash
bun install --ignore-scripts
bun test
```

Sixteen test files. The `bun install` dev dependencies pin omp **18.11.1**,
so the host APIs under test are the ones users run. Tests that need a real
`rizin` and a test binary **skip** (not fail) when either is missing:

| File | Needs rizin? | Tests (rizin present) |
| --- | --- | --- |
| `rizin-pure.test.ts` | No | 28 |
| `runtime.test.ts` | Its lifecycle tests (the record tests run without) | 5 |
| `app.test.ts` | No | 3 |
| `preserve.test.ts` | No | 5 |
| `format.test.ts` | No | 10 |
| `evidence.test.ts` | No | 4 |
| `audit.test.ts` | No | 5 |
| `report.test.ts` | No | 4 |
| `decompile.test.ts` | No | 5 |
| `extension-sdk.test.ts` | Only its rizin tests | 8 |
| `rizin-integration.test.ts` | Yes (one test runs without) | 13 |
| `tools-registry.test.ts` | Yes (the renderer and native-view tests run without) | 35 |
| `tools-mutate-registry.test.ts` | Yes | 15 |
| `rizin-cli.test.ts` | Its catalog and tool tests (policy and help search run without) | 24 |
| `rzcli.test.ts` | Its integration tests (the flag-policy tests run without) | 11 |
| `debug.test.ts` | Its integration tests (the enable-gate tests run without) | 9 |
| **Total** | | **184** |

`extension-sdk.test.ts` loads `extensions/re` through omp's real SDK and
extension runner (no model is called) and drives `/re` commands and tools
the way a session does. It is the suite that catches host API drift: omp 18
changed `getAllTools()` to return tool objects, which broke `/re on` while
every stub-based test stayed green. It runs in CI.

**The default fixture is `/bin/ls`**, which exists on every Linux host and on
macOS, so the integration suites need nothing but rizin. Point them at
another binary with `OMPRE_TEST_BINARY=/path/to/binary`. Ground truth is read
from rizin at runtime, so any ELF or PE with a function named `main`, at
least one call inside it, a PLT-backed import, and a local variable works;
setup fails with a message naming whatever the fixture lacks.

The decompile test follows whatever rizin reports: with rz-ghidra or jsdec
loaded it asserts the decompiler's output, without one it asserts the
labeled `(disassembly only — no decompiler plugin available)` fallback. Both
paths were run for the 0.2.0 release.

The debugger suite (`debug.test.ts`) sets `OMPRE_ENABLE_DEBUGGER` itself and
**executes the fixture** under rizin's debugger; it needs a host where
`ptrace` is permitted (most Linux, and containers started with it allowed).
Its enable-gate tests run everywhere. Two environment constraints the cross-OS
matrix surfaced:

- **macOS**: rizin's debugger can't get `task_for_pid` on a hosted runner (no
  codesigned/entitled rizin, no root), so the live-debug blocks would hang on
  each command until timeout. They are **gated off on macOS** (`process.platform
  === "darwin"`); set `OMPRE_FORCE_DEBUGGER=1` to force them on a host with a
  codesigned rizin. The emulation suite (RzIL VM, no `ptrace`) still runs.
- **Linux**: the attach-by-PID test attaches to a process that is not a child
  of rizin, which `kernel.yama.ptrace_scope=1` (the hosted-runner default)
  forbids. The cross-OS workflow sets `ptrace_scope=0` on the Linux leg so it
  runs for real; on a locked-down box without that, only that one test can't
  attach.

Expected shape with rizin present: **184 pass, 0 fail, 0 skip**. Without
rizin: **102 pass, 98 skip, 0 fail** (200 reported — bun counts skipped
`describe` blocks slightly differently from executed ones). This is CI's
permanent shape, not a degraded state to "fix".

## Fast smoke tier — `bash test/tui.sh`

```bash
bash test/tui.sh
```

A short tmux-driven smoke test against the real TUI. ~30s, 7 PASS, exit 0.
Requires tmux, `omp`, rizin, and a fixture (`OMPRE_TEST_BINARY`; its band
assertions expect a 32-bit PE); not run in CI (see below).

## Full QA tier — `bash test/tui-qa.sh` (`bun run qa:tui`)

```bash
bun run qa:tui
```

A long, comprehensive tmux-driven QA pass against the live TUI — 99
assertions covering every `/re` subcommand, the shortcuts, the evidence
panel, undo, and the audit log. Requires tmux, `omp`, rizin, a fixture, and a
working model (phases G/H/K make model round-trips and degrade to SKIP on an
outage); also not run in CI. Target shape on an otherwise-idle host: **PASS
99 / FAIL 0 / SKIP 0**. This tier drives a real interactive TUI over tmux
with wall-clock timing assumptions, so a host under heavy, unrelated
resource contention (high load average, active swap, competing processes)
can produce cascading, environment-induced failures unrelated to the
plugin's own correctness. The harness has robustness margins for this
(generous retries and backspace/keystroke budgets), but a heavily loaded
host can still flake; re-run on an idle host before treating a failure as
real.

The suite pins its own assertion count as a drift guard (a literal `-eq 99`
near the end of the script): if you add or remove an assertion, update that
literal in the same commit, and give any conditional assertion an explicit
`skip` mirror on every other branch it could take — the guard fails a
healthy run if a branch silently produces a different total than every
other branch.

## What CI actually runs

Two jobs:

- **`check`** — `bun install --ignore-scripts && bun run check` (`tsc
  --noEmit`). Needs nothing beyond Bun.
- **`test`** — `bun install --ignore-scripts && bun test`. Does **not**
  install rizin, so the rizin-dependent suites skip as described above and
  the run exits 0. Never add a malware sample to CI.

Both tmux tiers (`test/tui.sh`, `test/tui-qa.sh`) are **local/self-hosted
only**: both hard-exit 0 when a prerequisite is missing, which would make
them pure theatre on a hosted runner that has neither tmux nor a model.

## Cross-OS coverage — `.github/workflows/cross-os.yml`

The default `test` job is deliberately rizin-free, so the OS-specific paths —
above all the debugger (`debug.test.ts` executes the fixture under rizin's
debugger) and the PE/Mach-O format handling — are never exercised on a hosted
runner. `cross-os.yml` is the tier that does: a **manually dispatched**
(`workflow_dispatch`) matrix over `ubuntu-latest`, `macos-latest`, and
`windows-latest` that installs rizin **v0.9.1** on each (Linux: the portable
static release tarball — there is no `.deb`; macOS: `brew install rizin`;
Windows: the `rizin-windows-shared64` release zip) and runs the full suite.
This is how the plugin gets real Windows/macOS coverage without owning those
machines — CI borrows the runner per dispatch.

Because `/bin/ls` is absent on Windows and SIP-protected against the debugger
on macOS, each OS compiles **`test/fixtures/sample.c`** (a trivial program
with a `main`, locals, a called function, and a string — everything the
integration setups look up) and points `OMPRE_TEST_BINARY` at it. Ground truth
is still read from rizin at runtime. The debugger suite self-enables
`OMPRE_ENABLE_DEBUGGER`, so the workflow does **not** set it globally (that
would break `extension-sdk.test.ts`'s default-off assertion). Never add a
malware sample — the fixture is built on the runner.

The workflow was authored on Linux; its Windows/macOS legs were validated on the
**first dispatch**, which confirmed the install/build scaffolding works on all
three (the per-OS rizin install, `rizin -v` resolving its DLLs on Windows, and
`clang` producing a runnable PE) and surfaced three real cross-OS issues, all
fixed:

- **Windows output paths**: the confined-output logic (`output.ts`) hardcoded a
  `/` separator and rejected the drive-letter colon, so every file-emitting
  capability (dump_memory, trace save/load, export_project, create_signature)
  threw on Windows. Fixed to use `path.sep` and normalize rizin-facing paths to
  forward slashes (`toRizinPath`).
- **Windows line endings**: rizin and the `rz-*` tools emit CRLF on Windows; the
  pipe transport (`rizin.ts`) and `rizin_cli` now normalize `\r\n` → `\n` so
  parsers and exact assertions see the same bytes as on POSIX.
- **Windows test teardown**: a temp dir can't be `rm`'d while the rizin child
  still holds a file open (EBUSY), so cleanups use `rmDirSafe` (Node's
  `maxRetries`/`retryDelay` back-off, a no-op on POSIX).

Known residual: one Windows case (`set_comment` → `/re undo` → final clear) read
back a stale section line instead of an empty comment — a suspected
Windows-pipe-timing desync that doesn't reproduce off Windows; left to confirm
on the next dispatch.

## Loading the extension through omp itself

`test/extension-sdk.test.ts` shows the pattern: `createAgentSession({
additionalExtensionPaths: ["extensions/re"], disableExtensionDiscovery: true,
sessionManager })`, then `initializeExtensions(...)` from
`@oh-my-pi/pi-coding-agent/modes/runtime-init`. Slash commands passed to
`session.prompt("/re …")` and tools fetched with `session.getToolByName(...)`
run locally with no model call. For a full install check, `omp plugin
marketplace add /path/to/checkout` then `omp plugin install omp-re@drvova`
installs from a local checkout.

## Local dev loop

`extensions/re/` changes are picked up by a **fresh `omp` start** if you're
dev-loading via the `extensions:` config entry in
[the README](../README.md#install) — no build step, but also no hot reload;
restart `omp` after an edit. If you installed as a plugin instead, the
cached copy under `~/.omp/plugins/cache/plugins/...` is a **copy, not a
symlink**, so an edit to your checkout does nothing until you reinstall:

```bash
omp plugin upgrade omp-re@drvova
```
