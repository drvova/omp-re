# Testing

Three tiers: `bun test` (unit + rizin integration), `bash test/tui.sh` (fast
TUI smoke), `bash test/tui-qa.sh` (full tmux QA), plus `bash test/tui-carry.sh`
(the carry and findings loop end to end). Run from the repo root after
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

## Carry / findings e2e — `bash test/tui-carry.sh` (`bun run test:tui:carry`)

```bash
bun run test:tui:carry
```

Drives `/re carry --inherit` in a real omp TUI. It is self-contained: it
compiles two builds of `test/fixtures/sample.c`, records three findings on v1
with `test/e2e/make-carry-manifest.ts` (real rizin evidence and the real
`record_finding` tool, with a stand-in auditor so no model is needed), then
starts `omp -e extensions/re --binary v2` and types the slash commands. It
checks the carry statuses (hold, relocated, drifted), the agenda placed in the
editor with the checksum diff, the status band and `/re status` counting the
inherited findings, and the v2 report. It also skips omp's first-run setup
wizard on a fresh profile. ~40s, 9 PASS. It requires tmux, `omp`, rizin, `bun`
and a C compiler, and skips (exit 0) without them. Like the other tmux tiers,
it is not run in CI.

## Live-model tier — `bash test/live-model.sh` (`bun run test:live`)

```bash
MINIMAX_CODE_API_KEY=… bun run test:live          # default model: minimax-code/MiniMax-M3
OMPRE_LIVE_MODEL=anthropic/claude-… bun run test:live   # or any provider omp knows
```

This tier covers the model-facing half of findings, which no deterministic
test can reach. A real model drives omp in print mode on two builds of the
fixture:

1. **v1.** It reads `checksum` and `fib` with `rizin_command`, records a
   finding for each by citing the `[evidence …]` tags, and then attempts an
   overreaching claim, which the support auditor should refuse.
2. **v2.** `/re carry … --resolve` re-proves what holds and sends the drifted
   checksum finding to the model as a turn.
3. **v2 report.** The script writes it, then reports how many findings the
   model recorded while resolving.

Assertions are on recorded state only (session entries and report files),
never on model prose. Logs and sessions stay in the work directory (set
`OMPRE_LIVE_WORKDIR` to keep them somewhere specific). It costs real tokens
and is not run in CI. It skips without a key, omp, rizin, bun or a C compiler.
The model's host must be reachable through the network policy.

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
the debugger (`debug.test.ts` executes the fixture under rizin's debugger) and
PE format handling — are never exercised on a hosted runner. `cross-os.yml` is
the tier that does: a matrix over `ubuntu-latest` and `windows-latest` that
installs rizin **v0.9.1** on each (Linux: the portable static release tarball —
there is no `.deb`; Windows: the `rizin-windows-shared64` release zip) and runs
the full suite. It runs on every push to `main` and on manual dispatch, so the
plugin gets real Windows coverage without owning a Windows machine — CI borrows
the runner per run.

Because `/bin/ls` is absent on Windows, each OS compiles
**`test/fixtures/sample.c`** (a trivial program with a `main`, locals, a called
function, and a string — everything the integration setups look up) and points
`OMPRE_TEST_BINARY` at it. Ground truth is still read from rizin at runtime. The
debugger suite self-enables `OMPRE_ENABLE_DEBUGGER`, so the workflow does
**not** set it globally (that would break `extension-sdk.test.ts`'s default-off
assertion); on Linux it relaxes `kernel.yama.ptrace_scope` so the attach-by-PID
test can attach to a non-child. Never add a malware sample — the fixture is
built on the runner.

**Why no macOS leg.** macOS was in the matrix for its first runs and then
dropped. Its one unique value, the debugger, can't run on a hosted macOS runner
(rizin's Darwin backend needs `task_for_pid`, refused to a non-root,
un-codesigned rizin — `debug.test.ts` gates its live-debug blocks off on macOS
for exactly this). With the debugger gated off the leg still wedged `bun test`
for ~20 minutes for a cause that couldn't be diagnosed from CI: a timed-out job
is *cancelled*, and GitHub serves no downloadable log for a cancelled job, so
the hang point was never visible. Its remaining coverage (Mach-O static
analysis) overlaps Linux's ELF coverage, so the leg was removed. `debug.test.ts`
keeps its `process.platform === "darwin"` gate, so a local macOS dev run still
skips the debugger cleanly (override with `OMPRE_FORCE_DEBUGGER=1` on a
codesigned rizin).

The first runs surfaced several real Windows issues, all fixed — a useful
record of what a Windows host needs:

- **Output paths**: the confined-output logic (`output.ts`) hardcoded a `/`
  separator, so every file-emitting capability (dump_memory, trace save/load,
  export_project, create_signature) threw on Windows. Fixed to use `path.sep`.
  Separately, the runner's temp dir is an 8.3 short name (`C:\Users\RUNNER~1\…`)
  and `~` is rizin's grep operator, so a raw path mis-parsed; rizin-written
  paths go through `rizinPathArg` (forward-slash normalized and single-quoted),
  while the tool still reports and `stat`s the native path. The one exception is
  `trace_save`/`trace_load`: `dtst` creates a directory via rizin's
  `rz_sys_mkdirp`, which chokes on a forward-slash drive prefix (`mkdirp fail
  'C:'`), so those pass the **native** quoted path instead.
- **Line endings**: rizin and the `rz-*` tools emit CRLF on Windows; the pipe
  transport (`rizin.ts`) and `rizin_cli` normalize `\r\n` → `\n`.
- **Test teardown**: a temp dir can't be `rm`'d while the rizin child still
  holds a file open (EBUSY), so cleanups use `rmDirSafe` (Node's
  `maxRetries`/`retryDelay` back-off, a no-op on POSIX).
- **A fixture-specific test assumption**: `set_comment`'s undo test asserted the
  comment history bottoms out at `""`, but on the Windows fixture `main` sits on
  the `.text` section start, which rizin auto-annotates with a `CCu` comment —
  so the baseline there is that section comment, not empty. The test now
  captures the baseline and asserts undo restores to it.

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
