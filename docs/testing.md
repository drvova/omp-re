# Testing

Three tiers: `bun test` (unit + rizin integration), `bash test/tui.sh` (fast
TUI smoke), `bash test/tui-qa.sh` (full tmux QA). Run from the repo root after
`bun install --ignore-scripts`.

## Unit and integration tests — `bun test`

```bash
bun install --ignore-scripts
bun test
```

Nine test files. The `bun install` dev dependencies pin omp **18.11.1**, so
the host APIs under test are the ones users run. Tests that need a real
`rizin` and a test binary **skip** (not fail) when either is missing:

| File | Needs rizin? | Tests (rizin present) |
| --- | --- | --- |
| `rizin-pure.test.ts` | No | 26 |
| `format.test.ts` | No | 10 |
| `evidence.test.ts` | No | 4 |
| `audit.test.ts` | No | 5 |
| `report.test.ts` | No | 4 |
| `extension-sdk.test.ts` | Only its resume/replay test | 6 |
| `rizin-integration.test.ts` | Yes (one test runs without) | 13 |
| `tools-registry.test.ts` | Yes (the renderer and native-view tests run without) | 35 |
| `tools-mutate-registry.test.ts` | Yes | 15 |
| **Total** | | **118** |

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

Expected shape with rizin present: **118 pass, 0 fail, 0 skip**. Without
rizin: **62 pass, 64 skip, 0 fail** (126 reported — bun counts skipped
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
plugin's own correctness — see `test/QA-FINDINGS.md` for a worked example
and the harness robustness fixes it prompted.

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

## Loading the extension through omp itself

`test/extension-sdk.test.ts` shows the pattern: `createAgentSession({
additionalExtensionPaths: ["extensions/re"], disableExtensionDiscovery: true,
sessionManager })`, then `initializeExtensions(...)` from
`@oh-my-pi/pi-coding-agent/modes/runtime-init`. Slash commands passed to
`session.prompt("/re …")` and tools fetched with `session.getToolByName(...)`
run locally with no model call. For a full install check, `omp plugin
marketplace add /path/to/checkout` then `omp plugin install omp-re@unit221b`
installs from a local checkout.

## Local dev loop

`extensions/re/` changes are picked up by a **fresh `omp` start** if you're
dev-loading via the `extensions:` config entry in
[the README](../README.md#install) — no build step, but also no hot reload;
restart `omp` after an edit. If you installed as a plugin instead, the
cached copy under `~/.omp/plugins/cache/plugins/...` is a **copy, not a
symlink**, so an edit to your checkout does nothing until you reinstall:

```bash
omp plugin upgrade omp-re@unit221b
```
