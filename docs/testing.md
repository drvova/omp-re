# Testing

Two suites run without a terminal or a model, and CI runs both:

| Suite | Command | Tests |
| --- | --- | --- |
| The Lisp suite | `bun run test:engine` (`sbcl --non-interactive --load test/nodecode/run.lisp`) | the engine, and both hosts' Lisp |
| The bun suites | `bun test test/` | the omp extension, loaded through omp's real SDK, with the engine behind it |

Four more tiers drive a real omp terminal under tmux or a real model. They are
manual: no workflow runs them, and each exits 0 with a printed `SKIP` when a
program it needs to start at all is missing. `bash test/tui.sh`,
`bash test/tui-carry.sh`, `bash test/tui-qa.sh`, `bash test/live-model.sh`.

Run everything from the repository root after `bun install --ignore-scripts`.

## What you need

| | Lisp suite | bun suites |
| --- | --- | --- |
| SBCL and cl-ppcre | required | required — the extension starts the engine |
| bun | — | required |
| rizin and a test binary | each suite's rizin half prints `SKIPPED` without them | the `against rizin` groups skip without them |
| python3 | — | the Python-kernel groups skip when omp cannot start a Python |

**The default test binary is `/bin/ls`**, which exists on every Linux host and
on macOS. Point the suites at another with `OMPRE_TEST_BINARY=/path/to/binary`.
Ground truth is read from rizin at run time, so any ELF or PE with a function
named `main`, at least one call inside it, a PLT-backed import and a local
variable works.

A skip is printed, never silent. On a Linux host with all of the above, nothing
skips in the bun suites.

## The Lisp suite — `bun run test:engine`

`test/nodecode/run.lisp` loads the engine and the nodecode host and runs every
`test/nodecode/suite-*.lisp` in name order, each in a scratch home of its own,
against a real rizin. It ends with a line `omp-re: N checks, M failed` and
exits non-zero when any failed. `OMPRE_TEST_SUITES=core,annotate` runs a
subset.

This is where the engine's behaviour is held: the primitives against published
vectors (SHA-256, HMAC), the read-only command policy and every refusal's
words, every tool and `/re` line, the evidence store and the audit log, the
record on a branch, a rizin killed and replaced, a session forgotten and
restored from its record, an interrupted command, a timeout, the debugger's
command lines and gates, findings, verify, report, carry, the views and the
status band's facts.

Two of the suites are about a host:

- The nodecode host runs over `test/nodecode/kernel-stub.lisp`, a stand-in for
  the names it uses from nodecode's kernel. That proves the cell's own code,
  not nodecode's side of the seam: loading the folder in a nodecode build is a
  manual check ([`nodecode.md`](nodecode.md)).
- `suite-stdio.lisp` starts the omp host's server (`stdio/serve.lisp`) as a
  real child process and talks to it over real pipes, with Lisp standing in
  for omp. It holds the Lisp end of [`engine-protocol.md`](engine-protocol.md).
  The stand-in checks every message that crosses the pipe, either way, against
  `stdio/protocol.json`, so it cannot speak a protocol of its own.

The debugger checks run rizin's command lines against a stand-in program. One
group launches a real process under `rizin -d`, and only when the test binary
is `/bin/ls` or `/bin/true`; where `ptrace` is not permitted it checks that the
launch is refused cleanly instead.

The harness uses POSIX calls and `/bin/sh` stand-ins, so this suite does not
run on Windows.

## The bun suites — `bun test test/`

The dev dependencies pin omp **18.11.1**, so the host APIs under test are the
ones `bun install` gives you. No model is called.

| File | What it holds |
| --- | --- |
| `test/extension-sdk.test.ts` | The extension loaded by omp's real SDK and extension runner, driven the way a session drives it: `/re` lines, the tools through omp's own `eval` (`tool.<name>()`), `--binary`, resume with replay, the debugger's opt-in. It is the suite that catches omp API drift. |
| `test/shim.test.ts` | omp's end of the pipe. Against `test/stand-in-engine.ts`, a bun script that speaks `stdio/protocol.json` and holds everything omp's side sends to it: no SBCL, an engine that cannot load, dies, speaks another protocol version or never becomes ready; message framing; every method, session event and member of the wire sent once; the status band, the list and code overlays and their keys; a headless run's output; an engine that goes silent, loses a request, dies mid-request or will not leave. Against the real engine: the side model, two sessions on one engine process, an engine killed and replaced with `/re off` kept, the audit log under omp's own call ids, abort, `/re undo`, a session branched, compacted and switched, every approval sentence. |
| `test/versions.test.ts` | One version in `package.json`, the marketplace entry and the three `.asd` files; `extensions/re/protocol.ts` and the tables of `engine-protocol.md` current with `stdio/protocol.json`. |
| `test/recipes-eval.test.ts` | The recipes in omp's `eval`, both kernels. With rizin, the same recipes are run by the JavaScript script, the Python script and the Lisp verbs on the same binary and their reports compared whole — every line, evidence ids aside. It also runs `scripts/gen-recipes.ts --check`. |
| `test/omp-eval-contract.test.ts` | omp itself: one test for each behaviour of omp's `eval` that [`omp-eval.md`](omp-eval.md) describes and omp does not document. It uses a probe extension, not the RE tools. Its first test fails until the page names the installed omp version. |

## Fast smoke tier — `bash test/tui.sh`

A short tmux-driven smoke test against the real TUI: seven assertions, no model
round-trip. It needs tmux, `omp`, SBCL, rizin and a test binary (`/bin/ls`, or
`OMPRE_TEST_BINARY`). It exits 0 with a printed `SKIP` when a prerequisite is
missing.

## Carry / findings end to end — `bash test/tui-carry.sh`

Drives `/re carry --inherit` in a real omp TUI. It is self-contained: it
compiles two builds of `test/fixtures/sample.c`, records three findings on the
first with `test/e2e/make-carry-manifest.lisp` (real rizin evidence and the
real `record_finding`, with a stand-in auditor so no model is needed), then
starts `omp -e extensions/re --binary v2` and types the slash commands. It
checks the carry statuses, the agenda placed in the editor, the status band
and `/re status` counting the inherited findings, and the second build's
report. It needs tmux, `omp`, SBCL, rizin and a C compiler, and skips (exit 0)
without them.

## Live-model tier — `bash test/live-model.sh`

The model-facing half of findings, which no deterministic test can reach. A
real model drives omp in print mode on two builds of the fixture: it records
findings on the first and attempts an overreaching claim the support auditor
should refuse; `/re carry … --resolve` on the second prints the agenda for the
drifted finding; the script passes that agenda back as the next prompt and
writes the report.

`OMPRE_LIVE_MODEL=<provider>/<model>` names the model, in the form omp's
`--model` takes, with that provider's key in the environment. The script has
no default: without the variable it says so and exits 2. Assertions are on
recorded state only (session entries and report files), never on model prose.
It costs real tokens. It skips without `omp`, SBCL, rizin or a C compiler.

## Full QA tier — `bash test/tui-qa.sh`

A long tmux-driven pass against the live TUI: every `/re` subcommand, the
shortcuts, the evidence panel, undo and the audit log. It needs tmux, `omp`,
SBCL, rizin, two test binaries (`/bin/ls` and `/bin/cat`, or
`OMPRE_TEST_BINARY` and `OMPRE_TEST_BINARY_ALT`) and a working model. Three of
its phases rest on a model turn: one that does not finish fails its step and
the steps after it, it does not skip them. A step skips only where the fixture
has nothing to show it on. It drives an interactive terminal on wall-clock
assumptions, so a heavily loaded host can produce failures that have nothing
to do with the plugin; re-run on an idle host before treating one as real.

The script pins its own assertion count as a drift guard (a literal `-eq 100`
near its end): if you add or remove an assertion, update that literal in the
same commit, and give any conditional assertion an explicit `fail` or `skip`
mirror on every other branch it could take.

## What CI runs

`.github/workflows/ci.yml`, on every pull request and every push to `main`:
one Linux job that installs bun, SBCL, cl-ppcre and rizin 0.9.1 (the portable
static release build — it cannot load a decompiler plugin), builds
`test/fixtures/sample.c` as the test binary, and runs

1. `bun run check` — the type check;
2. `node scripts/release.mjs --check-versions` — `package.json`, the
   marketplace entry and the three `.asd` files carry one version;
3. `bun scripts/gen-recipes.ts --check` — the recipes' generated blocks are
   current with `recipes/tables.json`;
4. `bun scripts/gen-protocol.ts --check` — `extensions/re/protocol.ts` and the
   tables of `engine-protocol.md` are current with `stdio/protocol.json`;
5. system `omp-re` loaded in a plain SBCL — the engine needs nothing of either
   host;
6. the Lisp suite;
7. `bun test test/`, which runs steps 2 and 4 again (`versions.test.ts`) and
   step 3 (`recipes-eval.test.ts`), so a plain `bun test` holds them too.

`.github/workflows/cross-os.yml`, on every push to `main` and on manual
dispatch: one Windows job that installs SBCL (Chocolatey), cl-ppcre (cloned to
`~/common-lisp/`) and rizin (the release zip), builds the fixture as a PE, and
runs steps 1, 5 and 7. It cannot run the Lisp suite.

Neither workflow runs a tmux tier or calls a model: those tiers exit 0 when a
prerequisite is missing, which would make them theatre on a hosted runner.
Never add a malware sample to CI — the fixture is built on the runner.

## What is not proven

Stated plainly, so a green badge is not read as more than it is.

- **Windows.** The engine and the extension are written to run there, and the
  Windows CI job exists, but it had not been seen to pass when the engine
  moved to Common Lisp. Unchecked in particular: reading rizin's pipe with a
  timeout, SBCL threads, ending a process tree with `taskkill`, replacing a
  file by rename, and Chocolatey's SBCL finding its core in a CI step. The
  stand-in engine of `shim.test.ts` is a bun script, so the framing tests
  (CRLF line ends among them) no longer skip there; they had not been seen to
  run on Windows when they were written.
- **macOS.** Nothing in CI runs there, and the authors have not run the engine
  there. The extension's and the engine's code paths are the POSIX ones Linux
  uses, with one known difference: a process tree is ended through `/proc` on
  Linux, so on macOS only the direct child is killed.
- **The debugger in CI.** The Lisp suite's real launch runs only against
  `/bin/ls` or `/bin/true`, and CI's test binary is the fixture, so CI covers
  the debugger's command lines, gates and refusals, and one launch from
  `extension-sdk.test.ts`.
- **Decompiler output in CI.** CI's rizin has no decompiler plugin, so CI sees
  only the labeled-disassembly fallback.
- **What the terminal shows.** The overlays, the status band and the tool
  cards are type-checked; only the tmux tiers look at them, and those are run
  by hand.
- **nodecode itself.** The cell is tested over a stand-in for nodecode's
  kernel.
- **A newer omp.** The suites run against the pinned 18.11.1.

## Loading the extension through omp itself

`test/helpers.ts` (`boot`) shows the pattern: `createAgentSession({
additionalExtensionPaths: ["extensions/re"], disableExtensionDiscovery: true,
sessionManager })`, then `initializeExtensions(...)` from
`@oh-my-pi/pi-coding-agent/modes/runtime-init`. Slash commands passed to
`session.prompt("/re …")` run locally with no model call. For a full install
check, `omp plugin marketplace add /path/to/checkout` then `omp plugin install
omp-re@drvova` installs from a local checkout.

## Local dev loop

A change under `extensions/re/`, `engine/` or `stdio/` is picked up by a
**fresh `omp` start** if you dev-load through the `extensions:` config entry
in [the README](../README.md#install) — there is no build step and no hot
reload. A changed Lisp file is recompiled at that start. If you installed as a
plugin instead, the cached copy under `~/.omp/plugins/cache/plugins/...` is a
**copy, not a symlink**, so an edit to your checkout does nothing until you
reinstall:

```bash
omp plugin upgrade omp-re@drvova
```
