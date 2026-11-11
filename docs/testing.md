# Testing

Two suites run without a terminal or a model, and CI runs both:

| Suite | Command | Tests |
| --- | --- | --- |
| The Lisp suite | `bun run test:engine` (`sbcl --non-interactive --load test/nodecode/run.lisp`) | the engine, and both hosts' Lisp |
| The bun suites | `bun test test/` | the omp extension, loaded through omp's real SDK, with the engine behind it, driven from cells of omp's real `eval` in both of its kernels |

Two checks stand beside them, and CI runs both: `bun run check:warnings`
(the three Lisp systems compile from scratch with no warning) and
`bun run cover:engine` (the Lisp suite again, under sb-cover). They are
below.

One more tier drives a real `omp` with a real model, `bash test/live-model.sh`.
It is manual: no workflow runs it, and it exits 0 with a printed `SKIP` when a
program it needs to start at all is missing. Nothing drives a real omp
terminal: the tmux tiers that did typed `/re` lines, which no longer exist.

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
words, every tool and line, the evidence store and the audit log, the
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

One group of the carry suite compiles `test/fixtures/sample.c` twice, the
second time with a function renamed and a constant changed, writes a report
on the first build and carries it onto the second. It needs a C compiler
(`cc`, `gcc` or `clang`) and says `SKIPPED` without one.

The debugger checks run rizin's command lines against a stand-in program. One
group launches a real process under `rizin -d`, and only when the test binary
is `/bin/ls` or `/bin/true`; where `ptrace` is not permitted it checks that the
launch is refused cleanly instead.

The harness uses POSIX calls and `/bin/sh` stand-ins, so this suite does not
run on Windows.

## Compiler warnings — `bun run check:warnings`

`scripts/check-warnings.lisp` compiles `omp-re`, `omp-re-stdio` and
`nodecode-re` (over the suite's stand-in for nodecode's kernel) with every
file recompiled, into a scratch directory, and exits 1 when the compiler
signalled a warning or a style warning, printing each with its file. It is
what makes the declared types of the engine's exported functions
([`ARCHITECTURE.md`](ARCHITECTURE.md#the-engine-engine-system-omp-re)) hold
for the two hosts: a call that does not fit a declared type is a warning.
Nothing is allowed by its text. The one thing passed over is what SBCL itself
signals and never prints (`sb-ext:*muffled-warnings*`): a file's load meeting
the macros its own compile had just defined.

It was written against SBCL 2.2.9. A later SBCL can warn about what this one
does not; a failure after an SBCL upgrade is to be read before it is fixed.

## Coverage — `bun run cover:engine`

`scripts/cover.lisp` compiles the three systems with sb-cover's
instrumentation, runs the Lisp suite, and prints a line for each file of
`engine/`, `stdio/` and `nodecode/` — expressions run and their number,
branches run and their number — a total, and then every definition no part
of whose body ran. sb-cover's own report, a page for each file with what ran
in green and what did not in red, is `coverage/cover-index.html`; the table
and the list are also `coverage/summary.md`. `coverage/` is not committed.
`OMPRE_TEST_SUITES` narrows the run as it does for the suite.

The instrumented files are compiled into `coverage/fasl/`, apart from the
cache an ordinary load uses, so the suite, the bun suites and omp never run
instrumented code: instrumentation changes how the Lisp is compiled, and
slows it. The test files and the generated `nodecode/recipe-data.lisp` are
not measured. The omp host is a process of its own, which `suite-stdio`
starts; under coverage each such process loads the instrumented files and
leaves what it ran for the run to add up when omp's side closes its pipe. A
host process that a check kills leaves nothing.

When this was written the suite ran 91 % of the expressions and 84 % of the
branches, against `/bin/ls`, and three definitions were never entered. Why
each is left:

- `image-main` (`stdio/server.lisp`) runs only in a saved image, which has
  no instrumented copy: `test/image.test.ts` holds it, with real images.
- `rotr32` (`engine/sha256.lisp`) is declared inline, so its body runs
  inside SHA-256 and the function by its own name is never called. The
  published vectors hold it.
- `missing-commands-warning` (`engine/tools-core.lisp`) is said only of a
  rizin build that lacks a command the engine sends. The suite has one
  rizin, which has them all.

With `OMPRE_COVERAGE_FLOOR=<percent>` in the environment the script also
exits 1 when the expressions run, over all files, are below that percentage.
CI sets 80. That is not a target: it is far enough under the measured figure
that no ordinary change reaches it, and it is there for one failure a green
suite does not show — a suite, or the rizin half of every suite, that
stopped running. With rizin absent the suite still exits 0, and the same run
covers 56 %.

## The bun suites — `bun test test/`

The dev dependencies pin omp **18.11.1**, so the host APIs under test are the
ones `bun install` gives you. Everything the model would do is done the way
the model does it: a cell run through omp's own `eval` tool, with the library
loaded by the skill's load line (`bootLoaded` in `test/helpers.ts`), in the
JavaScript kernel and, where omp can start one, the Python kernel. No model is
called, on any machine: the one
harness every suite boots a session through (`boot` in `test/helpers.ts`)
gives the session no model and a side turn of its own, so the claim audit
finds nobody to ask even where omp has provider credentials. The one test of
the audit's wiring hands `boot` a stand-in to reply in the model's place.

| File | What it holds |
| --- | --- |
| `test/extension-sdk.test.ts` | The extension loaded by omp's real SDK and extension runner: that it registers no tool, command or flag; the verbs in both kernels, their refusals in the same words, the reload note under a cell that had not loaded the library; with rizin, a whole analysis from JavaScript cells and from Python cells of one session, a resumed session's replay, the debugger behind its switch, a session with no file. |
| `test/bridge.test.ts` | The way from a cell to the engine. The listener's file (the owner's alone, gone at shutdown, a stale one swept), a request without the token or with another, `OMPRE_DISABLED=1` starting nothing; two sessions in one process each reaching the engine as itself, two that share a kernel refused, a kernel behind a launcher found by its session file; a cell that is interrupted or times out cancelling the engine's call, in both kernels, and, with rizin, an interrupted analysis. Mostly against the stand-in engine, which writes down what omp's side said to it. |
| `test/shim.test.ts` | omp's end of the pipe. Against `test/stand-in-engine.ts`, a bun script that speaks `stdio/protocol.json` and holds everything omp's side sends to it: no SBCL, an engine that cannot load, one that dies, one of another version, one that never starts; every method and event of the protocol sent once and checked against the protocol's own description; the status band and the panels drawn and driven by key; what a headless run prints; how long omp waits and how an engine is ended. Against the real engine: one engine for the process, the audit log's call ids, and with rizin an annotation and its undo, the claim audit through a stand-in side model, a session whose binary is gone. |
| `test/image.test.ts` | How the engine process is started ([`install.md`](install.md#the-engine-image)), with real images and a real SBCL, each test in a cache directory of its own: a first start builds an image and is that image, and the next runs the same file; an image shipped in `dist/` is run while it is this source's, and a changed source passes it over and builds once; a cached image that will not run is built again; `OMPRE_ENGINE_IMAGE` is run as it is, with no SBCL, and one that is no image is the start's error; where no image can be built the engine loads from source and the log says why; two builds at once leave one whole image. What was started is read from the engine's own `hello` and, on Linux, from `/proc/<pid>/exe`. |
| `test/versions.test.ts` | One version in `package.json`, the marketplace entry and the three `.asd` files; `extensions/re/protocol.ts` and the tables of `engine-protocol.md` current with `stdio/protocol.json`. |
| `test/recipes-eval.test.ts` | The library's recipes in omp's `eval`, both kernels: what loading leaves in a kernel, refusals. With rizin, the same recipes are run by the JavaScript script, the Python script and the Lisp verbs on the same binary and their reports compared whole. `gen-recipes.ts --check` and `gen-api.ts --check` run here too. |
| `test/omp-eval-contract.test.ts` | omp itself: one test for each behaviour of omp's `eval` that [`omp-eval.md`](omp-eval.md) describes and omp does not document — among them everything the way to the engine stands on: a kernel is a child process of omp's, what it is told of its session, that it can reach a loopback listener, that a cell's timeout or interrupt hangs up. It uses a probe extension, not the plugin's. |

Every suite that boots a session starts the engine the way omp does, so it
runs the image. `test/setup.ts`, which `bunfig.toml` has `bun test` load
before any suite, builds that image when the cache has none for this source,
so that the first compile and save are not inside some test's own time
limit. Only the tests of `image.test.ts` that are about building build more.

## Live-model tier — `bash test/live-model.sh`

The model-facing half of findings, which no deterministic test can reach. A
real model drives omp in print mode on two builds of the fixture, doing
everything in `eval` through the library: on the first it records findings,
attempts an overreaching claim the support auditor should refuse, and writes
the report; on the second, in a fresh session, it carries the first report's
manifest with `--inherit`, works through the agenda the line hands it, and
writes the second report.

`OMPRE_LIVE_MODEL=<provider>/<model>` names the model, in the form omp's
`--model` takes, with that provider's key in the environment. The script has
no default: without the variable it says so and exits 2. Assertions are on
recorded state only (session entries and report files), never on model prose.
It costs real tokens. It skips without `omp`, SBCL, rizin or a C compiler.
It was rewritten when the `/re` command went and **had not been run** when
this was written: no `omp` binary and no model were at hand.

## What CI runs

`.github/workflows/ci.yml`, on every pull request and every push to `main`,
has two Linux jobs. `suite` installs bun, SBCL, cl-ppcre and rizin 0.9.1 (the
portable static release build — it cannot load a decompiler plugin), builds
`test/fixtures/sample.c` as the test binary, and runs

1. `bun run check` — the type check;
2. `node scripts/release.mjs --check-versions` — `package.json`, the
   marketplace entry and the three `.asd` files carry one version;
3. `bun scripts/gen-recipes.ts --check` and `bun scripts/gen-api.ts --check` —
   the generated blocks of the two eval libraries, and nodecode's
   `recipe-data.lisp` and `verb-forms.lisp`, are current with
   `recipes/tables.json` and `recipes/api.json`;
4. `bun scripts/gen-protocol.ts --check` — `extensions/re/protocol.ts` and the
   tables of `engine-protocol.md` are current with `stdio/protocol.json`;
5. `scripts/check-warnings.lisp` — the three Lisp systems compile from
   scratch with no warning;
6. system `omp-re` loaded in a plain SBCL — the engine needs nothing of either
   host;
7. the Lisp suite;
8. `bun test test/`, which runs steps 2 and 4 again (`versions.test.ts`) and
   step 3 (`recipes-eval.test.ts`), so a plain `bun test` holds them too.

`coverage` installs SBCL, cl-ppcre and rizin, builds the fixture, runs
`scripts/cover.lisp` with `OMPRE_COVERAGE_FLOOR` set, and writes the table
and the list of what never ran to the job's summary. It runs the suite a
second time on purpose: the `suite` job's run is of the code as it ships.

`.github/workflows/release.yml`, after it has tagged a release, builds the
engine's image on a Linux, a macOS and a Windows runner and attaches the
three to the GitHub release.

`.github/workflows/cross-os.yml`, on every push to `main` and on manual
dispatch: one Windows job that installs SBCL (Chocolatey), cl-ppcre (cloned to
`~/common-lisp/`) and rizin (the release zip), builds the fixture as a PE, and
runs steps 1, 6 and 8. It cannot run the Lisp suite.

No workflow calls a model: the live tier exits 0 when a prerequisite is
missing, which would make it theatre on a hosted runner.
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
- **The engine image off Linux.** Building an image, running one, and the
  cache directory were run on Linux only. On Windows an image is an `.exe`
  and the build's last step replaces a file that may be running; on macOS a
  downloaded image is quarantined. Neither was seen. If an image does not
  start, the start from source is what is left, and that is the path the
  Windows job was written for.
- **The release's images.** The `image` job of `release.yml` had not run when
  it was written: not the SBCL each runner installs, not the upload.
- **The CI steps added with them.** `check-warnings` and the coverage job were
  run on a developer's machine with SBCL 2.2.9, not on a runner. A runner's
  newer SBCL may warn where 2.2.9 does not.
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
- **A real omp.** Every suite loads the extension through omp's SDK and runs
  cells through omp's real `eval` tool, but none starts the `omp` program or
  a model's turn. Unseen, therefore: that omp finds the skill beside the
  extension as installed; that a model, given the skill, loads the library
  and uses it; what omp's agent loop does with the note added under a cell's
  error; a subagent (`re-analyst`) loading the library in its own kernel.
- **The listener off Linux.** `bridge.test.ts` ran on Linux. On Windows the
  file's mode bits mean nothing and a virtual environment's `python.exe` is a
  launcher, so the kernel's parent is not omp: the library then finds the
  listener by the session's file, which is tested here by renaming the file,
  not on Windows. On macOS the temporary directory is per user and the
  kernels' view of it was not seen.
- **What the terminal shows.** `shim.test.ts` draws the status band and the
  overlays without colours on a screen of its own and drives them by key.
  How omp's real terminal lays them out is seen by nothing now.
- **nodecode itself.** The cell is tested over a stand-in for nodecode's
  kernel.
- **A newer omp.** The suites run against the pinned 18.11.1.

## Loading the extension through omp itself

`test/helpers.ts` (`boot`) shows the pattern: `createAgentSession({
additionalExtensionPaths: ["extensions/re"], disableExtensionDiscovery: true,
sessionManager })`, then `initializeExtensions(...)` from
`@oh-my-pi/pi-coding-agent/modes/runtime-init`. A cell is run with
`session.getToolByName("eval").execute(…)` (`runCell`), which is the call the
agent loop makes for a model. For a full install
check, `omp plugin marketplace add /path/to/checkout` then `omp plugin install
omp-re@drvova` installs from a local checkout.

## Local dev loop

A change under `extensions/re/`, `engine/` or `stdio/` is picked up by a
**fresh `omp` start** if you dev-load through the `extensions:` config entry
in [the README](../README.md#install) — there is no build step and no hot
reload. A changed Lisp file is recompiled at that start and a new image saved
(a few seconds, once; `OMPRE_CACHE_DIR` holds the three used last). If you
installed as a
plugin instead, the cached copy under `~/.omp/plugins/cache/plugins/...` is a
**copy, not a symlink**, so an edit to your checkout does nothing until you
reinstall:

```bash
omp plugin upgrade omp-re@drvova
```
