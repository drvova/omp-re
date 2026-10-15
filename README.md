# omp-re

[![CI](https://github.com/drvova/omp-re/actions/workflows/ci.yml/badge.svg)](https://github.com/drvova/omp-re/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![omp ≥ 18.11.1](https://img.shields.io/badge/omp-%E2%89%A5%2018.11.1-informational)
![rizin 0.9+](https://img.shields.io/badge/rizin-0.9%2B-informational)
![26 tools](https://img.shields.io/badge/tools-26-informational)

![omp-re triaging /usr/bin/ls: hash, imports, and a plain-English verdict](docs/img/hero.png)

`omp-re` is a reverse-engineering plugin for [omp](https://omp.sh) (oh-my-pi):
it drives [rizin](https://rizin.re) behind 26 agent tools, a `/re` slash
command, five overlay panels, a packaged `re-analyst` subagent, a
content-addressed evidence store, an HMAC-signable audit log, and a report
writer that refuses to write a claim with no supporting evidence. The agent
gathers facts through the tools; the evidence store remembers exactly what it
observed; the report writer will not let it claim more than that.

## Install

```bash
omp plugin marketplace add drvova/omp-re
omp plugin install omp-re@drvova
```

`drvova` after the `@` is the *marketplace catalog name* declared inside
`.omp-plugin/marketplace.json`; it happens to match the GitHub owner but is a
separate identifier (the `marketplace add` argument is the GitHub `owner/repo`,
the `@name` is the catalog).

To develop against a local checkout instead of installing as a plugin, point
omp at the extension directory directly:

```yaml
# ~/.omp/agent/config.yml
extensions:
  - /path/to/omp-re/extensions/re
```

TypeScript loads natively through Bun; an edit is picked up on the next omp
start with no build step. Never use a real home directory in this config
(`/path/to/omp-re`, not a machine-specific path).

**rizin is required, and it is yours.** omp-re does not bundle, download,
or build rizin: it runs the `rizin` on your `PATH` (or the one
`OMPRE_RIZIN_PATH` names), so you choose the version, update it with your
package manager, and keep the decompiler plugins you already have. Without
it, `/re open` throws exactly: `omp-re: rizin not found on PATH — install
rizin (https://rizin.re) or set OMPRE_RIZIN_PATH`. See
[Prerequisites](#prerequisites) and [`docs/install.md`](docs/install.md).

## Quickstart

A copy-pasteable first run against `/bin/ls` — no sample binary, no setup
beyond rizin on PATH:

```
/re open /bin/ls
alt+g            # function navigator; type to filter (fuzzy)
Enter            # open a function in the code view
d                # toggle decompiled C
x                # follow the selected xref
a                # hand the function off to the model with a grounding prompt
/re report       # write a Markdown report from what was gathered
```

Or delegate a whole analysis: ask omp to run the `re-analyst` agent on a
binary path. It opens the binary in its own rizin process, follows the triage
order, and returns structured findings that each cite the tool output and
address behind them.

## What's omp-native

`omp-re` uses omp's own extension surfaces rather than working around them:

| omp feature | What omp-re does with it |
| --- | --- |
| Tool renderers (`renderCall`/`renderResult`) | Every RE tool renders a compact call line and a collapsible result; decompiled code is syntax-highlighted as C with omp's highlighter. |
| Native tool views (`describeCall`/`describeResult`) | In Tern and other TSP terminals, each RE tool is a native tool card — title, target, and facts in the head; C, JSON, or disassembly as a `code` node the terminal highlights and clamps — instead of a generic text card. |
| Streaming updates + `AbortSignal` | `open_binary` streams analysis progress; cancelling a tool call stops waiting without killing rizin (and its annotations); cancelling analysis kills the half-analyzed process. |
| Session artifacts (`artifact://`) | Output past the context cap is saved in full to the session's artifact store and linked from the result, never discarded. |
| Session branches (`getBranch`) | Evidence, annotations, and the open binary follow the active branch: after `/tree` navigation or a branch, an abandoned branch's renames are rolled back and its evidence no longer grounds claims. |
| Session lifecycle events | `--continue`/`/resume` reopen the branch's binary in the background and **replay its annotations** into the fresh rizin process; a crashed or timed-out rizin respawns the same way. |
| Approval tiers with reasons | Read tools (and `rizin_help`) are `read`; mutate tools are `write` with a per-call reason (e.g. `Rename function "main" to "parse_args"`); `rizin_command` is `exec` with the exact command in its reason; triage tools are `exec`. omp's `tools.approvalMode` decides. |
| Task subagents | omp forwards extension tools to `task` subagents, so the plugin ships `agents/re-analyst.md`, marked `structured: true` so its output schema is enforced even when `task.structured` is off. |
| Slash-command completion | `/re` completes its subcommands and, for `cite`/`evidence`, the evidence ids on this branch. |
| Footer status, widgets, logger | Analysis progress shows in the footer; the binary-facts band is a widget; headless warnings go to omp's log. |

## Using all of rizin

The dedicated tools cover the common path; rizin has about 2,000 commands.
Rather than hardcode a list, omp-re reads the catalog rizin publishes about
itself (`rizin -qc '?*j'`: every command in the installed build, plugins
included, with typed arguments and a summary) and uses it three ways:

- **`rizin_help`** answers "which command, and what arguments?" from the rizin
  you actually have, so the model never guesses syntax for the wrong version.
  `rizin_help ph` shows `ph <algo>` with its choices; `rizin_help "rop gadgets"`
  finds `/R`.
- **`rizin_command`** runs one read-only command from that catalog — function
  summaries (`pdsf`), call graphs (`agc`), hexdumps (`px`), entropy
  (`ph entropy @!4096`), byte and ROP searches (`/x`, `/R`), ESIL (`aoe`),
  headers (`iH`) — and returns rizin's own error and usage text when the
  arguments are wrong. Writes, config, shell escapes, file reads, and
  analysis changes are refused before anything reaches rizin; see
  [`SECURITY.md`](SECURITY.md#rizin_command).
- **A compatibility check**: when a binary opens, every command omp-re's own
  tools send is looked up in the catalog, and any your rizin lacks is named in
  a warning instead of failing later as an empty result. `/re status` shows
  the result and which decompiler the catalog lists.

Beyond the in-core commands, rizin's **standalone CLI tools** are one tool
away. `rizin_cli` fronts `rz-bin` (fast headers/imports/strings without full
analysis), `rz-diff` (compare two binaries — versions of a sample, patched vs.
original), `rz-hash` (hashing and entropy), `rz-find` (raw pattern search),
`rz-asm` (standalone assemble/disassemble), and `rz-ax` (base conversion),
each with its own arguments and its own `-h`. Argv only — no shell — and the
flags that write files, run code, fetch over the network, or open an
interactive view are refused.

### Decompiler: whatever you have

`decompile_function` and the code view use the best decompiler plugin
installed — rz-ghidra (`pdg`) then jsdec (`pdd`) by default. `OMPRE_DECOMPILER`
reorders that, or names another plugin's command entirely (any `pdX`-style
decompiler is probed the same way); the built-ins stay as a fallback. Without
any plugin, output is labeled annotated disassembly, never passed off as
decompiled code.

### Dynamic analysis: the debugger (opt-in)

rizin is also a debugger, and `rizin_debug` drives it — launch the target,
set breakpoints, continue, single-step, read registers and memory, walk the
backtrace. This **executes the sample**, so it is off until you set
`OMPRE_ENABLE_DEBUGGER`, runs in a session separate from the static one that
only ever reads the file, and every resume is an `exec`-tier approval that
says so. Run untrusted samples only in an isolated, disposable VM or
container — see [`SECURITY.md`](SECURITY.md#rizin_debug).

## What it looks like

The screenshots below are real, unmodified captures of an earlier `omp-re`
release against `/usr/bin/ls` on Ubuntu 24.04 — not mockups. They were taken
with the radare2 backend before the rizin port; the layout is unchanged, and
[`tools/shotgen`](tools/shotgen) regenerates them against rizin on any Linux
machine.

### Function navigator

`alt+g` opens a fuzzy-filterable, scrollable panel over every analyzed
function:

![Function navigator filtered to "fcn"](docs/img/functions.png)

### Decompile and cross-references

`d` inside the code view toggles decompiled C. Without a decompiler plugin
the view degrades honestly to annotated disassembly, labeled
`(disassembly only — no decompiler plugin available)`, rather than pretending
to have a real decompile — see [Prerequisites](#prerequisites).

![Decompiled view of main()](docs/img/decompile.png)

![Cross-references to entry0](docs/img/xrefs.png)

### Evidence, cited

`/re evidence` lists every fact gathered on this branch by an 8-character id;
Enter on a row (or `/re cite <id>`) pulls it straight into the editor as a
prefilled message — here, the exact SHA-256/SHA-1/MD5 `hash_binary` actually
returned, not a retyped guess:

![/re cite prefilling the editor with a hash_binary evidence entry](docs/img/evidence-cite.png)

### The report gate, proven

`/re report` refuses to write a report containing any claim with zero
backing evidence. Here the model is instructed to record an unverified
IOC-shaped claim directly (bypassing the RE tools on purpose) — the write is
blocked, and the IOC is defanged even in the error message:

![/re report withholding the whole report over one ungrounded IOC claim](docs/img/report-gate.png)

## Prerequisites

| Requirement | Notes |
| --- | --- |
| `omp` ≥ 18.11.1 | Developed and tested against 18.11.1, the latest release (its `getAllTools()` returns tool objects, and Tern renders tools natively). The dev dependencies pin it, so `bun install` tests against the same host. |
| `bun` | The runtime `omp` invokes plugin code with; omp ships it as a dependency, but you need it to run this repo's own `bun install`/`bun test` for local development. |
| **rizin — required, not bundled** | Your own install, found on `PATH` or via `OMPRE_RIZIN_PATH`. Tested with rizin 0.9.1, the latest release. `/re status` shows which rizin and decompiler omp-re found. |
| **rz-ghidra — optional, strongly recommended** | Provides `pdg`, a real Ghidra decompile. jsdec (`pdd`) is used when rz-ghidra is absent. With neither, `decompile_function` and the code viewer's `d` key return annotated disassembly whose output begins `(disassembly only — no decompiler plugin available) `. `/re status` shows which decompiler is active. |
| Optional triage binaries | Each is independently probed on PATH at load time and simply not registered when absent: `capa` → `triage_capa`, `floss` → `triage_floss`, `diec` → `triage_die`, `yara` → `triage_yara`. |

## Command reference

```
/re open <path>      open a binary        alt+g  function navigator
/re functions        function navigator   alt+s  strings
/re strings          string list          alt+i  imports; in code view:
/re imports          import list             d  toggle decompile
/re evidence [id]    evidence log            x  follow xrefs
/re cite <id>        cite evidence in chat   a  ask the model
/re undo             revert annotation
/re report [path]    write report
/re status           rizin, decompiler, and session status
/re on               enable RE tools
/re off              disable RE tools (quick toggle, no restart)
```

`omp --binary <path>` opens a binary at startup.

## Tool reference

All 26 tools — see [`docs/tools.md`](docs/tools.md) for full parameter
tables. Triage tools appear only when their backing binary is on PATH, and
`rizin_debug` only when `OMPRE_ENABLE_DEBUGGER` is set, so your own tool list
may legitimately show fewer than 26.

| Tool | Tier | What it does |
| --- | --- | --- |
| `open_binary` | session-setup | Spawns rizin on a binary and runs full analysis (`aaa`), streaming progress. |
| `list_functions` | read | List analyzed functions; sort by address, size, or callers. |
| `search_functions` | read | Search functions by name substring. |
| `get_function` | read | One function: signature, metrics, args/locals, named call targets, callers. |
| `decompile_function` | read | Decompile a function (rz-ghidra `pdg`, jsdec `pdd`, or labeled disassembly). |
| `disassemble_function` | read | Disassemble a function, with comments, labels, and incoming xrefs folded in. |
| `get_xrefs_to` | read | Cross-references pointing at an address. |
| `get_xrefs_from` | read | Cross-references originating from an instruction. |
| `list_imports` | read | List imported symbols. |
| `list_exports` | read | List exported symbols. |
| `list_strings` | read | List strings, optionally filtered. |
| `list_segments` | read | List sections with permissions and addresses. |
| `hash_binary` | read | SHA-256/SHA-1/MD5 of the binary. |
| `rename_function` | mutate | Rename a function, with read-back verification. |
| `rename_variable` | mutate | Rename a local variable or argument, with read-back verification. |
| `set_comment` | mutate | Set (or clear) a comment at an address. |
| `set_prototype` | mutate | Set a function's C prototype. |
| `set_variable_type` | mutate | Set a local variable's C type. |
| `rizin_help` | rizin REPL (read) | Look up commands in the installed rizin's own help: usage, typed arguments, keyword search. |
| `rizin_command` | rizin REPL (exec) | Run one read-only rizin command the dedicated tools don't cover (`pdsf`, `agc`, `px`, `ph entropy`, `/x`, `/R`, `aoe`, …). |
| `rizin_cli` | rizin CLI (exec) | Run a standalone rizin CLI tool (`rz-bin`, `rz-diff`, `rz-hash`, `rz-find`, `rz-asm`, `rz-ax`) with its own arguments. |
| `rizin_debug` | debugger (exec) | Dynamic analysis: launch the binary under rizin's debugger and drive it (breakpoints, continue, step, registers, memory, backtrace). Opt-in via `OMPRE_ENABLE_DEBUGGER`. |
| `triage_capa` | triage | Run capa rules (capabilities, ATT&CK techniques). |
| `triage_floss` | triage | Extract obfuscated strings (FLOSS). |
| `triage_die` | triage | Detect packers/compilers/file types (Detect It Easy). |
| `triage_yara` | triage | Scan with user-supplied YARA rules. |

Every mutate tool follows resolve → read-old → write → read-back → verify,
and throws with what rizin actually stored rather than reporting success when
the mutation did not land as requested. `/re undo` reverses the most recently
applied annotation. Every free-text and type argument reaches rizin as a
single-quoted literal, so a comment like `x; !id` is stored as text, never
run.

## Configuration

Three environment variables, all optional:

| Variable | Default | Effect |
| --- | --- | --- |
| `OMPRE_RIZIN_PATH` | `rizin` | Path to the rizin executable; its sibling `rz-*` tools are taken from the same directory. |
| `OMPRE_RIZIN_LOAD_USER_CONFIG` | unset | By default omp-re spawns rizin with `-N` so your `rizinrc` can't change the output it parses. Set (`1`/`true`) to load your rizinrc (e.g. for a custom `dir.plugins`). |
| `OMPRE_ANALYSIS_TIMEOUT_MS` | `300000` | Budget for the one-time `aaa` analysis run on open. |
| `OMPRE_DECOMPILER` | `pdg,pdd` | Comma-separated decompiler command priority; names a plugin's command. Built-ins stay as a fallback. |
| `OMPRE_ENABLE_DEBUGGER` | unset | Set (`1`/`true`) to register `rizin_debug`, which **executes** the sample under rizin's debugger. Off by default. |
| `OMPRE_DEBUG_TIMEOUT_MS` | `60000` | Budget for one debugger continue/step before the stuck debuggee is killed. |
| `OMPRE_AUDIT_HMAC_KEY` | unset | HMAC-SHA256 key for signing audit log lines. Unset → lines are written unsigned plus a one-time warning. |

## Docs

- [`docs/install.md`](docs/install.md) — installing rizin and the decompiler plugins.
- [`docs/workflow.md`](docs/workflow.md) — the evidence chain, branches, and the report gate.
- [`docs/tools.md`](docs/tools.md) — full parameter tables for all 26 tools.
- [`docs/testing.md`](docs/testing.md) — the three test tiers and what each needs.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — setup, style, and the QA harness's two hard rules.
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability, analysis hygiene.

## Known limitations

- **A notify raised while the code view is open can render underneath it.**
  Panels now close before reporting "nothing to open", and Enter on an
  evidence row cites it into the editor, so this only affects the code view's
  own `d` notice when a function has no decompiler output. Full writeup:
  [`test/QA-FINDINGS.md`](test/QA-FINDINGS.md) §1.
- **Annotations made by a `re-analyst` subagent stay in that subagent's
  rizin process.** They are not merged back into the parent session; the
  agent is instructed not to annotate unless asked.
- **`/re report` withholds the entire report, not just the ungrounded part,**
  when any claim has zero backing evidence ids — see
  [`docs/workflow.md`](docs/workflow.md) for why that's the point, not a bug.
- **Renaming a function can change rizin's idea of its prototype.** rizin
  drops a known library prototype (e.g. `int main(int argc, char **argv,
  char **envp)`) once the function no longer carries that name; set it back
  with `set_prototype` if it matters.

## License

MIT — see [LICENSE](LICENSE).
