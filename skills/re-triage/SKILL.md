---
name: re-triage
description: First-pass reverse engineering of a binary using omp-re's `run` tool (rizin behind it). Use whenever asked to analyse, reverse, triage, decompile, characterise, or unpack an executable, and when a binary has just been opened and no findings exist yet.
---

# RE with omp-re

omp-re is one tool, `run`: it executes TypeScript/JavaScript in a namespace
that persists for the session. `re` in that namespace is the RE workspace —
every operation is `await re.<name>({ ...params })`. Call `run` with empty
`code` for the manual, and `describe(re)` for the operations this install
actually has, with their signatures (`describe(re.decompile_function)` shows
one in full). A method with one required parameter also takes it bare:
`await re.decompile_function("main")`.

Write helpers. Top-level functions you define persist across calls, and
top-level functions, classes, and static consts are kept across restarts:
when you find yourself repeating a sequence (page through every string,
decompile every caller of an import, pull a field out of JSON output), make
it a function once and reuse it. `kept()` lists what is kept;
`forget(name)` drops one. Raw rizin is `await re.rz()` (`cmd`, `cmdj`) —
fine for exploring, but nothing it returns is evidence. MCP servers omp is
configured with are reachable as functions: `await mcp.servers()`, then
`const s = await mcp.connect("name")` and `await s.<tool>({ ... })`. If a
call is cancelled the namespace resets: kept definitions reload, other
variables are gone.

The `re` methods are the only source of recorded evidence in this session.
Anything learned another way — `bash`, `cat`, a pasted dump, prior knowledge,
or `re.rz()` — has no evidence id behind it, and `/re report` withholds the
**entire** report if any claim in it is unbacked. Get findings through the
`re` methods.

When you reach a conclusion, record it with `re.record_finding`: the claim,
stated as narrowly as the evidence supports, plus the evidence ids behind it
(every observing method's result ends with an `[evidence xxxxxxxx]` tag, and
each `run` result lists the evidence it recorded; cite those 8 characters).
That is how a conclusion gets into the report. A finding is refused if an id
doesn't resolve or the support auditor judges the claim more than the
evidence shows. Read the reason, then narrow the claim or gather better
evidence. Prefer `re.rizin_command` evidence (`pdf @ sym.x`, `px 64 @ addr`)
for findings that matter: only reproducible evidence carries to the next
build with `/re carry`. Revise a finding with `supersedes`, and withdraw one
with `re.retract_finding`.

## Start here

`await re.open_binary({ path })` (or `/re open <path>`) spawns rizin, runs
full analysis, and populates the status band. Nothing works until a binary is
open — every method rejects with `omp-re: no binary open` first. A task
subagent starts with no binary open: its first `run` must open it.

There is no `/re triage`. The subcommands are: `open <path>`, `functions`,
`strings`, `imports`, `evidence [id]`, `cite <id>`, `undo`, `report [path]`,
`findings [id]`, `verify`, `carry <manifest>`, `status`, `on`, `off`, `help`.

For a self-contained analysis, delegate to the `re-analyst` agent with the
binary path and the question; it returns findings tied to tool output. Its
evidence lives in its own session, so to put a subagent finding in this
session's report, `re.adopt_finding` it: pass the claim, its `reproduce`
lines as `commands` (split `cmd @ addr` into `command` + `addr`),
`source: "re-analyst"` and its `sha256` as `expect_sha256`. The commands are
re-run here and the claim is gated like any finding. Don't hand-copy a
subagent claim into `re.record_finding`.

## Order of work

Do not skip ahead — later steps depend on evidence the earlier ones record.
Several steps fit in one `run` call; print what you need to see.

1. `re.hash_binary()` — establish identity before anything else.
2. `re.list_segments()`, `re.list_imports()`, `re.list_exports()` — shape
   and external surface.
3. `re.list_strings({ filter })` when the set is large — never page blindly
   through thousands.
4. `re.list_functions()` — `sort: "callers"` surfaces the most-used helpers,
   `sort: "size"` the biggest logic; then `re.get_function` on the handful
   that matter (it lists what each one calls, by name, and who calls it). If
   the list looks sparse for the binary's size (a stripped, Go, or
   Objective-C target), run `re.analyze` with `preludes`, `golang`, or `objc`
   to recover more functions before reading.
5. `re.decompile_function` only on functions you have a reason to read.
6. `re.triage_capa` when it exists — it is the only source that grounds
   ATT&CK and verdict claims.

A triage method exists only when its binary was on PATH at load:
`re.triage_capa` needs `capa`, `re.triage_floss` needs `floss`,
`re.triage_die` needs `diec`, `re.triage_yara` needs `yara`. A missing method
means the binary is absent, not that a call failed; `describe(re)` shows
what is there.

Long output ends with `[Output truncated … Full output: artifact://N]`;
`read` that artifact when the part that was cut matters.

## Beyond the dedicated methods

The methods above cover the common path. For the rest of rizin — function
summaries (`pdsf`), call graphs (`agc`), hexdumps (`px`), entropy
(`ph entropy`), byte and ROP-gadget searches (`/x`, `/R`), ESIL emulation
(`aoe`), headers (`iH`) — use the installed rizin's own CLI:

1. `re.rizin_help({ query })` with a command prefix (`ph`, `/R`, `ag`) for
   its usage and typed arguments, or with keywords (`entropy`, `call graph`)
   to find one. It answers from the rizin actually installed, so its syntax is
   right for this version, and it marks the commands `re.rizin_command` will
   refuse.
2. `re.rizin_command({ command, addr })` with that one command; put the
   address in `addr`, never `@` in the command (the only `@` allowed is
   `@!<n>`, a block size, e.g. `ph entropy @!4096`). If rizin rejects the
   arguments its error comes back; fix them from `re.rizin_help` instead of
   guessing.

`re.rizin_command` output is recorded evidence like any other observation.
It runs read-only commands only: annotate with the dedicated methods so
annotations are recorded, verified, and undoable.

For rizin's standalone CLI programs, use `re.rizin_cli`: `rz-bin` for quick
headers/imports/strings, `rz-diff` to compare two binaries (e.g. two versions
of a sample), `rz-hash` for hashing and entropy, `rz-find` for raw pattern
search, `rz-asm` for one-off (dis)assembly, `rz-ax` for base conversion. Pass
the tool's own flags in `args`, `@binary` for the open file, and `["-h"]`
when unsure of a flag. It is argv-only; flags that write, run code, or fetch
over the network are refused.

Long literal text — a YARA rule, C declarations for `re.define_types`, a
byte pattern — goes in `run`'s `strings` argument and is read as
`strings.<name>`, so nothing needs escaping inside the code.

## Dynamic analysis (only if enabled)

`re.rizin_debug` is present only when the operator set
`OMPRE_ENABLE_DEBUGGER`, because it **runs the sample**. If it exists and the
task calls for runtime behaviour: `start` to launch (stops at entry; pass
`run` for argv/env/stdio), `break_add` or `watch_add` at the addresses you
care about, then `continue`/`continue_to_syscall`/`continue_to_ret`/`step`,
reading `registers`, `read_memory`, `backtrace`, and — when the sample
unpacks or rewrites itself — `disassemble` of *live* memory at each stop;
`write_register` and `write_memory` can nudge a branch.
`heap_arenas`/`heap_chunks`/`heap_bins` (glibc) and `heaps`/`heap_blocks`
(Windows) inspect the allocator. `stop` when done. Dynamic observations are
real but volatile — hedge them and never treat a single run as exhaustive.
Keep static annotations in the annotate methods.

For code that only computes (a decryptor, an argument builder) without
syscalls, `re.rizin_emulate` interprets it in rizin's RzIL VM with no OS
process — safer than the debugger and enabled by default.

## Navigating

`alt+g` opens the function navigator, `alt+s` the strings panel, `alt+i` the
imports panel; type to filter. In the code view: `d` toggles decompiled C, `x`
follows the selected cross-reference, `a` hands the function to the model with
a grounding prompt, `Escape` goes back.

`/re evidence` lists what has actually been recorded on this branch;
`/re cite <id>` pulls one entry into your next message so a follow-up carries
its context. From code, `re.evidence()` and `re.findings()` return the same
records.

## Annotating

`re.rename_function`, `re.rename_variable`, `re.set_comment`,
`re.set_prototype`, `re.set_variable_type`, `re.define_function` (for a
function rizin missed), `re.set_calling_convention` (to fix argument
recovery), `re.set_flag` (to name an address), and `re.set_arch_hint` (to
disassemble a region as a different arch/word size, e.g. ARM Thumb) write
back into the rizin session and record annotations. Each verifies its own
read-back and reports what rizin actually stored. `/re undo` reverts the last
one. Annotations are re-applied automatically when the session is resumed or
rizin restarts. `re.apply_signatures` names library functions from a FLIRT
file (also replayed on resume).

## Grounding rules

- Every address you name must have come from tool output in this session. Never
  infer an address arithmetically and never carry one over from another binary.
- Quote the `ea` field a method returned. Do not convert decimal offsets yourself.
- When `re.decompile_function` output begins `(disassembly only — …)`, it is
  disassembly, not decompiled code: say so before drawing behavioural
  conclusions from it.
- Hedge genuine hypotheses ("this resembles…", "possibly…"). Hedged reasoning is
  legitimate; an unhedged claim with no evidence is not.
- Absence of evidence is a finding. "No network imports observed" beats silence.
