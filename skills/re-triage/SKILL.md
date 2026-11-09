---
name: re-triage
description: First-pass reverse engineering of a binary using omp-re's rizin tools. Use whenever asked to analyse, reverse, triage, decompile, characterise, or unpack an executable, and when a binary has just been opened and no findings exist yet.
---

# RE with omp-re

## How you reach the tools

omp-re has **one** tool for reading the binary — `rizin_command`, which runs any
read-only rizin command — plus a few stateful tools (open, annotate, findings,
the rz-* CLI, triage, debugger). They are `xd://` devices, not top-level tools:
`read xd://<name>` shows a tool's parameters, `write xd://<name>` calls it. To do
more than one call — loop over functions, filter strings, follow xrefs, build
helpers — use the `eval` tool, where every tool is `await tool.<name>({ ... })`
and you compose rizin commands:

```js
await tool.open_binary({ path: "/path/to/binary" });
const rows = (r) => JSON.parse(r.text.split("\n").slice(1, -1).join("\n"));
for (const f of rows(await tool.rizin_command({ command: "aflj" })).sort((a, b) => b.nbbs - a.nbbs).slice(0, 10))
  print((await tool.rizin_command({ command: "pdsf", addr: f.offset })).text);
```

Call `await tool.rizin_command({ command: "" })` for the full manual (the command
families and the other tools), and `rizin_help` to look up a command's arguments.

- A tool returns `{ text, details }` to `eval`; read `.text`. Its first line is
  the header (`rizin> <cmd>`) and, for an observing command, its last line is the
  `[evidence xxxxxxxx]` tag; a `*j` command's lines in between are JSON, as
  `rows` above parses them (drop the first and last lines). Output cut short by
  the size cap ends with an `[Output truncated … artifact://N]` note and is not
  valid JSON: `read` that artifact, or run a narrower command. A failing tool
  throws; `try`/`catch` it.
- End statements with `;` in `eval`: it rewrites top-level destructuring, and
  without the semicolon the line can join the one before it.
- Functions you define in `eval` persist across cells and across compaction,
  until the kernel is lost: a cell that passes its deadline or is interrupted
  is killed with everything defined in it, and so is a resumed session's. Then
  define them again. To keep RE helpers, write them to a script and `%load` it.
- **A cell has a deadline — 30 seconds unless you set one — and the time a
  tool takes counts.** `open_binary` runs full analysis, which on a large
  binary takes minutes; a decompile can too. Give such a cell a `timeout` (in
  seconds, e.g. `timeout: 600` for an open), and keep a slow call in a cell of
  its own so a loss costs one call. rizin and its analysis survive a killed
  cell; only what eval held is gone.
- `eval`, `xd://`, and top-level calls are the same tool calls: each is
  recorded as evidence, audited, and approved the same way.

## Recipes

The reads every analysis opens with are already composed, in a script that
ships beside this file — one for each of `eval`'s kernels. Load the one for the
language you are writing, once, in a standalone `eval` cell of that language
(omp resolves `skill://<this skill's name>/<file>` to the skill's own
directory, wherever the plugin is installed), and again whenever that kernel
was lost (`re is not defined`, `name 'omp_re' is not defined`):

| `language` | Load | Global | A call |
| --- | --- | --- | --- |
| `"js"` | `%load skill://re-triage/recipes.js` | `re` | `print(await re.triage({ maxStrings: 40 }));` |
| `"py"` | `%load skill://re-triage/recipes.py` | `omp_re` | `print(omp_re.triage(max_strings=40))` |

**In Python the global is `omp_re`, not `re`:** `re` there is the standard
library's regex module, which omp has already imported into every Python cell,
and the recipes leave it alone. Python recipes are plain functions with keyword
options — no `await` (one is tolerated) — while a Python tool call is still
awaited and takes a dict: `r = await tool.rizin_command({"command": "aflj"})`,
then `r["text"]`.

Each function returns its report as a string — `print` it — and `help()` lists
them. The same five in both, with the same defaults and the same text:

| JavaScript (`await re.…`) | Python (`omp_re.…`) | Answers |
| --- | --- | --- |
| `triage({ maxStrings, maxFunctions })` | `triage(max_strings=…, max_functions=…)` | What the binary is, the build's protections, sections with entropy, what the imports reach, notable strings, the largest functions, entry points. The first call on a new binary. |
| `scanImports({ callers, maxCallers })` | `scan_imports(callers=…, max_callers=…)` | The imports a reviewer stops at (unbounded copies, shell and exec, format sinks, races, weak randomness), why each matters, and who calls it. |
| `inspectFunction(addr, { maxItems })` | `inspect_function(addr, max_items=…)` | One function's shape, variables, callers, callees and the strings it refers to: the context to read before `pdg` at the same address. |
| `findComparisons(addr, { maxItems })` | `find_comparisons(addr, max_items=…)` | Every compare with the branch that follows it and where each way leads, calls that compare or validate, strings on the way: the skeleton of validation logic. |
| `findCrypto({ references })` | `find_crypto(references=…)` | rizin's key and certificate search, and where the published constants of common algorithms lie. |

These are not tools: a recipe is `eval` code over `rizin_command`, so each read
it makes is its own tool call — approved, audited, recorded as evidence — and
a recipe reads a list past the size cap whole, from its artifact. Every section
of a report cites the `[evidence xxxxxxxx]` id of the read it rests on and the
report ends with the reads it took. A line of a report is a lead to open, not a
finding: a claim still goes through `record_finding` with those ids, and an
import or a constant table being present says nothing yet about how it is used.

## Evidence

These tools are the only source of recorded evidence in this session. Anything
learned another way — `bash`, `cat`, a pasted dump, prior knowledge — has no
evidence id behind it, and `/re report` withholds the **entire** report if any
claim in it is unbacked. Get findings through the tools.

When you reach a conclusion, record it with `record_finding`: the claim, stated
as narrowly as the evidence supports, plus the evidence ids behind it (every RE
tool result ends with an `[evidence xxxxxxxx]` tag; cite those 8 characters). That is how a conclusion
gets into the report. A finding is refused if an id doesn't resolve or the
support auditor judges the claim more than the evidence shows. Read the reason,
then narrow the claim or gather better evidence. Prefer `rizin_command` evidence
(`pdf @ sym.x`, `px 64 @ addr`) for findings that matter: only reproducible
evidence carries to the next build with `/re carry`. Revise a finding with
`supersedes`, and withdraw one with `retract_finding`.

## Start here

`open_binary` (or `/re open <path>`) spawns rizin, runs full analysis, and
populates the status band. Nothing works until a binary is open — every tool
returns `omp-re: no binary open` first. A task subagent starts with no binary
open: its first call must be `open_binary`.

There is no `/re triage`. The subcommands are: `open <path>`, `functions`,
`strings`, `imports`, `evidence [id]`, `cite <id>`, `undo`, `report [path]`,
`findings [id]`, `verify`, `carry <manifest>`, `status`, `on`, `off`, `help`.

For a self-contained analysis, delegate to the `re-analyst` agent with the
binary path and the question; it returns findings tied to tool output. Its
evidence lives in its own session, so to put a subagent finding in this
session's report, `adopt_finding` it: pass the claim, its `reproduce` lines as
`commands` (split `cmd @ addr` into `command` + `addr`), `source: "re-analyst"`
and its `sha256` as `expect_sha256`. The commands are re-run here and the claim
is gated like any finding. Don't hand-copy a subagent claim into
`record_finding`.

## Order of work

Do not skip ahead — later steps depend on evidence the earlier ones record. Run
each with `rizin_command`; `rizin_help` gives a command's exact arguments for the
installed rizin.

1. Identity first: `rizin_cli` with `rz-hash` (or `rizin_command` `ph sha256`) —
   hash the bytes before anything else.
2. Shape and external surface: `iSj` (sections), `iij` (imports), `iEj`
   (exports), `iHj` (headers), `ij` (bin info).
3. `izj` (strings); for a large set find a narrower search with `rizin_help`
   rather than paging thousands.
4. Functions: `aflj` lists them (each row has `offset`, `name`, `nbbs` blocks,
   `size`); sort in `eval` by callers or size and read the handful that matter
   with `afij @ <fn>` (signature, args, callers/callees) and `pdsf @ <fn>`
   (summary). If the list looks sparse for the binary's size (stripped, Go, or
   Objective-C), run `analyze` with `preludes`, `golang`, or `objc` to recover
   more functions first.
5. Decompile only functions you have a reason to read: `pdg @ <fn>` (rz-ghidra)
   or `pdd @ <fn>` (jsdec). If neither plugin is installed those error — fall
   back to `pdf @ <fn>` (annotated disassembly) and say it is disassembly, not
   decompiled C, before drawing behavioural conclusions.
6. `triage_capa` when it is registered — the only source that grounds ATT&CK and
   verdict claims.

A triage tool exists only when its binary was on PATH at load: `triage_capa`
needs `capa`, `triage_floss` needs `floss`, `triage_die` needs `diec`,
`triage_yara` needs `yara`. A missing tool means the binary is absent, not that
the call failed.

Long output ends with `[Output truncated … Full output: artifact://N]`; `read`
that artifact when the part that was cut matters.

## Playbooks

For a task beyond first-pass triage — deep-function review, vulnerability
hunting, crackme/constraint recovery, IOC extraction, exploit-dev recon,
shellcode or file-format triage, diffing two binaries, or emulation — `read`
the sibling file `playbooks.md` in this skill. Each playbook composes
`rizin_command`, the stateful tools, and `rizin_emulate` into the kind of
analysis other suites expose as a single tool, with the exact (version-checked)
commands and the evidence/finding tie-in. They are starting lines to adapt, not
scripts to run blind.

## Finding commands

`rizin_command` is the whole of rizin's read surface — function summaries
(`pdsf`), call graphs (`agc`), hexdumps (`px`), entropy (`ph entropy`), byte and
ROP-gadget searches (`/x`, `/R`), ESIL emulation (`aoe`), config (`e asm.arch`,
`el`), metadata, classes, types — not just the listings above. When you don't
know the command or its arguments:

1. `rizin_help` with a command prefix (`ph`, `/R`, `ag`) for its usage and typed
   arguments, or with keywords (`entropy`, `call graph`) to find one. It answers
   from the rizin actually installed, so its syntax is right for this version,
   and it marks the commands `rizin_command` will refuse.
2. `rizin_command` with that one command; put the address in `addr`, never `@` in
   the command (the only `@` allowed is `@!<n>`, a block size, e.g.
   `ph entropy @!4096`). If rizin rejects the arguments its error comes back;
   fix them from `rizin_help` instead of guessing.

Every `rizin_command` read is recorded evidence. It runs read-only commands
only: annotate with the dedicated tools below so annotations are recorded,
verified, and undoable.

For rizin's standalone CLI programs, use `rizin_cli`: `rz-bin` for quick
headers/imports/strings, `rz-diff` to compare two binaries (e.g. two versions
of a sample), `rz-hash` for hashing and entropy, `rz-find` for raw pattern
search, `rz-asm` for one-off (dis)assembly, `rz-ax` for base conversion. Pass
the tool's own flags in `args`, `@binary` for the open file, and `["-h"]` when
unsure of a flag. It is argv-only; flags that write, run code, or fetch over
the network are refused.

## Dynamic analysis (only if enabled)

`rizin_debug` is present only when the operator set `OMPRE_ENABLE_DEBUGGER`,
because it **runs the sample**. If it exists and the task calls for runtime
behaviour: `start` to launch (stops at entry; pass `run` for argv/env/stdio),
`break_add` or `watch_add` at the addresses you care about, then
`continue`/`continue_to_syscall`/`continue_to_ret`/`step`, reading
`registers`, `read_memory`, `backtrace`, and — when the sample unpacks or
rewrites itself — `disassemble` of *live* memory at each stop; `write_register`
and `write_memory` can nudge a branch. `heap_arenas`/`heap_chunks`/`heap_bins`
(glibc) and `heaps`/`heap_blocks` (Windows) inspect the allocator. `stop` when
done. Dynamic observations are real but volatile — hedge them and never treat
a single run as exhaustive. Keep static annotations in the mutate tools.

For code that only computes (a decryptor, an argument builder) without
syscalls, `rizin_emulate` interprets it in rizin's RzIL VM with no OS process
— safer than the debugger and enabled by default. Its `step` returns a full
per-instruction read/write trace, so you watch exactly which registers and
branch a candidate input takes. For one-off arithmetic with no VM, `ae <rpn>`
through `rizin_command` is an ESIL calculator (`ae 0x41,0x13,^`); `aoj`/`ao`
lifts a single instruction to its ESIL and RzIL forms. See the emulation
playbook in `playbooks.md`.

## Navigating

`alt+g` opens the function navigator, `alt+s` the strings panel, `alt+i` the
imports panel; type to filter. In the code view: `d` toggles decompiled C, `x`
follows the selected cross-reference, `a` hands the function to the model with
a grounding prompt, `Escape` goes back.

`/re evidence` lists what has actually been recorded on this branch;
`/re cite <id>` pulls one entry into your next message so a follow-up carries
its context.

## Annotating

`rename_function`, `rename_variable`, `set_comment`, `set_prototype`,
`set_variable_type`, `define_function` (for a function rizin missed),
`set_calling_convention` (to fix argument recovery), `set_flag` (to name
an address), and `set_arch_hint` (to disassemble a region as a different
arch/word size, e.g. ARM Thumb) write back into the rizin session and record annotations. Each
verifies its own read-back and reports what rizin actually stored. `/re undo`
reverts the last one. Annotations are re-applied automatically when the
session is resumed or rizin restarts. `apply_signatures` names library
functions from a FLIRT file (also replayed on resume).

## Grounding rules

- Every address you name must have come from tool output in this session. Never
  infer an address arithmetically and never carry one over from another binary.
- Quote the `ea` field a tool returned. Do not convert decimal offsets yourself.
- When no decompiler plugin is installed, `pdg`/`pdd` error and you fall back to
  `pdf` (disassembly): say it is disassembly, not decompiled code, before drawing
  behavioural conclusions from it.
- Hedge genuine hypotheses ("this resembles…", "possibly…"). Hedged reasoning is
  legitimate; an unhedged claim with no evidence is not.
- Absence of evidence is a finding. "No network imports observed" beats silence.
