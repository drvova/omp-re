---
name: re-triage
description: Reverse engineering of a binary with omp-re's rizin engine, driven from the eval tool. Use whenever asked to analyse, reverse, triage, decompile, characterise, or unpack an executable, to annotate one, to record evidence-backed findings about it or write its report, and when a binary has just been opened and no findings exist yet.
---

# RE with omp-re

## How you reach the engine

omp-re adds no tool of its own. Everything goes through the `eval` tool, with
one library that this skill ships and you load into the kernel you are writing
for. Load it once, in a cell **that holds only the load line**:

| `language` | Load line | Global | Calls are |
| --- | --- | --- | --- |
| `"js"` | `%load skill://re-triage/recipes.js` | `re` | async: `await` every one |
| `"py"` | `%load skill://re-triage/recipes.py` | `omp_re` | plain calls, nothing awaited |

Use the language `eval` offers you; the two libraries are the same functions
and act on the same session, so what one opened the other reads. **In Python
the global is `omp_re`, not `re`:** `re` there is the standard library's regex
module, which omp has already imported into every Python cell.

Load again whenever the kernel was lost — a cell fails with `re is not
defined` or `name 'omp_re' is not defined`, and omp-re adds the load line to
that error. A JavaScript kernel is lost when a cell runs past its timeout or is
interrupted, and when a session is resumed; a Python kernel survives a timeout
and an interrupt.

```js
await re.open("/path/to/binary");                      // spawn rizin + full analysis; do this first
const { data: functions, evidence } = await re.json("aflj");   // a *j command, as data
for (const f of functions.sort((a, b) => b.nbbs - a.nbbs).slice(0, 10))
  print(await re.cmd("pdsf", f.name));                  // one read-only command, as text
```

```python
omp_re.open("/path/to/binary")
functions, evidence = omp_re.json("aflj")
for f in sorted(functions, key=lambda f: -f["nbbs"])[:10]:
    print(omp_re.cmd("pdsf", f["name"]))
```

| JavaScript | Python | Does |
| --- | --- | --- |
| `await re.open(path, { arch, bits, base, map, format })` | `omp_re.open(path, arch=…, bits=…)` | Open a binary and analyze it. Every other call acts on the binary opened last in this session. The options are for a raw or headerless file. |
| `await re.cmd(command, addr?)` | `omp_re.cmd(command, addr=None)` | Run **one** read-only rizin command; its text. The one way to read the binary. Put an address or symbol in `addr`, never `@` in the command. |
| `await re.json(command, addr?)` → `{ data, evidence }` | `omp_re.json(command, addr=None)` → `(data, evidence)` | The same for a `*j` command, answering the decoded data — whole, even past the size cap — and the id of the evidence record the read left. |
| `await re.call(tool, { name: value })` | `omp_re.call(tool, name=value)` | Any other tool of the engine: annotations, `record_finding`, `rizin_help`, `rizin_cli`, `rizin_emulate`, `analyze`, … |
| `await re.tools()`, `await re.doc(tool)` | `omp_re.tools()`, `omp_re.doc(tool)` | The tools, one line each; one tool's arguments. |
| `await re.slash(line)` | `omp_re.slash(line)` | Run a line: `functions`, `strings`, `imports`, `evidence [id]`, `findings [id]`, `undo`, `verify [--strict]`, `report [path]`, `carry <manifest>`, `help`. The engine's text calls these `/re` lines; this is how you run one. |
| `await re.status()` | `omp_re.status()` | rizin, the open binary, evidence and findings so far. |
| `await re.help()` | `omp_re.help()` | The engine's manual: the command families and the tools. |

- A function answers a string (`json` answers data); `print` it. A read's text
  is the header line (`rizin> <cmd>`), the output, and a last line
  `[evidence xxxxxxxx — cite it in record_finding]`. A text cut by the size cap
  ends with an `[Output truncated … artifact://N]` note: use `re.json` for the
  data, `read("artifact://N")` for the whole text, or run a narrower command.
- A call the engine refuses, or that fails, throws with the engine's words
  (`RuntimeError` in Python); `try`/`catch` it where you can go on.
- Addresses are strings — `"0x401000"`, `"main"`, `"sym.imp.strcpy"`. In
  JavaScript an integer in `re.json` data that is past 2^53 comes as a BigInt.
- End statements with `;` in a JavaScript cell: `eval` rewrites top-level
  destructuring, and without the semicolon the line can join the one before it.
- What you define in `eval` persists across cells and across compaction, until
  the kernel is lost. To keep helpers, write them to a script and `%load` it.
- **A cell has a deadline — 30 seconds unless you set one — and the time the
  engine takes counts.** `open` runs full analysis, which on a large binary
  takes minutes; a decompile can too. Give such a cell a `timeout` (in seconds,
  e.g. `timeout: 600` for an open), and keep a slow call in a cell of its own.
  A cell that is stopped cancels the engine's work on its call; rizin and what
  was analyzed before survive.
- Every `re.cmd`/`re.json` read is one `rizin_command` call: written to the
  audit log and recorded as evidence. Only read-only commands run through it.

## Recipes

The reads every analysis opens with are already composed, in the same library.
Each returns its report as a string — `print` it — and `re.recipes()`
(`omp_re.recipes()`) lists them with their options. The same five in both
kernels, with the same defaults and the same text:

| JavaScript (`await re.…`) | Python (`omp_re.…`) | Answers |
| --- | --- | --- |
| `triage({ maxStrings, maxFunctions })` | `triage(max_strings=…, max_functions=…)` | What the binary is, the build's protections, sections with entropy, what the imports reach, notable strings, the largest functions, entry points. The first call on a new binary. |
| `scanImports({ callers, maxCallers })` | `scan_imports(callers=…, max_callers=…)` | The imports a reviewer stops at (unbounded copies, shell and exec, format sinks, races, weak randomness), why each matters, and who calls it. |
| `inspectFunction(addr, { maxItems })` | `inspect_function(addr, max_items=…)` | One function's shape, variables, callers, callees and the strings it refers to: the context to read before `pdg` at the same address. |
| `findComparisons(addr, { maxItems })` | `find_comparisons(addr, max_items=…)` | Every compare with the branch that follows it and where each way leads, calls that compare or validate, strings on the way: the skeleton of validation logic. |
| `findCrypto({ references })` | `find_crypto(references=…)` | rizin's key and certificate search, and where the published constants of common algorithms lie. |

A recipe is code over `rizin_command`, so each read it makes is audited and
recorded as evidence like one you make yourself. Every section of a report
cites the `[evidence xxxxxxxx]` id of the read it rests on and the report ends
with the reads it took. A line of a report is a lead to open, not a finding: a
claim still goes through `record_finding` with those ids, and an import or a
constant table being present says nothing yet about how it is used.

## Evidence

The engine is the only source of recorded evidence in this session. Anything
learned another way — `bash`, `cat`, a pasted dump, prior knowledge — has no
evidence id behind it, and `re.slash("report")` withholds the **entire** report
if any claim in it is unbacked. Get findings through the engine.

When you reach a conclusion, record it with `record_finding`: the claim, stated
as narrowly as the evidence supports, plus the evidence ids behind it (every
`rizin_command` read ends with an `[evidence xxxxxxxx …]` tag and `re.json`
hands you the id; cite those 8 characters — no other tool's result is
evidence).

```js
await re.call("record_finding", { claim: "main copies argv[1] into a 64-byte stack buffer with strcpy.", evidence: [evidence], addr: "main", confidence: "confirmed" });
```

That is how a conclusion gets into the report. A finding is refused if an id
doesn't resolve or the support auditor judges the claim more than the evidence
shows. Read the reason, then narrow the claim or gather better evidence. Prefer
`rizin_command` evidence (`pdf` at `sym.x`, `px 64` at an address) for findings
that matter: only reproducible evidence carries to the next build with
`re.slash("carry <manifest> --inherit")`, which answers the findings that hold
and, under them, the agenda of those you have to look at again. Revise a
finding with `supersedes`, and withdraw one with `retract_finding`.

## Start here

`re.open(path)` spawns rizin, runs full analysis, and populates the status
band. Nothing works until a binary is open — every read answers
`omp-re: no binary open` first. A task subagent starts with no binary open and
no library loaded: its first cells are the load line and `re.open`.

For a self-contained analysis, delegate to the `re-analyst` agent with the
binary path and the question; it returns findings tied to what it read. Its
evidence lives in its own session, so to put a subagent finding in this
session's report, `adopt_finding` it: pass the claim, its `reproduce` lines as
`commands` (split `cmd @ addr` into `command` + `addr`), `source: "re-analyst"`
and its `sha256` as `expect_sha256`. The commands are re-run here and the claim
is gated like any finding. Don't hand-copy a subagent claim into
`record_finding`.

## Order of work

Do not skip ahead — later steps depend on evidence the earlier ones record. Run
each with `re.cmd`/`re.json`; `rizin_help` gives a command's exact arguments
for the installed rizin.

1. Identity first: `rizin_cli` with `rz-hash` (or the command `ph sha256`) —
   hash the bytes before anything else.
2. Shape and external surface: `iSj` (sections), `iij` (imports), `iEj`
   (exports), `iHj` (headers), `ij` (bin info). `re.triage()` takes these for
   you.
3. `izj` (strings); for a large set find a narrower search with `rizin_help`
   rather than paging thousands.
4. Functions: `aflj` lists them (each row has `offset`, `name`, `nbbs` blocks,
   `size`); sort by callers or size and read the handful that matter with
   `afij` at the function (signature, args, callers/callees) and `pdsf`
   (summary). If the list looks sparse for the binary's size (stripped, Go, or
   Objective-C), call `analyze` with `preludes`, `golang`, or `objc` to recover
   more functions first.
5. Decompile only functions you have a reason to read: `pdg` (rz-ghidra) or
   `pdd` (jsdec) at the function. If neither plugin is installed those error —
   fall back to `pdf` (annotated disassembly) and say it is disassembly, not
   decompiled C, before drawing behavioural conclusions.
6. `triage_capa` when `re.tools()` lists it, for a fast read of capabilities
   and ATT&CK techniques. Its result is a lead, not evidence: confirm what it
   points at with a read before a finding cites it.

A triage tool is offered only while its program is on PATH: `triage_capa`
needs `capa`, `triage_floss` needs `floss`, `triage_die` needs `diec`,
`triage_yara` needs `yara`. A tool `re.tools()` does not list is absent, not
broken.

## Playbooks

For a task beyond first-pass triage — deep-function review, vulnerability
hunting, crackme/constraint recovery, IOC extraction, exploit-dev recon,
shellcode or file-format triage, diffing two binaries, or emulation — `read`
the sibling file `skill://re-triage/playbooks.md`. Each playbook composes
reads, the stateful tools, and `rizin_emulate` into the kind of analysis other
suites expose as a single tool, with the exact (version-checked) commands and
the evidence/finding tie-in. They are starting lines to adapt, not scripts to
run blind.

## Finding commands

`rizin_command` — what `re.cmd` and `re.json` run — is the whole of rizin's
read surface: function summaries (`pdsf`), call graphs (`agc`), hexdumps
(`px`), entropy (`ph entropy`), byte and ROP-gadget searches (`/x`, `/R`), ESIL
emulation (`aoe`), config (`e asm.arch`, `el`), metadata, classes, types — not
just the listings above. When you don't know the command or its arguments:

1. `await re.call("rizin_help", { query: "ph" })` with a command prefix (`ph`,
   `/R`, `ag`) for its usage and typed arguments, or with keywords (`entropy`,
   `call graph`) to find one. It answers from the rizin actually installed, so
   its syntax is right for this version, and it marks the commands a read will
   refuse.
2. `re.cmd` with that one command; put the address in the second argument,
   never `@` in the command (the only `@` allowed is `@!<n>`, a block size,
   e.g. `ph entropy @!4096`). If rizin rejects the arguments its error comes
   back; fix them from `rizin_help` instead of guessing.

It runs read-only commands only: annotate with the dedicated tools below so
annotations are recorded, verified, and undoable.

For rizin's standalone CLI programs, call `rizin_cli`: `rz-bin` for quick
headers/imports/strings, `rz-diff` to compare two binaries (e.g. two versions
of a sample), `rz-hash` for hashing and entropy, `rz-find` for raw pattern
search, `rz-asm` for one-off (dis)assembly, `rz-ax` for base conversion. Pass
the tool's own flags in `args`, `@binary` for the open file, and `["-h"]` when
unsure of a flag. It is argv-only; flags that write, run code, or fetch over
the network are refused.

## Dynamic analysis (only if enabled)

`rizin_debug` is offered only when the operator set `OMPRE_ENABLE_DEBUGGER`,
because it **runs the sample**. If `re.tools()` lists it and the task calls for
runtime behaviour: `start` to launch (stops at entry; pass `run` for
argv/env/stdio), `break_add` or `watch_add` at the addresses you care about,
then `continue`/`continue_to_syscall`/`continue_to_ret`/`step`, reading
`registers`, `read_memory`, `backtrace`, and — when the sample unpacks or
rewrites itself — `disassemble` of *live* memory at each stop; `write_register`
and `write_memory` can nudge a branch. `heap_arenas`/`heap_chunks`/`heap_bins`
(glibc) and `heaps`/`heap_blocks` (Windows) inspect the allocator. `stop` when
done. Dynamic observations are real but volatile — hedge them and never treat
a single run as exhaustive. Keep static annotations in the annotation tools.

For code that only computes (a decryptor, an argument builder) without
syscalls, `rizin_emulate` interprets it in rizin's RzIL VM with no OS process
— safer than the debugger and enabled by default. Its `step` returns a full
per-instruction read/write trace, so you watch exactly which registers and
branch a candidate input takes. For one-off arithmetic with no VM, the command
`ae <rpn>` is an ESIL calculator (`ae 0x41,0x13,^`); `aoj`/`ao` lifts a single
instruction to its ESIL and RzIL forms. See the emulation playbook in
`playbooks.md`.

## Annotating

`rename_function`, `rename_variable`, `set_comment`, `set_prototype`,
`set_variable_type`, `define_function` (for a function rizin missed),
`set_calling_convention` (to fix argument recovery), `set_flag` (to name an
address), and `set_arch_hint` (to disassemble a region as a different
arch/word size, e.g. ARM Thumb) write back into the rizin session and record
annotations: `await re.call("rename_function", { addr: "fcn.00401000", new: "parse_header" })`.
Each verifies its own read-back and reports what rizin actually stored.
`re.slash("undo")` reverts the last one. Annotations are re-applied
automatically when the session is resumed or rizin restarts.
`apply_signatures` names library functions from a FLIRT file (also replayed on
resume).

## Finishing

`re.slash("evidence")` lists what has been recorded on this branch and
`re.slash("findings")` the conclusions; `re.slash("verify")` re-runs the cited
commands and checks their output still hashes the same; `re.slash("report
out.md")` writes the report and its manifest, and refuses to write a claim
with no evidence under it.

## Grounding rules

- Every address you name must have come from the engine's output in this
  session. Never infer an address arithmetically and never carry one over from
  another binary.
- Quote the address a result gave. Do not convert decimal offsets yourself.
- When no decompiler plugin is installed, `pdg`/`pdd` error and you fall back to
  `pdf` (disassembly): say it is disassembly, not decompiled code, before drawing
  behavioural conclusions from it.
- Hedge genuine hypotheses ("this resembles…", "possibly…"). Hedged reasoning is
  legitimate; an unhedged claim with no evidence is not.
- Absence of evidence is a finding. "No network imports observed" beats silence.
