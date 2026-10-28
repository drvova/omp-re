# Tool reference

All 64 `omp-re` tools, grouped by tier. Triage tools register only when their
backing binary is on PATH at load time, so your own tool list may legitimately
show fewer than 64 (the debugger needs OMPRE_ENABLE_DEBUGGER too).

Every tool is registered `discoverable`, so omp presents it as an `xd://<name>`
device rather than a top-level tool: `read xd://<name>` shows its
documentation, `write xd://<name>` calls it, and omp's `eval` calls it as
`await tool.<name>({ ...params })`, which returns `{ text, details }` and
throws on failure. The parameter tables below are the same on every path.

Every tool follows omp's standard `ToolDefinition` shape: `approval` gates
whether omp prompts before running it (`tools.approvalMode` /
`tools.approval.<name>` in your omp config), every tool has its own
transcript renderer, and every read-tier and `rizin_command` call also
becomes a `re.evidence` entry — see [`workflow.md`](workflow.md). All tools honor
cancellation.

Output larger than the context cap (2000 lines or 50 KB) is truncated for the
model and saved in full to the session's artifact store; the result ends with
`[Output truncated: … Full output: artifact://<id>]` and the model can `read`
that artifact. List results are JSON arrays with one compact row per line.

## Guide (2 meta tools)

Two always-present meta tools bootstrap the rest. They are **not** counted in the
64: they spawn no rizin, need no open binary, record no evidence, and are not
disabled by `/re off` (they stay readable when the tools are off). They are the
in-namespace vocabulary for omp's `eval` host — `man()` and `describe()` — since
omp's extension API exposes no way to seed the eval namespace directly.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `re_manual` | `read` | (none) | **Start here.** The entry manual: the paradigm (every capability is an `xd://<name>` device driven from `eval` as `await tool.<name>({ … })`, with omp's `eval` the single code host), how to open a binary, the capability map, the evidence/report workflow, and the config env vars. |
| `re_describe` | `read` | `name?` | Lists every **live** capability with its call signature and one-line purpose; with `name`, the full parameters and docs for one. The live source of truth for what `tool.<name>()` you can call — triage and debugger capabilities appear only when actually registered. |

## Session (3 tools)

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `open_binary` | `read` | `path: string` | Spawns rizin on a binary and runs full analysis (`aaa`), streaming progress. Re-applies annotations this branch already recorded for the same binary. Every other RE tool acts on whichever binary was most recently opened — a `task` subagent must call this first. |
| `export_project` | `exec` | `file?` | Saves the current analysis — functions, names, comments, flags, types, including every annotation omp-re applied — to a rizin project (`.rzdb`, via `Ps`) so it can be opened in interactive rizin or Cutter (`rizin -p <file>`). Written to omp-re's output directory, never the sample. Export only: omp-re manages analysis state through its own session log and does not load projects. |
| `map_file` | `exec` | `path, addr, perm?` | Opens an additional file into the current session at a virtual address (`o <file> <addr>`) alongside the primary binary — overlay a dumped/unpacked region, or map a library for cross-module analysis. Mapped read-only (the file on disk is never written); the map is re-applied on resume/respawn (recorded like analysis passes). To analyze a dump on its own, use `open_binary`. Not undoable — reopen to drop the map. |

## Read tier (31 tools)

Every read-tier call that succeeds is recorded as a `re.evidence` entry.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `list_functions` | `read` | `offset?, limit?, sort?` | Functions as `{ea, name, size, span?, blocks, callers, callees, signature}`. `size` is bytes of code (rizin's `realsz`); `span`, rizin's linear extent, appears only when it differs — a sign of scattered blocks. `sort` is `address` (default), `size`, or `callers`. |
| `search_functions` | `read` | `query, offset?, limit?` | Same rows, filtered by name substring. |
| `get_function` | `read` | `target` (name or address) | One function: signature, size and complexity metrics, `args`/`locals` with types and storage, `calls` (unique call targets, named via rizin's flags), `callers` (call sites that reach it), and `refCounts`. Raw jump/data reference arrays are reduced to counts. |
| `decompile_function` | `read` | `addr` (address or name) | Decompile with rz-ghidra (`pdg`) or jsdec (`pdd`), header `decompiled <ea> (<kind>)`. With neither — or when the decompiler returns nothing for this function — returns annotated disassembly whose output begins `(disassembly only — …) `. |
| `disassemble_function` | `read` | `addr` | Annotated instructions: comments, flags/labels, and incoming xrefs folded in. |
| `get_xrefs_to` | `read` | `addr, offset?, limit?` | Cross-references pointing at an address, with `fromEa`/`toEa`. |
| `get_xrefs_from` | `read` | `addr, offset?, limit?` | Cross-references originating from the instruction at an address (per instruction — use `get_function`'s `calls` for a whole function). |
| `list_imports` | `read` | `offset?, limit?` | Imported symbols, with the PLT stub as `ea` when there is one. |
| `list_exports` | `read` | `offset?, limit?` | Exported symbols. |
| `list_symbols` | `read` | `offset?, limit?, filter?` | The full symbol table (`is`) — local/internal functions and data symbols with name, type, bind, size, and `ea`; a superset of imports/exports. `filter` matches the name. |
| `list_strings` | `read` | `offset?, limit?, filter?` | Strings in data sections, optionally filtered by substring. |
| `list_segments` | `read` | `offset?, limit?` | Sections with permissions, sizes, and addresses. |
| `hash_binary` | `read` | (none) | SHA-256, SHA-1, and MD5 digests of the open binary. |
| `get_graph` | `read` | `kind` (`function_cfg`/`callgraph`/`xrefs`/`imports`), `addr?`, `offset?, limit?` | Rizin's analysis graphs as JSON (`agf`/`agc`/`agx`/`agi`): a function's control-flow graph, the callgraph from a function, the xref graph around an address, or the import graph. Returns nodes (address + label) and their edges resolved to addresses. `addr` required except for `imports`. |
| `deobfuscate` | `read` | `addr, size, op, key?, algo?, iv?` | Reveal obfuscated bytes in place: xor/add/sub/or/and with a `key`, an endian swap, or `decrypt` with `algo`+`key`(+`iv`) — shown as hex and string. Runs under the write cache and resets it, so the file is never modified. |
| `search_bytes` | `read` | `pattern` (hex), `in_function?, offset?, limit?` | Raw-byte search (`/xj`) as `{ea, size, flag}` rows; `..` masks one nibble. |
| `search_string` | `read` | `pattern` (string), `in_function?, offset?, limit?` | Literal string search over raw bytes (hex-encoded client-side, then `/xj`) — finds matches everywhere, including code pages. |
| `search_regex_bytes` | `read` | `pattern` (regex), `in_function?, offset?, limit?` | Raw-byte regex search (`/xrj`) for shaped patterns (e.g. variable displacements). |
| `search_asm` | `read` | `instructions`, `in_function?, offset?, limit?` | Assemble instruction text with the binary's arch config and search for the resulting bytes (`/aj`). |
| `search_value` | `read` | `width` (1/2/4/8), `value` or `min`+`max`, `in_function?, offset?, limit?` | Immediate-value search (`/vNj` exact, `/VNj` range) — hardcoded constants, magic numbers, pointers. |
| `search_gadgets` | `read` | `kind` (`rop`/`cop`), `filter?, in_function?, offset?, limit?` | ROP/COP gadget chains natively: a text-mode run primes rizin's gadget cache, then `/Rj`/`/Cj` returns `{ea, size, gadgets}` rows (each opcode carries its own address and type). `filter` is rizin's own gadget filter string. |
| `list_types` | `read` | `kind` (`struct`/`enum`/`typedef`/`function`), `filter?, offset?, limit?` | Types loaded in rizin's database (`tsj`/`tej`/`ttj`/`tfj`) — the built-in Windows type base plus debug-info and user-defined types. |
| `define_types` | `read` | `definitions: string[]` | Define types from C statements (`td`, one declaration per entry; names used must be defined first). Rizin's errors surface verbatim. |
| `cast_memory` | `read` | `addr`, `type` | Print memory at an address interpreted as a named type (`tp`). |
| `list_syscalls` | `read` | `filter?, offset?, limit?` | The active syscall profile (`aslj`) — on a PE binary, the Windows Nt* interface, as `{name, swi, num}` rows. |
| `syscall_lookup` | `read` | `name` or `number` (exactly one) | Resolve a syscall name to its number (`asn`) or number to its name (`asr`). |
| `get_binary_info` | `read` | (none) | Binary identity object (`iIj`): arch, bits, base address, format, class, compiler, sizes, checksums. |
| `list_entrypoints` | `read` | (none) | Entry points (`iej`) as `{ea, type, headerAddr}`. |
| `list_relocations` | `read` | `offset?, limit?` | Load-time relocations (`irj`) as `{ea, type}`. |
| `list_flags` | `read` | `filter?, offset?, limit?` | All flags rizin knows (`flj`) as `{ea, name, size}` — analysis, reloc, and section labels. |
| `list_classes` | `read` | `filter?, offset?, limit?` | Classes from binary metadata (`icj`) — C++ RTTI, Objective-C, Swift; empty on plain C binaries. |

`offset`/`limit` default to 0/200 and cap at 1000; every paginated result
reports its total so the model knows a view is partial. An empty page is
marked as compactable, so omp can drop it from context once it has been read.

Every `search_*` tool accepts `in_function` (an address or name): the search
is restricted to that function's extent (rizin's `search.in=range` plus
`search.from`/`search.to`), and the previous scope is always restored
afterward. Omit it to search the whole binary.

## Mutate tier (15 tools)

Every mutate tool follows resolve → read-old → write → read-back → verify: it
throws with what rizin actually stored rather than reporting success when the
requested mutation did not land. Annotations are keyed on the function's
start address (or the exact address, for comments). `/re undo` reverses the
most recently applied annotation, and the session replays annotations into a
fresh rizin process on resume or respawn. Each approval prompt states the
exact change (e.g. `Rename function "main" to "parse_args". Reversible with
/re undo.`).

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `rename_function` | `write` | `addr, new` | Rename a function. |
| `rename_variable` | `write` | `addr, old, new` | Rename a local variable or argument; an unknown `old` lists the variables that exist. |
| `set_comment` | `write` | `addr, text` (empty clears) | Set or clear the comment at an address, replacing any existing one. Text is stored literally. |
| `set_prototype` | `write` | `addr, sig` | Set a function's C prototype; the name in it becomes the function's name. If rizin's C parser normalizes it differently, the error shows what it stored. |
| `set_variable_type` | `write` | `addr, var, type` | Set a local variable's C type. |
| `define_variable` | `write` | `addr, storage, location, name, type?` | Define a local variable analysis missed — a stack slot (`storage: stack`, `location` a frame delta, `afvs`) or a register variable (`storage: reg`, `location` a register, `afvr`) — so the decompiler names it. Refuses a name that already exists; `/re undo` runs `afv-`. |
| `define_function` | `write` | `addr` | Define a function where auto-analysis missed one (`af`); refuses when a function already begins there, verifies one now does. `/re undo` runs `af-`. |
| `define_global` | `write` | `addr, name, type` | Define a global variable at a data address (`avga`), naming and typing it so disassembly, xrefs, and the decompiler show the name and typed accesses. Refuses a name that already exists; `/re undo` runs `avgm`. |
| `set_calling_convention` | `write` | `addr, cc` | Set a function's calling convention (`afc`); an unknown convention is rejected with rizin's own error (list with `rizin_command afcl`). |
| `set_flag` | `write` | `addr, name` | Name an address with a flag (`f`), replacing any flag already there; `/re undo` restores the previous flag (or removes it). |
| `set_arch_hint` | `write` | `addr, arch?, bits?` | Hint the architecture and/or word size to disassemble from an address (`aha`/`ahb`) — e.g. `bits: 16` for an ARM Thumb region, or `arch` for mixed-arch firmware. `/re undo` deletes the hint. |
| `set_hint` | `write` | `addr, hint, value` | Set an analysis hint that corrects how rizin reads one instruction: `immediate_base` (how an operand is shown — hex/decimal/char/string/syscall/IP-relative, `ahi`), `opcode_type` (reclassify, `aho`), `opcode_size` (force byte-length to realign disassembly, `ahs`), `jump_target` (the real target of an indirect jump/call, `ahc`), or `return_value` (`ahr`). Records what rizin stored; `/re undo` deletes it or restores the prior hint. |
| `set_data` | `write` | `addr, size, count?` | Mark bytes as a data element/array (`Cd`) so they stop rendering as code. `/re undo` removes the mark. |
| `set_string` | `write` | `addr, size?` | Mark bytes as a string (`Cs`); omit `size` to autodetect. Correctly no-ops on non-string bytes. `/re undo` removes it. |
| `set_format` | `write` | `addr, size, format` | Overlay a pf struct format (with field names) on a region (`Cf`) so disassembly shows named fields. Display-only. `/re undo` removes it. |

## Findings (3 tools)

The model's own conclusions, recorded as report claims (`re.finding` entries).
A finding is gated when it is recorded, while the model can still act on the
result, and again at `/re report`. It lands in the report's **Findings**
section and in the verification manifest, and `/re carry --inherit` re-proves
it on the next build. Neither tool reads the binary, and neither records
evidence.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `record_finding` | `read` | `claim, evidence[], addr?, confidence?, supersedes?, override_audit?` | Records a conclusion backed by evidence ids (exact or a ≥6-character prefix). It is refused when an id doesn't resolve on this branch or was taken against a different binary than the one open. The claim then goes to the same side-turn support audit `/re report` uses. An `unsupported` or `overreach` verdict refuses the finding with the auditor's reason, unless `override_audit` gives a justification, which is kept and shown beside the finding. With no model available the finding is recorded as `unaudited` (fails open). The result says how much of its evidence is machine-reproducible: only `rizin_command` evidence carries to the next build. `supersedes` revises an earlier finding. `confidence` is `confirmed`, `likely` (the default) or `speculative`. |
| `adopt_finding` | `read` | `claim, commands[{command, addr?}], addr?, confidence?, source?, expect_sha256?, override_audit?` | Adopts a finding made somewhere else, typically by the `re-analyst` subagent, whose evidence lives in its own session. Each command is re-run read-only on the open binary through `rizin_command`'s own gate and recorded as evidence in this session, then the claim goes through the same checks as `record_finding`. It is refused if `expect_sha256` (the subagent's `sha256`) doesn't match the open binary, or if a command fails here. If the auditor refuses the claim, the re-run evidence stays recorded so a narrower claim can cite it. The finding is marked "adopted from <source>, re-proven in this session". |
| `retract_finding` | `read` | `id, reason` | Withdraws a finding, which then leaves the report. The reason is kept in the session log. |

## rizin REPL (2 tools)

For everything the dedicated tools don't cover. Both read the catalog the
installed rizin publishes about itself (`rizin -qc '?*j'`, read once per
process with no binary open), so they match the user's rizin version and
plugins exactly.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `rizin_help` | `read` | `query: string` | A command or prefix (`ph`, `afv`, `/R`) lists that family; an exact match adds its typed arguments (required/optional, defaults, choices) and description. Anything else is a keyword search over summaries and descriptions (`entropy`, `rop gadgets`). Entries `rizin_command` would refuse are marked `[not runnable via rizin_command]`. |
| `rizin_command` | `exec` (reason names the command) | `command: string`, `addr?: string` | Runs one read-only command and returns its output, or `(no output)`. When rizin rejects the arguments, its own error and usage text come back as an error result. `addr` is validated like every other address and sent as `@ <addr>`. Times out after 120 s. |

`rizin_command` accepts a command only if all of these hold, checked before
anything reaches rizin:

- **Read-only family**: print (`p…`), info (`i…`), search (`/…`), graphs
  (`ag…`), op/ESIL analysis (`ao…`, `ab…`), xref and function queries
  (`axt`, `axf`, `afl`, `afi`, `afb`, `afx`, `afvl`, `afvx`, `afvR`, `afvW`,
  `afvd`, `afo`, `afM`), comment queries (`CC.`, `CCl`, `CCf`), and flag
  descriptions (`fd…`).
- **Not an exception inside those families**: `pf`/`po`/`pw` (formats and
  writes), `pr`/`prz`/`prg`/`p6d` (raw bytes — a NUL ends a `-q0` frame; use
  `px`, `p8`, or `prx`), `pkill`, `pm`, `/F` (searches a file's content),
  `ag[enw]`, `afb[cer]`, `afii`, `ica`, `id`, or any command name containing
  `+ - = ! *`. A command whose catalog entry takes a file or path argument
  (`/m <magic-file>`) runs only with no arguments.
- **No syntax that leaves the command**: `;`, `|`, `<`/`>`, backticks,
  `$(`/`${`, `~`, `#`, `"`, `\`, line breaks, and every `@` modifier except
  `@!<n>` (a temporary block size, e.g. `ph entropy @!4096`). Seek with `addr`.
- **In this rizin's catalog**, and not an `interactive` output mode.

## rizin CLI suite (1 tool)

`rizin_cli` fronts the standalone `rz-*` executables that ship beside rizin,
for analysis the in-core commands don't cover. It registers only when those
binaries are found next to the configured rizin (or on PATH). Invoked by argv
through omp's `exec` — no shell — so there is no `;`/`|`/`$()` surface; the
gating is on the flags.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `rizin_cli` | `exec` (reason is the full command line) | `tool: enum`, `args: string[]` | Runs one of `rz-bin`, `rz-diff`, `rz-hash`, `rz-find`, `rz-asm`, `rz-ax` with the given arguments. `@binary` in `args` is the open binary's path (auto-appended for `rz-bin`). `args: ["-h"]` returns that tool's own help. Output, or `(no output)`; the tool's stderr comes back as an error result. |

| Tool | Covers | For example |
| --- | --- | --- |
| `rz-bin` | headers, imports, exports, symbols, sections, strings, classes, checksums, demangling — without loading the full core | `rz-bin -I -j` |
| `rz-diff` | compare two files: edit distance or structural (functions, imports, strings, …) | `rz-diff -t functions a.bin b.bin` |
| `rz-hash` | hashes, entropy, checksums of a file or input | `rz-hash -a sha256,entropy @binary` |
| `rz-find` | raw byte/string/regex/symbol search | `rz-find -x 4889e5 @binary` |
| `rz-asm` | standalone assemble / disassemble | `rz-asm -a x86 -b 64 -d 4889e5` |
| `rz-ax` | base and format conversion | `rz-ax 0xdead` |

Refused before the tool is spawned: any flag that runs code (`rz-find
-E`/`-R`, `rz-diff -t command`), writes or extracts to disk (`rz-bin
-O`/`-o`/`-C`/`-x`, `rz-asm -O`), fetches over the network (`rz-bin
-dd`/`-PP`), or opens an interactive view (`rz-diff -H`/`-S`), and any
argument with a line break or NUL. The check is getopt-aware: the flag is
caught whether written split (`-t command`), attached (`-tcommand`), or
clustered (`-ddj`), and a single `-d`/`-P` (local read) stays allowed while
`-dd`/`-d -d`/`-ddj` (network fetch) are refused. rz-gg (shellcode
generation) is not exposed — it generates rather than
analyzes. rz-run is not exposed as a CLI tool either, but its directives
(argv, env, cwd, stdio, limits) do configure the debugger's launch
environment through `rizin_debug`'s `run` option — the one place omp-re
executes a sample.

## Signatures (2 tools)

FLIRT signatures name library functions from a signature database (book:
analysis/signatures). `open_binary`'s analysis (`aaa`) already applies rizin's
built-in database, so this covers what that doesn't: re-applying it on demand,
applying a *custom* `.sig`/`.pat` file — which `rizin_command` can't, because
it refuses file arguments — and creating a new signature from the analyzed
functions. List the built-in database with `rizin_command Flt`.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `apply_signatures` | `exec` | `source` (`sigdb`/`file`), `path?` | `sigdb` re-applies rizin's built-in database (`Fa`); `file` applies the FLIRT file at `path` (`Fs`). Both rename matched functions, so it is exec-tier. A custom file is recorded and re-applied automatically on resume/respawn (like annotations), so the names it produced survive; it is not an undoable annotation. |
| `create_signature` | `exec` | `file?` | Builds a FLIRT signature (`Fc`) from the current binary's analyzed functions — to recognize them in other samples (tracking a routine across a malware family) — written to omp-re's output directory as `.pat` (text patterns, default) or `.sig` (compiled). Reads the analysis, modifies nothing. Apply it elsewhere with `apply_signatures` (`source: file`). |

## Analysis passes — `analyze` (1 tool)

`open_binary`'s `aaa` is the analysis baseline. `analyze` re-runs the deeper
or format-specific passes it skips (book: analysis/code_analysis), each
additive — it finds functions, xrefs, names, or types; none deletes. The pass
is recorded and re-run on resume/respawn (before signatures and annotations,
so each layer sees the one before it), not as an undoable annotation —
reopen the binary to return to the baseline.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `analyze` | `exec` | `pass` (enum) | Runs one pass and reports the function count before/after. `calls` (`aac`), `xrefs` (`aar`), `pointers` (`aav`), `preludes` (`aap` — recovers functions in stripped code), `all_functions` (`aaf`), `data_refs` (`aad`), `autoname` (`aan`), `types` (`aaft`), `struct_offsets` (`aat`), `golang` (`aalg`), `objc` (`aalor`), `rtti_classes` (`avrr` — C++ classes from RTTI), `emulate_functions` (`aaef` — thorough, slow). A pass that doesn't apply (e.g. `golang` on a non-Go binary) surfaces rizin's own message and records nothing. |

## Dynamic analysis — `rizin_debug` (1 tool, opt-in)

`rizin_debug` launches the open binary under rizin's debugger and drives it.
It **executes the sample**, so it registers only when `OMPRE_ENABLE_DEBUGGER`
is set, runs in a debug session separate from the static one (which never
executes the file), and is killed with its debuggee on `stop` or session
shutdown. Run untrusted samples only in an isolated, disposable environment.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `rizin_debug` | `exec` (the reason says plainly when an action executes, modifies, or inspects) | `action: enum`, `addr?`, `count?`, `size?`, `reg?`, `value?`, `bytes?`, `perm?`, `run?`, `attach?`, `condition?`, `command?`, `lib?`, `name?`, `file?` | Drives one debug action (below). `addr` is validated like every other address. |

Actions:

- **Start:** `start` launches the open binary, stopped at entry (`run`
  configures its argv/env/stdio). With `attach` it instead controls an
  existing target without launching: `attach: {pid: N}` attaches to a running
  process, `attach: {remote: "gdb://host:port"}` (or `windbg://…`) connects to
  a remote stub — e.g. a sample running in an isolated VM — with the open
  binary as the symbol source. `attach` is not combined with `run`.
- **Execution:** `continue` / `continue_until` (`addr`),
  `continue_to_syscall` / `continue_to_call` / `continue_to_ret`, `step` /
  `step_over` (`count` instructions).
- **Reverse debugging:** `trace_start` / `trace_stop` record a trace;
  `step_back` (`count`) / `continue_back` then move backward through it (they
  error until a trace is recorded). `trace_save` / `trace_load` (`file`)
  persist the recorded session to, and restore it from, a directory in
  omp-re's output directory — so an expensive recording survives across debug
  sessions.
- **Registers & memory:** `registers`, `registers_telescope` (each register
  resolved to what it points at), `write_register` (`reg`=`value`),
  `read_memory` (`size` bytes at `addr`, returned inline as hex),
  `dump_memory` (`size` bytes of live memory at `addr` written to a file in
  omp-re's output directory — for an unpacked/decrypted region too large to
  return inline; returns the path, size, and SHA-256), `write_memory` (`bytes`
  hex at `addr`, into the live process), `disassemble` (`count` instructions at
  `addr`, default the PC — reads *live* memory, so it shows self-modified or
  unpacked code the static view can't), `resolve_symbol` (`name`, optional
  `lib`) — the live, post-ASLR address of a loaded symbol such as libc
  `system`.
- **Breakpoints & watchpoints:** `break_add` / `break_remove` / `break_list`,
  `break_add_hw` (hardware breakpoint via debug registers — breaks on
  read-only / self-modifying / packed pages without patching int3 bytes),
  `break_enable` / `break_disable` (toggle the breakpoint at `addr`),
  `break_condition` (`condition`, e.g. `rax>0` — stop only when it holds; the
  expression is passed literally so `>`/`<`/`==` are not shell redirects),
  `break_command` (`command` — run a **read-only** rizin command on each hit,
  e.g. `drj` to log registers or `dbtj` the backtrace; restricted to vetted
  debugger-state reads plus static print/info/search, never shell, writes,
  config, or debugger control), `watch_add` (hardware watchpoint at `addr`,
  `perm` r/w/rw, `size` 1/2/4/8 — removed with `break_remove`), `backtrace`.
- **Process state:** `maps`, `modules`, `libraries`, `sections`, `processes`,
  `threads`, `fds`, `signals`, `windows`.
- **Heaps:** `heaps` / `heap_blocks` (Windows), `heap_arenas` / `heap_chunks`
  (optional arena in `addr`) / `heap_bins` (optional
  `tcache`/`fast`/`unsorted`/`small`/`large` in `addr`) — glibc.
- **Lifecycle:** `stop` (kill and end the session).

Every action needs a session started first except `start`; nothing is ever
launched implicitly. The `write_*` and `watch_add` actions change the live
process and are called out as such in the approval reason. A
`continue`/`step` that never returns (a debuggee blocked on input) is killed
at `OMPRE_DEBUG_TIMEOUT_MS` (60 s default). The debugger has
no facilities for evading detection or hiding the debuggee; see
[`SECURITY.md`](../SECURITY.md#rizin_debug).

`dump_memory` is the one tool that emits a file (the sample itself is still
never written). Dumps go to `OMPRE_OUTPUT_DIR` — or `<tmpdir>/omp-re-out` when
unset — under a bare filename it validates; it never writes to a path the
model chose, so it can't traverse out of that directory or clobber an
arbitrary file.

## Triage tier (up to 4 tools, conditional on PATH)

Each runs against the currently open binary via omp's `exec`, so cancelling
the tool call stops the scanner.

| Tool | Approval | Requires on PATH | Parameters | What it does |
| --- | --- | --- | --- | --- |
| `triage_capa` | `exec` | `capa` | (none) | Run capa rules to detect capabilities and ATT&CK techniques. |
| `triage_floss` | `exec` | `floss` | (none) | Extract obfuscated strings (stack, decoded, static) via FLOSS. |
| `triage_die` | `exec` | `diec` | (none) | Detect packers, compilers, and file types via Detect It Easy. |
| `triage_yara` | `exec` | `yara` | `rules_path` (required — no default ruleset ships) | Scan the binary with user-supplied YARA rules. |

For `triage_capa`/`triage_floss`/`triage_die`, a non-zero exit code with
non-empty stdout is treated as "the tool ran and reported zero findings",
matching how capa signals "no matches". A non-zero exit with *empty* stdout
is treated as a real failure and throws, so a tool that never ran doesn't
read as a false all-clear.
