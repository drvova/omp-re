# Tool reference

All 54 `omp-re` tools, grouped by tier. Triage tools register only when their
backing binary is on PATH at load time, so your own tool list may legitimately
show fewer than 54 (the debugger needs OMPRE_ENABLE_DEBUGGER too).

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

## Session-setup (1 tool)

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `open_binary` | `read` | `path: string` | Spawns rizin on a binary and runs full analysis (`aaa`), streaming progress. Re-applies annotations this branch already recorded for the same binary. Every other RE tool acts on whichever binary was most recently opened — a `task` subagent must call this first. |

## Read tier (30 tools)

Every read-tier call that succeeds is recorded as a `re.evidence` entry.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `list_functions` | `read` | `offset?, limit?, sort?` | Functions as `{ea, name, size, blocks, callers, callees, signature}`. `sort` is `address` (default), `size`, or `callers`. |
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
| `deobfuscate` | `read` | `addr, size, op, key?, algo?, iv?` | Reveal obfuscated bytes in place: xor/add/sub/or/and with a `key`, an endian swap, or `decrypt` with `algo`+`key`(+`iv`) — shown as hex and string. Runs under the write cache and resets it, so the file is never modified. |
| `search_bytes` | `read` | `pattern` (hex), `offset?, limit?` | Raw-byte search (`/xj`) as `{ea, size, flag}` rows; `..` masks one nibble. |
| `search_string` | `read` | `pattern` (string), `offset?, limit?` | Literal string search over raw bytes (hex-encoded client-side, then `/xj`) — finds matches everywhere, including code pages. |
| `search_regex_bytes` | `read` | `pattern` (regex), `offset?, limit?` | Raw-byte regex search (`/xrj`) for shaped patterns (e.g. variable displacements). |
| `search_asm` | `read` | `instructions`, `offset?, limit?` | Assemble instruction text with the binary's arch config and search for the resulting bytes (`/aj`). |
| `search_value` | `read` | `width` (1/2/4/8), `value` or `min`+`max`, `offset?, limit?` | Immediate-value search (`/vNj` exact, `/VNj` range) — hardcoded constants, magic numbers, pointers. |
| `search_gadgets` | `read` | `kind` (`rop`/`cop`), `filter?, offset?, limit?` | ROP/COP gadget chains natively: a text-mode run primes rizin's gadget cache, then `/Rj`/`/Cj` returns `{ea, size, gadgets}` rows (each opcode carries its own address and type). `filter` is rizin's own gadget filter string. |
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

## Mutate tier (12 tools)

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
| `define_function` | `write` | `addr` | Define a function where auto-analysis missed one (`af`); refuses when a function already begins there, verifies one now does. `/re undo` runs `af-`. |
| `set_calling_convention` | `write` | `addr, cc` | Set a function's calling convention (`afc`); an unknown convention is rejected with rizin's own error (list with `rizin_command afcl`). |
| `set_flag` | `write` | `addr, name` | Name an address with a flag (`f`), replacing any flag already there; `/re undo` restores the previous flag (or removes it). |
| `set_arch_hint` | `write` | `addr, arch?, bits?` | Hint the architecture and/or word size to disassemble from an address (`aha`/`ahb`) — e.g. `bits: 16` for an ARM Thumb region, or `arch` for mixed-arch firmware. `/re undo` deletes the hint. |
| `set_data` | `write` | `addr, size, count?` | Mark bytes as a data element/array (`Cd`) so they stop rendering as code. `/re undo` removes the mark. |
| `set_string` | `write` | `addr, size?` | Mark bytes as a string (`Cs`); omit `size` to autodetect. Correctly no-ops on non-string bytes. `/re undo` removes it. |
| `set_format` | `write` | `addr, size, format` | Overlay a pf struct format (with field names) on a region (`Cf`) so disassembly shows named fields. Display-only. `/re undo` removes it. |

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

## Signatures — `apply_signatures` (1 tool)

FLIRT signatures name library functions from a signature database (book:
analysis/signatures). `open_binary`'s analysis (`aaa`) already applies rizin's
built-in database, so this covers what that doesn't: re-applying it on demand,
and applying a *custom* `.sig`/`.pat` file — which `rizin_command` can't,
because it refuses file arguments. List the built-in database with
`rizin_command Flt`.

| Tool | Approval | Parameters | What it does |
| --- | --- | --- | --- |
| `apply_signatures` | `exec` | `source` (`sigdb`/`file`), `path?` | `sigdb` re-applies rizin's built-in database (`Fa`); `file` applies the FLIRT file at `path` (`Fs`). Both rename matched functions, so it is exec-tier. A custom file is recorded and re-applied automatically on resume/respawn (like annotations), so the names it produced survive; it is not an undoable annotation. |

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
| `rizin_debug` | `exec` (the reason says plainly when an action executes, modifies, or inspects) | `action: enum`, `addr?`, `count?`, `size?`, `reg?`, `value?`, `bytes?`, `perm?`, `run?`, `attach?` | Drives one debug action (below). `addr` is validated like every other address. |

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
  error until a trace is recorded).
- **Registers & memory:** `registers`, `write_register` (`reg`=`value`),
  `read_memory` (`size` bytes at `addr`), `write_memory` (`bytes` hex at
  `addr`, into the live process), `disassemble` (`count` instructions at
  `addr`, default the PC — reads *live* memory, so it shows self-modified or
  unpacked code the static view can't).
- **Breakpoints & watchpoints:** `break_add` / `break_remove` / `break_list`,
  `watch_add` (hardware watchpoint at `addr`, `perm` r/w/rw, `size` 1/2/4/8 —
  removed with `break_remove`), `backtrace`.
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
