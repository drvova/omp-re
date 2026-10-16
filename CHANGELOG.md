# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

Broadened coverage of rizin's own capabilities, chapter by chapter against
the Rizin Book, verified end to end on rizin 0.9.1. The tool count grows from
40 to 54.

### Added

- **`deobfuscate`.** Reveal obfuscated bytes in place — xor/add/sub/or/and
  with a key, an endian swap, or a cipher `decrypt` (RC4/AES via rizin's
  `woD`) over a window, shown as hex and string. The transform runs under
  rizin's write cache and is reset immediately, so the file on disk is never
  modified (consistent with "mutations never touch the file"). Read-tier and
  recorded as evidence — the single highest-payoff capability for unmasking
  xor-hidden strings and embedded configs (book: basic_commands/write).
- **`list_symbols`.** The full symbol table (`is`) — local/internal functions
  and data symbols with name/type/bind/size/address, filterable by name — the
  read-tier companion to `list_imports`/`list_exports` it was missing.
- **Analysis passes.** `analyze` re-runs a rizin analysis pass beyond
  `open_binary`'s baseline `aaa`: `calls`/`xrefs`/`pointers`, `preludes`
  (recovers functions in stripped binaries), `autoname`, `types`, `golang`,
  `objc`, and `emulate_functions`. It reports the function count before and
  after, surfaces rizin's own message for a pass that doesn't apply, and is
  re-run on resume/respawn (before signatures and annotations) so the
  recovered analysis is faithful across a restart.

- **Load options for raw/headerless targets.** `open_binary` accepts
  `arch`/`bits`/`base`/`map`/`format` (rizin's `-a`/`-b`/`-B`/`-m`/`-F`), so
  flat shellcode, firmware, and ROM dumps load with the right architecture
  instead of being autodetected as the build default. The settings are
  validated, persisted in the `re.binary` entry, and reused on every respawn
  and resume; an explicit `bits` also steers 32/64 build selection.
- **Four analysis-edit mutate tools**, each with the resolve → write →
  read-back → verify contract, `/re undo`, and replay: `define_function`
  (`af` where auto-analysis missed one), `set_calling_convention` (`afc`,
  which corrects argument recovery), `set_flag` (`f`, naming an address), and
  `set_arch_hint` (`aha`/`ahb`, to disassemble a region as a different
  architecture or word size — ARM/Thumb switches, mixed-arch firmware; book:
  analysis/cpu_platform_profiles); and the metadata family `set_data` (`Cd`,
  mark bytes as a data element/array), `set_string` (`Cs`, force a missed
  string), and `set_format` (`Cf`, overlay a pf struct format so disassembly
  shows named fields; book: disassembling/adding_metadata).
- **FLIRT signatures.** `apply_signatures` re-applies rizin's built-in sigdb
  (`Fa`) or applies a custom `.sig`/`.pat` file (`Fs`); a custom-file
  application is recorded and re-applied on resume/respawn. `rizin_command`
  can list the sigdb (`Flt`).
- **Debugger: writing and live code.** `rizin_debug` gains `write_register`,
  `write_memory`, `disassemble` (of *live* memory, revealing self-modified or
  unpacked code), `watch_add` (hardware watchpoints), `continue_to_syscall` /
  `continue_to_call` / `continue_to_ret`, and glibc heap inspection
  (`heap_arenas` / `heap_chunks` / `heap_bins`) alongside the existing Windows
  heap actions. The approval reason now distinguishes execute / modify /
  inspect.
- **Reverse debugging** (book: debugger/revdebug). `trace_start` / `trace_stop`
  record a trace session; `step_back` and `continue_back` then move the process
  backward through it — stepping back from a crash or a watchpoint hit.
- **Remote and attach debugging** (book: remote_access). `rizin_debug`'s
  `start` can now control an existing target instead of launching: `attach:
  {pid}` attaches to a running process, and `attach: {remote: "gdb://host:port"}`
  (or `windbg://…`) connects to a remote stub — so a sample can be driven
  inside an isolated VM from the host, the open binary serving as the symbol
  source. The pid and URI are validated; `attach` is refused together with
  `run`.
- **`rizin_command` read-only unlock.** Whole read-only families the book
  documents are now reachable: configuration reads (`e <key>`, `el`, `elj`,
  `et`, `es`), analysis-hint listings (`ahl`), metadata and string listings
  (`C`, `Csl`, …), class reads (`acl`, `aci`, `acg`, `acvl`, `acvf`), address
  info (`ai`), type reads (unions, enums, typedefs, calling-convention lists,
  type cross-references, typeclasses), and plugin listings
  (`Ll`/`La`/`Lc`/`LC`/`Lh`/`Li`/`Lp`/`LD`). A command the installed rizin
  catalogs that was blocked only by command shape now runs; coverage measured
  against rizin 0.9.1 rose from 800 to 926 of ~2020 commands.

### Fixed

- The search / types / syscall / binary-info read tools and the RzIL emulator
  were never added to the suite's tool roster, so those read tools recorded no
  `re.evidence` (breaking the report gate's grounding for anything found
  through them), none of these tools were written to the audit log, and
  `/re off` left them enabled. The roster now matches what is registered.
- `rizin_debug`'s `start` computed the program counter but dropped it from the
  result; it now reports where the process stopped (arch-agnostically).

### Security

- The `rizin_command` get/set duals are gated: `e <key>` reads a value but
  `e key=value` is refused, and `tn`/`Ld`/`Lo` run only in their list form.
  The ROP/JOP/COP constraint queries keep their `=` arguments. Every newly
  allowed command was confirmed read-only against a real rizin.

## [0.2.0] - 2026-10-15

radare2 is replaced by [rizin](https://rizin.re), and the plugin targets
omp **18.11.1** (the latest release) and its native extension surfaces.
rizin is not bundled: omp-re runs the rizin on your `PATH` or at
`OMPRE_RIZIN_PATH`. Verified against rizin 0.9.1 (latest), with and without
rz-ghidra, by loading the extension through omp 18.11.1's own SDK and
extension runner, and by installing it with `omp plugin install`.

### Security

- Fixed a command injection in `set_comment` (and `/re undo` of a comment):
  0.1.x interpolated comment text unquoted into `CC <text> @ <addr>`, and
  radare2 splits on `;`, so a comment like `a; !id` ran an extra command,
  including a `!` shell escape (reproduced on radare2 5.5.0). Free text and
  C types now reach rizin only as single-quoted literals, and addresses can
  no longer contain `@` (rizin's `@@` iterators). See `SECURITY.md`.
- rizin is now spawned with `-N`, so a user's `rizinrc` can't change the
  command output omp-re parses (plugins still load; `OMPRE_RIZIN_LOAD_USER_CONFIG=1`
  restores it). The `rizin_command` syntax denylist was audited against
  rizin's documented prompt grammar and pins the `&`/`&t` task and `!`/`!!`
  shell operators and the full `@` modifier family.

### Changed

- `hash_binary` computes its digests natively with rizin's own `rz-hash` (the
  sibling binary of `rizin` itself, one `-j` invocation for sha256/sha1/md5)
  instead of reading the file and hashing it in node. The digests are
  byte-identical to the previous output; the tool no longer reimplements a
  hasher rizin already ships.

- **Backend: radare2 → rizin.** `R2Session`/`r2.ts` become
  `RzSession`/`rizin.ts`, speaking `rizin -q0` with rizin's dialect (`%v`,
  `echo`, `afvlj`, `afs @`, `aflc`, `fdj`). rizin is required; radare2 is no
  longer used.
- **Process lifecycle on cordis.** The rizin and debug processes are now owned
  by [cordis](https://github.com/cordiverse/cordis) *revertible effects*: a
  child scope per omp session, and each process a `ctx.effect` whose setup
  returns its teardown (`runtime.ts`). Respawn disposes one effect; session
  shutdown disposes the scope and every process with it — replacing the
  hand-rolled nullable-field map and scattered `.close()` calls. `state.ts` is
  now a thin facade over it, so the tool and UI call sites are unchanged.
- **Extension composed on cordis.** Every subsystem — the read / mutate /
  rizin-REPL / rizin-CLI / debugger / triage tool groups, the evidence store,
  the audit log, the UI, and the command shell — is now a cordis plugin loaded
  on one `Context` per extension load (`app.ts`'s `composeApp`). The omp host
  (`pi`) is provided as a service each subsystem injects (`inject: ["pi"]`), so
  a subsystem activates only when the host is present — the *reactive coeffect*
  (spatial composability). The subsystems' registration functions stay plain
  `(pi) => …` so they remain independently testable.
- **Environment variables:** `OMPRE_R2_PATH` → `OMPRE_RIZIN_PATH`;
  `OMPRE_R2_ANALYSIS_TIMEOUT_MS` → `OMPRE_ANALYSIS_TIMEOUT_MS`.
- **Decompilers:** rz-ghidra (`pdg`) then jsdec (`pdd`). rizin has no `pdc`,
  so without a plugin `decompile_function` returns annotated disassembly
  labeled `(disassembly only — no decompiler plugin available)`; when a
  plugin is loaded but returns nothing for a function, the label says so. A
  failed probe is no longer cached for the life of the process, so a
  decompiler is never wrongly reported absent after one slow moment.
- `list_functions`/`search_functions` rows are slimmed to `{ea, name, size,
  blocks, callers, callees, signature}` (rizin's raw rows carry hundreds of
  reference entries each; `/bin/ls`'s full `aflj` is 457 KB). New `sort`
  parameter: `address`, `size`, `callers`.
- `get_function` returns a curated summary: metrics, signature, typed
  `args`/`locals`, unique `calls` named via rizin's flags, `callers`, and
  reference counts.
- List results are JSON arrays with one compact row per line.
- Mutate tools resolve to the function's start address before writing (a
  rename can retire the flag the model used), read variables back through
  `afvlj` JSON instead of parsing text, and report what rizin actually
  stored when a mutation lands differently from the request.
- Enter in the evidence panel now cites the entry into the editor and closes
  the panel; Enter on a string or an import lists the code that references
  it before opening a code view. Panels close before reporting that there is
  nothing to open, so those messages are no longer hidden under an overlay.
- Bare `/re` shows the help text.
- `/re on` works on omp 18, whose `getAllTools()` returns tool objects
  instead of names (0.1.x's `/re on` silently re-enabled nothing there).
- The `@oh-my-pi/*` packages are now pinned dev dependencies at `^18.11.1`
  (they stay `*` peers at runtime), so local typechecks and tests run against
  the current host. Tool schemas are declared as named consts so `params`
  types infer under omp 18's zod-compatible builder.
- Integration tests run against `/bin/ls` by default instead of an
  undistributed WannaCry sample.

### Added (using all of rizin)

- **Byte search** (`search_bytes`, `search_string`, `search_regex_bytes`):
  raw-byte search via `/xj` and `/xrj` — hex patterns with `..` nibble-mask
  wildcards, literal strings (hex-encoded client-side so one row shape covers
  all modes), and byte regexes; paginated `{ea, size, flag}` rows.
- **Types** (`list_types`, `define_types`, `cast_memory`): rizin's type
  database via `tsj`/`tej`/`ttj`/`tfj` (name-filtered, paginated — includes
  the built-in Windows type base), C definitions via `td` (one statement per
  entry, rizin's errors surfaced verbatim), and `tp` memory casting.
- **Syscalls** (`list_syscalls`, `syscall_lookup`): the active syscall
  profile via `aslj` (on a PE binary, the Windows Nt* interface), and single
  syscall resolution by name (`asn`) or number (`asr`).
- **Binary info** (`get_binary_info`, `list_entrypoints`,
  `list_relocations`, `list_flags`, `list_classes`): `iIj` identity object,
  `iej` entry points, `irj` relocations, `flj` flags (filtered), and `icj`
  classes (C++ RTTI / ObjC / Swift metadata).
- **Asm/value/gadget search** (`search_asm`, `search_value`, `search_gadgets`):
  `/aj` assemble-and-search, the `/v`+`/V` immediate-value family (exact or
  range, 1/2/4/8-byte widths), and ROP/COP gadget chains natively — a
  text-mode `/R`/`/C` run primes rizin's gadget cache, then `/Rj`/`/Cj`
  returns native JSON rows (per-opcode offsets and types included); the
  filter is rizin's own gadget filter string.
- Verified live against rizin 0.9.1 on Windows. Two rizin surfaces exist in
  the book but not in this build and are deliberately not wrapped: the `z`
  zignature family (the command is absent from the 0.9.1 Windows release)
  and ESIL emulation (`ae*`, deprecated upstream in 0.9.x and non-functional
  through the persistent-session transport); both return as tools when the
  build supports them.

- `rizin_cli`: one `exec`-tier tool fronting rizin's standalone command-line
  programs with their own arguments — `rz-bin` (headers/imports/strings
  without full analysis), `rz-diff` (compare two binaries), `rz-hash`
  (hashing and entropy), `rz-find` (raw pattern search), `rz-asm`
  (assemble/disassemble), `rz-ax` (base conversion). Invoked by argv (no
  shell); `@binary` substitutes the open binary; `args: ["-h"]` returns the
  tool's own help. Flags that run code (`rz-find -E`/`-R`, `rz-diff -t
  command`), write files (`rz-bin -O`/`-o`/`-C`, `rz-asm -O`), fetch over the
  network (`rz-bin -dd`/`-PP`), or open an interactive view (`rz-diff
  -H`/`-S`) are refused before the tool runs. rz-gg and rz-run are not exposed.
- The decompiler is now extensible: `OMPRE_DECOMPILER` is a comma-separated
  priority list (default `pdg,pdd`) that reorders the probe or names another
  plugin's `pdX`-style command, with the built-ins kept as a fallback. `/re
  status` lists the available decompilers and the active one.
- `rizin_debug` (opt-in via `OMPRE_ENABLE_DEBUGGER`): dynamic analysis under
  rizin's debugger — launch, breakpoints, continue/continue-until, single-
  step and step-over, registers, memory reads, and backtrace. It EXECUTES the
  sample, so it is off by default, runs in a debug session separate from the
  static one (which still never executes the file), is killed with its
  debuggee on `stop`/shutdown, and is `exec`-tier with a reason that
  distinguishes resuming from inspecting. No anti-anti-debug, hiding, or
  injection features. See `SECURITY.md`.

### Added (rizin REPL)

- `rizin_help`: looks up commands in the installed rizin's own catalog
  (`rizin -qc '?*j'`, about 2,000 commands with typed arguments): a command
  or prefix for its usage and arguments, or keywords to find one.
- `rizin_command` (`exec` approval naming the command): runs one read-only
  rizin command the dedicated tools don't cover — `pdsf`, `agc`, `px`,
  `ph entropy @!<n>`, `/x`, `/R`, `aoe`, `iH`, and the rest of rizin's
  print, info, search, graph, and listing commands — returning rizin's own
  error text when the arguments are wrong. Writes, config, shell escapes,
  file reads, raw-byte output, and analysis changes are refused before
  anything reaches rizin (policy in `SECURITY.md`). Its output is evidence
  like any read tool's.
- Compatibility check: opening a binary looks up every command omp-re sends
  in the installed rizin's catalog and names any that are missing; `/re
  status` shows the result and picks the decompiler from the catalog.

### Added (omp-native)

- **Compaction preservation** (`session.compacting`): when omp compacts the
  conversation, omp-re folds a snapshot of the RE session — the open binary,
  evidence and annotation counts, and the most recent evidence ids — into the
  summary, so the post-compaction model does not lose track of what is open or
  already found (the entries themselves always persisted on the branch; this
  keeps the model's working memory grounded). Only contributes lines when a
  session is active. `extensions/re/preserve.ts`.

- Tool renderers (`renderCall`/`renderResult`) for every RE tool, with
  decompiled code highlighted as C by omp's highlighter, plus native views
  (`describeCall`/`describeResult`) so Tern shows each RE tool as a native
  tool card with a `code` body instead of a generic text card.
- `open_binary` streams analysis progress via `onUpdate`, and the footer
  shows progress for `/re open` and session restores. Every tool honors its
  `AbortSignal`: cancelling a command stops waiting without killing rizin;
  cancelling analysis kills the half-analyzed process.
- Truncated output is saved in full as a session artifact and linked as
  `artifact://<id>`; evidence entries record the artifact, and `/re report`
  reads it.
- Evidence, annotations, and the open binary follow the active session
  **branch** (`getBranch()`), with handlers for `session_switch`,
  `session_branch`, and `session_tree`.
- **Annotation replay:** resuming a session, respawning a crashed rizin, or
  moving to a branch with different annotations re-applies that branch's
  annotations (minus undone ones) to a fresh rizin process. Annotations are
  attributed to the binary that was open when they were made.
- `agents/re-analyst.md`: a packaged `task` subagent (omp forwards
  extension tools to subagents) with a structured `{binary, sha256, summary,
  findings[{claim, ea, evidence, confidence}], gaps}` output, marked
  `structured: true` so the schema is enforced even with `task.structured`
  off.
- `test/extension-sdk.test.ts`: loads the extension through omp's real SDK
  in CI, so host API drift fails `bun test`.
- Per-call approval reasons for mutate and triage tools (e.g. `Rename
  function "main" to "parse_args"`); approval decisions for RE tools are
  written to the audit log.
- `/re` argument completion (subcommands, and evidence ids for `cite` /
  `evidence`), `/re status`, the `alt+i` imports shortcut, fuzzy panel
  filtering (best match first), and a scroll position in the code view.
- Empty list pages are marked compactable (`useless`) for omp's context
  compaction.

### Docs

- README, `docs/install.md` (rizin and rz-ghidra install, upgrade notes),
  `docs/workflow.md` (branches and replay, the re-analyst agent),
  `docs/tools.md`, `docs/testing.md`, `SECURITY.md`, and `CONTRIBUTING.md`
  rewritten for rizin. The committed screenshots predate the port and were
  taken with the radare2 backend.

## [0.1.x] - 2026-08

The 0.1.x releases (0.1.0–0.1.2) ran on the **radare2** backend, which 0.2.0
replaced with rizin. Their detailed notes are preserved in the git history.
