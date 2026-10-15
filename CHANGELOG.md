# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.0] - 2026-10-15

radare2 is replaced by [rizin](https://rizin.re), and the plugin now uses
omp 17.2.6's native extension surfaces throughout. Verified against rizin
0.9.1, with and without rz-ghidra, and by loading the extension through
omp's own SDK and extension runner.

### Security

- Fixed a command injection in `set_comment` (and `/re undo` of a comment):
  0.1.x interpolated comment text unquoted into `CC <text> @ <addr>`, and
  radare2 splits on `;`, so a comment like `a; !id` ran an extra command,
  including a `!` shell escape (reproduced on radare2 5.5.0). Free text and
  C types now reach rizin only as single-quoted literals, and addresses can
  no longer contain `@` (rizin's `@@` iterators). See `SECURITY.md`.

### Changed

- **Backend: radare2 → rizin.** `R2Session`/`r2.ts` become
  `RzSession`/`rizin.ts`, speaking `rizin -q0` with rizin's dialect (`%v`,
  `echo`, `afvlj`, `afs @`, `aflc`, `fdj`). rizin is required; radare2 is no
  longer used.
- **Environment variables:** `OMPRE_R2_PATH` → `OMPRE_RIZIN_PATH`;
  `OMPRE_R2_ANALYSIS_TIMEOUT_MS` → `OMPRE_ANALYSIS_TIMEOUT_MS`.
- **Decompilers:** rz-ghidra (`pdg`) then jsdec (`pdd`). rizin has no `pdc`,
  so without a plugin `decompile_function` returns annotated disassembly
  labeled `(disassembly only — no decompiler plugin available)`; when a
  plugin is loaded but returns nothing for a function, the label says so. A
  failed probe is no longer cached for the life of the process (the 0.1.x
  "falls back to pdc even with r2ghidra installed" report, QA-FINDINGS §4,
  does not apply to this probe).
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
- Integration tests run against `/bin/ls` by default instead of an
  undistributed WannaCry sample.

### Added (omp-native)

- Tool renderers (`renderCall`/`renderResult`) for every RE tool, with
  decompiled code highlighted as C by omp's highlighter.
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
- `agents/re-analyst.md`: a packaged `task` subagent (omp 17.2.6 forwards
  extension tools to subagents) with a structured `{binary, sha256, summary,
  findings[{claim, ea, evidence, confidence}], gaps}` output.
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

## [0.1.2] - 2026-08-04

### Changed

- `skills/re-triage/SKILL.md` rewritten to own the initial "analyse this
  binary" trigger instead of only covering post-open triage: broadened
  `description:` (analyse, reverse, triage, decompile, characterise,
  unpack), starts at `/re open <path>`, states there is no `/re triage`
  subcommand, and states the evidence/report-withhold rule (work done
  outside the RE tools has no evidence id, and `/re report` withholds the
  entire report if any claim is unbacked). Fixes agents routing to a
  different, non-omp-re RE toolchain on the first "analyse this binary"
  request and recording zero evidence.

## [0.1.1] - 2026-08-03

### Fixed

- `resolveEA` (the address normalizer `rename_function` and `set_prototype`
  use to build their `/re undo` message) read a JSON read-back's `offset`
  field, but r2 6.x renamed that field to `addr` on `afij` — confirmed
  directly (`afij @ entry0` returns `{"addr":...}`, no `offset` key at all).
  `resolveEA` therefore always fell back to the caller's raw address
  argument, so `/re undo` after a `rename_function` showed the literal
  string the model passed (e.g. `omp-re: undid rename_function @ entry0
  (restored ...)`) instead of a normalized hex address. `extensions/re/r2.ts`
  already exports `addrOf`/`eaFromOffset` handling exactly this `addr`/
  `offset` split for every read tool; `resolveEA` now uses them too.
  Verified against real radare2 6.1.8: `/re undo` now reports
  `omp-re: undid rename_function @ 0x...`. See
  [`test/QA-FINDINGS.md`](test/QA-FINDINGS.md) for the discovery context.
- `test/tui-qa.sh`'s `clear_editor` backspace budget (20s, 40 keys/batch)
  was sized for a short single-line prefill and could leave a fragment of a
  real ~250-byte `/re cite` evidence summary in the editor, which the next
  `slash` call would append to and submit as prose instead of a command.
  Widened to 45s/80 keys per batch (comfortable margin up to the 512-byte
  evidence-summary cap) — QA-harness-only, no plugin behavior change.
- `test/tui-qa.sh`'s readiness handshake (`/re help` retried 8× at 15s) was
  too tight on a host whose startup connects a large MCP server catalog;
  widened to 16× at 20s. QA-harness-only.

### Docs

- `docs/testing.md`, `.github/workflows/ci.yml`, and `CONTRIBUTING.md`
  corrected to the actual measured `bun test` shape: **72 pass / 0 fail / 0
  skip** locally with radare2 + the real fixture (not 73), **33 pass / 45
  skip / 78 total** in CI (the three fixture-gated files' tests report as
  skipped inside the total, not as zero tests as previously stated).
- `README.md` rewritten with real screenshots (`docs/img/`, regenerated via
  the new `tools/shotgen/`) replacing the two ASCII "screenshot" fences,
  one of which contained a fabricated `... 201 more rows ...` line that
  matched no real pane capture.
- New `test/QA-FINDINGS.md` §4: `decompileAt` observed falling back to
  `pdc` even with r2ghidra installed, reproduced but not root-caused.

## [0.1.0] - 2026-08-03

Initial public release.

### Added

- `/re cite <id>` — pulls a specific `/re evidence` entry into the editor as
  a prefilled chat message (`Re: evidence <id> (<tool> @ <addr>)` plus its
  summary), so a picked row's detail can actually be handed to the model
  instead of only rendering underneath the still-open evidence panel.
- Public docs: `docs/install.md`, `docs/workflow.md`, `docs/tools.md`,
  `docs/testing.md`, `CONTRIBUTING.md`, `SECURITY.md`.
- `.github/workflows/ci.yml` — `check` (typecheck) and `test` (unit tests)
  jobs on every push/PR.
- `LICENSE` (MIT).

### Fixed

- `rename_variable` and `set_variable_type` sent a bare `${addr}` as a
  trailing positional token to r2's `afvn`/`afvt`, which don't take an
  address argument at all; both tools threw `mutation did not land` on
  every input. Fixed to use r2's `@ addr` temporary-seek syntax. The
  identical defect in `/re undo`'s `rename_variable`/`set_variable_type`
  branches — found while verifying this fix — is fixed the same way; those
  branches previously reported success while silently reverting nothing.
- `set_prototype` sent `af ${sig} ${addr}` — `af` renames a function, it
  does not set a signature. Fixed to use `afs ${sig} @ ${addr}` (both the
  forward tool and `/re undo`'s branch). r2's `afij` read-back always
  re-punctuates a stored signature (adds a space before `(`, appends a
  trailing `;`); the tool now normalizes both sides of the comparison
  before checking they match, so it tolerates r2's own cosmetic
  reformatting without weakening the check — a genuinely different
  signature still fails loudly. The forward tool also now strips that
  trailing `;` from the captured old signature before storing it, so a
  later `/re undo` doesn't trip the `sig` validator's forbidden-character
  check on a semicolon r2 itself appended.
- `set_comment` used plain `CC ${text} @ ${addr}`, and r2's `CC` **appends**
  to an existing comment rather than replacing it, so a second call at the
  same address always failed its own read-back. Fixed to clear first
  (`CC- @ ${addr}`) before writing, in both the forward tool and `/re
  undo`'s branch, making both idempotent.

All four defects (and their `/re undo` counterparts) are verified fixed
against real radare2 6.1.8. All 5 mutate-tier tools and all 5 `/re undo`
branches now work end to end; the advertised tool count stays at 22. See
[`test/QA-FINDINGS.md`](test/QA-FINDINGS.md) §2 for the historical record
and [`test/tools-mutate-registry.test.ts`](test/tools-mutate-registry.test.ts)
for the regression coverage.

### Changed

- `test/tui-qa.sh` gained 3 assertions for `/re cite` (bare usage, unknown
  id, and prefill-into-editor); the suite's assertion-count drift guard
  moved from 96 to 99.
