# Workflow

## Triage walkthrough, end to end

Use a binary you're allowed to run commands against without a sandbox — a
system binary like `/bin/ls` is enough to learn the flow.

1. `/re open /bin/ls` — spawns rizin, runs full analysis (`aaa`, progress in
   the footer), and populates the status band.
2. `alt+g` (function navigator) or `/re functions` — browse everything
   rizin's analysis found. Type to filter (fuzzy, best match first).
3. Select a function to open the code view. `d` toggles decompiled pseudo-C;
   `x` follows the selected cross-reference one hop; `a` hands the function
   off to the model with a grounding prompt ("use the RE tools to gather
   evidence first; report only what the evidence supports").
4. `alt+s` / `/re strings` — the string list; Enter lists the code that
   references a string, then opens it.
5. `alt+i` / `/re imports` — imported symbols; Enter lists the callers of an
   import. Useful for a quick capability guess before diving into
   decompilation.
6. If `capa`/`floss`/`diec`/`yara` are on PATH, ask the model to run the
   matching `triage_*` tool for a fast capability/packer read before manual
   analysis.
7. `/re evidence` lists everything gathered so far on this branch; Enter on
   a row (or `/re cite <id>`, which completes ids) pulls that entry's
   tool/address/summary into your next chat message so you can ask a
   follow-up about it without retyping context.
8. `/re report [path]` writes a Markdown report. With no path, it prints the
   report directly instead of writing a file.
9. `/re verify [--strict]` re-runs each cited `rizin_command` read-only against
   the open binary and checks its recorded output hash — proving the report's
   evidence is not just cited but reproducible.
10. Conclusions go in with `record_finding` (claim + the evidence ids behind
    it). A finding is refused if its evidence doesn't resolve, belongs to
    another binary, or doesn't support the claim in the auditor's judgement,
    and it becomes a report claim like any other.
11. `/re carry <report>.manifest.json --against <next-build>` replays that
    report on a different binary and labels each claim holds, relocated
    (found again by fingerprint after a rename or move), drifted (with a line
    diff of what changed), broken (its anchor is gone), or unchecked.
    It works as a regression test for the next build: a broken claim exits
    non-zero headless, and `--strict` also fails on drift. Add `--inherit` to
    re-prove the surviving findings on the new build, with fresh evidence, and
    get the drifted ones back as a to-do list with their diffs.

## How the evidence chain actually works

The model works through one tool, `run`, which executes code against the
`re` workspace. Every successful call to a **read-tier capability** —
`re.list_functions`, `re.search_functions`, `re.get_function`,
`re.decompile_function`, `re.disassemble_function`, `re.get_xrefs_to`,
`re.get_xrefs_from`, `re.list_imports`, `re.list_strings`, `re.hash_binary`,
and the rest of the read tier — and to `re.rizin_command` is automatically
recorded as a `re.evidence` session entry (`invokeCapability` in
`extensions/re/capabilities.ts`, through `recordAndTag` in
`extensions/re/evidence.ts`), content-addressed and hashed. Its id ends the
method's result as `[evidence xxxxxxxx]`, and every `run` result lists the
evidence it recorded, so the id reaches the model even when its code never
printed the result. Mutations (`re.rename_function`, `re.set_comment`, etc.)
similarly record `re.annotation` entries.

**This is the single most useful thing to know about this suite: work done
outside these capabilities produces no evidence.** If the model reads a file
with `bash`/`cat`, drives rizin raw through `re.rz()`, greps a disassembly
dump you pasted in, or reasons from something it already knew, none of that
is backed by an evidence id — and
`/re report`'s write gate is hard: if *any* claim in the built report has
zero evidence ids, the **entire report is withheld**, not just the
ungrounded parts. Headless failure is loud (`console.error` plus a non-zero
exit code), never a silently dropped report. The gate exists so an
ungrounded report never reaches a ticket — a partial, quietly-trimmed report
would be worse than an obvious failure, because it would look complete.

In practice: if you want something in the final report, get it through a
`re` capability, not a shell command, raw rizin, or a paraphrase. `/re evidence` and `/re cite
<id>` exist specifically so the model (and you) can look back at exactly
what was actually observed, in its own words, before writing a claim that
depends on it.

Grounding is the first gate; reproducibility is the second. Alongside the
model-facing `outputHash` (which bakes in the header and any truncation footer,
so it is not reproducible), every `rizin_command` evidence record now stores a
`reproHash` — the SHA-256 of its *canonicalized* raw output (ANSI, line endings,
and trailing whitespace normalized; the binary's path redacted) — plus the open
binary's SHA-256. `/re verify [--strict]` re-runs each cited command read-only
and compares, and `/re report` ships the same data as a Verification Manifest
and a `<report>.manifest.json` sidecar, so a report is re-derivable from the
binary, not merely trusted.

The third gate is relevance. Before `/re report` emits, each grounded claim and
its cited evidence go to an LLM self-audit through omp's `ctx.runEphemeralTurn`
side turn (no tools, no history writes) that judges whether the evidence actually
supports the claim — supported, overreach, or unsupported. It is advisory by
default (flags claims inline, still writes the report); `/re report --audit=strict`
withholds the report on an unsupported/overreach verdict, and it fails open to an
"unaudited" note when no model or side turn is available, so the two deterministic
gates stay authoritative.

All three gates stop at the binary that was analysed. `/re carry` takes a report
to other binaries: the manifest's entries are `claim → exact read-only command →
canonical output hash`, so re-running them on another build and comparing hashes
tells you which findings carry over (`holds`), which still run but now say
something different (`drifted`, shown as a diff of the canonical excerpt), and
which point at something that no longer exists (`broken`: a symbolic anchor such
as `sym.decrypt_config` that does not resolve, or a command that now produces
nothing). A claim takes the worst status among its checked evidence.

A rebuild moves almost everything, so two mechanisms keep carry from reporting
that motion as change. First, every `rizin_command` record also stores a
`shiftHash`: the hash of its canonical output with *positional* addresses
masked. These are the leading address of a disassembly or listing line, `@ 0x…`,
branch and call targets, RIP-relative displacements, and auto-names such as
`fcn.000011fd`. Immediates in other operands are kept, so a changed constant
still drifts. Output that matches only after masking counts as **holds**, and
drift diffs are matched on the masked lines, so they show only real changes.
Second, when `/re report` writes the manifest with the report's own binary still
open, every address-pinned entry gets an **anchor fingerprint**: the containing
function's name, offset, size, block count, the anchor's offset inside it, and
its mnemonic sequence. When the anchor no longer resolves, or a numeric anchor
drifts, carry prefilters the new build's functions by size and block count,
scores the closest by mnemonic-sequence similarity (threshold 0.8), and re-runs
the command at the best match plus the same offset. The new name is folded back
to the old one before comparing, so a pure rename is **relocated**, not
drifted. Manifests written since carry shipped record each
`rizin_command`'s structured `{ command, addr }`. Older manifests are handled by
splitting the recorded line on its trailing `@ addr`.

Evidence and annotation entries persist in the session JSONL and survive a
`--continue`/reload, but they are **not** injected into LLM context and are
**not** rendered inline in the transcript — omp's `pi.appendEntry()`
explicitly does not forward custom entries to the model. The status band's
evidence counter and the `/re evidence`/`/re cite` panel and command are the
visible surfaces. When a tool's output was too large for the context and was
spilled to a session artifact, its evidence entry records the
`artifact://<id>` too, and `/re report` reads the untruncated artifact.

## Branches, resume, and annotation replay

Everything above reads the **current session branch** (root to active leaf),
not the whole session file:

- After `/tree` navigation or a branch, evidence from the abandoned branch no
  longer counts toward the status band, grounding, or the report gate.
- rizin's renames, comments, and prototypes live in the rizin process's
  memory. Whenever a fresh process is needed — `--continue`/`/resume`, a
  respawn after a crash or timeout, or a branch whose annotations differ from
  what the process holds — omp-re re-analyzes the binary the branch last
  opened and **replays that branch's annotations** (minus any `/re undo`
  reversed) in order. Each annotation is attributed to the binary that was
  open when it was made, so opening a second binary never receives the
  first one's renames.
- Annotations rizin rejects on replay are reported in a warning, not dropped
  silently.

## Related capabilities

**Dynamic analysis.** This suite does not build its own disassembler or
debugger. omp's built-in `debug` tool already provides a real DAP debugger
(`attach` by pid or `host:port`, source/function/instruction/data
breakpoints, `read_memory`/`write_memory`, `disassemble`) — use it directly
for anything dynamic; `omp-re` covers static analysis only.

**Enabling the grounding advisor.** omp's own advisor
(`/advisor configure`, or hand-editing `WATCHDOG.yml`) can run a second
model that reviews whether the analyst's claims are backed by evidence. Add
to your project's or user-level `WATCHDOG.yml`:

```yaml
advisors:
  - name: RE-Grounding
    model: anthropic/claude-opus-5
    tools: [read, grep, glob]
    instructions: |
      Review only whether the analyst's claims are supported by observations made this session.
```

Two constraints:

- **The advisor's model must differ from the RE session's model.** omp has
  no self-review guard — setting both to the same model is silently allowed
  and defeats the point of a second reviewer.
- **The `tools:` grant is restricted to omp's built-in tool names.** This
  suite's one tool (`run`) is extension-registered, not built-in, so listing
  it here does nothing —
  the advisor gets `read`/`grep`/`glob` regardless, which is enough to read
  evidence blobs and session entries directly. Never grant a mutating tool
  to an advisor even experimentally: advisor tool grants bypass the primary
  agent's approval wrapper, so a granted mutating tool would run unprompted.

`WATCHDOG.md` (this repo's root file, if you're dev-loading from a checkout)
carries RE-specific review priorities, but omp only discovers `WATCHDOG.md`
by walking up from your current working directory plus the user agent
dir — never inside an installed plugin's package directory. After
installing as a plugin, copy `WATCHDOG.md` into the project you're actually
reverse-engineering in, or into `<agentDir>/WATCHDOG.md` for a user-wide
default.

**Delegating to the `re-analyst` agent.** omp forwards extension-registered
tools to `task` subagents, so the plugin ships `agents/re-analyst.md`. Ask
for it by name with a binary path and a question; it opens the binary in its
own rizin process and its own `run` namespace (its first call always opens
the binary with `re.open_binary`; the kept helpers are there too), follows the
`re-triage` skill's order of work, and returns structured findings — a
summary plus a list of `{claim, ea, evidence, confidence}` — where every
`ea` is copied from tool output. Two properties to keep in mind: its
evidence entries live in the subagent's session, not yours, so cite the
findings it returns rather than expecting them in your `/re evidence`; and
annotations it makes stay in its own rizin process, which is why it is told
not to annotate unless asked.

## Findings, and inheriting them

Report claims used to come only from capa and from IOC strings in evidence
summaries. `record_finding` adds the model's own conclusions. A finding is a
`re.finding` entry holding the claim, the evidence ids it cites, an optional
address and a confidence. It is gated when it is recorded:

1. **Existence.** Every id must resolve on this branch (exact, or a unique
   prefix of at least 6 characters).
2. **Binding.** The evidence must have been taken against the open binary.
3. **Support.** The claim and its evidence go to the same `ctx.runEphemeralTurn`
   auditor `/re report` uses. An `unsupported` or `overreach` verdict refuses
   the finding and returns the reason, so the model narrows the claim or cites
   better evidence while it is still working. `override_audit` records it
   anyway, with the justification kept beside it in the report. A missing
   auditor fails open (`unaudited`).

A finding made elsewhere, typically by the `re-analyst` subagent (its own rizin
process and its own session, so its evidence ids mean nothing here), comes in
through `adopt_finding`. The subagent's output now carries, per finding, the
read-only `rizin_command` lines that reproduce its evidence (`reproduce`).
`adopt_finding` checks the subagent's binary hash against the open binary,
re-runs each line through `runRizinCommand`, records the results with
`recordEvidence` as this session's evidence, and then goes through the same
`gateAndRecord` path as `record_finding`. A subagent's claim therefore reaches
the report only on evidence the reporting session observed itself, and it is
marked "adopted from re-analyst, re-proven in this session".

Live findings (not superseded or retracted) form the report's **Findings**
section. There they go through the report's own gates again, and they are listed
in the manifest's `findings` block next to the evidence entries and anchor
fingerprints.

`/re carry --inherit` uses that block. For each finding whose claim **holds** or
**relocated** on the new build, each reproduced evidence row is re-run through
the same function `rizin_command` executes and recorded through the same
evidence path as a live tool call, bound to the new binary's SHA-256. The
finding is re-recorded citing only that fresh evidence. Its address follows a
relocation (old name to new name, old start to new start), and its provenance
records the source binary, the source finding and the carry status. Findings
that **drifted**, **broke**, or couldn't be re-checked form the agenda: a prompt
listing each claim with its evidence status and a compact diff (changed lines
plus two lines of context, matched with addresses masked). Interactively it goes
into the editor, like `/re cite`; headless it is printed. With `--resolve` it is
instead sent to the model as a user turn (`pi.sendUserMessage`). That works
because the model is in the session where the fresh evidence was just recorded,
so it can re-examine each item and `record_finding` a revision citing evidence
on this build. Inheriting is idempotent: a claim already live on the branch is
skipped.

Findings also survive compaction. The `session.compacting` hook (preserve.ts)
restates every live finding (id, confidence, inherited or not, claim, address)
in the summary, telling the model they are already recorded. They are revised
with `supersedes`, not re-recorded. `/re findings` lists them, and Enter pulls
one into the editor to discuss.

