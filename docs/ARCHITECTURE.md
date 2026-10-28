# Architecture

omp-re is an [omp](https://omp.sh) extension that drives [rizin](https://rizin.re)
for reverse engineering. It is deliberately plain: a set of tool and listener
registrations on omp's own extension API, over one shared backend process per
session. No framework sits between omp and the plugin.

## Extension entry

`index.ts`'s default export registers every subsystem, in order, against the
omp host (`pi`):

```
registerReadTools    registerMutateTools  registerRizinTools   registerRzCliTools
registerTriageTools  registerDebugTools   registerEvidenceStore registerAuditLog
registerPreservation registerUI           registerShell
```

The conditional groups probe the filesystem and are `await`ed so every tool is
in place before init completes: `registerRzCliTools` and `registerTriageTools`
register a tool only when its backing binary is found (the `rz-*` suite, and
capa/floss/die/yara), and `registerDebugTools` registers `rizin_debug` only
when `OMPRE_ENABLE_DEBUGGER` is set. `registerShell` adds the `re.binary`
renderer, the `open_binary` tool and `--binary` flag, the session-lifecycle
handlers, argument completion, and the `/re` command.

Each `registerX(pi)` is a plain function, so every subsystem is unit-testable
in isolation by calling it with a stub `pi`.

## The rizin backend (`state.ts`)

One rizin process per omp session, keyed by `ctx.sessionManager.getSessionId()`
(so the main session and every task subagent get their own). `state.ts` owns a
`Map<sessionId, record>`; each record holds the static analysis process (`rz`),
the optional debug process (`dbg`), the open binary path, and the per-session
counters the UI/evidence/audit modules read and write.

Lifecycle is explicit — rizin is a child process with a trivial teardown:

| Event | Handler |
| --- | --- |
| First tool use / respawn after a crash | `ensureRizin` spawns (shared in-flight promise so concurrent callers don't race two spawns); `spawnRizin` closes any prior process and replays this branch's annotations |
| `/tree` navigation to a branch with different annotations | `syncAnnotationsToBranch` closes the process; the next tool call respawns and replays that branch's annotations |
| `rizin_debug stop` | `stopDebug` closes just the debug process; the static session is untouched |
| `session_shutdown` / `session_before_switch` | `shutdownState` closes every process and drops the record |
| `session_branch` | `rekeyState` carries the record (and its live processes) to the new session id |

`RzSession` (`rizin.ts`) is the transport: the `-q0 -N` NUL-framed pipe, with
abort, timeouts, and stderr capture. The opt-in debugger uses a second
`RzSession` (`rizin -d`) held in the same record, launched only on demand and
never auto-respawned (that would silently re-run the sample).

## Module map

| File | Responsibility |
| --- | --- |
| `index.ts` | Extension entry; `registerShell` (renderers, `open_binary`, `--binary`, session-lifecycle handlers, completions, the `/re` command) |
| `state.ts` | Per-session records and the rizin/debug process lifecycle |
| `rizin.ts` | `RzSession` transport (`-q0 -N` pipe), spawn flags, validators, `rz-*` tool resolution |
| `catalog.ts` | rizin's self-described command catalog (`?*j`) and the `rizin_command` policy |
| `tools-read.ts` / `tools-mutate.ts` | The 12 read-tier and 5 mutate-tier tools |
| `tools-rizin.ts` | `rizin_help` / `rizin_command` (the REPL bridge) |
| `tools-rzcli.ts` | `rizin_cli` (the standalone `rz-*` tools) |
| `tools-debug.ts` | `rizin_debug` (opt-in dynamic analysis) |
| `tools-triage.ts` | capa / floss / die / yara |
| `decompile.ts` | Extensible decompiler probe (`OMPRE_DECOMPILER`) |
| `evidence.ts` | Content-addressed evidence store + `tool_result` hook |
| `audit.ts` | The RE tool-name sets (the audit gate) + signed audit log |
| `preserve.ts` | Compaction preservation (`session.compacting`) |
| `ui.ts` | Status band, overlay panels, evidence helpers |
| `report.ts` / `annotations.ts` / `entries.ts` / `disasm.ts` / `format.ts` / `render.ts` | Report gate, annotation replay, branch entry helpers, disassembly, result formatting, tool renderers |

## Data that outlives a process

Evidence, annotations, and the open binary are persisted as omp **custom
session entries** (`pi.appendEntry`), which live on the session branch and are
**not** sent to the model. They survive respawns, resumes, branches, and
compaction. On resume or branch change the evidence index is rebuilt and the
branch's annotations are replayed into the fresh rizin process; on compaction,
`preserve.ts` folds a snapshot of this state into the summary so the model's
working memory stays grounded even though the entries themselves were never at
risk.

## No runtime dependencies

omp-re has no runtime npm dependencies — it uses only the omp host APIs
(`@oh-my-pi/*`, peer-provided), the Node standard library via `node:*` imports
(which Bun implements), and the Bun globals `Bun.spawn` / `Bun.which`. It runs
the TypeScript directly under Bun with no build step. Keeping the dependency
surface empty keeps a tool that parses hostile input easy to audit.
