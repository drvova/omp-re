# Architecture

omp-re is an [omp](https://omp.sh) extension that drives [rizin](https://rizin.re) for reverse engineering. It has **no third-party runtime dependencies** — an installed omp plugin can only resolve the host's own `@oh-my-pi/*` packages, so everything below is hand-rolled on top of them.

## Process lifecycle (`runtime.ts`)

A rizin process is a resource with a lifetime: spawn, respawn on death or branch change, close on shutdown. That used to be a `Map` of nullable fields with `.close()` calls sprinkled across the code. It is now a single `RizinBackend` (a process-wide singleton) that gives each omp session (keyed by `ctx.sessionManager.getSessionId()`) a small **teardown scope**:

- Each process the session owns — the static analysis session (`rizin -q0 -N`) and the opt-in debug session (`rizin -d`) — registers its `close()` on the scope as an **effect** and gets back an idempotent **disposer**.
- Calling one disposer closes exactly that process; disposing the whole scope closes every process the session still owns (most-recent first).

The consequences fall out for free:

| Event | Mechanism |
| --- | --- |
| Respawn (process died / stale after a branch) | run the one rizin disposer, register a new effect |
| `/tree` navigation to a branch with different annotations | run the disposer; the next tool call respawns and replays that branch's annotations |
| `debug stop` | run just the debug disposer; the static session is untouched |
| `session_shutdown` / `session_before_switch` | dispose the whole session scope — every registered teardown runs |

`RzSession` (`rizin.ts`) stays the low-level transport: the `-q0` NUL-framed pipe, with abort, timeouts, and stderr capture. The scope owns _when a process lives and dies_, not how bytes move.

`state.ts` is a thin facade over the backend (`getState`, `ensureRizin`, `spawnRizin`, `shutdownState`, `rekeyState`, `syncAnnotationsToBranch`, `startDebug`, `stopDebug`, `requireDebug`). `getState()` stays synchronous and returns a plain per-session record, so the many call sites that read and write counters and paths are unchanged; the scope attaches lazily on the first spawn.

## Subsystem composition (`app.ts`)

`composeApp(pi, subsystems)` is the extension's composition root, run once per extension load: it applies each subsystem in order, handing the omp host (`pi`) to each, and awaits every one — so the async subsystems (the triage / CLI probes that stat PATH) finish before init completes. Each subsystem needs only the host, which is always present, so a plain sequential `await` gives the ordering with nothing to resolve. (This was a cordis `Context` graph until the cordis dependency stopped the installed plugin from loading; see the `[0.3.0]` CHANGELOG entry.)

The subsystems, in load order (`index.ts`):

```
re:read-tools   re:mutate-tools  re:rizin-repl  re:rizin-cli
re:triage-tools re:debugger      re:evidence    re:audit
re:preserve     re:ui            re:shell
```

Each subsystem's registration stays a plain `(pi) => …` function (see `tools-*.ts`, `evidence.ts`, `audit.ts`, `ui.ts`, `preserve.ts`, and `registerShell` in `index.ts`), so it is unit-testable in isolation; `app.ts` only sequences them.

## Teardown, honestly

omp's `ExtensionAPI` returns no handle from `on()`, `registerTool()`, `registerCommand()`, `registerMessageRenderer()`, or `registerFlag()`, and exposes no extension-unload hook. So a listener or tool, once registered, cannot be removed — those subsystems are **register-once by the host's design** — with no unregister call, there is nothing to undo. The teardown that is real is the per-session process lifecycle above; omp's one supported toggle, `setActiveTools`, is what `/re off` uses. There is no host-level hot-unload — the host does not offer one.

## Module map

| File | Responsibility |
| --- | --- |
| `index.ts` | Extension entry; `registerShell` (renderers, `open_binary`, `--binary`, session-lifecycle handlers, completions, the `/re` command); the `composeApp` call |
| `app.ts` | Composition root (`composeApp`): applies each subsystem in order with the host |
| `runtime.ts` | `RizinBackend`: per-session teardown scopes that own the rizin/debug process lifecycle |
| `state.ts` | Thin facade over `RizinBackend` |
| `rizin.ts` | `RzSession` transport (`-q0` pipe), spawn flags, validators, `rz-*` tool resolution |
| `catalog.ts` | rizin's self-described command catalog (`?*j`) and the `rizin_command` policy |
| `tools-read.ts` / `tools-mutate.ts` | The 14 read-tier and 15 mutate-tier tools |
| `tools-rizin.ts` | `rizin_help` / `rizin_command` (the REPL bridge) |
| `tools-rzcli.ts` | `rizin_cli` (the standalone `rz-*` tools) |
| `tools-debug.ts` | `rizin_debug` (opt-in dynamic analysis) |
| `tools-project.ts` | `export_project` (save the analysis as a rizin project) |
| `tools-mapfile.ts` / `mapfiles.ts` | `map_file` (open a file into the session) and its respawn-replay |
| `tools-triage.ts` | capa / floss / die / yara |
| `output.ts` | The one confined directory omp-re writes artifacts to (dumps, traces, projects) |
| `decompile.ts` | Extensible decompiler probe (`OMPRE_DECOMPILER`) |
| `evidence.ts` | Content-addressed evidence store, `recordEvidence`, and the `tool_result` hook |
| `verify.ts` / `audit-claims.ts` | `/re verify` (reproducibility) and the side-turn claim-support auditor |
| `findings.ts` | `record_finding` / `retract_finding`: the model's conclusions as gated `re.finding` claims |
| `carry.ts` / `anchor.ts` | `/re carry` (replay a manifest on another build, `--inherit`) and anchor fingerprints/relocation |
| `audit.ts` | The RE tool-name sets (the audit gate) + signed audit log |
| `preserve.ts` | Compaction preservation (`session.compacting`) |
| `ui.ts` | Status band, overlay panels, evidence helpers |
| `report.ts` / `annotations.ts` / `entries.ts` / `disasm.ts` / `format.ts` / `render.ts` | Report gate, annotation replay, branch entry helpers, disassembly, result formatting, tool renderers |

## Data that outlives a process

Evidence, annotations, and the open binary are persisted as omp **custom session entries** (`pi.appendEntry`), which live on the session branch and are **not** sent to the model. They survive respawns, resumes, branches, and compaction. On resume or branch change the evidence index is rebuilt and the branch's annotations are replayed into the fresh rizin process; on compaction, `preserve.ts` folds a snapshot of this state into the summary so the model's working memory stays grounded even though the entries themselves were never at risk.

## References

- [omp](https://omp.sh) — the host agent
- [rizin](https://rizin.re) — the reverse-engineering toolkit omp-re drives
