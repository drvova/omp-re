# Architecture

omp-re is an [omp](https://omp.sh) extension that drives [rizin](https://rizin.re)
for reverse engineering. Internally it is composed on one
[cordis](https://github.com/cordiverse/cordis) `Context` — the "context
paradigm" from *A Programming Paradigm for Spatiotemporal Composability* — so
process lifecycle and subsystem wiring are declarative rather than hand-rolled.

## The two cordis roles

cordis shows up in exactly two places, each matching one half of the paradigm.

### 1. Revertible effects — process lifecycle (`runtime.ts`)

A rizin process is a resource with a lifetime: spawn, respawn on death or
branch change, close on shutdown. That used to be a `Map` of nullable fields
with `.close()` calls sprinkled across the code. It is now a single `RizinBackend`
(a process-wide singleton) that owns one root `Context`:

- Each omp session (keyed by `ctx.sessionManager.getSessionId()`) gets a
  **child scope** — a cordis fiber created from the root context.
- Each process it owns — the static analysis session (`rizin -q0 -N`) and the
  opt-in debug session (`rizin -d`) — is a **`ctx.effect`** whose setup returns
  its own teardown (`() => rz.close()`). The runtime holds that inverse.

The consequences fall out for free:

| Event | Mechanism |
| --- | --- |
| Respawn (process died / stale after a branch) | dispose the one rizin effect, create a new one |
| `/tree` navigation to a branch with different annotations | dispose the effect; the next tool call respawns and replays that branch's annotations |
| `debug stop` | dispose just the debug effect; the static session is untouched |
| `session_shutdown` / `session_before_switch` | dispose the whole session scope — every process effect's inverse runs |

`RzSession` (`rizin.ts`) stays the low-level transport: the `-q0` NUL-framed
pipe, with abort, timeouts, and stderr capture. cordis owns *when a process
lives and dies*, not how bytes move.

`state.ts` is a thin facade over the backend (`getState`, `ensureRizin`,
`spawnRizin`, `shutdownState`, `rekeyState`, `syncAnnotationsToBranch`,
`startDebug`, `stopDebug`, `requireDebug`). `getState()` stays synchronous and
returns a plain per-session record, so the many call sites that read and write
counters and paths are unchanged; the cordis scope attaches lazily on the
first spawn.

### 2. Reactive coeffects — subsystem composition (`app.ts`)

`composeApp(pi, subsystems)` is the extension's composition root, built once
per extension load:

- A fresh `Context` is created (per load, not a process singleton, so
  concurrent omp sessions in one process never share a host service).
- The omp host, `pi`, is provided as a service: `app.provide("pi", pi)`.
- Every subsystem is a cordis **plugin** that declares `inject: ["pi"]`, so it
  activates only once the host is present — the paper's *reactive coeffect*
  (spatial composability). `composeApp` awaits each plugin, so the async ones
  (the triage / CLI probes that stat PATH) finish before init completes.

The subsystems, in load order (`index.ts`):

```
re:read-tools   re:mutate-tools  re:rizin-repl  re:rizin-cli
re:triage-tools re:debugger      re:evidence    re:audit
re:preserve     re:ui            re:shell
```

Each subsystem's registration stays a plain `(pi) => …` function (see
`tools-*.ts`, `evidence.ts`, `audit.ts`, `ui.ts`, `preserve.ts`, and
`registerShell` in `index.ts`), so it is unit-testable in isolation; `app.ts`
only wires them onto the graph.

## Teardown, honestly

omp's `ExtensionAPI` returns no handle from `on()`, `registerTool()`,
`registerCommand()`, `registerMessageRenderer()`, or `registerFlag()`, and
exposes no extension-unload hook. So a listener or tool, once registered,
cannot be removed — those subsystems are **register-once by the host's
design**, and their plugin nodes carry no inverse because there is nothing to
undo. The teardown that is real is the per-session process lifecycle above;
omp's one supported toggle, `setActiveTools`, is what `/re off` uses. The
context graph buys declarative, dependency-ordered composition and one place
to see every subsystem — not host-level hot-unload, which the host does not
offer.

## Module map

| File | Responsibility |
| --- | --- |
| `index.ts` | Extension entry; `registerShell` (renderers, `open_binary`, `--binary`, session-lifecycle handlers, completions, the `/re` command); the `composeApp` call |
| `app.ts` | cordis composition root (`composeApp`) |
| `runtime.ts` | cordis backbone: root `Context`, `RizinBackend`, per-session scopes, process effects |
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

## References

- cordis — the meta-framework: <https://github.com/cordiverse/cordis>
- *A Programming Paradigm for Spatiotemporal Composability* — the paradigm
  (revertible effects, reactive coeffects, the context paradigm):
  <https://github.com/cordiverse/paper>
