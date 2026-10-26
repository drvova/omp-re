# Architecture

omp-re is an [omp](https://omp.sh) extension that drives [rizin](https://rizin.re)
for reverse engineering. It has **no third-party runtime dependencies** — an
installed omp plugin can only resolve the host's own `@oh-my-pi/*` packages, so
everything below is hand-rolled on top of them.

## The run tool

omp-re advertises one tool, `run` (`tools-run.ts`), which executes
TypeScript/JavaScript; every RE operation is a method on `re` inside it. The
pieces:

```
index.ts       composeApp(registry.host(pi), [...subsystems])   then registerRunTool(pi, registry)
                 │  every pi.registerTool({...}) lands in the registry, not in omp
capabilities.ts  CapabilityRegistry: name → definition, tier, evidence flag, JSON Schema
                 invokeCapability: validate → audit line → definition.execute → evidence record + tag
namespace.ts   host side: one worker per omp session (on the session record in runtime.ts);
                 queues cells, collects output, answers the worker's calls (capabilities,
                 raw rizin, evidence, exec, MCP), terminates the worker on cancel
namespace-worker.ts
               the worker: its global IS the namespace, seeded with re, describe, man, kept,
                 forget, strings, print, exec, mcp, require; loads kept units; evaluates
                 cells; saves definitions
namespace-protocol.ts
               the messages between them: run/done/failed, print, call/reply
mcp.ts         MCP servers as functions: omp's MCP client and config, connections owned by the host
cell.ts        compileCell: Babel parse (omp's own parser) → strip TS (Bun.Transpiler)
                 → top-level declarations become assignments on the realm's global,
                   functions hoisted, last expression returned, `import` → await import()
                 findDefinitions: functions, classes, consts with static initializers
kept.ts        <OMPRE_KEPT_DIR or agent dir>/re/kept/<name>.ts, one definition per file
describe.ts    describe(x) and the manual: signatures from schemas and introspection
```

**Why nothing stays a wrapper local.** A cell runs as
`(async (g, import) => { … })`, so its own `const`/`function` would die with
the call — or worse, a helper defined in it would keep calling its sibling
from that cell after a later cell redefined the sibling. Every top-level
binding is instead written to the realm's global (`g["name"] = …`), so every
name a helper uses is read late, from the namespace — the same resolution a
helper gets when it is reloaded alone after a restart. The wrapper is strict,
so assigning to a namespace name that is read-only (`re`, `describe`, …)
throws instead of silently doing nothing.

**Why only definitions persist.** A function, class, or a `const` bound to a
literal, function, class, or plain data built from them can only define
something when it is evaluated again; anything with a call, `await`, or `new`
of a non-builtin does work. Only the former are saved, so a restart rebuilds
the model's tools and never re-runs its analysis. On load each file is
re-parsed and must be exactly one such definition of the name it is filed
under; a unit that throws (it may name one loaded later) is retried after the
rest, and one that still fails is reported in the manual and `kept()`.

**Why a worker.** Cells must not define names on omp's own global object,
each session needs its own namespace, and a call must be stoppable. A Bun
Worker gives all three: its global is a fresh realm, and terminating it ends
even a loop that never yields — something no in-thread realm (`node:vm`
included) can do once the loop has started. A cell that calls `process.exit()`
or crashes ends only the worker; a timer's late exception is caught by the
worker's own `uncaughtException`/`unhandledRejection` handlers and printed.
After a stop the host starts a fresh worker on the next call, which reloads
the kept definitions. Everything that needs omp crosses as a message
(structured clone): the worker asks, the host performs the operation with the
running call's context and signal and replies, so killing a worker never
leaves omp half-way through an operation — and the signal reaches whatever
the host was doing. MCP connections live on the host for the same reason: a
stdio server is a child process a terminated worker must not orphan. The
worker is unreferenced while idle, so it never keeps omp alive. It is a
naming and lifetime boundary, not a security boundary; the tool runs with
omp's authority, and the sandbox is the deployment's (see `SECURITY.md`).

**What did not change.** The operations' code and tests: each tool module
still builds its definitions with `pi.registerTool`, and the unit tests drive
those definitions directly through a stub host. The evidence and audit hooks
still exist for any tool that is registered for real; `invokeCapability` calls
the same `recordAndTag` and `appendAuditLine` they do.

## Process lifecycle (`runtime.ts`)

A rizin process is a resource with a lifetime: spawn, respawn on death or
branch change, close on shutdown. That used to be a `Map` of nullable fields
with `.close()` calls sprinkled across the code. It is now a single
`RizinBackend` (a process-wide singleton) that gives each omp session (keyed by
`ctx.sessionManager.getSessionId()`) a small **teardown scope**:

- Each process the session owns — the static analysis session (`rizin -q0 -N`)
  and the opt-in debug session (`rizin -d`) — registers its `close()` on the
  scope as an **effect** and gets back an idempotent **disposer**.
- Calling one disposer closes exactly that process; disposing the whole scope
  closes every process the session still owns (most-recent first).

The consequences fall out for free:

| Event | Mechanism |
| --- | --- |
| Respawn (process died / stale after a branch) | run the one rizin disposer, register a new effect |
| `/tree` navigation to a branch with different annotations | run the disposer; the next tool call respawns and replays that branch's annotations |
| `debug stop` | run just the debug disposer; the static session is untouched |
| `session_shutdown` / `session_before_switch` | dispose the whole session scope — every registered teardown runs |

`RzSession` (`rizin.ts`) stays the low-level transport: the `-q0` NUL-framed
pipe, with abort, timeouts, and stderr capture. The scope owns *when a process
lives and dies*, not how bytes move.

`state.ts` is a thin facade over the backend (`getState`, `ensureRizin`,
`spawnRizin`, `shutdownState`, `rekeyState`, `syncAnnotationsToBranch`,
`startDebug`, `stopDebug`, `requireDebug`). `getState()` stays synchronous and
returns a plain per-session record, so the many call sites that read and write
counters and paths are unchanged; the scope attaches lazily on the first spawn.

## Subsystem composition (`app.ts`)

`composeApp(pi, subsystems)` is the extension's composition root, run once per
extension load: it applies each subsystem in order, handing the omp host (`pi`)
to each, and awaits every one — so the async subsystems (the triage / CLI
probes that stat PATH) finish before init completes. Each subsystem needs only
the host, which is always present, so a plain sequential `await` gives the
ordering with nothing to resolve. (This was a cordis `Context` graph until the
cordis dependency stopped the installed plugin from loading; see the
`[0.3.0]` CHANGELOG entry.)

The subsystems, in load order (`index.ts`):

```
re:read-tools   re:mutate-tools  re:rizin-repl  re:rizin-cli
re:triage-tools re:debugger      re:evidence    re:audit
re:preserve     re:ui            re:shell
```

Each subsystem's registration stays a plain `(pi) => …` function (see
`tools-*.ts`, `evidence.ts`, `audit.ts`, `ui.ts`, `preserve.ts`, and
`registerShell` in `index.ts`), so it is unit-testable in isolation; `app.ts`
only sequences them.

## Teardown, honestly

omp's `ExtensionAPI` returns no handle from `on()`, `registerTool()`,
`registerCommand()`, `registerMessageRenderer()`, or `registerFlag()`, and
exposes no extension-unload hook. So a listener or tool, once registered,
cannot be removed — those subsystems are **register-once by the host's
design** — with no unregister call, there is nothing to undo. The teardown
that is real is the per-session process lifecycle above;
omp's one supported toggle, `setActiveTools`, is what `/re off` uses. There is
no host-level hot-unload — the host does not offer one.

## Module map

| File | Responsibility |
| --- | --- |
| `index.ts` | Extension entry; `registerShell` (renderers, `open_binary`, `--binary`, session-lifecycle handlers, completions, the `/re` command); the `composeApp` call and `registerRunTool` |
| `tools-run.ts` | `run`, the one advertised tool: description, approval, result shape |
| `capabilities.ts` | The capability registry (the `registerTool` shim) and `invokeCapability`, the one path a `re.<name>` call takes |
| `namespace.ts` | The per-session namespace, host side: the worker's lifetime, the cell queue, cancellation, answering the worker's calls |
| `namespace-worker.ts` | The worker the cells run in: vocabulary, evaluation, kept-unit loading and saving, output |
| `namespace-protocol.ts` | The host↔worker messages |
| `mcp.ts` | MCP servers as functions, through omp's own MCP client |
| `values.ts` | How printed and returned values read (JSON), error text |
| `cell.ts` | The cell compiler (top-level declarations → namespace globals) and definition detection |
| `kept.ts` | Kept definitions on disk, one file per name |
| `describe.ts` | `describe(x)` and the manual |
| `app.ts` | Composition root (`composeApp`): applies each subsystem in order with the host |
| `runtime.ts` | `RizinBackend`: per-session teardown scopes that own the rizin/debug process lifecycle |
| `state.ts` | Thin facade over `RizinBackend` |
| `rizin.ts` | `RzSession` transport (`-q0` pipe), spawn flags, validators, `rz-*` tool resolution |
| `catalog.ts` | rizin's self-described command catalog (`?*j`) and the `rizin_command` policy |
| `tools-read.ts` / `tools-mutate.ts` | The 14 read-tier and 15 mutate-tier capabilities |
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
| `audit.ts` | The RE capability-name sets (the audit gate, the evidence tier) + signed audit log |
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

- [omp](https://omp.sh) — the host agent
- [rizin](https://rizin.re) — the reverse-engineering toolkit omp-re drives
