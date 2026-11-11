# Architecture

omp-re is one engine and two hosts.

```
                       engine/            ASDF system omp-re
                 rizin, the read-only policy, the session record,
                 evidence, annotations, findings, verify, report,
                 carry, the debugger, /re, the views
                    |  the surface: engine/engine.lisp
                    |  the port:    engine/host.lisp
        +-----------+-----------+
        |                       |
   nodecode/                 stdio/  +  extensions/re/
   system nodecode-re        system omp-re-stdio, and a TypeScript shim
   in the nodecode image     a child SBCL process beside omp
```

The engine is Common Lisp and runs on SBCL. It knows nothing of either host.
There was once a second engine, in TypeScript, for omp; it is gone, and
nothing in `extensions/re` decides anything about reverse engineering.

## The engine (`engine/`, system `omp-re`)

A **session** is the engine's state for one host session: the open binary, the
rizin process analyzing it, and the session's **record** — an append-only list
of entries (`re.binary`, `re.evidence`, `re.annotation`, `re.finding`, …). The
record is the truth and the process is a cache of it. A rizin that died, a
session closed for idleness and a host that restarted all come back the same
way: rizin is started on the recorded binary and what the record says was done
to it is replayed. A tool group says what it replays and in what order
(`contribute` in `engine/session.lisp`): mapped files, then analysis passes,
then signatures, then annotations.

rizin is driven over `rizin -q0`: one NUL after every response, and a unique
`echo` marker after each command so the stream cannot lose its place. The
caller reads the pipe itself under the session's lock. A command whose caller
gave up is left to finish and its output is skipped by the next command, so
the process and its analysis survive; a timeout kills the process and the next
call starts another.

Every tool call, whoever makes it, goes through one function (`call-tool` in
`engine/call.lisp`): the arguments are checked against the tool's declared
parameters, `/re off` refuses, the audit line is written, the body runs, and
for `rizin_command` the result is recorded as evidence. Code that composes
reads (a recipe, `/re carry`, `adopt_finding`) makes each read a call in its
own right or goes through the same gate; there is no second way to reach
rizin.

What a host builds on is `engine/engine.lisp`: what tools and `/re`
subcommands there are, calling one, running one `/re` line, and — for a host
with a screen and sessions it starts and ends — views, the status band's
facts, the lines to keep through a compaction, the approval gate's decision,
restore, rekey and close. Each answers plain JSON data and none signals: a
failure is an answer with `failed` true and the reason as its text.

A tool is declared once (`define-tool`): its name, parameters, approval tier,
the sentence an approval prompt shows, and how a transcript should draw its
result. Both hosts read that declaration. Neither holds a list of tools.

## The port (`engine/host.lisp`)

A few things only the host can say or do: what the operator configured, who is
calling, where a session's record is kept and which of it is on the current
branch, how to tell the operator something, whom to ask a side question, where
a result too large to send is kept. A host installs functions for these
(`install-host`); every one is optional, and each has an answer for when no
host is installed, so the engine also runs alone — which is how the Lisp suite
tests it and what CI's "the engine loads alone" step holds.

Settings are declared once, in `+settings+`: the member of nodecode's `re`
section, the environment variable, or both. `nodecode/config.example.jsonc` is
written from that table and the suite checks the two agree.

The wording a host needs its own way (how to open a binary, how to switch the
debugger on, the manual `rizin_command ""` answers) is a table of phrases
(`+voice+`) a host may replace by key.

## The nodecode host (`nodecode/`, system `nodecode-re`)

The engine is loaded into the nodecode organism's own image. Three files are
the only places a nodecode name (`nlk:`, `nle:`) appears:

- `nodecode-host.lisp` answers the record services: entries are stamped with
  the turn they were written in, and a call reads those on the session's
  branch.
- `verbs.lisp` is the model's surface: functions in the `RE` package called
  from `eval`, over the engine's surface.
- `cell.lisp` declares the cell: the config section, the manual, `/re` and its
  dialog, the side question a support audit asks, start and stop.

The recipes (`recipes.lisp`, with `recipe-data.lisp` generated from
`recipes/tables.json`) live here because they are verbs. See
[`nodecode.md`](nodecode.md).

## The omp host (`stdio/`, system `omp-re-stdio`; `extensions/re/`)

omp is a TypeScript program, so the engine runs beside it as one SBCL child
for the whole omp process — the main session and every task subagent are
session ids on one pipe. `stdio/server.lisp` answers the port by asking omp
over that pipe; `stdio/voice.lisp` holds omp's phrases and manual. The
conversation is written down in [`engine-protocol.md`](engine-protocol.md).

`extensions/re` is the other end, and is thin on purpose:

- `engine.ts` starts the child, frames messages and ends it. It does not know
  what a message means.
- `host.ts` keeps the one engine of the process (on `globalThis`, because omp
  imports an extension afresh for each session) and answers the engine's
  requests: the session's record is omp's own session file, artifacts are
  omp's, the side question is omp's `runEphemeralTurn`.
- `index.ts` asks the engine what tools and subcommands exist and registers
  exactly those with omp, forwards calls and the session's life, and fills an
  approval sentence from the data the engine sent.
- `ui.ts` and `render.ts` draw what the engine sends: the status band, the
  panels, the code view, a tool's transcript card.

The engine is started while the extension's factory runs, not later: omp
accepts tool registrations only then, and the tool list comes from the engine.
That start is about a quarter of a second, or a few seconds the first time
after an install or upgrade, when ASDF compiles the engine into the user's
cache. If the child dies, the next call starts another and each session comes
back from its record.

Every RE tool is registered `discoverable`, so omp mounts it as an
`xd://<name>` device and the model reaches it from omp's `eval` as
`tool.<name>()`. Whichever way a call arrives, omp's tool wrapper applies the
tool's approval tier and then runs the one `execute` that forwards to the
engine. [`omp-eval.md`](omp-eval.md) is what the plugin relies on there.

## Where a change lands

| To change | Edit | Held by |
| --- | --- | --- |
| a tool, its parameters, its approval sentence, a refusal's words | the tool's `define-tool` in `engine/` | `test/nodecode/suite-*.lisp`; approval sentences also `test/shim.test.ts` |
| what `rizin_command` may run | `engine/policy-data.lisp`, `engine/policy.lisp` | `suite-core`, `suite-debug` (the on-hit policy) |
| a `/re` subcommand | its `define-slash` in `engine/` | the suites; `test/extension-sdk.test.ts` for omp's help and errors |
| a setting | `+settings+` in `engine/host.lisp` | `suite-core` (the example file equals the declaration) |
| what a panel or the code view shows | `engine/views.lisp` | `suite-views` |
| how omp draws it, a key binding | `extensions/re/ui.ts`, `render.ts` | type check only; the tmux tiers by hand |
| a message between omp and the engine | `stdio/server.lisp`, `extensions/re/host.ts` or `index.ts`, and [`engine-protocol.md`](engine-protocol.md) | `suite-stdio` (the Lisp end, over real pipes), `test/shim.test.ts` (omp's end) |
| a verb, the nodecode dialog, the primer | `nodecode/verbs.lisp`, `nodecode/cell.lisp` | `suite-core`, over a stand-in for nodecode's kernel |
| a recipe's reads, wording or tables | `recipes/tables.json`, then `bun run gen:recipes` | `test/recipes-eval.test.ts` (three hosts, whole reports); `suite-recipes` |

A new tool needs no TypeScript: the shim registers whatever `describe` lists.

## Data that outlives a process

| What | Under omp | Under nodecode |
| --- | --- | --- |
| The session's record | custom entries (type `re.…`) in omp's own session file, on its branch | a file of entries under `state_dir`, each stamped with its turn |
| Evidence blobs, the audit log | `<omp agent dir>/re/` | under `state_dir` |
| A result too large to send | an omp session artifact, `artifact://<id>` | a file beside the record |

Record entries are never sent to the model. On compaction under omp the engine
hands omp the lines to fold into the summary (the open binary, counts, recent
evidence ids, live findings), so the model stays grounded.
