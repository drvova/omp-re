# Architecture

omp-re is one engine and two hosts. On both, the model has one way in — the
host's own `eval` — and the same verbs there.

```
                       engine/            ASDF system omp-re
                 rizin, the read-only policy, the session record,
                 evidence, annotations, findings, verify, report,
                 carry, the debugger, the lines, the views
                    |  the surface: engine/engine.lisp
                    |  the port:    engine/host.lisp
        +-----------+-----------+
        |                       |
   nodecode/                 stdio/  +  extensions/re/  +  skills/re-triage/
   system nodecode-re        system omp-re-stdio, a TypeScript shim, and
   in the nodecode image     the library omp's eval loads
                             a child SBCL process beside omp
        |                       |
   (re:cmd "aflj")           await re.cmd("aflj")   omp_re.cmd("aflj")
   verbs in eval             the same verbs in eval's two kernels
        +-----------+-----------+
                    |
              recipes/api.json     one description of the verbs
              recipes/tables.json  one description of the recipes
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
parameters, the audit line is written, the body runs, and for `rizin_command`
the result is recorded as evidence. Code that composes reads (a recipe, the
line `carry`, `adopt_finding`) makes each read a call in its own right or goes
through the same gate; there is no second way to reach rizin.

Beside its tools the engine has **lines** (`define-slash` in `engine/slash.lisp`):
`report out.md`, `verify --strict`, `evidence`, `tools`, `doc <tool>`. A line
is a command the model runs. The code and the engine's text call them `/re`
lines, from when an operator typed them after `/re` on both hosts; no host has
that command now, and the name was left, since the model's verb for running
one is `slash` on every host and renaming half of that would help nobody. A
host's voice says how its model runs one.

What a host builds on is `engine/engine.lisp`: what tools there are, calling
one, running one line, and — for a host with a screen and sessions it starts
and ends — views, the status band's facts, the lines to keep through a
compaction, restore, rekey and close. Each answers plain JSON data and none
signals: a failure is an answer with `failed` true and the reason as its text.

A tool is declared once (`define-tool`): its name, parameters, what it does,
whether a result is evidence. Neither host holds a list of tools: the lines
`tools` and `doc` answer from the declarations.

Nothing in the engine tells an operator from a model, and nothing gates a
call but the engine's own policy. There used to be both: an operator typed
`/re` lines and could switch the tools off for a session, and omp asked about
each tool call on a tier the tool declared. With one way in on each host —
`eval`, which the host approves as a whole — none of that had a caller, and
it is gone.

What a host may name is what `engine/package.lisp` exports, and two things
hold a host to it.

**The exported functions are typed.** `engine/types.lisp` names the few kinds
of thing that cross the boundary (a session's id, a JSON object and array as
`engine/json.lisp` makes them, an answer, a level, an address as text, a
record's id, a SHA-256 digest), and every exported function is declared in
those words beside its definition (`declaim ftype`). SBCL checks a caller
against a declared type when the caller is compiled, so a host that passes
the wrong thing gets a compiler warning, and `scripts/check-warnings.lisp`,
which CI runs, compiles the three systems from scratch and fails on any
warning. The helpers are ordinary typed functions: called with the wrong
type they signal a `TYPE-ERROR`. The surface functions that promise never to
signal keep that promise for a wrong type too (`define-surface` in
`engine/engine.lisp`): they answer what they answer for any refusal, with
the text `omp-re: engine-call: name must be of type string, not 42`.

**The package is locked** (`(:lock t)` in its `defpackage`, an SBCL package
lock). Code in any other package that defines, redefines or removes a
function, macro or variable named by a symbol of `OMP-RE`, or interns a new
symbol there, signals a package-lock violation instead of taking effect. So
a host's helper that happens to share a name with one of the engine's is an
error when the host is compiled, not a changed engine. The engine's own
files are in the package and are not affected, and the macros a host builds
with (`with-host-service`) expand to nothing the lock forbids. A test may
read an internal with `omp-re::`; to stand in for something of the engine's
it answers a service of the port (`with-host-service`), it does not
redefine.

## The port (`engine/host.lisp`)

A few things only the host can say or do: what the operator configured, who is
calling, where a session's record is kept and which of it is on the current
branch, how to tell the operator something, whom to ask a side question, where
a result too large to send is kept. A host installs functions for these
(`install-host`); every one is optional, and each has an answer for when no
host is installed, so the engine also runs alone — which is how the Lisp suite
tests it and what CI's "the engine loads alone" step holds.

Settings are declared once, in `+settings+`: the member of nodecode's `re`
section, the environment variable, or both. A setting only one host reads is
declared by that host the same way (`audit_seconds`, in `nodecode/cell.lisp`).
`nodecode/config.example.jsonc` is written from those tables and the suite
checks they agree.

The wording a host needs its own way (how to open a binary, how to switch the
debugger on, the manual `rizin_command ""` answers) is a table of phrases
(`+voice+`) a host may replace by key.

## The nodecode host (`nodecode/`, system `nodecode-re`)

The engine is loaded into the nodecode organism's own image. The host is
three files, and a nodecode name (`nlk:`, `nle:`) appears only in the first
and the last:

- `nodecode-host.lisp` makes the host's package and answers the record services: entries are stamped with
  the turn they were written in, and a call reads those on the session's
  branch.
- `verbs.lisp` is what a verb is written in: a keyword list onto the engine's
  JSON, one call, one line. The verbs themselves — functions in the `RE`
  package called from `eval` — are `verb-forms.lisp`, generated from
  `recipes/api.json`, the same description omp's two libraries are generated
  from. `RE` (`nodecode-re`) is this host's own package: it uses what the
  engine's package exports (`engine/package.lisp`) and nothing else of it.
- `cell.lisp` declares the cell: the config section, the manual, the side
  question a support audit asks, start and stop. It contributes no command.

The recipes (`recipes.lisp`, with `recipe-data.lisp` generated from
`recipes/tables.json`) live here because they are verbs. See
[`nodecode.md`](nodecode.md).

## The omp host (`stdio/`, system `omp-re-stdio`; `extensions/re/`)

omp is a TypeScript program, so the engine runs beside it as one SBCL child
for the whole omp process — the main session and every task subagent are
session ids on one pipe. `stdio/server.lisp` answers the port by asking omp
over that pipe; `stdio/voice.lisp` holds omp's phrases and manual. Like the
nodecode host, it is a package of its own (`omp-re-stdio`) that uses only what
the engine's package exports.

The process itself is one function, `main` in `stdio/server.lisp`: standard
output becomes the wire, everything else that prints goes to standard error,
the first line is `{"ready": …}`, and omp is served until it leaves. It is
reached two ways. `stdio/serve.lisp` loads the system from source
(`stdio/load.lisp`) and calls it. A saved image of the system starts in
`image-main`, which calls it; `scripts/build-image.ts` (with its Lisp half,
`scripts/build-image.lisp`) is the one thing that saves an image. From the
`ready` line on the two are the same program, and `hello` says which it is.

The conversation is described once, as data, in `stdio/protocol.json`: each
method either way, its members and types, the version, the constants and keys
both sides share. `stdio/protocol.lisp` loads it; the server finds each
method's handler from it and refuses what it does not have, in and out.
`scripts/gen-protocol.ts` writes omp's types from it
(`extensions/re/protocol.ts`) and the tables of
[`engine-protocol.md`](engine-protocol.md), which has the prose.

`extensions/re` is the other end, and is thin on purpose:

- `protocol.ts` is generated: the wire's types, methods, constants and keys.
- `image.ts` says how the engine process is started, as one rule tried in
  order: the image `OMPRE_ENGINE_IMAGE` names; an image shipped in the
  plugin's `dist/`; an image it builds once with the user's SBCL and keeps
  in the user's cache, under a name that changes with the plugin's version,
  its Lisp source, the SBCL and the system; and `stdio/serve.lisp`. A way
  that does not come to say `ready` hands on to the next, and omp's log says
  why. [`install.md`](install.md#the-engine-image) is the operator's side.
- `engine.ts` starts the child that rule gives, frames messages, bounds how
  long it waits (a start deadline, and the engine's silence while a request
  is under way) and ends it. It does not know what a message means.
- `host.ts` keeps the one engine of the process (on `globalThis`, because omp
  imports an extension afresh for each session) and answers the engine's
  requests: the session's record is omp's own session file, artifacts are
  omp's, the side question is omp's `runEphemeralTurn`. It is also where a
  request from a cell of `eval` is answered: for which session it is, and the
  `call` or `command` it becomes.
- `bridge.ts` is the listener a cell reaches: the socket, the token, the
  file a kernel finds it by. It knows nothing of sessions or the engine.
- `index.ts` registers nothing a model or an operator calls. It forwards the
  session's life to the engine, hands omp the lines to keep through a
  compaction, binds the keys of the panels, and watches the one tool the
  model's calls arrive in: `eval`.
- `ui.ts` draws what the engine sends: the status band's lines, the panels,
  the code view. It does not know a record's shape.

The engine is started when a session starts, to bring back the binary the
session had open; a model's first call would start it as well. That start is
a few milliseconds from an image, or a few seconds the first time after an
install or upgrade, when the engine is compiled and its image saved. If the
child dies, the next call starts another and each session comes back from its
record.

### omp: the way in from `eval`

omp's model has one code tool, `eval`, with a JavaScript and a Python kernel,
and that is where it calls the engine from. The plugin registers no tool, so
`tool.<name>()` reaches nothing of it and `xd://` lists nothing of it. omp
also gives an extension nothing to put into a kernel — no global, no prelude,
no module — and a kernel is a separate process, a child of omp's.
[`omp-eval.md`](omp-eval.md) has each of those facts from omp's source, pinned
by a test.

So the way in is the one an unsandboxed child process has: a socket.

```
 eval cell (a kernel process)                 omp's process                    the engine
 re.cmd("aflj")
   skills/re-triage/recipes.js   --HTTP-->  extensions/re/bridge.ts
   (or recipes.py: omp_re.cmd)   loopback,   the token, the path
                                 a token       |
                                             host.ts: which session?  --pipe-->  call / command
                                               the kernel's session file,          (stdio/protocol.json)
                                               or its directory
```

- **The library** is what the `re-triage` skill ships and the model loads with
  `%load skill://re-triage/recipes.js` (or `.py`): the verbs, and the recipes
  composed over them. Its verbs are generated from `recipes/api.json` by
  `scripts/gen-api.ts`, which writes nodecode's verbs from the same file; its
  recipes' data from `recipes/tables.json` by `scripts/gen-recipes.ts`. What
  is written by hand in each language is the client of the listener and the
  loop that renders a recipe.
- **The listener** is one per omp process, on `127.0.0.1`, a port the system
  picks, alive while a session with the plugin is. A request carries a
  32-byte token. The token and the port are in a file only the user can read,
  named for omp's process id; a kernel finds its parent's.
  [`engine-protocol.md`](engine-protocol.md#the-other-wire-a-kernel-of-omps-eval-to-the-extension)
  has the wire, and [`SECURITY.md`](../SECURITY.md#the-listener-omps-eval-reaches-the-engine-through)
  what it protects.
- **The session** a request is for is the one omp gave that kernel: omp keys
  a kernel by the session's file and directory. Two sessions with no file in
  one directory share a kernel and cannot be told apart, which is refused.
- **Giving up** needs no hook: a cell that times out or is interrupted closes
  its connection, and the shim tells the engine `cancel`.
- **The audit log** names a call by the `eval` call it came from and its place
  in that cell, which the shim knows from omp's `tool_call` event.

Why not the alternatives: the engine cannot listen itself or be started by a
kernel, because its record is omp's session file, which only the shim can
read and append to; a kernel cannot be handed the listener's address in the
environment, because omp filters the Python kernel's environment; a Unix
socket would need a second design for Windows, whose Python has none; and
rewriting the model's cell to load the library for it would change what the
transcript says the model wrote.

What omp gates is the cell: `eval` is one `exec`-tier tool. Inside a cell the
engine's policy is the control ([`SECURITY.md`](../SECURITY.md#what-omp-approves)).

## Where a change lands

| To change | Edit | Held by |
| --- | --- | --- |
| a tool, its parameters, a refusal's words | the tool's `define-tool` in `engine/` | `test/nodecode/suite-*.lisp` |
| what `rizin_command` may run | `engine/policy-data.lisp`, `engine/policy.lisp` | `suite-core`, `suite-debug` (the on-hit policy) |
| a line | its `define-slash` in `engine/` | the suites; `test/extension-sdk.test.ts` for a line run from a cell |
| a verb the model calls: its arguments, what it does, how it refuses | `recipes/api.json`, then `bun run gen:api`; what a verb is written in is `nodecode/verbs.lisp` and the client in `skills/re-triage/recipes.js` and `recipes.py` | `bun run check:api`; `suite-core` (nodecode's verbs); `test/extension-sdk.test.ts` (both kernels) |
| how a cell reaches the engine: the listener, its file, which session | `extensions/re/bridge.ts`, `host.ts`; the client in the two libraries; the prose of [`engine-protocol.md`](engine-protocol.md) | `test/bridge.test.ts`; what it stands on in omp, `test/omp-eval-contract.test.ts` |
| a setting | `+settings+` in `engine/host.lisp` | `suite-core` (the example file equals the declaration) |
| what a host may call, and with what | the export in `engine/package.lisp`, the `declaim ftype` beside the function, a new kind of value in `engine/types.lisp` | `scripts/check-warnings.lisp` (both hosts compile against it with no warning); `suite-core` (a wrong type is refused in words; the package is locked) |
| how the engine process is started | `extensions/re/image.ts`; `main` and `image-main` in `stdio/server.lisp`; `scripts/build-image.lisp` | `test/image.test.ts`, with real images; `suite-stdio` for the start from source |
| what a panel or the code view shows | `engine/views.lisp` | `suite-views` |
| how omp draws it | `extensions/re/ui.ts` | `test/shim.test.ts` (the band and the overlays, drawn without colours) |
| a key binding | `keys` in `stdio/protocol.json`, then `bun run gen:protocol` | `test/shim.test.ts`; `suite-stdio` (each names a view the engine has) |
| a message between omp and the engine | `stdio/protocol.json`, then `bun run gen:protocol`; its handler in `stdio/server.lisp` or `extensions/re/host.ts`, its sender, and the prose of [`engine-protocol.md`](engine-protocol.md) | the type check (omp's side) and the server's load (a method with no handler); `suite-stdio` and `test/shim.test.ts`, whose stand-ins check every message against the same file |
| nodecode's primer, its settings, its side question | `nodecode/cell.lisp` | `suite-core`, `suite-audit`, over a stand-in for nodecode's kernel |
| a recipe's reads, wording or tables | `recipes/tables.json`, then `bun run gen:recipes` | `test/recipes-eval.test.ts` (three hosts, whole reports); `suite-recipes` |

A new tool needs no TypeScript and no change to a library: `re.call` reaches
whatever the engine offers, and `re.tools()` lists it.

## Data that outlives a process

| What | Under omp | Under nodecode |
| --- | --- | --- |
| The session's record | custom entries (type `re.…`) in omp's own session file, on its branch | a file of entries under `state_dir`, each stamped with its turn |
| Evidence blobs, the audit log | `<omp agent dir>/re/` | under `state_dir` |
| A result too large to send | an omp session artifact, `artifact://<id>` | a file beside the record |

Record entries are never sent to the model. On compaction under omp the engine
hands omp the lines to fold into the summary (the open binary, counts, recent
evidence ids, live findings), so the model stays grounded.
