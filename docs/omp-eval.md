# omp's `eval`, as omp-re uses it

omp-re registers nothing with omp that a model calls. The model reaches its
engine from omp's own `eval`: it loads a library there (`%load
skill://re-triage/recipes.js`, or `.py`), and that library asks a listener the
extension keeps on the loopback interface. That puts a number of host
behaviours under this plugin — what a kernel is and what it is told of its
session, that it may open a socket, what happens to that socket when a cell
is stopped, `%load`, `skill://` URLs, a kernel that keeps its state — and
[omp.sh](https://omp.sh) describes almost none of them. This page writes them
down, with where each comes from, so the plugin's reliance on them can be
checked.

**Documented here:** `@oh-my-pi/pi-coding-agent` **18.11.1**, the version this
repository pins. The installed package was compared with the upstream tag
`v18.11.1` (commit `7cc91294`, 2026-10-15) of
[can1357/oh-my-pi](https://github.com/can1357/oh-my-pi): the `src/` trees are
identical but for one generated file. Upstream has since moved to 18.18.6;
[Newer than this](#newer-than-this) lists what changed that matters here.

**What this is.** A description of what omp's code does and was seen to do —
not a contract omp has made. Nothing below is promised by omp to extension
authors, and any release may change it. `test/omp-eval-contract.test.ts` is
there so that a change is noticed.

**How to read the sources.** Every claim names one:

- *contract* — pinned by a test of that name in
  [`test/omp-eval-contract.test.ts`](../test/omp-eval-contract.test.ts), which
  drives omp's real `eval` through the SDK. Where a claim is also source-read,
  both are given.
- a path — relative to `node_modules/@oh-my-pi/pi-coding-agent/src/`, with the
  function or constant to look for. Paths starting `pi-tui/` are in the sibling
  package `@oh-my-pi/pi-tui/src/`. A claim with only a path was read, not run.
- an omp.sh URL — the public docs. They are quoted wherever they say
  something; everything else is from source.

## What omp does document

| Where | What it says about `eval` |
| --- | --- |
| <https://omp.sh/docs/tools> | One table row: "Compute in a persistent kernel", class Exec; languages "Python and JavaScript by default, Ruby and Julia opt-in". Also: `tools.xdev` "is on by default. It keeps less-frequently-used and dynamically discovered capabilities in an on-demand catalog … Turning it off changes presentation, not what is permitted." |
| <https://omp.sh/docs/approvals> | `tools.approval.eval` exists, and "bash rules do not cover a shell spawned through eval". |
| <https://omp.sh/docs/skills> | "Keep detailed references, templates, or scripts beside SKILL.md and refer to them with paths relative to the skill directory." "Supporting files do not execute automatically; the playbook must explain when and how they should be used." |
| <https://omp.sh/docs/extension-authoring> | `ToolDefinition` fields, among them `loadMode` (`"discoverable"` keeps the schema out of the always-present set; custom tools default to it) and `approval`. |
| `omp://tools/eval.md`, in a session | omp's own reference page for the tool. It is not on omp.sh, but it is in the upstream repository (`docs/tools/eval.md`) and ships inside the package (`dist/docs-index.generated.txt`, served by `internal-urls/omp-protocol.ts`), so `read omp://tools/eval.md` shows it. *contract: `read("omp://tools/eval.md") is omp's own reference…`* |
| The `eval` tool description | What the model is told: `prompts/tools/eval.md`, with `eval-helpers.md`, `eval-agents.md` and `eval-judge.md` behind `xd://eval/helpers`, `xd://eval/agents`, `xd://eval/judge`. |

So "undocumented" needs a qualifier: the website says next to nothing, while
the package carries a reference page a session can read. That page covers the
tool's fields, limits and helpers. It does not say that a kernel is a process
of its own, what that process is told about the session it serves, what
`skill://` means to `%load`, or what a stopped cell does to a connection it
had open — which is most of what omp-re depends on. Where it and this page overlap,
they agree unless [Open questions](#open-questions) says otherwise.

## Cells

One `eval` call is one cell (`tools/eval.ts`, `evalSchema`):

| Field | Type | Meaning |
| --- | --- | --- |
| `language` | `"py"` \| `"js"`, required | Which kernel. There is no default and no sniffing; anything else is refused by the schema. *contract: `the language is named by a required field…`* |
| `code` | string, required | The code, or one standalone percent command ([`%load`](#load-path)). |
| `title` | string | A transcript label. |
| `timeout` | number, seconds | The cell's deadline; `0` disables it. See [Limits](#limits-and-timeouts). |
| `reset` | boolean | Start a fresh kernel for this language before running. |

`eval` is a tool like any other: essential (always top-level), `approval:
"exec"`, and exclusive — one cell at a time per session (`tools/eval.ts`,
`EvalTool`). Each language has its own kernel and its own state. `eval.py` and
`eval.js` (both default `true`; `PI_PY` / `PI_JS` override) switch a language
off, and a disabled language is removed from the schema the model sees
(`eval/settings.ts`; `tools/eval-backends.ts`, `resolveEvalBackends`).

Most of this page is written from the JavaScript kernel. [`%load`](#load-path)
and the [internal URLs](#internal-urls) hold for the Python kernel too; where
it differs — and it does, in ways `recipes.py` has to know — is in
[The Python kernel](#the-python-kernel).

### What a cell answers

- The value of the last expression is the output; a string is printed as it
  is, an object as JSON under a `display[n]:` label after whatever was
  printed; no value gives `(no output)`. *contract: `the value of the last
  expression is the cell's output…`*
- An uncaught error is the output too — the stack, then `Command exited with
  code 1` — with the result marked `isError`. The kernel and its state survive
  it. *contract: `an uncaught error is the cell's output…`*
- A refusal before any code runs — the schema, a bad percent command, the
  approval gate — is thrown by the tool instead (`ToolError`); the model sees
  an error result either way.

What comes back is cut for the model, which matters to code that returns a
long report (a recipe's is `print`ed):

| Cut | Default | Setting | Source |
| --- | --- | --- | --- |
| A line wider than 768 bytes is cut and ends `…`; a note names `artifact://<id>:raw:<n>-<n>` for the whole line | 768 | `tools.outputMaxColumns` (`0` = off) | `tools/settings.ts`; *contract: `a line wider than tools.outputMaxColumns…`* |
| Past 50 KB the middle of the output is left out, a `[…Nln elided…]` line in its place, and a last line reads `[Showing lines a-b of N (50.0KB limit). Read artifact://<id> for full output]` | 50 KB, head 20 KB | `tools.artifactHeadBytes` (`0` = keep the tail only) | `pi-tui/tools/streaming-output.ts`, `DEFAULT_MAX_BYTES`; *contract: `past 50 KB the middle of the output is left out…`* |
| A displayed JSON value is previewed to 8000 bytes; the whole value goes to the same artifact | 8000 | — | `tools/eval.ts`, `MAX_DISPLAY_TEXT_BYTES` |
| The artifact itself is capped | 16 MB | `tools.artifactMaxBytes` (`0` = no cap) | `tools/settings.ts` |

Code that needs a value whole should not return it: write it to a file, or
keep it in a variable and return a slice. The tests here do the former.

### What persists, and when it is lost

Top-level `const`, `let`, `var`, `function` and `class` declarations and
anything put on `globalThis` are there in the next cell; a `const` can be
declared again. *contract: `top-level const, let, var, function, class…`* The
tool description says "top-level state persists, including across compaction"
(`prompts/tools/eval.md`).

The state lives in one worker per kernel (an isolated subprocess, or a Bun
Worker if that fails to start: `eval/js/context-manager.ts`, `acquireSession`)
and is lost whenever that worker ends:

| The kernel ends when | What the model sees | Source |
| --- | --- | --- |
| a cell passes its deadline | `Command timed out after N seconds. The JS worker was force-killed and its VM state was reset; variables from earlier cells are gone.` | `eval/js/executor.ts`, `formatJsTimeoutAnnotation`; *contract: `a cell past its deadline is killed and the kernel with it…`* |
| a cell is aborted (the user interrupts the turn) | `Command aborted` | `eval/js/context-manager.ts`, `runOnce` (`onAbort` → `killSessionFor`); *contract: `aborting a cell kills the kernel too…`* |
| a cell asks, with `reset: true` | nothing: the cell runs in the new kernel | `executeInVmContext`, `resetVmContext`; *contract: `reset: true starts a fresh kernel…`* |
| the session is disposed, or omp exits | — | `session/eval-runner.ts`, `disposeKernels` |

Killing the worker is the only way omp has to stop JavaScript that does not
yield, so a timeout or an interrupt never leaves the state behind. A session
resumed in a new process starts with no kernel. omp keeps the model told: it
adds a note to the context listing which kernels are alive and which scripts
were `%load`ed (at most 12 paths, never values), or, when the history has
`eval` calls and no kernel is registered, saying that setup must be re-run
(`eval/state.ts`, `formatEvalStateContext`; `prompts/system/eval-state-context.md`;
`session/agent-session.ts`, `#buildEvalStateContextMessage`).

A kernel is keyed by the session's file and working directory —
`js:session:<file>:cwd:<cwd>` — and, for a session with no file, by the
directory alone, so two such sessions in one directory share a kernel and each
other's globals (`eval/session-id.ts`, `defaultEvalSessionId`). *contract: `is
keyed by the session's file and working directory…`* An interactive omp session
has a file; SDK sessions made with `SessionManager.inMemory()` do not, which is
worth knowing when reading this repository's tests. Subagents have kernels of
their own.

## The JavaScript realm

Bun, with `Bun`, `fetch`, `process`, `require`, `fs` and Web Crypto as the
worker has them; top-level `await` and a bare `return` work. *contract:
`top-level await and return work`* TypeScript syntax is stripped when a cell
looks like TypeScript (`eval/js/shared/rewrite-imports.ts`, `stripTypeScript`).

The helpers are globals installed once per kernel
(`eval/js/shared/prelude.txt`; the reserved names are `PRELUDE_GLOBAL_KEYS` in
`eval/js/shared/runtime.ts`). Signatures are as the prelude source and
`prompts/tools/eval*.md` give them; JavaScript helpers take their options
positionally or as one trailing object. *contract: `the helpers are globals of
the realm…`*

| Global | Signature | omp-re uses it |
| --- | --- | --- |
| `tool` | `await tool.<name>(args)` — a session tool; see below. Also `tool(fn, { name?, description?, parameters? })`, `tool.defined()`, `tool.undefine(name)` to define kernel-hosted tools for subagents (`eval.tools.enabled`) | no — it reaches registered tools, and omp-re registers none |
| `read` | `await read(path, { offset?, limit? })` → string. A plain path is relative to the cwd; `local://` and this session's `artifact://<id>` are read from disk; any other scheme is handed to the `read` tool | by the model, for a text the size cap cut (SKILL.md) |
| `print` | `print(value, …)` — `console.log` | **yes** — how a text the library answers is shown |
| `display` | `display(value)` — JSON, image or text, shown under `display[n]:` | in the agent file's advice only |
| `write` | `await write(path, data)` → the path written. Plain paths and `local://` only; other schemes are refused | no |
| `log`, `phase` | `log(message)`, `phase(title)` — status lines on the cell's card | no |
| `env` | `env(key?, value?)` — read or set a variable for the kernel | no |
| `output` | `await output(...ids, { format?, query?, offset?, limit? })` — `tool.read` of `agent://<id>` | no |
| `wait` | `await wait(handles, { timeout?, raiseErrors? })` — barrier over agent and completion handles | no |
| `budget` | `await budget.total()`, `.spent()`, `.remaining()`, `.hard()` | no |
| `agent`, `workpool` | `agent(prompt, { agent?, label?, schema?, schemaMode?, isolated?, apply?, merge?, tools? })` → handle; `workpool(agent?, { name?, context?, tools? })` | no |
| `completion`, `judge`, `judgeBatch` | `completion(prompt, { model?, system?, schema? })`; `await judge(state, questions, { images? })`; `judgeBatch(states, questions, { intent?, concurrency?, retries?, minOk?, images? })` | no |

A script may define any other name. `re` is free: no helper is called that, and
neither is a prelude enabled by default. *contract: `the name re is not taken
by the host…`* That is true of this realm only: in the Python kernel `re` is
[taken](#what-a-python-cell-starts-with).

## `tool.<name>(args)`

`tool` is a proxy; any property is a function that sends `(name, args ?? {})`
to the host, where `callSessionTool` (`eval/js/tool-bridge.ts`) looks the tool
up among the session's *registered* tools — built-in, an extension's, an MCP
server's — validates the arguments and executes it under that tool's own
approval. A name that is no registered tool throws `Unknown tool from js
runtime: <name>`. *contract: `reaches a tool an extension registered, and
nothing else…`*

Up to 0.11 this was omp-re's way in: every RE tool was registered, and a cell
called `tool.rizin_command(…)`. omp-re registers no tool now, so this proxy
reaches nothing of it, and that is the whole reason for what follows: with no
tool, and no way for an extension to put a global or a module into a kernel
([Eval preludes](#eval-preludes)), a cell has to reach the plugin some other
way.

## A kernel is a process of its own

This is what omp-re's way from a cell to its engine stands on
(`extensions/re/bridge.ts`; [`ARCHITECTURE.md`](ARCHITECTURE.md#omp-the-way-in-from-eval)).
None of it is said to extension authors anywhere.

### Whose child it is

The JavaScript kernel is a separate Bun process — `bun <omp's cli>
__omp_worker_js_eval_process` — spawned by omp, with a channel back to it that
only omp's own code reads (`eval/js/context-manager.ts`, `acquireSession`;
`eval/js/process-entry.ts`). Its parent's process id is omp's, and nothing of
omp's JavaScript realm is in it: a value an extension puts on `globalThis` is
not there. *contract: `the JavaScript kernel is a child process of omp…`* If
that process cannot be started omp falls back to a Bun Worker thread inside
its own process (same file); then the kernel's own process id is omp's. *read,
not run*

The Python kernel is a plain `python -u <runner.py>` subprocess of omp
(`eval/py/kernel.ts`), started in the session's working directory. *contract:
`is a child process of omp too…`* On Windows, a virtual environment's
`python.exe` is a launcher that starts the real interpreter as a child of its
own, so the kernel's parent is that launcher, not omp. *not run; known of
Python's venv launcher, not read in omp*

### What it is told about its session

Not omp's session id, not the tool call's id, not the branch. Only this:

- **JavaScript:** a global, `__omp_session__`, `{ cwd, sessionId }`, where
  `sessionId` is the kernel's own key: `js:session:<session file>:cwd:<cwd>`,
  or `js:cwd:<cwd>` for a session with no file (`eval/js/shared/runtime.ts`;
  `eval/session-id.ts`, `defaultEvalSessionId`; `eval/js/index.ts`). *contract:
  `a JavaScript cell is told its session as __omp_session__…`* The name has
  two underscores each side because it is omp's internal; it is the only
  thing in the realm that says which session a cell belongs to.
- **Python:** environment variables set for each cell, among them
  `PI_SESSION_FILE`, the session's file, absent for a session with none
  (`eval/executor-base.ts`, `MANAGED_KERNEL_ENV_KEYS`), and the process's
  working directory, which is the session's. *contract: `is a child process of
  omp too, started in the session's directory, and told the session's file as
  PI_SESSION_FILE…`*

The same two facts — the session's file, else its directory — are what omp
keys a kernel by ([What persists](#what-persists-and-when-it-is-lost)), so
they name the session exactly as well as the kernel does: sessions with no
file in one directory share a kernel and cannot be told apart from inside it.

On the extension's side the same session answers
`ctx.sessionManager.getSessionFile()` and `.getCwd()`, which is how a request
from a kernel is matched to a session (`extensions/re/host.ts`,
`sessionOfKernel`).

### What it may do, and its environment

Anything its language can: a kernel is not sandboxed. A cell can require
`node:http`, `node:net` and `node:child_process`, call `fetch`, spawn
programs; a Python cell has `http.client`, `socket`, `subprocess`. In
particular a cell can talk to a listener on `127.0.0.1` in omp's process, and
a request without the listener's token is the listener's to refuse.
*contract: `a JavaScript cell can ask a loopback listener in omp's process
with node:http…`, `a Python cell can ask a loopback listener in omp's process
with http.client…`* omp's own bridge for Python tool calls is the same design:
a loopback HTTP server with a bearer token (`eval/py/tool-bridge.ts`).

Two things about *how* to ask, both Bun's and Python's rather than omp's:
Bun's `fetch` sends even a loopback request to the proxy `HTTP_PROXY` names,
unless `NO_PROXY` exempts it, and gives up on a silent response after five
minutes; `node:http` does neither. Python's `urllib` honours the proxy
variables too; `http.client` does not. So the plugin's library uses
`node:http` and `http.client`. *seen with the pinned Bun; not pinned by a
test*

The **JavaScript** kernel gets omp's environment as it is when the kernel
starts (`subprocess/worker-client.ts`). The **Python** kernel gets a filtered
one: an allowlist (`PATH`, `HOME`, `USER`, `TMPDIR`, `TEMP`, `TMP`,
`XDG_RUNTIME_DIR`, …), anything beginning `LC_`, `XDG_` or `PI_`, and nothing
else (`eval/py/runtime.ts`, `filterEnv`). A variable an extension sets under
its own name does not reach a Python cell. *contract: `its environment is
filtered…`* That is why the plugin's listener is found through a file and not
through a variable. The kernels agree with omp on where such a file would be:
their temporary directory, their user id and `XDG_RUNTIME_DIR` are omp's.
*contract: `the kernel's temporary directory and user are omp's own…`, `its
temporary directory, user and runtime directory are omp's own…`*

### A cell that is stopped hangs up

Time a cell spends waiting on a socket counts toward its deadline like any
other time (only omp's own waits pause it: `eval/bridge-timeout.ts`). When the
deadline passes, or the user interrupts:

- the **JavaScript** kernel is killed, so every connection it had open is
  closed by the operating system, and a server in omp's process sees its
  request aborted. *contract: `time a cell spends waiting on a socket counts
  toward its deadline…`, `aborting a cell kills the kernel too, and hangs up
  the request it was waiting on`*
- the **Python** kernel is interrupted, not killed
  ([The deadline in Python](#the-deadline-in-python)): the blocking call the
  cell was in raises `KeyboardInterrupt`, and a connection closed on the way
  out (`finally`) is seen as aborted the same way. *contract: `a Python cell
  past its deadline is interrupted, not killed: the call it was blocked in is
  stopped by KeyboardInterrupt…`, `aborting a Python cell interrupts it the
  same way…`*

So a listener learns that nobody waits any more without being told by a
hook. That matters, because a handler of `tool_call` is given no abort signal
for the cell.

### What an extension sees of a cell

`tool_call` fires for `eval` before the cell runs, with the tool call's id and
`input` — `language`, `code`, `title`, `timeout`, `reset` — and a context whose
`sessionManager` is the session's; `tool_result` fires after, with the
content, `isError` and the same `input`, and a handler may return a
replacement `content` (`extensibility/shared-events.ts`, `ToolCallEventResult`,
`ToolResultEventResult`; `extensibility/extensions/wrapper.ts`). A cell that
threw is a result too, with `isError`. *contract: `tool_call and tool_result
fire for a cell…`* omp-re uses the first to know which `eval` call a request
from a kernel belongs to, for the audit log, and the second to add one line
under a cell that failed because the library was not loaded: the error text
of an undefined name is `<name> is not defined` in JavaScript and `NameError:
name '<name>' is not defined` in Python. *contract: same test; `a name that
is not defined is NameError in these words…`*

A `tool_call` handler may also return a replacement `input`, which would let
an extension put a line of its own in front of the model's code. omp-re does
not: the cell that runs, and that the transcript shows, is the one the model
wrote. *read; the experiment that showed it works is not in the suite*

`tool_execution_start` and `tool_execution_end` are the agent loop's events
and do not fire when the tool is executed directly, as the suites do. omp-re
listens for the second as well as `tool_result`, to know a cell is over.
*read; not seen in a model's turn*

### How a cell is approved

`eval` is one tool to omp's approval gate, tier `exec`
(`tools/eval.ts`). Under `tools.approvalMode: always-ask` with no UI a cell is
refused, naming `tools.approval.eval`; with `tools.approval.eval: allow`, or
under the default mode, it runs, and nothing it then does over a socket is
put to the gate. *contract: `eval itself is an exec-tier tool…`, `that is the
one gate…`* omp.sh says as much about shells: "bash rules do not cover a shell
spawned through eval". So a plugin reached from inside a cell is approved
with the cell, as a whole, and has to hold its own line inside it —
[`SECURITY.md`](../SECURITY.md#what-omp-approves).

## `%load <path>`

A cell whose whole code is `%load <path>` runs that file in the kernel
(`eval/input.ts`, `prepareEvalSource`). The host reads the file; the kernel
runs it under its filename, so its relative imports resolve from the script.

| Behaviour | Pinned by |
| --- | --- |
| The source is not echoed. The cell's output is what the script printed and the value of its last expression; the transcript keeps the command | *contract: `runs the file in the kernel without echoing its source…`* |
| What the script defines at top level persists like a cell's own definitions | *contract: `what the script defines at top level persists…`* |
| An edited file is not picked up until it is loaded again; loading again runs it again | *contract: `an edited file needs another %load…`* |
| It must be the whole cell (surrounding blank space aside), with exactly one path | *contract: `it must be the whole cell, with exactly one path`* |

Accepted paths:

| Form | Resolves to | Pinned by |
| --- | --- | --- |
| `lib.js`, `./lib.js` | relative to the **session's working directory** (`resolveReadPathAsync(file, session.cwd)`) | *contract: `a relative path is relative to the session's working directory…`* |
| `/abs/lib.js`, `file:///abs/lib.js` | that file | same |
| `"sp ace/lib.js"`, `'…'` | quoting is required for a path with spaces | same |
| `skill://<name>/<path>` | the file under that skill's directory ([below](#skillnamepath)) | *contract: `skill://<name>/<path> loads the file beside that skill's SKILL.md…`* |
| `local://<file>` | the session's scratch root, where `write("local://…")` puts things | *contract: `local:// works…`* |
| `artifact://<id>` | the artifact's file, if this session has it | source only (`requireLocal`) |

Refusals, in omp's words:

| Cell | Message | Pinned by |
| --- | --- | --- |
| `%load` then more code | `Use %load, %pip, %bun, and %environment as standalone cells; run subsequent code in another eval call.` | *contract: `it must be the whole cell…`* |
| `%load`, or an unquoted path with a space | `Usage: %load <script path>. Quote paths containing spaces.` | same |
| a file that is not there | `Cannot load eval script <path as written>: ENOENT: …` | *contract: `a missing file is refused…`* |
| `https://…`, or any scheme omp has no handler for | `Eval scripts must be local. Download and inspect remote scripts before executing them.` | *contract: `a remote script is refused`* |
| `skill://<unknown>/…` | `Unknown skill: <name>` and, on a second line, `Available: <names>` | *contract: `an unknown skill is refused…`* |
| `skill://<name>/<missing>` | `Cannot load skill://…: File not found: <resolved path>` | same |
| a URL with no file behind it (`xd://…`) | `Cannot load xd:// URL: no local file backs xd://…` | *contract: `a URL with no file behind it cannot be loaded`* |

`%pip`, `%bun add <pkg>` and `%environment managed|project` are the other
percent commands (`prepareEvalSource`; `prompts/tools/eval-helpers.md`). omp-re
uses none: a plugin's script cannot count on packages, and `recipes.js` imports
nothing.

## Internal URLs

omp routes `scheme://` paths through one router (`internal-urls/router.ts`);
the `read` tool, and `read()` in a cell, accept them. The three this plugin
touches:

### `skill://<name>/<path>`

`skill://<name>` is the skill's `SKILL.md`; `skill://<name>/<path>` is a file
under the directory that holds it (`internal-urls/skill-protocol.ts`,
`skillTargetPath`). This is the mechanism behind omp.sh's "scripts beside
SKILL.md"; the URL form itself is not on omp.sh.

- **The name** is matched exactly against the skills loaded into the session —
  the `name` in the skill's frontmatter, not its directory.
- **The path** cannot leave the skill's directory: `..` is folded when the URL
  is parsed, and a path that still escapes is refused (`Path traversal is not
  allowed`). For a skill installed as part of a plugin package, the target must
  also resolve inside the plugin root, symlinks included (`containRoot`).
  *contract: `a skill:// path cannot climb out of the skill's directory`*
- **`read()` of one** returns the file's text, less its final newline, under a
  first line `[Skill file: <absolute path>]` (`tools/read.ts`). Code that
  parses the result must drop that line. *contract: `read("skill://<name>/<path>")
  is the file's text under a first line…`*
- **A name collision.** When two loaded skills have the same name and
  different content, one keeps the bare name and the other is renamed
  `<namespace>/<name>` (`~2`, `~3` … if that is taken too), with a warning
  (`extensibility/skills.ts`, `resolveCollision`). Who keeps the name: a skill
  the user wrote over an installed package; a skill from
  `skills.customDirectories` over a provider's; otherwise whichever loaded
  first. The namespace is the plugin's name when the provider supplies one,
  else the directory that owns `skills/` (`skillNamespace`). The renamed skill
  is `skill://<namespace>/<name>/<path>`. *contract: `a skill whose name was
  taken is addressed by its namespace…`* (the URL form; the loader's choice of
  winner was read, not run). Two skills with the same name and identical
  content collapse into one.

  For this plugin: if another loaded skill is called `re-triage` and wins,
  `skill://re-triage/recipes.js` names a file in *that* skill's directory —
  `File not found`, or a different script.

When no loaded skill has the name, `read` (not `%load`) will also serve a
resource an MCP server advertises under exactly that URI, waiting up to 5 s for
MCP to start (`SkillProtocolHandler.resolve`).

### `artifact://<id>`

A session on disk keeps an artifacts directory beside its file; an artifact is
a file `<id>.<tool>.log` in it, `id` a counter starting at 0
(`session/artifacts.ts`, `ArtifactManager`). Artifacts are made by:

- omp, when a tool result passes 50 KB (`tools.artifactSpillThreshold`): it
  cuts the middle out and names the artifact that has it whole;
- every `eval` cell, which reserves one for its own output (so ids are not
  consecutive per tool);
- an extension, with `await ctx.sessionManager.saveArtifact(content, toolType)`,
  which returns the id (`session/session-manager.ts`). This is what
  `extensions/re/host.ts` does (`saveArtifact`) when the engine asks omp to
  keep a result that is past the engine's own cap.

Reading one back from a cell: `await read("artifact://<id>")` returns the file
raw and whole — no header, no line numbers, no size bound — and `{ offset,
limit }` select lines (`eval/js/shared/prelude.txt`, `read`;
`eval/js/shared/helpers.ts`, `resolveArtifactPath`). *contract:
`read("artifact://<id>") returns, raw and whole…`* The `read` *tool* on the same
URL (`tool.read({ path })`, or the model's own `read`) is a different path: it
pages, numbers lines unless `:raw` is appended, and refuses to inline an
artifact over 8 MiB (`internal-urls/artifact-protocol.ts`,
`MAX_INLINE_ARTIFACT_BYTES`).

**When artifacts are unavailable.** A session that is not on disk
(`SessionManager.inMemory()`; `omp --no-session`) has no artifacts directory.
`saveArtifact` still returns an id — it keeps the text in memory — and omp's
truncation note still says `Read artifact://<id>`, but nothing can read it
back: `getArtifactPath` is `null` and `read("artifact://<id>")` throws `No
session - artifacts unavailable`. *contract: `a session that is not on disk
still hands out artifact ids…`* An id is therefore not proof the text can be
had. That is one reason the plugin's library does not get a read's data
through an artifact: the engine answers what rizin printed beside the text.

### `xd://<name>`

With `tools.xdev` on (the default), a discoverable tool is not in the model's
tool list; it is *mounted*: `read xd://` lists the devices, `read xd://<name>`
is one tool's documentation and schema, `write xd://<name>` with a JSON object
calls it (`tools/xdev.ts`; `internal-urls/xd-protocol.ts`). `xd://<tool>/<topic>`
is a named doc page of a tool: `xd://eval/helpers` is where the model reads
about `%load`. *contract: `read("xd://") lists the mounted devices…`*

A device is a registered tool, and a topic is a registered tool's: there is no
entry an extension can add without registering one. So omp-re, which
registers none, is not under `xd://`; what a model would have read there it
reads from the skill, and from the engine through `re.help()`, `re.tools()`
and `re.doc(name)`.

## The Python kernel

A plain Python subprocess running omp's own runner (`eval/py/runner.py`: "no
third-party imports, no IPython"), spoken to over stdin and stdout, with a
loopback HTTP bridge for tool calls. Everything here was seen with CPython
3.13; the runner's source allows for older ones (it has a branch for "Python <
3.12") and uses `asyncio.to_thread`, so 3.9 is the floor it could run on. omp
states no minimum.

### Finding a Python

Before a Python cell, `eval` asks whether a kernel can be had
(`tools/eval.ts`, `resolveBackend`; `eval/py/kernel.ts`,
`checkPythonKernelAvailability`). The candidates, in order
(`eval/py/runtime.ts`, `enumeratePythonRuntimes`): the interpreter of an
active or project virtualenv (`VIRTUAL_ENV`, `CONDA_PREFIX`, else `.venv` or
`venv` under the working directory); omp's managed environment
(`~/.omp/python-env`); `python`, else `python3`, on `PATH`. The first that
runs `import sys` is used. `python.interpreter` names one outright and skips
the search. None working gives the model `Python backend is unavailable in this
session. Pass language: "js" or install the python kernel.`; `eval.py: false`
(or `PI_PY=0`) gives `Python backend is disabled …` and takes `py` out of the
schema. *source only* — except that the tests here ask omp the same question
before they run, with `forceProbe`, because under `bun test` (and with
`PI_PYTHON_SKIP_CHECK`) the check answers "available" without looking.

The kernel is started in the session's working directory, and that directory
has to exist: started in one that does not, the cell's answer was `ENOENT: no
such file or directory, posix_spawn '<the interpreter's path>'`, which names
the wrong file. *seen while writing the contract test; the test makes the
directory.* `python.kernelMode: "per-call"` gives up persistence
(`eval/settings.ts`); the default, `session`, keeps one kernel as JavaScript
does.

### What a Python cell starts with

omp's prelude (`eval/py/prelude.py`) is executed *in the cell namespace*, so
its imports are globals of every cell beside its helpers: `asyncio`,
`collections`, `contextvars`, `inspect`, `json`, `math`, `os`, **`re`**,
`time`, `types`, `typing`, `urllib`, `Path` and `unquote`, plus the prelude's
own underscore-prefixed internals (`_bridge_call`, `_ToolProxy`, …). A cell may
write `re.search(…)` or `json.loads(…)` with no import, and a script that bound
one of those names would take the module away from every later cell.
*contract: `the name re is taken in a Python cell…`* That is why the Python
recipes are `omp_re` and not `re`.

The helpers have the names the JavaScript ones have and, as the tool
description says, are synchronous and take keyword arguments
(`prompts/tools/eval.md`: "Python helpers: sync, kwargs"):
`read(path, offset=1, limit=None)`, `write(path, content)`, `display(value)`,
`env(key=None, value=None)`, `output(*ids, format=…, query=…, offset=…,
limit=…)`, `log`, `phase`, `wait`, `budget`, `agent`, `workpool`, `completion`,
`judge`, `judge_batch`. *contract: same test* (that they are there and
callable; the signatures were read).

`tool.<name>(…)` is the exception, an `async def` that has to be awaited;
omp-re does not use it.

### One event loop, and a blocking call in it

A cell is compiled with top-level `await` allowed and run inside the runner's
persistent event loop, on the main thread. A plain function that blocks —
on a socket, say — holds that loop for as long as it waits. omp's own helpers
do exactly that: `read()` is synchronous and answers a value, not a coroutine,
going to the read tool over omp's bridge while the loop waits (`prelude.py`,
`_read_tool_text` → `_bridge_call`). *contract: `a cell runs inside a running
event loop, and a plain blocking call there is how omp's own helpers work…`*
So a library whose functions are plain calls that block on a request is
within what the kernel already does, and is what "Python helpers: sync"
promises a model. This is how `recipes.py` is written.

### What a Python cell answers

`print()` output is the text. The value of the last expression is shown as
`repr(value)` (`runner.py`, `_mime_bundle`: `text/plain` is the repr unless the
value has a `_repr_*_` method), so a string comes out on one line, quoted, its
newlines as `\n` — where the JavaScript kernel prints a string as it is. A
`str` subclass with its own `__repr__` is shown by that. *contract: `a string
left as a cell's last expression is shown as its repr…`* An uncaught exception
is the output — the traceback, then `Command exited with code 1` — marked
`isError`.

**A line that begins with `%` or `!` is a magic or a shell escape wherever it
stands.** The runner rewrites such lines before parsing (`runner.py`,
`transform_cell`), strings excepted but brackets not, so a string format
continued onto a line starting `% (…)` becomes a `SyntaxError` naming the line
above. This applies to a `%load`ed file as much as to a cell. *contract: `a
line that begins with % is rewritten as a magic…`*

### `%load` in Python

The host half is [the same](#load-path) — `prepareEvalSource` resolves the
path, reads the file and refuses the same things in the same words; for Python
it intercepts `%load` only (`%pip` is the runner's own). The runner then
executes the source in the cell namespace under the file's name. Beyond what
the script itself does, that leaves three marks (`runner.py`,
`_prepare_file_source`, and Python's rules for module code):

- `__file__` is set, in the cell namespace, to the script's path;
- the script's directory is put on `sys.path`;
- a string literal as the script's first statement becomes the namespace's
  `__doc__`. *seen; not pinned* — `recipes.py` opens with comments for that
  reason.

*contract: `%load skill://<name>/<path> runs a Python file in the cell
namespace…`* The output is what the script printed and the repr of its last
expression; a script that wants to say what it defined should `print` it.

### `read("artifact://<id>")` in Python

Synchronous, like every Python helper. For a bare `artifact://<id>` the
prelude looks for `<id>.*` in the session's artifacts directory — the host
passes the directory in `PI_EVAL_LOCAL_ROOTS` — and returns the file's text
whole, with no header, no line numbers and no size bound; `offset` and `limit`
select lines. *contract: `read("artifact://<id>") is synchronous in Python…`*
The file is opened in text mode, so `\r\n` and a lone `\r` come back as
`\n` — a difference from JavaScript's raw read that does not touch a `*j`
command's output, where JSON escapes them. *seen; not pinned* Any other
`scheme://` goes to the `read` tool (`skill://…` comes back under its
`[Skill file: …]` line, as in JavaScript).

A session with no artifacts directory has no root to pass; the read falls to
the `read` tool and raises `RuntimeError: No session - artifacts unavailable`.
*contract: `in a session that is not on disk, read of an artifact id raises…`*

### The deadline in Python

Not the JavaScript kernel's. A Python cell past its deadline is *interrupted*
(SIGINT) and the kernel is meant to live: the output begins `[eval cell timed
out after Ns; kernel interrupted but remains running. Reset the kernel via {
reset: true } if state appears corrupted.]`. The interrupt surfaces as
`KeyboardInterrupt` in whatever the cell was doing; when that is a plain
function blocked on a request — any call of `omp_re` — the call ends, the
cell ends, and the namespace is intact: `omp_re` survives a timed-out call,
where `re` in the JavaScript kernel does not. An interrupt by the user does
the same. *contract: `a Python cell past its deadline is interrupted, not
killed…`, `aborting a Python cell interrupts it the same way…`*

## Eval preludes

A *prelude* is a capability omp installs into every kernel: a snippet of
JavaScript and Python that defines globals, a handler that stays in the host,
documentation served at `xd://eval/<name>`, and an approval tier of its own
(`eval/preludes.ts`, `EvalPreludeDefinition`). It is the mechanism a plugin
would want for shipping `re` without a `%load`.

It is not open to plugins. The session's preludes are assembled from four
built-ins and nothing else — `browser` (`browser.enabled`, default on),
`computer` (`computer.enabled`, off), `ratchet` (`ratchet.enabled`, off),
`archive` (`archive.enabled`, on) — in `sdk.ts` (`createAgentSession`, the
`getEvalPreludes` closure), and `ExtensionAPI`
(`extensibility/extensions/types.ts`) has `registerTool`, `registerCommand` and
the rest but no prelude registration. *contract: `are built in — browser,
computer, ratchet, archive — and an extension is given no way to register
one`* So a script the model loads is the only way for an extension to put code
in the kernel, and omp.sh's rule for skills applies: it does not run until the
playbook says to load it.

## Limits and timeouts

| Limit | Default | Setting | Source |
| --- | --- | --- | --- |
| Cell deadline | 30 s; a given value is clamped to 1–3600 s; `0` disables | the cell's `timeout`; `tools.maxTimeout` caps it (default `0`, no cap) | `tools/tool-timeouts.ts`, `TOOL_TIMEOUTS.eval`, `clampTimeout` |
| What the deadline counts | the kernel's own time, tool calls included; host waits pause it and restart a full window | — | `eval/idle-timeout.ts`, `IdleTimeout`; `eval/bridge-timeout.ts` |
| Kernel start | 15 s, or the cell's deadline if longer | — | `eval/js/context-manager.ts`, `WORKER_INIT_TIMEOUT_MS` |
| Idle kernel | none: a kernel is kept until reset, disposal or exit | — | `omp://tools/eval.md`, "no heartbeat or idle timer" |
| Tool result text | 50 KB | `tools.artifactSpillThreshold`, `tools.artifactHeadBytes`, `tools.artifactTailBytes`, `tools.artifactTailLines` | `tools/output-meta.ts`, `getSpillConfig` |
| Cell output | 50 KB; 768 bytes a line; 8000 bytes a displayed value | `tools.outputMaxColumns`, `tools.artifactHeadBytes` | see [What a cell answers](#what-a-cell-answers) |
| Long cells in the background | off | `eval.autoBackground.enabled`, `eval.autoBackground.thresholdMs` (60 s) | `eval/settings.ts` |

`IdleTimeout`, despite the name, is the per-cell watchdog; nothing reaps an
idle kernel. `timeout: 0` was read, not run.

## What omp-re relies on

Each row is a host behaviour this plugin would break without. "contract" is
`test/omp-eval-contract.test.ts`; the other files show the same behaviour
through the plugin itself: `test/bridge.test.ts` (the way from a cell to the
engine), `test/extension-sdk.test.ts` (the verbs in both kernels) and
`test/recipes-eval.test.ts` (the recipes).

| Behaviour | Depends on it | Pinned by |
| --- | --- | --- |
| An extension can register no prelude, and `tool.<name>()` reaches only registered tools | the whole design: a library the model loads, asking a listener | contract: `are built in — browser, computer, ratchet, archive…`, `reaches a tool an extension registered, and nothing else…` |
| A kernel is a child process of omp's | the library finds the listener by a file named for its parent's process id (`recipes.js`, `recipes.py`: `connect`) | contract: `the JavaScript kernel is a child process of omp…`, `is a child process of omp too…`; bridge: `its file is the owner's alone…` |
| The kernel's temporary directory, user id and `XDG_RUNTIME_DIR` are omp's | where that file is looked for (`bridgeDirectories` on both sides) | contract: `the kernel's temporary directory and user are omp's own…`, `its temporary directory, user and runtime directory are omp's own…` |
| The Python kernel's environment is filtered | the listener is not named in a variable | contract: `its environment is filtered…` |
| A cell can reach a loopback listener in omp's process | every verb | contract: `a JavaScript cell can ask a loopback listener…`, `a Python cell can ask a loopback listener…`; extension-sdk: `omp's eval reaches the engine through the library…` |
| `__omp_session__.sessionId` is `js:session:<file>:cwd:<cwd>` or `js:cwd:<cwd>` | `recipes.js` (`kernel`): which session a request is for | contract: `a JavaScript cell is told its session as __omp_session__…`; bridge: `two sessions in one omp process, each with its file…` |
| `PI_SESSION_FILE` is the session's file during a Python cell, and the kernel's directory is the session's | `recipes.py` (`kernel`) | contract: `is a child process of omp too, started in the session's directory…`; extension-sdk: `the same analysis from Python cells, in the same session…` |
| A kernel is keyed by the session's file, or by its directory when it has none | `host.ts` (`sessionOfKernel`): two sessions that share a kernel are refused | contract: `is keyed by the session's file and working directory…`; bridge: `sessions omp keeps no file for are told apart by their directory…` |
| A stopped cell's open request is hung up, in both kernels | the engine's work on a call is cancelled when nobody waits for it (`host.ts`, `answerKernel`) | contract: `time a cell spends waiting on a socket counts toward its deadline…`, `aborting a cell kills the kernel too…`, the two Python tests of the same; bridge: `a JavaScript cell that is interrupted, or runs past its timeout, cancels the engine's call…`, `a Python cell that is interrupted…` |
| `tool_call` for `eval` carries the call's id and a context that names the session | the audit log names a call `<eval call id>#<n>` (`host.ts`, `cellStarted`) | contract: `tool_call and tool_result fire for a cell…`; shim: `every call that ran is in the audit log, named by the eval call it came from…` |
| `tool_result` for `eval` fires for a failed cell too, and what a handler adds to the content reaches the result | the line that says how to load the library (`index.ts`) | contract: same test; extension-sdk: `a cell that uses the library in a kernel that has not loaded it is told the line that loads it…` |
| An undefined name is said as `<name> is not defined` / `NameError: name '<name>' is not defined` | what that handler looks for | contract: same test, `a name that is not defined is NameError in these words…` |
| `%load skill://re-triage/recipes.js` runs the script beside SKILL.md | SKILL.md; README; the library | contract: `skill://<name>/<path> loads the file…`; recipes-eval: `%load by the skill's own URL defines re…` |
| `%load` does not echo the source and shows the script's last expression | `recipes.js` (its last expression is the call that defines `re`, whose value is the "loaded" message) | contract: `runs the file in the kernel without echoing its source…` |
| What a script puts on `globalThis` persists across cells | `recipes.js` (`globalThis.re`) | contract: `top-level const, let, var…`, `what the script defines at top level persists…` |
| The name `re` is free in the realm | `recipes.js` | contract: `the name re is not taken by the host…`; recipes-eval: same test as above |
| `eval` is one `exec`-tier call to the approval gate, and nothing inside a cell is put to it | what SECURITY.md says omp approves | contract: `eval itself is an exec-tier tool…`, `that is the one gate…` |
| `ctx.sessionManager.saveArtifact(content, tool)` returns an id; `getArtifactPath(id)` finds the file | `host.ts` (`saveArtifact`, `readArtifact`: where the engine keeps a text the size cap cut, and how the line `report` reads it back) | contract: `read("artifact://<id>") returns, raw and whole…` |
| What a cell prints is cut at 50 KB | the engine's cap on a result's body, 48 KiB (`engine/util.lisp`, `+max-octets+`), which is meant to be the only cut of a printed read | contract: `past 50 KB the middle of the output is left out…`; recipes-eval: `the engine's own cut stays under omp's limit…` |

The Python library, `skills/re-triage/recipes.py`, stands on these besides,
all from [The Python kernel](#the-python-kernel):

| Behaviour | Depends on it | Pinned by |
| --- | --- | --- |
| `re` is already the regex module in a Python cell | `recipes.py` (the global is `omp_re`); SKILL.md | contract: `the name re is taken in a Python cell…`; recipes-eval: `%load by the skill's own URL defines omp_re…` |
| A plain function may block the cell's event loop, as omp's own `read()` does | every function of `omp_re` is a plain call | contract: `a cell runs inside a running event loop, and a plain blocking call there…` |
| `%load skill://re-triage/recipes.py` runs the file in the cell namespace; the output is what it printed | `recipes.py` (it prints the "loaded" message as it finishes loading); SKILL.md | contract: `%load skill://<name>/<path> runs a Python file…`; recipes-eval: same test as the first row |
| A value is shown by its `__repr__` | `recipes.py` (`Report`: a text left as a cell's value reads as written) | contract: `a string left as a cell's last expression is shown as its repr…`; recipes-eval: `what the library answers is text…` |
| A line beginning with `%` is a magic even inside brackets | `recipes.py` (no line starts with a format's `%`) | contract: `a line that begins with % is rewritten as a magic…` |
| A stopped Python cell is interrupted and the namespace kept | `omp_re` need not be loaded again after a timeout; SKILL.md says so | contract: `a Python cell past its deadline is interrupted, not killed…`; bridge: `a Python cell that is interrupted, or runs past its timeout, cancels the engine's call and keeps its kernel…` |

Two host behaviours the plugin is exposed to and can only tell the model
about, and one it keeps clear of. They are pinned so that they stay known:

- **A JavaScript cell that outlives its deadline takes `re` with it.** The
  default is 30 s and time in the engine counts; opening a binary budgets
  300 s for analysis and a rizin command 120 s. The skill says to give such a
  cell a `timeout`, and the line under the next cell's error says how to load
  the library again. contract: `a cell past its deadline is killed…`
- **An interrupted cell does too.** contract: `aborting a cell kills the kernel
  too…`
- **A printed read within 50 KB is the plugin's to keep under.** The engine
  caps a result's *body* at 48 KiB, so that the header line, the truncation
  note and the evidence tag it adds stay under omp's limit on what a cell
  shows. (With the cap at 50 KiB a cut result went just over, and omp cut its
  middle out a second time and named a second artifact.) Held by the group
  "a long read through omp's eval is cut once" in `test/recipes-eval.test.ts`.

## Open questions

- **Ruby and Julia.** omp.sh/docs/tools says they are opt-in languages. The
  schema accepts `py` and `js` only (`tools/eval.ts`, `evalSchema`; *contract*),
  there are settings for those two only (`eval/settings.ts`), and the one
  mention of `rb`/`jl` is a comment. Upstream 18.18.6 is the same.
- **"Persists across compaction."** True of the kernel, which compaction does
  not touch. The description does not say that a timeout or an interrupt ends
  it; the timeout message does, and the description's "Kernel-loss notice means
  reload setup" is the only instruction about it.
- **The tail notice.** A long cell's last line says `Showing lines a-b of N`,
  naming only the tail, while the head is kept as well and a marker line
  stands in the middle. Observed; the wording comes from the tail-truncation
  path (`tools/eval.ts`, `truncationFromSummary(…, { direction: "tail" })`).
- **Python's kernel.** The setting's label says "IPython kernel"; the tool
  description says "plain Python subprocess, not IPython". The description
  matches the code.
- **The JavaScript kernel as a thread.** When the kernel's process cannot be
  started omp runs it as a Bun Worker in its own process. The library looks
  for the listener's file under its own process id as well as its parent's
  for that case, and `__omp_session__` is set the same way; neither was run.
- **A subagent's kernel.** A task subagent is a session with a file of its
  own, so it has kernels of its own and its requests name its own session.
  That an extension's `tool_call` handler fires for a subagent's `eval` was
  read, not run: no suite starts a subagent.
- **A model's turn.** Everything here was shown by executing the `eval` tool
  directly. `tool_execution_end`, and what the agent loop does with content a
  `tool_result` handler added, were not seen.
- **An older Python.** The runner allows for Python before 3.12 and nothing
  states a floor. `recipes.py` uses nothing newer than 3.9, but was run on
  3.13 only.
- **Another session's artifact.** When a session has no artifacts directory,
  `read("artifact://<id>")` falls to the `read` tool, which searches the
  directories of every session registered in the process
  (`artifact-protocol.ts`, `resolveArtifactFile`; `registry-helpers.ts`). Ids
  are per-session counters, so in a process hosting several sessions it could
  return another session's artifact of the same number. SDK sessions are not
  registered, so this could not be shown either way.
- **Fork, branch, `/new`.** A different session file is a different kernel key
  (`defaultEvalSessionId`). What omp does to a kernel when a session is
  forked or its tree navigated was not examined.
- **A handler that revises the arguments.** The wrapper lets a `tool_call`
  handler return a replacement `input`, re-checked by the approval gate
  (`ExtensionToolWrapper.execute`). Read, not run here; omp-re's `tool_call`
  handler returns nothing.
- **`timeout: 0`**, images in a tool result, and the ACP permission gate
  `getToolForEvalBridge` applies (`#wrapToolForAcpPermission`) were read, not
  run.

## Newer than this

Upstream `main` was at 18.18.6 (commit `98eacbbc`, 2026-11-09) when this was
written. `eval/input.ts` — `%load` — is unchanged. Differences in the eval and
URL sources that bear on this page, from a diff of `src/eval`,
`src/tools/eval.ts`, `src/prompts/tools` and `src/internal-urls`:

- **In-memory artifacts become readable.** `artifact-protocol.ts` gains
  `callerInMemoryArtifact`: a session with no artifacts directory reads its
  own in-memory spill. `No session - artifacts unavailable` stops being the
  answer for an id the session issued, so the contract test of that name will
  change. Nothing of omp-re's depends on it any more.
- **`read("artifact://<id>")` for another session's artifact** locates the
  file with a bounded `read` and then reads it directly (`prelude.txt`).
- **A tool that is registered but not enabled** throws `Tool is registered but
  not available in this session: <name>` instead of `Unknown tool…`
  (`tool-bridge.ts`, `getTool`).
- **`task` and `wait` pause the cell's deadline** when called through the
  bridge (`DELEGATED_WORK_TOOLS`). Other tools still count.
- **A new global, `sh`** — `` await sh`cmd ${arg}` `` — and a reply scheme,
  `out://`, that a bridged `write` cannot reach.
- **`__omp_session__`, the kernel's process model and the Python
  environment filter are unchanged** (`eval/js/shared/runtime.ts`,
  `eval/js/context-manager.ts`, `eval/py/runtime.ts`): what the way to the
  engine stands on is the same there.
- **A `tool_call` handler's revised `input`** "becomes what the loop
  schedules, displays, persists" (`extensibility/shared-events.ts`), which is
  one more reason omp-re does not rewrite a cell.
- **The tool description names the session's tools** and states the deadline's
  clamp; a prelude may inline its documentation there.
- **Skills** can be re-discovered mid-session (`rediscoverSkills`,
  `findStaleSkillStandIn` in `skill-protocol.ts`).

On an upgrade: run `bun test test/omp-eval-contract.test.ts`, re-read the
sections whose tests fail against the new source, and change the version at the
top — the first test in the file holds this page to the installed version.
