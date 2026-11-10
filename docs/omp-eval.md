# omp's `eval`, as omp-re uses it

omp-re registers no code tool of its own: the model composes the RE tools in
omp's `eval`, and the recipes are a script that `eval` loads. That puts a
number of host behaviours under this plugin — `await tool.<name>(args)`,
`%load`, `read("artifact://…")`, `skill://` URLs, a kernel that keeps its
state — and [omp.sh](https://omp.sh) describes almost none of them. This page
writes them down, with where each comes from, so the plugin's reliance on them
can be checked.

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
tool's fields, limits and helpers. It does not say what `tool.<name>()` hands
back for an extension's tool, how such a call is approved and recorded, what
`skill://` means to `%load`, or what happens to an artifact a session cannot
keep — which is most of what omp-re depends on. Where it and this page overlap,
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

Most of this page is written from the JavaScript kernel, which is where the
plugin's tools are usually composed. The Python kernel reaches the same tools
through the same bridge (`eval/py/tool-bridge.ts` forwards to
`callSessionTool`), so [`tool.<name>()`](#toolnameargs),
[`%load`](#load-path) and the [internal URLs](#internal-urls) hold for it;
where it differs — and it does, in ways `recipes.py` has to know — is in
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
| `tool` | `await tool.<name>(args)` — a session tool; see below. Also `tool(fn, { name?, description?, parameters? })`, `tool.defined()`, `tool.undefine(name)` to define kernel-hosted tools for subagents (`eval.tools.enabled`) | **yes** — `recipes.js`, SKILL.md |
| `read` | `await read(path, { offset?, limit? })` → string. A plain path is relative to the cwd; `local://` and this session's `artifact://<id>` are read from disk; any other scheme is handed to the `read` tool | **yes** — `recipes.js` reads `artifact://` |
| `print` | `print(value, …)` — `console.log` | **yes** — how a recipe's report is shown |
| `display` | `display(value)` — JSON, image or text, shown under `display[n]:` | in README's advice only |
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
up, validates the arguments and executes it.

### Which tools

Every **enabled** tool, by its registered name: the top-level ones and the ones
mounted as `xd://` devices alike (`session/session-tools.ts`,
`getToolForEvalBridge` over `getEnabledToolNames`). That is what lets a
discoverable tool, which the model never sees a schema for, be called from a
cell. *contract: `reaches a discoverable tool that is mounted as an xd://
device…`*

Not reachable: a name that is no tool; a tool that is registered but not
enabled (`defaultInactive`, or turned off) — both throw `Unknown tool from js
runtime: <name>`; and `checkpoint` and `rewind`, which the bridge refuses by
name. *contract: `a name that is not a tool…`, `checkpoint and rewind are
refused…`*

### Arguments

Validated against the tool's schema before anything else happens; a failure
throws `Validation failed for tool "<name>": …` and no event fires. Omitted
arguments are `{}`. The harness's intent key `i` is dropped unless the schema
declares it. Validation is the lenient kind the model's own calls get: an
unknown key was seen to pass through to the tool, and `{ command: 5 }` to reach
a tool whose `command` is a string (`callSessionTool`;
`validateAgentToolArguments` in `@oh-my-pi/pi-agent-core`, not read further).
*contract: `arguments are checked against the tool's schema…`*

### What comes back

`bridgeValueFromToolResult` (`eval/js/tool-bridge.ts`) turns the tool's result
into the cell's value:

| The tool's result | The cell gets | Pinned by |
| --- | --- | --- |
| text only, `details` undefined, no error | the text, as a bare **string** | *contract: `a result with no details comes back as a bare string`* |
| has `details` | `{ text, details }` — `details` exactly as the tool gave it | *contract: `a result with details comes back as { text, details }…`* |
| has images | `{ text, details, images }` | source only |
| `isError: true`, or `details.isError: true` | `{ text, details, hasError: true }` — it does **not** throw | *contract: `a result the tool marked isError does not throw…`* |
| the tool throws | the `await` rejects with a plain `Error` whose message is the tool's | *contract: `a tool that throws rejects in the cell…`* |

`text` is every text block of the result joined with nothing between them. A
block appended by a `tool_result` handler is therefore the end of `text` — the
handler supplies its own newline. That is how omp-re's `[evidence …]` tag comes
to be the last line.

One case moves a throw into the fourth row: when a `tool_result` handler
replaces the content of a call that threw, the wrapper returns the replacement
marked as an error instead of rethrowing
(`extensibility/extensions/wrapper.ts`, `ExtensionToolWrapper.execute`), and
the cell gets `{ text, hasError: true }`. *contract: `a thrown tool whose
result a tool_result handler replaced…`* Code that must not miss a failure
checks `hasError` as well as catching.

Calls started together run concurrently, and a call the cell did not await is
still finished before the cell's result is returned (`context-manager.ts`,
`settlePending`). *contract: `calls started together run concurrently…`*

### How a call is approved and recorded

The tool the bridge executes is the session's registry entry, which is the
extension wrapper around the tool (`sdk.ts` wraps every tool in
`ExtensionToolWrapper` when extensions are loaded). So a call from a cell takes
the same path as one the model makes directly, in this order
(`ExtensionToolWrapper.execute`):

1. A user policy of `deny` (`tools.approval.<name>`) throws `Tool "<name>" is
   blocked by user policy.` before anything is announced.
2. `tool_call` fires, with `toolCallId` `js-<name>-<uuid>` and the validated
   arguments. A handler returning `{ block: true, reason }` makes the call
   throw `reason`; the tool does not run.
3. The approval gate: the tool's own tier (`approval`, default `"exec"`)
   against `tools.approvalMode` (`always-ask` approves `read`, `write` approves
   up to `write`, `yolo` — the default — approves all), with
   `tools.approval.<name>` overriding (`tools/approval.ts`, `resolveApproval`).
   A call that needs a prompt gets one; with no UI it throws `Tool "<name>"
   requires approval but no interactive UI available.`
4. The tool runs.
5. omp's bound on the result's size is applied ([below](#a-tool-result-that-is-too-long)).
6. `tool_result` fires, with the content, the details and `isError`; a handler
   may replace the content.

*contract: `tool_call and tool_result fire for a call made from a cell…`, `a
tool_call handler that blocks…`, `a thrown tool reaches tool_result handlers as
isError…`, `each tool.<name>() call is approved on its own tier and policy…`,
`under the default mode (yolo) every tier runs unprompted`*

Two consequences. The cell is itself an `exec`-tier call (`tools.approval.eval`,
as <https://omp.sh/docs/approvals> says), approved once; each tool it calls is
then approved again on its own terms, so approving a cell does not approve what
it does. *contract: `eval itself is an exec-tier tool…`* And nothing is written
to the transcript per call: the cell's card shows a status line for each
(`summarizeToolResult`), but the session record has one tool call, the cell.
Anything that must outlive the cell has to be recorded by a handler, as
`evidence.ts` and `audit.ts` do.

### Deadline and abort

Time spent inside `tool.<name>()` counts toward the cell's deadline. Only
waits the host owns pause it: agent and completion handles, `judge`, package
installs, prelude calls (`eval/bridge-timeout.ts`, `withBridgeTimeoutPause`;
the comment in `tools/eval.ts`, `#runCells`, says "ordinary tool calls all
count against the budget"). When the deadline passes, or the cell is aborted,
the signal each in-flight tool was given is aborted — with a `TimeoutError` or
an `AbortError` — and then the kernel is killed. *contract: `time spent inside
tool.<name>() counts toward the deadline…`, `aborting a cell kills the kernel
too…`*

### A tool result that is too long

omp bounds every tool result, extension tools included (`tools/output-meta.ts`,
`spillLargeResultToArtifact`, applied by `wrapToolWithMetaNotice`):

- At most `tools.artifactSpillThreshold` — 50 KB, i.e. 51200 bytes of text —
  passes through untouched. *contract: `a result whose text is at most
  tools.artifactSpillThreshold…`*
- One byte more and the whole text is saved as a session artifact, the middle
  is cut out (20 KB of head and 20 KB of tail are kept:
  `tools.artifactHeadBytes`, `tools.artifactTailBytes`,
  `tools.artifactTailLines`), a last line is appended — `[Showing lines 1-a and
  b-N of N; M middle lines (… ) elided. Read artifact://<id> for full output]`
  — and `details.meta.truncation` (with `artifactId`, `totalBytes`,
  `direction: "middle"`) is added beside the tool's own details. *contract: `one
  byte more and omp cuts the middle out…`*

A tool that truncates for itself and stays at or under the threshold is left
alone: its text, and whatever it put in `details`, reach the cell as written.
This happens before `tool_result`, so a handler sees the cut text and what it
appends lands after omp's note. *contract: same test*

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

- omp, when a tool result passes 50 KB ([above](#a-tool-result-that-is-too-long));
- every `eval` cell, which reserves one for its own output (so ids are not
  consecutive per tool);
- an extension, with `await ctx.sessionManager.saveArtifact(content, toolType)`,
  which returns the id (`session/session-manager.ts`). This is what
  `extensions/re/format.ts` does past its own cap.

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
had; `recipes.js` treats a failed read as fatal for that reason.

### `xd://<name>`

With `tools.xdev` on (the default), a discoverable tool is not in the model's
tool list; it is *mounted*: `read xd://` lists the devices, `read xd://<name>`
is one tool's documentation and schema, `write xd://<name>` with a JSON object
calls it (`tools/xdev.ts`; `internal-urls/xd-protocol.ts`). `xd://<tool>/<topic>`
is a named doc page of a tool: `xd://eval/helpers` is where the model reads
about `%load`. *contract: `read("xd://") lists the mounted devices…`*

Which tools mount: those whose `loadMode` is `"discoverable"`, which is what an
extension's tool gets unless it says `"essential"` (`tools/essential-tools.ts`,
`defaultLoadModeForToolName`; `isMountableUnderXdev` — `read`, `write`, `todo`,
`ask`, `grep`, `web_search` and `yield` never mount).

For `tool.<name>()` none of this matters: mounted or top-level, an enabled tool
is reached the same way and returns the same thing. With `tools.xdev` off the
tools are listed top-level, `xd://` is "not mounted in this session", and cells
are unchanged — the presentation changed, as omp.sh says, not what is
permitted. *contract: `off, the same tools are listed top-level…`*

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

**`tool.<name>(…)` is the exception: it answers a coroutine.**
`_ToolCallable.__call__` is `async def`; nothing reaches the bridge until it is
awaited, and a call left un-awaited is shown as `<coroutine object …>` with a
`RuntimeWarning`. Arguments are one dict, keywords, or both (keywords win);
anything else positional is a `TypeError`. Awaited, it gives what
[JavaScript gets](#what-comes-back), as Python values:

| The tool's result | The cell gets | Pinned by |
| --- | --- | --- |
| text only, no details | the text, a `str` | *contract: `tool.<name>(args) answers a coroutine; awaited…`* |
| has `details` | `{"text": …, "details": …}`, a `dict` | same |
| marked `isError` | the dict with `"hasError": True` — no exception | *contract: `a tool that throws raises RuntimeError…`* |
| the tool throws, the arguments fail validation, or the name is no tool | `RuntimeError` whose message is the tool's (`Unknown tool from js runtime: <name>` for the last — the wording is the bridge's, whatever the kernel) | same |

Integers arrive as Python `int`s, but they crossed the bridge as JSON written
by JavaScript: a number in a tool's `details` past 2^53 was already rounded on
the other side. A tool's *text* is a string and arrives as written, which is
why `recipes.py` parses rizin's JSON out of the text. *seen; not pinned*

### One event loop, and what a plain function can do in it

A cell is compiled with top-level `await` allowed and run inside the runner's
persistent event loop, on the main thread. `asyncio.run(…)` there raises
`asyncio.run() cannot be called from a running event loop`, so a synchronous
function cannot wait for a tool call the ordinary way. *contract: `a cell runs
inside a running event loop…`*

It can on another thread: `asyncio.run` on a thread of its own, entered
through a copy of the calling context (`contextvars.copy_context().run(…)`),
while the caller joins the thread. The copy is not optional. The bridge
attributes a call to the running cell by `__omp_current_run_id__`, which reads
a context variable (`runner.py`, `_CURRENT_RID`); a fresh thread has an empty
context and the bridge answers `Missing session/run/name`. With the copy the
call is the same call as any other — `tool_call` and `tool_result` fire, the
approval gate applies. *contract: `a tool call can be settled from a plain
function on another thread…`* omp's own `read()` blocks the loop the same way
when it goes to the read tool (`prelude.py`, `_read_tool_text` →
`_bridge_call`), so a helper that holds the main thread for a tool call is
within what the kernel already does. This is how `recipes.py` keeps to "Python
helpers: sync".

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
reset: true } if state appears corrupted.]`. Tool time counts toward the
deadline as it does in JavaScript, and the signal of a tool call in flight is
aborted with a `TimeoutError`. When the interrupt lands in a plain function
waiting on a thread — a recipe — it surfaces as `KeyboardInterrupt`, the cell
ends, and the namespace is intact: `omp_re` survives a timed-out recipe.
*contract: `a Python cell past its deadline is interrupted, not killed…`*

When it lands in a cell that is itself `await`ing a tool call, what was seen is
worse than the message says: the cell reports the timeout as above, and the
*next* cell answers `[Kernel died during execution; completion is uncertain…]`
`Python kernel exited with code 130`, after which a fresh kernel is started
with nothing in it. *seen once, in a scratch run; not pinned, and not examined
in the source.* So for Python too, give a slow tool call a `timeout` and a cell
of its own.

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
`test/omp-eval-contract.test.ts`; the other two files show the same behaviour
through the real RE tools (`test/extension-sdk.test.ts`) and the real recipes
(`test/recipes-eval.test.ts`).

| Behaviour | Depends on it | Pinned by |
| --- | --- | --- |
| `tool.<name>()` reaches tools mounted as `xd://` devices | every RE tool (`render.ts`, `RE_LOAD_MODE`); `recipes.js` and `recipes.py` (`observe`); SKILL.md | contract: `reaches a discoverable tool…`; extension-sdk: `omp's eval reaches an RE tool as tool.<name>()…` |
| A tool with details returns `{ text, details }`, details intact | `recipes.js` (`observe` reads `details.truncated`, `details.artifactId`); SKILL.md ("read `.text`") | contract: `a result with details comes back as { text, details }…` |
| `text` is the blocks joined, so a `tool_result` handler's block is its last line | `evidence.ts` (the `[evidence …]` tag); `recipes.js` (`EVIDENCE_TAG`) | contract: same test; extension-sdk: `open, annotate, and resume through eval…` |
| A tool that throws rejects with its own message | `recipes.js`; SKILL.md ("A failing tool throws"); every `omp-re: …` refusal | contract: `a tool that throws rejects in the cell…`; extension-sdk: `…its error is catchable in the cell` |
| A result marked as an error comes back with `hasError` instead | `recipes.js` (`observe` throws on it) | contract: `a result the tool marked isError does not throw…`, `a thrown tool whose result a tool_result handler replaced…` |
| `tool_call` and `tool_result` fire for calls from a cell | `audit.ts` (the audit log); `evidence.ts` (the evidence record); `index.ts` (`/re off` blocks in `tool_call`) | contract: `tool_call and tool_result fire…`, `a tool_call handler that blocks…`; extension-sdk: `/re off refuses RE tool calls from eval…` |
| Each call is approved on its own tier and `tools.approval.<name>` | every tool's `approval`; `audit.ts` (`tool_approval_resolved`) | contract: `each tool.<name>() call is approved on its own tier and policy…` |
| `%load skill://re-triage/recipes.js` runs the script beside SKILL.md | SKILL.md; README; `recipes.js` | contract: `skill://<name>/<path> loads the file…`; recipes-eval: `%load by the skill's own URL defines re…` |
| `%load` does not echo the source and shows the script's last expression | `recipes.js` (its last line is the "recipes loaded" message) | contract: `runs the file in the kernel without echoing its source…` |
| What a script puts on `globalThis` persists across cells | `recipes.js` (`globalThis.re`) | contract: `top-level const, let, var…`, `what the script defines at top level persists…` |
| The name `re` is free in the realm | `recipes.js` | contract: `the name re is not taken by the host…`; recipes-eval: same test as above |
| `ctx.sessionManager.saveArtifact(content, tool)` returns an id; `getArtifactPath(id)` finds the file | `format.ts` (`spill`); `report.ts` | contract: `read("artifact://<id>") returns, raw and whole…` |
| `read("artifact://<id>")` in a cell returns that text raw and whole | `recipes.js` (`wholeOutput`) | contract: same test; recipes-eval: `a read cut at the size cap is read back whole…` |
| Without a session on disk the read fails, with an error rather than other text | `recipes.js` (`lost`: it stops instead of parsing cut JSON) | contract: `a session that is not on disk still hands out artifact ids…`; recipes-eval: `when the whole of a cut read cannot be had…` |
| A tool result of at most 50 KB reaches the cell uncut | `format.ts` (its cap is meant to be the only one) | contract: `a result whose text is at most tools.artifactSpillThreshold…`, `one byte more…` |
| `read xd://<name>` documents a mounted tool; `tools.xdev` off changes nothing for cells | SKILL.md; README | contract: `read("xd://") lists the mounted devices…`, `off, the same tools are listed top-level…` |

The Python script, `skills/re-triage/recipes.py`, stands on the same bridge
and on these besides, all from [The Python kernel](#the-python-kernel):

| Behaviour | Depends on it | Pinned by |
| --- | --- | --- |
| `re` is already the regex module in a Python cell | `recipes.py` (the global is `omp_re`); SKILL.md | contract: `the name re is taken in a Python cell…`; recipes-eval: `%load by the skill's own URL defines omp_re…` |
| `tool.<name>()` answers a coroutine that gives a `str` or a `dict` of `text` and `details` | `recipes.py` (`observe`) | contract: `tool.<name>(args) answers a coroutine; awaited…` |
| A tool that throws raises `RuntimeError` with its message; an `isError` result comes back with `hasError` | `recipes.py` (`observe` raises on it); every `omp-re: …` refusal reaching a Python cell | contract: `a tool that throws raises RuntimeError…`; recipes-eval: `with no binary open every recipe fails…` (Python) |
| A coroutine can be run to its end on another thread under a copy of the cell's context, and only under one | `recipes.py` (`settled`: what lets a recipe be a plain function) | contract: `a tool call can be settled from a plain function on another thread…` |
| `%load skill://re-triage/recipes.py` runs the file in the cell namespace; the output is what it printed | `recipes.py` (its last line prints the "recipes loaded" message); SKILL.md | contract: `%load skill://<name>/<path> runs a Python file…`; recipes-eval: same test as the first row |
| `read("artifact://<id>")` is synchronous and returns the text whole; without a session on disk it raises | `recipes.py` (`whole_output`, `lost`) | contract: `read("artifact://<id>") is synchronous in Python…`, `in a session that is not on disk…`; recipes-eval: `a read cut at the size cap is read back whole … by Python's read()`, `when the whole of a cut read cannot be had, the Python recipe stops…` |
| A value is shown by its `__repr__` | `recipes.py` (`Report`: a report left as a cell's value reads as its text) | contract: `a string left as a cell's last expression is shown as its repr…`; recipes-eval: `a report is text…` |
| A line beginning with `%` is a magic even inside brackets | `recipes.py` (no line starts with a format's `%`) | contract: `a line that begins with % is rewritten as a magic…` |
| A timed-out Python cell is interrupted and the namespace kept | nothing depends on it; it is why `omp_re` outlives a recipe that ran out of time | contract: `a Python cell past its deadline is interrupted, not killed…` |

Three host behaviours the plugin is exposed to and does nothing about. They are
pinned so that they stay known:

- **A JavaScript cell that outlives its deadline takes `re` with it.** (A
  Python one is interrupted instead; see [The deadline in
  Python](#the-deadline-in-python).) The default is 30 s and tool time counts; `open_binary` budgets 300 s for analysis and
  `rizin_command` 120 s a command. contract: `a cell past its deadline is
  killed…`, `time spent inside tool.<name>() counts toward the deadline…`
- **An interrupted cell does too.** contract: `aborting a cell kills the kernel
  too…`
- **A result within 50 KB of text is the plugin's to keep under.**
  `format.ts` caps the *body* at 50 KiB and then adds a header line and a
  truncation note, which puts a capped multi-line result just over omp's
  threshold; omp then cuts 10 KB from its middle and appends a second note
  naming a second artifact. Seen with `pd 3000 @ main` on `/bin/ls`; not pinned
  here, since it is this plugin's arithmetic and not the host's.

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
- **`tool.<name>(args)` in Python: awaited or not.** The tool description's
  helper list puts `await` before `tool.<name>(args)` for JavaScript only
  (`prompts/tools/eval.md`: `{{#if js}}await {{/if}}tool.<name>(args)`), under
  the heading "Python helpers: sync, kwargs" — which reads as "no await in
  Python". The code is `async def __call__`, and an un-awaited call does
  nothing (*contract*). `omp://tools/eval.md` was not checked on this point.
  SKILL.md tells the model to await it.
- **A Python cell that times out while awaiting a tool call.** The message
  says the kernel "remains running"; the next cell found it dead (exit 130).
  Seen once; whether it is the rule was not established.
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
  (`ExtensionToolWrapper.execute`). Read, not run; omp-re's handlers return
  nothing.
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
  answer for an id the session issued, so the contract test of that name, and
  `when the whole of a cut read cannot be had…` in recipes-eval, will change.
- **`read("artifact://<id>")` for another session's artifact** locates the
  file with a bounded `read` and then reads it directly (`prelude.txt`).
- **A tool that is registered but not enabled** throws `Tool is registered but
  not available in this session: <name>` instead of `Unknown tool…`
  (`tool-bridge.ts`, `getTool`).
- **`task` and `wait` pause the cell's deadline** when called through the
  bridge (`DELEGATED_WORK_TOOLS`). Other tools still count.
- **A new global, `sh`** — `` await sh`cmd ${arg}` `` — and a reply scheme,
  `out://`, that a bridged `write` cannot reach.
- **The tool description names the session's tools** and states the deadline's
  clamp; a prelude may inline its documentation there.
- **Skills** can be re-discovered mid-session (`rediscoverSkills`,
  `findStaleSkillStandIn` in `skill-protocol.ts`).

On an upgrade: run `bun test test/omp-eval-contract.test.ts`, re-read the
sections whose tests fail against the new source, and change the version at the
top — the first test in the file holds this page to the installed version.
