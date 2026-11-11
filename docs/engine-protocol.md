# The engine protocol

omp-re has one engine, written in Common Lisp (`engine/`, ASDF system `omp-re`). Under nodecode it runs inside the organism. omp is a TypeScript program, so there the engine runs beside it as a child process and the two talk over the child's standard input and output. This page is that conversation, written down. The Lisp side is `stdio/server.lisp`; omp's side is `extensions/re/engine.ts`.

## Starting

```
sbcl --noinform --no-sysinit --no-userinit --disable-debugger --load stdio/serve.lisp
```

One engine process serves one omp process: every session in it, task subagents included, is a session id on the same pipe. It is started when a session first needs it.

Standard output carries the protocol and nothing else. Whatever the engine prints (compiler notes on a first load, warnings, a backtrace) goes to standard error, which omp keeps as a log.

The first line the engine writes is one of

| Line | Meaning |
|---|---|
| `{"ready": 1}` | loaded; the number is the protocol version |
| `{"fatal": "…"}` | it could not load; the text says what to install. The process exits with status 3 |

The first start after an install or an upgrade compiles the engine (a few seconds); later starts load the compiled files ASDF keeps in the user's cache (well under a second).

## Messages

Each message is one JSON object on one line, UTF-8, ended by a line feed. A carriage return before the line feed is ignored. Either side may send any of three shapes:

| Shape | Members |
|---|---|
| request | `id`, `method`, `params` |
| answer | `id`, and `result` or `error: {message}` |
| notification | `method`, `params` (no `id`, no answer) |

Each side numbers its own requests; an answer carries the id of the request it answers. A line that is not a JSON object is skipped.

Requests are served concurrently. The engine runs each of omp's requests on its own thread and may ask omp something in the middle of one, so neither side may wait for an answer before reading on. Calls into one session take turns (rizin answers one command at a time); calls into different sessions do not wait for each other.

Addresses travel as strings (`"0x4010"`): a 64-bit address does not survive a JSON number in JavaScript.

Most of omp's requests are about a session and carry

```
"session": {"id": "<omp's session id>", "cwd": "<the session's directory>", "hasUI": true}
```

`cwd` is what a relative path in an argument is read against. `hasUI` says whether an operator is watching (false under `omp -p`).

## What omp asks the engine

`hello`, `environment`, `cancel` and `shutdown` take effect in the order they arrive. Everything else may be answered in any order.

| Method | Params | Result |
|---|---|---|
| `hello` | `protocol`, `variables`, `stateDir`, `voice?` | `{protocol, version}` |
| `environment` | `variables`, `stateDir` | `{}` |
| `describe` | | `{tools, commands}` |
| `call` | `session`, `name`, `arguments`, `callId` | `{text, failed, raw?, evidenceId?, details?, state}` |
| `command` | `session`, `line` | `{text, failed, level, draft?, userMessage?, state}` |
| `view` | `session`, `kind`, `arg?` | a view |
| `facts` | `session` | a state |
| `preserved` | `session` | `{lines}` |
| `approval` | `session`, `callId`, `tool`, `approved`, `reason?` | `{}` |
| `event` | `session`, `kind`, `previous?`, `binary?` | `{state?}` |
| `cancel` (notification) | `id` | |
| `shutdown` (notification) | | |

**hello / environment.** The engine process is started once, so it cannot see omp's environment change. `variables` is omp's environment as the engine reads it: every `OMPRE_*` variable and `PATH`. `stateDir` is omp's agent directory; the engine keeps its blobs and audit log under `<stateDir>/re/`, as earlier versions did. omp sends `environment` again whenever either changed, before the request that follows. `voice` may replace any of the engine's host-voiced phrases by key (`engine/host.lisp`, `+VOICE+`); omp sends none, the server speaks omp already.

**describe.** `tools` is what `engine-tools` answers: for each tool offered now, `name`, `label`, `description`, `parameters` (JSON Schema, handed to omp's `registerTool` as it is), `approval` (`read`, `write` or `exec`), `approvalReason?`, `render?` and `evidence`. Which tools are offered depends on the environment (`rizin_debug` needs `OMPRE_ENABLE_DEBUGGER`; the triage tools need their programs on `PATH`), so omp asks once for each session it starts.

`approvalReason` is the sentence an approval prompt shows for one call, as data, because omp computes it in a callback that cannot wait for the engine. It is a list of cases tried in order; the first whose `when` holds is used.

```
[{"when": [{"arg": "source", "equals": "file"}, {"arg": "path", "type": "string"}],
  "parts": ["Apply the FLIRT signature file ",
            {"pieces": [{"arg": "path", "missing": "?"}], "quote": true, "clip": 80},
            " — this renames matched functions."]},
 {"parts": ["Re-apply rizin's built-in signature database — this renames matched functions."]}]
```

A `when` condition names an argument by path (`attach.pid`) and holds when it equals `equals`, or is of `type` (`string` or `number`). A part is literal text or a slot. A slot runs its `pieces` together: each is the argument at `arg` (a string or number as it is, an array of strings joined by spaces), with `prefix` before it when it is there and `missing` in its place when it is not. The text is then cut to `clip` characters (the last three become `...`) and, with `quote`, written as a JSON string.

`render` is how a transcript shows a result: `title`, the argument that is the call's `subject`, and whether the `body` is `text`, `json` or `none`.

`commands` is what `engine-commands` answers: for each `/re` subcommand `name`, `usage?`, `description`, and `view: true` when it is also a list omp may open as a panel.

**call.** Run one tool. `callId` is omp's own id for the call and is written to the audit log. `failed` is true for a refusal or an error, with the reason as `text`. `details` is the result's own: `ea?`, `truncated?`, `artifactId?`, `commands?`, `reproHash?`, `canonicalExcerpt?`, `shiftHash?`, `evidenceId?`.

**command.** Run one `/re` line as the operator typed it, without the `/re`. `level` is how loudly to say `text`: `info`, `warning` or `error`. `draft: {text, notice}` asks for `text` to be put in the operator's input box and `notice` said in place of `text`, where there is an input box. `userMessage` asks for that text to be sent to the model as the operator's next message.

**state.** Every `call`, `command` and `event` answer carries what omp draws between calls, so drawing never costs a round trip:

```
"state": {"facts": {"name", "path?", "size?", "format?", "arch?", "os?", "entry?",
                    "prot": [], "fnCount", "findings", "evidence"} | null,
          "evidence": [["<evidence id>", "<tool> @ <address>"], …]}
```

`facts` is the status band. `evidence` is the newest 200 evidence records, newest first, for completing an id after `/re cite`. `facts` asks for the same on its own.

**view.** What a screen shows. `kind` is `functions`, `strings`, `imports`, `evidence` or `findings`, or one a row or a code view named, sent back with its `arg` unchanged. The answer is one of

| `type` | Members |
|---|---|
| `panel` | `title`, `hint`, `rows`: each `{value, label, description?, enter}` |
| `code` | `title`, `disasm` (lines), `decompile?: {label, note, tone, code, language?}`, `noDecompile`, `ask`, `xrefs: {kind, arg}` |
| `notice` | `text`, `level` |

A row's `enter` is what choosing it does: `{draft: text}` puts the text in the input box and closes the list; `{view: {kind, arg}}` asks for that view and shows it over the list, or, when the answer is a notice, says it and closes the list. In a code view `ask` is the draft a hand-off to the model starts from, `xrefs` the view of the references to the function, `noDecompile` what to say when `decompile` is absent. A failure is a notice at level `error`. Views record no evidence.

**preserved.** The lines to fold into the summary when omp compacts the session's conversation; empty when nothing was reverse engineered in it.

**approval.** What omp's approval gate decided of a call. The engine writes it to the audit log beside the call's own line; a denied call never reaches `call`, so this line is all the log has of it.

**event.** The session's life, as omp reports it.

| `kind` | Engine does |
|---|---|
| `start` | brings the session in line with its branch; opens `binary` (omp's `--binary`) unless the branch already has it open, else analyzes again the binary the branch has open |
| `switch`, `tree` | the same, without `binary` |
| `branch` | first carries the session `previous` over to this id, its rizin with it |
| `before-switch`, `shutdown` | ends the session's rizin and debugger; the record stays |

For the first four the analysis runs after the answer, holding the session, so a call that arrives meanwhile waits for it. When it ends the engine sends `state`, and `tell` if there is something to say.

**cancel.** omp gave up on its request `id`. The call leaves at its next wait, answering `failed` with `omp-re: … aborted`. A rizin command under way is left to finish and its output is skipped by the next command, so the process and its analysis survive; an analysis that was cancelled kills its half-analyzed process.

**shutdown,** or the end of standard input: the engine ends every session's processes and exits.

## What the engine asks omp

Every one names the `session` it is for.

| Method | Params | Result |
|---|---|---|
| `entries` | `after`, `count` | `{append: […]}` or `{all: […]}` |
| `append` | `type`, `data` | `{id}` |
| `judge` | `prompt`, `seconds` | `{text}` or `{reason}` |
| `saveArtifact` | `content`, `label` | `{id?}` |
| `readArtifact` | `id` | `{text?}` |
| `keepSession` | `name` | `{}` |
| `notify` (notification) | `text`, `level` | |
| `tell` (notification) | `text`, `level` | |
| `progress` (notification) | `request`, `text` | |
| `transcript` (notification) | `type`, `text`, `details` | |
| `state` (notification) | `state` | |

**entries / append.** The session's record is omp's own session file: the custom entries whose type begins `re.`, on the current branch, root first, each `{id, customType, data}`. The engine keeps a copy and asks once per request for what it has not seen: it holds `count` entries and the last has id `after`. If the branch still begins with those, omp answers the entries after them (`append`); otherwise the branch moved and it answers the whole list (`all`). `append` writes one entry and answers its id.

**judge.** Put `prompt` to a model as a side question with no tools and answer its reply. `reason` says why it could not be had; an empty object means there is nobody to ask.

**saveArtifact / readArtifact.** A result too large to send is kept whole by omp, which answers the artifact's id; the result then names it `artifact://<id>`.

**keepSession.** A `/re` line recorded something that must outlive the process though no model turn follows: write the session now, and where nobody is watching and it has no name, call it `name`.

**notify** tells the operator something outside any answer. **tell** is said the way a `/re` answer is said (under `omp -p`: standard output, or standard error and a failing exit status for an error). **progress** says a long analysis is under way (`text`) or over (`null`); `request` is omp's request it belongs to, or null for one the engine started itself. **transcript** shows a line in the conversation that is never sent to the model (`re.binary`: `[re: opened <path>]`).
