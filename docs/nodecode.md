# omp-re on nodecode

[nodecode](https://nodecode.ai) is an agent whose model has one tool, `eval`,
which evaluates Lisp in the running program; everything else is a **cell** — a
folder of Lisp under `~/.nodecode/cells/` that declares what it contributes.
This repository is also such a cell, `nodecode-re`. It gives a nodecode agent
the same reverse-engineering engine the omp plugin runs: one tool to read the
binary, stateful annotations, the evidence store, the audit log, gated
findings, and the report writer that refuses a claim with no evidence.

It is the same engine, not a port. The cell is native Lisp — verbs, a `/re`
command, a manual topic, a config section — and it drives `extensions/re`
through a small stdio bridge, so a fix to the engine lands on both hosts.

## Install

You need [rizin](install.md), [bun](https://bun.sh), and nodecode.

```sh
git clone https://github.com/drvova/omp-re ~/.nodecode/cells/nodecode-re
cd ~/.nodecode/cells/nodecode-re && bun install
```

The folder must be named `nodecode-re`, after the system in
`nodecode-re.asd`. It loads at the next launch (or `(restart-cells
"nodecode-re")`). To work from a checkout elsewhere, link it instead:
`ln -s /path/to/omp-re ~/.nodecode/cells/nodecode-re`.

`bun install` fetches the engine's dependencies (omp's own packages, which it
is written against). Without it the first call says so and names the command.

Then, in a session:

```lisp
(re:status)            ; rizin found? binary open? evidence so far?
(re:open "/bin/ls")    ; open and analyze
(re:cmd "aflj")        ; read
```

## The surface: verbs in `eval`

omp-re's design under omp is "one tool to read the binary, composed in the
host's code tool". nodecode's design is "one tool, `eval`". They are the same
idea, so the cell adds **no tools by default** — it adds verbs in the `RE`
package that an eval form calls, loops over and builds helpers around. Every
verb answers a string, except `re:json`, which answers data.

| Verb | What it does |
| --- | --- |
| `(re:open "path" &key arch bits base map format)` | Open a binary and run full analysis. A relative path reads against the session's directory. The keys force how a raw/headerless file loads. |
| `(re:cmd "command" &optional addr)` | Run **one read-only rizin command** (`rizin_command`), optionally at an address or symbol. `(re:cmd "")` answers the manual of command families. |
| `(re:json "command" &optional addr)` | The same, for a `*j` command, answering the **decoded data** (arrays as vectors, objects as hash tables) and the evidence id as a second value. Reads the whole output even when it is past the size cap. |
| `(re:call "tool" :key value ...)` | Any other engine tool: the annotate tools, `record_finding`, `retract_finding`, `rizin_help`, `rizin_cli`, `rizin_emulate`, `analyze`, `apply_signatures`, `map_file`, `export_project`, … |
| `(re:tools)` | The engine's tools, one line each. |
| `(re:doc "tool")` | One tool's description and its keyword arguments. |
| `(re:slash "line")` | A `/re` line: `functions`, `strings`, `imports`, `evidence [id]`, `cite <id>`, `findings [id]`, `undo`, `verify [--strict]`, `report [path]`, `carry <manifest>`. |
| `(re:status)` | rizin, the open binary, evidence and findings on this session. |

Arguments map mechanically onto the engine's JSON: `:expect-sha256` is
`expect_sha256`; `t` is true and `:false` is false; a `nil` value leaves the
parameter out; a list is an array (`#()` for an empty one). `(re:doc …)` shows
each tool's keywords, so the mapping never has to be guessed.

```lisp
;; The ten largest functions, decompiled.
(let ((functions (sort (coerce (re:json "aflj") 'list) #'>
                       :key (lambda (f) (or (gethash "size" f) 0)))))
  (loop for f in (subseq functions 0 (min 10 (length functions)))
        collect (re:cmd "pdg" (gethash "name" f))))

;; A conclusion cites evidence ids from results actually seen, or is refused.
(re:call "record_finding"
         :claim "main parses argv with getopt_long."
         :evidence '("1a2b3c4d")
         :confidence "confirmed")
(re:slash "report analysis.md")
```

A result past the engine's size cap is cut, and says which file holds all of
it (under `state_dir`); `re:json` reads that file itself. A helper defined in
eval is kept by the organism like any other definition, so
the analysis vocabulary you build stays. A failed call is an `RE-ERROR`
carrying the engine's own words, which eval reports as the form's error.

The model learns all of this from the cell's manual: one summary line rides
every request and `(help :re)` answers the full primer.

### Top-level tools, if you want them

Set `"surface": "tools"` and every engine tool is also registered as a tool of
its own, named `re_<name>` (`re_rizin_command`, `re_record_finding`, …), with
the engine's own description and JSON schema. The verbs stay. Use this for a
model that calls tools more reliably than it writes Lisp; the default keeps
thirty schemas out of every request.

## `/re`

The operator's command, in every shell nodecode has: `/re open <path>`,
`/re status`, `/re functions`, `/re findings`, `/re verify`,
`/re report [path]`, `/re undo`, `/re off`, `/re on`, `/re help`. It is the
engine's own `/re`, answered as text — the overlay panels are omp's and are
listed here as plain lists.

## Configuration

A section of `~/.nodecode/config.jsonc`; every member is optional (see
`nodecode/config.example.jsonc`).

| Key | Default | Effect |
| --- | --- | --- |
| `command` | `["bun"]` | The argv prefix that runs the engine. |
| `timeout_seconds` | `600` | One call's ceiling. A call past it is cancelled in the engine and says so. |
| `surface` | `"eval"` | `"eval"`: verbs only. `"tools"`: also one `re_<name>` tool per engine tool. |
| `rizin_path` | `""` | The rizin to run when it is not the one on `PATH`. |
| `state_dir` | `""` | Where session records, evidence, the audit log and reports go. Empty: `omp-re/` under the nodecode home (it follows a profile). |
| `debugger` | `false` | Offer `rizin_debug`, which **executes the sample**. Leave off outside a sandbox. |

The engine's own environment variables (`OMPRE_DECOMPILER`,
`OMPRE_ANALYSIS_TIMEOUT_MS`, `OMPRE_AUDIT_HMAC_KEY`, …; see the README) are
read from the organism's environment as before. `"enabled": false` turns the
cell off.

## What is the same as under omp, and what is not

The same, because it is the same code:

- every call is written to the audit log, signed when `OMPRE_AUDIT_HMAC_KEY`
  is set;
- every observing call is recorded in the content-addressed evidence store and
  tagged `[evidence xxxxxxxx]`;
- `record_finding` is gated on evidence that exists, and `/re report` refuses
  ungrounded claims; `/re verify` re-runs the evidence against the binary's
  hash;
- annotations are recorded and **replayed** when rizin restarts. A session's
  record (open binary, annotations, evidence, findings) is an append-only file
  under `state_dir`, so it survives the engine exiting, a nodecode restart, and
  the idle reaper (a session unused for 30 minutes has its rizin closed; its
  next call restores it).

Different, because the host is:

- **No approval tiers.** Under omp each tool call passes omp's approval mode.
  nodecode has no per-tool approval — its model already runs arbitrary code
  through `eval` — so the cell adds none. The one dangerous capability,
  executing the sample under a debugger, is off unless the operator sets
  `debugger`. Run untrusted samples in a sandbox either way
  ([SECURITY.md](../SECURITY.md)).
- **No branch following.** omp's `/tree` rolls annotations back with the
  branch. A nodecode session is one line of history here; `/re undo` and
  `retract_finding` are the ways back.
- **No panels, renderers or status band** — those are omp's terminal UI. The
  `/re` lists are text.
- **No claim-support audit side turn** (`/re report --audit`): it uses omp's
  ephemeral model turn, which this host does not provide, so the report runs
  with the evidence gate alone.
- **The `re-analyst` subagent and the `re-triage` skill** are omp assets; the
  cell's `(help :re)` primer carries the same workflow.

## How it is built

```
nodecode-re.asd            the system: this repository is the cell folder
nodecode/package.lisp      NODECODE-RE, nicknamed RE; the peripheral declaration
nodecode/bridge.lisp       the engine process and one request to it
nodecode/verbs.lisp        the verbs, the argument mapping, the top-level surface
nodecode/cell.lisp         the primer, /re, the nle:define-cell declaration
nodecode/bridge.ts         stdio bridge: one JSON object per line, each way
nodecode/host.ts           a headless host for extensions/re (no UI, file-backed session)
```

`host.ts` is a second implementation of the part of omp's `ExtensionAPI` the
engine uses: a session branch of custom entries, the `tool_call` → execute →
`tool_result` pipeline with its blocking and rewriting semantics, an artifact
store, argv exec. The engine cannot tell it from omp, which is why evidence
and audit behave identically.

`bridge.lisp` starts `bun nodecode/bridge.ts` at the first request and keeps
it. There is no reader thread: callers take turns reading replies in short
slices and file each under its request id, so two sessions' calls overlap in
the engine. A call that outlasts its deadline, or whose eval is interrupted,
is cancelled in the engine. If the engine dies, the next call starts another
and the session is restored from its record. The engine's stderr is appended
to `bridge.log` in the state directory.

## Tests, and what they prove

- `bun test test/nodecode-bridge.test.ts` — the headless host in-process and
  the bridge as a child process over its real protocol; with rizin present,
  that a call is audited and recorded as evidence and that a new process
  restores the session.
- `bun run test:nodecode` (`sbcl --non-interactive --load
  test/nodecode/smoke.lisp`) — loads the real `nodecode-re` system and drives
  the real bridge and rizin through the cell's Lisp: argument mapping, every
  verb, `/re`, deadlines, overlapping sessions, the top-level surface, an
  engine killed and replaced, stop.

The Lisp suite runs on `test/nodecode/kernel-stub.lisp`, a stand-in for the
two dozen names the cell uses from nodecode's kernel, written to the contract
in nodecode's `docs/CELLS.md` and source. It proves the cell's own code. It
does not prove nodecode's side of the seam — that takes loading the folder in
a nodecode build, which CI here does not do.
