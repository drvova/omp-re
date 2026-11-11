# omp-re on nodecode

[nodecode](https://nodecode.ai) is an agent whose model has one tool, `eval`,
which evaluates Lisp in the running program; everything else is a **cell** — a
folder of Lisp under `~/.nodecode/cells/` that declares what it contributes.
This repository is also such a cell, `nodecode-re`. It gives a nodecode agent
the same reverse-engineering engine the omp plugin runs: one tool to read the
binary, stateful annotations, the evidence store, the audit log, gated
findings, and the report writer that refuses a claim with no evidence.

There is one engine (`engine/`, ASDF system `omp-re`), and it is the one the
omp plugin runs too. The cell (`nodecode/`, system `nodecode-re`) is the
nodecode host over it: the verbs, the `/re` command, the manual and the config
section. Here the engine is loaded into the organism's own Lisp image — no
bun, no node, no second process.

## Install

You need nodecode and [rizin](install.md#rizin). The engine's system also
depends on the cl-ppcre library by name. The cell's own guide says nothing but
rizin has to be installed, on the understanding that nodecode carries
cl-ppcre; this repository cannot check that. If the cell fails to load for
want of it, put a copy where ASDF looks by default
(`~/common-lisp/cl-ppcre/`).

```sh
git clone https://github.com/drvova/omp-re ~/.nodecode/cells/nodecode-re
```

The folder must be named `nodecode-re`, after the system in
`nodecode-re.asd`. `omp-re.asd`, the engine's system, is beside it in the same
folder. It loads at the next launch (or `(restart-cells
"nodecode-re")`). To work from a checkout elsewhere, link it instead:
`ln -s /path/to/omp-re ~/.nodecode/cells/nodecode-re`.

Then, in a session:

```lisp
(re:status)            ; rizin found? binary open? evidence so far?
(re:open "/bin/ls")    ; open and analyze
(re:cmd "aflj")        ; read
```

## The surface: verbs in `eval`

omp-re's design under omp is "one tool to read the binary, composed in the
host's code tool". nodecode's design is "one tool, `eval`", whose helpers are
functions inside it. They are the same idea, so the cell registers **no
tools** — it adds verbs in the `RE` package that an eval form calls, loops over and builds helpers around. Every
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
parameter out; a list is an array (`#()` for an empty one). Where a parameter
is an object it is written as a list of keys and values, and an array of
objects as a list of those: `:attach '(:pid 1234)`, `:commands '((:command
"pdf" :addr "main"))`. JSON text or a `"pdf @ main"` string in their place is
refused. `(re:doc …)` shows each tool's keywords, so the mapping never has to
be guessed.

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

### Recipes: reads composed once

Every analysis opens with the same dozen reads. The recipes are those reads
and a plain reading of them — ordinary functions over `(re:cmd …)`, not tools:

| Function | What it answers |
| --- | --- |
| `(re:triage &key max-strings max-functions)` | What the binary is, which protections the build has (canary, NX, PIE, RELRO, fortify), its sections with entropy and what stands out about them, what its imports say it can reach, the strings worth a first look, its largest functions, its entry points. |
| `(re:scan-imports &key callers max-callers)` | The imports a reviewer stops at — unbounded copies, shell and exec calls, format sinks, race-prone file calls, weak randomness — each with why and who calls it. |
| `(re:inspect-function "main" &key max-items)` | One function from every side: size, complexity, signature, variables, callers, callees, the strings it refers to. |
| `(re:find-comparisons "main" &key max-items)` | What a function decides on: each compare with the branch that follows and where it goes, calls that compare or validate, the strings on the way. Static; nothing is run. |
| `(re:find-crypto &key references)` | rizin's search for keys and certificates, and the published constants of common algorithms (AES, SHA-1/256/512, MD5, CRC-32, ChaCha/Salsa20, Blowfish, TEA, DES, Base64), with what refers to each hit. |

Each read a recipe makes is a `rizin_command` call in its own right — gated,
audited, recorded as evidence — and every section of what it answers names
the evidence id it rests on, so its lines can be cited in `record_finding`
and re-run by `/re verify`. A recipe says what was observed and what is worth
a look; it never states a conclusion.

What each recipe reads, its options, sections, wording and tables are data in
`recipes/tables.json`. `bun run gen:recipes` generates that data into all
three places the recipes exist: `nodecode/recipe-data.lisp` here, and the
marked blocks of the omp plugin's twins of these functions —
`skills/re-triage/recipes.js` for the JavaScript kernel of omp's `eval` and
`skills/re-triage/recipes.py` for its Python kernel. A test runs all three on
the same binary and compares their reports whole.

## `/re`

The operator's command, in every shell nodecode has. Typed alone it answers
a dialog, as nodecode's commands do: a row for each thing it does — status,
functions, strings, imports, evidence, findings, verify, undo, tools on and
off — and rows that ask for a word first (open a binary, cite evidence,
write the report). The same lines work typed or from eval
(`/re status`, `(re:slash "status")`); a line from eval is the model's, so
`/re off` refuses it as it refuses a tool call, while the operator's typed
lines are never gated. `help`, `status`, `on` and `off` answer at once even
while another call holds the session. `/re cite <id>` puts the citation in
the input box where the shell has one, and answers it as text elsewhere. The
lists are text: the overlay panels are omp's.

Something that lasts — annotations that could not be replayed, an audit log
that could not be written — stands as the cell's notice in `/cells` and at
the tail of the model's prompt until it is replaced or the cell stops.

## Configuration

A section of `~/.nodecode/config.jsonc`; every member is optional (see
`nodecode/config.example.jsonc`).

| Key | Default | Effect |
| --- | --- | --- |
| `allowed_dirs` | `[]` | Directories binaries and other input files may be opened from, links resolved. Empty: any file the organism can read. `OMPRE_ALLOWED_DIRS` (comma-separated) is the same. |
| `rizin_path` | `""` | The rizin to run when it is not the one on `PATH`. |
| `state_dir` | `"omp-re/"` | Where session records, evidence, the audit log and reports go. A relative folder is under the nodecode home (it follows a profile). |
| `debugger` | `false` | Offer `rizin_debug`, which **executes the sample**. Leave off outside a sandbox. |
| `idle_minutes` | `30` | Close the rizin process of a session unused this long. Nothing is lost: its next call restores it from the record. |
| `audit` | `true` | Ask the model, in a side question, whether a finding's (and a report claim's) evidence supports it. Each question is a model turn and costs tokens; `false` records findings and writes reports `unaudited`. |
| `audit_seconds` | `120` | How long a support audit waits for its answer before the claim goes `unaudited`. |

The engine's environment variables (`OMPRE_DECOMPILER`,
`OMPRE_ANALYSIS_TIMEOUT_MS`, `OMPRE_AUDIT_HMAC_KEY`, `OMPRE_OUTPUT_DIR`, …; see
the README) are read from the organism's environment. `"enabled": false` turns
the cell off.

Where a setting has both a member here and an environment variable
(`rizin_path` and `OMPRE_RIZIN_PATH`, `allowed_dirs` and `OMPRE_ALLOWED_DIRS`,
`debugger` and `OMPRE_ENABLE_DEBUGGER`), one rule decides: the section's value
when it says something other than the default, else the variable when it is
set, else the default. So a `rizin_path` in the section wins over the
variable, and `"debugger": false` — the default — does not switch off a
debugger that `OMPRE_ENABLE_DEBUGGER` switched on.

The settings are declared once, in `engine/host.lisp`; the section's fields
and `nodecode/config.example.jsonc` are written from that declaration.

## What is the same as under omp, and what is not

The same, because it is the same engine:

- every call is written to the audit log, signed when `OMPRE_AUDIT_HMAC_KEY`
  is set;
- every observing call is recorded in the content-addressed evidence store and
  tagged `[evidence xxxxxxxx]`;
- `record_finding` is gated on evidence that exists, and `/re report` refuses
  ungrounded claims; `/re verify` re-runs the evidence against the binary's
  hash;
- **the record follows the session's branch.** nodecode's session is a tree
  of turns, as omp's is. Each entry is stamped with the turn it was written
  in, and a call reads only the entries on the current branch: after a `/tree`
  rewind, what the abandoned branch renamed is rolled back in rizin (the
  process is replaced and only this branch's annotations replayed) and what
  it observed no longer grounds a finding; `/redo` brings it back; a `/fork`
  starts with its parent's binary and the evidence of the turns before the
  fork point, and writes to a record of its own;
- annotations are recorded and **replayed** when rizin restarts. A session's
  record (open binary, annotations, evidence, findings) is an append-only file
  under `state_dir`, so it survives rizin dying, a nodecode restart, and the
  idle reaper;
- `rizin_command` runs exactly the commands it runs under omp, and refuses
  the rest in the same words.

Different, because the host is:

- **No approval tiers.** Under omp each tool call passes omp's approval mode.
  nodecode has no per-tool approval — its model already runs arbitrary code
  through `eval` — so the cell adds none. The one dangerous capability,
  executing the sample under a debugger, is off unless the operator sets
  `debugger`. Run untrusted samples in a sandbox either way
  ([SECURITY.md](../SECURITY.md)).
- **No panels, renderers or status band** — those are omp's terminal UI. The
  `/re` lists are text.
- **The claim-support audit is a side question to a session of its own.**
  `record_finding`, `adopt_finding` and `(re:slash "report …")` put the claim
  and its quoted evidence to the model with `nle:submit … :tools '()`, in a
  detached child of the asking session named `re: support audit` (source
  `re-audit`): none of its history, its model, no tool it may call. That is
  one model turn per finding and one per report, so it costs tokens; `audit`
  turns it off and `audit_seconds` bounds the wait. The sessions are kept —
  nodecode has no hidden session — and go with their parent, or with a prune
  by source. `unaudited` means nobody judged the claim, never that it failed:
  `audit` is off, there is no store, the turn failed, was cancelled, ran past
  `audit_seconds` or answered nothing readable — the reason is recorded, and
  `--audit=strict` withholds on a verdict only. `/re report` typed as a
  command does not wait on a model turn, so its report is `unaudited` and
  says so; ask for it from eval to have it audited.
- **A cut result names a file**, not `artifact://N`: the whole output is kept
  beside the session's record and `(re:json …)` reads it for you.
- **The `re-analyst` subagent and the `re-triage` skill** are omp assets; the
  cell's `(help :re)` primer and `(re:cmd "")` manual carry the same workflow.

## How it is built

The repository holds three ASDF systems. `omp-re.asd` is the engine
(`engine/`), which knows nothing of nodecode and loads in a plain SBCL.
`nodecode-re.asd` is this cell (`nodecode/`), depending on `nodecode` and
`omp-re`. `omp-re-stdio.asd` is the omp host and is not loaded here.
[`ARCHITECTURE.md`](ARCHITECTURE.md) describes the engine and the port a host
answers.

The cell is three files of host and the recipes:

- `nodecode-host.lisp` makes the cell's own package, `NODECODE-RE` (nickname
  `RE`), which uses the engine's package and so only what that exports
  (`engine/package.lisp`). It has its own `RE-ERROR`, which a verb signals with
  the engine's words when the engine answers a failure. The file also answers
  where a session's record is kept: each entry is stamped with the turn it was
  written in, and a call reads the entries on the session's branch.
- `verbs.lisp` is the verbs and the argument mapping, over the engine's
  surface (`engine/engine.lisp`).
- `cell.lisp` is the primer, the manual, `/re` and its dialog, the side
  question a support audit asks, and the `nle:define-cell` declaration.
- `recipes.lisp` and the generated `recipe-data.lisp` are the recipes, which
  are verbs.

Those are the only files in which a name of nodecode's (`nlk:`, `nle:`)
appears. The cell closes the rizin process of a session unused for
`idle_minutes`; the omp host does not.

## Tests, and what they prove

`bun run test:engine` (`sbcl --non-interactive --load test/nodecode/run.lisp`)
loads the engine and this cell and runs the suites against a real rizin; see
[`testing.md`](testing.md). They run on `test/nodecode/kernel-stub.lisp`, a
stand-in for the names the cell uses from nodecode's kernel. They prove the
cell's own code. They do not prove nodecode's side of the seam — that takes
loading the folder in a nodecode build, which CI here does not do.
