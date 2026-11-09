# omp-re on nodecode

[nodecode](https://nodecode.ai) is an agent whose model has one tool, `eval`,
which evaluates Lisp in the running program; everything else is a **cell** — a
folder of Lisp under `~/.nodecode/cells/` that declares what it contributes.
This repository is also such a cell, `nodecode-re`. It gives a nodecode agent
the same reverse-engineering engine the omp plugin runs: one tool to read the
binary, stateful annotations, the evidence store, the audit log, gated
findings, and the report writer that refuses a claim with no evidence.

The cell is pure Common Lisp: omp-re's engine ported file by file from the
TypeScript under `extensions/re`, with the verbs, the `/re` command, the
manual and the config section over it. It needs rizin and nothing else — no
bun, no node. The two engines write the same records and enforce the same
read-only policy, and a test holds them to each other
([Two engines, one behaviour](#two-engines-one-behaviour)).

## Install

You need [rizin](install.md) and nodecode.

```sh
git clone https://github.com/drvova/omp-re ~/.nodecode/cells/nodecode-re
```

The folder must be named `nodecode-re`, after the system in
`nodecode-re.asd`. It loads at the next launch (or `(restart-cells
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
a look; it never states a conclusion. The tables behind them (which imports,
which constants) are data in `recipes/tables.json`, shared with the omp
plugin's twin of these functions, `skills/re-triage/recipes.js`, which omp's
`eval` loads with `%load skill://re-triage/recipes.js` (`await re.triage()`
and so on); a test compares the two outputs line for line.

## `/re`

The operator's command, in every shell nodecode has. Typed alone it answers
a dialog, as nodecode's commands do: a row for each thing it does — status,
functions, strings, imports, evidence, findings, verify, undo, tools on and
off — and rows that ask for a word first (open a binary, cite evidence,
write the report). The same lines work typed or from eval
(`/re status`, `(re:slash "status")`). `/re cite <id>` puts the citation in
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
| `state_dir` | `""` | Where session records, evidence, the audit log and reports go. Empty: `omp-re/` under the nodecode home (it follows a profile). |
| `debugger` | `false` | Offer `rizin_debug`, which **executes the sample**. Leave off outside a sandbox. |
| `idle_minutes` | `30` | Close the rizin process of a session unused this long. Nothing is lost: its next call restores it from the record. |

The engine's environment variables (`OMPRE_DECOMPILER`,
`OMPRE_ANALYSIS_TIMEOUT_MS`, `OMPRE_AUDIT_HMAC_KEY`, `OMPRE_OUTPUT_DIR`, …; see
the README) are read from the organism's environment, as the omp plugin reads
them. `rizin_path` and `debugger` take the place of `OMPRE_RIZIN_PATH` and
`OMPRE_ENABLE_DEBUGGER`, which still work. `"enabled": false` turns the
cell off.

## What is the same as under omp, and what is not

The same, because the Lisp engine is a port of the TypeScript one and writes
the same records:

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
- `rizin_command` runs exactly the commands the omp plugin's does, and refuses
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
- **No claim-support audit yet** (`/re report --audit`). Under omp it asks
  the model a side question; nodecode has the means (`nle:submit` to a fork
  with no tools), but the cell does not use it yet, so findings are stored as
  `unaudited` and the report runs with the evidence gate alone.
- **A cut result names a file**, not `artifact://N`: the whole output is kept
  beside the session's record and `(re:json …)` reads it for you.
- **The `re-analyst` subagent and the `re-triage` skill** are omp assets; the
  cell's `(help :re)` primer and `(re:cmd "")` manual carry the same workflow.

## How it is built

```
nodecode-re.asd            the system: this repository is the cell folder
nodecode/package.lisp      NODECODE-RE, nicknamed RE; the peripheral declaration
nodecode/json.lisp         JSON, written in a fixed order (records are hashed and signed)
nodecode/sha256.lisp       SHA-256, HMAC-SHA256, base64 — no digest library is assumed
nodecode/util.lisp         validators, quoting, truncation, the canonical output projection
nodecode/rizin.lisp        one rizin process on the NUL-framed pipe; finding rizin; its catalog
nodecode/policy-data.lisp  GENERATED from extensions/re/catalog.ts — the read-only policy's data
nodecode/policy.lisp       which commands rizin_command may run; rizin_help
nodecode/session.lisp      the session record, the process lifecycle, evidence, audit, one tool call
nodecode/tools-core.lisp   open_binary, rizin_help, rizin_command, /re, status, the output directory
nodecode/extras.lisp       map_file, analyze, signatures, export_project, rizin_cli, triage, rizin_emulate
nodecode/annotate.lisp     the fifteen annotation tools, undo, replay
nodecode/findings.lisp     record_finding, adopt_finding, retract_finding
nodecode/verify.lisp       /re verify
nodecode/report.lisp       /re report and its verification manifest
nodecode/carry.lisp        /re carry
nodecode/debug.lisp        rizin_debug (only when `debugger` is set)
nodecode/recipe-data.lisp  GENERATED from recipes/tables.json — the recipes' tables
nodecode/recipes.lisp      re:triage, re:scan-imports, re:inspect-function, re:find-comparisons, re:find-crypto
nodecode/verbs.lisp        the verbs and the argument mapping
nodecode/cell.lisp         the primer, /re, the nle:define-cell declaration
```

Each file names the TypeScript it ports in its header. The shape is the
engine's own: a **session** is the open binary, the rizin process analyzing it
and the session's **record**; the record is the truth and the process a cache
of it. Every call, whoever makes it — a verb, a recipe, `/re` — goes through
one function that checks the arguments against the tool's
declared parameters, refuses while `/re off`, writes the audit line, runs the
body, and for a read records the evidence.

rizin is driven the way the TypeScript engine drives it: `rizin -q0`, one NUL
after every response, a unique `echo` marker after each command so the stream
cannot lose its place. There is no reader thread — the caller reads the pipe
itself under the session's lock, draining stderr as it goes — and a command
left half-read by an interrupted eval is read up to its marker by the next, so
the process and its analysis survive. Only a timeout kills it, and then the
next call starts another and replays the record.

The cell uses about a dozen and a half names from nodecode (`nle:define-cell`,
`nlk:define-peripheral`, `nlk:spawn-program`, `nlk:run-bounded`, `nle:turn`,
`nle:register-tool`, …) and `cl-ppcre`, which nodecode already carries.

## Two engines, one behaviour

A port drifts unless something holds it. Three things do:

- **The policy is generated, not transcribed.** `bun run gen:nodecode` lifts
  the regular expressions and command lists out of `extensions/re/catalog.ts`
  into `nodecode/policy-data.lisp`; `cl-ppcre` reads the same Perl syntax, so
  the patterns cross unchanged. `test/nodecode-parity.test.ts` fails when the
  generated file is stale.
- **Both engines are asked the same questions.** The same test hands a file of
  cases to the Lisp engine and compares: which of the installed rizin's ~2000
  commands `rizin_command` runs, every refusal's exact words, the breakpoint
  on-hit policy, `rizin_help`'s output, quoting and the validators, the
  canonical/shift hashes, SHA-256 and HMAC, JSON as written to records, and
  truncation.
- **The records are the same shape**, so evidence taken under one engine
  verifies under the other.
- **The recipes' tables are generated too**, from `recipes/tables.json` into
  both hosts' code (`bun run gen:nodecode`), and a test compares what the
  Lisp functions and the omp script print for the same binary.

## Tests, and what they prove

- `bun run test:nodecode` (`sbcl --non-interactive --load
  test/nodecode/run.lisp`) loads the real `nodecode-re` system and runs its
  suites against a real rizin: the primitives against published vectors, the
  policy, every verb and tool, `/re`, the audit log and evidence store, a
  rizin killed and replaced, a session forgotten and restored from its record,
  an interrupted command, a timeout, the idle reaper, start and stop. Needs
  SBCL and cl-ppcre (the distribution's packages are enough).
- `bun test test/nodecode-parity.test.ts` is the comparison above.

The Lisp suites run on `test/nodecode/kernel-stub.lisp`, a stand-in for the
names the cell uses from nodecode's kernel, written to the contract in
nodecode's `docs/CELLS.md` and source. They prove the cell's own code. They do
not prove nodecode's side of the seam — that takes loading the folder in a
nodecode build, which CI here does not do.
