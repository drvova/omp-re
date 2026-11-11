# Security

## Reporting a vulnerability

Open a private security advisory on this repository's GitHub Security tab,
or email the maintainer listed in `package.json`. Do not open a public issue
for an unpatched vulnerability. Include a minimal reproduction and the
`omp`/`rizin`/SBCL/`omp-re` versions involved; expect an initial response
within a few business days.

## Analysis hygiene — this is not a sandbox

`omp-re` is a dual-use tool: it runs rizin against binaries you feed it,
which may include real, live malware. Neither `omp-re` nor rizin itself
provides any isolation:

- **`aaa` (full analysis) on a hostile binary is not a sandbox.** rizin is
  a static analysis tool — it disassembles and analyzes the file, it does
  not execute it — but rizin itself, its plugins (rz-ghidra, jsdec), the
  triage tools (capa, etc.), and any file-format parsing anywhere in that
  chain are attack surface. A
  malformed binary crafted to exploit a parser bug is a real, if narrow,
  risk. **Run this suite against untrusted samples inside a VM or other
  disposable environment you're prepared to lose, not on your primary
  machine.**
- The static tools never execute the binary you open; they only read and
  analyze the file. The **one exception is `rizin_debug`**, which launches
  the sample under rizin's debugger. It is off unless you set
  `OMPRE_ENABLE_DEBUGGER`, and when on, the sandboxing responsibility is
  entirely yours — see `## rizin_debug` below.
- Triage tools (`triage_capa`, `triage_yara`, etc.) shell out to real
  external binaries you installed yourself. Their own security posture is
  out of scope for this document — keep them updated.
- omp-re adds no tool at all, and no code-execution tool. The model reaches
  the engine from omp's own `eval`, whose code runs in omp's eval kernel under
  omp's approval of `eval` — see `## What omp approves` and `## The listener`
  below for what that does and does not gate.
- Under omp the engine is a child process: the extension starts the `sbcl` on
  your `PATH` (or `OMPRE_SBCL_PATH`) by argv, with no shell, with
  `--no-sysinit --no-userinit` so no init file runs in it. It talks to omp on
  its standard input and output only; the engine opens no socket (the
  extension does, on the loopback interface: `## The listener`). It runs with
  your privileges, as omp does. ASDF keeps the engine's compiled files in its cache
  in your home directory and loads them at the next start, so that cache is as
  trusted as the plugin's own files.
- What the extension runs as the engine is, in order, the executable
  `OMPRE_ENGINE_IMAGE` names, an image in the plugin's `dist/` folder, and
  the image it built itself in omp-re's cache directory
  ([`docs/install.md`](docs/install.md#the-engine-image)). Each is run with
  your privileges, so each is as trusted as the plugin's own files: whoever
  can write to that cache directory, or set that variable for omp, chooses
  the program omp starts. The extension downloads none of them. An image
  from a GitHub release is a binary you chose to run; building your own
  (`bun run build:image`) from source you have read is the alternative.
- `OMPRE_ALLOWED_DIRS` (nodecode: `allowed_dirs`) limits the directories the
  engine opens a binary, a mapped file, YARA rules or a FLIRT signature file
  (`apply_signatures`) from, compared after links are resolved. It is unset by
  default, which allows any file you can read. It is a guard against a model
  opening the wrong file, not a sandbox. Three kinds of path are not held to
  it:
  - a file named in `rizin_cli`'s arguments, which the `rz-*` tool opens
    itself: an argument list has no reliable way to tell a path;
  - `rizin_debug`'s `run.stdin`, `run.stdout`, `run.stderr` and `run.cwd`,
    which rz-run opens for the debuggee. The debugger is off unless you
    switch it on, and it runs the target's code in any case;
  - the manifest the line `carry` reads. The binary given with `--against`
    is held to the list.

## What omp approves

Up to 0.11 every tool of omp-re was a tool registered with omp, and omp asked
about each call on that tool's own tier: `read` for a lookup, `write` for an
annotation, `exec` for a rizin command, with a sentence saying what the call
would do. **That per-call approval is gone.** omp-re registers no tool; the
model calls the engine from inside a cell of omp's `eval`, and to omp a cell is
one call of one `exec`-tier tool:

- omp's approval mode and `tools.approval.eval` decide whether a cell runs.
  Under omp's default mode nothing is asked. Under `always-ask` you are shown
  the cell's code, once, and what it asks of the engine while it runs is not
  shown to you again.
- A policy cannot tell one cell from another: `tools.approval.eval: allow`
  allows renaming a function and reading one alike. There is no setting that
  lets reads through and asks about writes.
- nodecode never had per-call approval; the two hosts are now alike in this.

What stands between a cell and your machine is therefore the engine's own
policy, which is unchanged and does not depend on omp:

- only read-only rizin commands run through `rizin_command` (`## rizin_command`);
- files are opened only from `OMPRE_ALLOWED_DIRS` when you set it;
- the tools write only into `OMPRE_OUTPUT_DIR`, the report where its line says;
- the debugger does not exist unless you set `OMPRE_ENABLE_DEBUGGER`;
- every call is a line in the audit log, signed when `OMPRE_AUDIT_HMAC_KEY` is
  set, named by the `eval` call it came from and its place in that cell.

Note what `eval` is: omp runs a cell's code unsandboxed, as a process of
yours. A cell that is allowed to run can already read files, spawn programs
and open sockets without omp-re. omp-re's policy governs what is asked of
*its engine*; it is not a sandbox for the model.

`OMPRE_DISABLED=1` in omp's environment keeps the extension from starting
anything: no engine, no listener. There is no longer a per-session switch
(`/re off`).

## The listener omp's eval reaches the engine through

An `eval` kernel is a separate process, and omp gives a plugin no channel into
it. So, under omp, the extension listens for the kernels of its own omp
process (`extensions/re/bridge.ts`):

- It binds `127.0.0.1` only, on a port the system picks, for as long as a
  session with the plugin is alive in that omp process. It is not reachable
  from another machine.
- Every request must carry a bearer token: 32 random bytes made when the
  listener starts, compared in constant time. A request without it is refused
  (401) before its body is read. A web page in your browser can send a request
  to a loopback port, and cannot know the token.
- The token and the port are written to one file, `<pid of omp>.json`, mode
  `0600`, in `$XDG_RUNTIME_DIR/omp-re` or else `<tmpdir>/omp-re-<your uid>`,
  a directory made `0700`. The extension refuses a directory that is not a
  directory of yours, since someone else's directory under a shared `/tmp` is
  one they could swap files in; the library in the kernel refuses a file that
  is not yours. The file is removed when the listener stops; one left by a
  killed omp is removed by the next.
- **Whoever can read that file can drive the engine**: open binaries, run
  read-only rizin commands, annotate, record findings, write a report where a
  line says. That is every process running as you — your shell, your editor,
  anything you run — and nobody else, short of root. It is the trust boundary
  of your own account, the same one that already lets those processes run
  `rizin`, read omp's session files, or attach to omp. It is not a boundary
  against other software you run as yourself.
- A request says which session it is for by the session file (or, for a
  session omp keeps no file for, the directory) its kernel was given by omp.
  The token authorizes the whole listener, not one session: a process that
  has the token can name any session of that omp process. Two sessions that a
  request cannot tell apart are refused, never guessed.
- On Windows the file's mode bits do not restrict anything; the file is
  protected by where it is, your own temporary directory. This is as written
  and has not been run there.
- A kernel that stops waiting — a cell's timeout, an interrupt — closes its
  connection, and the engine's work on that request is cancelled.

## Mutations never touch the file on disk

`set_comment`, `rename_function`, `rename_variable`, `set_prototype`, and
`set_variable_type` only mutate rizin's **in-process analysis database**
for the running session. The engine starts rizin with `-q0`, `-N`, two
settings that keep its output plain, and the path — no `-w` (write) flag — so
rizin opens the file read-only and none of these tools ever writes back to
the sample on disk. The annotations themselves are recorded in the session's
record and replayed into rizin when the session is resumed.

`map_file` opens a *second* file into the session (`o <file> <addr>`, book:
basic_commands/mapping_files) — a dump, a library, a blob to analyze alongside
the primary binary. Reading a file the model names is the same trust boundary
as `open_binary` (which opens the sample itself); the path is resolved to an
existing readable file, held to `OMPRE_ALLOWED_DIRS` when that is set, and
single-quoted so it cannot inject a command. It is opened
with `o`, never `o+`, so the mapped file stays read-only on disk — mapping
never writes it.

The sample is never written. The files the tools themselves emit — a memory
dump (`rizin_debug`'s `dump_memory`), a saved trace (`trace_save`), an
exported project (`export_project`) and a created signature
(`create_signature`) — all go to a single confined directory:
`OMPRE_OUTPUT_DIR`, or `<tmpdir>/omp-re-out` when unset. The model supplies at
most a bare file name, validated to letters, digits, `.`, `_` and `-` (no
separators, no `..`, not absolute), never a path, so none of them can
traverse out of that directory or overwrite an arbitrary file. A memory dump's
bytes are read by the engine through the debugger and written by the engine;
for the other three rizin is handed the confined path, single-quoted.
The lines `report <path>` and `carry --out <path>` write where the line says.
On both hosts it is the model that runs a line, from `eval`, where it can
already write files.

`-N` additionally skips the user's `rizinrc` and startup scripts, so a global
eval var or alias in the operator's config can't silently change the command
output omp-re parses; plugins still load (that needs `-NN`, which omp-re never
uses), so decompilers are unaffected. `OMPRE_RIZIN_LOAD_USER_CONFIG=1` restores
`rizinrc` loading for operators who need it. The debug session adds `-d` to
the same flags — see `## rizin_debug`.

## Command construction

Every value a model supplies reaches rizin through one of three paths, and
none of them can start a second command:

- Addresses and names are checked against an allowlist (`[0-9a-zA-Z_.:$+-]`)
  that excludes `;`, `@`, `~`, `|`, quotes, backticks, and parentheses, so no
  value can add a command, a `@@` iterator, a grep, a pipe, or a `$(...)`
  substitution.
- Function and variable names must be identifiers.
- Free text (comments) and C types/prototypes are passed as single-quoted
  rizin arguments with `\'` and `\\` escaped, which rizin treats as a
  literal; line breaks and NUL are rejected outright. This includes the type
  given to `define_variable` (`afvs`/`afvr`), which — like `set_prototype`,
  `set_variable_type`, and `define_global` — is single-quoted, not merely
  character-checked.
- The single read entry, `rizin_command` (the one tool through which the model
  reads the binary — searches included, as `/xj`, `/xrj`, `/Rj`, …), gates every
  command against the read-only catalog check and a forbidden-syntax guard
  (`forbidden-syntax-reason` in `engine/policy.lisp`) before it reaches the pipe: no `;`, `|`, `<`/`>`,
  backticks, `~`, line breaks, or `@` modifiers except `@!<n>`.

**0.1.x is affected by a command-injection bug fixed in 0.2.0.** It
interpolated `set_comment` text into `CC <text> @ <addr>` unquoted, and the
command backend splits on `;`, so a comment such as `a; !id` ran an
additional command — including `!`, a shell escape. `set_comment` was then a
`write`-tier tool, so this let a model (for example one steered by text
inside the sample it was analyzing) reach shell execution without passing an
`exec`-tier approval. `/re undo` replayed stored comments the same way.
Upgrade if you run 0.1.x; 0.2.0 onward (rizin) is not affected.

## rizin_command

`rizin_command` is the one tool that sends a model-written rizin command
line, and it refuses before anything reaches rizin unless the command:

- belongs to a read-only family — print, info, search, graph, op/ESIL
  analysis, xref and function queries, comment and flag lookups — and is
  none of the write, config, shell, file-reading, or analysis-changing
  commands inside those families (`po`, `pw`, `pkill`, `/F`, `ag[enw]`,
  `afb[cer]`, `afii`, `ica`, `idp`, or any name containing `+ - = ! *`), **or**
  is one of a curated set of read-only commands the family regex can't shape
  (config reads `e`/`el`/`et`/`es`, analysis-hint and metadata/string
  listings, class reads, address info, type/union/xref reads, plugin
  listings, the FLIRT sigdb listing) that was each confirmed read-only
  against a real rizin, or is one of the `p=`/`p==` statistical-histogram
  prints (entropy, chi-square, printable/string density, byte histograms)
  allowed by name despite the `=` guard — with the interactive visual (`…v`)
  variants excluded so none can block the command pipe;
- is not a get/set dual used in its set form: `e <key>` reads a value but
  `e <key>=<value>` (a config write) is refused, and the positional duals
  `tn`/`Ld`/`Lo` run only with no argument (an argument makes them add or
  set);
- takes no file or path argument according to rizin's own catalog
  (`/m <magic-file>` runs only bare);
- contains none of `;`, `|`, `<`, `>`, backticks, `$(`, `${`, `~`, `#`, `"`,
  `\`, line breaks, or NUL, and no `@` modifier except `@!<n>` — so no
  chaining, piping to a shell, redirection, substitution, `@@` iterators,
  `@f:` file reads, or `@e:` config changes; the seek address comes only
  from the validated `addr` parameter;
- is in the installed rizin's catalog and is not an `interactive` mode.

Raw-byte printers (`pr`, `prz`, `prg`, `p6d`) are refused too: a NUL in
their output ends a `-q0` frame, which desyncs the pipe and kills the
session's rizin process (and with it the live analysis). The checks are
`check-rizin-command` in `engine/policy.lisp` and the patterns and command
lists are `engine/policy-data.lisp`; both hosts run this one copy. The escapes
above are covered by the policy checks of `test/nodecode/suite-core.lisp`.

The forbidden-syntax set is drawn from rizin's own documented prompt grammar
(the Rizin Book, *First Steps → Command-line*): command separator `;`, pipes
`|`, redirection `>`/`2>`/`H>`/`<`, the grep `~`, the full `@` temporary-
modifier family (`@@` iterators, `@e:`, `@f:`, `@x:`, `@r:`, `@o:`, … — all
refused, with only `@!<n>` block size allowed), substitution, and comments.
The shell (`!`/`!!`) and background-task (`&`/`&t`) operators are command
heads, so they are refused by the read-only-family check rather than the
syntax scan.

Even read-only commands parse the sample, so the analysis-hygiene advice
above applies to them unchanged.

## rizin_cli

`rizin_cli` runs the standalone `rz-*` tools. The engine starts them by argv,
never through a shell, so `;`/`|`/`$()`/backticks in an argument are inert
text. What is gated is the flags, refused before the tool
is spawned:

- flags that run code: `rz-find -E` (shell command per hit), `rz-find -R`
  (rizin command per hit, which can reach `!` shell), `rz-diff -t command`
  (runs a rizin command per file, which reaches `!` shell);
- flags that write or extract to disk: `rz-bin -O`/`-o`/`-C`/`-x`, `rz-asm -O`;
- flags that reach the network: `rz-bin -dd`/`-PP` (debuginfod / pdb);
- flags that open an interactive view that would hang: `rz-diff -H`/`-S`.

The gating is **getopt-aware**, so a denied capability cannot be smuggled
past by respelling the flag. Short-flag clusters are checked letter by letter
and case-sensitively (so `rz-bin -c`, list classes, is allowed while `-C`,
create a binary, is not). A capability that escalates on repetition —
`rz-bin -d` reads local DWARF but `-dd` downloads it — is refused by counting
the letter across *all* clusters, so `-dd`, `-d -d`, `-ddj`, and `-jdd` are
all caught while a single `-d` stays allowed. A value-taking flag whose value
is dangerous — `rz-diff -t command` — is refused in every spelling (`-t
command`, `-tcommand`, `-Xtcommand`), since the value is the rest of the
cluster after the flag or the next token. (Earlier versions matched only the
exact doubled token and the split `-t command` pair; the attached and
split-letter forms were a sandbox-escape bypass, now closed and regression-
tested.) `rz-gg` (shellcode/egg
generation) is not exposed at all. `rz-run` is not a `rizin_cli` tool either,
but its directives configure the debugger's launch environment via
`rizin_debug`'s `run` option (see below) — stdio targets there are files
only; a `!command` target that would run a shell command is refused. This is
a convenience boundary over the flags, not a sandbox: the tools read whatever
files you point them at, with your privileges, exactly as if you ran them.
The policy is `check-rz-cli` in `engine/extras.lisp`, covered by
`test/nodecode/suite-extras.lisp`.

## rizin_debug

`rizin_debug` is the one tool that **executes the sample**: it launches the
binary under rizin's debugger (`rizin -d`) so it can be stepped and inspected
at runtime. Because that inverts the "never runs the file" property the rest
of the suite holds:

- It is **off by default**. The tool is offered only when
  `OMPRE_ENABLE_DEBUGGER` is set (nodecode: or `debugger` is true in the `re`
  section), so a default install cannot be talked into
  executing a sample — the capability has to be deliberately enabled by the
  operator, out of band.
- It runs in a **separate rizin session** (`-d`) from the static one, which
  continues to only read the file. The debug process is killed with its
  debuggee on `stop` and on session shutdown.
- Nothing asks you about one action: once the debugger is switched on, a
  cell may resume execution (`start`, `continue`, `continue_to_syscall`,
  `step`), modify the live process (`write_register`, `write_memory`,
  `watch_add`, `break_add_hw`), read live memory out to a file (`dump_memory`
  — see the confined output directory above), or inspect (`registers`,
  `read_memory`, `disassemble`, `backtrace`, the heap and process-state
  actions). The switch is the gate. Addresses, register names, register
  values, and hex byte strings are all validated before anything reaches the
  process.
- `break_command` stores a rizin command that reruns on **every** breakpoint
  hit (`dbc`), so its command string is gated the way `rizin_command` is —
  but, running inside the live debugger, it additionally allows a vetted set
  of read-only debugger-state reads (register/arena views, memory-map/module/
  library/heap listings, backtraces, process/thread/fd/signal listings; see
  `check-debug-on-hit-command` in `engine/policy.lisp`). Matched by exact command token,
  with any `=` refused, so a register-assign dual (`dr rax=0`), a control
  command (`dc`/`ds`), a write, config, shell, or script form can never be
  stored — the on-hit command can only log state, never drive or mutate the
  process. `break_condition` passes its expression to rizin single-quoted, so
  comparison operators in the condition stay literal and never become
  redirects.
- It is a **plain debugger** — breakpoints and watchpoints, stepping,
  reading and writing registers and memory, disassembling live memory,
  recording a trace and stepping backward through it (reverse debugging),
  backtraces, heap and process-state inspection. The register/memory writes
  act only on the process this session drives; the tool has no features for
  evading anti-debugging, hiding the debuggee, or injecting into other
  processes.
- Besides launching, `start` can **attach** to a running pid or **connect to
  a remote stub** (`attach: {pid}` / `attach: {remote: "gdb://…"}`), so a
  sample can be driven inside an isolated VM from the host. Attaching controls
  an existing process with your privileges; a remote target opens an outbound
  connection to the stub you name (through the environment's network policy).
  The pid must be a positive integer and the remote URI must be a
  charset-validated `gdb://`/`windbg://` string — both reach rizin through
  argv, never a shell. `attach` is refused together with `run` (there is no
  new process to configure), and these paths still require
  `OMPRE_ENABLE_DEBUGGER`.

The debugger provides **no isolation whatsoever** — it is the opposite of a
sandbox. Enable it and run a sample only inside a disposable VM or container
you are prepared to lose. The implementation is `engine/debug.lisp`, covered
by `test/nodecode/suite-debug.lisp`.

## Scope

In scope: the engine (`engine/`), its two hosts (`stdio/` with
`extensions/re/`, and `nodecode/`), the listener and the library that asks it
(`extensions/re/bridge.ts`, `skills/re-triage/recipes.js` and `recipes.py`),
the engine's lines, and the tool implementations. Out of scope: rizin itself, rz-ghidra, jsdec, capa/floss/
diec/yara, SBCL, cl-ppcre, omp and nodecode — report vulnerabilities in those
projects upstream.
