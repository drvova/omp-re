# Security

## Reporting a vulnerability

Open a private security advisory on this repository's GitHub Security tab,
or email the maintainer listed in `package.json`. Do not open a public issue
for an unpatched vulnerability. Include a minimal reproduction and the
`omp`/`rizin`/`omp-re` versions involved; expect an initial response
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

## Mutations never touch the file on disk

`set_comment`, `rename_function`, `rename_variable`, `set_prototype`, and
`set_variable_type` only mutate rizin's **in-process analysis database**
for the running session. `RzSession.spawn` launches rizin as
`rizin -q0 -N <path>` — no `-w` (write) flag — so rizin opens the file
read-only and none of these tools ever writes back to the sample on disk.
The annotations themselves are recorded in the omp session and replayed into
rizin when the session is resumed.

`-N` additionally skips the user's `rizinrc` and startup scripts, so a global
eval var or alias in the operator's config can't silently change the command
output omp-re parses; plugins still load (that needs `-NN`, which omp-re never
uses), so decompilers are unaffected. `OMPRE_RIZIN_LOAD_USER_CONFIG=1` restores
`rizinrc` loading for operators who need it. The debug session
(`RzSession.spawnDebug`) adds `-d` to the same flags — see `## rizin_debug`.

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
  literal; line breaks and NUL are rejected outright.

**0.1.x is affected by a command-injection bug fixed in 0.2.0.** It
interpolated `set_comment` text into `CC <text> @ <addr>` unquoted, and
radare2 splits commands on `;`. A comment such as `a; !id` therefore ran an
additional radare2 command — including `!`, a shell escape — reproduced
against radare2 5.5.0. `set_comment` is a `write`-tier tool, so this let a
model (for example one steered by text inside the sample it was analyzing)
reach shell execution without passing an `exec`-tier approval. `/re undo`
replayed stored comments the same way. Upgrade if you run 0.1.x.

## rizin_command

`rizin_command` is the one tool that sends a model-written rizin command
line, so it is `exec`-tier (the approval prompt quotes the exact command)
and it refuses before anything reaches rizin unless the command:

- belongs to a read-only family — print, info, search, graph, op/ESIL
  analysis, xref and function queries, comment and flag lookups — and is
  none of the write, config, shell, file-reading, or analysis-changing
  commands inside those families (`pf`, `po`, `pw`, `pkill`, `pm`, `/F`,
  `ag[enw]`, `afb[cer]`, `afii`, `ica`, `id`, or any name containing
  `+ - = ! *`);
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
session's rizin process (and with it the live analysis). Each refusal and
the policy table live in `extensions/re/catalog.ts`; the escapes above are
covered by `test/rizin-cli.test.ts`.

The forbidden-syntax set is drawn from rizin's own documented prompt grammar
(the Rizin Book, *First Steps → Command-line*): command separator `;`, pipes
`|`, redirection `>`/`2>`/`H>`/`<`, the grep `~`, the full `@` temporary-
modifier family (`@@` iterators, `@e:`, `@f:`, `@x:`, `@r:`, `@o:`, … — all
refused, with only `@!<n>` block size allowed), substitution, and comments.
The shell (`!`/`!!`) and background-task (`&`/`&t`) operators are command
heads, so they are refused by the read-only-family check rather than the
syntax scan. `test/rizin-cli.test.ts` pins each of these.

Even read-only commands parse the sample, so the analysis-hygiene advice
above applies to them unchanged.

## rizin_cli

`rizin_cli` runs the standalone `rz-*` tools. They are invoked by argv
through omp's `exec`, never a shell, so `;`/`|`/`$()`/backticks in an
argument are inert text. What is gated is the flags, refused before the tool
is spawned:

- flags that run code: `rz-find -E` (shell command per hit), `rz-find -R`
  (rizin command per hit, which can reach `!` shell), `rz-diff -t command`
  (runs commands in both files);
- flags that write to disk: `rz-bin -O`/`-o`/`-C`, `rz-asm -O`;
- flags that reach the network: `rz-bin -dd`/`-PP` (debuginfod / pdb);
- flags that open an interactive view that would hang: `rz-diff -H`/`-S`.

Short-flag clusters are checked letter by letter and case-sensitively (so
`rz-bin -c`, list classes, is allowed while `-C`, create a binary, is not),
and a doubled flag like `-dd` is matched whole. `rz-gg` (shellcode/egg
generation) and `rz-run` (launches a process) are not exposed at all. This is
a convenience boundary over the flags, not a sandbox: the tools read whatever
files you point them at, with your privileges, exactly as if you ran them.
The policy lives in `extensions/re/tools-rzcli.ts` and is covered by
`test/rzcli.test.ts`.

## rizin_debug

`rizin_debug` is the one tool that **executes the sample**: it launches the
binary under rizin's debugger (`rizin -d`) so it can be stepped and inspected
at runtime. Because that inverts the "never runs the file" property the rest
of the suite holds:

- It is **off by default**. The tool is registered only when
  `OMPRE_ENABLE_DEBUGGER` is set, so a default install cannot be talked into
  executing a sample — the capability has to be deliberately enabled by the
  operator, out of band.
- It runs in a **separate rizin session** (`-d`) from the static one, which
  continues to only read the file. The debug process is killed with its
  debuggee on `stop` and on session shutdown.
- Every action is `exec`-tier, and the approval reason says plainly whether
  it resumes execution (`start`, `continue`, `step`) or only inspects
  (`registers`, `read_memory`, `backtrace`). Addresses are validated with the
  same allowlist as every other tool.
- It is a **plain debugger** — breakpoints, stepping, registers, memory,
  backtrace. It has no features for evading anti-debugging, hiding the
  debuggee, or injecting into other processes.

The debugger provides **no isolation whatsoever** — it is the opposite of a
sandbox. Enable it and run a sample only inside a disposable VM or container
you are prepared to lose. The implementation is `extensions/re/tools-debug.ts`
(launch in `RzSession.spawnDebug`), covered by `test/debug.test.ts`.

## Scope

In scope: `extensions/re/*.ts`, the `/re` command surface, and the tool
implementations. Out of scope: rizin itself, rz-ghidra, jsdec, capa/floss/
diec/yara, and omp — report vulnerabilities in those projects upstream.
