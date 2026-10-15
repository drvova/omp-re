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
- `omp-re` never executes the binary you open. `debug`-tool-driven dynamic
  analysis (attach, breakpoints) is a separate, explicit action via omp's
  own built-in `debug` tool — see [`docs/workflow.md`](docs/workflow.md).
  If you use it, the sandboxing responsibility is entirely yours.
- Triage tools (`triage_capa`, `triage_yara`, etc.) shell out to real
  external binaries you installed yourself. Their own security posture is
  out of scope for this document — keep them updated.

## Mutations never touch the file on disk

`set_comment`, `rename_function`, `rename_variable`, `set_prototype`, and
`set_variable_type` only mutate rizin's **in-process analysis database**
for the running session. `RzSession.spawn` launches rizin as
`rizin -q0 <path>` — no `-w` (write) flag — so rizin opens the file
read-only and none of these tools ever writes back to the sample on disk.
The annotations themselves are recorded in the omp session and replayed into
rizin when the session is resumed.

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

Even read-only commands parse the sample, so the analysis-hygiene advice
above applies to them unchanged.

## Scope

In scope: `extensions/re/*.ts`, the `/re` command surface, and the tool
implementations. Out of scope: rizin itself, rz-ghidra, jsdec, capa/floss/
diec/yara, and omp — report vulnerabilities in those projects upstream.
