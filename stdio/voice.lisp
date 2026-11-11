;;;; voice.lisp --- the engine's phrases as omp says them, and omp's manual.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Under omp the operator's settings are environment variables — which is
;;;; how the engine says them itself — a binary can be named on the command
;;;; line (--binary), and the model reaches a tool from omp's eval as `await
;;;; tool.<name>({...})'. The keys are the engine's (engine/host.lisp,
;;;; +VOICE+); only what omp says differently is here. This file also makes
;;;; the host's package.

(defpackage #:omp-re-stdio
  (:use #:cl #:omp-re)
  (:export #:serve #:+protocol+))

(in-package #:omp-re-stdio)

(defparameter +omp-voice+
  '((:open-first . "use /re open <path>, open_binary, or --binary <path> first")
    (:launcher . "A desktop launch of omp")
    (:open-binary-note . ", especially in a task subagent, which starts with no binary open")
    (:help-keys . "keys: alt+g functions · alt+s strings · alt+i imports; in a code view: d toggle decompile · x follow xrefs · a ask the model")
    (:list-hint . "enter ~a · type to filter · esc close")
    (:references-hint . "enter open · esc back")
    (:next-prompt . "(e.g. omp -c -p \"<agenda>\")")
    (:manual-start . "omp-re — reverse engineering with rizin, driven from code.

You observe the binary by running rizin's own commands through this one tool,
`rizin_command`, and composing them in omp's `eval` as
`await tool.rizin_command({ command, addr? })`. omp's eval is the single code
host — define helper functions there and reuse them across calls this session.

Start here
  1. await tool.open_binary({ path: \"/path/to/binary\" })  — spawn rizin + analyze (aaa).
     Every command acts on the most-recently-opened binary; a task subagent opens its own.
  2. await tool.rizin_help({ query: \"<prefix or keywords>\" })  — find the command
     (e.g. \"entropy\", \"call graph\", \"pdf\") and its exact arguments for THIS rizin.
  3. await tool.rizin_command({ command: \"aflj\" })  — run it. Put an address in
     `addr` (sent as `@ addr`), never `@` in the command.")
    (:manual-results . "Render in eval (display vs print)
  A call returns { text, details } to your code — not a card. display(value) shows a
  highlighted block, print(x) monospace text. A read is recorded as evidence, so its
  `.text` is: the header line, the JSON (`*j`) body, then a trailing [evidence …] tag
  line — parse the body by dropping the first and last lines. A helper that falls back
  to print (so truncated/non-JSON output never throws):
    const show = (r) => { try { display(JSON.parse(r.text.split(\"\\n\").slice(1, -1).join(\"\\n\"))); } catch { print(r.text); } };
    show(await tool.rizin_command({ command: \"afij\", addr: \"main\" }));   // highlighted JSON
    print((await tool.rizin_command({ command: \"pdg\", addr: \"main\" })).text);   // C/text
  A big list (aflj, izj on a large binary) is cut at the size cap and ends with
  [Output truncated … artifact://N]: read that artifact, or run a narrower command.")
    (:manual-tools . "The other (stateful) tools — reach them the same way, await tool.<name>({…})")))

