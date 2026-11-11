;;;; voice.lisp --- the engine's phrases as omp says them, and omp's manual.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Under omp the operator's settings are environment variables — which is
;;;; how the engine says them itself — and the model reaches the engine from
;;;; omp's own `eval' tool, through the library the re-triage skill loads
;;;; there: `re' in the JavaScript kernel, where every function is awaited,
;;;; and `omp_re' in the Python kernel, where none is. One text serves both
;;;; kernels, so a call is shown in both spellings where they differ. The
;;;; keys are the engine's (engine/host.lisp, +VOICE+); only what omp says
;;;; differently is here.

(in-package #:omp-re-stdio)

(defparameter +omp-voice+
  '((:open-first . "open one first: await re.open(\"/path/to/binary\") — in Python, omp_re.open(\"/path/to/binary\")")
    (:list-tools . " — re.tools() lists them")
    (:read-more . "read the rest with re.cmd(…) or re.json(…)")
    (:launcher . "A desktop launch of omp")
    (:open-binary-note . ", especially in a task subagent, which starts with no binary open")
    (:list-hint . "enter ~a · type to filter · esc close")
    (:references-hint . "enter open · esc back")
    (:slash . "re.slash(\"~a\")")
    (:type-object . "an object~@[ (~{~a~^, ~})~]; in Python a dict")
    (:type-objects . "an array of objects (~{~a~^, ~}); in Python a list of dicts")
    (:doc-takes . "await re.call(~s, { name: value, … }) — in Python omp_re.call(~:*~s, name=value, …) — takes:")
    (:manual-start . "omp-re — reverse engineering with rizin, driven from code in omp's eval.

Everything is a function of one library, loaded once per kernel in a cell of
its own: `%load skill://re-triage/recipes.js` defines `re` (JavaScript; every
function is async, so await it), `%load skill://re-triage/recipes.py` defines
`omp_re` (Python; the same functions, plain calls, options as keywords, names
in snake_case). Below is the JavaScript spelling.

Start here
  1. await re.open(\"/path/to/binary\")       — spawn rizin + analyze (aaa). Every other
     function acts on the binary opened last in this session; a task subagent opens
     its own. A raw or headerless file takes { arch, bits, base, map, format }.
  2. await re.call(\"rizin_help\", { query: \"<prefix or keywords>\" })  — find the command
     (e.g. \"entropy\", \"call graph\", \"pdf\") and its exact arguments for THIS rizin.
  3. await re.cmd(\"aflj\")                    — run ONE read-only rizin command; its text.
     Put an address in the second argument, re.cmd(\"pdg\", \"main\") (sent as `@ addr`),
     never `@` in the command. No ; | > or ~ either: filter and loop in code.
  4. const { data, evidence } = await re.json(\"aflj\")  — the same for a *j command, as
     the data itself, whole even past the size cap, with the id of its evidence record.
     In Python: data, evidence = omp_re.json(\"aflj\").")
    (:manual-results . "How a result reads
  A function answers a string (re.json answers data). A read is recorded as
  evidence, so re.cmd's text is: the header line (rizin> <cmd>), the body (JSON for a
  *j command), then a trailing [evidence …] tag line. print(text) shows it; a big
  list is cut at the size cap in that text and ends with [Output truncated …
  artifact://N] — use re.json for the data, read(\"artifact://N\") for the text, or
  run a narrower command. A call the engine refuses, or that fails, throws with the
  engine's words (Python: RuntimeError).
  Addresses are strings (\"0x401000\", \"main\"): a 64-bit one does not fit a number.")
    (:manual-tools . "The other (stateful) tools — await re.call(\"<name>\", { … }); re.tools() lists them
and re.doc(\"<name>\") shows one's arguments")
    (:manual-config . "Lines
  await re.slash(\"<line>\") runs what the engine's text calls a /re line: functions,
  strings, imports, evidence [id], findings [id], undo, verify [--strict],
  report [path], carry <manifest>, help. re.status() is the line `status`.

Recipes (reads composed for you, each line naming the evidence it rests on)
  re.triage(), re.scanImports(), re.inspectFunction(\"main\"), re.findComparisons(\"main\"),
  re.findCrypto() — in Python triage, scan_imports, inspect_function, find_comparisons,
  find_crypto. re.recipes() says what each answers and takes.

Config (the operator's, in omp's environment)
  OMPRE_RIZIN_PATH (rizin if not on PATH) · OMPRE_DECOMPILER (pdg/pdd order) ·
  OMPRE_ENABLE_DEBUGGER · OMPRE_AUDIT_HMAC_KEY · OMPRE_DISABLED=1 (the plugin off).
  re.status() for live state.")))
