;;;; voice.lisp --- the engine's phrases as omp says them, and omp's manual.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Under omp the operator's settings are environment variables, a binary can
;;;; be named on the command line (--binary), and the model reaches a tool
;;;; from omp's eval as `await tool.<name>({...})'. The keys are the engine's
;;;; (engine/host.lisp, +VOICE+).

(in-package #:omp-re)

(defparameter +omp-manual+
  "omp-re — reverse engineering with rizin, driven from code.

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
     `addr` (sent as `@ addr`), never `@` in the command.

Reading the binary (prefer the JSON `*j` forms; they canonicalize for /re verify)
  functions   aflj            one function  afij  @ <fn>     decompile  pdg  @ <fn>  (or pdd)
  disassemble pdfj  @ <fn>     xrefs to      axtj @ <addr>   xrefs from axfj @ <addr>
  strings     izj              imports       iij             exports    iEj
  symbols     isj              sections      iSj             headers    iHj
  types       tsj              entropy       ph entropy      hexdump    px <n> @ <addr>
  search      /xj <hex>  /Rj (ROP)  /vj (value)             info       ij
  il lift     aoj @ <addr>  (esil+rzil)  esil calc  ae <rpn>  (ae 0x41,0x13,^)
  Anything else: rizin_help first, then rizin_command. Read-only; writes are refused here.
  Driving the RzIL VM (stateful) is the separate rizin_emulate tool.

Render in eval (display vs print)
  A call returns { text, details } to your code — not a card. display(value) shows a
  highlighted block, print(x) monospace text. A read is recorded as evidence, so its
  `.text` is: the header line, the JSON (`*j`) body, then a trailing [evidence …] tag
  line — parse the body by dropping the first and last lines. A helper that falls back
  to print (so truncated/non-JSON output never throws):
    const show = (r) => { try { display(JSON.parse(r.text.split(\"\\n\").slice(1, -1).join(\"\\n\"))); } catch { print(r.text); } };
    show(await tool.rizin_command({ command: \"afij\", addr: \"main\" }));   // highlighted JSON
    print((await tool.rizin_command({ command: \"pdg\", addr: \"main\" })).text);   // C/text
  A big list (aflj, izj on a large binary) is cut at the size cap and ends with
  [Output truncated … artifact://N]: read that artifact, or run a narrower command.

The other (stateful) tools — reach them the same way, await tool.<name>({…})
  open_binary, map_file, export_project            — session: open/overlay/save.
  rename_function, rename_variable, set_comment, set_prototype, set_variable_type,
  define_function, define_global, set_flag, set_calling_convention, set_arch_hint, …
                                                   — annotate; recorded and REPLAYED on resume.
  apply_signatures, create_signature               — FLIRT.        analyze — extra recovery passes.
  record_finding, adopt_finding, retract_finding   — gate report claims on evidence ids.
  rizin_cli                                        — the rz-* programs (rz-bin, rz-diff, rz-hash, …).
  triage_capa/floss/die/yara                       — external triage (present only when installed).
  rizin_debug (opt-in, executes the sample), rizin_emulate (RzIL)  — dynamic analysis.

Evidence & reports
  Every rizin_command read is recorded as evidence (/re evidence); cite its
  [evidence xxxxxxxx] id in record_finding to gate a claim. /re report writes the
  evidence-gated report; /re verify re-runs cited commands to confirm they still reproduce.

Config
  OMPRE_RIZIN_PATH (rizin if not on PATH) · OMPRE_DECOMPILER (pdg/pdd order) ·
  OMPRE_ENABLE_DEBUGGER · OMPRE_AUDIT_HMAC_KEY.  Run /re status for live state.")

(defparameter +omp-voice+
  `((:open-first . "use /re open <path>, open_binary, or --binary <path> first")
    (:list-tools . "")
    (:read-more . "read the rest with rizin_command")
    (:debugger-switch . "OMPRE_ENABLE_DEBUGGER")
    (:debugger-enable . "set OMPRE_ENABLE_DEBUGGER")
    (:allowed-dirs . "OMPRE_ALLOWED_DIRS")
    (:rizin-path . "set OMPRE_RIZIN_PATH")
    (:launcher . "A desktop launch of omp")
    (:open-binary-note . ", especially in a task subagent, which starts with no binary open")
    (:help-keys . "keys: alt+g functions · alt+s strings · alt+i imports; in a code view: d toggle decompile · x follow xrefs · a ask the model")
    (:manual . ,+omp-manual+)))
