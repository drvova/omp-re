;;;; cell.lisp --- the primer, the /re command, the declaration.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Config, a sibling top-level key of ~/.nodecode/config.jsonc:
;;;;   "re": {"rizin_path": "", "state_dir": "",
;;;;          "allowed_dirs": [], "debugger": false, "idle_minutes": 30}
;;;; A vetoed section ("enabled": false) installs nothing. There is no secret
;;;; here: the audit log's signing key stays the engine's own environment
;;;; variable, OMPRE_AUDIT_HMAC_KEY.

(in-package #:nodecode-re)

(defparameter +primer+
  "Reverse engineering with rizin is available through the nodecode-re cell (omp-re). You reach
it from eval, as verbs in the RE package; each answers a string, but re:json.
  (re:open \"path\")          open a binary and analyze it. Do this first; every other verb acts
                            on the binary opened last in this session. A relative path reads
                            against the session's directory. A raw or headerless file takes
                            :arch \"arm\" :bits 32 :map \"0x8000000\" (also :base, :format).
  (re:cmd \"aflj\")           run ONE read-only rizin command: the one way to read the binary.
                            (re:cmd \"pdg\" \"main\") runs it at an address or symbol. No ; | > @
                            or ~ in a command: filter and loop in Lisp instead.
                            (re:cmd \"\") answers the full manual of command families.
  (re:json \"aflj\")          the same, for a *j command, answering the data itself: arrays as
                            vectors, objects as hash tables, read with (gethash \"name\" f). It
                            reads the whole output even past the size cap, and its second
                            value is the evidence id.
  (re:call \"tool\" :key v)   every other tool: annotations (rename_function, set_comment,
                            set_prototype, ...), record_finding, retract_finding, rizin_help,
                            rizin_cli, rizin_emulate, analyze, apply_signatures, map_file,
                            export_project. :max-depth spells max_depth; false is :false; an
                            array is a list.
  Reads composed for you — plain functions over (re:cmd), each line naming the evidence id it
  rests on, so what they show can be cited:
  (re:triage)               identity, build protections, sections with entropy, notable imports
                            and strings, the largest functions, entry points. Start here.
  (re:scan-imports)         imports a reviewer stops at, why, and who calls them; what the
                            program can reach, by what it links.
  (re:inspect-function \"main\")   one function's shape, variables, callers, callees, strings.
  (re:find-comparisons \"main\")   what it compares and which way each branch goes.
  (re:find-crypto)          cryptographic constants and key material, with what refers to them.
  (re:tools)                the tools, one line each.   (re:doc \"tool\")  one tool's arguments.
  (re:slash \"functions\")    a /re line: functions, strings, imports, evidence [id], cite <id>,
                            findings [id], undo, verify [--strict], report [path], carry <manifest>.
  (re:status)               rizin, the open binary, evidence and findings so far.
How a result reads: its first line is a header (rizin> <cmd>); a command that observes the
binary ends with a line [evidence xxxxxxxx — cite it in record_finding]; a *j command's lines
in between are JSON. Output cut by the size cap says so and names the file holding the rest.
How to work: open, then triage wide before reading deep — (re:cmd \"iIj\") the header,
(re:cmd \"iij\") imports, (re:cmd \"izj\") strings, (re:cmd \"aflj\") functions — then decompile
what the triage points at with pdg, follow references with axtj, and annotate what you learn
(rename_function, set_comment), which the engine replays if rizin restarts. State a conclusion
only with (re:call \"record_finding\" :claim \"...\" :evidence '(\"xxxxxxxx\") :confidence \"confirmed\"):
a finding must cite evidence ids from results you actually saw, and (re:slash \"report out.md\")
refuses to write a claim with none. Say what the evidence shows, not what the sample probably is.
Compose in Lisp: a helper you define in eval stays, so a loop over the ten largest functions or
a filter over strings is a defun away. A slow call yields to the background like any eval.
Safety: every verb above reads or annotates; none runs the sample. Dynamic analysis
(rizin_debug) exists only when the operator set debugger true, and it executes the binary on
this machine: use it only when they asked, never on untrusted samples outside a sandbox.
The operator has the same lines as /re: /re open <path>, /re status, /re report."
  "What (help :re) answers while the cell runs: the omp plugin's re-triage
skill, in the cell's voice.")

;;; --- the operator's command ----------------------------------------------------------

(defun run-slash (&optional args session-id)
  "One /re invocation: the engine's own /re line for the session it was
typed in, `help' when typed alone."
  (handler-case
      (let* ((line (trimmed args))
             (session-id (if (and (stringp session-id) (plusp (length session-id))) session-id "default"))
             (words (words line)))
        (values
         (run-slash-line
          (find-session session-id)
          ;; A path typed after `open' reads against the session's directory, as (re:open) reads it.
          (if (and (string-equal (first words) "open") (rest words))
              (format nil "open ~a"
                      (session-path (trimmed (subseq line (length (first words)))) session-id))
              (if (plusp (length line)) line "help")))))
    (re-error (condition)
      (format nil "re: ~a" condition))))

;;; --- start ---------------------------------------------------------------------------

(defun start ()
  "Nothing runs until a binary is opened: a home that never reverses one
never starts rizin. What start owes is the way back — every session's
process closed on stop — and a worker that closes the rizin of a session
nothing has called for idle_minutes, which loses nothing: the session's
record is on disk and its next call restores it."
  (setf *state-directory*
        (lambda ()
          (let ((named (trimmed (and *re* (setting :state-dir)))))
            (if (plusp (length named)) (nlk:expand-home named) (nlk:home "omp-re/"))))
        ;; Read through *RE*, not SETTING: a stopped cell answers "unset", it does not refuse.
        *configured-rizin* (lambda () (and *re* (setting :rizin-path)))
        *debugger-setting* (lambda () (and *re* (setting :debugger)))
        *allowed-directories* (lambda () (and *re* (setting :allowed-dirs))))
  (nle:on-stop #'shutdown-sessions)
  (let* ((idle (* 60 (setting :idle-minutes)))
         (worker (nlk:worker-start "nodecode-re idle sessions"
                                   (lambda () (reap-idle-sessions idle))
                                   :wake 60)))
    (nle:on-stop (lambda () (nlk:worker-stop worker)))))

(nle:define-cell re
  (:section ("re")
    (:guide "install rizin (https://rizin.re); nothing else is required. (re:status) says what the engine found")
    ("rizin_path" :string :default ""
     :doc "the rizin to run when it is not the one on PATH (the engine's OMPRE_RIZIN_PATH)")
    ("state_dir" :string :default ""
     :doc "where session records, evidence, the audit log and reports are kept; omp-re/ under the home when empty")
    ("allowed_dirs" :list :default '()
     :doc "directories binaries and other input files may be opened from; empty allows any file the organism can read")
    ("debugger" :boolean :default nil
     :doc "offer rizin_debug, which EXECUTES the binary under analysis on this machine; leave off outside a sandbox")
    ("idle_minutes" :integer :default 30 :min 1
     :doc "close the rizin process of a session unused this long; its next call restores it"))
  (:help :re
         "re: reverse engineering with rizin - (re:open \"path\"), (re:cmd \"aflj\"), evidence-backed findings - (help :re)"
         +primer+)
  (:command "re" 'run-slash
            :description "Reverse engineering with rizin: open <path>, status, functions, findings, report")
  (:start #'start))
