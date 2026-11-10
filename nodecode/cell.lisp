;;;; cell.lisp --- the primer, the /re command, the declaration.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Config, a sibling top-level key of ~/.nodecode/config.jsonc:
;;;;   "re": {"rizin_path": "", "state_dir": "omp-re/",
;;;;          "allowed_dirs": [], "debugger": false, "idle_minutes": 30,
;;;;          "audit": true, "audit_seconds": 120}
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
refuses to write a claim with none. The claim is then checked by a support auditor and refused,
with the reason, if the evidence doesn't establish it or it claims more than the evidence shows:
narrow the claim to what the evidence shows or cite evidence that establishes it. Only if the
auditor is wrong, pass :override-audit with a one-line justification, recorded and shown beside
the finding. Say what the evidence shows, not what the sample probably is.
Compose in Lisp: a helper you define in eval stays, so a loop over the ten largest functions or
a filter over strings is a defun away. A slow call yields to the background like any eval.
Safety: every verb above reads or annotates; none runs the sample. Dynamic analysis
(rizin_debug) exists only when the operator set debugger true, and it executes the binary on
this machine: use it only when they asked, never on untrusted samples outside a sandbox.
The operator has the same lines as /re: /re open <path>, /re status, /re report."
  "What (help :re) answers while the cell runs: the omp plugin's re-triage
skill, in the cell's voice.")

;;; --- the operator's command ----------------------------------------------------------

(defun re-dialog ()
  "What /re offers typed alone: a row a thing it does. A command is its name
— nobody types after it — so the lines that need a word ask for it."
  (nle:list-dialog
   :title "Reverse engineering"
   :summary "rizin, with every read recorded as evidence"
   :rows (list (nle:ask-row "Open a binary" "Path" "/re open" :placeholder "/path/to/binary" :verb "open")
               (nle:run-row "Status" "/re status" :detail "rizin, the open binary, evidence and findings")
               (nle:run-row "Functions" "/re functions")
               (nle:run-row "Strings" "/re strings")
               (nle:run-row "Imports" "/re imports")
               (nle:run-row "Evidence" "/re evidence" :detail "what has been observed on this branch")
               (nle:ask-row "Cite evidence" "Evidence id" "/re cite" :placeholder "1a2b3c4d" :verb "cite")
               (nle:run-row "Findings" "/re findings" :detail "the conclusions recorded, each on its evidence")
               (nle:run-row "Verify" "/re verify" :detail "re-run the evidence and compare")
               (nle:ask-row "Write the report" "File" "/re report" :placeholder "analysis.md" :verb "write")
               (nle:run-row "Undo the last annotation" "/re undo")
               (nle:run-row "Turn the tools off" "/re off")
               (nle:run-row "Turn the tools on" "/re on")
               (nle:run-row "Help" "/re help"))))

(defun run-slash (&optional args session-id)
  "One /re invocation for the session it was typed in: typed alone, the
dialog of what it offers; with a line, the engine's /re answer, and — where
the caller has an input box — the draft a line such as `cite' leaves in it."
  (if (nle:bare-args-p args)
      (values "Reverse engineering with rizin" (re-dialog))
      (handler-case
          (let* ((line (trimmed args))
                 (session-id (if (and (stringp session-id) (plusp (length session-id))) session-id "default"))
                 (words (words line))
                 (*offered-draft* (if (member :draft nle:*slash-effects*) nil :unbound))
                 (text (values
                        (run-slash-line
                         (find-session session-id)
                         ;; A path typed after `open' reads against the session's directory, as (re:open) reads it.
                         (if (and (string-equal (first words) "open") (rest words))
                             (format nil "open ~a"
                                     (session-path (trimmed (subseq line (length (first words)))) session-id))
                             line)))))
            (if (stringp *offered-draft*)
                (values text nil (list (list :draft *offered-draft*)))
                text))
        (re-error (condition)
          (format nil "re: ~a" condition)))))

;;; --- the support auditor ---------------------------------------------------------------
;;; audit-claims.lisp asks *CLAIM-JUDGE* one question and reads the reply.
;;; Here the question goes to the model the way nodecode's cell API says a
;;; side question is asked: NLE:SUBMIT to a session of the cell's own, with
;;; no tool the turn may call. omp's judge is a turn with no history, so the
;;; session is not a fork: it hangs under the session that asked as a
;;; detached child, which composes none of its history, runs on its model,
;;; and goes when it is deleted.

(defparameter +audit-source+ "re-audit"
  "The source kind of the turns the auditor starts: what the session list
and a prune by source know them by.")

(defparameter +audit-title+ "re: support audit"
  "What an audit's session is called, so no model is asked to name it.")

(defparameter *audit-poll-seconds* 1/4
  "How often a waiting audit asks whether its turn has ended.")

(defvar *audit-turns* '()
  "The audit turns not yet ended, each (SESSION-ID . TURN-ID): what stop asks to stop.")

(defvar *audit-lock* (sb-thread:make-mutex :name "omp-re audits"))

(defun one-line-clip (text)
  "TEXT as part of a one-line reason: its first line, 200 characters at most."
  (let ((line (trimmed (or (first (split-lines (or text ""))) ""))))
    (subseq line 0 (min 200 (length line)))))

(defun audit-terminal-detail (turn kind member)
  "What the terminal fact of KIND says of TURN in MEMBER, or NIL."
  (let ((payload (ignore-errors (nlk:events :turn-id turn :kind kind :as :payload))))
    (and (hash-table-p payload)
         (stringp (gethash member payload))
         (plusp (length (one-line-clip (gethash member payload))))
         (one-line-clip (gethash member payload)))))

(defun await-audit-turn (child turn seconds settings)
  "Wait on the calling thread for TURN of the session CHILD to end
=> its terminal kind, :TIMEOUT once SECONDS have passed, or :STOPPED when
the cell that asked is no longer the one running (SETTINGS is its section).
A turn left open is asked to stop: nothing waits on it after this returns."
  (let ((entry (cons child turn))
        (deadline (+ (get-internal-real-time) (* seconds internal-time-units-per-second))))
    (sb-thread:with-mutex (*audit-lock*) (push entry *audit-turns*))
    (unwind-protect
         (loop
           (let ((kind (nlk:turn-terminal-kind turn)))
             (cond (kind (return kind))
                   ((not (eq *re* settings))
                    (ignore-errors
                     (nlk:request-cancel-turn child turn "the nodecode-re cell stopped"))
                    (return :stopped))
                   ((>= (get-internal-real-time) deadline)
                    (ignore-errors
                     (nlk:request-cancel-turn child turn "the support audit ran past audit_seconds"))
                    (return :timeout))
                   (t (sleep *audit-poll-seconds*)))))
      (sb-thread:with-mutex (*audit-lock*)
        (setf *audit-turns* (remove entry *audit-turns*))))))

(defun stop-audits ()
  "Ask every audit turn still open to stop. Its waiter sees the cell gone
and returns by itself."
  (dolist (entry (sb-thread:with-mutex (*audit-lock*) (copy-list *audit-turns*)))
    (ignore-errors (nlk:request-cancel-turn (car entry) (cdr entry) "the nodecode-re cell stopped"))))

(defun ask-judge (prompt)
  "Put PROMPT to the model as a side question and answer its reply
=> the text, or (values NIL REASON) when it could not be had; a NIL with no
reason is a host with nobody to ask. Never signals and never outlasts
audit_seconds.

The wait is on the calling thread, which is safe only where that thread is
a turn's own: a verb inside eval, which yields a long form to the
background by itself. A /re line the operator typed runs where the gateway
answers commands, and that thread must not sit through a model turn — so
there the question is not asked, and the report says its claims went
unaudited and how to have them audited."
  (let ((settings *re*)
        (origin (getf (nle:turn) :session-id)))
    (cond ((not (and settings (setting :audit))) nil)
          ((not (nlk:store-open-p)) nil)
          ((null (nle:turn))
           (values nil "a /re line typed as a command does not wait for the audit's side question; (re:slash \"report\") from eval asks it"))
          (t
           (handler-case
               (let* ((seconds (setting :audit-seconds))
                      (parent (and (stringp origin) (ignore-errors (nlk:session-exists-p origin)) origin))
                      (directory (and parent (ignore-errors (nlk:find-session-cwd parent))))
                      (child (nlk:durable-session-id
                              (if parent
                                  (nlk:create-session :parent parent :detached t
                                                      :cwd (if (pathnamep directory)
                                                               (native directory)
                                                               directory))
                                  (nlk:create-session))))
                      (turn (progn
                              ;; Named before its first prompt, or the gateway asks a model to name it.
                              (ignore-errors (nle:set-session-title child +audit-title+))
                              (nlk:active-input-admission-turn-id
                               (nle:submit child prompt :tools '() :source +audit-source+
                                                        :source-id parent)))))
                 (if (null turn)
                     (values nil "the audit side turn was not started")
                     (let ((kind (await-audit-turn child turn seconds settings)))
                       (cond ((eq kind :timeout)
                              (values nil (format nil "the audit side turn did not end within audit_seconds (~d s)" seconds)))
                             ((eq kind :stopped)
                              (values nil "the nodecode-re cell stopped before the audit side turn ended"))
                             ((equal kind "turn.completed")
                              (let ((answer (nlk:turn-answer child turn)))
                                (if (and (stringp answer) (not (blank-p answer)))
                                    answer
                                    (values nil "the audit side turn ended without an answer"))))
                             ((equal kind "turn.failed")
                              (values nil (format nil "the audit side turn failed~@[: ~a~]"
                                                  (audit-terminal-detail turn kind "detail"))))
                             ((equal kind "turn.cancelled")
                              (values nil (format nil "the audit side turn was cancelled~@[: ~a~]"
                                                  (audit-terminal-detail turn kind "reason"))))
                             (t (values nil (format nil "the audit side turn ended as ~a" kind)))))))
             (error (condition)
               (values nil (format nil "the audit side turn could not be asked: ~a"
                                   (one-line-clip (princ-to-string condition))))))))))

;;; --- start ---------------------------------------------------------------------------

(defun start ()
  "Nothing runs until a binary is opened: a home that never reverses one
never starts rizin. What start owes is the way back — every session's
process closed on stop — and a worker that closes the rizin of a session
nothing has called for idle_minutes, which loses nothing: the session's
record is on disk and its next call restores it."
  (setf *state-directory*
        (lambda ()
          ;; A :directory value may arrive as a string or a pathname, home-
          ;; relative or expanded; all of them end up under the home.
          (let* ((value (and *re* (setting :state-dir)))
                 (named (trimmed (if (pathnamep value) (native value) value))))
            (if (plusp (length named))
                (merge-pathnames (uiop:ensure-directory-pathname (nlk:expand-home named)) (nlk:home))
                (nlk:home "omp-re/"))))
        ;; Read through *RE*, not SETTING: a stopped cell answers "unset", it does not refuse.
        *configured-rizin* (lambda ()
                             (let ((value (and *re* (setting :rizin-path))))
                               (if (pathnamep value) (native value) value)))
        *debugger-setting* (lambda () (and *re* (setting :debugger)))
        *allowed-directories* (lambda () (and *re* (setting :allowed-dirs)))
        *current-turn* (lambda () (getf (nle:turn) :turn-id))
        ;; Which turns are on a session's branch, across its fork lineage:
        ;; what makes evidence and annotations follow /tree, /redo and /fork.
        *branch-view* (lambda (session-id)
                        (when (nlk:store-open-p)
                          (values (nlk:session-visible-turn-set session-id)
                                  (nlk:session-lineage session-id))))
        ;; What lasts is a keyed notice: it stands in /cells and at the tail
        ;; of the model's prompt until it is replaced or the cell stops.
        *notify* (lambda (text &key (level :warning))
                   (nle:notice text :level level :key "nodecode-re"))
        ;; Who answers the support audit's question (audit-claims.lisp).
        *claim-judge* #'ask-judge)
  (nle:on-stop (lambda () (nle:notice nil :key "nodecode-re")))
  (nle:on-stop (lambda ()
                 (setf *claim-judge* nil)
                 (stop-audits)))
  (nle:on-stop #'shutdown-sessions)
  (let* ((idle (* 60 (setting :idle-minutes)))
         (worker (nlk:worker-start "nodecode-re idle sessions"
                                   (lambda () (reap-idle-sessions idle))
                                   :wake 60)))
    (nle:on-stop (lambda () (nlk:worker-stop worker)))))

(nle:define-cell re
  (:section ("re")
    (:guide "install rizin (https://rizin.re); nothing else is required. (re:status) says what the engine found")
    ("rizin_path" :path :default ""
     :doc "the rizin to run when it is not the one on PATH (the engine's OMPRE_RIZIN_PATH)")
    ("state_dir" :directory :default "omp-re/"
     :doc "where session records, evidence, the audit log and reports are kept; a relative folder is under the home")
    ("allowed_dirs" :list :default '()
     :doc "directories binaries and other input files may be opened from; empty allows any file the organism can read")
    ("debugger" :boolean :default nil
     :doc "offer rizin_debug, which EXECUTES the binary under analysis on this machine; leave off outside a sandbox")
    ("idle_minutes" :integer :default 30 :min 1
     :doc "close the rizin process of a session unused this long; its next call restores it")
    ("audit" :boolean :default t
     :doc "ask the model, in a side question that costs tokens, whether a finding's or a report claim's evidence supports it; off records them unaudited")
    ("audit_seconds" :integer :default 120 :min 1
     :doc "how long a support audit waits for its answer before the claim goes unaudited"))
  (:help :re
         "re: reverse engineering with rizin - (re:open \"path\"), (re:cmd \"aflj\"), evidence-backed findings - (help :re)"
         +primer+)
  (:command "re" 'run-slash
            :description "Reverse engineering with rizin: open <path>, status, functions, findings, report")
  (:start #'start))
