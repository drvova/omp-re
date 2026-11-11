;;;; cell.lisp --- the primer, the /re command, the declaration.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The nodecode host: what the engine's port (host.lisp) asks, answered by
;;;; the organism, installed at start and taken back at stop. The `re'
;;;; section of ~/.nodecode/config.jsonc is declared from the engine's own
;;;; table of settings (host.lisp, +SETTINGS+; config.example.jsonc shows
;;;; it). A vetoed section ("enabled": false) installs nothing. There is no
;;;; secret in it: the audit log's signing key stays the engine's own
;;;; environment variable, OMPRE_AUDIT_HMAC_KEY.

(in-package #:omp-re)

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
  "What /re offers typed alone: a row a thing it does, as the subcommands
declare them. A command is its name — nobody types after it — so the lines
that need a word ask for it."
  (nle:list-dialog
   :title "Reverse engineering"
   :summary "rizin, with every read recorded as evidence"
   :rows (loop for command in (sort (remove-if-not (lambda (command) (jget command "row"))
                                                   (coerce (engine-commands) 'list))
                                    #'< :key (lambda (command) (jget command "row" "position")))
               for row = (jget command "row")
               for line = (format nil "/re ~a" (jstring command "name"))
               collect (if (jstring row "ask")
                           (nle:ask-row (jstring row "label") (jstring row "ask") line
                                        :placeholder (jstring row "placeholder")
                                        :verb (jstring row "verb"))
                           (apply #'nle:run-row (jstring row "label") line
                                  (and (jstring row "detail") (list :detail (jstring row "detail"))))))))

(defun run-slash (&optional args session-id)
  "One /re invocation for the session it was typed in: typed alone, the
dialog of what it offers; with a line, the engine's answer, and — where the
caller has an input box and the line offers a draft — the draft put in it."
  (if (nle:bare-args-p args)
      (values "Reverse engineering with rizin" (re-dialog))
      (let* ((answer (engine-command (if (and (stringp session-id) (plusp (length session-id)))
                                         session-id
                                         +default-session+)
                                     args))
             (draft (jget answer "draft")))
        (if (and draft (member :draft nle:*slash-effects*))
            (values (jstring draft "notice") nil (list (list :draft (jstring draft "text"))))
            (jstring answer "text")))))

;;; --- the support auditor ---------------------------------------------------------------
;;; The engine's claim audit asks its host one question (the port's :JUDGE)
;;; and reads the reply. Here the question goes to the model the way nodecode's cell API says a
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
    (cond ((not (and settings (setting-value :audit))) nil)
          ((not (nlk:store-open-p)) nil)
          ((null (nle:turn))
           (values nil "a /re line typed as a command does not wait for the audit's side question; (re:slash \"report\") from eval asks it"))
          (t
           (handler-case
               (let* ((seconds (setting-value :audit-seconds))
                      (parent (and (stringp origin) (ignore-errors (nlk:session-exists-p origin)) origin))
                      (directory (and parent (ignore-errors (nlk:find-session-cwd parent))))
                      (child (nlk:durable-session-id
                              (if parent
                                  (nlk:create-session :parent parent :detached t
                                                      :cwd (if (pathnamep directory)
                                                               (uiop:native-namestring directory)
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
never starts rizin. What start owes is the way back — the port cleared and
every session's process closed on stop — and the worker that closes the
rizin of a session nothing has called for idle_minutes, which loses nothing:
the session's record is on disk and its next call restores it."
  (install-host
   ;; Read through *RE*, not SETTING: a stopping cell answers "unset", it does not refuse.
   :setting (lambda (name) (if *re* (values (setting name) t) (values nil nil)))
   :home (lambda () (nlk:home))
   :turn #'nle:turn
   ;; A session nodecode does not know — the one a call outside any turn is
   ;; for — has no directory, and its paths are read as written.
   :directory (lambda (session-id) (ignore-errors (nlk:find-session-cwd session-id)))
   :entries #'branch-entries
   :append-entry #'turn-stamped-append
   ;; What lasts is a keyed notice: it stands in /cells and at the tail of
   ;; the model's prompt until it is replaced or the cell stops. A notice
   ;; has one level here, whatever the engine's.
   :notify (lambda (text level)
             (declare (ignore level))
             (nle:notice text :level :warning :key "nodecode-re"))
   :judge #'ask-judge)
  (nle:on-stop (lambda () (nle:notice nil :key "nodecode-re")))
  (nle:on-stop #'clear-host)
  (nle:on-stop #'stop-audits)
  (nle:on-stop #'shutdown-sessions)
  (nle:on-stop (start-idle-reaper)))

(macrolet ((declare-cell ()
             `(nle:define-cell re
                (:section ("re")
                  (:guide "install rizin (https://rizin.re); nothing else is required. (re:status) says what the engine found")
                  ,@(section-fields))
                (:help :re
                       "re: reverse engineering with rizin - (re:open \"path\"), (re:cmd \"aflj\"), evidence-backed findings - (help :re)"
                       +primer+)
                (:command "re" 'run-slash
                          :description "Reverse engineering with rizin: open <path>, status, functions, findings, report")
                (:start #'start))))
  (declare-cell))
