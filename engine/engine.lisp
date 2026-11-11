;;;; engine.lisp --- the engine as a host sees it.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; These functions are the surface a host builds on (engine/package.lisp
;;;; exports them, with the port of host.lisp), each answering plain JSON
;;;; data (objects as OBJ makes them, arrays as vectors), so a host in this
;;;; image reads them directly and one across a pipe writes them out:
;;;;
;;;;   (engine-tools)                        what tools there are
;;;;   (engine-call SESSION NAME ARGUMENTS)  call one
;;;;   (engine-commands)                     what /re subcommands there are
;;;;   (engine-command SESSION LINE &key by-model)   run one /re line
;;;;
;;;; and, for a host with a screen and a session it starts, moves and ends:
;;;;
;;;;   (engine-view SESSION KIND ARGUMENT)   a list to pick from, a function's code
;;;;   (engine-facts SESSION)                the open binary, for a status band
;;;;   (engine-evidence SESSION LIMIT)       the newest evidence, to complete an id from
;;;;   (engine-preserved SESSION)            lines to keep through a compaction
;;;;   (engine-memory SESSION)               what no record holds: `/re off'
;;;;   (engine-remember SESSION MEMORY)      give it back under a new engine
;;;;   (engine-approval SESSION CALL-ID TOOL APPROVED REASON)
;;;;                                         what the host's gate decided of a call
;;;;   (engine-restore SESSION &key open)    bring rizin up when a session starts
;;;;   (engine-rekey FROM TO)                a session goes on under a new id
;;;;   (engine-close SESSION)                a session is over
;;;;   (engine-hold SESSION THUNK)           several of the above as one sequence
;;;;
;;;; SESSION is the host's id for the session, a string. None of them
;;;; signals, but ENGINE-HOLD: a failure is an answer with "failed" true and
;;;; the reason as its text. What the engine in turn asks of the host is in
;;;; host.lisp.
;;;;
;;;; Each is declared in the types of types.lisp. Those that never signal
;;;; are made by DEFINE-SURFACE, which keeps that promise for an argument of
;;;; the wrong type too.

(in-package #:omp-re)

(defun mistyped-argument (function parameter type value)
  (let ((*package* (find-package '#:omp-re))
        (shown (prin1-to-string value)))
    (format nil "omp-re: ~(~a~): ~(~a~) must be of type ~(~s~), not ~a"
            function parameter type
            (if (< 80 (length shown)) (format nil "~a..." (subseq shown 0 77)) shown))))

(defmacro define-surface (name (&rest parameters) (result mistyped) &body body)
  "Define NAME, a function of the surface that never signals. PARAMETERS is
a lambda list in which every variable is (VARIABLE TYPE), or after &OPTIONAL
and &KEY (VARIABLE TYPE [DEFAULT]); RESULT is the type of its value. That
type is proclaimed, so a host's calls are held to it when the host is
compiled. A call that arrives all the same with an argument of another type
is answered, not signalled: MISTYPED, a function of what is wrong in the
engine's words, gives the answer.

This is why NAME is not a DEFUN. SBCL holds a DEFUN to its proclaimed type
on entry, before anything of the function has run, and the caller would get
a TYPE-ERROR where the surface promises an answer. The function installed
here takes anything and checks for itself."
  (let ((kind nil) (lambda-list '()) (types '()) (checks '())
        (text (gensym "TEXT")))
    (dolist (parameter parameters)
      (if (member parameter '(&optional &key))
          (progn (setf kind parameter)
                 (push parameter lambda-list)
                 (push parameter types))
          (destructuring-bind (variable type &optional default) parameter
            (push (if kind (list variable default) variable) lambda-list)
            (push (if (eq kind '&key) (list (intern (symbol-name variable) '#:keyword) type) type) types)
            (push `((not (typep ,variable ',type))
                    (mistyped-argument ',name ',variable ',type ,variable))
                  checks))))
    (multiple-value-bind (documentation body)
        (if (stringp (first body)) (values (first body) (rest body)) (values nil body))
      `(progn
         (declaim (ftype (function ,(reverse types) (values ,result &optional)) ,name))
         (setf (fdefinition ',name)
               (lambda ,(reverse lambda-list)
                 (let ((,text (cond ,@(reverse checks))))
                   (if ,text
                       (funcall ,mistyped ,text)
                       (progn ,@body)))))
         (setf (documentation ',name 'function) ,documentation)
         ',name))))

(declaim (ftype (function () (values json-array &optional)) engine-tools))
(defun engine-tools ()
  "The tools offered now, in the order defined => a vector of
  {name, label, description, parameters, approval, approvalReason?, render?,
   evidence}
PARAMETERS is the tool's arguments as JSON Schema; APPROVAL one of \"read\",
\"write\" and \"exec\" — whether it observes, annotates, or runs code and
writes files; APPROVAL-REASON what a prompt asking the operator about one
call says, as data a host fills from the call's arguments (call.lisp,
APPROVAL-CASES); RENDER, {title, subject?, body}, how a host that draws
results shows one; EVIDENCE whether a successful result is recorded as
evidence.
A tool can come and go (rizin_debug with the debugger setting), so a host
asks again rather than keeping the answer."
  (map 'vector
       (lambda (tool)
         (obj "name" (tool-name tool)
              "label" (or (tool-label tool) :absent)
              "description" (tool-description-text tool)
              "parameters" (tool-schema tool)
              "approval" (string-downcase (tool-tier tool))
              "approvalReason" (if (tool-reason tool) (approval-cases (tool-reason tool)) :absent)
              "render" (if (tool-render tool)
                           (destructuring-bind (&key title subject (body :text)) (tool-render tool)
                             (obj "title" (or title (tool-label tool) (tool-name tool))
                                  "subject" (or subject :absent)
                                  "body" (string-downcase body)))
                           :absent)
              "evidence" (and (tool-evidence tool) t)))
       (offered-tools)))

(define-surface engine-call ((session session-id) (name string) (arguments (or null json-object))
                             &key (call-id (or null string)))
    (answer (lambda (text) (obj "text" text "failed" t "refused" t)))
  "Call the tool NAME with the JSON object ARGUMENTS in SESSION =>
  {text, failed, refused?, raw?, evidenceId?, artifactPath?, details?}
TEXT is what the model reads. REFUSED is true when the call never came to a
result — the tool is off, unknown or mis-called, the session could not be
had, or its body signalled — as against a result that says it failed. RAW is
the whole of what rizin printed, for a tool that reads the binary, where
TEXT may be cut; EVIDENCE-ID the id of the
evidence record the call left; ARTIFACT-PATH where all of a TEXT that was
cut is kept. DETAILS is the result's own, for a host that renders more than
text: {ea?, truncated?, artifactId?, artifactPath?, commands?, reproHash?,
canonicalExcerpt?, shiftHash?}. A call refused before its tool ran has none.
CALL-ID is the host's own id for the call, written to the audit log."
  (multiple-value-bind (text failed raw evidence-id artifact-path details)
      (call-tool session name arguments :call-id call-id)
    (obj "text" text
         "failed" (and failed t)
         "refused" (if (eq failed :refused) t :absent)
         "raw" (if (stringp raw) raw :absent)
         "evidenceId" (or evidence-id :absent)
         "artifactPath" (or artifact-path :absent)
         "details" (or details :absent))))

(declaim (ftype (function () (values json-array &optional)) engine-commands))
(defun engine-commands ()
  "The /re subcommands, in the order /re help lists them => a vector of
  {name, usage?, description, view?, completes?, row?}
VIEW is true for a subcommand that is also a list a host with a screen may
open instead of printing (ENGINE-VIEW by the same name). COMPLETES is
\"evidence\" where the subcommand's argument is an evidence id, for a host
that completes one as it is typed. ROW, where the
subcommand has one, is its row in a dialog of what /re
offers, for a host that draws one: {position, label, detail?, ask?,
placeholder?, verb?}. A row with ASK asks for a word under that label —
PLACEHOLDER in the empty box, VERB on the button — and runs the subcommand
with it; any other runs the subcommand as it is. Rows are shown by POSITION."
  (map 'vector
       (lambda (slash)
         (obj "name" (slash-name slash)
              "usage" (or (slash-usage slash) :absent)
              "description" (slash-description slash)
              "view" (if (slash-listing slash) t :absent)
              "completes" (if (slash-completes slash) (string-downcase (slash-completes slash)) :absent)
              "row" (if (slash-row slash)
                        (destructuring-bind (position label &key detail ask placeholder verb)
                            (slash-row slash)
                          (obj "position" position "label" label
                               "detail" (or detail :absent) "ask" (or ask :absent)
                               "placeholder" (or placeholder :absent) "verb" (or verb :absent)))
                        :absent)))
       *slash-commands*))

(define-surface engine-command ((session session-id) (line (or null string)) &key (by-model t))
    (answer (lambda (text) (obj "text" text "failed" t "level" "error")))
  "Run one /re LINE — \"status\", \"open /bin/ls\" — in SESSION =>
  {text, failed, level, draft?, userMessage?}
BY-MODEL is true where the line comes from the model and not the operator:
`/re off' then refuses it, as it refuses a tool call.
LEVEL is how loudly to say TEXT: \"info\", \"warning\" or \"error\" — error
for a line that failed, unless the line says otherwise. DRAFT, {text,
notice}, is offered by a line such as cite: a host with an input box puts
DRAFT's text in it and shows the notice instead of TEXT; any other host
shows TEXT. USER-MESSAGE is text the line asks to have sent to the model as
the operator's next message."
  (multiple-value-bind (text failed reply) (run-slash-line session line :by-model by-model)
    (destructuring-bind (&key draft level user-message) reply
      (obj "text" text
           "failed" (and failed t)
           "level" (string-downcase (or level (if failed :error :info)))
           "draft" (if draft
                       (obj "text" (draft-text draft) "notice" (draft-notice draft))
                       :absent)
           "userMessage" (or user-message :absent)))))

(define-surface engine-view ((session session-id) (kind string) &optional (argument (or null json-object)))
    (answer (lambda (text) (notice-view :error "~a" text)))
  "What a screen shows for KIND in SESSION => a view (views.lisp): a panel
of rows to pick from, a function's code, or a notice to say instead. KIND is
\"functions\", \"strings\", \"imports\", \"evidence\" or \"findings\", or
one a row or a code view asked for by name with its ARGUMENT. A failure is
a notice at level \"error\"."
  (multiple-value-bind (answer failed) (in-session (session (format nil "the ~a view" kind))
                                         (view kind (or argument (obj))))
    (if failed
        (notice-view :error "~a" answer)
        answer)))

(define-surface engine-facts ((session session-id))
    ((or null json-object) (constantly nil))
  "The facts of SESSION's open binary, for a status band (views.lisp,
SESSION-FACTS) — as the session stands: a call that holds it is not waited
for, rizin is asked nothing and none is started. NIL when they could not be
had."
  (multiple-value-bind (answer failed) (in-session (session "the status band" :wait nil)
                                         (session-facts))
    (and (not failed) answer)))

(define-surface engine-evidence ((session session-id) (limit (integer 0)))
    (json-array (constantly (vector)))
  "The newest LIMIT evidence records of SESSION, newest first => a vector of
[id, \"tool @ address\"], for a host that completes an evidence id as it is
typed. As the session stands, like ENGINE-FACTS; empty when it could not be
read."
  (multiple-value-bind (answer failed)
      (in-session (session "listing evidence" :wait nil)
        (map 'simple-vector
             (lambda (record) (vector (jstring record "id") (evidence-place record)))
             (reverse (last (evidence-records) limit))))
    (if failed (vector) answer)))

(define-surface engine-memory ((session session-id))
    (json-object (lambda (text) (declare (ignore text)) (obj)))
  "What SESSION holds that is in no record, and so would be gone with this
process => a JSON object, {toolsOff?}. A host that outlives the engine keeps
the latest and hands it to ENGINE-REMEMBER when the session meets another
engine. As the session stands, like ENGINE-FACTS."
  (multiple-value-bind (answer failed)
      (in-session (session "the session's memory" :wait nil)
        (obj "toolsOff" (if (session-tools-off *session*) t :absent)))
    (if failed (obj) answer)))

(define-surface engine-remember ((session session-id) (memory json-object))
    ((member t) (constantly t))
  "Give SESSION back what ENGINE-MEMORY answered of it under an engine that
is gone."
  (in-session (session "the session's memory" :wait nil)
    (when (eq t (jget memory "toolsOff"))
      (setf (session-tools-off *session*) t))
    nil)
  t)

(define-surface engine-preserved ((session session-id))
    (json-array (constantly (vector)))
  "The lines to fold into a summary of SESSION's conversation when the host
compacts it => a vector of strings, empty when there is nothing to keep."
  (multiple-value-bind (answer failed) (in-session (session "the compaction summary")
                                         (coerce (preserved-lines) 'simple-vector))
    (if failed (vector) answer)))

(define-surface engine-approval ((session session-id) (call-id (or null string)) (tool (or null string))
                                 (approved t) &optional (reason (or null string)))
    ((member t) (constantly t))
  "Write to SESSION's audit log what the host's approval gate decided of the
call CALL-ID to TOOL. A call that was denied never reaches ENGINE-CALL, so
this line is all the log has of it."
  (in-session (session "the audit log" :wait nil)
    (append-audit-line *session* call-id tool :approved approved :reason reason)
    nil)
  t)

(define-surface engine-restore ((session session-id) &key (open (or null string)))
    (answer (lambda (text) (obj "text" text "failed" t "level" "error")))
  "Bring SESSION's rizin up without waiting to be called: when a session
starts or its branch moved => {text?, failed, level}. OPEN, a path the
operator started the host with, is opened unless the branch already has it
open; otherwise the binary the branch has open is analyzed again when no
process holds it. TEXT is what to tell the operator, when there is
something: a failure, or what would not be put back."
  (multiple-value-bind (text failed level)
      (in-session (session "restoring the session")
        (let ((recorded (session-binary-path *session*)))
          (cond ((and open (not (equal recorded (resolve-binary-path open))))
                 (multiple-value-bind (text failures) (open-binary open)
                   (values (and (plusp failures) text) nil :warning)))
                (recorded
                 (ensure-rizin)
                 (values nil nil :info)))))
    (obj "text" (or text :absent)
         "failed" (and failed t)
         "level" (string-downcase (if failed :error (or level :info))))))

(define-surface engine-rekey ((from session-id) (to session-id))
    ((member t) (constantly t))
  "The session FROM goes on under the id TO, its rizin with it."
  (rekey-session from to)
  t)

(define-surface engine-close ((session session-id))
    ((member t) (constantly t))
  "SESSION is over: end what runs for it. Its record stays."
  (close-session session))

(declaim (ftype (function (session-id function) *) engine-hold))
(defun engine-hold (session thunk)
  "Call THUNK holding SESSION, so the calls it makes for that session are
one sequence no other call cuts into => THUNK's values. What THUNK signals
passes through, and so does the engine's RE-ERROR when the session cannot
be had: the caller gave up while waiting for it, or its record could not be
read."
  (hold-session (find-session session) thunk))
