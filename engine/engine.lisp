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
;;;;   (engine-command SESSION LINE)         run one /re line
;;;;
;;;; Those are all the model has, on every host: its calls and its lines.
;;;; For a host with a screen and a session it starts, moves and ends:
;;;;
;;;;   (engine-view SESSION KIND ARGUMENT)   a list to pick from, a function's code
;;;;   (engine-facts SESSION)                the open binary, for a status band
;;;;   (engine-preserved SESSION)            lines to keep through a compaction
;;;;   (engine-restore SESSION)              bring rizin up when a session starts
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
  {name, description, parameters, evidence}
PARAMETERS is the tool's arguments as JSON Schema; EVIDENCE whether a
successful result is recorded as evidence.
A tool can come and go (rizin_debug with the debugger setting), so a host
asks again rather than keeping the answer."
  (map 'vector
       (lambda (tool)
         (obj "name" (tool-name tool)
              "description" (tool-description-text tool)
              "parameters" (tool-schema tool)
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

(define-surface engine-command ((session session-id) (line (or null string)))
    (answer (lambda (text) (obj "text" text "failed" t)))
  "Run one /re LINE — \"status\", \"report out.md\" — in SESSION =>
  {text, failed}"
  (multiple-value-bind (text failed) (run-slash-line session line)
    (obj "text" text "failed" (and failed t))))

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

(define-surface engine-preserved ((session session-id))
    (json-array (constantly (vector)))
  "The lines to fold into a summary of SESSION's conversation when the host
compacts it => a vector of strings, empty when there is nothing to keep."
  (multiple-value-bind (answer failed) (in-session (session "the compaction summary")
                                         (coerce (preserved-lines) 'simple-vector))
    (if failed (vector) answer)))

(define-surface engine-restore ((session session-id))
    (answer (lambda (text) (obj "text" text "failed" t)))
  "Bring SESSION's rizin up without waiting to be called, when a session
starts or its branch moved: the binary the branch has open is analyzed again
when no process holds it => {text?, failed}. TEXT is why it failed."
  (multiple-value-bind (text failed)
      (in-session (session "restoring the session")
        (when (session-binary-path *session*)
          (ensure-rizin))
        nil)
    (obj "text" (if failed text :absent)
         "failed" (and failed t))))

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
