;;;; engine.lisp --- the engine as a host sees it.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; These functions are the whole surface a host builds on, each answering
;;;; plain JSON data (objects as OBJ makes them, arrays as vectors), so a host
;;;; in this image reads them directly and one across a pipe writes them out:
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
;;;;   (engine-preserved SESSION)            lines to keep through a compaction
;;;;   (engine-approval SESSION CALL-ID TOOL APPROVED REASON)
;;;;                                         what the host's gate decided of a call
;;;;   (engine-restore SESSION &key open)    bring rizin up when a session starts
;;;;   (engine-rekey FROM TO)                a session goes on under a new id
;;;;   (engine-close SESSION)                a session is over
;;;;
;;;; SESSION is the host's id for the session, a string. None of them
;;;; signals: a failure is an answer with "failed" true and the reason as
;;;; its text. What the engine in turn asks of the host is in host.lisp.

(in-package #:omp-re)

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

(defun engine-call (session name arguments &key call-id)
  "Call the tool NAME with the JSON object ARGUMENTS in SESSION =>
  {text, failed, raw?, evidenceId?, artifactPath?, details?}
TEXT is what the model reads. RAW is the whole of what rizin printed, for a
tool that reads the binary, where TEXT may be cut; EVIDENCE-ID the id of the
evidence record the call left; ARTIFACT-PATH where all of a TEXT that was
cut is kept. DETAILS is the result's own, for a host that renders more than
text: {ea?, truncated?, artifactId?, artifactPath?, commands?, reproHash?,
canonicalExcerpt?, shiftHash?}. A call refused before its tool ran has none.
CALL-ID is the host's own id for the call, written to the audit log."
  (multiple-value-bind (text failed raw evidence-id artifact-path details)
      (call-tool session name arguments :call-id call-id)
    (obj "text" text
         "failed" (and failed t)
         "raw" (if (stringp raw) raw :absent)
         "evidenceId" (or evidence-id :absent)
         "artifactPath" (or artifact-path :absent)
         "details" (or details :absent))))

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
              "view" (if (member (slash-name slash) +list-views+ :test #'string=) t :absent)
              "completes" (if (slash-completes slash) (string-downcase (slash-completes slash)) :absent)
              "row" (if (slash-row slash)
                        (destructuring-bind (position label &key detail ask placeholder verb)
                            (slash-row slash)
                          (obj "position" position "label" label
                               "detail" (or detail :absent) "ask" (or ask :absent)
                               "placeholder" (or placeholder :absent) "verb" (or verb :absent)))
                        :absent)))
       *slash-commands*))

(defun engine-command (session line &key by-model)
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

(defun engine-view (session kind &optional argument)
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

(defun engine-facts (session)
  "The facts of SESSION's open binary, for a status band (views.lisp,
SESSION-FACTS) — as the session stands: a call that holds it is not waited
for, and no rizin is started. NIL when they could not be had."
  (multiple-value-bind (answer failed) (in-session (session "the status band" :wait nil)
                                         (session-facts))
    (and (not failed) answer)))

(defun engine-preserved (session)
  "The lines to fold into a summary of SESSION's conversation when the host
compacts it => a vector of strings, empty when there is nothing to keep."
  (multiple-value-bind (answer failed) (in-session (session "the compaction summary")
                                         (coerce (preserved-lines) 'simple-vector))
    (if failed (vector) answer)))

(defun engine-approval (session call-id tool approved &optional reason)
  "Write to SESSION's audit log what the host's approval gate decided of the
call CALL-ID to TOOL. A call that was denied never reaches ENGINE-CALL, so
this line is all the log has of it."
  (in-session (session "the audit log" :wait nil)
    (append-audit-line *session* call-id tool :approved approved :reason reason)
    nil)
  t)

(defun engine-restore (session &key open)
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

(defun engine-rekey (from to)
  "The session FROM goes on as TO, its rizin with it."
  (rekey-session from to)
  t)

(defun engine-close (session)
  "SESSION is over: end what runs for it. Its record stays."
  (close-session session))
