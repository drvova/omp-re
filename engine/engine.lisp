;;;; engine.lisp --- the engine as a host sees it.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Four functions are the whole surface a host builds on, each answering
;;;; plain JSON data (objects as OBJ makes them, arrays as vectors), so a host
;;;; in this image reads them directly and one across a pipe writes them out:
;;;;
;;;;   (engine-tools)                        what tools there are
;;;;   (engine-call SESSION NAME ARGUMENTS)  call one
;;;;   (engine-commands)                     what /re subcommands there are
;;;;   (engine-command SESSION LINE &key by-model)   run one /re line
;;;;
;;;; SESSION is the host's id for the session, a string. Neither call
;;;; signals: a failure is an answer with "failed" true and the reason as
;;;; its text. What the engine in turn asks of the host is in host.lisp.

(in-package #:omp-re)

(defun engine-tools ()
  "The tools offered now, in the order defined => a vector of
  {name, label, description, parameters, approval, evidence}
PARAMETERS is the tool's arguments as JSON Schema; APPROVAL one of \"read\",
\"write\" and \"exec\" — whether it observes, annotates, or runs code and
writes files; EVIDENCE whether a successful result is recorded as evidence.
A tool can come and go (rizin_debug with the debugger setting), so a host
asks again rather than keeping the answer."
  (map 'vector
       (lambda (tool)
         (obj "name" (tool-name tool)
              "label" (or (tool-label tool) :absent)
              "description" (tool-description tool)
              "parameters" (tool-schema tool)
              "approval" (string-downcase (tool-tier tool))
              "evidence" (and (tool-evidence tool) t)))
       (offered-tools)))

(defun engine-call (session name arguments)
  "Call the tool NAME with the JSON object ARGUMENTS in SESSION =>
  {text, failed, raw?, evidenceId?, artifactPath?, details?}
TEXT is what the model reads. RAW is the whole of what rizin printed, for a
tool that reads the binary, where TEXT may be cut; EVIDENCE-ID the id of the
evidence record the call left; ARTIFACT-PATH where all of a TEXT that was
cut is kept. DETAILS is the result's own, for a host that renders more than
text: {ea?, truncated?, artifactId?, artifactPath?, commands?, reproHash?,
canonicalExcerpt?, shiftHash?}. A call refused before its tool ran has none."
  (multiple-value-bind (text failed raw evidence-id artifact-path details)
      (call-tool session name arguments)
    (obj "text" text
         "failed" (and failed t)
         "raw" (if (stringp raw) raw :absent)
         "evidenceId" (or evidence-id :absent)
         "artifactPath" (or artifact-path :absent)
         "details" (or details :absent))))

(defun engine-commands ()
  "The /re subcommands, in the order /re help lists them => a vector of
  {name, usage?, description, row?}
ROW, where the subcommand has one, is its row in a dialog of what /re
offers, for a host that draws one: {position, label, detail?, ask?,
placeholder?, verb?}. A row with ASK asks for a word under that label —
PLACEHOLDER in the empty box, VERB on the button — and runs the subcommand
with it; any other runs the subcommand as it is. Rows are shown by POSITION."
  (map 'vector
       (lambda (slash)
         (obj "name" (slash-name slash)
              "usage" (or (slash-usage slash) :absent)
              "description" (slash-description slash)
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
