;;;; call.lisp --- one tool call: what a tool answers, the tools, the audit log.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; CALL-TOOL is the one way a tool runs, whoever asks — a verb in eval, a
;;;; recipe: RUN-TOOL — a line in the audit log, the body, and for a result
;;;; that observes the binary an evidence record whose id is appended to
;;;; what the model reads. A tool or a /re line that makes reads of its own
;;;; (adopt_finding, /re carry --inherit) makes each through RUN-TOOL, so it
;;;; is audited and recorded like any other.

(in-package #:omp-re)

;;; --- what a tool answers -------------------------------------------------------------------

(defstruct (result (:copier nil))
  (text "" :type string)
  ;; A JSON object a host may show beside the text, and what an evidence
  ;; record keeps of the result: ea, truncated, artifactId, artifactPath,
  ;; commands, reproHash, canonicalExcerpt, shiftHash.
  (details (obj))
  (failed nil)
  ;; Whether the text is an observation of the binary. Its body knows: the
  ;; manual rizin_command answers for an empty command is not one.
  (observation t))

(defun plain-result (text &optional ea)
  "A one-off, untruncated result: a mutation, a hash, session setup."
  (make-result :text text :details (obj "ea" (or ea :absent))))

(defun as-failure (result)
  "RESULT marked as a failure: its text is still what the model reads."
  (setf (result-failed result) t)
  result)

(defun failed-result (text &optional ea)
  (as-failure (plain-result text ea)))

(defun artifact-path (id &optional (session *session*))
  (merge-pathnames (format nil "artifacts/~a.txt" (file-safe id)) (session-directory session)))

(defun save-artifact (content label &optional (session *session*))
  "Keep CONTENT whole => (values ID WHERE): the artifact's id, and where a
reader finds it, in the host's words. A host that keeps artifacts keeps this
one; otherwise it is a file beside the session's record. NIL when it could
not be kept: a result then stays truncated, never fails."
  (ignore-errors
   (if (host-service :save-artifact)
       (ask-host :save-artifact session content label)
       ;; An evidence record keeps the id and the record outlives this
       ;; process, so an id is never reused after a restart.
       (let ((id (format nil "~(~36r~)-~d-~a" (get-universal-time) (incf (session-artifacts session))
                         (file-safe label))))
         (write-text-file (artifact-path id session) content)
         (values id (uiop:native-namestring (artifact-path id session)))))))

(defun locate-artifact (id &optional (session *session*))
  "How a reader is told to find the artifact ID: the host's name for it
where the host keeps artifacts, else the file's path."
  (if (host-service :locate-artifact)
      (ask-host :locate-artifact session id)
      (uiop:native-namestring (artifact-path id session))))

(defun read-artifact (id &optional (session *session*))
  (ignore-errors
   (if (host-service :read-artifact)
       (ask-host :read-artifact session id)
       (read-text-file (artifact-path id session)))))

(defvar *running-tool* nil "The name of the tool whose body is running.")

(defun build-result (lead body &key ea commands repro-hash canonical-excerpt shift-hash)
  "LEAD then BODY, cut to what a context can take; the whole text is kept as
an artifact, labelled with the running tool's name, and the result says
where."
  (multiple-value-bind (kept truncated shown-lines total-lines shown-octets total-octets)
      (truncate-head body)
    (multiple-value-bind (artifact where)
        (and truncated *session*
             (save-artifact (concatenate 'string lead body) (or *running-tool* "omp-re")))
      (make-result
       :text (concatenate
              'string lead kept
              (if truncated
                  (format nil "~%~%[Output truncated: ~d of ~d lines (~a of ~a). ~a]"
                          shown-lines total-lines (format-size shown-octets) (format-size total-octets)
                          (if artifact
                              (format nil "Full output: ~a" where)
                              "Full output was larger."))
                  ""))
       :details (obj "ea" (or ea :absent)
                     "truncated" (if truncated t :absent)
                     "artifactId" (or artifact :absent)
                     "artifactPath" (or (and artifact where) :absent)
                     "commands" (if commands (coerce commands 'simple-vector) :absent)
                     "reproHash" (or repro-hash :absent)
                     "canonicalExcerpt" (or canonical-excerpt :absent)
                     "shiftHash" (or shift-hash :absent))))))

(defun text-result (header body &rest keys)
  "Plain-text output — disassembly, decompiled code, a listing — under HEADER."
  (apply #'build-result (format nil "~a~%" header) body keys))

(defun json-result (header data &rest keys)
  "DATA as the real JSON payload under HEADER, not just a count."
  (apply #'build-result (format nil "~a~%" header) (format-json data) keys))

;;; --- tools -----------------------------------------------------------------------------------

(defstruct (tool (:copier nil))
  (name "" :type string)
  (description "")                      ; a string, or a function answering one where a host's voice is in it
  (parameters '())                      ; ((NAME TYPE &key required doc enum properties) ...)
  (function nil)                        ; (lambda (ARGS)) => a RESULT
  (evidence nil)                        ; a successful result is recorded as evidence
  (available nil))                      ; NIL, or a predicate: offered only while it answers true

(defvar *tools* '() "Every engine tool, in the order defined.")

(defun register-engine-tool (tool)
  (setf *tools* (append (remove (tool-name tool) *tools* :key #'tool-name :test #'string=)
                        (list tool)))
  tool)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun parameter-form (parameter)
    "The form that builds PARAMETER as DEFINE-TOOL spells it: its options are
evaluated, and the members of an object are parameters in turn."
    (destructuring-bind (name type &rest options) parameter
      `(list ,name ,type
             ,@(loop for (key value) on options by #'cddr
                     append (list key (if (eq key :properties)
                                          `(list ,@(mapcar #'parameter-form value))
                                          value)))))))

(defmacro define-tool (name (&key description evidence available)
                       parameters (arguments) &body body)
  "Define the engine tool NAME. PARAMETERS is a list of
(\"name\" TYPE &key required doc enum properties) with TYPE one of :string,
:integer, :number, :boolean, :strings (an array of strings), :string-map (an
object whose values are strings), :object and :objects (an object, an array
of objects, whose members PROPERTIES lists the same way); the body runs
with ARGUMENTS bound to the validated JSON object and *SESSION* to the
session, and answers a RESULT. With EVIDENCE a successful result is recorded
as evidence; AVAILABLE, a predicate, offers the tool only while it answers
true."
  `(register-engine-tool
    (make-tool :name ,name :description ,description
               :evidence ,evidence :available ,available
               :parameters (list ,@(mapcar #'parameter-form parameters))
               :function (lambda (,arguments) (declare (ignorable ,arguments)) ,@body))))

(defun tool-offered-p (tool)
  (or (null (tool-available tool)) (funcall (tool-available tool))))

(defun offered-tools ()
  (remove-if-not #'tool-offered-p *tools*))

(defun tool-description-text (tool)
  (let ((description (tool-description tool)))
    (if (functionp description) (funcall description) description)))

(declaim (ftype (function ((or string symbol)) (values string &optional)) engine-name))
(defun engine-name (designator)
  "DESIGNATOR — a string, a keyword, a symbol — as the engine spells a tool,
a parameter or a /re subcommand: lowercase, words joined by underscores. So
:MAX-DEPTH is \"max_depth\" and \"Open-Binary\" is \"open_binary\"."
  (substitute #\_ #\- (string-downcase (string designator))))

(defun find-tool (name)
  (let ((tool (find name *tools* :key #'tool-name :test #'string=)))
    (and tool (tool-offered-p tool) tool)))

(defun members-schema (parameters)
  (let ((properties (obj))
        (required '()))
    (dolist (parameter parameters)
      (setf (gethash (first parameter) properties) (parameter-schema parameter))
      (when (getf (cddr parameter) :required) (push (first parameter) required)))
    (obj "type" "object"
         "properties" properties
         "required" (if required (coerce (nreverse required) 'simple-vector) :absent))))

(defun parameter-schema (parameter)
  (destructuring-bind (name type &key doc enum properties &allow-other-keys) parameter
    (declare (ignore name))
    (let ((schema (ecase type
                    (:string (obj "type" "string"))
                    (:integer (obj "type" "integer"))
                    (:number (obj "type" "number"))
                    (:boolean (obj "type" "boolean"))
                    (:strings (obj "type" "array" "items" (obj "type" "string")))
                    (:string-map (obj "type" "object" "additionalProperties" (obj "type" "string")))
                    (:object (members-schema properties))
                    (:objects (obj "type" "array" "items" (members-schema properties))))))
      (when enum (setf (gethash "enum" schema) (coerce enum 'simple-vector)))
      (when doc (setf (gethash "description" schema) doc))
      schema)))

(defun tool-schema (tool)
  (members-schema (tool-parameters tool)))

(defun check-members (parameters arguments path)
  "ARGUMENTS held to PARAMETERS => (values CHECKED PROBLEMS): a fresh object
of the declared members that were given, and a line for each that does not
fit, named by PATH and its own name."
  (let ((checked (obj)) (problems '()))
    (dolist (parameter parameters)
      (destructuring-bind (name type &key required enum properties &allow-other-keys) parameter
        (multiple-value-bind (value present) (gethash name arguments)
          (let ((present (and present (not (eq value :null))))
                (said (format nil "~a~a" path name)))
            (flet ((members (object)
                     (multiple-value-bind (inner inner-problems)
                         (check-members properties object (format nil "~a." said))
                       (setf problems (append (reverse inner-problems) problems))
                       ;; A member the object does not declare is left for
                       ;; the tool to refuse in its own words: these objects
                       ;; configure a process, and one silently dropped
                       ;; would read as one applied.
                       (maphash (lambda (key member)
                                  (unless (nth-value 1 (gethash key inner))
                                    (unless (find key properties :key #'first :test #'string=)
                                      (setf (gethash key inner) member))))
                                object)
                       inner)))
              (cond ((not present)
                     (when required (push (format nil "~a is required (was missing)" said) problems)))
                    ((not (ecase type
                            (:string (stringp value))
                            (:integer (integerp value))
                            (:number (realp value))
                            (:boolean (member value '(t nil)))
                            (:strings (and (json-array-p value) (every #'stringp value)))
                            (:string-map (and (hash-table-p value)
                                              (loop for member being the hash-values of value
                                                    always (stringp member))))
                            (:object (hash-table-p value))
                            (:objects (and (json-array-p value) (every #'hash-table-p value)))))
                     (push (format nil "~a must be ~a (was ~a)" said
                                   (ecase type
                                     (:string "a string") (:integer "an integer") (:number "a number")
                                     (:boolean "true or false") (:strings "an array of strings")
                                     (:string-map "an object of strings") (:object "an object")
                                     (:objects "an array of objects"))
                                   (json-encode value))
                           problems))
                    ((and enum (not (member value enum :test #'equal)))
                     (push (format nil "~a must be one of ~{~a~^, ~} (was ~a)" said
                                   (mapcar #'json-encode enum) (json-encode value))
                           problems))
                    (t (setf (gethash name checked)
                             (case type
                               (:object (members value))
                               (:objects (map 'simple-vector #'members value))
                               (t value))))))))))
    (values checked (nreverse problems))))

(defun check-arguments (tool arguments)
  "ARGUMENTS held to TOOL's parameters => a fresh object of exactly the
declared members that were given; an object among them keeps what it does
not declare, for its tool to judge. A member of the wrong type is refused,
never coerced; null reads as absent."
  (multiple-value-bind (checked problems) (check-members (tool-parameters tool) arguments "")
    (when problems
      (fail "omp-re: ~a was called with arguments that do not fit its schema: ~{~a~^; ~}"
            (tool-name tool) problems))
    checked))

;;; --- the audit log -------------------------------------------------------------------------

(defun append-audit-line (session call-id tool arguments)
  "Append one line to the session's audit log, signed when the signing key
is set: the call CALL-ID to TOOL with its ARGUMENTS. Never signals: the log is a mirror
for the operator, and must not abort the call it records."
  (handler-case
      (let* ((base (obj "ts" (iso-now) "sessionId" (session-id session)
                        "toolCallId" call-id "tool" tool
                        "args" arguments))
             (canonical (json-encode base))
             (key (setting-value :audit-hmac-key)))
        (cond (key
               ;; The signature is over the line as written without it.
               (setf (gethash "hmac" base) (base64 (hmac-sha256 (utf-8 key) (utf-8 canonical)))
                     canonical (json-encode base)))
              ((not (session-audit-warned session))
               (setf (session-audit-warned session) t)
               ;; Not a fault, so the operator is told once a session and
               ;; quietly; /re status says it to anyone who asks.
               (notify :info "omp-re: ~a not configured — audit log entries will not be signed."
                       (setting-variable :audit-hmac-key))))
        (append-text-file (state-path "audit" (format nil "~a.log" (session-id session)))
                          (format nil "~a~%" canonical)))
    (error (condition)
      (notify :warning "omp-re: audit log write failed: ~a" condition))))

(contribute "audit log" :order 80
  :status (lambda (session)
            (declare (ignore session))
            (list (format nil "audit log signing: ~a"
                          (if (setting-value :audit-hmac-key)
                              "HMAC-SHA256"
                              (format nil "unsigned (set ~a)" (setting-variable :audit-hmac-key)))))))

;;; --- one call --------------------------------------------------------------------------------

(defun run-tool (name arguments &key call-id (session *session*))
  "The tool NAME run with the JSON object ARGUMENTS in SESSION, which the
caller holds => (values RESULT RAW EVIDENCE-ID): the arguments held to the
schema, a line in the audit log, the body, and for a result that observes
the binary its evidence record. CALL-ID is the host's own id for the call,
where it has one, and is what the audit line names it by; without one the
line carries the session's own count of its calls."
  (let* ((tool (or (find-tool name)
                   (fail "omp-re: no tool named ~a~a" (js-string name) (voice :list-tools))))
         (arguments (check-arguments tool (or arguments (obj)))))
    (append-audit-line session
                       (or call-id
                           (format nil "~a-~d" (file-safe (session-id session))
                                   (incf (session-calls session))))
                       name arguments)
    (multiple-value-bind (result raw) (let ((*running-tool* name))
                                        (funcall (tool-function tool) arguments))
      (let ((id (and (tool-evidence tool) (result-observation result) (not (result-failed result))
                     ;; A blob-store failure degrades to "no evidence
                     ;; recorded", it does not fail the call.
                     (handler-case (record-evidence name arguments (result-text result)
                                                    (result-details result) session)
                       (error (condition)
                         (notify :warning "omp-re: evidence recording failed: ~a" condition)
                         nil)))))
        (when id (setf (gethash "evidenceId" (result-details result)) id))
        (values result raw id)))))

(defun call-tool (session name arguments &key call-id)
  "Run the tool NAME with the JSON object ARGUMENTS in SESSION — a session
or the id of one => (values TEXT FAILED RAW EVIDENCE-ID ARTIFACT-PATH
DETAILS). TEXT is what the model reads: for a failure, what went wrong in
words it can act on. FAILED is T for a result that says it failed and
:REFUSED for a call that never came to a result (IN-SESSION). RAW is the tool's second value when it has one — the
whole of what rizin printed, where TEXT may be cut. EVIDENCE-ID is the
record this call left, whose tag TEXT ends with; ARTIFACT-PATH where all of
a TEXT that was cut is kept; DETAILS the result's own details object."
  (in-session (session name)
    (multiple-value-bind (result raw id) (run-tool name arguments :call-id call-id)
      (let ((text (result-text result))
            (details (result-details result)))
        ;; The id rides on its own trailing line, so a *j result's body
        ;; stays valid JSON between the header and the tag.
        (values (if id (format nil "~a~%~a" text (evidence-tag id)) text)
                (result-failed result)
                raw
                id
                (jstring details "artifactPath")
                details)))))
