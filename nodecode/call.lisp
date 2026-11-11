;;;; call.lisp --- one tool call: what a tool answers, the tools, the audit log.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; CALL-TOOL is the one way a tool runs, whoever asks — a verb in eval, a
;;;; host that registered the tool, a recipe: the `/re off' gate, a line in
;;;; the audit log, the body, and for a result that observes the binary an
;;;; evidence record whose id is appended to what the model reads.

(in-package #:nodecode-re)

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

(defun failed-result (text &optional ea)
  (let ((result (plain-result text ea)))
    (setf (result-failed result) t)
    result))

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

(defun build-result (lead body &key ea tool commands repro-hash canonical-excerpt shift-hash)
  "LEAD then BODY, cut to what a context can take; the whole text is kept as
an artifact and the result names the file that holds it."
  (multiple-value-bind (kept truncated shown-lines total-lines shown-octets total-octets)
      (truncate-head body)
    (multiple-value-bind (artifact where)
        (and truncated *session*
             (save-artifact (concatenate 'string lead body) (or tool "omp-re")))
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
  (label nil)                           ; what a host that lists tools to a person calls it
  (description "" :type string)
  (parameters '())                      ; ((NAME TYPE &key required doc enum) ...)
  (function nil)                        ; (lambda (ARGS)) => a RESULT
  (tier :exec)                          ; :read observes, :write annotates, :exec runs code or writes files
  (evidence nil)                        ; a successful result is recorded as evidence
  (available nil))                      ; NIL, or a predicate: offered only while it answers true

(defvar *tools* '() "Every engine tool, in the order defined.")

(defun register-engine-tool (tool)
  (setf *tools* (append (remove (tool-name tool) *tools* :key #'tool-name :test #'string=)
                        (list tool)))
  tool)

(defmacro define-tool (name (&key label description (tier :exec) evidence available) parameters
                       (arguments) &body body)
  "Define the engine tool NAME. PARAMETERS is a list of
(\"name\" TYPE &key required doc enum) with TYPE one of :string, :integer,
:number, :boolean and :strings (an array of strings); the body runs with
ARGUMENTS bound to the validated JSON object and *SESSION* to the session,
and answers a RESULT."
  `(register-engine-tool
    (make-tool :name ,name :label ,label :description ,description :tier ,tier
               :evidence ,evidence :available ,available
               :parameters (list ,@(mapcar (lambda (parameter)
                                             `(list ,(first parameter) ,(second parameter)
                                                    ,@(cddr parameter)))
                                           parameters))
               :function (lambda (,arguments) (declare (ignorable ,arguments)) ,@body))))

(defun tool-offered-p (tool)
  (or (null (tool-available tool)) (funcall (tool-available tool))))

(defun offered-tools ()
  (remove-if-not #'tool-offered-p *tools*))

(defun engine-name (designator)
  "DESIGNATOR — a string, a keyword, a symbol — as the engine spells a tool,
a parameter or a /re subcommand: lowercase, words joined by underscores. So
:MAX-DEPTH is \"max_depth\" and \"Open-Binary\" is \"open_binary\"."
  (substitute #\_ #\- (string-downcase (string designator))))

(defun find-tool (name)
  (let ((tool (find name *tools* :key #'tool-name :test #'string=)))
    (and tool (tool-offered-p tool) tool)))

(defun parameter-schema (parameter)
  (destructuring-bind (name type &key doc enum &allow-other-keys) parameter
    (declare (ignore name))
    (let ((schema (ecase type
                    (:string (obj "type" "string"))
                    (:integer (obj "type" "integer"))
                    (:number (obj "type" "number"))
                    (:boolean (obj "type" "boolean"))
                    (:strings (obj "type" "array" "items" (obj "type" "string"))))))
      (when enum (setf (gethash "enum" schema) (coerce enum 'simple-vector)))
      (when doc (setf (gethash "description" schema) doc))
      schema)))

(defun tool-schema (tool)
  "TOOL's parameters as the JSON Schema a provider is shown."
  (let ((properties (obj))
        (required '()))
    (dolist (parameter (tool-parameters tool))
      (setf (gethash (first parameter) properties) (parameter-schema parameter))
      (when (getf (cddr parameter) :required) (push (first parameter) required)))
    (obj "type" "object"
         "properties" properties
         "required" (if required (coerce (nreverse required) 'simple-vector) :absent))))

(defun check-arguments (tool arguments)
  "ARGUMENTS held to TOOL's parameters => a fresh object of exactly the
declared members that were given. A member of the wrong type is refused,
never coerced; null reads as absent."
  (let ((checked (obj)) (problems '()))
    (dolist (parameter (tool-parameters tool))
      (destructuring-bind (name type &key required enum &allow-other-keys) parameter
        (multiple-value-bind (value present) (gethash name arguments)
          (let ((present (and present (not (eq value :null)))))
            (cond ((not present)
                   (when required (push (format nil "~a is required (was missing)" name) problems)))
                  ((not (ecase type
                          (:string (stringp value))
                          (:integer (integerp value))
                          (:number (realp value))
                          (:boolean (member value '(t nil)))
                          (:strings (and (json-array-p value) (every #'stringp value)))))
                   (push (format nil "~a must be ~a (was ~a)" name
                                 (ecase type
                                   (:string "a string") (:integer "an integer") (:number "a number")
                                   (:boolean "true or false") (:strings "an array of strings"))
                                 (json-encode value))
                         problems))
                  ((and enum (not (member value enum :test #'equal)))
                   (push (format nil "~a must be one of ~{~a~^, ~} (was ~a)" name
                                 (mapcar #'json-encode enum) (json-encode value))
                         problems))
                  (t (setf (gethash name checked) value)))))))
    (when problems
      (fail "omp-re: ~a was called with arguments that do not fit its schema: ~{~a~^; ~}"
            (tool-name tool) (nreverse problems)))
    checked))

;;; --- the audit log -------------------------------------------------------------------------

(defun append-audit-line (session call-id tool arguments)
  "Append one line for this call to the session's audit log, signed when
OMPRE_AUDIT_HMAC_KEY is set. Never signals: the log is a mirror for the
operator, and must not abort the call it records."
  (handler-case
      (let* ((base (obj "ts" (iso-now) "sessionId" (session-id session)
                        "toolCallId" call-id "tool" tool "args" arguments))
             (canonical (json-encode base))
             (key (setting-value :audit-hmac-key)))
        (cond (key
               ;; The signature is over the line as written without it.
               (setf (gethash "hmac" base) (base64 (hmac-sha256 (utf-8 key) (utf-8 canonical)))
                     canonical (json-encode base)))
              ((not (session-audit-warned session))
               (setf (session-audit-warned session) t)
               ;; Said once a session, and only on the log: the status line
               ;; carries it for anyone who asks, and it is not a fault.
               (warn "omp-re: OMPRE_AUDIT_HMAC_KEY not configured — audit log entries will not be signed.")))
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
                              "unsigned (set OMPRE_AUDIT_HMAC_KEY)")))))

;;; --- one call --------------------------------------------------------------------------------

(defun call-tool (session name arguments)
  "Run the tool NAME with the JSON object ARGUMENTS in SESSION — a session
or the id of one => (values TEXT FAILED RAW EVIDENCE-ID ARTIFACT-PATH
DETAILS). TEXT
is what the model reads: for a failure, what went wrong in words it can act
on. RAW is the tool's second value when it has one — the whole of what rizin
printed, where TEXT may be cut. EVIDENCE-ID is the record this call left,
whose tag TEXT ends with; ARTIFACT-PATH where all of a TEXT that was cut is
kept; DETAILS the result's own details object. This is the whole pipeline — the `/re off' gate, the audit
line, the body, the evidence record — so code that composes reads makes each
of them a tool call in its own right, not a way around one."
  (in-session (session name)
    (let* ((session *session*)
           (tool (or (find-tool name)
                     (fail "omp-re: no tool named ~a — (re:tools) lists them" (js-string name))))
           (arguments (check-arguments tool (or arguments (obj)))))
      (when (session-tools-off session)
        (fail "omp-re: RE tools are off for this session — the user can re-enable them with /re on"))
      (append-audit-line session
                         (format nil "~a-~d" (file-safe (session-id session)) (incf (session-calls session)))
                         name arguments)
      (multiple-value-bind (result raw) (funcall (tool-function tool) arguments)
        (let* ((text (result-text result))
               (details (result-details result))
               ;; A blob-store failure degrades to "no evidence recorded", it
               ;; does not fail the call.
               (id (and (tool-evidence tool) (result-observation result) (not (result-failed result))
                        (handler-case (record-evidence name arguments text details)
                          (error (condition)
                            (notify :warning "omp-re: evidence recording failed: ~a" condition)
                            nil)))))
          (when id (setf (gethash "evidenceId" details) id))
          ;; The id rides on its own trailing line, so a *j result's body
          ;; stays valid JSON between the header and the tag.
          (values (if id (format nil "~a~%~a" text (evidence-tag id)) text)
                  (result-failed result)
                  raw
                  id
                  (jstring details "artifactPath")
                  details))))))

;;; --- names the tool groups still call; removed when they move to the above ---------------
;;; CALL-TOOL-IN-SESSION name arguments (recipes.lisp) → (call-tool *session* name arguments):
;;;     a call inside a held session takes no lock of its own.

(defun call-tool-in-session (name arguments)
  (call-tool *session* name arguments))
