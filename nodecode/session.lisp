;;;; session.lisp --- a session's record, its rizin process, and one tool call.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Ported from omp-re's runtime.ts, state.ts, entries.ts, evidence.ts,
;;;; audit.ts and the result half of format.ts.
;;;;
;;;; A SESSION is everything the engine holds for one nodecode session: the
;;;; open binary, the rizin process analyzing it, and the session's RECORD —
;;;; an append-only list of entries (re.binary, re.evidence, re.annotation,
;;;; re.finding, ...) kept on disk as one JSON object a line. The record is
;;;; the truth and the process is a cache of it: a rizin that died, a session
;;;; reaped for idleness and an organism restarted all come back the same
;;;; way, by spawning rizin on the recorded binary and replaying what the
;;;; record says was done to it. The entries are the ones omp-re writes to an
;;;; omp session branch, field for field.
;;;;
;;;; CALL-TOOL is the one way a tool runs, whoever asks — a verb in eval, a
;;;; top-level tool, the /re command: the `/re off' gate, a line in the audit
;;;; log, the body, and for a tool that observes the binary an evidence
;;;; record whose id is appended to what the model reads.

(in-package #:nodecode-re)

;;; --- where things are kept -------------------------------------------------------------

(defvar *state-directory* nil
  "A function answering the directory everything is kept under. Set by the
cell at start; a test binds it.")

(defun state-directory ()
  (uiop:ensure-directory-pathname
   (if *state-directory*
       (funcall *state-directory*)
       (nlk:home "omp-re/"))))

(defun state-path (&rest parts)
  "A path under the state directory's re/ folder — the layout omp-re keeps
under omp's agent directory."
  (merge-pathnames (format nil "re/~{~a~^/~}" parts) (state-directory)))

;;; --- the session -------------------------------------------------------------------------

(defstruct (session (:copier nil))
  (id "default" :type string)
  ;; One tool call or /re line at a time: rizin answers one request at a time,
  ;; and a record written by two threads at once is no record.
  (lock (sb-thread:make-mutex :name "omp-re session"))
  (rz nil)                              ; the static analysis process
  (dbg nil)                             ; the opt-in debug process, never respawned on its own
  (binary-path nil)
  (binary-sha256 nil)
  (load-options nil)                    ; a JSON object, or NIL for header autodetection
  (entries (make-array 0 :adjustable t :fill-pointer 0))
  (evidence-by-addr (make-hash-table :test #'equal))
  (applied-annotations "")
  (tools-off nil)
  (audit-warned nil)
  (calls 0)
  (artifacts 0)
  (last-used (get-universal-time)))

(defvar *sessions* (make-hash-table :test #'equal))
(defvar *sessions-lock* (sb-thread:make-mutex :name "omp-re sessions"))

(defvar *session* nil
  "The session the running tool call or /re line is for.")

(defun session-directory (session)
  (uiop:ensure-directory-pathname (state-path "sessions" (file-safe (session-id session)))))

(defun record-path (session)
  (merge-pathnames "branch.jsonl" (session-directory session)))

(defun load-record (session)
  "Read SESSION's record from disk. A torn last line — the process died
mid-append — loses that one entry, never the record."
  (let ((text (read-text-file (record-path session))))
    (when text
      (dolist (line (split-lines text))
        (let ((entry (and (not (blank-p line)) (json-parse line))))
          (when (and (hash-table-p entry) (jstring entry "customType"))
            (vector-push-extend entry (session-entries session))))))))

(defun find-session (id)
  "The session called ID, its record read and its state restored from it on
first use."
  (sb-thread:with-mutex (*sessions-lock*)
    (or (gethash id *sessions*)
        (let ((session (make-session :id id)))
          (load-record session)
          (restore-from-record session)
          (setf (gethash id *sessions*) session)))))

(defun append-entry (type data &optional (session *session*))
  "Append one entry of TYPE carrying the JSON object DATA to the record, on
disk before it is in memory's list: what was said to be recorded is."
  (let ((entry (obj "type" "custom"
                    "id" (format nil "~(~36r~)-~d" (get-universal-time) (length (session-entries session)))
                    "customType" type
                    "data" data)))
    (append-text-file (record-path session) (format nil "~a~%" (json-encode entry)))
    (vector-push-extend entry (session-entries session))
    entry))

(defun entries-of (type &optional (session *session*))
  "The data of every entry of TYPE, in the order recorded."
  (loop for entry across (session-entries session)
        when (equal type (jstring entry "customType"))
          collect (jget entry "data")))

(defun binary-entries (type binary-path &optional (session *session*))
  "The data of the TYPE entries that belong to BINARY-PATH: an entry belongs
to whichever re.binary opened most recently before it. This is how
annotations, signatures, analysis passes and mapped files stay with the
binary they were made on when a session opens another."
  (loop with current = nil
        for entry across (session-entries session)
        for kind = (jstring entry "customType")
        for data = (jget entry "data")
        do (when (equal kind "re.binary")
             (setf current (jstring data "path")))
        when (and (equal kind type) (equal current binary-path))
          collect data))

(defun last-binary-entry (&optional (session *session*))
  (car (last (entries-of "re.binary" session))))

;;; --- evidence ----------------------------------------------------------------------------

(defun evidence-records (&optional (session *session*))
  "Every re.evidence record, oldest first; malformed rows are skipped."
  (remove-if-not (lambda (record) (jstring record "id")) (entries-of "re.evidence" session)))

(defun find-evidence (id &optional (session *session*))
  "The evidence record whose id is ID, or begins with it: a result shows
only the first eight characters, so what the model retypes is a prefix."
  (let ((records (evidence-records session)))
    (or (find id records :key (lambda (record) (jstring record "id")) :test #'string=)
        (and (plusp (length id))
             (find-if (lambda (record) (starts-with id (jstring record "id"))) records)))))

(defun record-evidence-at (ea id &optional (session *session*))
  (when (and ea (plusp (length ea)))
    (setf (gethash (normalize-addr ea) (session-evidence-by-addr session)) id)))

(defun evidence-id-at (ea &optional (session *session*))
  "The most recent evidence observed at EA, or NIL: what grounds an annotation there."
  (gethash (normalize-addr ea) (session-evidence-by-addr session)))

(defun rebuild-evidence-index (session)
  (clrhash (session-evidence-by-addr session))
  (dolist (record (evidence-records session))
    (record-evidence-at (jstring record "ea") (jstring record "id") session)))

(defun blob-path (hash)
  (state-path "blobs" (subseq hash 0 2) (subseq hash 2 4) hash))

(defun write-blob (content)
  "Store CONTENT in the content-addressed blob store => its SHA-256. Written
through a temporary file and one rename, so a reader never sees half a blob;
a blob already there is left alone."
  (let* ((hash (sha256-hex content))
         (target (blob-path hash)))
    (unless (probe-file target)
      (ensure-directories-exist target)
      (nlk:write-file-atomically target content))
    hash))

(defun read-blob (hash)
  "The blob stored under HASH, or NIL when it is missing."
  (and (stringp hash) (>= (length hash) 4) (read-text-file (blob-path hash))))

(defun evidence-tag (id)
  (format nil "[evidence ~a — cite it in record_finding]" (subseq id 0 8)))

(defun record-evidence (tool-name arguments text details &optional (session *session*))
  "Append one re.evidence record for a successful observation => its id.
TEXT is what the model was sent; DETAILS the result's own details object,
whose reproducibility fields are what /re verify later re-runs."
  (let* ((id (uuid))
         (ea (jstring details "ea"))
         (commands (jget details "commands")))
    (record-evidence-at ea id session)
    (append-entry "re.evidence"
                  (obj "id" id
                       "tool" tool-name
                       "args" arguments
                       "ea" (or ea :absent)
                       "outputHash" (write-blob text)
                       "artifactId" (or (jstring details "artifactId") :absent)
                       "commands" (if (and (vectorp commands) (every #'stringp commands)) commands :absent)
                       "reproHash" (or (jstring details "reproHash") :absent)
                       "canonicalExcerpt" (or (jstring details "canonicalExcerpt") :absent)
                       "shiftHash" (or (jstring details "shiftHash") :absent)
                       ;; Binds the evidence to the exact bytes it was taken against.
                       "binarySha256" (or (session-binary-sha256 session) :absent)
                       "summary" (clip-utf-8 text 512))
                  session)
    id))

;;; --- the audit log -------------------------------------------------------------------------

(defun append-audit-line (session call-id tool arguments)
  "Append one line for this call to the session's audit log, signed when
OMPRE_AUDIT_HMAC_KEY is set. Never signals: the log is a mirror for the
operator, and must not abort the call it records."
  (handler-case
      (let* ((base (obj "ts" (iso-now) "sessionId" (session-id session)
                        "toolCallId" call-id "tool" tool "args" arguments))
             (canonical (json-encode base))
             (key (uiop:getenv "OMPRE_AUDIT_HMAC_KEY")))
        (cond ((and key (plusp (length key)))
               ;; The signature is over the line as written without it.
               (setf (gethash "hmac" base) (base64 (hmac-sha256 (utf-8 key) (utf-8 canonical)))
                     canonical (json-encode base)))
              ((not (session-audit-warned session))
               (setf (session-audit-warned session) t)
               (warn "omp-re: OMPRE_AUDIT_HMAC_KEY not configured — audit log entries will not be signed.")))
        (append-text-file (state-path "audit" (format nil "~a.log" (session-id session)))
                          (format nil "~a~%" canonical)))
    (error (condition)
      (warn "omp-re: audit log write failed: ~a" condition))))

;;; --- what a tool answers -------------------------------------------------------------------

(defstruct (result (:copier nil))
  (text "" :type string)
  (details (obj))                       ; the JSON object omp-re calls a result's details
  (failed nil))

(defun result-ea (result)
  (jstring (result-details result) "ea"))

(defun plain-result (text &optional ea)
  "A one-off, untruncated result: a mutation, a hash, session setup."
  (make-result :text text
               :details (obj "ea" (or ea :absent)
                             "summary" (subseq text 0 (min 512 (length text)))
                             "header" (first (split-lines text)))))

(defun failed-result (text &optional ea)
  (let ((result (plain-result text ea)))
    (setf (result-failed result) t)
    result))

(defun artifact-path (id &optional (session *session*))
  (merge-pathnames (format nil "artifacts/~a.txt" (file-safe id)) (session-directory session)))

(defun save-artifact (content label &optional (session *session*))
  "Keep CONTENT whole beside the session's record => the artifact's id, or
NIL when it could not be written: a result then stays truncated, never fails."
  (ignore-errors
   ;; An evidence record keeps the id and the record outlives this process,
   ;; so an id is never reused after a restart.
   (let ((id (format nil "~(~36r~)-~d-~a" (get-universal-time) (incf (session-artifacts session))
                     (file-safe label))))
     (write-text-file (artifact-path id session) content)
     id)))

(defun build-result (lead header body &key ea tool narrow-hint decompiler commands repro-hash
                                           canonical-excerpt shift-hash)
  "LEAD then BODY, cut to what a context can take; the whole text is kept as
an artifact and the result names the file that holds it."
  (multiple-value-bind (kept truncated shown-lines total-lines shown-octets total-octets)
      (truncate-head body)
    (let* ((artifact (and truncated *session*
                          (save-artifact (concatenate 'string lead body) (or tool "omp-re"))))
           (text (concatenate
                  'string lead kept
                  (if truncated
                      (format nil "~%~%[Output truncated: ~d of ~d lines (~a of ~a). ~a]"
                              shown-lines total-lines (format-size shown-octets) (format-size total-octets)
                              (if artifact
                                  (format nil "Full output: ~a" (native (artifact-path artifact)))
                                  (or narrow-hint "Full output was larger.")))
                      ""))))
      (make-result
       :text text
       :details (obj "ea" (or ea :absent)
                     "summary" (subseq text 0 (min 512 (length text)))
                     "header" header
                     "truncated" (if truncated t :absent)
                     "artifactId" (or artifact :absent)
                     "decompiler" (or decompiler :absent)
                     "commands" (if commands (coerce commands 'simple-vector) :absent)
                     "reproHash" (or repro-hash :absent)
                     "canonicalExcerpt" (or canonical-excerpt :absent)
                     "shiftHash" (or shift-hash :absent))))))

(defun text-result (header body &rest keys)
  "Plain-text output — disassembly, decompiled code, a listing — under HEADER."
  (apply #'build-result (format nil "~a~%" header) header body keys))

(defun json-result (header data &rest keys)
  "DATA as the real JSON payload under HEADER, not just a count."
  (apply #'build-result (format nil "~a~%" header) header (format-json data)
         (append keys (list :narrow-hint "Narrow with offset/limit or filter."))))

(defun prefixed-text-result (prefix body &rest keys)
  "Like TEXT-RESULT, but PREFIX stays at byte 0 of the content."
  (apply #'build-result prefix (trimmed prefix) body keys))

;;; --- the rizin process a session owns ------------------------------------------------------

(defun require-binary (&optional (session *session*))
  (or (session-binary-path session)
      (fail "omp-re: no binary open — use /re open <path>, (re:open \"path\") or the open_binary tool first")))

(defvar *replay-hooks* '()
  "Functions (name . function) run on every fresh rizin process, in the order
registered, each putting back what the record says was done to this binary —
mapped files, analysis passes, signatures, annotations. A function takes
(SESSION RZ BINARY-PATH) and answers a list of failure lines.")

(defun register-replay (name function)
  "Register FUNCTION under NAME to run on every fresh rizin process, after
those registered before it. Registering a name again replaces it in place."
  (let ((existing (assoc name *replay-hooks* :test #'string=)))
    (if existing
        (setf (cdr existing) function)
        (setf *replay-hooks* (append *replay-hooks* (list (cons name function))))))
  name)

(defvar *annotation-fingerprint* nil
  "A function of (SESSION BINARY-PATH) answering a string that names the set
of annotations in effect, or NIL when no annotation module is loaded.")

(defvar *live-annotations* nil
  "A function of (BINARY-PATH SESSION) answering the annotations in effect
for that binary as a list of their recorded data objects, or NIL when no
annotation module is loaded. Set by annotate.lisp.")

(defun spawn-rizin (binary-path &key load (session *session*))
  "Spawn and analyze a fresh rizin for BINARY-PATH, replay the record into
it, and make it SESSION's process => (values RZ FAILURES). The process it
replaces is closed only once the new one is analyzed and live."
  (let ((binary-path (resolve-binary-path binary-path)))
    (assert-rizin-available)
    (when load (setf (session-load-options session) load))
    (let* ((load (or load (session-load-options session)))
           (rz (spawn-rz (resolve-rizin-path binary-path (and load (jget load "bits")))
                         binary-path :load load))
           (previous (session-rz session))
           (failures '()))
      ;; The replay reads the record as it stands for this binary, so the
      ;; session must already say which binary is open.
      (setf (session-binary-path session) binary-path)
      (handler-case
          (loop for (nil . hook) in *replay-hooks*
                do (setf failures (append failures (funcall hook session rz binary-path))))
        (error (condition)
          (rz-close rz)
          (error condition)))
      (setf (session-rz session) rz
            (session-applied-annotations session)
            (if *annotation-fingerprint* (funcall *annotation-fingerprint* session binary-path) ""))
      (when (and previous (not (eq previous rz)))
        (rz-close previous))
      (values rz failures))))

(defun ensure-rizin (&optional (session *session*))
  "SESSION's live rizin, respawned — and the record replayed — when the
previous process died."
  (let ((rz (session-rz session)))
    (if (rz-alive-p rz)
        rz
        (progn
          (when rz (rz-close rz))
          (multiple-value-bind (rz failures) (spawn-rizin (require-binary session) :session session)
            (when failures
              (warn "omp-re: ~d annotation(s) could not be replayed:~%~{~a~^~%~}" (length failures) failures))
            rz)))))

(defun restore-from-record (session)
  "Set SESSION's binary, its hash and its load options from the record's
last re.binary entry, and rebuild the evidence index. No process is started:
the next call that needs one starts it."
  (rebuild-evidence-index session)
  (let ((binary (last-binary-entry session)))
    (when binary
      (setf (session-binary-path session) (jstring binary "path")
            (session-binary-sha256 session) (jstring binary "sha256")
            (session-load-options session) (let ((load (jget binary "load")))
                                             (and (hash-table-p load) load))))))

(defun close-session-processes (session)
  (rz-close (session-rz session))
  (rz-close (session-dbg session))
  (setf (session-rz session) nil
        (session-dbg session) nil))

(defun shutdown-sessions ()
  "Close every session's processes and forget the sessions; their records stay."
  (let ((sessions (sb-thread:with-mutex (*sessions-lock*)
                    (prog1 (loop for session being the hash-values of *sessions* collect session)
                      (clrhash *sessions*)))))
    (mapc #'close-session-processes sessions)
    t))

(defun reap-idle-sessions (idle-seconds)
  "Close the processes of every session nothing has called for IDLE-SECONDS.
Nothing is lost: the record is on disk and the next call restores from it."
  (let ((now (get-universal-time)))
    (dolist (session (sb-thread:with-mutex (*sessions-lock*)
                       (loop for session being the hash-values of *sessions* collect session)))
      (when (and (>= (- now (session-last-used session)) idle-seconds)
                 (or (session-rz session) (session-dbg session)))
        ;; Only when nothing is running on it: never wait, never interrupt.
        (when (sb-thread:grab-mutex (session-lock session) :waitp nil)
          (unwind-protect (close-session-processes session)
            (sb-thread:release-mutex (session-lock session))))))))

;;; --- tools -----------------------------------------------------------------------------------

(defstruct (tool (:copier nil))
  (name "" :type string)
  (label nil)
  (description "" :type string)
  (parameters '())                      ; ((NAME TYPE &key required doc enum) ...)
  (function nil)                        ; (lambda (ARGS)) => a RESULT
  (tier :exec)                          ; :read observes; anything else changes state or runs code
  (evidence nil)                        ; a successful result is an observation of the binary
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
                          (:strings (and (vectorp value) (not (stringp value)) (every #'stringp value)))))
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

(defmacro with-session ((session) &body body)
  "BODY with SESSION as *SESSION*, holding its lock: one call at a time."
  (let ((it (gensym "SESSION")))
    `(let ((,it ,session))
       (sb-thread:with-mutex ((session-lock ,it))
         (let ((*session* ,it))
           (setf (session-last-used ,it) (get-universal-time))
           ,@body)))))

(defun call-tool (session name arguments)
  "Run the tool NAME for SESSION with the JSON object ARGUMENTS
=> (values TEXT FAILED-P). A failure is an answer, never a signal: TEXT is
then what went wrong, in words the model can act on."
  (let ((tool (find-tool name)))
    (unless tool
      (return-from call-tool
        (values (format nil "omp-re: no tool named ~a — (re:tools) lists them" (js-string name)) t)))
    (handler-case
        (let ((arguments (check-arguments tool (or arguments (obj)))))
          (with-session (session)
            (when (session-tools-off session)
              (return-from call-tool
                (values "omp-re: RE tools are off for this session — the user can re-enable them with /re on" t)))
            (let ((call-id (format nil "~a-~d" (file-safe (session-id session))
                                   (incf (session-calls session)))))
              (append-audit-line session call-id name arguments)
              (let* ((result (funcall (tool-function tool) arguments))
                     (text (result-text result)))
                (cond ((result-failed result) (values text t))
                      ((and (tool-evidence tool) (not (jget (result-details result) "manual")))
                       ;; The id rides on its own trailing line, so a *j
                       ;; result's body stays valid JSON between the header
                       ;; and the tag. A blob-store failure degrades to "no
                       ;; evidence recorded", it does not fail the call.
                       (let ((id (handler-case (record-evidence name arguments text (result-details result))
                                   (error (condition)
                                     (warn "omp-re: evidence recording failed: ~a" condition)
                                     nil))))
                         (values (if id (format nil "~a~%~a" text (evidence-tag id)) text) nil)))
                      (t (values text nil)))))))
      (re-error (condition)
        (values (princ-to-string condition) t))
      (error (condition)
        (values (format nil "omp-re: ~a failed: ~a" name condition) t)))))
