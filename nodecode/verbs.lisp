;;;; verbs.lisp --- what the model calls from eval, and the tools behind them.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; nodecode's model has one tool, eval, and omp-re's design is the same
;;;; idea from the other side: one tool to read the binary and a handful of
;;;; stateful ones, composed in code rather than listed as schemas. So the
;;;; native surface here is verbs — (re:open ...), (re:cmd ...), (re:call
;;;; ...) — that an eval form loops over, filters and defines helpers around,
;;;; and what the model defines that way the organism keeps.
;;;;
;;;; Every verb answers a string, but (re:json ...), which answers a *j
;;;; command's output already decoded. A call the engine ran and failed is
;;;; RE-ERROR carrying the engine's own words, so eval marks the form failed
;;;; and the model reads why. Each call is audited and, when it observes the
;;;; binary, recorded as evidence by the engine exactly as under omp: the
;;;; `[evidence xxxxxxxx]' tag at the end of a result is what record_finding
;;;; cites.

(in-package #:nodecode-re)

;;; --- the session a call is for ----------------------------------------------------

(defun session-id ()
  "The running turn's session, which the engine keys its rizin process, its
open binary and its evidence by; \"default\" outside a turn."
  (or (getf (nle:turn) :session-id) "default"))

(defun session-path (path session)
  "PATH as the model wrote it — ~/ and all — read against SESSION's
directory when it is relative: the engine is one process for every session
and has no directory of its own to read it against."
  (unless (and (stringp path) (plusp (length (nlk:trimmed path))))
    (fail "a path must be a non-empty string, not ~s" path))
  (let ((path (nlk:expand-home path)))
    (native
     (if (uiop:absolute-pathname-p path)
         path
         (let ((directory (ignore-errors (nlk:find-session-cwd session))))
           (if directory
               (merge-pathnames path (uiop:ensure-directory-pathname directory))
               path))))))

;;; --- Lisp arguments onto the wire -------------------------------------------------

(defun wire-key (key)
  "A keyword as the engine spells the parameter: :EXPECT-SHA256 is
\"expect_sha256\". A string is taken as written."
  (if (stringp key)
      key
      (substitute #\_ #\- (string-downcase (symbol-name key)))))

(defun wire-value (value)
  "VALUE as JSON: a string, a number and T as themselves, :FALSE as false, a
keyword as its lowercase name, a list or vector as an array."
  (cond ((eq value :false) nil)
        ((member value '(t :null)) value)
        ((stringp value) value)
        ((keywordp value) (string-downcase (symbol-name value)))
        ((hash-table-p value) value)
        ((or (listp value) (vectorp value)) (map 'vector #'wire-value value))
        ((realp value) value)
        (t (fail "~s has no JSON form: pass a string, a number, T, :false, or a list of those" value))))

(defun wire-arguments (plist)
  "The JSON object a keyword PLIST of tool arguments spells. A NIL value is a
parameter left out — false is :FALSE, an empty array is #()."
  (unless (evenp (length plist))
    (fail "tool arguments are keyword and value pairs; ~s has an odd one out" plist))
  (let ((object (nlk:make-json-object)))
    (loop for (key value) on plist by #'cddr
          do (unless (or (keywordp key) (stringp key))
               (fail "a tool argument is named by a keyword, not ~s" key))
             (unless (null value)
               (setf (gethash (wire-key key) object) (wire-value value))))
    object))

;;; --- one call ---------------------------------------------------------------------

(defun answer (reply)
  "REPLY's text => (values TEXT FAILED-P); a request the bridge itself
refused is RE-ERROR."
  (unless (nlk:json-value reply :boolean "ok")
    (fail "~a" (or (nlk:json-value reply :string "error") "the engine refused the request")))
  (values (or (nlk:json-value reply :string "text") "")
          (nlk:json-value reply :boolean "isError")))

(defun tool-answer (name arguments &optional (session (session-id)))
  "Call the engine's tool NAME with the JSON object ARGUMENTS for SESSION
=> (values TEXT FAILED-P)."
  (answer (exchange (nlk:make-json-object "op" "call" "session" session
                                           "tool" name "args" arguments))))

(defun tool-text (name arguments)
  "The text of one tool call, or RE-ERROR carrying it when the call failed."
  (multiple-value-bind (text failed) (tool-answer name arguments)
    (if failed (fail "~a" text) text)))

(defun command-text (line &optional (session (session-id)))
  "One /re line for SESSION => (values TEXT FAILED-P)."
  (answer (exchange (nlk:make-json-object "op" "command" "session" session
                                           "name" "re" "args" (nlk:trimmed (or line ""))))))

;;; --- the catalog, read ------------------------------------------------------------

(defun catalog-tools ()
  "The engine's tools as a list of JSON objects, in the order it registers them."
  (coerce (or (nlk:json-value (catalog) :array "tools") #()) 'list))

(defun first-sentence (text)
  "TEXT up to its first full stop, on one line."
  (let* ((text (substitute #\Space #\Newline (or text "")))
         (stop (search ". " text)))
    (if stop (subseq text 0 (1+ stop)) text)))

(defun schema-type (schema)
  "What a parameter takes, in a word."
  (let ((options (nlk:json-value schema :array "enum"))
        (type (nlk:json-value schema :string "type")))
    (cond (options (format nil "one of ~{~s~^, ~}" (coerce options 'list)))
          (type type)
          (t "value"))))

(defun parameter-lines (tool)
  "One line per parameter of TOOL: how eval names it, what it takes, what it means."
  (let* ((schema (nlk:json-value tool :object "parameters"))
         (properties (nlk:json-value schema :object "properties"))
         (required (coerce (or (nlk:json-value schema :array "required") #()) 'list))
         (lines '()))
    (when properties
      (maphash (lambda (name property)
                 (push (format nil "  :~a  ~a~:[~;, required~]~@[ — ~a~]"
                               (substitute #\- #\_ name)
                               (schema-type property)
                               (member name required :test #'string=)
                               (nlk:json-value property :string "description"))
                       lines))
               properties))
    (nreverse lines)))

;;; --- the verbs --------------------------------------------------------------------

(define-verb open (path &rest options &key &allow-other-keys)
  "Open the binary at PATH for this session and analyze it; every other verb
acts on the binary opened last. The keys :ARCH, :BITS, :BASE, :MAP and
:FORMAT force how a raw or headerless file is loaded."
  ;; DEFINE-VERB opens the body with the not-running refusal, so there is no
  ;; place for a declaration: the keys ride in OPTIONS and the engine's own
  ;; schema says which it takes.
  (tool-text "open_binary"
             (wire-arguments (list* :path (session-path path (session-id)) options))))

(define-verb cmd (command &optional addr)
  "Run one read-only rizin COMMAND on the open binary, at ADDR when given —
the one way to read it. (re:cmd \"\") answers the engine's manual."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (tool-text "rizin_command" (wire-arguments (list :command command :addr addr))))

(defun evidence-id (text)
  "The id in TEXT's trailing [evidence xxxxxxxx ...] tag, or NIL."
  (let ((tag (search "[evidence " text :from-end t)))
    (and tag
         (<= (+ tag 18) (length text))
         (subseq text (+ tag 10) (+ tag 18)))))

(defun whole-output (text)
  "TEXT, or — when the engine cut it at its size cap — the file it says
holds all of it."
  (let* ((mark "Full output: ")
         (at (search mark text))
         (end (and at (position #\] text :start at)))
         (file (and end (probe-file (subseq text (+ at (length mark)) end)))))
    (if file (uiop:read-file-string file) text)))

(define-verb json (command &optional addr)
  "Run one read-only rizin COMMAND whose output is JSON — a *j command —
and answer the data itself: objects as EQUAL hash tables, arrays as vectors
=> (values DATA EVIDENCE-ID). Reads the whole output even when it is past
the size cap a result is cut at."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (let* ((text (tool-text "rizin_command" (wire-arguments (list :command command :addr addr))))
         (whole (whole-output text))
         ;; The first line is the header; DECODE-JSON reads the one value after it.
         (body (subseq whole (1+ (or (position #\Newline whole) -1)))))
    (values (handler-case (nlk:decode-json body)
              (error ()
                (fail "~a did not answer JSON; read it with (re:cmd ~s) instead" command command)))
            (evidence-id text))))

(define-verb call (tool &rest arguments)
  "Call the engine's TOOL — a name (re:tools) lists — with keyword
ARGUMENTS: (re:call \"set_comment\" :addr \"main\" :text \"entry\")."
  (unless (stringp tool)
    (fail "a tool is named by a string, as (re:tools) lists them, not ~s" tool))
  (tool-text (substitute #\_ #\- tool) (wire-arguments arguments)))

(define-verb tools ()
  "Every tool the engine offers, one line each."
  (format nil "~{~a~^~%~}"
          (mapcar (lambda (tool)
                    (format nil "~a — ~a"
                            (nlk:json-value tool :string "name")
                            (first-sentence (nlk:json-value tool :string "description"))))
                  (catalog-tools))))

(define-verb doc (tool)
  "What the engine's TOOL does and the keyword arguments it takes."
  (let* ((name (substitute #\_ #\- (string tool)))
         (found (find name (catalog-tools)
                      :key (lambda (entry) (nlk:json-value entry :string "name"))
                      :test #'equal)))
    (unless found
      (fail "no tool is named ~s; (re:tools) lists them" name))
    (format nil "~a~%~a~%(re:call ~s ...) takes:~%~{~a~^~%~}"
            name
            (nlk:json-value found :string "description")
            name
            (or (parameter-lines found) '("  nothing")))))

(define-verb slash (line)
  "Run one /re line — \"functions\", \"evidence\", \"findings\", \"verify\",
\"report out.md\", \"undo\", \"help\" — and answer what it says."
  (multiple-value-bind (text failed) (command-text line)
    (if failed (fail "~a" text) text)))

(define-verb status ()
  "The engine's state for this session: rizin, the open binary, evidence and findings."
  (values (command-text "status")))

;;; --- the same tools, top-level ------------------------------------------------------
;;; For the operator who sets surface to "tools": every engine tool becomes a
;;; tool of its own, named re_<name>, its schema the engine's own.

(defun surface-name (name)
  (concatenate 'string "re_" name))

(defun run-surface-tool (name arguments)
  "One top-level call => the text, recorded failed when the engine says so."
  (handler-case
      (multiple-value-bind (text failed)
          (tool-answer name (if (hash-table-p arguments) arguments (nlk:make-json-object)))
        (if failed (nle:failure text) text))
    (re-error (condition)
      (nle:failure (format nil "ERROR: ~a" condition)))))

(defun register-surface-tools ()
  "Register every engine tool => the names registered."
  (loop for tool in (catalog-tools)
        for name = (nlk:json-value tool :string "name")
        for registered = (surface-name name)
        do (let ((name name))
             (nle:register-tool registered
                                (list :description (or (nlk:json-value tool :string "description") name)
                                      :parameters (or (nlk:json-value tool :object "parameters")
                                                      (nlk:make-json-object "type" "object")))
                                (lambda (arguments) (run-surface-tool name arguments))))
        collect registered))
