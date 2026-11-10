;;;; verbs.lisp --- what the model calls from eval.
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
;;;; and the model reads why. Each call goes through CALL-TOOL: audited and,
;;;; when it observes the binary, recorded as evidence — the
;;;; `[evidence xxxxxxxx]' tag at the end of a result is what record_finding
;;;; cites.

(in-package #:nodecode-re)

;;; --- the session a call is for ----------------------------------------------------

(defun current-session ()
  "The running turn's session — which the engine keys its rizin process, its
open binary and its record by — or the one called \"default\" outside a turn."
  (find-session (or (getf (nle:turn) :session-id) "default")))

(defun session-path (path session-id)
  "PATH as the model wrote it — ~/ and all — read against the session's
directory when it is relative."
  (unless (and (stringp path) (not (blank-p path)))
    (fail "a path must be a non-empty string, not ~s" path))
  (let ((path (nlk:expand-home path)))
    (native
     (if (uiop:absolute-pathname-p path)
         path
         (let ((directory (ignore-errors (nlk:find-session-cwd session-id))))
           (if directory
               (merge-pathnames path (uiop:ensure-directory-pathname directory))
               path))))))

;;; --- Lisp arguments onto the engine's JSON ------------------------------------------

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
        ((or (listp value) (vectorp value)) (map 'simple-vector #'wire-value value))
        ((realp value) value)
        (t (fail "~s has no JSON form: pass a string, a number, T, :false, or a list of those" value))))

(defun wire-arguments (plist)
  "The JSON object a keyword PLIST of tool arguments spells. A NIL value is a
parameter left out — false is :FALSE, an empty array is #()."
  (unless (evenp (length plist))
    (fail "tool arguments are keyword and value pairs; ~s has an odd one out" plist))
  (let ((object (obj)))
    (loop for (key value) on plist by #'cddr
          do (unless (or (keywordp key) (stringp key))
               (fail "a tool argument is named by a keyword, not ~s" key))
             (unless (null value)
               (setf (gethash (wire-key key) object) (wire-value value))))
    object))

;;; --- one call ---------------------------------------------------------------------

(defun tool-text (name arguments)
  "The text of one tool call for the current session, or RE-ERROR carrying
it when the call failed."
  (multiple-value-bind (text failed) (call-tool (current-session) name arguments)
    (if failed (fail "~a" text) text)))

(defun first-sentence (text)
  "TEXT up to its first full stop, on one line."
  (let* ((text (substitute #\Space #\Newline (or text "")))
         (stop (search ". " text)))
    (if stop (subseq text 0 (1+ stop)) text)))

(defun parameter-lines (tool)
  "One line per parameter of TOOL: how eval names it, what it takes, what it means."
  (loop for (name type . options) in (tool-parameters tool)
        collect (format nil "  :~a  ~a~:[~;, required~]~@[ — ~a~]"
                        (substitute #\- #\_ name)
                        (let ((enum (getf options :enum)))
                          (if enum
                              (format nil "one of ~{~a~^, ~}" (mapcar #'json-encode enum))
                              (ecase type
                                (:string "string") (:integer "integer") (:number "number")
                                (:boolean "t or :false") (:strings "list of strings"))))
                        (getf options :required)
                        (getf options :doc))))

;;; --- the verbs --------------------------------------------------------------------

(define-verb open (path &rest options &key &allow-other-keys)
  "Open the binary at PATH for this session and analyze it; every other verb
acts on the binary opened last. The keys :ARCH, :BITS, :BASE, :MAP and
:FORMAT force how a raw or headerless file is loaded."
  ;; DEFINE-VERB opens the body with the not-running refusal, so there is no
  ;; place for a declaration: the keys ride in OPTIONS and the tool's own
  ;; parameters say which it takes.
  (tool-text "open_binary"
             (wire-arguments
              (list* :path (session-path path (getf (nle:turn) :session-id)) options))))

(define-verb cmd (command &optional addr)
  "Run one read-only rizin COMMAND on the open binary, at ADDR when given —
the one way to read it. (re:cmd \"\") answers the engine's manual."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (tool-text "rizin_command" (wire-arguments (list :command command :addr addr))))

(defun evidence-id-of (text)
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
         (whole (and end (read-text-file (subseq text (+ at (length mark)) end)))))
    (or whole text)))

(define-verb json (command &optional addr)
  "Run one read-only rizin COMMAND whose output is JSON — a *j command —
and answer the data itself: objects as EQUAL hash tables, arrays as vectors
=> (values DATA EVIDENCE-ID). Reads the whole output even when it is past
the size cap a result is cut at."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (let* ((text (tool-text "rizin_command" (wire-arguments (list :command command :addr addr))))
         (whole (whole-output text))
         ;; The first line is the header; the one value after it is the data.
         (body (subseq whole (1+ (or (position #\Newline whole) -1)))))
    (values (handler-case (json-decode body)
              (json-refusal ()
                (fail "~a did not answer JSON; read it with (re:cmd ~s) instead" command command)))
            (evidence-id-of text))))

(define-verb call (tool &rest arguments)
  "Call the engine's TOOL — a name (re:tools) lists — with keyword
ARGUMENTS: (re:call \"set_comment\" :addr \"main\" :text \"entry\")."
  (unless (stringp tool)
    (fail "a tool is named by a string, as (re:tools) lists them, not ~s" tool))
  (tool-text (substitute #\_ #\- tool) (wire-arguments arguments)))

(define-verb tools ()
  "Every tool the engine offers, one line each."
  (join-lines (mapcar (lambda (tool)
                        (format nil "~a — ~a" (tool-name tool) (first-sentence (tool-description tool))))
                      (offered-tools))))

(define-verb doc (tool)
  "What the engine's TOOL does and the keyword arguments it takes."
  (let* ((name (substitute #\_ #\- (string-downcase (string tool))))
         (found (find-tool name)))
    (unless found
      (fail "no tool is named ~s; (re:tools) lists them" name))
    (format nil "~a~%~a~%(re:call ~s ...) takes:~%~{~a~^~%~}"
            name (tool-description found) name
            (or (parameter-lines found) '("  nothing")))))

(define-verb slash (line)
  "Run one /re line — \"functions\", \"evidence\", \"findings\", \"verify\",
\"report out.md\", \"undo\", \"help\" — and answer what it says."
  (multiple-value-bind (text failed) (run-slash-line (current-session) (or line ""))
    (if failed (fail "~a" text) text)))

(define-verb status ()
  "The engine's state for this session: rizin, the open binary, evidence and findings."
  (values (run-slash-line (current-session) "status")))
