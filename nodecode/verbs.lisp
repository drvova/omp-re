;;;; verbs.lisp --- what the model calls from eval.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; nodecode's model has one tool, eval, and the engine's design is the same
;;;; idea from the other side: one tool to read the binary and a handful of
;;;; stateful ones, composed in code rather than listed as schemas. So the
;;;; native surface here is verbs — (re:open ...), (re:cmd ...), (re:call
;;;; ...) — that an eval form loops over, filters and defines helpers around,
;;;; and what the model defines that way the organism keeps.
;;;;
;;;; Every verb answers a string, but (re:json ...), which answers a *j
;;;; command's output already decoded. The verbs are a thin user of the
;;;; engine's surface (engine.lisp): each is one ENGINE-CALL or
;;;; ENGINE-COMMAND for the running turn's session, and an answer that
;;;; failed is RE-ERROR carrying the engine's own words, so eval marks the
;;;; form failed and the model reads why.

(in-package #:nodecode-re)

;;; --- Lisp arguments onto the engine's JSON ------------------------------------------

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
               (setf (gethash (engine-name key) object) (wire-value value))))
    object))

;;; --- one call ---------------------------------------------------------------------

(defun answer-text (answer)
  "The text of an engine ANSWER, or RE-ERROR carrying it when it failed."
  (if (jget answer "failed")
      (fail "~a" (jstring answer "text"))
      (jstring answer "text")))

(defun call-for-turn (name arguments)
  (engine-call (turn-session-id) name (wire-arguments arguments)))

(defun first-sentence (text)
  "TEXT up to its first full stop, on one line."
  (let* ((text (substitute #\Space #\Newline (or text "")))
         (stop (search ". " text)))
    (if stop (subseq text 0 (1+ stop)) text)))

(defun parameter-lines (schema)
  "One line per property of a tool's JSON SCHEMA: how eval names it, what it
takes, what it means."
  (let ((required (jlist schema "required")))
    (loop for name being the hash-keys of (jget schema "properties") using (hash-value property)
          collect (format nil "  :~a  ~a~:[~;, required~]~@[ — ~a~]"
                          (substitute #\- #\_ name)
                          (let ((enum (jlist property "enum"))
                                (type (jstring property "type")))
                            (cond (enum (format nil "one of ~{~a~^, ~}" (mapcar #'json-encode enum)))
                                  ((equal type "boolean") "t or :false")
                                  ((equal type "array") "list of strings")
                                  (t type)))
                          (member name required :test #'equal)
                          (jstring property "description")))))

;;; --- the verbs --------------------------------------------------------------------

(define-verb open (path &rest options &key &allow-other-keys)
  "Open the binary at PATH for this session and analyze it; every other verb
acts on the binary opened last. The keys :ARCH, :BITS, :BASE, :MAP and
:FORMAT force how a raw or headerless file is loaded."
  ;; DEFINE-VERB opens the body with the not-running refusal, so there is no
  ;; place for a declaration: the keys ride in OPTIONS and the tool's own
  ;; parameters say which it takes.
  (unless (and (stringp path) (not (blank-p path)))
    (fail "a path must be a non-empty string, not ~s" path))
  (answer-text (call-for-turn "open_binary" (list* :path path options))))

(define-verb cmd (command &optional addr)
  "Run one read-only rizin COMMAND on the open binary, at ADDR when given —
the one way to read it. (re:cmd \"\") answers the engine's manual."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (answer-text (call-for-turn "rizin_command" (list :command command :addr addr))))

(define-verb json (command &optional addr)
  "Run one read-only rizin COMMAND whose output is JSON — a *j command —
and answer the data itself: objects as EQUAL hash tables, arrays as vectors
=> (values DATA EVIDENCE-ID). Reads the whole output even when it is past
the size cap a result is cut at."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (let ((answer (call-for-turn "rizin_command" (list :command command :addr addr))))
    (answer-text answer)
    (values (handler-case (json-decode (trimmed (jstring answer "raw")))
              (json-refusal ()
                (fail "~a did not answer JSON; read it with (re:cmd ~s) instead" command command)))
            (and (jstring answer "evidenceId") (shown-id (jstring answer "evidenceId"))))))

(define-verb call (tool &rest arguments)
  "Call the engine's TOOL — a name (re:tools) lists — with keyword
ARGUMENTS: (re:call \"set_comment\" :addr \"main\" :text \"entry\")."
  (unless (stringp tool)
    (fail "a tool is named by a string, as (re:tools) lists them, not ~s" tool))
  (answer-text (call-for-turn (engine-name tool) arguments)))

(define-verb tools ()
  "Every tool the engine offers, one line each."
  (join-lines (map 'list
                   (lambda (tool)
                     (format nil "~a — ~a" (jstring tool "name")
                             (first-sentence (jstring tool "description"))))
                   (engine-tools))))

(define-verb doc (tool)
  "What the engine's TOOL does and the keyword arguments it takes."
  (let* ((name (engine-name tool))
         (found (find name (engine-tools) :key (lambda (tool) (jstring tool "name")) :test #'string=)))
    (unless found
      (fail "no tool is named ~s; (re:tools) lists them" name))
    (format nil "~a~%~a~%(re:call ~s ...) takes:~%~{~a~^~%~}"
            name (jstring found "description") name
            (or (parameter-lines (jget found "parameters")) '("  nothing")))))

(define-verb slash (line)
  "Run one /re line — \"functions\", \"evidence\", \"findings\", \"verify\",
\"report out.md\", \"undo\", \"help\" — and answer what it says."
  (answer-text (engine-command (turn-session-id) (or line "") :by-model t)))

(define-verb status ()
  "The engine's state for this session: rizin, the open binary, evidence and findings."
  (answer-text (engine-command (turn-session-id) "status" :by-model t)))
