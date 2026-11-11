;;;; annotate.lisp --- the annotations: what they mean to rizin, the tools that
;;;; make them, /re undo, and their replay into a fresh process.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; An annotation is the analyst's edit to rizin's picture of the binary: a
;;;; rename, a comment, a type, a hint. It lives in the rizin process's memory
;;;; and nowhere else, so the record is what keeps it: one re.annotation entry
;;;; for each, carrying the value it replaced and the value that landed, and
;;;; one re.undo entry for each one taken back. ANNOTATION-COMMANDS is the
;;;; single place that says what "make this annotation's value X" is in rizin
;;;; commands; the tools (X = what was asked), /re undo (X = the old value)
;;;; and the replay into a fresh process (X = the new value) all go through
;;;; it, so a command template cannot drift between the three.
;;;;
;;;; Every tool follows one sequence: resolve, read the old value, write, read
;;;; back, verify, record. The old value is the pre-read and the new value the
;;;; read-back — never the request — so a tool cannot claim a value that did
;;;; not land; a mismatch is a refusal that says what rizin actually holds.

(in-package #:omp-re)

;;; --- what may reach the pipe ---------------------------------------------------------
(defun full-match-p (regex text)
  "Whether REGEX — written without anchors — matches all of TEXT."
  (and (stringp text) (js-scan (format nil "^(?:~a)$" regex) text)))

(defun js-split (text separator limit)
  "TEXT split on the character SEPARATOR as JavaScript's split with a limit
does: at most LIMIT pieces, the ones past it dropped, not folded into the last."
  (let ((pieces (uiop:split-string text :separator (list separator))))
    (subseq pieces 0 (min limit (length pieces)))))

;;; --- the kinds -------------------------------------------------------------------------

(defparameter +hint-spec+
  '(("immediate_base" "ahi" "immbase")
    ("opcode_type" "aho" "type")
    ("opcode_size" "ahs" "size")
    ("jump_target" "ahc" "jump")
    ("return_value" "ahr" "ret"))
  "The analysis hints set_hint can set: (KIND COMMAND KEY), each a one-letter
`ah' command and the key it shows under in `ahl.j'. The arch and bits hints
have their own tool; the delete-region, highlight and esil forms stay out.")

(defparameter +hint-kinds+ (mapcar #'first +hint-spec+))

(defun int-arg (key value)
  "VALUE when it is a positive integer: a data, string or format size."
  (unless (and (full-match-p "[0-9]+" value) (string/= value "0"))
    (fail "omp-re: invalid ~a: ~a — a positive integer" key (js-string value)))
  value)

(defun hint-value-arg (kind value)
  "VALUE as the argument of the hint KIND, so a malformed hint fails here,
not at rizin."
  (let ((v (trimmed value)))
    (cond ((string= kind "immediate_base")
           ;; The documented inputs, plus the numeric codes `ahl.j' reads back
           ;; (11, 32, 80, ...), so an undo or a replay round-trips.
           (unless (full-match-p "[0-9]+u?|d|du|[bohipSs]" v)
             (fail "omp-re: invalid immediate_base: ~a — one of 2, 8, 10, 10u, 16, b, o, h, i, p, S, s"
                   (js-string value)))
           v)
          ((string= kind "opcode_type")
           (unless (full-match-p "[a-z][a-z0-9]*" v)
             (fail "omp-re: invalid opcode_type: ~a — a lowercase opcode type such as call, jmp, ret, nop, mov"
                   (js-string value)))
           v)
          ((string= kind "opcode_size") (int-arg "opcode_size" v))
          ((string= kind "jump_target") (validate-addr v))
          ((string= kind "return_value")
           (unless (full-match-p "0x[0-9a-fA-F]+|[0-9]+" v)
             (fail "omp-re: invalid return_value: ~a — a decimal or 0x-hex integer" (js-string value)))
           v)
          (t (fail "omp-re: unknown hint kind: ~a" kind)))))

(defun data-mark-args (encoded)
  "The arguments of `Cd' from <size> or <size>:<repeat>."
  (destructuring-bind (&optional (size "") repeat) (js-split encoded #\: 2)
    (if repeat
        (format nil "~a ~a" (int-arg "size" size) (int-arg "repeat" repeat))
        (int-arg "size" size))))

(defun format-mark-args (encoded)
  "The arguments of `Cf' from `<size> <pf-format[ fields...]>'. The format
reaches rizin unquoted, so it is held to a charset with no separator in it."
  (let ((space (position #\Space encoded)))
    (unless space
      (fail "omp-re: set_format needs a size and a pf format, e.g. `8 xxdd field1 field2`"))
    (let ((size (int-arg "size" (subseq encoded 0 space)))
          (format (trimmed (subseq encoded (1+ space)))))
      (unless (full-match-p "[A-Za-z0-9_ .*\\[\\]]+" format)
        (fail "omp-re: invalid pf format: ~a" (js-string format)))
      (format nil "~a ~a" size format))))

(defun arch-hint-commands (encoded at)
  "The `aha <arch>' and `ahb <bits>' commands an encoded arch hint
(`arch=arm;bits=16') spells, each part checked."
  (let ((commands '()))
    (dolist (part (uiop:split-string encoded :separator '(#\;)))
      (destructuring-bind (&optional key value) (js-split part #\= 2)
        (cond ((equal key "arch")
               (push (format nil "aha ~a ~a" (validate-ident "arch" (or value "")) at) commands))
              ((equal key "bits")
               (unless (member value '("8" "16" "32" "64") :test #'equal)
                 (fail "omp-re: invalid arch hint bits: ~a — one of 8, 16, 32, 64"
                       (if value (js-string value) "undefined")))
               (push (format nil "ahb ~a ~a" value at) commands))
              (t (fail "omp-re: invalid arch hint ~a — use arch=<name> and/or bits=<n>" (js-string part))))))
    (unless commands
      (fail "omp-re: set_arch_hint needs arch and/or bits"))
    (nreverse commands)))

(defun define-variable-commands (name encoded at)
  "The `afvs' or `afvr' command that creates the variable NAME from an
encoded `<storage> <location> [<type>]' (`stack 0x30 char *', `reg rdi int').
The type may hold spaces; rizin strips the trailing `@ <ea>' seek before the
command sees its arguments, so the seek never reaches the type."
  (let* ((space (position #\Space encoded))
         (storage (if space (subseq encoded 0 space) encoded))
         (rest (if space (trimmed (subseq encoded (1+ space))) ""))
         (space (position #\Space rest))
         (location (if space (subseq rest 0 space) rest))
         (type (if space (trimmed (subseq rest (1+ space))) "")))
    (when (string= location "")
      (fail "omp-re: define_variable needs a location (a stack delta or a register)"))
    ;; The type is single-quoted, as afvt, avga and afs quote theirs:
    ;; VALIDATE-TYPE-LIKE still lets `>', `<' and `@' through, which would
    ;; redirect or seek through the pipe; quoted, the whole type is text.
    (let ((type-arg (if (string= type "")
                        ""
                        (format nil " ~a" (rz-quote (validate-type-like "type" type))))))
      (cond ((string= storage "stack")
             (unless (full-match-p "-?(?:0x[0-9a-fA-F]+|[0-9]+)" location)
               (fail "omp-re: invalid stack delta: ~a — a decimal or 0x-hex offset" (js-string location)))
             (list (format nil "afvs ~a ~a~a ~a" location name type-arg at)))
            ((string= storage "reg")
             (list (format nil "afvr ~a ~a~a ~a" (validate-ident "reg" location) name type-arg at)))
            (t (fail "omp-re: invalid variable storage: ~a — stack or reg" (js-string storage)))))))

(defun annotation-commands (kind ea to from &optional target)
  "The rizin commands that set the annotation KIND at EA to the value TO.
FROM is the value being replaced — rename_variable and set_flag address what
is there by its current name. TARGET is the one identifier a kind needs
beyond those: the variable's or global's name, or which hint. An empty TO is
the annotation taken away, which is what an undo onto nothing asks for."
  (let ((at (format nil "@ ~a" (validate-addr ea)))
        (to (or to ""))
        (from (or from "")))
    (flet ((kind-p (name) (string= kind name))
           (target (what)
             (or (and target (string/= target "") target)
                 (fail "omp-re: ~a annotation is missing the ~a" kind what))))
      (cond
        ((kind-p "rename_function")
         (list (format nil "afn ~a ~a" (rz-quote (validate-ident "name" to)) at)))
        ((kind-p "rename_variable")
         (list (format nil "afvn ~a ~a ~a" (rz-quote (validate-ident "name" to))
                       (rz-quote (validate-ident "name" from)) at)))
        ((kind-p "set_comment")
         ;; rizin's CC appends to a comment already there, so a replace is
         ;; always clear, then write.
         (if (string= to "")
             (list (format nil "CC- ~a" at))
             (list (format nil "CC- ~a" at)
                   (format nil "CC ~a ~a" (rz-quote (validate-text to)) at))))
        ((kind-p "set_prototype")
         ;; Empty only when undoing onto a function rizin had no signature
         ;; for: there is nothing to restore.
         (if (string= to "")
             '()
             (list (format nil "afs ~a ~a" (rz-quote (validate-type-like "sig" to)) at))))
        ((kind-p "set_variable_type")
         (let ((name (target "variable name")))
           (if (string= to "")
               '()
               (list (format nil "afvt ~a ~a ~a" (rz-quote (validate-ident "var" name))
                             (rz-quote (validate-type-like "type" to)) at)))))
        ((kind-p "define_variable")
         ;; TO encodes `<storage> <location> [<type>]'; afv- deletes by name.
         (let ((name (validate-ident "name" (target "variable name"))))
           (if (string= to "")
               (list (format nil "afv- ~a ~a" name at))
               (define-variable-commands name to at))))
        ((kind-p "define_global")
         ;; TO is the C type. avga adds a global at EA; avgm deletes it by
         ;; name, so it takes no seek. The type is quoted so `char *' and
         ;; `unsigned int' pass as one argument.
         (let ((name (validate-ident "name" (target "variable name"))))
           (if (string= to "")
               (list (format nil "avgm ~a" name))
               (list (format nil "avga ~a ~a ~a" name (rz-quote (validate-type-like "type" to)) at)))))
        ((kind-p "define_function")
         ;; TO is the name rizin gave the function when one should exist.
         (list (format nil "~:[af~;af-~] ~a" (string= to "") at)))
        ((kind-p "set_calling_convention")
         ;; A function always has some convention, so neither side is empty.
         (list (format nil "afc ~a ~a" (validate-ident "cc" to) at)))
        ((kind-p "set_flag")
         ;; The flag at EA is to be named TO and was named FROM: drop the old
         ;; name, add the new. Either side may be empty — no flag.
         (append (unless (string= from "")
                   (list (format nil "f- ~a" (validate-ident "flag" from))))
                 (unless (string= to "")
                   (list (format nil "f ~a ~a" (validate-ident "flag" to) at)))))
        ((kind-p "set_arch_hint")
         (if (string= to "")
             (list (format nil "aha- ~a" at) (format nil "ahb- ~a" at))
             (arch-hint-commands to at)))
        ((kind-p "set_hint")
         ;; Which hint rides in TARGET, so an undo can delete the right one
         ;; even though its value is empty.
         (let* ((hint (target "hint kind"))
                (spec (or (assoc hint +hint-spec+ :test #'string=)
                          (fail "omp-re: unknown hint kind: ~a" hint))))
           (if (string= to "")
               (list (format nil "~a- ~a" (second spec) at))
               (list (format nil "~a ~a ~a" (second spec) (hint-value-arg hint to) at)))))
        ((kind-p "set_data")
         (if (string= to "")
             (list (format nil "Cd- ~a" at))
             (list (format nil "Cd ~a ~a" (data-mark-args to) at))))
        ((kind-p "set_string")
         ;; TO is a byte size, or "auto" for rizin to find encoding and length.
         (cond ((string= to "") (list (format nil "Cs- ~a" at)))
               ((string= to "auto") (list (format nil "Cs ~a" at)))
               (t (list (format nil "Cs ~a ~a" (int-arg "size" to) at)))))
        ((kind-p "set_format")
         (if (string= to "")
             (list (format nil "Cf- ~a" at))
             (list (format nil "Cf ~a ~a" (format-mark-args to) at))))
        (t (fail "omp-re: unknown annotation kind: ~a" kind))))))

;;; --- what is in effect ---------------------------------------------------------------------

(defun live-annotation-entries (binary-path &optional (session *session*))
  "The annotations recorded against BINARY-PATH and not since undone, oldest
first, each as (ENTRY-ID . DATA) — the id is what /re undo marks. An
annotation belongs to whichever binary the last re.binary before it opened,
so a session that opens another never replays one binary's renames onto it."
  (let ((undone (make-hash-table :test #'equal))
        (live '())
        (current nil))
    (dolist (marker (entries-of "re.undo" session))
      (let ((id (jstring marker "undidEntryId")))
        (when id (setf (gethash id undone) t))))
    (loop for entry across (session-entries session)
          for type = (jstring entry "customType")
          for data = (jget entry "data")
          do (cond ((equal type "re.binary")
                    (setf current (jstring data "path")))
                   ((and (equal type "re.annotation")
                         (equal current binary-path)
                         (not (gethash (jstring entry "id") undone))
                         (jstring data "kind")
                         (jstring data "ea"))
                    (push (cons (jstring entry "id")
                                (obj "kind" (jstring data "kind")
                                     "ea" (jstring data "ea")
                                     "oldValue" (or (jstring data "oldValue") "")
                                     "newValue" (or (jstring data "newValue") "")
                                     "target" (or (jstring data "target") :absent)
                                     "evidenceId" (or (jstring data "evidenceId") :absent)
                                     "ungrounded" (multiple-value-bind (value present)
                                                      (gethash "ungrounded" data)
                                                    (if present value :absent))))
                          live))))
    (nreverse live)))

(defun live-annotations (binary-path &optional (session *session*))
  "The annotations in effect for BINARY-PATH — recorded and not undone — as
a list of their data objects, in the order made."
  (mapcar #'cdr (live-annotation-entries binary-path session)))

(defun annotation-fingerprint (session binary-path)
  "The identity of the set of annotations in effect: two records with the
same fingerprint need the same rizin state."
  (format nil "~{~a~^,~}" (mapcar #'car (live-annotation-entries binary-path session))))

(defun apply-commands (rz commands)
  (dolist (command commands)
    (rz-cmd rz command)))

(defun replay-annotations (session rz binary-path)
  "Put the annotations in effect back into the freshly analyzed RZ, in
order => (values FAILURES APPLIED): a line for each that no longer applies —
rizin's analysis changed between versions — and how many went in. One that
fails does not stop the rest."
  (let ((failures '())
        (applied 0))
    (dolist (data (live-annotations binary-path session))
      (handler-case
          (progn
            (apply-commands rz (annotation-commands (jstring data "kind") (jstring data "ea")
                                                    (jstring data "newValue") (jstring data "oldValue")
                                                    (jstring data "target")))
            (incf applied))
        (error (condition)
          (push (format nil "~a @ ~a: ~a" (jstring data "kind") (jstring data "ea") condition)
                failures))))
    (values (nreverse failures) applied)))

(contribute "annotations" :order 60 :noun "annotation(s)"
  :replay #'replay-annotations
  :fingerprint #'annotation-fingerprint
  :status (lambda (session)
            (let ((binary-path (session-binary-path session)))
              (when binary-path
                (list (format nil "annotations in effect: ~d"
                              (length (live-annotations binary-path session))))))))

;;; --- reading rizin's side ------------------------------------------------------------------

(defun row-offset (row)
  "The address in a rizin JSON ROW: most say `offset', a few `addr'."
  (or (jnumber row "addr") (jnumber row "offset")))

(defun first-row (value)
  (and (vectorp value) (not (stringp value)) (plusp (length value)) (aref value 0)))

(defun function-at (rz addr)
  "The function containing ADDR => (values START-EA NAME). An annotation
keys on the start address, so it stays addressable after the name it was
asked by is gone: a rename can retire the old flag."
  (let* ((numeric (ea-from-offset (resolve-numeric-addr rz (validate-addr addr))))
         (row (first-row (rz-cmdj rz (format nil "afij @ ~a" numeric))))
         (start (and row (row-offset row)))
         (name (and row (jstring row "name"))))
    (unless (and start name)
      (fail "omp-re: no function at ~a" addr))
    (values (ea-from-offset start) name)))

(defun resolved-ea (rz addr)
  (ea-from-offset (resolve-numeric-addr rz (validate-addr addr))))

(defun variables-at (rz ea)
  "Every variable of the function at EA: `afvlj' groups them by storage kind
({stack: [...], reg: [...]}), and this is all the groups, flattened."
  (let ((grouped (rz-cmdj rz (format nil "afvlj @ ~a" ea))))
    (when (hash-table-p grouped)
      (loop for group being the hash-values of grouped
            when (and (vectorp group) (not (stringp group)))
              append (remove-if-not (lambda (variable)
                                      (and (jstring variable "name") (jstring variable "type")))
                                    (coerce group 'list))))))

(defun variable-named (name variables)
  (find name variables :key (lambda (variable) (jstring variable "name")) :test #'string=))

(defun signature-at (rz ea)
  "The stored signature of the function at EA; `afs' prints it with a trailing `;'."
  (ppcre:regex-replace ";\\s*\\z" (trimmed (rz-cmd rz (format nil "afs @ ~a" ea))) ""))

(defun function-starting-at (rz ea)
  "The `afij' row of the function that starts exactly at EA, or NIL: `afij'
answers the function containing an address, which may start earlier."
  (let ((row (first-row (rz-cmdj rz (format nil "afij @ ~a" ea)))))
    (and row
         (row-offset row)
         (string= ea (ea-from-offset (row-offset row)))
         row)))

(defun calling-convention-at (rz ea)
  (trimmed (rz-cmd rz (format nil "afc @ ~a" ea))))

(defun flag-at (rz ea)
  "The name of the flag at EA, or the empty string."
  (or (jstring (rz-cmdj rz (format nil "fdj @ ~a" ea)) "name") ""))

(defun hints-at (rz ea)
  "The hints at EA as `ahl.j' lists them ([{addr, arch?, bits?, immbase?,
type?, size?, jump?, ret?}]): the first row, or NIL when there is none."
  (let ((row (first-row (rz-cmdj rz (format nil "ahl.j @ ~a" ea)))))
    (and (hash-table-p row) row)))

(defun js-number (number)
  "NUMBER as JavaScript prints it: an integral value has no fraction."
  (cond ((integerp number) (format nil "~d" number))
        ((= number (ffloor number)) (format nil "~d" (round number)))
        (t (string-downcase (format nil "~f" number)))))

(defun hint-value-at (rz ea kind)
  "The value of the analysis hint KIND at EA as a canonical string, or the
empty string when it is unset."
  (let* ((key (third (assoc kind +hint-spec+ :test #'string=)))
         (raw (jget (hints-at rz ea) key)))
    (cond ((null raw) "")
          ;; `jump' reads back as a number; an undo or a replay sends it as hex.
          ((and (string= kind "jump_target") (integerp raw)) (ea-from-offset raw))
          ((stringp raw) raw)
          ((realp raw) (js-number raw))
          ((eq raw t) "true")
          (t (json-encode raw)))))

(defun global-named (rz name)
  "The global variable called NAME as `avglj' lists it, or NIL."
  (let ((global (find name (jlist (rz-cmdj rz "avglj"))
                      :key (lambda (global) (jstring global "name")) :test #'equal)))
    (and global (jstring global "type") global)))

(defun meta-at (rz ea type)
  "The metadata item of TYPE (`Cd', `Cs', `Cf') at EA, or NIL: `C.j' lists
everything marked at an address."
  (find type (jlist (rz-cmdj rz (format nil "C.j @ ~a" ea)))
        :key (lambda (meta) (jstring meta "type")) :test #'equal))

(defun normalize-c-type (value)
  "VALUE with rizin's own cosmetic re-punctuation — spacing, a trailing `;' —
taken out, and nothing else: a semantic difference still compares unequal."
  (ppcre:regex-replace-all "\\s+" (ppcre:regex-replace ";+\\s*\\z" (trimmed value) "") ""))

(defun js-or-null (value)
  "VALUE as the engine's messages quote what rizin has: null when it has nothing."
  (if (or (null value) (equal value "")) "null" (json-encode value)))

;;; --- recording ---------------------------------------------------------------------------------

(defun record-annotation (kind ea old-value new-value &optional target)
  "Append the re.annotation entry — grounded by the latest evidence at the
same address, when there is any — say that rizin now matches the record, and
answer what the model reads."
  (let ((evidence (or (evidence-id-at ea) "")))
    (append-entry "re.annotation"
                  (obj "kind" kind
                       "ea" ea
                       "oldValue" old-value
                       "newValue" new-value
                       "target" (or target :absent)
                       "evidenceId" evidence
                       "ungrounded" (and (string= evidence "") t)))
    (mark-applied "annotations")
    (plain-result (format nil "~a: ~@[~a: ~]~a -> ~a @ ~a"
                          kind target (js-string old-value) (js-string new-value) ea)
                  ea)))

(defun positive-integer (tool value)
  "VALUE as an integer when it is a positive whole number, as a JSON number
may spell one (4 or 4.0); a refusal in TOOL's name otherwise."
  (let ((whole (and (realp value) (= value (ffloor value)) (round value))))
    (unless (and whole (plusp whole))
      (fail "omp-re: ~a: size must be a positive integer" tool))
    whole))

;;; --- the tools ---------------------------------------------------------------------------------

(define-tool "rename_function"
    (:label "Rename Function" :tier :write
     :reason "Rename function {addr} to {new}. Reversible with /re undo."
     :render '(:title "Rename function" :subject "addr" :body :none)
     :description "Rename the function at an address, verifying the rename actually landed before reporting success.")
    (("addr" :string :required t :doc "Function address or name.")
     ("new" :string :required t :doc "New function name (identifier characters only)."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (new-name (validate-ident "new" (jstring arguments "new"))))
    (multiple-value-bind (ea name) (function-at rz (jstring arguments "addr"))
      (apply-commands rz (annotation-commands "rename_function" ea new-name name))
      (let ((landed (jstring (first-row (rz-cmdj rz (format nil "afij @ ~a" ea))) "name")))
        (unless (equal landed new-name)
          (fail "omp-re: rename_function: mutation did not land: expected ~a, rizin has ~a"
                (js-string new-name) (js-or-null landed)))
        (record-annotation "rename_function" ea name landed)))))

(define-tool "rename_variable"
    (:label "Rename Variable" :tier :write
     :reason "Rename variable {old} to {new} in {addr}. Reversible with /re undo."
     :render '(:title "Rename variable" :subject "addr" :body :none)
     :description "Rename a local variable or argument within a function, verifying the rename actually landed before reporting success.")
    (("addr" :string :required t :doc "Function address or name.")
     ("old" :string :required t :doc "Current variable name.")
     ("new" :string :required t :doc "New variable name."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (old-name (validate-ident "old" (jstring arguments "old")))
         (new-name (validate-ident "new" (jstring arguments "new"))))
    (multiple-value-bind (ea name) (function-at rz (jstring arguments "addr"))
      (let ((before (variables-at rz ea)))
        (unless (variable-named old-name before)
          (fail "omp-re: rename_variable: ~a has no variable ~a (has: ~a)"
                name (js-string old-name)
                (if before
                    (format nil "~{~a~^, ~}" (mapcar (lambda (variable) (jstring variable "name")) before))
                    "none"))))
      (apply-commands rz (annotation-commands "rename_variable" ea new-name old-name))
      (let ((after (variables-at rz ea)))
        (when (or (not (variable-named new-name after)) (variable-named old-name after))
          (fail "omp-re: rename_variable: mutation did not land: expected ~a in place of ~a"
                (js-string new-name) (js-string old-name))))
      (record-annotation "rename_variable" ea old-name new-name))))

(define-tool "set_comment"
    (:label "Set Comment" :tier :write
     :reason "Set the comment at {addr}. Reversible with /re undo."
     :render '(:title "Comment" :subject "addr" :body :none)
     :description "Set (or clear, with empty text) the comment at an address, replacing any existing comment, and verify it landed before reporting success.")
    (("addr" :string :required t :doc "Address (or name) to comment.")
     ("text" :string :required t :doc "Comment text (single line); empty string clears the comment."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (text (trimmed (validate-text (jstring arguments "text"))))
         (ea (resolved-ea rz (jstring arguments "addr")))
         (old-value (trimmed (rz-cmd rz (format nil "CC. @ ~a" ea)))))
    (apply-commands rz (annotation-commands "set_comment" ea text old-value))
    (let ((read-back (trimmed (rz-cmd rz (format nil "CC. @ ~a" ea)))))
      (unless (string= read-back text)
        (fail "omp-re: set_comment: mutation did not land: expected ~a, rizin has ~a"
              (js-string text) (js-string read-back)))
      (record-annotation "set_comment" ea old-value read-back))))

(define-tool "set_prototype"
    (:label "Set Prototype" :tier :write
     :reason "Set the prototype of {addr} to {sig}. Reversible with /re undo."
     :render '(:title "Prototype" :subject "addr" :body :none)
     :description "Set a function's C prototype, e.g. `int parse_config(const char *path, int flags)`. The name in the prototype becomes the function's name. Verifies what rizin stored and reports it if rizin's C parser normalized it differently.")
    (("addr" :string :required t :doc "Function address or name.")
     ("sig" :string :required t :doc "New C-style prototype, without a trailing semicolon."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (sig (validate-type-like "sig" (trimmed (jstring arguments "sig"))))
         (ea (function-at rz (jstring arguments "addr")))
         (old-value (signature-at rz ea)))
    (apply-commands rz (annotation-commands "set_prototype" ea sig old-value))
    (let ((read-back (signature-at rz ea)))
      (unless (string= (normalize-c-type read-back) (normalize-c-type sig))
        (fail "omp-re: set_prototype: mutation did not land as requested: expected ~a, rizin stored ~a"
              (js-string sig) (js-string read-back)))
      (record-annotation "set_prototype" ea old-value read-back))))

(define-tool "set_variable_type"
    (:label "Set Variable Type" :tier :write
     :reason "Set the type of {var} in {addr} to {type}. Reversible with /re undo."
     :render '(:title "Variable type" :subject "addr" :body :none)
     :description "Set a local variable's or argument's C type, verifying it actually landed before reporting success.")
    (("addr" :string :required t :doc "Function address or name.")
     ("var" :string :required t :doc "Variable name.")
     ("type" :string :required t :doc "New C-style type, e.g. `char *` or `struct sockaddr_in *`."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (variable (validate-ident "var" (jstring arguments "var")))
         (type (validate-type-like "type" (trimmed (jstring arguments "type")))))
    (multiple-value-bind (ea name) (function-at rz (jstring arguments "addr"))
      (let ((old (variable-named variable (variables-at rz ea))))
        (unless old
          (fail "omp-re: set_variable_type: ~a has no variable ~a" name (js-string variable)))
        (apply-commands rz (annotation-commands "set_variable_type" ea type (jstring old "type") variable))
        (let ((landed (variable-named variable (variables-at rz ea))))
          (unless (and landed (string= (normalize-c-type (jstring landed "type")) (normalize-c-type type)))
            (fail "omp-re: set_variable_type: mutation did not land: expected ~a, rizin has ~a"
                  (js-string type) (js-or-null (and landed (jstring landed "type")))))
          (record-annotation "set_variable_type" ea (jstring old "type") (jstring landed "type") variable))))))

(define-tool "define_variable"
    (:label "Define Variable" :tier :write
     :reason "Define {storage} variable {name} in {addr}. Reversible with /re undo."
     :render '(:title "Define variable" :subject "addr" :body :none)
     :description "Define a local variable or argument in a function that rizin's analysis didn't recover — a stack slot (`afvs`, by frame delta) or a register variable (`afvr`, by register) — so the decompiler and disassembly name it instead of showing a raw offset. Refuses when a variable of that name already exists, verifies the new one landed, and is reversible with /re undo (which runs `afv-`).")
    (("addr" :string :required t :doc "Function address or name.")
     ("storage" :string :required t :enum '("stack" "reg")
      :doc "`stack` for a stack-based local/argument (`afvs`), `reg` for a register-based one (`afvr`).")
     ("location" :string :required t
      :doc "For `stack`: the frame offset as a decimal or 0x-hex delta (e.g. `0x30`). For `reg`: the register name (e.g. `rdi`).")
     ("name" :string :required t :doc "New variable name (identifier characters).")
     ("type" :string :doc "C type, e.g. `int` or `char *`; omit to let rizin default it (int)."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (name (validate-ident "name" (jstring arguments "name"))))
    (multiple-value-bind (ea function) (function-at rz (jstring arguments "addr"))
      (when (variable-named name (variables-at rz ea))
        (fail "omp-re: define_variable: ~a already has a variable ~a" function (js-string name)))
      (let* ((given (trimmed (jstring arguments "type")))
             (type (if (string= given "") "" (validate-type-like "type" given)))
             (encoded (format nil "~a ~a~:[ ~a~;~]" (jstring arguments "storage")
                              (trimmed (jstring arguments "location")) (string= type "") type)))
        (apply-commands rz (annotation-commands "define_variable" ea encoded "" name))
        (unless (variable-named name (variables-at rz ea))
          (fail "omp-re: define_variable: mutation did not land: no variable ~a in ~a after defining it"
                (js-string name) function))
        (record-annotation "define_variable" ea "" encoded name)))))

(define-tool "define_global"
    (:label "Define Global" :tier :write
     :reason "Define global {name} at {addr}. Reversible with /re undo."
     :render '(:title "Define global" :subject "addr" :body :none)
     :description "Define a global variable at a data address (`avga`), giving it a name and a C type so disassembly, xrefs, and the decompiler show the name and typed accesses instead of a raw address. Refuses when a global of that name already exists, verifies it landed, and is reversible with /re undo (which runs `avgm`).")
    (("addr" :string :required t :doc "Data address (or name/expression) where the global variable lives.")
     ("name" :string :required t :doc "Global variable name (identifier characters).")
     ("type" :string :required t :doc "C type, e.g. `int`, `char *`, or a named struct/typedef."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (name (validate-ident "name" (jstring arguments "name")))
         (type (validate-type-like "type" (trimmed (jstring arguments "type"))))
         (ea (resolved-ea rz (jstring arguments "addr"))))
    (when (global-named rz name)
      (fail "omp-re: define_global: a global named ~a already exists" (js-string name)))
    (apply-commands rz (annotation-commands "define_global" ea type "" name))
    (let ((landed (global-named rz name)))
      (unless landed
        (fail "omp-re: define_global: mutation did not land: no global ~a after defining it at ~a"
              (js-string name) ea))
      (record-annotation "define_global" ea "" (jstring landed "type") name))))

(define-tool "define_function"
    (:label "Define Function" :tier :write
     :reason "Define a function at {addr}. Reversible with /re undo."
     :render '(:title "Define function" :subject "addr" :body :none)
     :description "Define a function at an address rizin's auto-analysis missed (obfuscated call targets, hand-written stubs, code reached only indirectly). Runs `af`, then verifies a function now begins exactly there. Reversible with /re undo (which runs `af-`).")
    (("addr" :string :required t
      :doc "Address (or name/expression) where a function begins that rizin's auto-analysis missed."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (ea (resolved-ea rz (jstring arguments "addr")))
         (existing (function-starting-at rz ea)))
    (when existing
      (fail "omp-re: define_function: a function already begins at ~a (~a); nothing to define"
            ea (js-or-null (jstring existing "name"))))
    (apply-commands rz (annotation-commands "define_function" ea "function" ""))
    (let ((landed (function-starting-at rz ea)))
      (unless landed
        (fail "omp-re: define_function: rizin did not create a function at ~a (it may not be valid code there)" ea))
      (record-annotation "define_function" ea "" (or (jstring landed "name") "function")))))

(define-tool "set_calling_convention"
    (:label "Set Calling Convention" :tier :write
     :reason "Set the calling convention of {addr} to {cc}. Reversible with /re undo."
     :render '(:title "Calling convention" :subject "addr" :body :none)
     :description "Set a function's calling convention (how arguments and the return value are passed), which corrects argument recovery in the decompiler and call sites. Verifies what rizin stored; an unknown convention is rejected with rizin's own error (list them with rizin_command afcl). Reversible with /re undo.")
    (("addr" :string :required t :doc "Function address or name.")
     ("cc" :string :required t
      :doc "Calling convention name, e.g. `amd64`, `ms`, `cdecl`, `stdcall` — see the list from rizin_command afcl."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (cc (validate-ident "cc" (trimmed (jstring arguments "cc"))))
         (ea (function-at rz (jstring arguments "addr")))
         (old-value (calling-convention-at rz ea)))
    (apply-commands rz (annotation-commands "set_calling_convention" ea cc old-value))
    (let ((read-back (calling-convention-at rz ea)))
      (unless (string= read-back cc)
        (fail "omp-re: set_calling_convention: mutation did not land: expected ~a, rizin has ~a (unknown convention? see rizin_command afcl)"
              (js-string cc) (js-string read-back)))
      (record-annotation "set_calling_convention" ea old-value read-back))))

(define-tool "set_flag"
    (:label "Set Flag" :tier :write
     :reason "Flag {addr} as {name}. Reversible with /re undo."
     :render '(:title "Flag" :subject "addr" :body :none)
     :description "Name an address with a flag (rizin's named label), so disassembly, xrefs, and your own commands can refer to it by name. Replaces any flag already at that address. Verifies the flag landed. Reversible with /re undo.")
    (("addr" :string :required t :doc "Address (or name/expression) to label.")
     ("name" :string :required t
      :doc "Flag name (identifier characters, dots allowed), e.g. `str.banner` or `decrypt_key`."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (name (validate-ident "name" (jstring arguments "name")))
         (ea (resolved-ea rz (jstring arguments "addr")))
         (old-value (flag-at rz ea)))
    (apply-commands rz (annotation-commands "set_flag" ea name old-value))
    (let ((read-back (flag-at rz ea)))
      (unless (string= read-back name)
        (fail "omp-re: set_flag: mutation did not land: expected flag ~a at ~a, rizin has ~a"
              (js-string name) ea (js-or-null read-back)))
      (record-annotation "set_flag" ea old-value name))))

(define-tool "set_arch_hint"
    (:label "Set Arch Hint" :tier :write
     :reason "Hint arch/bits at {addr}. Reversible with /re undo."
     :render '(:title "Arch hint" :subject "addr" :body :none)
     :description "Hint the architecture and/or word size to disassemble from an address, for a region that differs from the file's default — most often ARM/Thumb switches (bits 16) or mixed-arch firmware. Sets `aha`/`ahb`, verifies the hint landed, and is reversible with /re undo (which deletes it).")
    (("addr" :string :required t :doc "Address (or name/expression) where the hint applies.")
     ("arch" :string :doc "Architecture to disassemble as from here, e.g. `arm`, `x86` (sets an `aha` hint).")
     ("bits" :integer :enum '(8 16 32 64)
      :doc "Word size from here, e.g. 16 for ARM Thumb (sets an `ahb` hint)."))
    (arguments)
  (let ((arch (jstring arguments "arch"))
        (bits (jnumber arguments "bits")))
    (unless (or arch bits)
      (fail "omp-re: set_arch_hint needs arch and/or bits"))
    (let* ((rz (ensure-rizin))
           (ea (resolved-ea rz (jstring arguments "addr")))
           (encoded (format nil "~{~a~^;~}"
                            (append (when arch (list (format nil "arch=~a" (validate-ident "arch" arch))))
                                    (when bits (list (format nil "bits=~d" bits)))))))
      (apply-commands rz (annotation-commands "set_arch_hint" ea encoded ""))
      (let ((landed (hints-at rz ea)))
        (unless (and landed
                     (or (null arch) (equal arch (jget landed "arch")))
                     (or (null bits) (eql bits (jget landed "bits"))))
          (fail "omp-re: set_arch_hint: mutation did not land: expected ~a, rizin has ~a"
                (js-string encoded) (if landed (json-encode landed) "null")))
        (record-annotation "set_arch_hint" ea "" encoded)))))

(define-tool "set_hint"
    (:label "Set Hint" :tier :write
     :reason "Set the {hint} hint at {addr}. Reversible with /re undo."
     :render '(:title "Hint" :subject "addr" :body :none)
     :description "Set an analysis hint at an instruction that corrects how rizin reads it: the display base of an immediate (hex/decimal/char/string/syscall/IP-relative), the opcode type, the opcode byte-length (to realign disassembly), the real target of an indirect jump/call, or a function's return value. Verifies the hint landed and records what rizin stored; reversible with /re undo (which deletes it or restores the prior hint).")
    (("addr" :string :required t :doc "Instruction address (or name/expression) the hint applies to.")
     ("hint" :string :required t :enum +hint-kinds+
      :doc (join-lines
            '("immediate_base: how an operand's immediate is shown (value: 2/8/10/10u/16 or b/o/h/i/p/S/s — e.g. `h` hex, `S` string, `s` syscall, `i` IP-relative)."
              "opcode_type: reclassify the instruction (value: a type such as call, jmp, ret, nop, mov)."
              "opcode_size: force the instruction's byte length (value: a positive integer) to realign disassembly."
              "jump_target: the real destination of an indirect/computed jump or call (value: an address)."
              "return_value: a function's return-value hint (value: a decimal or 0x-hex integer).")))
     ("value" :string :required t
      :doc "The hint value; its grammar depends on `hint` (see the hint descriptions)."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (ea (resolved-ea rz (jstring arguments "addr")))
         (kind (jstring arguments "hint"))
         (value (jstring arguments "value"))
         (old-value (hint-value-at rz ea kind)))
    ;; The value sent is the request, checked in ANNOTATION-COMMANDS; the
    ;; value recorded is the read-back, never the request.
    (apply-commands rz (annotation-commands "set_hint" ea value "" kind))
    (let ((landed (hint-value-at rz ea kind)))
      (when (string= landed "")
        (fail "omp-re: set_hint: mutation did not land: no ~a hint at ~a after setting ~a"
              kind ea (js-string value)))
      (record-annotation "set_hint" ea old-value landed kind))))

(define-tool "set_data"
    (:label "Set Data" :tier :write
     :reason "Mark data at {addr}. Reversible with /re undo."
     :render '(:title "Data" :subject "addr" :body :none)
     :description "Mark bytes as a data element (or an array, with `count`) so disassembly and xrefs stop rendering data as code. Verifies the mark landed; reversible with /re undo.")
    (("addr" :string :required t :doc "Address (or name/expression) to mark as data.")
     ("size" :number :required t :doc "Size in bytes of one data element.")
     ("count" :number :doc "Number of consecutive elements (an array); default 1."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (size (positive-integer "set_data" (jnumber arguments "size")))
         (count (jnumber arguments "count"))
         (ea (resolved-ea rz (jstring arguments "addr")))
         (encoded (if (and count (> count 1))
                      (format nil "~d:~a" size (js-number count))
                      (format nil "~d" size))))
    (apply-commands rz (annotation-commands "set_data" ea encoded ""))
    (unless (meta-at rz ea "Cd")
      (fail "omp-re: set_data: mutation did not land: no data mark at ~a" ea))
    (record-annotation "set_data" ea "" encoded)))

(define-tool "set_string"
    (:label "Set String" :tier :write
     :reason "Mark a string at {addr}. Reversible with /re undo."
     :render '(:title "String" :subject "addr" :body :none)
     :description "Mark bytes as a string where rizin's auto-analysis missed one, so it shows in the disassembly and string views. Omit `size` to autodetect encoding and length. Verifies it landed; reversible with /re undo.")
    (("addr" :string :required t :doc "Address (or name/expression) where a string begins.")
     ("size" :number
      :doc "String length in bytes; omit to let rizin autodetect the encoding and length."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (size (and (jnumber arguments "size")
                    (positive-integer "set_string" (jnumber arguments "size"))))
         (ea (resolved-ea rz (jstring arguments "addr")))
         (encoded (if size (format nil "~d" size) "auto")))
    (apply-commands rz (annotation-commands "set_string" ea encoded ""))
    (unless (meta-at rz ea "Cs")
      (fail "omp-re: set_string: mutation did not land: no string mark at ~a (not valid string bytes there?)" ea))
    (record-annotation "set_string" ea "" encoded)))

(define-tool "set_format"
    (:label "Set Format" :tier :write
     :reason "Overlay a format at {addr}. Reversible with /re undo."
     :render '(:title "Format" :subject "addr" :body :none)
     :description "Overlay a struct format (a pf format string, optionally with field names) on a memory region, so the disassembly shows named, typed fields instead of raw bytes — one of the highest-leverage annotations for data structures. Display-only (doesn't perturb analysis). Verifies it landed; reversible with /re undo.")
    (("addr" :string :required t :doc "Address (or name/expression) to overlay a struct format on.")
     ("size" :number :required t :doc "Total size in bytes the format covers.")
     ("format" :string :required t
      :doc "A pf format string, optionally with field names, e.g. `xxdd field1 field2 field3 field4` (see rizin_help pf)."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (size (positive-integer "set_format" (jnumber arguments "size")))
         (ea (resolved-ea rz (jstring arguments "addr")))
         (encoded (format nil "~d ~a" size (trimmed (jstring arguments "format")))))
    (apply-commands rz (annotation-commands "set_format" ea encoded ""))
    (unless (meta-at rz ea "Cf")
      (fail "omp-re: set_format: mutation did not land: no format mark at ~a (bad pf format?)" ea))
    (record-annotation "set_format" ea "" encoded)))

;;; --- /re undo ------------------------------------------------------------------------------------

(defun undo-last-annotation (&optional (session *session*))
  "Take back the most recent annotation still in effect by applying its old
value, then record an re.undo marker, so a repeated /re undo steps further
back instead of applying the same reversal again => the line that says so."
  (let* ((binary-path (session-binary-path session))
         (last (and binary-path (car (last (live-annotation-entries binary-path session))))))
    (unless last
      (fail "omp-re: no annotation left to undo"))
    (let ((data (cdr last))
          (rz (ensure-rizin session)))
      (apply-commands rz (annotation-commands (jstring data "kind") (jstring data "ea")
                                              (jstring data "oldValue") (jstring data "newValue")
                                              (jstring data "target")))
      (append-entry "re.undo" (obj "undidEntryId" (car last)) session)
      (mark-applied "annotations" session)
      (format nil "omp-re: undid ~a @ ~a (restored ~a)"
              (jstring data "kind") (jstring data "ea") (js-string (jstring data "oldValue"))))))

(define-slash "undo" (:description "revert the last annotation" :order 80
                      :row (110 "Undo the last annotation"))
    (words)
  (undo-last-annotation))
