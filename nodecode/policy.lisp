;;;; policy.lisp --- which rizin commands rizin_command may run, and why not.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The patterns and command lists are policy-data.lisp; this is the logic
;;;; over them. rizin_command is read-only: print, info,
;;;; search, graphs and listings run; everything that writes, sets config,
;;;; opens files, runs a shell or changes analysis is refused, and
;;;; annotations go through the dedicated, undoable tools.

(in-package #:nodecode-re)

(defparameter *allowed-scanner* (js-scanner +allowed-command+))
(defparameter *denied-scanner* (js-scanner +denied-command+))
(defparameter *entropy-scanner* (js-scanner +entropy-map+))
(defparameter *forbidden-scanners*
  (mapcar (lambda (entry) (cons (js-scanner (car entry)) (cdr entry))) +forbidden-syntax+))

(defun string-set (names)
  (let ((table (make-hash-table :test #'equal)))
    (dolist (name names table) (setf (gethash name table) t))))

(defparameter *read-only-extras* (string-set +read-only-extras+))
(defparameter *noarg-duals* (string-set +noarg-duals+))
(defparameter *debug-read-commands* (string-set +debug-read-commands+))

(defun known-command-p (catalog name)
  "Whether NAME is a command in CATALOG, or a group whose subcommands are
(rizin lists `iz' only as `izj', `izq', ...)."
  (or (nth-value 1 (gethash name catalog))
      (loop for command being the hash-keys of catalog
            thereis (uiop:string-prefix-p name command))))

(defun missing-required-commands (catalog)
  (remove-if (lambda (command) (nth-value 1 (gethash command catalog))) +required-commands+))

(defun runnable-p (name)
  "Whether rizin_command would run the command NAME."
  (or (gethash name *read-only-extras*)
      (gethash name *noarg-duals*)
      (and (ppcre:scan *entropy-scanner* name) t)
      (and (ppcre:scan *allowed-scanner* name)
           (not (ppcre:scan *denied-scanner* name)))))

(defun forbidden-syntax-reason (value)
  "The words for the first forbidden syntax in VALUE, or NIL."
  (loop for (scanner . label) in *forbidden-scanners*
        when (ppcre:scan scanner value) return label))

(defun check-rizin-command (catalog command &optional addr)
  "Decide whether COMMAND, run at ADDR when given, may go through
rizin_command => (values LINE NAME), the exact line sent to rizin and the
command's name; a refusal is RE-ERROR in the engine's words."
  (let* ((line (trimmed command))
         (forbidden (and (plusp (length line)) (forbidden-syntax-reason line))))
    (when (zerop (length line))
      (fail "omp-re: rizin_command: empty command"))
    (when forbidden
      (fail "omp-re: rizin_command: ~a is not allowed in a command" forbidden))
    (let* ((name (first (words line)))
           (colon (position #\: name))
           (checked (if colon (subseq name 0 colon) name)))
      ;; A table-query suffix (cmd:spec[:spec...]) sorts, filters and pages
      ;; the command's table. Only the head must be runnable and known; every
      ;; spec part must be table-grammar-shaped.
      (when colon
        (unless (every (lambda (part) (js-scan "^[A-Za-z0-9_*/.-]+$" part))
                       (uiop:split-string (subseq name (1+ colon)) :separator '(#\:)))
          (fail "omp-re: rizin_command: table spec parts must match [A-Za-z0-9_*/.-] (see the table query grammar)")))
      (unless (runnable-p checked)
        (fail "omp-re: rizin_command: ~a is not available here: only read-only print, info, search, graph, and listing commands run through this tool. Use rename_function, set_comment, set_prototype, rename_variable, or set_variable_type to annotate."
              (js-string name)))
      (unless (known-command-p catalog checked)
        (fail "omp-re: rizin_command: this rizin has no command ~a — look it up with rizin_help"
              (js-string checked)))
      (when (js-scan "(^|\\s)interactive(\\s|$)" line)
        (fail "omp-re: rizin_command: interactive output modes would wait for keyboard input"))
      (let ((arguments (trimmed (subseq line (length name)))))
        ;; `e <key>' reads a value; `e <key>=<value>' sets it.
        (when (and (string= checked "e") (find #\= arguments))
          (fail "omp-re: rizin_command: setting config variables (`e key=value`) is a write and is not allowed; `e <key>` reads a value, `el`/`elj` list them"))
        (when (and (gethash checked *noarg-duals*) (plusp (length arguments)))
          (fail "omp-re: rizin_command: ~a runs read-only only with no argument (an argument makes it set/add); it lists when run bare"
                checked))
        ;; A command whose catalog entry takes a file or path reads from disk; it runs only with none given.
        (let ((file-argument (find-if (lambda (argument)
                                        (js-scan "(?i)file|path|dir" (or (jstring argument "name") "")))
                                      (jlist (gethash checked catalog) "args"))))
          (when (and file-argument (string/= line name))
            (fail "omp-re: rizin_command: ~a reads <~a> from disk; run it without arguments or not at all"
                  checked (jstring file-argument "name")))))
      (values (if addr (format nil "~a @ ~a" line (validate-addr addr)) line)
              (if colon (format nil "~a (table spec)" checked) checked)))))

(defun check-debug-on-hit-command (catalog command)
  "Decide whether COMMAND may run as a breakpoint's on-hit command: a vetted
read of the debugger's state, or anything the static policy allows => the
line. Any `=' is refused, so a register assignment can never write."
  (let ((line (trimmed command)))
    (when (zerop (length line))
      (fail "omp-re: break_command: empty command"))
    (let ((forbidden (forbidden-syntax-reason line)))
      (when forbidden
        (fail "omp-re: break_command: ~a is not allowed in an on-hit command" forbidden)))
    (let ((name (first (words line))))
      (cond ((gethash name *debug-read-commands*)
             (when (find #\= line)
               (fail "omp-re: break_command: ~a with `=` would assign/select (a write); use the bare read form to log state"
                     (js-string name)))
             (unless (known-command-p catalog name)
               (fail "omp-re: break_command: this rizin has no command ~a — look it up with rizin_help"
                     (js-string name)))
             line)
            (t (handler-case (values (check-rizin-command catalog command))
                 (re-error ()
                   (fail "omp-re: break_command: ~a is not a read-only on-hit command. Allowed: read-only debugger state (registers `drj`/`drr`, maps `dmj`, modules `dmmj`, backtrace `dbtj`, heap `dmhg`), or a static read (print/info/search)."
                         (js-string name)))))))))

;;; --- rizin_help -------------------------------------------------------------------------

(defparameter +collation-order+
  " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789"
  "Where the characters that are not letters stand in the order JavaScript's
localeCompare sorts by (the Unicode collation root): blanks, punctuation,
symbols, the currency sign, digits — and every letter after all of them.")

(defun collation-key (char)
  (let ((at (position char +collation-order+)))
    (cond (at at)
          ((alpha-char-p char) (+ 100 (char-code (char-downcase char))))
          (t (+ 1000 (char-code char))))))

(defun locale-less-p (a b)
  "Whether A sorts before B the way localeCompare orders command names:
letters compared without case first, punctuation before digits before
letters, and between two names that differ only by case the lowercase first."
  (let ((mismatch (mismatch a b :test (lambda (x y) (= (collation-key x) (collation-key y))))))
    (cond ((null mismatch)
           (let ((cased (mismatch a b)))
             (and cased (lower-case-p (char a cased)) (upper-case-p (char b cased)))))
          ((>= mismatch (length a)) t)
          ((>= mismatch (length b)) nil)
          (t (< (collation-key (char a mismatch)) (collation-key (char b mismatch)))))))

(defun describe-arguments (spec)
  (mapcar (lambda (argument)
            (format nil "  <~a>: ~{~a~^, ~}"
                    (jstring argument "name")
                    (append (list (jstring argument "type")
                                  (if (jget argument "required") "required" "optional"))
                            (when (jget argument "is_array") (list "repeatable"))
                            (when (jstring argument "default")
                              (list (format nil "default ~a" (jstring argument "default"))))
                            (when (jlist argument "choices")
                              (list (format nil "one of: ~{~a~^, ~}" (jlist argument "choices")))))))
          (jlist spec "args")))

(defun catalog-line (spec)
  (format nil "~a~a — ~a~a"
          (jstring spec "cmd") (or (jstring spec "args_str") "") (or (jstring spec "summary") "")
          (if (runnable-p (jstring spec "cmd")) "" "  [not runnable via rizin_command]")))

(defun search-catalog (catalog query &optional (limit 60))
  "Answer a help QUERY from CATALOG => (values HEADER LINES). A query naming
a command or prefix lists that family, with full argument detail for an exact
match; anything else is a keyword search over summaries and descriptions."
  (let* ((query (trimmed query))
         (exact (gethash query catalog))
         (specs (loop for spec being the hash-values of catalog collect spec))
         (family (and (plusp (length query))
                      (sort (remove-if-not (lambda (spec) (uiop:string-prefix-p query (jstring spec "cmd"))) specs)
                            #'locale-less-p :key (lambda (spec) (jstring spec "cmd"))))))
    (if (or exact family)
        (let* ((rest (remove query family :key (lambda (spec) (jstring spec "cmd")) :test #'string=))
               (lines (append
                       (when exact
                         (append (list (catalog-line exact))
                                 (describe-arguments exact)
                                 (when (plusp (length (jstring exact "description")))
                                   (list (format nil "  ~a" (jstring exact "description"))))
                                 (when (jlist exact "details")
                                   (list (format nil "  details: ~a" (json-encode (jget exact "details")))))
                                 (when (> (length family) 1) (list "" "related:"))))
                       (mapcar #'catalog-line (subseq rest 0 (min limit (length rest))))
                       (when (> (length rest) limit)
                         (list (format nil "… ~d more; narrow the prefix" (- (length rest) limit)))))))
          (values (format nil "rizin help: ~a (~d command~:p)" query (length family)) lines))
        (let* ((wanted (mapcar #'string-downcase (words query)))
               (scored (loop for spec in specs
                             for summary = (string-downcase (or (jstring spec "summary") ""))
                             for description = (string-downcase (or (jstring spec "description") ""))
                             for score = (loop with score = 0
                                               for word in wanted
                                               do (cond ((search word summary) (incf score 2))
                                                        ((search word description) (incf score 1))
                                                        (t (return 0)))
                                               ;; Prefer the plain form over its j/q/t output-mode twins.
                                               finally (return (- score (* 0.01 (length (jstring spec "cmd"))))))
                             when (and wanted (> score 0)) collect (cons score spec)))
               (scored (stable-sort scored #'> :key #'car)))
          (values (format nil "rizin help search: ~a (~d match~:*~[es~;~:;es~])" (js-string query) (length scored))
                  (if scored
                      (mapcar (lambda (entry) (catalog-line (cdr entry)))
                              (subseq scored 0 (min limit (length scored))))
                      (list "no command matches; try a shorter keyword or a command prefix such as p, i, /, a")))))))
