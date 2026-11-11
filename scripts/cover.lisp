;;;; cover.lisp --- what of the Lisp the Lisp suite runs: sb-cover over engine/, stdio/ and nodecode/.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --noinform --non-interactive --no-sysinit --no-userinit --load scripts/cover.lisp
;;;;   OMPRE_TEST_SUITES=core,stdio sbcl ... --load scripts/cover.lisp
;;;;
;;;; Compiles the three systems with sb-cover's instrumentation, runs the
;;;; suites of test/nodecode/ as run.lisp does, and reports:
;;;;
;;;;   coverage/cover-index.html   sb-cover's report, a page for each file
;;;;   coverage/summary.md         the table below and the list under it
;;;;   on standard output          a line for each file — expressions and
;;;;                               branches run, of how many — and a total;
;;;;                               then every function none of whose body ran
;;;;
;;;; The instrumented compiled files are kept in coverage/fasl/, apart from
;;;; the cache an ordinary load uses: instrumentation changes how the code is
;;;; compiled and slows it, so the suite itself (run.lisp) and omp never run
;;;; it. Generated code (nodecode/recipe-data.lisp) and the test files are not
;;;; in the report.
;;;;
;;;; The omp host is a process of its own (suite-stdio starts it), so this
;;;; file is also what that process loads: `--load scripts/cover.lisp
;;;; --end-toplevel-options serve' does what stdio/serve.lisp does over the
;;;; instrumented files and, when omp has gone, leaves what it ran in
;;;; coverage/fasl/ for the run to add up. A host process a check kills
;;;; leaves nothing; what only such a process ran reads as not run.
;;;;
;;;; Exits 1 when a check of the suite failed. With OMPRE_COVERAGE_FLOOR set
;;;; to a percentage it also exits 1 when the expressions run, over all the
;;;; files, are below it; docs/testing.md says what CI sets it to and why.

(require :asdf)
(require :sb-cover)
(require :sb-posix)

(defpackage #:omp-re-cover
  (:use #:cl))
(in-package #:omp-re-cover)

(defparameter *root*
  (uiop:pathname-parent-directory-pathname
   (uiop:pathname-directory-pathname (or *load-truename* *default-pathname-defaults*))))
(defparameter *this* (or *load-truename* (error "scripts/cover.lisp is loaded, not evaluated")))
(defparameter *out* (merge-pathnames "coverage/" *root*))
(defparameter *fasl* (merge-pathnames "fasl/" *out*))

(defun instrumented-output ()
  "Have this process keep what it compiles of this repository in coverage/fasl/."
  (asdf:initialize-output-translations
   `(:output-translations (,(namestring *root*) ,(namestring *fasl*)) :inherit-configuration)))

;;; --- the omp host's process ------------------------------------------------------------------

(when (equal '("serve") (uiop:command-line-arguments))
  (let ((log (sb-sys:make-fd-stream (sb-sys:fd-stream-fd sb-sys:*stderr*) :output t :buffering :line)))
    (setf *standard-output* log *error-output* log))
  (instrumented-output)
  (load (merge-pathnames "stdio/load.lisp" *root*))
  (uiop:symbol-call '#:omp-re-stdio '#:main)
  (sb-cover:save-coverage-in-file
   (merge-pathnames (format nil "host-~36r.coverage" (random (expt 36 10) (make-random-state t))) *fasl*))
  (sb-ext:exit :code 0 :abort t))

;;; --- the run -----------------------------------------------------------------------------------

;; A host process that did not take itself for one would run the suites, and
;; start host processes of its own.
(when (uiop:getenv "OMPRE_COVERAGE_RUN")
  (format *error-output* "omp-re: scripts/cover.lisp was started inside its own run~%")
  (sb-ext:exit :code 2 :abort t))
(sb-posix:setenv "OMPRE_COVERAGE_RUN" "1" 1)

;; cl-ppcre is not what is measured: it is loaded, and compiled if it never
;; was, before anything is instrumented.
(push *root* asdf:*central-registry*)
(asdf:load-system "cl-ppcre")

(uiop:delete-directory-tree *out* :validate (lambda (directory) (uiop:subpathp directory *root*))
                                  :if-does-not-exist :ignore)
(ensure-directories-exist *fasl*)
(instrumented-output)

(proclaim '(optimize sb-cover:store-coverage-data))
(load (merge-pathnames "test/nodecode/harness.lisp" *root*))
(asdf:load-system "omp-re-stdio")
(proclaim '(optimize (sb-cover:store-coverage-data 0)))

(setf (symbol-value (uiop:find-symbol* '#:*serve-command* '#:omp-re-test))
      (list "sbcl" "--noinform" "--no-sysinit" "--no-userinit" "--disable-debugger"
            "--load" (uiop:native-namestring *this*) "--end-toplevel-options" "serve"))

(defparameter *passed* (uiop:symbol-call '#:omp-re-test '#:run-suites))

;;; --- adding up ---------------------------------------------------------------------------------

(defun measured-p (file)
  "Whether FILE, a namestring sb-cover has data for, is in the report."
  (let ((relative (uiop:subpathp (pathname file) *root*)))
    (and relative
         (member (second (pathname-directory relative)) '("engine" "stdio" "nodecode") :test #'equal)
         (= 2 (length (pathname-directory relative)))
         (string/= "recipe-data" (pathname-name relative)))))

(defun add-host-processes ()
  "Add what each omp host process ran to what this image ran. sb-cover saves
a state as ((FILE (PATH . MARK) ...) ...), MARK being T for a path that ran,
and restores one by setting the mark of each path it is given."
  (dolist (saved (uiop:directory-files *fasl* "*.coverage"))
    (sb-cover:restore-coverage
     (loop for (file . records) in (with-open-file (in saved)
                                     (with-standard-io-syntax
                                       (let ((*package* (find-package '#:sb-cover))) (read in))))
           collect (cons file (remove t records :key #'cdr :test-not #'eq))))))

(add-host-processes)

(let ((*error-output* (make-broadcast-stream)))
  (sb-cover:report *out* :if-matches #'measured-p))

;;; --- the table -----------------------------------------------------------------------------------
;;; sb-cover gives its counts to nobody but its report, so they are read
;;; back from the index it wrote: under a heading for each directory, a row
;;; for each file, of the expressions run, their number, a percentage, and
;;; the same three for branches.

(defun index-rows ()
  (let ((html (uiop:read-file-string (merge-pathnames "cover-index.html" *out*)))
        (directory "")
        (rows '()))
    (ppcre:do-matches-as-strings
        (row "<td colspan='7'>[^<]+</td>|<a href='[0-9a-f]+\\.html'>[^<]+</a></td>(?:<td>[^<]*</td>){6}" html)
      (let ((cells (nth-value 1 (ppcre:scan-to-strings
                                 "'>([^<]+)</a></td><td>(\\d+)</td><td>(\\d+)</td><td>[^<]*</td><td>(\\d+)</td><td>(\\d+)</td>"
                                 row))))
        (if cells
            (push (cons (enough-namestring (concatenate 'string directory (aref cells 0)) *root*)
                        (loop for index from 1 to 4 collect (parse-integer (aref cells index))))
                  rows)
            ;; A heading over the rows of one directory.
            (setf directory (subseq row (1+ (position #\> row)) (position #\< row :from-end t))))))
    (or (sort rows #'string< :key #'first)
        (error "omp-re: sb-cover's index has no row this script can read: ~a"
               (merge-pathnames "cover-index.html" *out*)))))

(defun percent (part whole)
  (if (zerop whole) "    -" (format nil "~5,1f" (* 100 (/ part whole)))))

(defun write-table (rows stream)
  (format stream "| File | Expressions | of | % | Branches | of | % |~%|---|---:|---:|---:|---:|---:|---:|~%")
  (flet ((row (name expressions-run expressions branches-run branches)
           (format stream "| ~a | ~d | ~d | ~a | ~d | ~d | ~a |~%" name
                   expressions-run expressions (string-left-trim " " (percent expressions-run expressions))
                   branches-run branches (string-left-trim " " (percent branches-run branches)))))
    (dolist (one rows) (apply #'row one))
    (apply #'row "**total**" (loop for index from 1 to 4 collect (reduce #'+ rows :key (lambda (one) (nth index one)))))))

;;; --- functions nothing ran -------------------------------------------------------------------------
;;; A record's path ends with the number of the top-level form it is in. A
;;; definition whose form holds records, none of them run but the ones the
;;; load itself runs — the form, and for an installed function the forms
;;; around its lambda — was never called.

;;;
;;; Macros are left out. A macro runs while files are compiled, and for the
;;; file that defines it that is a copy the compiler made for itself, not
;;; the one loaded and measured: a macro used only in its own file would
;;; always read as never run.

(defparameter +definers+
  '("DEFUN" "DEFINE-SURFACE" "DEFINE-TOOL" "DEFINE-SLASH" "DEFINE-LIST" "DEFINE-METHOD" "DEFINE-VERB"))

(defun top-level-forms (file)
  "FILE's top-level forms as (OPERATOR NAME), in order: read in the package
its IN-PACKAGE names, and not evaluated."
  (with-open-file (in file :external-format :utf-8)
    (let ((*package* (find-package '#:cl-user)))
      (loop for form = (read in nil in)
            until (eq form in)
            do (when (and (consp form) (string= "IN-PACKAGE" (symbol-name (first form))))
                 (setf *package* (find-package (second form))))
            collect (and (consp form) (symbolp (first form))
                         (list (symbol-name (first form))
                               (let ((name (second form)))
                                 (cond ((stringp name) name)
                                       ((symbolp name) (string-downcase name))
                                       (t (string-downcase (prin1-to-string name)))))))))))

(defun never-run ()
  "(FILE OPERATOR NAME) of each definition no part of whose body ran."
  (let ((found '()))
    (loop for (file . records) in (sb-cover:save-coverage)
          do (when (measured-p file)
               (let ((forms (coerce (top-level-forms file) 'vector))
                     (inside (make-hash-table))
                     (ran (make-hash-table)))
                 (loop for (path . visited) in records
                       for source = (if (keywordp (first path)) (rest path) path)
                       for form = (car (last source))
                       ;; The form itself, and one level into it, is what the load runs.
                       do (when (< 2 (length source))
                            (incf (gethash form inside 0))
                            (when (eq visited t) (incf (gethash form ran 0)))))
                 (loop for form from 0 below (length forms)
                       for (operator name) = (or (aref forms form) '("" ""))
                       do (when (and (member operator +definers+ :test #'equal)
                                     (plusp (gethash form inside 0))
                                     (zerop (gethash form ran 0)))
                            (push (list (enough-namestring file *root*) (string-downcase operator) name)
                                  found))))))
    (sort found (lambda (a b) (or (string< (first a) (first b))
                                  (and (string= (first a) (first b)) (string< (third a) (third b))))))))

(defvar *below-floor* nil)

(let ((rows (index-rows))
      (never (never-run)))
  (with-open-file (out (merge-pathnames "summary.md" *out*) :direction :output :if-exists :supersede
                                                             :external-format :utf-8)
    (format out "### Lisp coverage (sb-cover, over the Lisp suite)~%~%")
    (write-table rows out)
    (format out "~%~d definition~:p none of whose body ran~:[.~;:~]~%~%~:{- `~a` ~a `~a`~%~}"
            (length never) never never))
  (format t "~&~%omp-re: coverage of the Lisp suite~%~%")
  (format t "~32a ~11@a ~6@a ~6@a  ~8@a ~6@a ~6@a~%" "file" "expressions" "of" "%" "branches" "of" "%")
  (flet ((row (name expressions-run expressions branches-run branches)
           (format t "~32a ~11d ~6d ~6a  ~8d ~6d ~6a~%" name expressions-run expressions
                   (percent expressions-run expressions) branches-run branches (percent branches-run branches))))
    (dolist (one rows) (apply #'row one))
    (apply #'row "total" (loop for index from 1 to 4 collect (reduce #'+ rows :key (lambda (one) (nth index one))))))
  (format t "~%omp-re: ~d definition~:p none of whose body ran~%~:{  ~a: ~a ~a~%~}" (length never) never)
  (format t "~%omp-re: the report is ~a~%" (uiop:native-namestring (merge-pathnames "cover-index.html" *out*)))
  (let ((floor (ignore-errors (parse-integer (uiop:getenv "OMPRE_COVERAGE_FLOOR"))))
        (ran (reduce #'+ rows :key #'second))
        (all (reduce #'+ rows :key #'third)))
    (when (and floor (< (* 100 ran) (* floor all)))
      (setf *below-floor* t)
      (format t "omp-re: ~a% of the expressions ran, under the floor of ~d% (OMPRE_COVERAGE_FLOOR): is a suite, or rizin, missing from this run?~%"
              (string-left-trim " " (percent ran all)) floor))))

(finish-output)
(sb-ext:exit :code (if (and *passed* (not *below-floor*)) 0 1) :abort t)
