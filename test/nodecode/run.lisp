;;;; run.lisp --- the engine's Lisp suite, and its two hosts'.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --non-interactive --load test/nodecode/run.lisp
;;;;   OMPRE_TEST_SUITES=core,annotate sbcl --non-interactive --load test/nodecode/run.lisp
;;;;
;;;; Loads the engine, and the nodecode host over a stand-in for the nodecode
;;;; kernel names that host uses (harness.lisp, kernel-stub.lisp), and runs
;;;; every suite-*.lisp beside this file, in name order, against a real
;;;; rizin, each in a scratch home of its own. Most suites drive the engine
;;;; through the nodecode host's verbs, as the nearest caller to hand;
;;;; suite-stdio starts the omp host as omp does, in a process of its own.
;;;; A suite's rizin half runs when rizin and the test binary
;;;; (OMPRE_TEST_BINARY, default /bin/ls) are present and says SKIPPED when
;;;; they are not. Needs SBCL and cl-ppcre (the distribution's package is
;;;; enough). Exits 0 when every check holds.

(load (merge-pathnames "harness.lisp" (or *load-truename* *default-pathname-defaults*)))
(in-package #:omp-re-test)

(let* ((here (uiop:pathname-directory-pathname (or *load-truename* *default-pathname-defaults*)))
       (wanted (let ((names (uiop:getenv "OMPRE_TEST_SUITES")))
                 (and names (plusp (length names)) (uiop:split-string names :separator '(#\,)))))
       (suites (sort (remove-if-not
                      (lambda (file)
                        (let ((name (pathname-name file)))
                          (and (eql 0 (search "suite-" name))
                               (or (null wanted) (member (subseq name 6) wanted :test #'string=)))))
                      (uiop:directory-files here "*.lisp"))
                     #'string< :key #'pathname-name)))
  (format t "~&omp-re: ~a, home ~a, rizin ~:[absent~;present~]~%" *root* *scratch-root* *rizin*)
  (dolist (file suites)
    (begin-suite-file (pathname-name file))
    (handler-case (load file)
      (error (condition)
        (push (format nil "~a did not load: ~a" (pathname-name file) condition) *failures*)
        (format t "  FAIL  ~a did not load: ~a~%" (pathname-name file) condition)))))

(begin-suite-file "end")
(uiop:delete-directory-tree *scratch-root* :validate t :if-does-not-exist :ignore)
(format t "~&omp-re: ~a checks, ~a failed~%" *checks* (length *failures*))
(dolist (failure (reverse *failures*)) (format t "  failed: ~a~%" failure))
(sb-ext:exit :code (if *failures* 1 0) :abort t)
