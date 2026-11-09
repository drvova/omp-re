;;;; run.lisp --- the nodecode cell's Lisp suite.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --non-interactive --load test/nodecode/run.lisp
;;;;   OMPRE_TEST_SUITES=core,annotate sbcl --non-interactive --load test/nodecode/run.lisp
;;;;
;;;; Loads the real system over a stand-in for the nodecode kernel names it
;;;; uses (harness.lisp, kernel-stub.lisp) and runs every suite-*.lisp beside
;;;; this file, in name order, against a real rizin. A suite's rizin half
;;;; runs when rizin and the test binary (OMPRE_TEST_BINARY, default /bin/ls)
;;;; are present and says SKIPPED when they are not. Needs SBCL and cl-ppcre
;;;; (the distribution's package is enough). Exits 0 when every check holds.

(load (merge-pathnames "harness.lisp" (or *load-truename* *default-pathname-defaults*)))
(in-package #:nodecode-re-test)

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
  (format t "~&nodecode-re: ~a, home ~a, rizin ~:[absent~;present~]~%" *root* *scratch* *rizin*)
  (dolist (file suites)
    (handler-case (load file)
      (error (condition)
        (push (format nil "~a did not load: ~a" (pathname-name file) condition) *failures*)
        (format t "  FAIL  ~a did not load: ~a~%" (pathname-name file) condition)))))

(ignore-errors (nodecode-re::stop-cell))
(uiop:delete-directory-tree *scratch* :validate t :if-does-not-exist :ignore)
(format t "~&nodecode-re: ~a checks, ~a failed~%" *checks* (length *failures*))
(dolist (failure (reverse *failures*)) (format t "  failed: ~a~%" failure))
(sb-ext:exit :code (if *failures* 1 0) :abort t)
