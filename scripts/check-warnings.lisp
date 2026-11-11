;;;; check-warnings.lisp --- every system compiled from scratch, and no warning let by.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --noinform --non-interactive --no-sysinit --no-userinit --load scripts/check-warnings.lisp
;;;;
;;;; Compiles the engine (omp-re), the omp host (omp-re-stdio) and the
;;;; nodecode host (nodecode-re, over the suite's stand-in for nodecode's
;;;; kernel) with every file recompiled, into a scratch directory so that the
;;;; user's compiled-file cache is neither trusted nor touched. Each WARNING
;;;; and each STYLE-WARNING signalled meanwhile is printed with the file it
;;;; was signalled in, and the script exits 1 when there was one.
;;;;
;;;; The engine's exported functions carry declared types (engine/types.lisp),
;;;; and a call that does not fit one is a warning: this is what holds the
;;;; two hosts to those declarations. No warning is allowed by its text.

(require :asdf)

(defpackage #:omp-re-check
  (:use #:cl))
(in-package #:omp-re-check)

(defparameter *root*
  (uiop:pathname-parent-directory-pathname
   (uiop:pathname-directory-pathname (or *load-truename* *default-pathname-defaults*))))

(defparameter *scratch*
  (uiop:ensure-directory-pathname
   (merge-pathnames (format nil "omp-re-warnings-~36r/" (random (expt 36 8) (make-random-state t)))
                    (uiop:temporary-directory))))

(defvar *caught* '() "(FILE KIND TEXT) of each warning, newest first.")

(defun note (condition)
  ;; A handler sees what SBCL signals and then does not print: loading a file
  ;; just compiled meets the macros its own compile defined, and SBCL holds
  ;; that redefinition, from the same place in the same file, to be none.
  (unless (typep condition sb-ext:*muffled-warnings*)
    ;; A warning the compiler keeps for the end of a compilation unit — a
    ;; function called and never defined — is signalled with no file under way.
    (let ((file (or *compile-file-truename* *load-truename*)))
      (push (list (if file (enough-namestring file *root*) "(at the end of the compilation unit)")
                  (if (typep condition 'style-warning) "STYLE-WARNING" "WARNING")
                  (princ-to-string condition))
            *caught*))))

(load (merge-pathnames "test/nodecode/kernel-stub.lisp" *root*))
(asdf:register-preloaded-system "nodecode")
(push *root* asdf:*central-registry*)
(asdf:initialize-output-translations
 `(:output-translations (,(namestring *root*) ,(namestring *scratch*)) :inherit-configuration))

;; Every warning is collected and the compile goes on to the next file: one
;; run lists them all.
(setf asdf:*compile-file-failure-behaviour* :ignore
      asdf:*compile-file-warnings-behaviour* :ignore)

(unwind-protect
     (handler-bind ((warning #'note))
       (dolist (system '("omp-re" "omp-re-stdio" "nodecode-re"))
         (asdf:load-system system :force t)))
  (uiop:delete-directory-tree *scratch* :validate t :if-does-not-exist :ignore))

(dolist (one (reverse *caught*))
  (destructuring-bind (file kind text) one
    (format t "~&~a: ~a~%~{    ~a~%~}" file kind (uiop:split-string text :separator '(#\Newline)))))
(format t "~&omp-re: ~d warning~:p compiling omp-re, omp-re-stdio and nodecode-re~%" (length *caught*))
(sb-ext:exit :code (if *caught* 1 0) :abort t)
