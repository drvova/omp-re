;;;; load.lisp --- bring the omp host's system into this image.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Loaded by the two things that make an engine process for omp:
;;;; stdio/serve.lisp, which then serves, and scripts/build-image.lisp,
;;;; which then saves the image. It finds cl-ppcre, loads system
;;;; omp-re-stdio from this checkout, compiling what is stale, and prints
;;;; nothing. What goes wrong is an error whose text says what to install;
;;;; each of the two says it its own way.

(in-package #:cl-user)

(require :asdf)

;; Where Quicklisp is installed, cl-ppcre may only be there.
(let ((quicklisp (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (when (and (not (find-package '#:quicklisp)) (probe-file quicklisp))
    (ignore-errors (load quicklisp))))

(let ((root (uiop:pathname-parent-directory-pathname
             (uiop:pathname-directory-pathname (or *load-truename* *default-pathname-defaults*)))))
  (push root asdf:*central-registry*)
  (unless (ignore-errors (asdf:find-system "cl-ppcre"))
    (error "omp-re: the Common Lisp library cl-ppcre was not found. Install it — Debian/Ubuntu: apt install cl-ppcre; with Quicklisp: (ql:quickload \"cl-ppcre\"); otherwise put it where ASDF looks (~~/common-lisp/cl-ppcre/) — and start omp again."))
  (handler-case
      (handler-bind ((warning #'muffle-warning))
        (let ((*compile-verbose* nil) (*compile-print* nil) (*load-verbose* nil))
          (asdf:load-system "omp-re-stdio" :verbose nil)))
    (error (condition)
      (error "omp-re: the engine could not be loaded by ~a ~a: ~a"
             (lisp-implementation-type) (lisp-implementation-version) condition))))
