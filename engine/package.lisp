;;;; package.lisp --- the engine's package, and its one condition.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Every refusal is RE-ERROR, carrying the engine's own words. The engine
;;;; needs SBCL, UIOP, cl-ppcre and rizin, and nothing of any host.
;;;;
;;;; OPEN is shadowed here although the engine defines no OPEN: the nodecode
;;;; host makes it a verb of this package (re:open), and a symbol can only be
;;;; shadowed before anything is read into the package.

(defpackage #:omp-re
  (:use #:cl)
  (:shadow #:open))

(in-package #:omp-re)

(define-condition re-error (error)
  ((detail :initarg :detail))
  (:report (lambda (condition stream)
             (format stream "~a" (slot-value condition 'detail)))))

(defun fail (control &rest arguments)
  (error 're-error :detail (apply #'format nil control arguments)))
