;;;; package.lisp --- the engine's package, and its one condition.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; One package holds the engine and, under nodecode, the verbs its model
;;;; calls. It is named after the nodecode cell's system — which is how that
;;;; host's folder loader finds START-CELL in it — and nicknamed RE so an
;;;; eval form reads (re:cmd "aflj"). It is meant to be used qualified only:
;;;; OPEN shadows its CL namesake (the model's verb).
;;;;
;;;; Every refusal is RE-ERROR, carrying the engine's own words. The engine
;;;; needs SBCL, UIOP, cl-ppcre and rizin, and nothing of any host.

(defpackage #:nodecode-re
  (:use #:cl)
  (:nicknames #:re)
  (:shadow #:open)
  (:export
   ;; model-facing vocabulary (see the primer in cell.lisp)
   #:open #:cmd #:json #:call #:tools #:doc #:slash #:status
   ;; recipes: reads composed once (recipes.lisp)
   #:triage #:scan-imports #:inspect-function #:find-comparisons #:find-crypto
   ;; the one condition
   #:re-error))

(in-package #:nodecode-re)

(define-condition re-error (error)
  ((detail :initarg :detail))
  (:report (lambda (condition stream)
             (format stream "~a" (slot-value condition 'detail)))))

(defun fail (control &rest arguments)
  (error 're-error :detail (apply #'format nil control arguments)))
