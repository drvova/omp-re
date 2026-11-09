;;;; package.lisp --- the NODECODE-RE package: the model's verbs and their condition.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; One package, named after the system, which is how the folder loader finds
;;;; START-CELL in it, and nicknamed RE so an eval form reads
;;;; (re:cmd "aflj"). It is meant to be used qualified only: OPEN shadows its
;;;; CL namesake (the model's verb).
;;;;
;;;; Every exported verb returns a STRING — but JSON, which answers the
;;;; decoded data — and every refusal is RE-ERROR, which the eval snippet
;;;; renders as "ERROR: ..." with the detail.
;;;;
;;;; The engine underneath is this package too: omp-re's own, ported from the
;;;; TypeScript the omp plugin runs (extensions/re) file by file. It needs
;;;; rizin and nothing else.

(defpackage #:nodecode-re
  (:use #:cl)
  (:nicknames #:re)
  (:shadow #:open)
  (:export
   ;; model-facing vocabulary (see the primer in cell.lisp)
   #:open #:cmd #:json #:call #:tools #:doc #:slash #:status
   ;; the one condition
   #:re-error))

(in-package #:nodecode-re)

;;; RE-ERROR and FAIL; *RE*, RUNNING-SETTINGS and DEFINE-VERB. SETTING comes
;;; from the NLE:DEFINE-CELL declaration in cell.lisp, which loads last; the
;;; files between read the section through it.
(nlk:define-peripheral re :not-running t)
