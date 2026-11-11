;;;; package.lisp --- the engine's package, what a host may use of it, and its one condition.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Every refusal is RE-ERROR, carrying the engine's own words. The engine
;;;; needs SBCL, UIOP, cl-ppcre and rizin, and nothing of any host.
;;;;
;;;; A host is a package of its own that uses this one, and what it may use
;;;; is what is exported here: the surface (engine.lisp), the port it
;;;; answers (host.lisp), the record file it may keep a branch view over
;;;; (session.lisp), and the JSON and text helpers the surface's answers are
;;;; read with. Nothing else of the engine is a host's to name.

(defpackage #:omp-re
  (:use #:cl)
  (:lock t)
  (:export
   ;; the surface
   #:engine-tools #:engine-call #:engine-command
   #:engine-view #:engine-facts #:engine-preserved
   #:engine-restore #:engine-rekey #:engine-close #:engine-hold #:shutdown-sessions
   #:engine-name #:shown-id #:re-error
   ;; the port
   #:install-host #:clear-host #:with-host-service #:notify #:check-cancelled
   #:+settings+ #:setting-value #:+default-session+ #:turn-session-id
   ;; the record's own file, for a host that keeps a branch view over it
   #:find-session #:session-id #:session-held #:session-file-entries #:file-append-entry
   ;; JSON as the surface answers it
   #:obj #:jget #:jstring #:jnumber #:jlist #:json-array-p
   #:json-encode #:json-decode #:json-parse #:json-refusal
   ;; text
   #:trimmed #:blank-p #:split-lines #:join-lines #:js-scan #:ea-from-offset
   ;; the types the above are declared in (types.lisp); SESSION-ID is one too
   #:json-object #:json-array #:json-value #:answer #:level
   #:address-text #:record-id #:evidence-id #:finding-id #:sha256-hex))

(in-package #:omp-re)

(define-condition re-error (error)
  ((detail :initarg :detail))
  (:report (lambda (condition stream)
             (format stream "~a" (slot-value condition 'detail)))))

(defun fail (control &rest arguments)
  (error 're-error :detail (apply #'format nil control arguments)))
