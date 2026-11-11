;;;; omp-re.asd --- the omp-re engine: reverse engineering with rizin.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The whole engine — rizin, the read-only command policy, the session
;;;; record, evidence, annotations, findings, verify, report, carry, the
;;;; debugger, the /re command — with no host in it. It needs SBCL, cl-ppcre
;;;; and the operator's rizin, and loads in a plain image:
;;;;
;;;;   sbcl --eval '(asdf:load-asd "omp-re.asd")' --eval '(asdf:load-system "omp-re")'
;;;;
;;;; A host is a system of its own over this one: it installs what the engine
;;;; asks of it (engine/host.lisp) and builds on the surface engine/engine.lisp
;;;; defines and engine/package.lisp exports. nodecode-re.asd is the nodecode
;;;; host, omp-re-stdio.asd the omp host.
;;;;
;;;; cl-ppcre is named because the read-only command policy is a set of
;;;; regular expressions (engine/policy-data.lisp).

(defsystem "omp-re"
  :description "Reverse engineering with rizin: evidence-backed findings, annotations and reports"
  :author "drvova"
  :license "MIT"
  :version "0.10.0"
  :depends-on ("cl-ppcre" (:feature (:not :win32) "sb-posix"))
  :pathname "engine/"
  :serial t
  :components ((:file "package")
               (:file "json")
               (:file "sha256")
               (:file "util")
               (:file "os")
               (:file "host")
               (:file "rizin")
               (:file "policy-data")
               (:file "policy")
               (:file "session")
               (:file "evidence")
               (:file "call")
               (:file "files")
               (:file "tools-core")
               (:file "slash")
               (:file "slash-lines")
               ;; The order a fresh rizin is given back what the record holds
               ;; is each group's own to say (CONTRIBUTE's :order), not this
               ;; list's. audit-claims stands before findings and report,
               ;; which put claims to it.
               (:file "extras")
               (:file "annotate")
               (:file "audit-claims")
               (:file "findings")
               (:file "verify")
               (:file "anchor")
               (:file "report")
               (:file "carry")
               (:file "debug")
               (:file "views")
               (:file "engine")))
