;;;; nodecode-re.asd --- omp-re as a nodecode cell: reverse engineering with rizin.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; This repository is the cell folder. Clone it (or link a checkout) into
;;;; the cells folder under the system's name:
;;;;
;;;;   git clone https://github.com/drvova/omp-re ~/.nodecode/cells/nodecode-re
;;;;
;;;; The folder loader loads the system at boot and the gateway calls
;;;; START-CELL, which reads the `re' section of ~/.nodecode/config.jsonc.
;;;; The Lisp under nodecode/ is the whole of it: omp-re's engine, ported
;;;; from the TypeScript the omp plugin runs (extensions/re), and over it the
;;;; verbs the model calls from eval, the /re command and the manual. rizin
;;;; is the operator's own install; nothing else is needed. See
;;;; docs/nodecode.md.
;;;;
;;;; cl-ppcre is named because the read-only command policy is a set of Perl
;;;; regular expressions shared with the TypeScript engine
;;;; (nodecode/policy-data.lisp is generated from it). nodecode's own system
;;;; depends on cl-ppcre, so nothing new is loaded.

(defsystem "nodecode-re"
  :description "Reverse engineering with rizin: evidence-backed findings, annotations and reports, as eval verbs"
  :author "drvova"
  :license "MIT"
  :version "0.9.1"
  :depends-on ("nodecode" "cl-ppcre")
  :pathname "nodecode/"
  :serial t
  :components ((:file "package")
               (:file "json")
               (:file "sha256")
               (:file "util")
               (:file "rizin")
               (:file "policy-data")
               (:file "policy")
               (:file "session")
               (:file "tools-core")
               ;; extras before annotate: on a fresh rizin, mapped files, analysis
               ;; passes and signatures are put back before the annotations that
               ;; may name what they recovered (replay runs in load order).
               (:file "extras")
               (:file "annotate")
               (:file "findings")
               (:file "verify")
               (:file "report")
               (:file "carry")
               (:file "debug")
               (:file "recipe-data")
               (:file "recipes")
               (:file "verbs")
               (:file "cell")))
