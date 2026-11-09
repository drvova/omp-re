;;;; nodecode-re.asd --- omp-re as a nodecode cell: reverse engineering with rizin.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; This repository is the cell folder. Clone it (or link a checkout) into
;;;; the cells folder under the system's name and install the engine's
;;;; dependencies once:
;;;;
;;;;   git clone https://github.com/drvova/omp-re ~/.nodecode/cells/nodecode-re
;;;;   cd ~/.nodecode/cells/nodecode-re && bun install
;;;;
;;;; The folder loader loads the system at boot and the gateway calls
;;;; START-CELL, which reads the `re' section of ~/.nodecode/config.jsonc.
;;;; The Lisp under nodecode/ is the cell: the verbs the model calls from
;;;; eval, the /re command, the manual. The engine it drives is the same
;;;; TypeScript the omp plugin runs (extensions/re), reached over the stdio
;;;; bridge in nodecode/bridge.ts, so the two hosts cannot drift apart. rizin
;;;; and bun are the operator's own installs. See docs/nodecode.md.

(defsystem "nodecode-re"
  :description "Reverse engineering with rizin: evidence-backed findings, annotations and reports, as eval verbs"
  :author "drvova"
  :license "MIT"
  :version "0.9.1"
  :depends-on ("nodecode")
  :pathname "nodecode/"
  :serial t
  :components ((:file "package")
               (:file "bridge")
               (:file "verbs")
               (:file "cell")))
