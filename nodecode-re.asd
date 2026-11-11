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
;;;; The engine is the system beside this one, omp-re.asd, which knows nothing
;;;; of nodecode; here is the nodecode host over it: the cell, the verbs the
;;;; model calls from eval, and the recipes, which are verbs. rizin is the
;;;; operator's own install. See docs/nodecode.md.

(defsystem "nodecode-re"
  :description "Reverse engineering with rizin: evidence-backed findings, annotations and reports, as eval verbs"
  :author "drvova"
  :license "MIT"
  :version "0.10.0"
  :depends-on ("nodecode" "omp-re")
  :pathname "nodecode/"
  :serial t
  :components ((:file "nodecode-host")
               (:file "recipe-data")
               (:file "recipes")
               (:file "verbs")
               (:file "cell")))
