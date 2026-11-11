;;;; omp-re-stdio.asd --- the omp host: the engine behind a pipe.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The engine (omp-re.asd) with the server that lets omp, a TypeScript
;;;; program, drive it from another process: JSON lines on standard input and
;;;; output (docs/engine-protocol.md). stdio/serve.lisp is the script omp's
;;;; side starts; it loads this system.

(defsystem "omp-re-stdio"
  :description "omp-re for omp: the engine served over standard input and output"
  :author "drvova"
  :license "MIT"
  :version "0.10.0"
  :depends-on ("omp-re")
  :pathname "stdio/"
  :serial t
;; protocol.json is read when the system is loaded, not compiled in: a
  ;; change to it needs no recompile.
  :components ((:static-file "protocol.json")
               (:file "protocol")
               (:file "voice")
               (:file "server")))
