;;;; run.lisp --- the engine's Lisp suite, and its two hosts'.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --non-interactive --load test/nodecode/run.lisp
;;;;   OMPRE_TEST_SUITES=core,annotate sbcl --non-interactive --load test/nodecode/run.lisp
;;;;
;;;; Loads the engine, and the nodecode host over a stand-in for the nodecode
;;;; kernel names that host uses (harness.lisp, kernel-stub.lisp), and runs
;;;; every suite-*.lisp beside this file, in name order, against a real
;;;; rizin, each in a scratch home of its own. Most suites drive the engine
;;;; through the nodecode host's verbs, as the nearest caller to hand;
;;;; suite-stdio starts the omp host as omp does, in a process of its own.
;;;; A suite's rizin half runs when rizin and the test binary
;;;; (OMPRE_TEST_BINARY, default /bin/ls) are present and says SKIPPED when
;;;; they are not. Needs SBCL and cl-ppcre (the distribution's package is
;;;; enough). Exits 0 when every check holds.

(load (merge-pathnames "harness.lisp" (or *load-truename* *default-pathname-defaults*)))
(sb-ext:exit :code (if (omp-re-test:run-suites) 0 1) :abort t)
