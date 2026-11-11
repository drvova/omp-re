;;;; make-carry-manifest.lisp --- the fixture test/tui-carry.sh carries onto another build.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --script test/e2e/make-carry-manifest.lisp <v1-binary> <report.md>
;;;;
;;;; Records three findings on build v1 of the sample fixture — real
;;;; rizin_command evidence, the real record_finding tool, a stand-in for the
;;;; support auditor so no model is needed — and writes the report and its
;;;; manifest. The engine runs alone here, with no host but that stand-in and
;;;; a scratch directory to keep its state in.

(require :asdf)
(let ((*standard-output* (make-broadcast-stream))
      (*error-output* (make-broadcast-stream)))
  (push (uiop:pathname-parent-directory-pathname
         (uiop:pathname-parent-directory-pathname
          (uiop:pathname-directory-pathname *load-truename*)))
        asdf:*central-registry*)
  (handler-bind ((warning #'muffle-warning))
    (asdf:load-system "omp-re")))

(in-package #:omp-re)

(destructuring-bind (&optional binary report) (uiop:command-line-arguments)
  (unless (and binary report)
    (format *error-output* "usage: sbcl --script test/e2e/make-carry-manifest.lisp <v1-binary> <report.md>~%")
    (sb-ext:exit :code 2 :abort t))
  (let ((state (uiop:ensure-directory-pathname (format nil "~a.state" report)))
        (session "tui-carry-fixture"))
    (install-host
     :home (lambda () state)
     :judge (lambda (prompt)
              (json-encode
               (map 'vector
                    (lambda (line)
                      (obj "index" (parse-integer line :start 6 :junk-allowed t)
                           "verdict" "supported" "reason" "fixture"))
                    (remove-if-not (lambda (line) (eql 0 (search "CLAIM " line))) (split-lines prompt))))))
    (flet ((must (answer)
             (when (jget answer "failed")
               (format *error-output* "~a~%" (jstring answer "text"))
               (shutdown-sessions)
               (sb-ext:exit :code 1 :abort t))
             answer))
      ;; What the engine would write to its log (the audit log is unsigned here) is not this script's to say.
      (handler-bind ((warning #'muffle-warning))
        (must (engine-call session "open_binary" (obj "path" binary)))
        (loop for (function claim) in '(("sym.fib" "fib computes Fibonacci numbers iteratively.")
                                        ("sym.clamp" "clamp bounds its input to [lo, hi].")
                                        ("sym.checksum" "checksum is a djb2 hash (h * 33 + c)."))
              do (let ((read (must (engine-call session "rizin_command" (obj "command" "pdf" "addr" function)))))
                   (must (engine-call session "record_finding"
                                      (obj "claim" claim "evidence" (vector (jstring read "evidenceId"))
                                           "addr" function "confidence" "confirmed")))))
        (must (engine-command session (format nil "report ~a --no-audit" report)))))
    (shutdown-sessions)
    (uiop:delete-directory-tree state :validate t :if-does-not-exist :ignore)))
