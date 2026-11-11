;;;; verify.lisp --- /re verify: re-derive the evidence from the open binary.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The report gate withholds a report whose claims lack an evidence id.
;;;; This is the next guarantee: a claim's evidence is not merely cited but
;;;; RE-RUNNABLE — its exact rizin command, run read-only against the same
;;;; binary (matched by SHA-256), still produces the same canonical output
;;;; hash. Evidence that cannot be re-run is flagged; evidence that was
;;;; tampered with or drifted FAILS the line, the same loud signal the report
;;;; gate gives for an ungrounded claim.
;;;;
;;;; Which records can be re-run is EVIDENCE-RERUN's to say (evidence.lisp).
;;;;
;;;; Read-only and without side effects: a command goes through the same
;;;; policy gate and the session's live rizin, and is sent to the process
;;;; directly, not as a tool call, so verifying records no new evidence.

(in-package #:omp-re)

(defun verify-row (record status detail)
  (obj "id" (jstring record "id")
       "tool" (jstring record "tool")
       "command" (or (evidence-command record) :absent)
       "status" status
       "detail" detail))

(defun rerun-evidence (record read binary-path)
  "Take READ — RECORD's own, as EVIDENCE-RERUN answered it — again on the
open binary and compare the canonical hash => a row. Never signals: anything
that goes wrong leaves the record unverifiable, which is not a failure."
  (let ((recorded (jstring record "reproHash")))
    (handler-case
        (let ((line (handler-case (gate-read (jstring read "command") (jstring read "addr"))
                      (re-error (condition)
                        (return-from rerun-evidence
                          (verify-row record "unverifiable"
                                      (format nil "command no longer runnable in this rizin build: ~a"
                                              condition)))))))
          (let ((rehash (canonical-hash (run-gated-line line) binary-path)))
            (if (string= rehash recorded)
                (verify-row record "reproducible" "re-run output hash matches")
                (verify-row record "tampered"
                            (format nil "output hash changed: recorded ~a… but re-run produced ~a…"
                                    (shown-hash recorded) (shown-hash rehash))))))
      (error (condition)
        (verify-row record "unverifiable" (format nil "re-run failed: ~a" condition))))))

(defun build-verification (&optional (session *session*))
  "One row for every evidence record: reproducible, tampered or unverifiable.
What cannot be re-run — another tool's record, a legacy one, one bound to no
binary or to a different one — is decided from the recorded fields alone and
never touches rizin; the catalog and the process are asked for only once a
record is really re-runnable."
  (let* ((binary-path (session-binary-path session))
         (current-sha (or (session-binary-sha256 session)
                          (and binary-path (ignore-errors (sha256-file binary-path))))))
    (loop for record in (evidence-records session)
          for (read why) = (multiple-value-list (evidence-rerun record))
          for bound-sha = (jstring record "binarySha256")
          collect (cond ((null read)
                         (verify-row record "unverifiable" (rerun-refusal why)))
                        ((zerop (length bound-sha))
                         (verify-row record "unverifiable" "legacy: evidence not bound to a binary hash"))
                        ((null current-sha)
                         (verify-row record "unverifiable" "no binary open to verify against"))
                        ((string/= bound-sha current-sha)
                         (verify-row record "unverifiable"
                                     (format nil "evidence was taken against a different binary — open sha ~a… to verify"
                                             (shown-hash bound-sha))))
                        (t (rerun-evidence record read binary-path))))))

(defun verify-evidence (&key strict (session *session*))
  "Run BUILD-VERIFICATION and say what it found => (values TEXT FAILED-P ROWS).
Tampered or drifted evidence fails. Unverifiable evidence fails only under
STRICT, so resuming an old session never spuriously breaks a pipeline."
  (let* ((rows (build-verification session))
         (with-status (lambda (status)
                        (remove-if-not (lambda (row) (equal status (jstring row "status"))) rows)))
         (reproducible (funcall with-status "reproducible"))
         (tampered (funcall with-status "tampered"))
         (unverifiable (funcall with-status "unverifiable")))
    (values
     (join-lines
      (append
       (list (format nil "omp-re: verify — ~d reproducible, ~d FAILED, ~d unverifiable (of ~d evidence record(s))"
                     (length reproducible) (length tampered) (length unverifiable) (length rows)))
       (mapcar (lambda (row)
                 (format nil "  FAIL ~a ~a `~a`: ~a" (shown-id (jstring row "id")) (jstring row "tool")
                         (or (jstring row "command") "?") (jstring row "detail")))
               tampered)
       (when strict
         (mapcar (lambda (row)
                   (format nil "  UNVERIFIABLE ~a ~a: ~a" (shown-id (jstring row "id")) (jstring row "tool")
                           (jstring row "detail")))
                 unverifiable))))
     (and (or tampered (and strict unverifiable)) t)
     rows)))

(define-slash "verify" (:usage "[--strict]"
                        :description "re-run cited rizin commands and check recorded output hashes"
                        :order 100)
    (words)
  (multiple-value-bind (text failed) (verify-evidence :strict (and (member "--strict" words :test #'string=) t))
    (values text failed)))
