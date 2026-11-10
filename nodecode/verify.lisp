;;;; verify.lisp --- /re verify: re-derive the evidence from the open binary.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Ported from omp-re's verify.ts (its sha256File is the spine's
;;;; SHA256-FILE).
;;;;
;;;; The report gate withholds a report whose claims lack an evidence id.
;;;; This is the next guarantee: a claim's evidence is not merely cited but
;;;; RE-RUNNABLE — its exact rizin command, run read-only against the same
;;;; binary (matched by SHA-256), still produces the same canonical output
;;;; hash. Evidence that cannot be re-run is flagged; evidence that was
;;;; tampered with or drifted FAILS the line, the same loud signal the report
;;;; gate gives for an ungrounded claim.
;;;;
;;;; Only rizin_command evidence is machine-verified: its recorded arguments
;;;; fully re-run the line and its hash is over the raw rizin output.
;;;;
;;;; Read-only and without side effects: a command goes through the same
;;;; policy gate and the session's live rizin, and is sent to the process
;;;; directly, never through CALL-TOOL, so verifying records no new evidence.

(in-package #:nodecode-re)

(defparameter +verify-command-seconds+ 120)

(defun recorded-status (record)
  "What an evidence RECORD says of itself, from its fields alone and with
nothing re-run — what the report's manifest shows."
  (cond ((and (plusp (length (jstring record "reproHash")))
              (plusp (length (jstring record "binarySha256"))))
         "reproducible")
        ((recorded-command-lines record) "provenance-only")
        (t "unverifiable (legacy)")))

(defun recorded-command-lines (record)
  "RECORD's commands when they are a non-empty array of strings, as a list."
  (let ((commands (jget record "commands")))
    (and (vectorp commands) (not (stringp commands)) (plusp (length commands))
         (every #'stringp commands)
         (coerce commands 'list))))

(defun recorded-command (record)
  "The exact line(s) recorded for RECORD, for display; failing those, the
recorded arguments rendered as a line; else NIL."
  (let ((lines (recorded-command-lines record))
        (command (jstring record "args" "command"))
        (addr (jstring record "args" "addr")))
    (cond (lines (format nil "~{~a~^ ; ~}" lines))
          (command (format nil "~a~@[ @ ~a~]" command (and (plusp (length addr)) addr))))))

(defun verify-row (record status detail)
  (obj "id" (jstring record "id")
       "tool" (jstring record "tool")
       "command" (or (recorded-command record) :absent)
       "status" status
       "detail" detail))

(defun rerun-evidence (record binary-path)
  "Re-run RECORD's command on the open binary and compare the canonical hash
=> a row. Never signals: anything that goes wrong leaves the record
unverifiable, which is not a failure."
  (let ((command (jstring record "args" "command"))
        (addr (jstring record "args" "addr"))
        (recorded (jstring record "reproHash")))
    (handler-case
        (let ((line (handler-case (check-rizin-command (load-catalog) command addr)
                      (re-error (condition)
                        (return-from rerun-evidence
                          (verify-row record "unverifiable"
                                      (format nil "command no longer runnable in this rizin build: ~a"
                                              condition)))))))
          (let ((rehash (canonical-hash (rz-run (ensure-rizin) line :seconds +verify-command-seconds+)
                                        binary-path)))
            (if (string= rehash recorded)
                (verify-row record "reproducible" "re-run output hash matches")
                (verify-row record "tampered"
                            (format nil "output hash changed: recorded ~a… but re-run produced ~a…"
                                    (subseq recorded 0 (min 12 (length recorded))) (subseq rehash 0 12))))))
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
    (loop for record in (collected-evidence session)
          for repro-hash = (jstring record "reproHash")
          for bound-sha = (jstring record "binarySha256")
          collect (cond ((or (string/= (jstring record "tool") "rizin_command")
                             (zerop (length repro-hash)))
                         (verify-row record "unverifiable"
                                     (if (recorded-command-lines record)
                                         "provenance-only: tool ran multiple internal commands; re-run manually"
                                         "legacy: no reproducible hash recorded")))
                        ((zerop (length bound-sha))
                         (verify-row record "unverifiable" "legacy: evidence not bound to a binary hash"))
                        ((null current-sha)
                         (verify-row record "unverifiable" "no binary open to verify against"))
                        ((string/= bound-sha current-sha)
                         (verify-row record "unverifiable"
                                     (format nil "evidence was taken against a different binary — open sha ~a… to verify"
                                             (subseq bound-sha 0 (min 12 (length bound-sha))))))
                        ((null (jstring record "args" "command"))
                         (verify-row record "unverifiable" "recorded args carry no command to re-run"))
                        (t (rerun-evidence record binary-path))))))

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
                 (format nil "  FAIL ~a ~a `~a`: ~a" (short-id (jstring row "id")) (jstring row "tool")
                         (or (jstring row "command") "?") (jstring row "detail")))
               tampered)
       (when strict
         (mapcar (lambda (row)
                   (format nil "  UNVERIFIABLE ~a ~a: ~a" (short-id (jstring row "id")) (jstring row "tool")
                           (jstring row "detail")))
                 unverifiable))))
     (and (or tampered (and strict unverifiable)) t)
     rows)))

(define-slash "verify" (:usage "[--strict]"
                        :description "re-run cited rizin commands and check recorded output hashes")
    (words)
  (multiple-value-bind (text failed) (verify-evidence :strict (and (member "--strict" words :test #'string=) t))
    (values text failed)))
