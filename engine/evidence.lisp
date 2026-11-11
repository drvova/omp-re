;;;; evidence.lisp --- the evidence: its records, their ids, and reading again.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; An observation of the binary is recorded as an re.evidence entry: which
;;;; tool, with what arguments, at what address, the hash of the text the
;;;; model was sent (the text itself in a content-addressed blob store), and
;;;; — for a read that can be repeated — the exact line, the hash of its
;;;; canonical output and the hash of the bytes it was taken against. A
;;;; finding cites these by id, the report lists them, /re verify and /re
;;;; carry read them again. What a record is, how an id written by hand finds
;;;; one, whether and how a record can be re-run (EVIDENCE-RERUN, which the
;;;; report's status, /re verify and /re carry all ask) and how a read
;;;; reaches rizin are all here, once.

(in-package #:omp-re)

;;; --- ids and hashes, as they are shown --------------------------------------------------------

(defparameter +shown-id-length+ 8
  "How much of an evidence or finding id a result shows.")

(declaim (ftype (function (record-id) (values string &optional)) shown-id))
(defun shown-id (id)
  (subseq id 0 (min +shown-id-length+ (length id))))

(defparameter +shown-hash-length+ 12)

(defun shown-hash (hash)
  (subseq hash 0 (min +shown-hash-length+ (length hash))))

(defparameter +shortest-id-prefix+ 6
  "The shortest prefix that may stand for an id: a result shows eight
characters, and fewer than six would too easily name the wrong record.")

(defun find-by-id (items id)
  "The one of ITEMS — JSON objects with an id — whose id is ID, or uniquely
begins with at least +SHORTEST-ID-PREFIX+ characters of it
=> (values ITEM NIL NIL), or (values NIL REASON WHY) with WHY one of :SHORT,
:MISSING and :AMBIGUOUS."
  (let ((exact (find id items :key (lambda (item) (jstring item "id")) :test #'equal)))
    (cond (exact (values exact nil nil))
          ((< (length id) +shortest-id-prefix+)
           (values nil (format nil "~a is too short (use at least ~d characters of the id)"
                               (js-string id) +shortest-id-prefix+)
                   :short))
          (t
           (let ((matches (remove-if-not (lambda (item) (uiop:string-prefix-p id (jstring item "id")))
                                         items)))
             (cond ((= 1 (length matches)) (values (first matches) nil nil))
                   ((null matches)
                    (values nil (format nil "no id starting ~a on this branch" (js-string id)) :missing))
                   (t (values nil (format nil "~a is ambiguous (~d matches)" (js-string id) (length matches))
                              :ambiguous))))))))

;;; --- the records -------------------------------------------------------------------------------

(defun evidence-records (&optional (session *session*))
  "The evidence on SESSION's branch, oldest first. A row counts when it has
an id, a tool and a summary: nothing may rest on less."
  (remove-if-not (lambda (record)
                   (and (jstring record "id") (jstring record "tool") (jstring record "summary")))
                 (entries-of "re.evidence" session)))

(defun find-evidence (id &optional (session *session*))
  (find-by-id (evidence-records session) id))

(defun evidence-id-at (ea &optional (session *session*))
  "The most recent evidence observed at EA, or NIL: what grounds an
annotation there. The index is the branch's, rebuilt when the branch is not
the one it was built from."
  (let* ((view (session-entries session))
         (held (session-held session "evidence-at")))
    (unless (and held (eq view (first held)) (eql (length view) (second held)))
      (let ((index (make-hash-table :test #'equal)))
        (dolist (record (evidence-records session))
          (let ((at (jstring record "ea")))
            (when (plusp (length at))
              (setf (gethash (normalize-addr at) index) (jstring record "id")))))
        (setf held (list view (length view) index)
              (session-held session "evidence-at") held)))
    (values (gethash (normalize-addr ea) (third held)))))

(defun blob-path (hash)
  (state-path "blobs" (subseq hash 0 2) (subseq hash 2 4) hash))

(defun write-blob (content)
  "Store CONTENT in the content-addressed blob store => its SHA-256. A blob
already there is left alone."
  (let* ((hash (sha256-hex content))
         (target (blob-path hash)))
    (unless (probe-file target)
      (write-file-atomically target content))
    hash))

(defun read-blob (hash)
  (and (stringp hash) (>= (length hash) 4) (read-text-file (blob-path hash))))

(defun evidence-tag (id)
  (format nil "[evidence ~a — cite it in record_finding]" (shown-id id)))

(defparameter +summary-octets+ 512
  "How much of a result's text its evidence record carries, in UTF-8 octets.")

(defun record-evidence (tool-name arguments text details &optional (session *session*))
  "Append one re.evidence record for a successful observation => its id.
TEXT is what the model was sent; DETAILS the result's own details object,
whose reproducibility fields are what /re verify later re-runs."
  (let ((id (uuid))
        (commands (jget details "commands")))
    (append-entry "re.evidence"
                  (obj "id" id
                       "tool" tool-name
                       "args" arguments
                       "ea" (or (jstring details "ea") :absent)
                       "outputHash" (write-blob text)
                       "artifactId" (or (jstring details "artifactId") :absent)
                       "commands" (if (and (json-array-p commands) (every #'stringp commands))
                                      commands
                                      :absent)
                       "reproHash" (or (jstring details "reproHash") :absent)
                       "canonicalExcerpt" (or (jstring details "canonicalExcerpt") :absent)
                       "shiftHash" (or (jstring details "shiftHash") :absent)
                       ;; Binds the evidence to the exact bytes it was taken against.
                       "binarySha256" (or (session-binary-sha256 session) :absent)
                       "summary" (clip-utf-8 text +summary-octets+))
                  session)
    id))

(defun evidence-place (record)
  "RECORD in a few words, wherever a list names one: its tool and where it read."
  (format nil "~a @ ~a" (jstring record "tool") (or (jstring record "ea") "?")))

(defun cite-text (record)
  "RECORD as the start of a message about it: what /re cite drafts."
  (format nil "Re: evidence ~a (~a)~%~%~a" (shown-id (jstring record "id")) (evidence-place record)
          (jstring record "summary")))

;;; --- what a record says of itself ----------------------------------------------------------------

(defparameter +read-tool+ "rizin_command"
  "The one tool whose results are evidence, and so the one whose records can
be re-run: its arguments are the whole read and its hash is over rizin's raw
output.")

(defun evidence-command-lines (record)
  "RECORD's commands when they are a non-empty array of strings, as a list."
  (let ((commands (jget record "commands")))
    (and (json-array-p commands) (plusp (length commands)) (every #'stringp commands)
         (coerce commands 'list))))

(defun evidence-command (record)
  "The exact line(s) recorded for RECORD, for display; failing those, the
recorded arguments rendered as a line; else NIL."
  (let ((lines (evidence-command-lines record))
        (command (jstring record "args" "command"))
        (addr (jstring record "args" "addr")))
    (cond (lines (format nil "~{~a~^ ; ~}" lines))
          (command (format nil "~a~@[ @ ~a~]" command (and (plusp (length addr)) addr))))))

(defun evidence-read (record)
  "The read RECORD — an evidence record, or a manifest's entry for one,
which has the same members — was taken by, {command, addr?}; NIL for any
other tool's record and for one that says no command. The recorded
arguments are the read. A manifest written before it carried them has only
the line that was sent, `<command> @ <addr>' as the policy gate joins them:
that line is split back at its last ` @ ', leaving `@!<blocksize>', which
is part of a command and not a seek, alone."
  (when (equal (jstring record "tool") +read-tool+)
    (let ((command (jstring record "args" "command"))
          (addr (jstring record "args" "addr"))
          (lines (evidence-command-lines record)))
      (if command
          (obj "command" command "addr" (if (plusp (length addr)) addr :absent))
          (let ((line (trimmed (if (= 1 (length lines)) (first lines) (jstring record "command")))))
            (when (plusp (length line))
              (multiple-value-bind (matched parts)
                  (ppcre:scan-to-strings (js-scanner "^(.*\\S)\\s+@\\s+([^!\\s]\\S*)$") line)
                (if matched
                    (obj "command" (aref parts 0) "addr" (aref parts 1))
                    (obj "command" line)))))))))

(defun evidence-rerun (record)
  "Whether RECORD — a record, or a manifest's entry for one — can be re-run
and its output compared => (values READ NIL), READ as EVIDENCE-READ answers
it, or (values NIL WHY): :PROVENANCE-ONLY for a record that names its
commands but is another tool's or carries no hash to compare with, :LEGACY
for one from before either was recorded. Decided from the record alone,
with nothing run. The one place this is decided."
  (let ((read (evidence-read record)))
    (cond ((and read (plusp (length (jstring record "reproHash")))) (values read nil))
          ((evidence-command-lines record) (values nil :provenance-only))
          (t (values nil :legacy)))))

(defun rerun-refusal (why)
  "What is said of a record EVIDENCE-RERUN answered WHY for."
  (ecase why
    (:provenance-only "provenance-only: no reproducible hash to compare (re-run by hand)")
    (:legacy "legacy: no reproducible hash recorded")))

(defparameter +unknown-evidence-status+ "unverifiable (legacy)"
  "The status of a cited id no evidence record is behind, and of a record
from before commands and hashes were recorded.")

(defun evidence-status (record)
  "What a report says of RECORD's verifiability: a manifest's `status', read
by /re carry and by manifests' other readers, so the three spellings are
fixed. `reproducible' is a record that can be re-run and is bound to the
bytes it was taken against."
  (multiple-value-bind (read why) (evidence-rerun record)
    (cond ((and read (plusp (length (jstring record "binarySha256")))) "reproducible")
          ((or read (eq why :provenance-only)) "provenance-only")
          (t +unknown-evidence-status+))))

;;; --- reading the binary, and reading again -------------------------------------------------------

(defparameter +read-seconds+ 120
  "One read-only command's ceiling: the first time, and every time it is run again.")

(defun gate-read (command addr)
  "COMMAND, at ADDR when given, through the read-only policy => the exact
line rizin is sent. A refusal is RE-ERROR."
  (values (check-rizin-command (load-catalog) command addr)))

(defun run-gated-line (line &optional (session *session*))
  "Run LINE — what GATE-READ answered — on SESSION's rizin
=> (values OUTPUT STDERR)."
  (rz-run (ensure-rizin session) line :seconds +read-seconds+))

(defun run-read (command addr &optional (session *session*))
  "One read of the binary: gated, then run => (values OUTPUT STDERR LINE).
The one way a read reaches rizin, the first time and every time after."
  (let ((line (gate-read command addr)))
    (multiple-value-bind (output stderr) (run-gated-line line session)
      (values output stderr line))))

(contribute "evidence" :order 50
  :status (lambda (session)
            (list (format nil "evidence on this branch: ~d" (length (evidence-records session))))))
