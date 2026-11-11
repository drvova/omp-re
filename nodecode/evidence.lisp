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
;;;; one, what a record says of its own verifiability and how its command is
;;;; run again are all here, once.

(in-package #:nodecode-re)

;;; --- ids and hashes, as they are shown --------------------------------------------------------

(defparameter +shown-id-length+ 8
  "How much of an evidence or finding id a result shows.")

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
  "The evidence record ID names => as FIND-BY-ID answers."
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
  "The blob stored under HASH, or NIL when it is missing."
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

;;; --- what a record says of itself ----------------------------------------------------------------

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
  "The read RECORD can be taken again by — a rizin_command record's
{command, addr} — or NIL for any other tool's record or a malformed one."
  (let ((command (jstring record "args" "command"))
        (addr (jstring record "args" "addr")))
    (and (equal (jstring record "tool") "rizin_command")
         command
         (obj "command" command "addr" (if (plusp (length addr)) addr :absent)))))

(defun evidence-status (record)
  "What RECORD says of its own verifiability, from its fields alone and with
nothing re-run. `provenance-only' and `unverifiable (legacy)' are said of
records sessions written by earlier versions still hold: a tool that ran
several commands, and one from before the reproducibility hash."
  (cond ((and (plusp (length (jstring record "reproHash")))
              (plusp (length (jstring record "binarySha256"))))
         "reproducible")
        ((evidence-command-lines record) "provenance-only")
        (t "unverifiable (legacy)")))

;;; --- reading the binary, and reading again -------------------------------------------------------

(defparameter +read-seconds+ 120
  "One read-only command's ceiling: the first time, and every time it is run again.")

(defun run-read (command addr &optional (session *session*))
  "Gate COMMAND, at ADDR when given, through the read-only policy and run it
on SESSION's rizin => (values OUTPUT STDERR LINE), LINE being exactly what
rizin was sent. The one way a read reaches rizin; a refusal is RE-ERROR."
  (let ((line (check-rizin-command (load-catalog) command addr)))
    (multiple-value-bind (output stderr) (rz-run (ensure-rizin session) line :seconds +read-seconds+)
      (values output stderr line))))

(defun rerun-evidence-read (record &optional (session *session*))
  "Take RECORD's read again on the binary SESSION has open => as RUN-READ
answers. Nothing is recorded."
  (let ((read (or (evidence-read record)
                  (fail "omp-re: evidence ~a records no command that can be run again"
                        (shown-id (or (jstring record "id") "?"))))))
    (run-read (jstring read "command") (jstring read "addr") session)))

(contribute "evidence" :order 50
  :status (lambda (session)
            (list (format nil "evidence on this branch: ~d" (length (evidence-records session))))))

;;; --- names the tool groups still call; removed when they move to the above ---------------
;;; EVIDENCE-ID-OF text (recipes.lisp)   → CALL-TOOL's fourth value, the id
;;;     itself; (shown-id id) is what a line cites.
;;; In the tool groups' own files, to be deleted there for the names above:
;;;   findings.lisp  COLLECTED-EVIDENCE → EVIDENCE-RECORDS; RESOLVE-ID → FIND-BY-ID;
;;;                  SHORT-ID → SHOWN-ID; +MIN-ID-PREFIX+ → +SHORTEST-ID-PREFIX+
;;;   verify.lisp    RECORDED-STATUS → EVIDENCE-STATUS; RECORDED-COMMAND → EVIDENCE-COMMAND;
;;;                  RECORDED-COMMAND-LINES → EVIDENCE-COMMAND-LINES;
;;;                  check-rizin-command + rz-run with +VERIFY-COMMAND-SECONDS+ → RERUN-EVIDENCE-READ
;;;   report.lisp    RIZIN-COMMAND-ARGUMENTS → EVIDENCE-READ
;;;   carry.lisp     SHORT-SHA's subseq → SHOWN-HASH; its two check-rizin-command + rz-run
;;;                  with +CARRY-COMMAND-SECONDS+ → RUN-READ
;;;   every inline (subseq hash 0 (min 12 ...)) → SHOWN-HASH

(defun evidence-id-of (text)
  "The shown id in TEXT's trailing [evidence xxxxxxxx ...] tag, or NIL."
  (let ((tag (search "[evidence " text :from-end t)))
    (and tag
         (<= (+ tag 10 +shown-id-length+) (length text))
         (subseq text (+ tag 10) (+ tag 10 +shown-id-length+)))))
