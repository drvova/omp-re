;;;; session.lisp --- a session: its record, its rizin process, and acting in it.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A SESSION is everything the engine holds for one host session: the open
;;;; binary, the rizin process analyzing it, and the session's RECORD — an
;;;; append-only list of entries (re.binary, re.evidence, re.annotation,
;;;; re.finding, ...). The record is the truth and the process is a cache of
;;;; it: a rizin that died, a session reaped for idleness and a host restarted
;;;; all come back the same way, by spawning rizin on the recorded binary and
;;;; replaying what the record says was done to it.
;;;;
;;;; Where the record is kept, and which of it the session's current branch
;;;; sees, is the host's to say (host.lisp, :ENTRIES and :APPEND-ENTRY). With
;;;; no host saying, it is one JSON object a line in a file of the session's
;;;; own, all of it on the branch.
;;;;
;;;; What is replayed, what a status says of it and what else must be closed
;;;; with a session is not known here: a tool group says so by name
;;;; (CONTRIBUTE). IN-SESSION is the one way to act in a session, whoever
;;;; asks — a tool call, a /re line, a recipe composing reads.

(in-package #:omp-re)

;;; --- the session -------------------------------------------------------------------------

(defstruct (session (:copier nil))
  (id +default-session+ :type string)
  ;; One tool call or /re line at a time: rizin answers one request at a time,
  ;; and a record written by two threads at once is no record.
  (lock (sb-thread:make-mutex :name "omp-re session"))
  (rz nil)                              ; the static analysis process
  (binary-path nil)
  (binary-sha256 nil)
  (load-options nil)                    ; a JSON object, or NIL for header autodetection
  (file-entries (make-array 0 :adjustable t :fill-pointer 0)) ; the record's own file, as read and written
  (synced-view nil)                     ; the branch's entries the fields above were last set from,
  (synced-length -1)                    ; and how many there were then
  (applied '())                         ; ((CONTRIBUTION-NAME . FINGERPRINT) ...) of what the live rizin carries
  (kept '())                            ; ((NAME . VALUE) ...): what a tool group or a host keeps for the session
  (tools-off nil)
  (audit-warned nil)
  (calls 0)
  (artifacts 0)
  (last-used (get-universal-time)))

(defvar *sessions* (make-hash-table :test #'equal))
(defvar *sessions-lock* (sb-thread:make-mutex :name "omp-re sessions"))

(defvar *session* nil
  "The session the running tool call or /re line is for.")

(defun session-held (session name)
  (cdr (assoc name (session-kept session) :test #'equal)))

(defun (setf session-held) (value session name)
  (let ((entry (assoc name (session-kept session) :test #'equal)))
    (if entry
        (setf (cdr entry) value)
        (push (cons name value) (session-kept session)))
    value))

(defun session-directory (session)
  (uiop:ensure-directory-pathname (state-path "sessions" (file-safe (session-id session)))))

;;; --- the record, in a file of the session's own -------------------------------------------

(defun record-path (session)
  (merge-pathnames "branch.jsonl" (session-directory session)))

(defun load-record (session)
  "Read SESSION's record file. A torn last line — the process died
mid-append — loses that one entry, never the record."
  (let ((text (read-text-file (record-path session))))
    (when text
      (dolist (line (split-lines text))
        (let ((entry (and (not (blank-p line)) (json-parse line))))
          (when (and (hash-table-p entry) (jstring entry "customType"))
            (vector-push-extend entry (session-file-entries session))))))))

(defun file-append-entry (session type data &optional turn)
  "Append one entry of TYPE carrying DATA to SESSION's record file, on disk
before it is in memory's list: what was said to be recorded is. TURN, when a
host has turns, stamps the entry with the one it was written in."
  (let ((entry (obj "type" "custom"
                    "id" (format nil "~(~36r~)-~d" (get-universal-time)
                                 (length (session-file-entries session)))
                    "customType" type
                    "turn" (or turn :absent)
                    "data" data)))
    (append-text-file (record-path session) (format nil "~a~%" (json-encode entry)))
    (vector-push-extend entry (session-file-entries session))
    entry))

(defun find-session (id)
  "The session called ID, its record file read and its state restored from
the record on first use."
  (multiple-value-bind (session fresh)
      (sb-thread:with-mutex (*sessions-lock*)
        (let ((known (gethash id *sessions*)))
          (if known
              (values known nil)
              (let ((session (make-session :id id)))
                (load-record session)
                (values (setf (gethash id *sessions*) session) t)))))
    ;; Outside the table's lock: reading a fork's branch reads its ancestors'
    ;; records, which finds their sessions in turn.
    (when fresh
      (sb-thread:with-mutex ((session-lock session))
        (sync-to-branch session)))
    session))

;;; --- the record, as the session's branch sees it -------------------------------------------

(defun session-entries (session)
  "SESSION's record as its current branch sees it, a vector, oldest first."
  (if (host-service :entries)
      (or (ask-host :entries session) (vector))
      (session-file-entries session)))

(defun append-entry (type data &optional (session *session*))
  "Record one entry of TYPE carrying the JSON object DATA => the entry."
  (if (host-service :append-entry)
      (ask-host :append-entry session type data)
      (file-append-entry session type data)))

(defun entries-of (type &optional (session *session*))
  "The data of every entry of TYPE, in the order recorded."
  (loop for entry across (session-entries session)
        when (equal type (jstring entry "customType"))
          collect (jget entry "data")))

(defun binary-entries (type binary-path &optional (session *session*))
  "The data of the TYPE entries that belong to BINARY-PATH: an entry belongs
to whichever re.binary opened most recently before it. This is how
annotations, signatures, analysis passes and mapped files stay with the
binary they were made on when a session opens another."
  (loop with current = nil
        for entry across (session-entries session)
        for kind = (jstring entry "customType")
        for data = (jget entry "data")
        do (when (equal kind "re.binary")
             (setf current (jstring data "path")))
        when (and (equal kind type) (equal current binary-path))
          collect data))

(defun last-binary-entry (&optional (session *session*))
  (car (last (entries-of "re.binary" session))))

;;; --- what a tool group contributes ---------------------------------------------------------

(defstruct (contribution (:copier nil))
  (name "" :type string)
  (order 100)
  noun replay fingerprint status close)

(defvar *contributions* '()
  "What the tool groups have said of themselves, in ORDER.")

(defun contribute (name &key (order 100) noun replay fingerprint status close)
  "Say, in one call, what the tool group NAME adds to a session. All of it
is optional:
  REPLAY       (SESSION RZ BINARY-PATH) puts back into a fresh rizin what the
               record says the group did to this binary => (values FAILURES
               APPLIED): a line for each thing that would not go back, and
               how many did. A group that answers no APPLIED is not counted
               when a binary is opened, only its failures are listed.
  NOUN         what one replayed thing is called: \"annotation(s)\".
  FINGERPRINT  (SESSION BINARY-PATH) a string naming what of the group's the
               record has in effect: when it is no longer what the live rizin
               was given, that rizin is dropped and the next call replays.
  STATUS       (SESSION) the group's lines of /re status.
  CLOSE        (SESSION) end whatever else the group runs for the session.
ORDER places it among the others — in the replay, where a later layer may
name what an earlier one recovered, and in the status. Saying a NAME again
replaces what it said."
  (setf *contributions*
        (stable-sort (append (remove name *contributions* :key #'contribution-name :test #'string=)
                             (list (make-contribution :name name :order order :noun noun
                                                      :replay replay :fingerprint fingerprint
                                                      :status status :close close)))
                     #'< :key #'contribution-order))
  name)

(defun applied-fingerprint (session name)
  (or (cdr (assoc name (session-applied session) :test #'string=)) ""))

(defun (setf applied-fingerprint) (fingerprint session name)
  (let ((entry (assoc name (session-applied session) :test #'string=)))
    (if entry
        (setf (cdr entry) fingerprint)
        (push (cons name fingerprint) (session-applied session)))
    fingerprint))

(defun mark-applied (name &optional (session *session*))
  "Say that SESSION's rizin now holds exactly what the record has in effect
of the group NAME: a tool has just applied the one thing that changed."
  (let ((contribution (find name *contributions* :key #'contribution-name :test #'string=)))
    (when (and contribution (contribution-fingerprint contribution) (session-binary-path session))
      (setf (applied-fingerprint session name)
            (funcall (contribution-fingerprint contribution) session (session-binary-path session))))))

(defun applied-in-step-p (session)
  (loop for contribution in *contributions*
        for fingerprint = (contribution-fingerprint contribution)
        always (or (null fingerprint)
                   (string= (funcall fingerprint session (session-binary-path session))
                            (applied-fingerprint session (contribution-name contribution))))))

;;; --- the rizin process a session owns ------------------------------------------------------

(defun require-binary (&optional (session *session*))
  (or (session-binary-path session)
      (fail "omp-re: no binary open — use /re open <path>, (re:open \"path\") or the open_binary tool first")))

(defun spawn-rizin (binary-path &key load (session *session*))
  "Spawn and analyze a fresh rizin for BINARY-PATH, replay the record into
it, and make it SESSION's process => (values RZ REPLAYED), REPLAYED being
(CONTRIBUTION FAILURES APPLIED) for each group that replays. The process it
replaces is closed only once the new one is analyzed and live."
  (let ((binary-path (resolve-binary-path binary-path)))
    (assert-rizin-available)
    (when load (setf (session-load-options session) load))
    (let* ((load (or load (session-load-options session)))
           (rz (unwind-protect
                    (progn
                      (report-progress (format nil "rizin: analyzing ~a…" (file-namestring binary-path)))
                      (spawn-rz (resolve-rizin-path binary-path (and load (jget load "bits")))
                                binary-path :load load))
                 (report-progress nil)))
           (previous (session-rz session)))
      ;; The replay reads the record as it stands for this binary, so the
      ;; session must already say which binary is open.
      (setf (session-binary-path session) binary-path)
      (let ((replayed (handler-case
                          (loop for contribution in *contributions*
                                when (contribution-replay contribution)
                                  collect (multiple-value-bind (failures applied)
                                              (funcall (contribution-replay contribution)
                                                       session rz binary-path)
                                            (list contribution failures applied)))
                        (error (condition)
                          (rz-close rz)
                          (error condition)))))
        (setf (session-rz session) rz
              (session-applied session) '())
        (dolist (contribution *contributions*)
          (mark-applied (contribution-name contribution) session))
        (when (and previous (not (eq previous rz)))
          (rz-close previous))
        (values rz replayed)))))

(defun ensure-rizin (&optional (session *session*))
  "SESSION's live rizin, respawned — and the record replayed — when the
previous process died."
  (let ((rz (session-rz session)))
    (if (rz-alive-p rz)
        rz
        (progn
          (when rz (rz-close rz))
          (multiple-value-bind (rz replayed) (spawn-rizin (require-binary session) :session session)
            (let ((lost (loop for (contribution failures) in replayed
                              when failures
                                collect (format nil "omp-re: ~d ~a could not be replayed:~%~{~a~^~%~}"
                                                (length failures)
                                                (or (contribution-noun contribution)
                                                    (contribution-name contribution))
                                                failures))))
              (when lost
                (notify :warning "~{~a~^~%~}" lost)))
            rz)))))

(defun sync-to-branch (session)
  "Bring SESSION in line with the branch it is on: the binary its branch
last opened, that binary's hash and load options, and — when what the record
has in effect is no longer what the live rizin carries — no rizin, so the
next call that needs one starts it and replays exactly this branch's. Cheap
when nothing moved: it acts only on a view it has not seen. No process is
started here."
  (let ((view (session-entries session)))
    (unless (and (eq view (session-synced-view session))
                 (eql (length view) (session-synced-length session)))
      (setf (session-synced-view session) view
            (session-synced-length session) (length view))
      (let* ((binary (last-binary-entry session))
             (path (and binary (jstring binary "path"))))
        (unless (equal path (session-binary-path session))
          ;; The branch is about another binary, or none: the process
          ;; analyzing the old one has nothing to say about it.
          (rz-close (session-rz session))
          (setf (session-rz session) nil
                (session-binary-path session) path))
        (setf (session-binary-sha256 session) (and binary (jstring binary "sha256"))
              (session-load-options session) (let ((load (and binary (jget binary "load"))))
                                               (and (hash-table-p load) load)))
        (when (and path (rz-alive-p (session-rz session)) (not (applied-in-step-p session)))
          (rz-close (session-rz session))
          (setf (session-rz session) nil)))))
  session)

(defun close-session-processes (session)
  (rz-close (session-rz session))
  (setf (session-rz session) nil)
  (dolist (contribution *contributions*)
    (when (contribution-close contribution)
      ;; One group's trouble must not leave another's process running.
      (ignore-errors (funcall (contribution-close contribution) session)))))

(defun shutdown-sessions ()
  "Close every session's processes and forget the sessions; their records stay."
  (let ((sessions (sb-thread:with-mutex (*sessions-lock*)
                    (prog1 (loop for session being the hash-values of *sessions* collect session)
                      (clrhash *sessions*)))))
    (mapc #'close-session-processes sessions)
    t))

(defun reap-idle-sessions (idle-seconds)
  "Close the processes of every session nothing has called for IDLE-SECONDS.
Nothing is lost: the record is kept and the next call restores from it."
  (let ((now (get-universal-time)))
    (dolist (session (sb-thread:with-mutex (*sessions-lock*)
                       (loop for session being the hash-values of *sessions* collect session)))
      (when (>= (- now (session-last-used session)) idle-seconds)
        ;; Only when nothing is running on it: never wait, never interrupt.
        (when (sb-thread:grab-mutex (session-lock session) :waitp nil)
          (unwind-protect (close-session-processes session)
            (sb-thread:release-mutex (session-lock session))))))))

(defun start-idle-reaper ()
  "Reap, once a minute, the sessions unused for idle_minutes => a function
that stops doing so."
  (let* ((idle (* 60 (setting-value :idle-minutes)))
         (worker (start-worker "omp-re idle sessions" (lambda () (reap-idle-sessions idle)) 60)))
    (lambda () (stop-worker worker))))

;;; --- acting in a session -------------------------------------------------------------------

(defun hold-session (session thunk)
  "Call THUNK with SESSION as *SESSION*. The session's lock is taken, and
the session brought in line with its branch, only when this thread does not
hold it already: a verb called inside a recipe or a /re line's body acts in
the session its caller holds."
  (if (sb-thread:holding-mutex-p (session-lock session))
      (let ((*session* session))
        (funcall thunk))
      (sb-thread:with-mutex ((session-lock session))
        (let ((*session* session))
          (setf (session-last-used session) (get-universal-time))
          (sync-to-branch session)
          (funcall thunk)))))

(defun act-in-session (session what thunk)
  (handler-case (hold-session (if (stringp session) (find-session session) session) thunk)
    (re-error (condition)
      (values (princ-to-string condition) t))
    (error (condition)
      (values (format nil "omp-re: ~a failed: ~a" what condition) t))))

(defmacro in-session ((session what) &body body)
  "BODY acting in SESSION — a session or the id of one — with *SESSION*
bound to it => BODY's values, the first of them the text of an answer. This
is the one place a refusal becomes text: an RE-ERROR in BODY answers
(values ITS-WORDS T), and anything else that goes wrong answers the same way
as `omp-re: WHAT failed: ...'. A failure is an answer, never a signal."
  `(act-in-session ,session ,what (lambda () ,@body)))
