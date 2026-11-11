;;;; server.lisp --- the engine behind a pipe: JSON lines in, JSON lines out.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The omp host. omp is a TypeScript program, so the engine runs beside it
;;;; as one SBCL process for the whole omp process, and the two speak the
;;;; protocol docs/engine-protocol.md writes down: one JSON object a line,
;;;; both ways. omp's side (extensions/re) asks for what the engine's surface
;;;; offers (engine/engine.lisp); the engine asks back for what only omp can
;;;; do, which is the port of engine/host.lisp answered over the wire.
;;;;
;;;; One thread reads the pipe. Every request runs on a thread of its own, so
;;;; a long decompile in one session holds up nothing in another, and the
;;;; engine can ask omp something in the middle of a call without the two
;;;; waiting on each other. Calls into one session still take their turn:
;;;; the session's lock is the engine's.

(in-package #:omp-re-stdio)

;;; --- the wire --------------------------------------------------------------------------------

(defvar *wire-out* nil "The pipe to omp. Nothing else may write to it.")
(defvar *wire-lock* (sb-thread:make-mutex :name "omp-re wire"))

(defun send (message)
  (let ((line (json-encode message)))
    (sb-thread:with-mutex (*wire-lock*)
      (write-string line *wire-out*)
      (write-char #\Newline *wire-out*)
      (finish-output *wire-out*))))

(defstruct (request (:copier nil))
  id                                    ; omp's id for it; NIL for work the engine started itself
  (session-id +default-session+)
  directory                             ; where that session works
  has-ui
  (cancelled nil)
  (seen '()))                           ; the sessions whose record this request has already asked omp for

(defvar *request* nil "The request this thread serves.")

(defvar *requests* (make-hash-table :test #'equal :synchronized t)
  "omp's requests under way, by id: what a cancel finds.")

(defvar *answers* (make-hash-table :test #'eql :synchronized t)
  "What the engine has asked omp and not yet been answered, by the engine's
id for the question: (SEMAPHORE . ANSWER).")

(defvar *asked* 0)
(defvar *closing* nil "True once the pipe has ended: nobody is left to answer.")

(defun tell-omp (method &rest members)
  (let ((params (apply #'obj members)))
    (conform-params "toHost" method params)
    (send (obj "method" method "params" params))))

(defun ask-omp (method &rest members)
  "Ask omp METHOD and wait for its answer => the result. An error answered,
the pipe ending, or the request this thread serves being cancelled is an
error here; so is a question or an answer that is not the protocol's."
  (let* ((params (conform-params "toHost" method (apply #'obj members) :request t))
         (id (sb-thread:with-mutex (*wire-lock*) (incf *asked*)))
         (waiting (cons (sb-thread:make-semaphore) nil)))
    (setf (gethash id *answers*) waiting)
    (unwind-protect
         (progn
           (send (obj "id" id "method" method "params" params))
           (loop until (sb-thread:wait-on-semaphore (car waiting) :timeout 0.1)
                 do (when *closing* (error "omp is gone"))
                    (check-cancelled (format nil "asking omp for ~a" method)))
           (let ((answer (cdr waiting)))
             (when (jget answer "error")
               (error "~a" (or (jstring answer "error" "message") "omp refused")))
             (conform-result "toHost" method (jget answer "result"))))
      (remhash id *answers*))))

;;; --- the port, answered by omp -------------------------------------------------------------

(defvar *environment* (make-hash-table :test #'equal)
  "omp's environment, as it last said it: the engine's own process was
started once and omp's variables can change after.")
(defvar *state-directory* nil "omp's agent directory: everything is kept under its re/ folder.")
(defvar *met* (make-hash-table :test #'equal :synchronized t)
  "The sessions this process has been asked about. One it meets for the
first time may come with what an earlier engine held of it (ENGINE-MEMORY).")

(defun asking-session-id ()
  (if *request* (request-session-id *request*) +default-session+))

(defvar *record-lock* (sb-thread:make-mutex :name "omp-re record")
  "Held from asking omp about a record until the answer is the engine's
copy. A status band reads a session beside the call that holds it; without
this the two would each add what omp reported new.")

(defun host-record (session)
  "SESSION's record as omp's session branch holds it. omp is asked once per
request, and only for what the engine has not seen: the entries after the
last one it holds, or all of them when the branch is no longer the one
they were read from. What the engine appends meanwhile it adds itself.

The vector answered is never changed afterwards: a longer record is a new
vector. So whoever reads it beside the call that appends — a status band,
an immediate /re line — walks a record that holds still, and the engine
sees by identity when there is something new (the port's :ENTRIES)."
  (sb-thread:with-recursive-lock (*record-lock*)
    (let ((held (or (session-held session "omp record") (vector))))
      (unless (and *request* (member session (request-seen *request*)))
        (let* ((last (and (plusp (length held)) (jstring (aref held (1- (length held))) "id")))
               (answer (ask-omp "entries" "session" (session-id session)
                                "after" (or last :null) "count" (length held)))
               (all (jget answer "all"))
               (more (jget answer "append")))
          (cond ((json-array-p all) (setf held (copy-seq all)))
                ((and (json-array-p more) (plusp (length more)))
                 (setf held (concatenate 'simple-vector held more))))
          (setf (session-held session "omp record") held))
        (when *request* (push session (request-seen *request*))))
      held)))

(defun host-append (session type data)
  (sb-thread:with-recursive-lock (*record-lock*)
    (let* ((held (host-record session))
           (answer (ask-omp "append" "session" (session-id session) "type" type "data" data))
           (entry (obj "type" "custom" "id" (jstring answer "id") "customType" type "data" data)))
      (setf (session-held session "omp record") (concatenate 'simple-vector held (vector entry)))
      entry)))

(defun install-omp-host ()
  (install-host
   ;; omp has no section for the engine: its operator's settings are the
   ;; environment. The one thing it says itself is where state is kept.
   :setting (lambda (name)
              (if (eq name :state-dir)
                  (values *state-directory* (and *state-directory* t))
                  (values nil nil)))
   :environment (lambda (name) (values (gethash name *environment*)))
   :voice (lambda (key) (cdr (assoc key +omp-voice+)))
   :turn (lambda () (list :session-id (asking-session-id)))
   :directory (lambda (session-id)
                (and *request* (equal session-id (request-session-id *request*))
                     (request-directory *request*)))
   :entries #'host-record
   :append-entry #'host-append
   :notify (lambda (text level)
             (tell-omp "notify" "session" (asking-session-id) "text" text
                                "level" (string-downcase level)))
   :judge (lambda (prompt)
            (let ((answer (ask-omp "judge" "session" (asking-session-id) "prompt" prompt
                                           "seconds" (protocol-constant "judgeSeconds"))))
              (or (jstring answer "text")
                  (values nil (and (jstring answer "reason")
                                   (side-turn-failure (jstring answer "reason")))))))
   :progress (lambda (text)
               (tell-omp "progress" "session" (asking-session-id)
                                    "request" (or (and *request* (request-id *request*)) :null)
                                    "text" (or text :null)))
   :cancelled (lambda () (and *request* (request-cancelled *request*)))
   :save-artifact (lambda (session content label)
                    (let ((id (jstring (ask-omp "saveArtifact" "session" (session-id session)
                                                               "content" content "label" label)
                                       "id")))
                      (and id (values id (format nil "artifact://~a" id)))))
   :read-artifact (lambda (session id)
                    (jstring (ask-omp "readArtifact" "session" (session-id session) "id" id) "text"))
   :locate-artifact (lambda (session id)
                      (declare (ignore session))
                      (format nil "artifact://~a" id))
   :transcript (lambda (session type text details)
                 (tell-omp "transcript" "session" (session-id session) "type" type "text" text
                                        "details" details))
   :has-ui (lambda () (and *request* (request-has-ui *request*)))
   :keep-session (lambda (session name)
                   (ask-omp "keepSession" "session" (session-id session) "name" name))))

;;; --- what omp asks ---------------------------------------------------------------------------

(defun side-turn-failure (reason)
  "omp's own words for why its side model gave no reply, as the audit says
them: one line, short enough for a finding's note."
  (let ((text (or (first (split-lines (format nil "the audit side turn failed: ~a" reason))) "")))
    (subseq text 0 (min 200 (length text)))))

(defun band-size (octets)
  "OCTETS as the status band says a size: 512B, 1.5K, 142K, 2M."
  (let ((unit 0) (one 1))
    (loop while (and (>= octets (* one 1024)) (< unit 4))
          do (setf one (* one 1024)) (incf unit))
    (if (zerop unit)
        (format nil "~dB" octets)
        (multiple-value-bind (whole tenth) (floor (floor (+ (* octets 20) one) (* 2 one)) 10)
          (format nil "~d~:[.~d~;~*~]~a" whole (zerop tenth) tenth (char "KMGT" (1- unit)))))))

(defun band-lines (facts)
  "The status band of omp's screen, from the facts of a session's binary
(ENGINE-FACTS) => its two lines: the binary, then the counts."
  (flet ((said (&rest path) (apply #'jget facts path)))
    (vector (format nil "~{~a~^  ~}"
                    (remove nil
                            (list (said "name")
                                  (let ((kind (remove nil (list (said "format") (said "arch") (said "os")))))
                                    (and kind (format nil "~{~a~^ ~}" kind)))
                                  (and (said "entry") (format nil "entry ~a" (said "entry")))
                                  (and (integerp (said "size")) (band-size (said "size")))
                                  (and (plusp (length (said "prot")))
                                       (format nil "~{~a~^,~}" (coerce (said "prot") 'list))))))
            (format nil "~d fn · ~d findings · ~d evidence"
                    (or (said "fnCount") 0) (or (said "findings") 0) (or (said "evidence") 0)))))

(defun session-state (session-id)
  "What omp's own surface shows of the session between calls — the status
band's lines, and the evidence ids its /re completion offers, newest first,
each as it is shown — and what the session holds that no record has, for
omp to hand back to an engine started after this one. Sent with every
answer that may have changed them, so drawing never costs a round trip.
None of it waits for a call that holds the session or asks rizin anything."
  (let ((facts (engine-facts session-id)))
    (obj "band" (if facts (band-lines facts) :null)
         "evidence" (map 'simple-vector
                         (lambda (row) (vector (shown-id (aref row 0)) (aref row 1)))
                         (engine-evidence session-id (protocol-constant "completedEvidence")))
         "memory" (engine-memory session-id))))

(defun with-state (answer session-id)
  (setf (gethash "state" answer) (session-state session-id))
  answer)

(defun restore-in-background (request &key open)
  "Start restoring the request's session on a thread of its own and return
once that thread holds the session: a call that arrives next waits its turn
behind the analysis, it does not race it. While another call holds the
session this waits with the restore, for as long as omp waits for the
answer."
  (let ((held (sb-thread:make-semaphore))
        (session-id (request-session-id request)))
    (sb-thread:make-thread
     (lambda ()
       (let ((*request* (make-request :session-id session-id
                                      :directory (request-directory request)
                                      :has-ui (request-has-ui request))))
         (let ((answer nil))
           (unwind-protect
                (ignore-errors
                 (engine-hold session-id
                              (lambda ()
                                (sb-thread:signal-semaphore held)
                                (setf answer (engine-restore session-id :open open)))))
             (sb-thread:signal-semaphore held))
           (handler-case
               (progn
                 (when (and answer (jstring answer "text"))
                   (tell-omp "tell" "session" session-id "text" (jstring answer "text")
                                    "level" (jstring answer "level")))
                 (tell-omp "state" "session" session-id "state" (session-state session-id)))
             ;; Nobody waits for this thread: what it could not say is in the log.
             (error (condition)
               (format *error-output* "~&omp-re: after restoring ~a: ~a~%" session-id condition))))))
     :name "omp-re restore")
    (loop until (sb-thread:wait-on-semaphore held :timeout 0.1)
          do (check-cancelled "restoring the session"))))

(defun members-of (object &rest names)
  "OBJECT's members NAMES, those it has: what of an answer of the engine's
surface the wire carries."
  (let ((picked (obj)))
    (dolist (name names picked)
      (multiple-value-bind (value found) (gethash name object)
        (when found (setf (gethash name picked) value))))))

(defvar *methods* (make-hash-table :test #'equal)
  "What omp may ask, by method => (lambda (PARAMS REQUEST)). REQUEST is NIL
for a notification.")

(defmacro define-method (name (params request) &body body)
  "What the engine does when omp sends NAME. The protocol says whether it is
a request, whose answer BODY's value is, or a notification; and whether it
is done in the order it came or on a thread of its own."
  `(setf (gethash ,name *methods*)
         (lambda (,params ,request)
           (declare (ignorable ,params ,request))
           ,@body)))

(defun set-environment (params)
  (clrhash *environment*)
  (maphash (lambda (name value) (setf (gethash name *environment*) value))
           (jget params "variables"))
  (setf *state-directory* (jstring params "stateDir")))

(define-method "hello" (params request)
  (unless (eql +protocol+ (jget params "protocol"))
    (error "omp-re: the extension speaks protocol ~a and its engine protocol ~a: the two halves of omp-re are of different versions. Reinstall or upgrade the omp-re plugin, then start omp again."
           (jget params "protocol") +protocol+))
  (set-environment params)
  (obj "protocol" +protocol+
       "version" (asdf:component-version (asdf:find-system "omp-re"))))

(define-method "environment" (params request)
  (set-environment params))

(define-method "cancel" (params request)
  (let ((cancelled (gethash (jget params "id") *requests*)))
    (when cancelled (setf (request-cancelled cancelled) t))))

(define-method "shutdown" (params request)
  (throw 'leave nil))

(define-method "describe" (params request)
  (obj "tools" (map 'vector
                    (lambda (tool)
                      (members-of tool "name" "label" "description" "parameters" "approval"
                                       "approvalReason" "render"))
                    (engine-tools))
       "commands" (map 'vector
                       (lambda (command) (members-of command "name" "usage" "description" "view" "completes"))
                       (engine-commands))))

(define-method "call" (params request)
  (let ((session-id (request-session-id request)))
    (with-state (members-of (engine-call session-id (jstring params "name") (jget params "arguments")
                                         :call-id (jstring params "callId"))
                            "text" "failed" "refused" "details")
      session-id)))

(define-method "command" (params request)
  (let ((session-id (request-session-id request)))
    (with-state (engine-command session-id (jstring params "line")) session-id)))

(define-method "view" (params request)
  (engine-view (request-session-id request) (jstring params "kind") (jget params "arg")))

(define-method "preserved" (params request)
  (obj "lines" (engine-preserved (request-session-id request))))

(define-method "approval" (params request)
  (engine-approval (request-session-id request) (jstring params "callId") (jstring params "tool")
                   (jget params "approved") (jstring params "reason"))
  (obj))

(defun session-arrives (params request)
  "omp entered the session, or moved within it: bring it in line with its
branch, after the answer."
  (let ((session-id (request-session-id request)))
    (restore-in-background request :open (jstring params "binary"))
    (obj "state" (session-state session-id))))

(defun session-branches (params request)
  (when (jstring params "previous")
    (engine-rekey (jstring params "previous") (request-session-id request)))
  (session-arrives params request))

(defun session-leaves (params request)
  (declare (ignore params))
  (engine-close (request-session-id request))
  (remhash (request-session-id request) *met*)
  (obj))

(defparameter +events+
  '(("start" . session-arrives)
    ("switch" . session-arrives)
    ("tree" . session-arrives)
    ("branch" . session-branches)
    ("before-switch" . session-leaves)
    ("shutdown" . session-leaves))
  "What each kind of session event does. A kind that is not here is an
error: an event never falls to another's meaning.")

(define-method "event" (params request)
  (funcall (or (cdr (assoc (jstring params "kind") +events+ :test #'equal))
               (error "omp-re: the engine has no event ~a" (jstring params "kind")))
           params request))

(defun check-methods ()
  "The methods and event kinds defined here are exactly the protocol's."
  (flet ((same (what defined described)
           (let ((defined (sort (copy-list defined) #'string<))
                 (described (sort (copy-list described) #'string<)))
             (unless (equal defined described)
               (error "omp-re: stdio/server.lisp handles the ~a ~{~a~^, ~} and stdio/protocol.json has ~{~a~^, ~}"
                      what defined described)))))
    (same "methods"
          (loop for name being the hash-keys of *methods* collect name)
          (loop for name being the hash-keys of (jget *protocol* "toEngine") collect name))
    (same "events"
          (mapcar #'car +events+)
          (coerce (jget *protocol* "toEngine" "event" "params" "kind" "enum") 'list))))

(check-methods)

(defun meet-session (session-id memory)
  "A session omp asks about for the first time since this process started
is given what an earlier engine held of it, when omp sends that."
  (unless (gethash session-id *met*)
    (setf (gethash session-id *met*) t)
    (when (and memory (plusp (hash-table-count memory)))
      (engine-remember session-id memory))))

(defun serve-request (id method params)
  "Answer omp's request ID on a thread of its own."
  (let* ((session (jget params "session"))
         (request (make-request :id id
                                :session-id (or (jstring session "id") +default-session+)
                                :directory (jstring session "cwd")
                                :has-ui (eq t (jget session "hasUI")))))
    (setf (gethash id *requests*) request)
    (sb-thread:make-thread
     (lambda ()
       (let ((*request* request))
         (unwind-protect
              (send (handler-case
                        ;; What the engine writes to its log while it serves
                        ;; omp is said to the operator: omp is its log.
                        (handler-bind ((warning (lambda (warning)
                                                  (ignore-errors
                                                   (tell-omp "notify" "session" (request-session-id request)
                                                                      "text" (princ-to-string warning)
                                                                      "level" "warning"))
                                                  (muffle-warning warning))))
                          (conform-params "toEngine" method params :request t)
                          (when session
                            (meet-session (request-session-id request) (jget session "memory")))
                          (obj "id" id "result"
                               (conform-result "toEngine" method
                                               (funcall (gethash method *methods*) params request))))
                      (error (condition)
                        (obj "id" id "error" (obj "message" (princ-to-string condition))))))
           (remhash id *requests*))))
     :name (format nil "omp-re ~a" method))))

(defun serve-in-order (id method params)
  "Do what omp sent on the reader's own thread: what follows it on the pipe
must find it done."
  (conform-params "toEngine" method params :request (and id t))
  (let ((result (funcall (gethash method *methods*) params nil)))
    (when id
      (send (obj "id" id "result" (conform-result "toEngine" method result))))))

(defun say-alive ()
  "While omp waits for anything, tell it at a steady beat which of its
requests are being served. An analysis can run for minutes, so omp cannot
bound a request by the clock; it bounds the engine's silence instead, and
learns here of a request the engine never got or whose answer was lost."
  (loop until *closing*
        do (sleep (protocol-constant "aliveSeconds"))
           (let ((serving (sort (loop for id being the hash-keys of *requests* collect id) #'<)))
             (when (and serving (not *closing*))
               (ignore-errors (tell-omp "alive" "serving" (coerce serving 'simple-vector)))))))

(defun serve (in out)
  "Serve omp over IN and OUT until IN ends or omp says to leave. Whatever
happens to one message, the next is still read."
  (setf *wire-out* out)
  (install-omp-host)
  (sb-thread:make-thread #'say-alive :name "omp-re alive")
  (catch 'leave
    (loop for line = (read-line in nil nil)
          while line
          do (let ((message (json-parse (string-right-trim '(#\Return) line))))
               (when (hash-table-p message)
                 (let ((id (jget message "id"))
                       (method (jget message "method"))
                       (params (or (jget message "params") (obj))))
                   (handler-case
                       (cond
                         ((null method)
                          (let ((waiting (gethash id *answers*)))
                            (when waiting
                              (setf (cdr waiting) message)
                              (sb-thread:signal-semaphore (car waiting)))))
                         ((not (and (stringp method) (gethash method *methods*)))
                          (method-described "toEngine" method))
                         ((method-ordered-p method) (serve-in-order id method params))
                         (id (serve-request id method params))
                         (t (conform-params "toEngine" method params)))
                     (error (condition)
                       (if id
                           (send (obj "id" id "error" (obj "message" (princ-to-string condition))))
                           ;; Nobody waits for a notification's answer: the log has it.
                           (format *error-output* "~&~a~%" condition)))))))))
  (setf *closing* t)
  (shutdown-sessions))
