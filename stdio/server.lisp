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

(in-package #:omp-re)

(defparameter +protocol+ 1)

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
  "Say METHOD to omp, expecting no answer."
  (send (obj "method" method "params" (apply #'obj members))))

(defun ask-omp (method &rest members)
  "Ask omp METHOD and wait for its answer => the result. An error answered,
the pipe ending, or the request this thread serves being cancelled is an
error here."
  (let* ((id (sb-thread:with-mutex (*wire-lock*) (incf *asked*)))
         (waiting (cons (sb-thread:make-semaphore) nil)))
    (setf (gethash id *answers*) waiting)
    (unwind-protect
         (progn
           (send (obj "id" id "method" method "params" (apply #'obj members)))
           (loop until (sb-thread:wait-on-semaphore (car waiting) :timeout 0.1)
                 do (when *closing* (error "omp is gone"))
                    (check-cancelled (format nil "asking omp for ~a" method)))
           (let ((answer (cdr waiting)))
             (when (jget answer "error")
               (error "~a" (or (jstring answer "error" "message") "omp refused")))
             (jget answer "result")))
      (remhash id *answers*))))

;;; --- the port, answered by omp -------------------------------------------------------------

(defvar *environment* (make-hash-table :test #'equal)
  "omp's environment, as it last said it: the engine's own process was
started once and omp's variables can change after.")
(defvar *state-directory* nil "omp's agent directory: everything is kept under its re/ folder.")
(defvar *voice-overrides* '())

(defparameter +audit-seconds+ 30
  "How long a support audit waits for omp's side turn.")

(defun asking-session-id ()
  (if *request* (request-session-id *request*) +default-session+))

(defvar *record-lock* (sb-thread:make-mutex :name "omp-re record")
  "Held from asking omp about a record until the answer is in the engine's
copy. A status band reads a session beside the call that holds it; without
this the two would each add what omp reported new.")

(defun host-record (session)
  "SESSION's record as omp's session branch holds it. omp is asked once per
request, and only for what the engine has not seen: the entries after the
last one it holds, or all of them when the branch is no longer the one
they were read from. What the engine appends meanwhile it adds itself."
  (sb-thread:with-recursive-lock (*record-lock*)
    (let ((held (or (session-held session "omp record")
                    (setf (session-held session "omp record")
                          (make-array 0 :adjustable t :fill-pointer 0)))))
      (unless (and *request* (member session (request-seen *request*)))
        (let* ((last (and (plusp (length held)) (jstring (aref held (1- (length held))) "id")))
               (answer (ask-omp "entries" "session" (session-id session)
                                "after" (or last :null) "count" (length held))))
          (when (json-array-p (jget answer "all"))
            (setf held (make-array 0 :adjustable t :fill-pointer 0)
                  (session-held session "omp record") held))
          (loop for entry across (or (jget answer "all") (jget answer "append") #())
                do (vector-push-extend entry held)))
        (when *request* (push session (request-seen *request*))))
      held)))

(defun host-append (session type data)
  (sb-thread:with-recursive-lock (*record-lock*)
    (let* ((held (host-record session))
           (answer (ask-omp "append" "session" (session-id session) "type" type "data" data))
           (entry (obj "type" "custom" "id" (jstring answer "id") "customType" type "data" data)))
      (vector-push-extend entry held)
      entry)))

(defun install-omp-host ()
  (install-host
   :setting (lambda (name)
              (case name
                (:state-dir (values *state-directory* (and *state-directory* t)))
                (:audit-seconds (values +audit-seconds+ t))
                (t (values nil nil))))
   :environment (lambda (name) (values (gethash name *environment*)))
   :voice (lambda (key)
            (cdr (or (assoc key *voice-overrides*) (assoc key +omp-voice+))))
   :turn (lambda () (list :session-id (asking-session-id) :turn-id nil))
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
                                           "seconds" (setting-value :audit-seconds))))
              (or (jstring answer "text")
                  (values nil (jstring answer "reason")))))
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

(defun session-state (session-id)
  "What omp's own surface shows of the session between calls: the status
band's facts, and the evidence ids its /re completion offers, newest first.
Sent with every answer that may have changed them, so drawing either never
costs a round trip."
  (obj "facts" (or (engine-facts session-id) :null)
       "evidence" (multiple-value-bind (rows failed)
                      (in-session (session-id "listing evidence" :wait nil)
                        (map 'simple-vector
                             (lambda (record)
                               (vector (jstring record "id")
                                       (format nil "~a @ ~a" (jstring record "tool")
                                               (or (jstring record "ea") "?"))))
                             (last (reverse (evidence-records)) 200)))
                    (if failed (vector) rows))))

(defun with-state (answer session-id)
  (setf (gethash "state" answer) (session-state session-id))
  answer)

(defun restore-in-background (request &key open)
  "Start restoring the request's session on a thread of its own and return
once that thread holds the session: a call that arrives next waits its turn
behind the analysis, it does not race it."
  (let ((held (sb-thread:make-semaphore))
        (session-id (request-session-id request)))
    (sb-thread:make-thread
     (lambda ()
       (let ((*request* (make-request :session-id session-id
                                      :directory (request-directory request)
                                      :has-ui (request-has-ui request))))
         (let ((answer nil))
           (unwind-protect
                (in-session (session-id "restoring the session")
                  (sb-thread:signal-semaphore held)
                  (setf answer (engine-restore session-id :open open))
                  nil)
             (sb-thread:signal-semaphore held))
           (handler-case
               (progn
                 (when (and answer (jstring answer "text"))
                   (tell-omp "tell" "session" session-id "text" (jstring answer "text")
                                    "level" (jstring answer "level")))
                 (tell-omp "state" "session" session-id "state" (session-state session-id)))
             (error () nil)))))
     :name "omp-re restore")
    (sb-thread:wait-on-semaphore held :timeout 10)))

(defun handle (method params request)
  "The answer to omp's METHOD with PARAMS, a JSON object."
  (let ((session-id (request-session-id request)))
    (cond
      ((string= method "describe")
       (obj "tools" (engine-tools) "commands" (engine-commands)))
      ((string= method "call")
       (with-state (engine-call session-id (jstring params "name") (jget params "arguments")
                                :call-id (jstring params "callId"))
         session-id))
      ((string= method "command")
       (with-state (engine-command session-id (or (jstring params "line") "")) session-id))
      ((string= method "view")
       (engine-view session-id (or (jstring params "kind") "") (jget params "arg")))
      ((string= method "facts")
       (session-state session-id))
      ((string= method "preserved")
       (obj "lines" (engine-preserved session-id)))
      ((string= method "approval")
       (engine-approval session-id (jstring params "callId") (jstring params "tool")
                        (jget params "approved") (jstring params "reason"))
       (obj))
      ((string= method "event")
       (let ((kind (jstring params "kind")))
         (cond ((member kind '("before-switch" "shutdown") :test #'equal)
                (engine-close session-id)
                (obj))
               (t
                (when (and (equal kind "branch") (jstring params "previous"))
                  (engine-rekey (jstring params "previous") session-id))
                (restore-in-background request :open (and (equal kind "start") (jstring params "binary")))
                (obj "state" (session-state session-id))))))
      (t (error "omp-re: the engine has no method ~a" method)))))

(defun serve-request (id method params)
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
                          (obj "id" id "result" (handle method params request)))
                      (error (condition)
                        (obj "id" id "error" (obj "message" (princ-to-string condition))))))
           (remhash id *requests*))))
     :name (format nil "omp-re ~a" method))))

(defun set-environment (params)
  (let ((variables (jget params "variables")))
    (when (hash-table-p variables)
      (clrhash *environment*)
      (maphash (lambda (name value)
                 (when (stringp value) (setf (gethash name *environment*) value)))
               variables))
    (when (jstring params "stateDir")
      (setf *state-directory* (jstring params "stateDir")))))

(defun serve (in out)
  "Serve omp over IN and OUT until IN ends. Whatever happens to one
message, the next is still read."
  (setf *wire-out* out)
  (install-omp-host)
  (loop for line = (read-line in nil nil)
        while line
        do (let ((message (json-parse (string-right-trim '(#\Return) line))))
             (when (hash-table-p message)
               (let ((id (jget message "id"))
                     (method (jstring message "method"))
                     (params (or (jget message "params") (obj))))
                 (handler-case
                     (cond
                       ((null method)
                        (let ((waiting (gethash id *answers*)))
                          (when waiting
                            (setf (cdr waiting) message)
                            (sb-thread:signal-semaphore (car waiting)))))
                       ;; These three are done here, in the order they came:
                       ;; what follows them on the pipe must find them done.
                       ((string= method "hello")
                        (set-environment params)
                        (let ((voice (jget params "voice")))
                          (when (hash-table-p voice)
                            (setf *voice-overrides*
                                  (loop for key being the hash-keys of voice using (hash-value text)
                                        when (stringp text)
                                          collect (cons (intern (string-upcase (substitute #\- #\_ key)) :keyword)
                                                        text)))))
                        (send (obj "id" id "result"
                                   (obj "protocol" +protocol+
                                        "version" (asdf:component-version (asdf:find-system "omp-re"))))))
                       ((string= method "environment")
                        (set-environment params)
                        (when id (send (obj "id" id "result" (obj)))))
                       ((string= method "cancel")
                        (let ((request (gethash (jget params "id") *requests*)))
                          (when request (setf (request-cancelled request) t))))
                       ((string= method "shutdown")
                        (return))
                       (id (serve-request id method params)))
                   (error (condition)
                     (when (and id method)
                       (send (obj "id" id "error" (obj "message" (princ-to-string condition)))))))))))
  (setf *closing* t)
  (shutdown-sessions))
