;;;; kernel-stub.lisp --- a stand-in for the part of nodecode the cell touches.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; This is NOT nodecode. It is the two dozen names nodecode/*.lisp
;;;; uses from NODECODE.KERNEL (nlk) and NODECODE.EVOLVED (nle), written to
;;;; the contract nodecode's own docs/CELLS.md and docstrings state, so that
;;;; the cell — the whole engine and its verbs — can be compiled and run
;;;; under a bare SBCL against a real rizin, with no nodecode build in the
;;;; loop. It proves the cell's own code; it cannot
;;;; prove nodecode's side of the seam. smoke.lisp is what runs on it.

(require :asdf)
(require :sb-posix)

(defpackage #:nodecode.kernel
  (:use #:cl)
  (:nicknames #:nlk)
  (:export #:define-peripheral #:spawn-program #:child-exit #:kill-tree #:run-bounded
           #:worker-start #:worker-stop #:write-file-atomically
           #:home #:expand-home #:find-session-cwd
           #:store-open-p #:session-visible-turn-set #:session-lineage
           ;; a side question (docs/cell-api.mdx, "Ask a side question")
           #:session-exists-p #:create-session #:durable-session-id
           #:active-input-admission-turn-id #:turn-terminal-kind #:turn-answer
           #:request-cancel-turn #:events
           #:*stub-home* #:*stub-session-cwd* #:*stub-visible* #:*stub-lineage*
           #:*stub-store-open* #:*stub-judge* #:*stub-sessions* #:*stub-submissions*
           #:*stub-cancels* #:stub-forget-sessions #:stub-open-turns))

(defpackage #:nodecode.evolved
  (:use #:cl)
  (:nicknames #:nle)
  (:export #:define-cell #:turn #:failure #:notice #:on-stop #:register-tool #:unregister-tool
           #:submit #:set-session-title
           #:list-dialog #:run-row #:ask-row #:bare-args-p #:*slash-effects*
           #:*tools* #:*notices* #:*help* #:*commands* #:*stub-session* #:*stub-turn* #:*failed*))

(in-package #:nodecode.kernel)

;;; --- text and paths ---------------------------------------------------------------

(defvar *stub-home* nil "The scratch home the test runs in, a directory pathname.")
(defvar *stub-session-cwd* nil "What FIND-SESSION-CWD answers.")

(defun home (&optional (relative ""))
  (merge-pathnames relative *stub-home*))

(defun expand-home (text &aux (text (string-trim '(#\Space #\Tab) text)))
  (if (uiop:string-prefix-p "~/" text)
      (merge-pathnames (subseq text 2) (user-homedir-pathname))
      (uiop:parse-native-namestring text)))

(defun write-file-atomically (path content &key mode directory-mode (parents t))
  "CONTENT, a string, to PATH through a temporary file beside it and one rename."
  (declare (ignore mode directory-mode))
  (let* ((native (if (stringp path) path (sb-ext:native-namestring path)))
         (temporary (format nil "~a.~a.~a.tmp" native (sb-posix:getpid) (random 1000000))))
    (when parents (ensure-directories-exist (uiop:parse-native-namestring native)))
    (with-open-file (out (uiop:parse-native-namestring temporary) :direction :output
                         :if-exists :supersede :external-format :utf-8)
      (write-string content out))
    (sb-posix:rename temporary native)
    path))

;;; --- the session tree: which turns are on a session's branch -------------------------
;;; A test sets these to play /tree, /redo and /fork.

(defvar *stub-visible* (make-hash-table :test #'equal)
  "session id => a table whose keys are the turn ids on that session's branch.")
(defvar *stub-lineage* (make-hash-table :test #'equal)
  "session id => ((ANCESTOR-SESSION-ID ANCHOR-TURN-ID POSITION) ...), root first.")

(defvar *stub-store-open* nil
  "True plays an open store with no session tree described: sessions can be
created and asked, and every entry is on its session's branch.")

(defun store-open-p ()
  "True once a test has described a session tree, or said the store is open."
  (or *stub-store-open*
      (plusp (hash-table-count *stub-visible*)) (plusp (hash-table-count *stub-lineage*))))

(defun session-visible-turn-set (session-id)
  (values (gethash session-id *stub-visible*)))

(defun session-lineage (session-id)
  (values (gethash session-id *stub-lineage*)))

(defun find-session-cwd (session-id)
  (declare (ignore session-id))
  *stub-session-cwd*)

;;; --- sessions, and a turn put to one: what a side question touches ------------------
;;; The names "Ask a side question" (docs/cell-api.mdx) is written in, shaped
;;; as src/session/identity.lisp, src/session/lifecycle.lisp and
;;; src/gateway/gateway.lisp shape them: CREATE-SESSION answers a
;;; DURABLE-SESSION, NLE:SUBMIT an ACTIVE-INPUT-ADMISSION and never waits on
;;; the turn, TURN-TERMINAL-KIND the kind string of the turn's terminal fact
;;; or NIL while it is open, TURN-ANSWER the assistant's text or NIL. No model
;;; is asked: a test says in *STUB-JUDGE* how the turn a submit starts ends.

(defstruct (durable-session (:constructor %make-durable-session))
  id cwd parent created-at anchor-turn-id anchor-log-position
  ;; Not the kernel's slots: what a test reads back.
  detached title)

(defstruct active-input-admission
  disposition turn turn-id prompt-id sequence (queue-depth 0))

(defstruct stub-turn id session kind answer payload)

(defvar *stub-sessions* (make-hash-table :test #'equal :synchronized t)
  "session id => the DURABLE-SESSION a CREATE-SESSION recorded.")
(defvar *stub-turns* (make-hash-table :test #'equal :synchronized t)
  "turn id => the STUB-TURN a submit started.")
(defvar *stub-submissions* '()
  "What NLE:SUBMIT was called with, newest first: plists of :SESSION :PROMPT
:TOOLS :TOOLS-P :SOURCE :SOURCE-ID :TURN.")
(defvar *stub-cancels* '()
  "The turns REQUEST-CANCEL-TURN was called for, newest first: (SESSION-ID TURN-ID REASON).")
(defvar *stub-judge* nil
  "How the turn a submit starts ends. NIL: completed, having said nothing.
A string: completed, with that answer. (:FAIL DETAIL): failed. (:CANCEL
REASON): cancelled. :NEVER: left open until it is asked to stop. (:ERROR
TEXT): the submit itself signals. A function of the prompt answers one of
these.")
(defvar *stub-counter* 0)

(defun stub-forget-sessions ()
  "Forget every session, turn, submission and cancel a test made."
  (clrhash *stub-sessions*)
  (clrhash *stub-turns*)
  (setf *stub-submissions* '() *stub-cancels* '() *stub-judge* nil))

(defun stub-open-turns ()
  "The ids of the turns that have not ended."
  (loop for turn being the hash-values of *stub-turns*
        unless (stub-turn-kind turn) collect (stub-turn-id turn)))

(defun session-exists-p (session-id)
  (check-type session-id string)
  (and (store-open-p)
       (or (gethash session-id *stub-sessions*)
           (gethash session-id *stub-visible*)
           (gethash session-id *stub-lineage*))
       t))

(defun create-session (&key id cwd parent command-id anchor-turn-id occurred-at detached)
  "Record a session => its DURABLE-SESSION. PARENT must exist; DETACHED and
an anchor are the two edges and never both."
  (declare (ignore command-id))
  (when (and detached anchor-turn-id)
    (error "a session edge is an anchor or detached, not both"))
  (when (and parent (not (session-exists-p parent)))
    (error "unknown parent session ~a" parent))
  (let ((session-id (or id (format nil "session-stub-~d" (incf *stub-counter*)))))
    (when (gethash session-id *stub-sessions*)
      (error "duplicate session ~a" session-id))
    (setf (gethash session-id *stub-sessions*)
          (%make-durable-session :id session-id
                                 :cwd (or cwd (uiop:native-namestring (uiop:getcwd)))
                                 :parent parent
                                 :created-at (or occurred-at "1970-01-01T00:00:00Z")
                                 :anchor-turn-id anchor-turn-id
                                 :detached (and detached t)))))

(defun turn-terminal-kind (turn-id)
  (check-type turn-id string)
  (let ((turn (gethash turn-id *stub-turns*)))
    (and turn (stub-turn-kind turn))))

(defun turn-answer (session-id &optional turn-id)
  (check-type session-id string)
  (let ((turn (and turn-id (gethash turn-id *stub-turns*))))
    (and (store-open-p) turn (equal session-id (stub-turn-session turn))
         (let ((answer (stub-turn-answer turn)))
           (and (stringp answer) (plusp (length answer)) answer)))))

(defun request-cancel-turn (session-id turn-id &optional (reason "cancelled") retract)
  "Ask SESSION-ID's open TURN-ID to stop; here it ends at once, cancelled."
  (declare (ignore retract))
  (let ((turn (gethash turn-id *stub-turns*)))
    (when (and turn (null (stub-turn-kind turn)) (equal session-id (stub-turn-session turn)))
      (push (list session-id turn-id (princ-to-string reason)) *stub-cancels*)
      (let ((payload (make-hash-table :test #'equal)))
        (setf (gethash "reason" payload) (princ-to-string reason)
              (stub-turn-payload turn) payload
              (stub-turn-kind turn) "turn.cancelled"))
      turn)))

(defun events (&key kind turn-id (as :instances) &allow-other-keys)
  "The one read of the log the cell makes: a turn's terminal fact, as its payload."
  (unless (eq as :payload)
    (error "the stand-in's EVENTS answers :as :payload alone, not ~s" as))
  (let ((turn (gethash turn-id *stub-turns*)))
    (and turn (equal kind (stub-turn-kind turn)) (stub-turn-payload turn))))

(defun stub-start-turn (session-id prompt)
  "Start a turn of SESSION-ID for PROMPT and end it as *STUB-JUDGE* says => its id."
  (let* ((id (format nil "turn-stub-~d" (incf *stub-counter*)))
         (turn (make-stub-turn :id id :session session-id))
         (how (if (functionp *stub-judge*) (funcall *stub-judge* prompt) *stub-judge*))
         (payload (make-hash-table :test #'equal)))
    (cond ((null how) (setf (stub-turn-kind turn) "turn.completed"))
          ((stringp how) (setf (stub-turn-kind turn) "turn.completed" (stub-turn-answer turn) how))
          ((eq how :never))
          ((and (consp how) (eq (first how) :fail))
           (setf (gethash "detail" payload) (second how)
                 (stub-turn-payload turn) payload
                 (stub-turn-kind turn) "turn.failed"))
          ((and (consp how) (eq (first how) :cancel))
           (setf (gethash "reason" payload) (second how)
                 (stub-turn-payload turn) payload
                 (stub-turn-kind turn) "turn.cancelled"))
          (t (error "*stub-judge* says ~s, which is no way for a turn to end" how)))
    (setf (gethash id *stub-turns*) turn)
    id))

;;; --- processes --------------------------------------------------------------------

(defun spawn-program (argv &key directory environment (output :stream) (error-output :stream) (input :null))
  "=> (values PID OUTPUT-STREAM ERROR-STREAM PROCESS INPUT-STREAM)"
  (let ((process (sb-ext:run-program (first argv) (rest argv)
                                     :search t :wait nil
                                     :input (if (eq input :stream) :stream nil)
                                     :output output
                                     :error (if (pathnamep error-output) (uiop:native-namestring error-output) error-output)
                                     :if-error-exists :append
                                     ;; What a binary prints is not always UTF-8: never signal on it.
                                     :external-format '(:utf-8 :replacement #\?)
                                     :directory (and directory (uiop:native-namestring directory))
                                     :environment (or environment (sb-ext:posix-environ)))))
    (values (sb-ext:process-pid process)
            (sb-ext:process-output process)
            (sb-ext:process-error process)
            process
            (sb-ext:process-input process))))

(defun run-bounded (argv &key (seconds 60) directory environment input
                             (output :string) (error-output :string))
  "Run ARGV to completion or SECONDS => (values OUTPUT ERROR-OUTPUT STATUS),
STATUS the exit code or :TIMEOUT."
  (declare (ignore output error-output))
  ;; stdout is read here to its end; stderr goes to a file so a child that
  ;; fills one pipe while the other is read cannot wedge; a watchdog thread
  ;; enforces the bound.
  (let* ((errors (uiop:native-namestring
                  (merge-pathnames (format nil "run-bounded-~a-~a.err" (sb-posix:getpid) (random 1000000))
                                   (uiop:temporary-directory))))
         (process (sb-ext:run-program (first argv) (rest argv)
                                      :search t :wait nil
                                      :input (if input :stream nil)
                                      :output :stream :error errors :if-error-exists :supersede
                                      :external-format '(:utf-8 :replacement #\?)
                                      :directory (and directory (uiop:native-namestring directory))
                                      :environment (or environment (sb-ext:posix-environ))))
         (timed-out nil)
         (watchdog (sb-thread:make-thread
                    (lambda ()
                      (loop repeat (ceiling (* seconds 20))
                            while (sb-ext:process-alive-p process)
                            do (sleep 0.05))
                      (when (sb-ext:process-alive-p process)
                        (setf timed-out t)
                        (sb-ext:process-kill process sb-posix:sigkill))))))
    (when input
      (ignore-errors (write-string input (sb-ext:process-input process))
                     (close (sb-ext:process-input process))))
    (let ((out (with-output-to-string (collected)
                 (loop for char = (read-char (sb-ext:process-output process) nil nil)
                       while char do (write-char char collected)))))
      (sb-ext:process-wait process)
      (sb-thread:join-thread watchdog :default nil)
      (close (sb-ext:process-output process))
      (let ((err (or (ignore-errors (uiop:read-file-string errors)) "")))
        (ignore-errors (delete-file errors))
        (values out err (if timed-out :timeout (sb-ext:process-exit-code process)))))))

(defstruct worker thread (stopping nil) (semaphore (sb-thread:make-semaphore)))

(defun worker-start (name step &key (wake 60) prime &aux (worker (make-worker)))
  "A thread NAME running STEP whenever WAKE seconds pass, until stopped."
  (declare (ignore prime))
  (setf (worker-thread worker)
        (sb-thread:make-thread
         (lambda ()
           (loop
             (sb-thread:wait-on-semaphore (worker-semaphore worker) :timeout wake)
             (when (worker-stopping worker) (return))
             (handler-case (funcall step) (error (condition) (warn "~a: ~a" name condition)))))
         :name name))
  worker)

(defun worker-stop (worker &key (timeout 5))
  (when worker
    (setf (worker-stopping worker) t)
    (sb-thread:signal-semaphore (worker-semaphore worker))
    (sb-thread:join-thread (worker-thread worker) :default nil :timeout timeout))
  nil)

(defun child-exit (pid process)
  (declare (ignore pid))
  (unless (sb-ext:process-alive-p process)
    (sb-ext:process-exit-code process)))

(defun kill-tree (pid)
  (ignore-errors (sb-posix:kill pid sb-posix:sigkill)))

;;; --- NLK:DEFINE-PERIPHERAL, to the shape of nodecode's own -------------------------

(defmacro define-peripheral (name &key not-running lock recursive filter)
  (declare (ignore recursive filter))
  (let* ((package (symbol-package name))
         (text (symbol-name name))
         (condition (intern (format nil "~a-ERROR" text) package))
         (slot (intern "DETAIL" package))
         (fail (intern "FAIL" package))
         (settings (intern (format nil "*~a*" text) package))
         (running (intern "RUNNING-SETTINGS" package))
         (verb (intern "DEFINE-VERB" package))
         (lock-var (intern "*LOCK*" package))
         (with-lock (intern (format nil "WITH-~a-LOCK" text) package)))
    `(progn
       (define-condition ,condition (error) ((,slot :initarg :detail))
         (:report (lambda (condition stream) (format stream "~a" (slot-value condition ',slot)))))
       (defun ,fail (format-control &rest args)
         (error ',condition :detail (apply #'format nil format-control args)))
       ,@(when not-running
           `((defvar ,settings nil)
             (defun ,running ()
               (or ,settings (,fail ,(format nil "the ~(~a~) cell is not running" text))))
             (defmacro ,verb (name lambda-list documentation &body body)
               (list* 'defun name lambda-list documentation '(,running) body))))
       ,@(when lock
           `((defvar ,lock-var (sb-thread:make-mutex :name ,lock))
             (defmacro ,with-lock (&body body)
               (list* 'sb-thread:with-mutex (list ',lock-var) body)))))))

(in-package #:nodecode.evolved)

;;; --- the engine's side: a turn, tools, notices --------------------------------------

(defvar *stub-session* "smoke" "The session NLE:TURN says the calling thread works for.")
(defvar *failed* nil "T once NLE:FAILURE was called.")
(defvar *tools* '())
(defvar *notices* (make-hash-table :test #'equal))
(defvar *help* '())
(defvar *commands* '())
(defvar *registrations* nil)

(defvar *stub-turn* nil "The id of the turn NLE:TURN says is running, or NIL for an unnamed one.")

(defun turn ()
  (and *stub-session* (list :session-id *stub-session* :turn-id *stub-turn*)))

;;; --- a command's dialog and effects, as tui/commands/bare.lisp shapes them --------------

(defvar *slash-effects* nil "The effects the caller of a command performs: (:clipboard :draft) from a shell.")

(defun bare-args-p (args)
  (zerop (length (string-trim '(#\Space #\Tab #\Return #\Newline) (or args "")))))

(defun run-row (label line &rest keys &key detail mark mark-tone key verb suffix)
  (declare (ignore detail mark mark-tone key verb suffix))
  (list* :label label :run (list :enter line) keys))

(defun ask-row (label ask line &rest keys &key placeholder detail mark mark-tone key verb)
  (declare (ignore detail mark mark-tone key))
  (list* :label label
         :ask (list :label ask :line line :placeholder (or placeholder "") :verb (or verb ""))
         keys))

(defun list-dialog (&rest keys &key title rows summary &allow-other-keys)
  (declare (ignore title rows summary))
  (list* :dialog :list keys))

(defun failure (text)
  (setf *failed* t)
  text)

;;; --- the one in-process ingress, as gateway.lisp shapes it -------------------------------

(defun submit (session-id prompt &key steer images command-id invocation source source-id
                                   (tools nil tools-p))
  "Put PROMPT into SESSION-ID => the admission; the turn is started, never waited for."
  (declare (ignore steer images invocation))
  (check-type session-id string)
  (check-type prompt string)
  (unless (and (listp tools) (every #'stringp tools))
    (error "submit :tools must be a list of tool names, got ~s" tools))
  (unless (nlk:session-exists-p session-id)
    (error "unknown session ~a" session-id))
  (let ((how (if (functionp nlk:*stub-judge*) nil nlk:*stub-judge*)))
    (when (and (consp how) (eq (first how) :error))
      (error "~a" (second how))))
  (let ((turn (nlk::stub-start-turn session-id prompt)))
    (push (list :session session-id :prompt prompt :tools tools :tools-p tools-p
                :source source :source-id source-id :turn turn)
          nlk:*stub-submissions*)
    (nlk::make-active-input-admission :disposition :started :turn-id turn
                                      :prompt-id (or command-id turn))))

(defun set-session-title (session-id title)
  "Name SESSION-ID TITLE => the name now in effect."
  (let ((session (gethash session-id nlk:*stub-sessions*)))
    (unless session (error "unknown session ~a" session-id))
    (setf (nlk::durable-session-title session) title)))

(defun notice (text &key level key)
  (declare (ignore level))
  (if text (setf (gethash key *notices*) text) (remhash key *notices*))
  text)

(defun on-stop (fn)
  (unless *registrations* (error "on-stop: no (starting ...) scope is open on this thread"))
  (push fn (car *registrations*))
  fn)

(defun register-tool (name schema function)
  (check-type name string)
  (check-type schema list)
  (setf *tools* (cons (list name schema function) (remove name *tools* :key #'first :test #'string=)))
  name)

(defun unregister-tool (name)
  (setf *tools* (remove name *tools* :key #'first :test #'string=))
  name)

;;; --- NLE:DEFINE-CELL: the clauses the cell uses, each with its inverse ----------------

(defun section-defaults (fields)
  "The settings plist a section's declared defaults spell: max_results is :MAX-RESULTS."
  (loop for field in fields
        when (stringp (first field))
          append (list (intern (substitute #\- #\_ (string-upcase (first field))) :keyword)
                       (eval (getf (cddr field) :default)))))

(defmacro define-cell (name &body clauses)
  (let* ((package (symbol-package name))
         (variable (intern (format nil "*~a*" (symbol-name name)) package))
         (running (intern "RUNNING-SETTINGS" package))
         (setting (intern "SETTING" package))
         (stop-variable (intern "*STOP*" package))
         (start-cell (intern "START-CELL" package))
         (stop-cell (intern "STOP-CELL" package))
         (section (rest (rest (assoc :section clauses))))
         (forms '()))
    (dolist (clause clauses)
      (destructuring-bind (head &rest arguments) clause
        (ecase head
          (:section)
          (:help (destructuring-bind (topic summary text) arguments
                   (push `(progn (push (list ,topic ,summary ,text) *help*)
                                 (on-stop (lambda () (setf *help* (remove ,topic *help* :key #'first)))))
                         forms)))
          (:command (destructuring-bind (spelling run &rest keys) arguments
                      (declare (ignore keys))
                      (push `(progn (push (cons ,spelling ,run) *commands*)
                                    (on-stop (lambda () (setf *commands* (remove ,spelling *commands*
                                                                                 :key #'car :test #'string=)))))
                            forms)))
          (:start (push `(funcall ,(first arguments)) forms)))))
    `(progn
       (export ',start-cell ,(package-name package))
       (defvar ,stop-variable nil)
       (defun ,setting (key)
         (let ((settings (,running)))
           (multiple-value-bind (indicator value tail) (get-properties settings (list key))
             (declare (ignore indicator))
             (unless tail (error "no setting ~s" key))
             value)))
       (defun ,stop-cell ()
         (when ,stop-variable
           (let ((scope ,stop-variable))
             (setf ,stop-variable nil)
             (loop for fn = (pop (car scope)) while fn do (funcall fn))))
         (setf ,variable nil)
         t)
       ;; OVERRIDES stands in for the operator's section of config.jsonc.
       (defun ,start-cell (&optional overrides)
         (,stop-cell)
         (setf ,variable (append overrides (section-defaults ',section)))
         (let ((*registrations* (list '())))
           (setf ,stop-variable *registrations*)
           ,@(reverse forms))
         #',stop-cell)
       ',name)))
