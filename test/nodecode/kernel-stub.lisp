;;;; kernel-stub.lisp --- a stand-in for the part of nodecode the cell touches.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; This is NOT nodecode. It is the names the nodecode host
;;;; (nodecode/nodecode-host.lisp, verbs.lisp, cell.lisp) uses from
;;;; NODECODE.KERNEL (nlk) and NODECODE.EVOLVED (nle), written to the contract
;;;; nodecode's own docs/CELLS.md and docstrings state, so that the cell can
;;;; be compiled and run under a bare SBCL against a real rizin, with no
;;;; nodecode build in the loop. The engine itself (omp-re.asd) needs none of
;;;; it. It proves the cell's own code; it cannot prove nodecode's side of
;;;; the seam.

(require :asdf)
#-win32 (require :sb-posix)

(defpackage #:nodecode.kernel
  (:use #:cl)
  (:nicknames #:nlk)
  (:export #:define-peripheral
           #:home #:find-session-cwd
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
  (:export #:define-cell #:turn #:notice #:on-stop
           #:submit #:set-session-title
           #:*notices* #:*help* #:*commands* #:*stub-session* #:*stub-turn*))

(in-package #:nodecode.kernel)

;;; --- text and paths ---------------------------------------------------------------

(defvar *stub-home* nil "The scratch home the test runs in, a directory pathname.")
(defvar *stub-session-cwd* nil "What FIND-SESSION-CWD answers.")

(defun home (&optional (relative ""))
  (merge-pathnames relative *stub-home*))

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

;;; --- the engine's side: a turn, notices ----------------------------------------------

(defvar *stub-session* "smoke" "The session NLE:TURN says the calling thread works for.")
(defvar *notices* (make-hash-table :test #'equal))
(defvar *help* '())
(defvar *commands* '())
(defvar *registrations* nil)

(defvar *stub-turn* nil "The id of the turn NLE:TURN says is running, or NIL for an unnamed one.")

(defun turn ()
  (and *stub-session* (list :session-id *stub-session* :turn-id *stub-turn*)))

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
