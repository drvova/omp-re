;;;; kernel-stub.lisp --- a stand-in for the part of nodecode the cell touches.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; This is NOT nodecode. It is the dozen and a half names nodecode/*.lisp
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
           #:*stub-home* #:*stub-session-cwd* #:*stub-visible* #:*stub-lineage*))

(defpackage #:nodecode.evolved
  (:use #:cl)
  (:nicknames #:nle)
  (:export #:define-cell #:turn #:failure #:notice #:on-stop #:register-tool #:unregister-tool
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

(defun store-open-p ()
  "True once a test has described a session tree."
  (or (plusp (hash-table-count *stub-visible*)) (plusp (hash-table-count *stub-lineage*))))

(defun session-visible-turn-set (session-id)
  (values (gethash session-id *stub-visible*)))

(defun session-lineage (session-id)
  (values (gethash session-id *stub-lineage*)))

(defun find-session-cwd (session-id)
  (declare (ignore session-id))
  *stub-session-cwd*)

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
