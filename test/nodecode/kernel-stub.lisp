;;;; kernel-stub.lisp --- a stand-in for the part of nodecode the cell touches.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; This is NOT nodecode. It is the two dozen names nodecode/*.lisp uses from
;;;; NODECODE.KERNEL (nlk) and NODECODE.EVOLVED (nle), written to the
;;;; contract nodecode's own docs/CELLS.md and docstrings state, so that the
;;;; cell's Lisp — its transport, its argument mapping, its verbs — can be
;;;; compiled and run under a bare SBCL against the real engine, with no
;;;; nodecode build in the loop. It proves the cell's own code; it cannot
;;;; prove nodecode's side of the seam. smoke.lisp is what runs on it.

(require :asdf)
(require :sb-posix)

(defpackage #:nodecode.kernel
  (:use #:cl)
  (:nicknames #:nlk)
  (:export #:define-peripheral #:spawn-program #:child-exit #:kill-tree #:environment-with
           #:decode-json #:encode-json-object #:make-json-object #:json-value
           #:home #:expand-home #:trimmed #:find-session-cwd
           #:*stub-home* #:*stub-session-cwd*))

(defpackage #:nodecode.evolved
  (:use #:cl)
  (:nicknames #:nle)
  (:export #:define-cell #:turn #:failure #:notice #:on-stop #:register-tool #:unregister-tool
           #:*tools* #:*notices* #:*help* #:*commands* #:*stub-session* #:*failed*))

(in-package #:nodecode.kernel)

;;; --- text and paths ---------------------------------------------------------------

(defun trimmed (text)
  (string-trim '(#\Space #\Tab #\Return #\Newline) text))

(defvar *stub-home* nil "The scratch home the test runs in, a directory pathname.")
(defvar *stub-session-cwd* nil "What FIND-SESSION-CWD answers.")

(defun home (&optional (relative ""))
  (merge-pathnames relative *stub-home*))

(defun expand-home (text &aux (text (string-trim '(#\Space #\Tab) text)))
  (if (uiop:string-prefix-p "~/" text)
      (merge-pathnames (subseq text 2) (user-homedir-pathname))
      (uiop:parse-native-namestring text)))

(defun find-session-cwd (session-id)
  (declare (ignore session-id))
  *stub-session-cwd*)

;;; --- JSON: objects EQUAL hash tables, arrays simple vectors, true T, false NIL, null :NULL

(defun decode-json (source)
  (let ((index 0) (end (length source)))
    (labels ((peek () (and (< index end) (char source index)))
             (skip () (loop while (and (< index end)
                                       (member (char source index) '(#\Space #\Tab #\Newline #\Return)))
                            do (incf index)))
             (expect (word value)
               (unless (and (<= (+ index (length word)) end)
                            (string= word source :start2 index :end2 (+ index (length word))))
                 (error "JSON: expected ~a at ~a" word index))
               (incf index (length word))
               value)
             (read-string ()
               (incf index)
               (with-output-to-string (out)
                 (loop
                   (let ((char (char source index)))
                     (incf index)
                     (case char
                       (#\" (return))
                       (#\\ (let ((escape (char source index)))
                              (incf index)
                              (case escape
                                (#\n (write-char #\Newline out))
                                (#\t (write-char #\Tab out))
                                (#\r (write-char #\Return out))
                                (#\b (write-char #\Backspace out))
                                (#\f (write-char #\Page out))
                                (#\u (let ((code (parse-integer source :start index :end (+ index 4) :radix 16)))
                                       (incf index 4)
                                       (when (and (<= #xd800 code #xdbff)
                                                  (string= "\\u" source :start2 index :end2 (+ index 2)))
                                         (let ((low (parse-integer source :start (+ index 2) :end (+ index 6) :radix 16)))
                                           (incf index 6)
                                           (setf code (+ #x10000 (ash (- code #xd800) 10) (- low #xdc00)))))
                                       (write-char (code-char code) out)))
                                (t (write-char escape out)))))
                       (t (write-char char out)))))))
             (read-number ()
               (let ((start index))
                 (loop while (and (< index end) (find (char source index) "+-0123456789.eE"))
                       do (incf index))
                 (let ((text (subseq source start index)))
                   (if (find-if (lambda (char) (find char ".eE")) text)
                       (let ((*read-default-float-format* 'double-float))
                         (with-standard-io-syntax (read-from-string text)))
                       (parse-integer text)))))
             (read-value ()
               (skip)
               (case (peek)
                 (#\{ (incf index)
                  (let ((object (make-hash-table :test #'equal)))
                    (skip)
                    (if (eql (peek) #\}) (incf index)
                        (loop
                          (skip)
                          (let ((key (read-string)))
                            (skip) (expect ":" nil)
                            (setf (gethash key object) (read-value)))
                          (skip)
                          (if (eql (peek) #\,) (incf index) (progn (expect "}" nil) (return)))))
                    object))
                 (#\[ (incf index)
                  (let ((items '()))
                    (skip)
                    (if (eql (peek) #\]) (incf index)
                        (loop
                          (push (read-value) items)
                          (skip)
                          (if (eql (peek) #\,) (incf index) (progn (expect "]" nil) (return)))))
                    (coerce (nreverse items) 'simple-vector)))
                 (#\" (read-string))
                 (#\t (expect "true" t))
                 (#\f (expect "false" nil))
                 (#\n (expect "null" :null))
                 (t (read-number)))))
      (read-value))))

(defun write-json (value out)
  (cond ((eq value t) (write-string "true" out))
        ((null value) (write-string "false" out))
        ((eq value :null) (write-string "null" out))
        ((stringp value)
         (write-char #\" out)
         (loop for char across value
               do (case char
                    (#\" (write-string "\\\"" out))
                    (#\\ (write-string "\\\\" out))
                    (#\Newline (write-string "\\n" out))
                    (#\Return (write-string "\\r" out))
                    (#\Tab (write-string "\\t" out))
                    (t (if (< (char-code char) 32)
                           (format out "\\u~4,'0x" (char-code char))
                           (write-char char out)))))
         (write-char #\" out))
        ((integerp value) (format out "~d" value))
        ((realp value) (format out "~f" value))
        ((hash-table-p value)
         (write-char #\{ out)
         (let ((first t))
           (maphash (lambda (key member)
                      (if first (setf first nil) (write-char #\, out))
                      (write-json key out) (write-char #\: out) (write-json member out))
                    value))
         (write-char #\} out))
        ((vectorp value)
         (write-char #\[ out)
         (loop for item across value for first = t then nil
               do (unless first (write-char #\, out)) (write-json item out))
         (write-char #\] out))
        (t (error "JSON: cannot encode ~s" value))))

(defun encode-json-object (object)
  (with-output-to-string (out) (write-json object out)))

(defun make-json-object (&rest pairs &aux (object (make-hash-table :test #'equal)))
  (loop for (key value) on pairs by #'cddr do (setf (gethash key object) value))
  object)

(defun json-value (object type &rest path &aux (value object) (present t))
  (dolist (key path)
    (if (hash-table-p value)
        (multiple-value-setq (value present) (gethash key value))
        (setf value nil present nil)))
  (values (ecase type
            (:any (if (eq value :null) nil value))
            (:string (and (stringp value) value))
            (:text (and (stringp value) (plusp (length value)) value))
            (:integer (and (integerp value) value))
            (:number (and (realp value) value))
            (:boolean (eq value t))
            (:object (and (hash-table-p value) value))
            (:array (and (vectorp value) (not (stringp value)) value)))
          present))

;;; --- processes --------------------------------------------------------------------

(defun environment-with (overrides &optional (environment (sb-ext:posix-environ)))
  (flet ((name (entry) (subseq entry 0 (or (position #\= entry) (length entry)))))
    (let ((names (mapcar #'name overrides)))
      (append (remove-if-not (lambda (entry) (find #\= entry)) overrides)
              (remove-if (lambda (entry) (member (name entry) names :test #'string=)) environment)))))

(defun spawn-program (argv &key directory environment (output :stream) (error-output :stream) (input :null))
  "=> (values PID OUTPUT-STREAM ERROR-STREAM PROCESS INPUT-STREAM)"
  (let ((process (sb-ext:run-program (first argv) (rest argv)
                                     :search t :wait nil
                                     :input (if (eq input :stream) :stream nil)
                                     :output output
                                     :error (if (pathnamep error-output) (uiop:native-namestring error-output) error-output)
                                     :if-error-exists :append
                                     :external-format :utf-8
                                     :directory (and directory (uiop:native-namestring directory))
                                     :environment (or environment (sb-ext:posix-environ)))))
    (values (sb-ext:process-pid process)
            (sb-ext:process-output process)
            (sb-ext:process-error process)
            process
            (sb-ext:process-input process))))

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

(defun turn ()
  (and *stub-session* (list :session-id *stub-session* :turn-id "turn-1")))

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
