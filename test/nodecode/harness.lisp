;;;; harness.lisp --- load the cell over the kernel stand-in; CHECK and friends.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Loaded by run.lisp before the suites. It loads the real system
;;;; (nodecode-re.asd, nodecode/*.lisp) over kernel-stub.lisp, points the
;;;; cell at a scratch home, and gives the suites their vocabulary:
;;;;
;;;;   (suite "name")                      a heading
;;;;   (check "what holds" FORM)           FORM must answer true and not signal
;;;;   (refusal (lambda () ...))           the text of the error a thunk signals, or NIL
;;;;   (has "needle" text)                 substring test
;;;;   (with-cell (:surface "tools") ...)  the body with the cell started, stopped after
;;;;   *rizin*                             true when rizin and *binary* are there
;;;;   *binary*                            OMPRE_TEST_BINARY, default /bin/ls
;;;;   *scratch*                           the scratch home, a directory pathname
;;;;   (fresh-session)                     a session id nothing has used
;;;;   (in-session (id) ...)               the body as that session's turn

(load (merge-pathnames "kernel-stub.lisp" (or *load-truename* *default-pathname-defaults*)))

(defpackage #:nodecode-re-test
  (:use #:cl)
  (:export #:suite #:check #:refusal #:has #:with-cell #:*rizin* #:*binary* #:*scratch* #:*root*
           #:fresh-session #:in-session #:*checks* #:*failures*))
(in-package #:nodecode-re-test)

(defparameter *root*
  (uiop:pathname-parent-directory-pathname
   (uiop:pathname-parent-directory-pathname
    (uiop:pathname-directory-pathname (or *load-truename* *default-pathname-defaults*))))
  "The repository, two folders above this file.")

(defvar *checks* 0)
(defvar *failures* '())
(defvar *suite* "")

(defun suite (name)
  (setf *suite* name)
  (format t "~&~a~%" name)
  (finish-output))

(defmacro check (description form)
  `(progn
     (incf *checks*)
     (handler-case
         (if ,form
             (format t "  ok    ~a~%" ,description)
             (progn (push (format nil "~a: ~a" *suite* ,description) *failures*)
                    (format t "  FAIL  ~a~%" ,description)))
       (error (condition)
         (push (format nil "~a: ~a" *suite* ,description) *failures*)
         (format t "  FAIL  ~a~%        signalled: ~a~%" ,description condition)))
     (finish-output)))

(defun refusal (thunk)
  "The text of the error THUNK signals, or NIL when it returned."
  (handler-case (progn (funcall thunk) nil)
    (error (condition) (princ-to-string condition))))

(defun has (needle text)
  (and (stringp text) (search needle text) t))

;;; The system the cell's .asd depends on: its names are the stand-in's, already loaded.
(asdf:register-preloaded-system "nodecode")
(push *root* asdf:*central-registry*)
(asdf:load-system "nodecode-re")

(defparameter *scratch*
  (uiop:ensure-directory-pathname
   (uiop:native-namestring
    (merge-pathnames (format nil "nodecode-re-test-~a/" (sb-posix:getpid)) (uiop:temporary-directory)))))
(ensure-directories-exist *scratch*)
(setf nlk:*stub-home* *scratch*
      nlk:*stub-session-cwd* (uiop:native-namestring *scratch*))

(defparameter *binary* (or (uiop:getenv "OMPRE_TEST_BINARY") "/bin/ls"))
(defparameter *rizin*
  (and (probe-file *binary*)
       (ignore-errors (zerop (nth-value 2 (uiop:run-program '("rizin" "-v") :ignore-error-status t))))))

(defvar *session-counter* 0)
(defun fresh-session ()
  (format nil "test-~d" (incf *session-counter*)))

(defmacro in-session ((id) &body body)
  "BODY as a turn of the session called ID."
  `(let ((nle:*stub-session* ,id)) ,@body))

(defmacro with-cell ((&rest overrides) &body body)
  "BODY with the cell started under OVERRIDES — a plist standing in for the
operator's `re' section — and stopped after."
  `(progn
     (nodecode-re:start-cell (list ,@overrides))
     (unwind-protect (progn ,@body)
       (nodecode-re::stop-cell))))
