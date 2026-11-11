;;;; harness.lisp --- load the cell over the kernel stand-in; the suites' vocabulary.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Loaded by run.lisp before the suites. It loads the engine (omp-re.asd)
;;;; and the nodecode host over it (nodecode-re.asd) on kernel-stub.lisp, and
;;;; gives the suites their vocabulary:
;;;;
;;;;   (suite "name")                      a heading
;;;;   (check "what holds" FORM)           FORM must answer true and not signal
;;;;   (refusal (lambda () ...))           the text of the error a thunk signals, or NIL
;;;;   (has "needle" text)                 substring test
;;;;   *rizin*                             true when rizin and *binary* are there
;;;;   *binary*                            OMPRE_TEST_BINARY, default /bin/ls
;;;;   *root*                              the repository
;;;;
;;;;   (with-cell (:debugger t) ...)       the body with the cell started under that section, stopped after
;;;;   (stop-running-cell)                 stop it now, by the function START-CELL answered
;;;;   (with-open-store () ...)            the body with nodecode's store open and no session tree; its
;;;;                                       sessions and turns forgotten after
;;;;   (fresh-session)                     a session id nothing has used
;;;;   (in-session (id) ...)               the body as that session's turn
;;;;   (seed-session &key sha evidence)    a fresh session whose record says a binary is open and holds
;;;;                                       one reproducible read => its id
;;;;   (kill-rizin id)                     kill that session's rizin and wait until it is gone => the dead process
;;;;   (tagged-evidence text)              the evidence id a tool result ends with
;;;;   (cited-evidence text)               every evidence id a text cites, in order
;;;;
;;;;   *scratch*                           the running suite file's own scratch home, a directory pathname
;;;;   (scratch-path "name")               a native path in it
;;;;   (write-scratch "name" content)      a file in it, of a string or of octets => its native path
;;;;   (begin-suite-file "name")           what run.lisp does before each suite file: a fresh scratch
;;;;                                       home, the stand-in's tables emptied, the engine's sessions forgotten

(load (merge-pathnames "kernel-stub.lisp" (or *load-truename* *default-pathname-defaults*)))

(defpackage #:omp-re-test
  (:use #:cl)
  (:export #:suite #:check #:refusal #:has #:with-cell #:*rizin* #:*binary* #:*scratch* #:*root*
           #:fresh-session #:in-session #:*checks* #:*failures*))
(in-package #:omp-re-test)

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

(defun set-environment (name value)
  "Set the environment variable NAME, or with NIL unset it. SBCL has no call
for this that every platform has, so here is the one place the suites
differ by platform."
  #-win32 (if value (sb-posix:setenv name value 1) (sb-posix:unsetenv name))
  #+win32 (sb-alien:alien-funcall
           (sb-alien:extern-alien "_putenv" (function sb-alien:int sb-alien:c-string))
           (format nil "~a=~a" name (or value ""))))

(defmacro with-environment ((name value) &body body)
  "BODY with the environment variable NAME set to VALUE — unset, for NIL —
and put back after."
  (let ((before (gensym "BEFORE")))
    `(let ((,before (sb-ext:posix-getenv ,name)))
       (set-environment ,name ,value)
       (unwind-protect (progn ,@body)
         (set-environment ,name ,before)))))

(defun starts (prefix text)
  (and (stringp text) (uiop:string-prefix-p prefix text)))

(defun ends (suffix text)
  (and (stringp text) (uiop:string-suffix-p text suffix)))

;;; The system the cell's .asd depends on: its names are the stand-in's, already loaded.
(asdf:register-preloaded-system "nodecode")
(push *root* asdf:*central-registry*)
(asdf:load-system "nodecode-re")

(defparameter *binary* (or (uiop:getenv "OMPRE_TEST_BINARY") "/bin/ls"))
(defparameter *rizin*
  (and (probe-file *binary*)
       (ignore-errors (zerop (nth-value 2 (uiop:run-program '("rizin" "-v") :ignore-error-status t))))))

;;; --- the cell ------------------------------------------------------------------------------

(defvar *stop-cell* nil "The function the running cell's START-CELL answered.")

(defun stop-running-cell ()
  (when *stop-cell*
    (funcall (shiftf *stop-cell* nil))))

(defmacro with-cell ((&rest overrides) &body body)
  "BODY with the cell started under OVERRIDES — a plist standing in for the
operator's `re' section — and stopped after."
  `(progn
     (setf *stop-cell* (nodecode-re:start-cell (list ,@overrides)))
     (unwind-protect (progn ,@body)
       (stop-running-cell))))

(defmacro with-open-store (() &body body)
  "BODY with nodecode's store open — sessions can be created and asked a
side question — no session tree described, and nothing left of earlier
sessions; closed and forgotten after. Set, not bound, so a thread BODY starts
sees it too."
  `(progn
     (nlk:stub-forget-sessions)
     (setf nlk:*stub-store-open* t)
     (unwind-protect (progn ,@body)
       (setf nlk:*stub-store-open* nil)
       (nlk:stub-forget-sessions))))

;;; --- scratch ------------------------------------------------------------------------------

(defparameter *scratch-root*
  (uiop:ensure-directory-pathname
   (uiop:native-namestring
    (merge-pathnames (format nil "nodecode-re-test-~36r/" (random (expt 36 8) (make-random-state t)))
                     (uiop:temporary-directory))))
  "Every suite file's scratch home is a folder of this one, deleted when the run ends.")

(defvar *scratch* nil)

(defun begin-suite-file (name)
  (ignore-errors (stop-running-cell))
  (omp-re:shutdown-sessions)
  (clrhash nlk:*stub-visible*)
  (clrhash nlk:*stub-lineage*)
  (clrhash nle:*notices*)
  (nlk:stub-forget-sessions)
  (setf nlk:*stub-store-open* nil
        nle:*stub-session* "smoke"
        nle:*stub-turn* nil
        *scratch* (merge-pathnames (format nil "~a/" name) *scratch-root*)
        nlk:*stub-home* *scratch*
        nlk:*stub-session-cwd* (uiop:native-namestring *scratch*))
  (ensure-directories-exist *scratch*)
  ;; With no cell running the engine keeps its state under the user's data
  ;; directory, which for a suite is its scratch home too.
  (set-environment "XDG_DATA_HOME" (uiop:native-namestring *scratch*))
  *scratch*)

(defun scratch-path (name)
  (uiop:native-namestring (merge-pathnames name *scratch*)))

(defun write-scratch (name content)
  "CONTENT — a string, or a sequence of octets — as the file NAME in the
scratch home => its native path."
  (let ((path (scratch-path name)))
    (ensure-directories-exist path)
    (if (stringp content)
        (omp-re::write-text-file path content)
        (with-open-file (out path :direction :output :if-exists :supersede
                                  :element-type '(unsigned-byte 8))
          (write-sequence (coerce content '(vector (unsigned-byte 8))) out)))
    path))

;;; --- sessions -------------------------------------------------------------------------------

(defmacro with-service ((service function) &body body)
  "BODY with the host's SERVICE answered by FUNCTION — the judge a claim is
put to, a record store that fails — and the host as it was after."
  `(omp-re:with-host-service (,service ,function) ,@body))

(defun typed (line &optional (session-id nle:*stub-session*))
  "What the operator's own /re LINE answers, typed in the session SESSION-ID."
  (funcall (cdr (assoc "re" nle:*commands* :test #'string=)) line session-id))

(defun described-tool (name)
  "The engine's description of the tool NAME, as a host is given it, or NIL."
  (find name (omp-re:engine-tools) :key (lambda (tool) (gethash "name" tool)) :test #'string=))

(defvar *session-counter* 0)
(defun fresh-session ()
  (format nil "test-~d" (incf *session-counter*)))

(defmacro in-session ((id) &body body)
  "BODY as a turn of the session called ID."
  `(let ((nle:*stub-session* ,id)) ,@body))

(defun seed-session (&key (sha (make-string 64 :initial-element #\a))
                          (evidence "11111111-aaaa-bbbb-cccc-000000000001"))
  "A fresh session whose record says a binary with hash SHA is open and
holds one reproducible rizin_command record with the id EVIDENCE. Nothing in
it needs the binary to exist => the session's id."
  (let ((id (fresh-session)))
    (omp-re::in-session (id "seeding a test session")
      (omp-re::append-entry "re.binary" (omp-re:obj "path" "/bin/sample" "sha256" sha))
      (omp-re::append-entry "re.evidence"
                        (omp-re:obj "id" evidence
                                 "tool" "rizin_command"
                                 "args" (omp-re:obj "command" "pdf" "addr" "sym.f")
                                 "commands" (vector "pdf @ sym.f")
                                 "reproHash" (make-string 64 :initial-element #\b)
                                 "binarySha256" sha
                                 "summary" "imul eax, eax, 0x21")))
    id))

(defun rizin-pid (rz)
  (sb-ext:process-pid (omp-re::rz-process rz)))

(defun kill-rizin (id)
  "Kill the rizin of the session called ID, as a crash would, and wait until
the engine sees it gone => the dead process."
  (let* ((rz (omp-re::session-rz (omp-re:find-session id)))
         (process (omp-re::rz-process rz)))
    (sb-ext:process-kill process 9)
    (sb-ext:process-wait process)
    rz))

(defun cited-evidence (text)
  "Every evidence id TEXT cites or is tagged with, in order, without duplicates."
  (let ((ids '()))
    (ppcre:do-register-groups (id) ("\\[evidence ([0-9a-f]{8})[ \\]]" text)
      (pushnew id ids :test #'string=))
    (nreverse ids)))

(defun tagged-evidence (text)
  "The evidence id a tool result ends with, or NIL."
  (car (last (cited-evidence text))))

(begin-suite-file "harness")
