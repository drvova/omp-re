;;;; smoke.lisp --- the nodecode cell's Lisp, run against the real engine.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --non-interactive --load test/nodecode/smoke.lisp
;;;;
;;;; Loads the real system (nodecode-re.asd, nodecode/*.lisp) over
;;;; kernel-stub.lisp and drives the real bridge (bun nodecode/bridge.ts):
;;;; the transport, the argument mapping, the verbs, the /re command, the
;;;; top-level tool surface, start and stop. The rizin half runs when rizin
;;;; and a test binary are present (OMPRE_TEST_BINARY, default /bin/ls) and
;;;; is skipped, loudly, when they are not. Needs bun and `bun install`.
;;;; Exits 0 when every check holds, 1 otherwise.

(load (merge-pathnames "kernel-stub.lisp" (or *load-truename* *default-pathname-defaults*)))

(defpackage #:nodecode-re-smoke (:use #:cl))
(in-package #:nodecode-re-smoke)

(defparameter *root*
  (uiop:pathname-parent-directory-pathname
   (uiop:pathname-parent-directory-pathname
    (uiop:pathname-directory-pathname (or *load-truename* *default-pathname-defaults*))))
  "The repository, two folders above this file.")

(defvar *checks* 0)
(defvar *failures* '())

(defmacro check (description form)
  `(progn
     (incf *checks*)
     (handler-case
         (if ,form
             (format t "  ok    ~a~%" ,description)
             (progn (push ,description *failures*) (format t "  FAIL  ~a~%" ,description)))
       (error (condition)
         (push ,description *failures*)
         (format t "  FAIL  ~a~%        signalled: ~a~%" ,description condition)))
     (finish-output)))

(defun refusal (thunk)
  "The text THUNK's RE-ERROR carries, or NIL when it returned."
  (handler-case (progn (funcall thunk) nil)
    (error (condition) (princ-to-string condition))))

(defun has (needle text)
  (and (stringp text) (search needle text) t))

;;; The stub system the cell's .asd depends on: the names are already loaded above.
(asdf:register-preloaded-system "nodecode")
(push *root* asdf:*central-registry*)
(asdf:load-system "nodecode-re")

(defparameter *scratch*
  (uiop:ensure-directory-pathname
   (uiop:native-namestring
    (merge-pathnames (format nil "nodecode-re-smoke-~a/" (sb-posix:getpid)) (uiop:temporary-directory)))))
(ensure-directories-exist *scratch*)
(setf nlk:*stub-home* *scratch*
      nlk:*stub-session-cwd* (uiop:native-namestring *scratch*))

(defparameter *binary* (or (uiop:getenv "OMPRE_TEST_BINARY") "/bin/ls"))
(defparameter *rizin*
  (and (probe-file *binary*)
       (ignore-errors (zerop (nth-value 2 (uiop:run-program '("rizin" "-v") :ignore-error-status t))))))

(format t "~&nodecode-re smoke: root ~a, home ~a~%" *root* *scratch*)

;;; --- before start -----------------------------------------------------------------

(format t "~&before start~%")
(check "a verb refuses while the cell is not running"
       (has "not running" (refusal (lambda () (re:status)))))
(check "the loader's contract: START-CELL is external in the system's package"
       (eq :external (nth-value 1 (find-symbol "START-CELL" "NODECODE-RE"))))

;;; --- the argument mapping (no engine) ------------------------------------------------

(format t "~&arguments~%")
(let ((object (nodecode-re::wire-arguments
               '(:expect-sha256 "ab" :bits 32 :flag t :off :false :absent nil :items ("a" "b") :kind :elf))))
  (check "a keyword is spelt as the engine spells the parameter"
         (equal "ab" (gethash "expect_sha256" object)))
  (check "T is true, :false is false and present, NIL is left out"
         (and (eq t (gethash "flag" object))
              (multiple-value-bind (value present) (gethash "off" object) (and present (null value)))
              (not (nth-value 1 (gethash "absent" object)))))
  (check "a list is an array and a keyword value its lowercase name"
         (and (equalp #("a" "b") (gethash "items" object)) (equal "elf" (gethash "kind" object))))
  (check "it encodes to the JSON the bridge reads"
         (has "\"off\":false" (nlk:encode-json-object object))))
(check "an odd argument list is refused in words"
       (has "odd one out" (refusal (lambda () (nodecode-re::wire-arguments '(:a))))))

;;; --- start, and the rizin-free half ----------------------------------------------------

(format t "~&engine~%")
(nodecode-re:start-cell (list :state-dir (uiop:native-namestring (merge-pathnames "state/" *scratch*))))

(check "the help topic and the /re command are contributed"
       (and (assoc :re nle:*help*) (assoc "re" nle:*commands* :test #'string=)))
(check "starting does not launch the engine" (null nodecode-re::*bridge*))
(check "(re:status) answers from the engine" (has "rizin" (re:status)))
(check "the first request launched it" (nodecode-re::live-p nodecode-re::*bridge*))
(check "(re:tools) lists the engine's tools"
       (let ((text (re:tools))) (and (has "rizin_command" text) (has "record_finding" text) (has "open_binary" text))))
(check "(re:doc) spells a tool's parameters as eval keywords"
       (let ((text (re:doc "record-finding"))) (and (has ":claim" text) (has "required" text))))
(check "(re:doc) refuses an unknown tool" (has "no tool is named" (refusal (lambda () (re:doc "nope")))))
(check "a call that does not fit the schema is RE-ERROR carrying the engine's words"
       (has "schema" (refusal (lambda () (re:call "rizin_command")))))
(check "an unknown tool is RE-ERROR" (has "no tool named" (refusal (lambda () (re:call "no_such_tool")))))
(check "(re:slash \"help\") answers the engine's /re help" (has "report" (re:slash "help")))
(check "/re typed alone answers help, for the session it was typed in"
       (has "report" (funcall (cdr (assoc "re" nle:*commands* :test #'string=)) "" "smoke")))
;; A session the engine has never seen has to be built before it can answer,
;; which takes far longer than the one short slice a zero deadline allows.
(check "a deadline cancels the call and says so"
       (let ((nodecode-re::*slice-seconds* 0.001))
         (has "did not answer" (refusal (lambda ()
                                          (nodecode-re::exchange (nlk:make-json-object "op" "command" "session" "slow"
                                                                                         "name" "re" "args" "status")
                                                                 :seconds 0))))))
(check "and the call after an abandoned one reads its own answer" (has "rizin" (re:status)))
(check "two sessions' calls overlap and each reads its own answer"
       (let* ((results (make-array 6 :initial-element nil))
              (threads (loop for index below 6
                             collect (let ((index index))
                                       (sb-thread:make-thread
                                        (lambda ()
                                          (let ((nle:*stub-session* (format nil "parallel-~a" (mod index 2))))
                                            (setf (aref results index)
                                                  (ignore-errors (re:slash (if (evenp index) "status" "help")))))))))))
         (mapc #'sb-thread:join-thread threads)
         (loop for index below 6
               always (has (if (evenp index) "audit log" "verify") (aref results index)))))

;;; --- the top-level tool surface ---------------------------------------------------------

(format t "~&surface~%")
(let ((names (nodecode-re::register-surface-tools)))
  (check "surface \"tools\" registers every engine tool as re_<name>"
         (and (member "re_rizin_command" names :test #'string=)
              (= (length names) (length nle:*tools*))))
  (let* ((entry (find "re_rizin_help" nle:*tools* :key #'first :test #'string=))
         (schema (second entry)))
    (check "each with the engine's own description and JSON schema"
           (and (stringp (getf schema :description))
                (equal "object" (gethash "type" (getf schema :parameters))))))
  (let ((nle:*failed* nil)
        (entry (find "re_rizin_command" nle:*tools* :key #'first :test #'string=)))
    (check "a failed top-level call answers its text through NLE:FAILURE"
           (and (has "schema" (funcall (third entry) (nlk:make-json-object))) nle:*failed*)))
  (mapc #'nle:unregister-tool names))

;;; --- the rizin half ---------------------------------------------------------------------

(cond
  (*rizin*
   (format t "~&rizin (~a)~%" *binary*)
   (check "(re:open) opens and analyzes the binary" (has "Binary opened" (re:open *binary*)))
   (let* ((functions (re:cmd "aflj"))
          (tag (search "[evidence " functions))
          (id (and tag (subseq functions (+ tag 10) (+ tag 18)))))
     (check "(re:cmd) reads it, and the result carries its evidence id" (and id (has "rizin> aflj" functions)))
     (multiple-value-bind (data evidence) (re:json "aflj")
       (check "(re:json) answers the decoded data, whole even past the size cap, and its evidence id"
              (and (vectorp data) (> (length data) 10)
                   (stringp (gethash "name" (aref data 0)))
                   (= 8 (length evidence)))))
     (check "(re:json) refuses a command that does not answer JSON"
            (has "did not answer JSON" (refusal (lambda () (re:json "pd 1" "entry0")))))
     (check "a command at an address" (has "rizin>" (re:cmd "pdf" "entry0")))
     (check "the engine's command policy holds here too"
            (has "not allowed" (refusal (lambda () (re:cmd "afl~main")))))
     (check "a finding citing that evidence is recorded"
            (has "inding" (re:call "record_finding" :claim "The binary defines functions rizin can list."
                                                    :evidence (list id) :confidence "confirmed")))
     (check "a finding citing nothing real is refused"
            (refusal (lambda () (re:call "record_finding" :claim "Unsupported." :evidence '("00000000")))))
     (check "(re:slash \"findings\") lists it" (has "functions rizin can list" (re:slash "findings")))
     (check "the report carries the grounded claim" (has "functions rizin can list" (re:slash "report")))
     (check "(re:slash \"verify\") re-runs the evidence" (has "0 FAILED" (re:slash "verify")))
     ;; After verify: a comment changes what `pdf' prints there, which verify would rightly report.
     (check "an annotation lands" (stringp (re:call "set-comment" :addr "entry0" :text "smoke: entry")))
     (check "/re open reads a relative path against the session's directory"
            (progn (uiop:copy-file *binary* (merge-pathnames "sample.bin" *scratch*))
                   (let ((nle:*stub-session* "relative"))
                     (funcall (cdr (assoc "re" nle:*commands* :test #'string=)) "open sample.bin" "relative")
                     (has "sample.bin" (re:status)))))
     ;; The engine dies; the next call starts another, which restores the session from its record.
     (let ((old nodecode-re::*bridge*))
       (nlk:kill-tree (nodecode-re::bridge-pid old))
       (loop repeat 50 until (not (nodecode-re::live-p old)) do (sleep 0.1))
       (check "a killed engine is replaced by the next call" (has "rizin" (re:status)))
       (check "by a new process" (not (eq old nodecode-re::*bridge*)))
       (check "which restores the open binary, the evidence and the finding from the session's record"
              (let ((status (re:status)))
                (and (has (file-namestring *binary*) status)
                     (has "functions rizin can list" (re:slash "findings")))))
       (check "and replays the annotation into the fresh rizin" (has "smoke: entry" (re:cmd "pd 1" "entry0"))))))
  (t (format t "~&rizin: SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*)))

;;; --- surface "tools", as the section sets it -----------------------------------------------

(format t "~&restart with surface \"tools\"~%")
(nodecode-re:start-cell (list :surface "tools"
                              :state-dir (uiop:native-namestring (merge-pathnames "state/" *scratch*))))
(check "a start under surface \"tools\" registers the tools itself"
       (find "re_open_binary" nle:*tools* :key #'first :test #'string=))
(check "and leaves no notice standing" (zerop (hash-table-count nle:*notices*)))

;;; --- stop -------------------------------------------------------------------------------

(format t "~&stop~%")
(let ((bridge nodecode-re::*bridge*))
  (nodecode-re::stop-cell)
  (check "stopping ends the engine process"
         (and (null nodecode-re::*bridge*) (not (nodecode-re::live-p bridge))
              (nlk:child-exit (nodecode-re::bridge-pid bridge) (nodecode-re::bridge-process bridge))))
  (check "and takes the help topic, the command and the tools back"
         (and (null nle:*help*) (null nle:*commands*) (null nle:*tools*)))
  (check "a verb refuses again" (has "not running" (refusal (lambda () (re:status))))))

(uiop:delete-directory-tree *scratch* :validate t :if-does-not-exist :ignore)
(format t "~&nodecode-re smoke: ~a checks, ~a failed~%" *checks* (length *failures*))
(dolist (failure (reverse *failures*)) (format t "  failed: ~a~%" failure))
(sb-ext:exit :code (if *failures* 1 0) :abort t)
