;;;; suite-stdio.lisp --- the omp host: the engine served over real pipes.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Starts stdio/serve.lisp as omp starts it — a child SBCL, JSON lines on
;;;; its standard input and output — and plays omp's side of
;;;; docs/engine-protocol.md: it keeps each session's record, answers what
;;;; the engine asks, and notes what it is told. Everything that crosses the
;;;; pipe, either way, is held to stdio/protocol.json by the server's own
;;;; reading of it, so this stand-in cannot speak a protocol of its own.

(in-package #:omp-re-test)

(asdf:load-system "omp-re-stdio")

(defstruct (omp (:copier nil))
  process
  (lock (sb-thread:make-mutex :name "omp stand-in"))
  (next 0)
  (answers (make-hash-table))           ; request id => the engine's answer
  (heard '())                           ; (METHOD . PARAMS) of everything the engine sent, newest first
  (records (make-hash-table :test #'equal)) ; session id => list of entries, oldest first
  (artifacts (make-hash-table :test #'equal))
  (judge nil)                           ; (lambda (prompt)) => reply text, NIL for nobody to ask, :WITHHELD to never
                                        ; answer, (:REASON . TEXT) for a side model that could not be had
  (asked (make-hash-table))             ; request id => its method
  (violations '())                      ; what was said that the protocol does not have
  first-line)

(defmacro conforming ((omp what) &body body)
  "BODY, a check against the protocol; a violation is noted, not signalled."
  `(handler-case (progn ,@body)
     (omp-re-stdio::wire-violation (condition)
       (sb-thread:with-mutex ((omp-lock ,omp))
         (push (format nil "~a: ~a" ,what condition) (omp-violations ,omp))))))

(defun omp-write (omp object)
  (let ((stream (sb-ext:process-input (omp-process omp))))
    (sb-thread:with-mutex ((omp-lock omp))
      (write-string (if (stringp object) object (omp-re:json-encode object)) stream)
      (write-char #\Newline stream)
      (finish-output stream))))

(defun omp-answer (omp method params)
  "What omp's side answers the engine's request METHOD."
  (let ((session (gethash "session" params)))
    (cond
      ((string= method "entries")
       (let ((held (mapcar (lambda (entry)
                             (omp-re:obj "id" (gethash "id" entry) "customType" (gethash "customType" entry)
                                         "data" (gethash "data" entry)))
                           (gethash session (omp-records omp))))
             (count (gethash "count" params)))
         (if (and (<= count (length held))
                  (or (zerop count)
                      (equal (gethash "after" params) (gethash "id" (nth (1- count) held)))))
             (omp-re:obj "append" (coerce (nthcdr count held) 'simple-vector))
             (omp-re:obj "all" (coerce held 'simple-vector)))))
      ((string= method "append")
       (let ((id (format nil "entry-~d" (incf (omp-next omp)))))
         (setf (gethash session (omp-records omp))
               (append (gethash session (omp-records omp))
                       (list (omp-re:obj "type" "custom" "id" id "customType" (gethash "type" params)
                                      "data" (gethash "data" params)))))
         (omp-re:obj "id" id)))
      ((string= method "judge")
       (let ((reply (and (omp-judge omp) (funcall (omp-judge omp) (gethash "prompt" params)))))
         (cond ((eq reply :withheld) :withheld)
               ((consp reply) (omp-re:obj "reason" (cdr reply)))
               (reply (omp-re:obj "text" reply))
               (t (omp-re:obj)))))
      ((string= method "saveArtifact")
       (let ((id (format nil "~d" (hash-table-count (omp-artifacts omp)))))
         (setf (gethash id (omp-artifacts omp)) (gethash "content" params))
         (omp-re:obj "id" id)))
      ((string= method "readArtifact")
       (omp-re:obj "text" (or (gethash (gethash "id" params) (omp-artifacts omp)) :absent)))
      (t (omp-re:obj)))))

(defvar *off-protocol* nil
  "True while a check says on purpose what the protocol does not have.")

(defun omp-request (omp method &rest members)
  "Send the request METHOD without waiting => its id."
  (let ((id (sb-thread:with-mutex ((omp-lock omp)) (incf (omp-next omp))))
        (params (apply #'omp-re:obj members)))
    (unless *off-protocol*
      (omp-re-stdio::conform-params "toEngine" method params :request t)
      (sb-thread:with-mutex ((omp-lock omp)) (setf (gethash id (omp-asked omp)) method)))
    (omp-write omp (omp-re:obj "id" id "method" method "params" params))
    id))

(defun omp-tell (omp method &rest members)
  "Send the notification METHOD."
  (let ((params (apply #'omp-re:obj members)))
    (unless *off-protocol*
      (omp-re-stdio::conform-params "toEngine" method params))
    (omp-write omp (omp-re:obj "method" method "params" params))))

(defun omp-await (omp id &optional (seconds 120))
  "The engine's answer to the request ID => its result, or (values NIL
MESSAGE) for an error, or (values NIL :TIMEOUT)."
  (loop repeat (* seconds 100)
        do (let ((answer (sb-thread:with-mutex ((omp-lock omp)) (gethash id (omp-answers omp)))))
             (when answer
               (return (if (gethash "error" answer)
                           (values nil (omp-re:jstring answer "error" "message"))
                           (gethash "result" answer)))))
           (sleep 0.01)
        finally (return (values nil :timeout))))

(defun omp-ask (omp method &rest members)
  (omp-await omp (apply #'omp-request omp method members)))

(defun start-omp (&key variables (state (scratch-path "agent/")) judge)
  "Start the engine as omp does and say hello => the stand-in."
  (let* ((process (sb-ext:run-program (first *serve-command*) (rest *serve-command*)
                                      :search t :wait nil :input :stream :output :stream :error nil
                                      :external-format :utf-8))
         (omp (make-omp :process process :judge judge)))
    (setf (omp-first-line omp) (read-line (sb-ext:process-output process) nil ""))
    (sb-thread:make-thread
     (lambda ()
       (loop for line = (read-line (sb-ext:process-output process) nil nil)
             while line
             do (let* ((message (omp-re:json-parse line))
                       (method (and (hash-table-p message) (gethash "method" message))))
                  (cond ((null method)
                         (when (hash-table-p message)
                           (let ((asked (sb-thread:with-mutex ((omp-lock omp))
                                          (gethash (gethash "id" message) (omp-asked omp)))))
                             (when (and asked (not (gethash "error" message)))
                               (conforming (omp "the engine's answer")
                                 (omp-re-stdio::conform-result "toEngine" asked (gethash "result" message)))))
                           (sb-thread:with-mutex ((omp-lock omp))
                             (setf (gethash (gethash "id" message) (omp-answers omp)) message))))
                        (t
                         (let ((params (gethash "params" message))
                               (id (gethash "id" message)))
                           (conforming (omp "the engine said")
                             (omp-re-stdio::conform-params "toHost" method params :request (and id t)))
                           (sb-thread:with-mutex ((omp-lock omp))
                             (push (cons method params) (omp-heard omp)))
                           (when id
                             (let ((result (omp-answer omp method params)))
                               (unless (eq result :withheld)
                                 (conforming (omp "the stand-in answered")
                                   (omp-re-stdio::conform-result "toHost" method result))
                                 (omp-write omp (omp-re:obj "id" id "result" result)))))))))))
     :name "omp stand-in reader")
    (omp-ask omp "hello" "protocol" omp-re-stdio:+protocol+ "stateDir" state
                         "variables" (apply #'omp-re:obj "PATH" (uiop:getenv "PATH") variables))
    omp))

(defun omp-heard-of (omp method &optional session)
  "The params of everything the engine sent as METHOD, oldest first."
  (reverse (loop for (said . params) in (sb-thread:with-mutex ((omp-lock omp)) (copy-list (omp-heard omp)))
                 when (and (string= said method)
                           (or (null session) (equal session (gethash "session" params))))
                   collect params)))

(defun wait-until (predicate &optional (seconds 60))
  (loop repeat (* seconds 50)
        do (when (funcall predicate) (return t))
           (sleep 0.02)))

(defun stop-omp (omp)
  "End the engine by closing its input, as omp's exit does => its exit code."
  (ignore-errors (close (sb-ext:process-input (omp-process omp))))
  (wait-until (lambda () (not (sb-ext:process-alive-p (omp-process omp)))) 20)
  (prog1 (sb-ext:process-exit-code (omp-process omp))
    (ignore-errors (sb-ext:process-kill (omp-process omp) 9))))

(defun print-violations (omp)
  (let ((violations (reverse (omp-violations omp))))
    (dolist (violation violations violations)
      (format t "    ~a~%" violation))))

(defun session-of (id)
  (omp-re:obj "id" id "cwd" (uiop:native-namestring *scratch*)))

(defun tool-call (omp session name &rest arguments)
  (omp-ask omp "call" "session" (session-of session) "name" name
                      "arguments" (apply #'omp-re:obj arguments)
                      "callId" (format nil "call-~a-~a" session name)))

(defun run-line (omp session line)
  (omp-ask omp "command" "session" (session-of session) "line" line))

(defun session-state (omp session)
  "The state the engine sends with an answer in SESSION, had by a line that
waits for nothing."
  (gethash "state" (run-line omp session "help")))

(defun band-count (state what)
  "The number the status band's second line gives for WHAT: \"fn\",
\"findings\" or \"evidence\"."
  (let* ((line (aref (gethash "band" state) 1))
         (end (search (format nil " ~a" what) line)))
    (and end
         (parse-integer line :start (1+ (or (position #\Space line :end end :from-end t) -1)) :end end))))

(defun offered-p (omp name)
  "Whether the line `tools' lists the tool NAME."
  (find name (omp-re:split-lines (gethash "text" (run-line omp "s-none" "tools")))
        :key (lambda (line) (subseq line 0 (position #\Space line))) :test #'string=))

(defun serving-p (omp)
  "Whether the engine still answers a request."
  (hash-table-p (omp-ask omp "preserved" "session" (session-of "s-none"))))

(defun audit-lines (session)
  (mapcar #'omp-re:json-parse
          (remove-if #'omp-re:blank-p
                     (omp-re:split-lines
                      (or (omp-re::read-text-file (scratch-path (format nil "agent/re/audit/~a.log" session)))
                          "")))))

;;; --- no rizin needed ---------------------------------------------------------------------------

(suite "stdio: the wire")
(let ((omp (start-omp)))
  (unwind-protect
       (progn
         (check "the first line says the engine is ready, and hello answers the protocol, the version, and that this engine was loaded from source"
                (and (equal (format nil "{\"ready\":~d}" omp-re-stdio:+protocol+) (omp-first-line omp))
                     (let ((hello (omp-ask omp "hello" "protocol" omp-re-stdio:+protocol+
                                                       "stateDir" (scratch-path "agent/")
                                                       "variables" (omp-re:obj "PATH" (uiop:getenv "PATH")))))
                       (and (eql omp-re-stdio:+protocol+ (gethash "protocol" hello))
                            (equal (asdf:component-version (asdf:find-system "omp-re"))
                                   (gethash "version" hello))
                            (equal "source" (gethash "started" hello))))))
         (check "a line that is not JSON, an empty line and a CRLF line ending do not stop the next request"
                (progn
                  (omp-write omp "this is not json")
                  (omp-write omp "")
                  (omp-write omp (format nil "{\"id\":9001,\"method\":\"preserved\",\"params\":{\"session\":{\"id\":\"s-none\",\"cwd\":\"/\"}}}~c" #\Return))
                  (hash-table-p (omp-await omp 9001 20))))
         (check "an omp of another protocol version is refused at hello, told to reinstall"
                (multiple-value-bind (result message)
                    (let ((*off-protocol* t))
                      (omp-ask omp "hello" "protocol" (1+ omp-re-stdio:+protocol+)
                                           "stateDir" (scratch-path "agent/")
                                           "variables" (omp-re:obj "PATH" (uiop:getenv "PATH"))))
                  (and (null result)
                       (has (format nil "protocol ~d and its engine protocol ~d"
                                    (1+ omp-re-stdio:+protocol+) omp-re-stdio:+protocol+)
                            message)
                       (has "Reinstall or upgrade the omp-re plugin" message))))
         (check "a method the engine does not have is an error answer naming it, and the pipe goes on"
                (multiple-value-bind (result message) (let ((*off-protocol* t)) (omp-ask omp "no_such_method"))
                  (and (null result) (has "no_such_method" message)
                       (serving-p omp))))
         (check "a member the protocol does not have, or one it requires and is not there, is an error naming it"
                (let ((*off-protocol* t))
                  (and (has "has no member lineX"
                            (nth-value 1 (omp-ask omp "command" "session" (session-of "s-none") "line" "help" "lineX" "help")))
                       (has "lacks arguments"
                            (nth-value 1 (omp-ask omp "call" "session" (session-of "s-none")
                                                         "name" "rizin_help")))
                       (has "session lacks cwd"
                            (nth-value 1 (omp-ask omp "preserved" "session" (omp-re:obj "id" "s-none")))))))
         (check "a session event of a kind the protocol does not have is an error: it neither restores nor closes"
                (let ((*off-protocol* t))
                  (multiple-value-bind (result message)
                      (omp-ask omp "event" "session" (session-of "s-none") "kind" "before-switchX")
                    (and (null result) (has "before-switchX" message)
                         (null (omp-heard-of omp "state" "s-none"))))))
         (check "a notification is not answered, a request sent as one is refused, and the pipe goes on"
                (let ((*off-protocol* t))
                  (omp-write omp (omp-re:obj "method" "preserved" "params" (omp-re:obj "session" (session-of "s-none"))))
                  (and (has "environment is a notification"
                            (nth-value 1 (omp-ask omp "environment" "stateDir" (scratch-path "agent/")
                                                  "variables" (omp-re:obj))))
                       (let ((*off-protocol* nil)) (serving-p omp)))))
         (check "the keys omp binds are views the engine has"
                (every (lambda (key) (omp-re::find-list (gethash "view" key)))
                       (coerce (omp-re:jget omp-re-stdio::*protocol* "keys" "views") 'list)))
         (check "the line tools names every tool the engine offers, one a line with what it does"
                (let ((lines (omp-re:split-lines (gethash "text" (run-line omp "s-none" "tools")))))
                  (and (every (lambda (name) (offered-p omp name))
                              '("open_binary" "map_file" "export_project" "analyze" "apply_signatures"
                                "create_signature" "record_finding" "adopt_finding" "retract_finding"
                                "rizin_help" "rizin_command" "rizin_emulate"
                                "rename_function" "rename_variable" "set_comment" "set_prototype"
                                "set_variable_type" "define_variable" "define_global" "define_function"
                                "set_calling_convention" "set_flag" "set_arch_hint" "set_hint" "set_data"
                                "set_string" "set_format"))
                       (every (lambda (line) (has " — " line)) lines))))
         (check "the line doc says how a tool is called in both of omp's kernels, each argument by the engine's own name"
                (let ((text (gethash "text" (run-line omp "s-none" "doc adopt_finding"))))
                  (and (starts (format nil "adopt_finding~%") text)
                       (has "await re.call(\"adopt_finding\", { name: value, … }) — in Python omp_re.call(\"adopt_finding\", name=value, …) — takes:"
                            text)
                       (has (format nil "~%  claim  string, required — ") text)
                       (has (format nil "~%  commands  an array of objects (command, addr); in Python a list of dicts, required — ") text)
                       (has (format nil "~%  confidence  one of \"confirmed\", \"likely\", \"speculative\"") text))))
         (check "doc of a tool the engine does not have is refused in omp's words"
                (let ((answer (run-line omp "s-none" "doc nope")))
                  (and (eq t (gethash "failed" answer))
                       (equal "omp-re: no tool named \"nope\" — re.tools() lists them" (gethash "text" answer)))))
         (check "the debugger is offered only once omp's environment switches it on: the engine reads omp's variables, not its own"
                (and (null (offered-p omp "rizin_debug"))
                     (progn
                       (omp-tell omp "environment" "stateDir" (scratch-path "agent/")
                                                   "variables" (omp-re:obj "PATH" (uiop:getenv "PATH")
                                                                        "OMPRE_ENABLE_DEBUGGER" "1"))
                       t)
                     (offered-p omp "rizin_debug")
                     (let ((text (gethash "text" (run-line omp "s-none" "doc rizin_debug"))))
                       (and (has (format nil "~%  attach  an object (pid, remote); in Python a dict") text)
                            (has (format nil "~%  count  number — ") text)))
                     (progn
                       (omp-tell omp "environment" "stateDir" (scratch-path "agent/")
                                                   "variables" (omp-re:obj "PATH" (uiop:getenv "PATH")))
                       t)
                     (null (offered-p omp "rizin_debug"))))
         (check "a call with no binary open fails in omp's words"
                (let ((answer (tool-call omp "s-none" "rizin_command" "command" "aflj")))
                  (and (eq t (gethash "failed" answer))
                       (eq t (gethash "refused" answer))
                       (equal "omp-re: no binary open — open one first: await re.open(\"/path/to/binary\") — in Python, omp_re.open(\"/path/to/binary\")"
                              (gethash "text" answer)))))
         (check "the manual is omp's: the library of both kernels, how a line is run, and it needs no binary"
                (let ((text (gethash "text" (tool-call omp "s-none" "rizin_command" "command" ""))))
                  (and (has "%load skill://re-triage/recipes.js" text) (has "%load skill://re-triage/recipes.py" text)
                       (has "await re.open(\"/path/to/binary\")" text) (has "await re.cmd(\"aflj\")" text)
                       (has "data, evidence = omp_re.json(\"aflj\")" text)
                       (has "recorded as evidence (re.slash(\"evidence\"))" text)
                       (has "re.slash(\"report\") writes the evidence-gated report." text)
                       (not (has "tool.rizin" text)) (not (has "(re:cmd" text)))))
         (check "the line help lists the lines; one the engine does not have fails, naming help"
                (let ((help (run-line omp "s-none" "help"))
                      (bogus (run-line omp "s-none" "bogus")))
                  (and (has "/re open <path>" (gethash "text" help))
                       (not (has "alt+" (gethash "text" help)))
                       (null (gethash "failed" help))
                       (equal '("text" "failed" "state")
                              (loop for key being the hash-keys of help collect key))
                       (equal "omp-re: unknown /re subcommand \"bogus\" — try /re help" (gethash "text" bogus))
                       (eq t (gethash "failed" bogus)))))
         (check "off and on are no lines: nothing switches the tools off for a session"
                (every (lambda (line)
                         (has "unknown /re subcommand" (gethash "text" (run-line omp "s-none" line))))
                       '("off" "on")))
         (check "every call that ran is a line in the audit log under omp's own call id; unsigned, the operator is told once a session"
                (let ((lines (audit-lines "s-none")))
                  (and (= 2 (length lines))
                       (every (lambda (line) (equal "call-s-none-rizin_command" (gethash "toolCallId" line))) lines)
                       (equal "aflj" (omp-re:jstring (first lines) "args" "command"))
                       (= 1 (count-if (lambda (params) (has "OMPRE_AUDIT_HMAC_KEY not configured" (gethash "text" params)))
                                      (omp-heard-of omp "notify" "s-none"))))))
         (check "a call omp gives no id is a line under the session's own count of its calls"
                (progn
                  (omp-ask omp "call" "session" (session-of "s-counted") "name" "rizin_help"
                                      "arguments" (omp-re:obj "query" "pdf"))
                  (omp-ask omp "call" "session" (session-of "s-counted") "name" "rizin_help"
                                      "arguments" (omp-re:obj "query" "pdf"))
                  (equal '("s-counted-1" "s-counted-2")
                         (mapcar (lambda (line) (gethash "toolCallId" line)) (audit-lines "s-counted")))))
         (check "with OMPRE_AUDIT_HMAC_KEY in omp's environment a line carries an HMAC that verifies over the rest of it"
                (progn
                  (omp-tell omp "environment" "stateDir" (scratch-path "agent/")
                                              "variables" (omp-re:obj "PATH" (uiop:getenv "PATH")
                                                                   "OMPRE_AUDIT_HMAC_KEY" " key with spaces "))
                  (tool-call omp "s-signed" "rizin_help" "query" "pdf")
                  (let* ((line (first (audit-lines "s-signed")))
                         (unsigned (let ((copy (omp-re:obj)))
                                     (maphash (lambda (key value)
                                                (unless (string= key "hmac") (setf (gethash key copy) value)))
                                              line)
                                     copy)))
                    (and (stringp (gethash "hmac" line))
                         (string= (gethash "hmac" line)
                                  (omp-re::base64 (omp-re::hmac-sha256 (omp-re::utf-8 " key with spaces ")
                                                               (omp-re::utf-8 (omp-re:json-encode unsigned)))))
                         (null (omp-heard-of omp "notify" "s-signed"))))))
         (check "a session that never reverse engineered anything has nothing to keep through a compaction"
                (equalp #() (gethash "lines" (omp-ask omp "preserved" "session" (session-of "s-none")))))
         (check "the status band of a session with no binary says so, and starts nothing"
                (equalp #("no binary" "0 fn · 0 findings · 0 evidence")
                        (gethash "band" (session-state omp "s-none"))))
         (check "the band says a size in at most four figures and a unit"
                (equal '("0B" "1023B" "1K" "1.5K" "142K" "1024K" "1M" "2.4G" "1024T")
                       (mapcar #'omp-re-stdio::band-size
                               (list 0 1023 1024 1536 145408 (1- (* 1024 1024)) (* 1024 1024)
                                     (* 24 1024 1024 1024 1/10) (expt 1024 5))))))
    (check "when omp closes the pipe the engine exits cleanly"
           (eql 0 (stop-omp omp)))
    (check "everything that crossed the pipe, either way, is what stdio/protocol.json describes"
           (null (print-violations omp)))))

(let ((omp (start-omp)))
  (omp-tell omp "shutdown")
  (check "told to shut down, the engine leaves cleanly though its input is still open"
         (and (wait-until (lambda () (not (sb-ext:process-alive-p (omp-process omp)))) 20)
              (eql 0 (sb-ext:process-exit-code (omp-process omp)))
              (open-stream-p (sb-ext:process-input (omp-process omp)))))
  (stop-omp omp))

;;; --- against rizin -----------------------------------------------------------------------------

(suite "stdio: a session over the wire")
(if (not *rizin*)
    (format t "  SKIPPED (rizin or ~a is absent)~%" *binary*)
    (let ((omp (start-omp :judge (lambda (prompt)
                                   (cond
                                     ((search "CLAIM 0: Withheld" prompt) :withheld)
                                     ((search "CLAIM 0: Unreachable" prompt)
                                      (cons :reason (format nil "the provider answered 503~%and a second line")))
                                     (t
                                      (omp-re:json-encode
                                        (map 'vector (lambda (line)
                                                       (omp-re:obj "index" (parse-integer line :start 6 :junk-allowed t)
                                                                "verdict" "supported" "reason" "it says so"))
                                             (remove-if-not (lambda (line) (eql 0 (search "CLAIM " line)))
                                                            (omp-re:split-lines prompt)))))))))
          (children '()))
      (unwind-protect
           (progn
             (let ((opened (tool-call omp "s1" "open_binary" "path" *binary*)))
               (check "open_binary analyzes the binary; the record omp keeps says so, and the transcript line is asked for"
                      (and (not (gethash "failed" opened))
                           (has "Binary opened: " (gethash "text" opened))
                           (equal '("re.binary")
                                  (mapcar (lambda (entry) (gethash "customType" entry))
                                          (gethash "s1" (omp-records omp))))
                           (let ((line (first (omp-heard-of omp "transcript" "s1"))))
                             (and (equal "re.binary" (gethash "type" line))
                                  (has "[re: opened " (gethash "text" line))
                                  (stringp (omp-re:jstring line "details" "sha256"))))))
               (check "while it analyzes, progress is said for that request, then said to be over"
                      (let ((progress (omp-heard-of omp "progress" "s1")))
                        (and (has "rizin: analyzing " (gethash "text" (first progress)))
                             (integerp (gethash "request" (first progress)))
                             (eq :null (gethash "text" (car (last progress)))))))
               (check "the answer carries the status band's two lines, so drawing it asks nothing more"
                      (let ((band (omp-re:jget opened "state" "band")))
                        (and (starts (format nil "~a  " (file-namestring *binary*)) (aref band 0))
                             (has "  entry 0x" (aref band 0))
                             (plusp (band-count (gethash "state" opened) "fn"))
                             (eql 0 (band-count (gethash "state" opened) "evidence"))))))
             (let* ((read (tool-call omp "s1" "rizin_command" "command" "afij" "addr" "main"))
                    (id (omp-re:jstring read "details" "evidenceId")))
               (check "a read answers its text with the evidence tag, the id of the record it left in its details, and the record gains the evidence"
                      (and (starts (format nil "rizin> afij @ main~%") (gethash "text" read))
                           (ends (format nil "[evidence ~a — cite it in record_finding]" (subseq id 0 8))
                                 (gethash "text" read))
                           (equalp #("afij @ main") (omp-re:jget read "details" "commands"))
                           (equal id (omp-re:jstring (car (last (gethash "s1" (omp-records omp)))) "data" "id"))))
               (check "what the wire carries of a call is its text, whether it failed, all rizin printed, the evidence it left, its details and the state"
                      (equal '("details" "evidence" "failed" "raw" "state" "text")
                             (sort (loop for name being the hash-keys of read collect name) #'string<)))
               (check "the engine asked omp only for what it had not seen: after its last entry, by count"
                      (let ((asked (omp-heard-of omp "entries" "s1")))
                        (and (eql 0 (gethash "count" (first asked)))
                             (eql 1 (gethash "count" (car (last asked))))
                             (equal (gethash "id" (first (gethash "s1" (omp-records omp))))
                                    (gethash "after" (car (last asked)))))))
               (check "record_finding puts the claim to omp's side model, and the finding is recorded"
                      (let ((text (gethash "text" (tool-call omp "s1" "record_finding"
                                                             "claim" "main is a function."
                                                             "evidence" (vector (subseq id 0 8))))))
                        (and (has "record_finding: recorded" text)
                             (omp-heard-of omp "judge" "s1")
                             (eql 30 (gethash "seconds" (first (omp-heard-of omp "judge" "s1")))))))
               (check "a call omp cancels while the engine waits for omp's own answer ends at once, as aborted, and records nothing"
                      (let ((findings (band-count (session-state omp "s1") "findings"))
                            (asking (omp-request omp "call" "session" (session-of "s1") "name" "record_finding"
                                                 "arguments" (omp-re:obj "claim" "Withheld: main is a function."
                                                                         "evidence" (vector (subseq id 0 8)))
                                                 "callId" "call-withheld")))
                        (wait-until (lambda () (= 2 (length (omp-heard-of omp "judge" "s1")))) 20)
                        (omp-tell omp "cancel" "id" asking)
                        (let ((answer (omp-await omp asking 10)))
                          (and (hash-table-p answer)
                               (equal "omp-re: the support audit aborted" (gethash "text" answer))
                               (eq t (gethash "refused" answer))
                               (eql findings (band-count (session-state omp "s1") "findings"))))))
               (check "the line cite answers the evidence as the opening of a message about it"
                      (starts (format nil "Re: evidence ~a (rizin_command @ " (subseq id 0 8))
                              (gethash "text" (run-line omp "s1" (format nil "cite ~a" (subseq id 0 8)))))))
             (let ((big (tool-call omp "s1" "rizin_command" "command" "aflj")))
               (check "a result too large to send is kept whole by omp and named artifact://<id>"
                      (and (eq t (omp-re:jget big "details" "truncated"))
                           (not (has "\"name\"" (gethash "text" big)))
                           (has (format nil "Full output: artifact://~a]" (omp-re:jstring big "details" "artifactId"))
                                (gethash "text" big))
                           (starts "rizin> aflj"
                                   (gethash (omp-re:jstring big "details" "artifactId") (omp-artifacts omp)))))
               (check "the answer carries all rizin printed beside the cut text, and the id of the evidence as it is shown"
                      (and (omp-re:json-array-p (omp-re:json-parse (gethash "raw" big)))
                           (equal (subseq (omp-re:jstring big "details" "evidenceId") 0 8) (gethash "evidence" big))))
               (check "/re evidence <id> names the artifact the same way, not a file of the engine's"
                      (has (format nil "full output: artifact://~a" (omp-re:jstring big "details" "artifactId"))
                           (gethash "text" (run-line omp "s1" (format nil "evidence ~a"
                                                                        (subseq (omp-re:jstring big "details" "evidenceId") 0 8)))))))
             (let ((panel (omp-ask omp "view" "session" (session-of "s1") "kind" "functions")))
               (check "the functions view is a panel of rows, each opening that function's code"
                      (let ((row (find "main" (coerce (gethash "rows" panel) 'list)
                                       :key (lambda (row) (gethash "label" row)) :test #'string=)))
                        (and (equal "panel" (gethash "type" panel))
                             (equal "omp-re: functions" (gethash "title" panel))
                             row
                             (uiop:string-prefix-p "0x" (gethash "value" row))
                             (equal "code" (omp-re:jstring row "enter" "view" "kind")))))
               (let* ((row (find "main" (coerce (gethash "rows" panel) 'list)
                                 :key (lambda (row) (gethash "label" row)) :test #'string=))
                      (code (omp-ask omp "view" "session" (session-of "s1") "kind" "code"
                                                "arg" (omp-re:jget row "enter" "view" "arg"))))
                 (check "a code view is the disassembly, each line at its address, with the draft that hands it to the model"
                        (and (equal "code" (gethash "type" code))
                             (equal "main" (gethash "title" code))
                             (some (lambda (line) (starts (gethash "value" row) line))
                                   (coerce (gethash "disasm" code) 'list))
                             (has "Analyze function main at " (gethash "ask" code))
                             (equal "xrefs" (omp-re:jstring code "xrefs" "kind"))))
                 (check "with no decompiler plugin the decompiled side is the disassembly, labeled as that"
                        (or (omp-re:jget code "decompile" "language")
                            (and (equal "decompile (disassembly only)" (omp-re:jstring code "decompile" "label"))
                                 (starts "(disassembly only — " (omp-re:jstring code "decompile" "note")))))
                 (check "a view records no evidence: browsing is not the model observing"
                        (= 2 (count "re.evidence" (gethash "s1" (omp-records omp))
                                    :key (lambda (entry) (gethash "customType" entry)) :test #'equal)))))
             (check "the evidence view's rows carry the citation a choice drafts; a view that cannot be shown is a notice"
                    (let ((evidence (omp-ask omp "view" "session" (session-of "s1") "kind" "evidence"))
                          (missing (omp-ask omp "view" "session" (session-of "s1") "kind" "code"
                                                       "arg" (omp-re:obj "addr" "0xdeadbeef00"))))
                      (and (starts "Re: evidence " (omp-re:jstring (aref (gethash "rows" evidence) 0) "enter" "draft"))
                           (equal "notice" (gethash "type" missing))
                           (equal "error" (gethash "level" missing)))))
             (check "the compaction lines name the binary, the evidence and the finding"
                    (let ((lines (coerce (gethash "lines" (omp-ask omp "preserved" "session" (session-of "s1"))) 'list)))
                      (and (has "preserve" (first lines))
                           (some (lambda (line) (has (format nil "- Open binary: ~a (" (file-namestring *binary*)) line))
                                 lines)
                           (some (lambda (line) (has "2 evidence item(s), 0 annotation(s) in effect" line)) lines)
                           (some (lambda (line) (has "[likely] main is a function." line)) lines))))
             ;; After the counts above: these two record evidence and findings of their own.
             (let ((cut (find-if (lambda (entry) (omp-re:jstring entry "data" "artifactId"))
                                 (gethash "s1" (omp-records omp)))))
               (check "a report over a claim that cites a cut result asks omp for the whole of it, by the artifact's id"
                      (let ((cited (tool-call omp "s1" "record_finding"
                                              "claim" "The binary has functions."
                                              "evidence" (vector (omp-re:jstring cut "data" "id")))))
                        (run-line omp "s1" "report")
                        (and (has "record_finding: recorded" (gethash "text" cited))
                             (find (omp-re:jstring cut "data" "artifactId") (omp-heard-of omp "readArtifact" "s1")
                                   :key (lambda (params) (gethash "id" params)) :test #'equal)
                             t))))
             (check "a side model omp could not reach leaves the finding unaudited, with omp's reason in one line"
                    (let* ((read (tool-call omp "s1" "rizin_command" "command" "afij" "addr" "main"))
                           (text (gethash "text" (tool-call omp "s1" "record_finding"
                                                            "claim" "Unreachable: main is a function."
                                                            "evidence" (vector (omp-re:jstring read "details" "evidenceId"))))))
                      (and (has "record_finding: recorded" text)
                           (has (format nil "~%support audit: unaudited — the audit side turn failed: the provider answered 503~%")
                                text))))

             ;; A session an earlier, TypeScript, version wrote: omp's file
             ;; holds the entries; the engine has never seen the session.
             (let* ((renamed (tool-call omp "s1" "rename_function" "addr" "main" "new" "omp_re_wire_main"))
                    (annotation (omp-re:jget (car (last (gethash "s1" (omp-records omp)))) "data"))
                    (binary (omp-re:jget (first (gethash "s1" (omp-records omp))) "data")))
               (check "an annotation over the wire lands and is recorded with the entry id omp gave it"
                      (and (not (gethash "failed" renamed))
                           (equal "rename_function" (gethash "kind" annotation))))
               (setf (gethash "s-old" (omp-records omp))
                     (list (omp-re:json-parse
                            (format nil "{\"type\":\"custom\",\"id\":\"a1\",\"parentId\":null,\"timestamp\":\"2026-01-01T00:00:00.000Z\",\"customType\":\"re.binary\",\"data\":{\"path\":~a,\"sha256\":~a}}"
                                    (omp-re:json-encode (gethash "path" binary)) (omp-re:json-encode (gethash "sha256" binary))))
                           (omp-re:json-parse
                            (format nil "{\"type\":\"custom\",\"id\":\"a2\",\"parentId\":\"a1\",\"customType\":\"re.annotation\",\"data\":{\"kind\":\"rename_function\",\"ea\":~a,\"oldValue\":\"main\",\"newValue\":\"ts_written_main\",\"evidenceId\":null,\"ungrounded\":true}}"
                                    (omp-re:json-encode (gethash "ea" annotation))))
                           (omp-re:json-parse
                            "{\"type\":\"custom\",\"id\":\"a3\",\"parentId\":\"a2\",\"customType\":\"re.evidence\",\"data\":{\"id\":\"0f0f0f0f-1111-2222-3333-444444444444\",\"tool\":\"rizin_command\",\"args\":{\"command\":\"ij\"},\"outputHash\":\"00\",\"summary\":\"rizin> ij\"}}")))
               (let ((started (omp-ask omp "event" "session" (session-of "s-old") "kind" "start")))
                 (check "a session written by an earlier version restores from omp's file: the start answers at once"
                        (hash-table-p started))
                 (check "and a call made right after waits for the analysis, then sees the replayed rename"
                        (let ((read (tool-call omp "s-old" "rizin_command" "command" "afij" "addr" "ts_written_main")))
                          (and (not (gethash "failed" read))
                               (has "ts_written_main" (gethash "text" read)))))
                 (check "when the restore is done the engine sends the session's state, the band's facts in it"
                        (wait-until (lambda ()
                                      (some (lambda (params) (plusp (band-count (gethash "state" params) "fn")))
                                            (omp-heard-of omp "state" "s-old")))
                                    20))
                 (check "its status counts the evidence the earlier version recorded"
                        (has "evidence on this branch: 2" (gethash "text" (run-line omp "s-old" "status"))))))

             (check "a session whose binary is gone when it starts is told so, as an error: the restore runs in the background"
                    (progn
                      (setf (gethash "s-gone" (omp-records omp))
                            (list (omp-re:obj "type" "custom" "id" "g1" "customType" "re.binary"
                                              "data" (omp-re:obj "path" (scratch-path "no-such-binary")
                                                                 "sha256" (make-string 64 :initial-element #\a)))))
                      (omp-ask omp "event" "session" (session-of "s-gone") "kind" "start")
                      (wait-until (lambda () (omp-heard-of omp "tell" "s-gone")) 20)
                      (let ((told (first (omp-heard-of omp "tell" "s-gone"))))
                        (and told
                             (has "no-such-binary" (gethash "text" told))
                             (equal "error" (gethash "level" told))))))
             (check "a branch carries the session over to its new id, rizin and all: nothing is analyzed again"
                    (progn
                      (setf (gethash "s1-branch" (omp-records omp)) (gethash "s1" (omp-records omp)))
                      (omp-ask omp "event" "session" (session-of "s1-branch") "kind" "branch" "previous" "s1")
                      (let ((read (tool-call omp "s1-branch" "rizin_command" "command" "afij" "addr" "omp_re_wire_main")))
                        (and (not (gethash "failed" read))
                             (null (omp-heard-of omp "progress" "s1-branch"))))))
             (check "when omp's branch no longer holds what the engine read, the engine reads it all again: the binary is not open there"
                    (progn
                      (setf (gethash "s1-branch" (omp-records omp)) '())
                      (has "no binary open" (gethash "text" (tool-call omp "s1-branch" "rizin_command"
                                                                       "command" "ij")))))

             ;; Cancel: a session analyzing a large binary, and one waiting behind it.
             (let* ((large (or (find-if #'probe-file '("/usr/bin/python3" "/usr/bin/perl" "/bin/bash")) *binary*))
                    (opening (omp-request omp "call" "session" (session-of "s-cancel") "name" "open_binary"
                                              "arguments" (omp-re:obj "path" large) "callId" "c-open"))
                    (queued (progn
                              (wait-until (lambda () (omp-heard-of omp "progress" "s-cancel")) 20)
                              (omp-request omp "call" "session" (session-of "s-cancel") "name" "rizin_help"
                                                      "arguments" (omp-re:obj "query" "pdf") "callId" "c-queued")))
                    (other (get-internal-real-time))
                    (elsewhere (run-line omp "s-old" "status")))
               (check "a long analysis in one session does not hold up another session's line"
                      (and (has "binary: " (gethash "text" elsewhere))
                           (< (- (get-internal-real-time) other) (* 5 internal-time-units-per-second))))
               (check "/re status of the session being analyzed answers at once, from what the session holds"
                      (let ((began (get-internal-real-time))
                            (status (run-line omp "s-cancel" "status")))
                        (and (has "rizin: " (gethash "text" status))
                             (< (- (get-internal-real-time) began) (* 5 internal-time-units-per-second)))))
               (check "while omp waits, the engine says at a steady beat which requests it is serving"
                      (wait-until (lambda ()
                                    (some (lambda (params)
                                            (and (find opening (gethash "serving" params))
                                                 (find queued (gethash "serving" params))))
                                          (omp-heard-of omp "alive")))
                                  (* 3 (omp-re-stdio::protocol-constant "aliveSeconds"))))
               (omp-tell omp "cancel" "id" queued)
               (check "a call cancelled while it waits its turn leaves the queue, saying it was aborted"
                      (let ((answer (omp-await omp queued 10)))
                        (and (eq t (gethash "failed" answer)) (has "aborted" (gethash "text" answer)))))
               (omp-tell omp "cancel" "id" opening)
               (check "a cancelled analysis answers promptly, as aborted"
                      (let ((answer (omp-await omp opening 10)))
                        (and (eq t (gethash "failed" answer)) (has "aborted" (gethash "text" answer)))))
               (check "nothing of the half-analyzed binary is left open, and the session opens another normally"
                      (and (has "no binary open" (gethash "text" (tool-call omp "s-cancel" "rizin_command"
                                                                            "command" "ij")))
                           (not (gethash "failed" (tool-call omp "s-cancel" "open_binary" "path" *binary*))))))

             ;; A status band is drawn beside whatever call holds the session.
             (let ((large (find-if #'probe-file '("/bin/bash" "/usr/bin/perl"))))
               (unless large
                 (format t "  SKIPPED (the status band beside a long command: no /bin/bash or /usr/bin/perl to analyze)~%"))
               (when large
                 (tool-call omp "s-busy" "open_binary" "path" large)
                 (let* ((known (band-count (session-state omp "s-busy") "fn"))
                        (busy (omp-request omp "call" "session" (session-of "s-busy") "name" "analyze"
                                                "arguments" (omp-re:obj "pass" "emulate_functions")
                                                "callId" "c-busy"))
                        (began (progn (sleep 1) (get-internal-real-time)))
                        (line (omp-await omp (omp-request omp "command" "session" (session-of "s-busy")
                                                                         "line" "help")
                                         4)))
                   (check "while a long rizin command runs in a session its status band answers at once, from what the session knows"
                          (and (hash-table-p line)
                               (plusp known)
                               (eql known (band-count (gethash "state" line) "fn"))
                               (< (- (get-internal-real-time) began) (* 3 internal-time-units-per-second))
                               ;; and the command was still running when it answered
                               (null (sb-thread:with-mutex ((omp-lock omp)) (gethash busy (omp-answers omp))))))
                   (omp-tell omp "cancel" "id" busy)
                   (omp-await omp busy 20)
                   (omp-ask omp "event" "session" (session-of "s-busy") "kind" "shutdown"))))

             (check "a session's end closes its rizin; the others keep theirs"
                    (progn
                      (omp-ask omp "event" "session" (session-of "s-cancel") "kind" "shutdown")
                      (and (eql 0 (band-count (session-state omp "s-cancel") "fn"))
                           (plusp (band-count (session-state omp "s-old") "fn")))))
             #-win32
             (setf children (omp-re::process-descendants (sb-ext:process-pid (omp-process omp)))))
        (let ((code (stop-omp omp)))
          (check "everything that crossed the pipe, either way, is what stdio/protocol.json describes"
                 (null (print-violations omp)))
          (check "the pipe closing ends the engine and every rizin it started"
                 (and (eql 0 code)
                      #-win32 (and children
                                   (wait-until (lambda ()
                                                 (notany (lambda (pid) (probe-file (format nil "/proc/~d/stat" pid)))
                                                         children))
                                               10))))))))
