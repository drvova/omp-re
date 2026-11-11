;;;; suite-debug.lisp --- the opt-in debugger (engine/debug.lisp).
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; rizin_debug is the one tool that executes a program, so most of this
;;;; suite executes nothing. The gate, the builders and the validators are
;;;; pure. The tool itself is driven against a stand-in for rizin: a shell
;;;; script that speaks the NUL-framed pipe protocol, writes down the argv it
;;;; was started with and every command it was sent, and debugs nothing. That
;;;; shows the exact command line of a launch and of an attach, the exact
;;;; rizin command of every action, and every refusal, with no process under
;;;; a debugger. Last, one real session launches the test binary — /bin/ls or /bin/true only —
;;;; under rizin's debugger, stopped at its entry, and stops it again.

(in-package #:nodecode-re-test)

(defun debug-call (&rest arguments)
  (apply #'re:call "rizin_debug" arguments))

(defun debug-refusal (&rest arguments)
  (refusal (lambda () (apply #'debug-call arguments))))

(defun json-of (text)
  (omp-re:json-decode text))

(defun process-gone-p (process)
  "Whether PROCESS ended, waiting a few seconds for it."
  (loop repeat 60
        when (not (sb-ext:process-alive-p process)) return t
        do (sleep 0.05)))

(defun pid-gone-p (pid)
  "Whether no process PID runs — it is gone, or a zombie nothing reaped
yet — waiting a few seconds for that."
  (loop repeat 60
        do (let ((stat (ignore-errors
                        (uiop:read-file-string (format nil "/proc/~d/stat" pid)))))
             (when (or (null stat)
                       ;; "pid (comm) state ...": the state follows the last ")".
                       (let ((close (position #\) stat :from-end t)))
                         (and close (< (+ close 2) (length stat))
                              (char= #\Z (char stat (+ close 2))))))
               (return t)))
           (sleep 0.05)))

(defun children-of (pid)
  "The pids of PID's children. rizin forks the debuggee from whichever of
its threads runs the debugger, so every thread's list is read."
  (loop for task in (directory (format nil "/proc/~d/task/*/" pid))
        append (let ((text (ignore-errors
                            (uiop:read-file-string (merge-pathnames "children" task)))))
                 (and text (mapcar #'parse-integer (omp-re::words text))))))

;;; --- the gate -------------------------------------------------------------------------

(suite "debug: the gate")
(with-environment ("OMPRE_ENABLE_DEBUGGER" nil)
  (check "the debugger is off unless explicitly opted in"
         (and (not (omp-re::debugger-enabled-p))
              (every (lambda (on)
                       (with-environment ("OMPRE_ENABLE_DEBUGGER" on) (omp-re::debugger-enabled-p)))
                     '("1" "true" "yes" "on" "TRUE"))
              (notany (lambda (off)
                        (with-environment ("OMPRE_ENABLE_DEBUGGER" off) (omp-re::debugger-enabled-p)))
                      '("0" "false" "no" ""))))
  (with-cell ()
    (check "with the debugger off the tool is not offered"
           (and (not (has "rizin_debug" (re:tools)))
                (null (omp-re::find-tool "rizin_debug"))
                (has "no tool is named" (refusal (lambda () (re:doc "rizin_debug"))))))
    (check "and a call to it says there is no such tool"
           (has "no tool named \"rizin_debug\"" (debug-refusal :action "start")))
    (check "nor does it run through the name the engine knows it by"
           (multiple-value-bind (text failed)
               (omp-re::call-tool (omp-re:find-session (fresh-session)) "rizin_debug" (omp-re:obj "action" "stop"))
             (and failed (has "no tool named" text)))))
  (with-cell (:debugger t)
    (check "with the debugger on the tool is offered"
           (and (has "rizin_debug — Dynamic analysis" (re:tools))
                (omp-re::find-tool "rizin_debug")))
    (check "(re:doc) lists its parameters, the engine's own"
           (let ((text (re:doc "rizin_debug")))
             (and (every (lambda (name) (has (format nil "  :~a  " name) text))
                         '("action" "addr" "count" "size" "file" "reg" "value" "bytes" "perm"
                           "condition" "command" "lib" "name" "run" "attach"))
                  (has ":action  one of \"start\", \"continue\"" text)
                  (has "\"heap_bins\", \"stop\", required" text))))
    (check "it is exec-tier and never evidence"
           (let ((tool (described-tool "rizin_debug")))
             (and (equal "exec" (gethash "approval" tool)) (not (gethash "evidence" tool)))))
    (check "the status line says it is enabled"
           (in-session ((fresh-session)) (has "debugger: enabled" (re:status)))))
  (with-environment ("OMPRE_ENABLE_DEBUGGER" "1")
    (with-cell ()
      (check "OMPRE_ENABLE_DEBUGGER switches it on as the setting does"
             (has "rizin_debug" (re:tools))))))

;;; --- the builders ---------------------------------------------------------------------

(suite "debug: run directives")
(check "nothing given, or an empty object, is no directive"
       (and (null (omp-re::build-run-directives :absent))
            (null (omp-re::build-run-directives (json-of "{}")))))
(check "args, env, cwd, aslr and a limit become directives, in the order given"
       (equal '("arg0=--flag" "arg1=value with spaces" "setenv=PATH_EXTRA=a=b" "chdir=C:/tmp"
                "aslr=no" "timeout=30")
              (omp-re::build-run-directives
               (json-of "{\"args\":[\"--flag\",\"value with spaces\"],\"env\":{\"PATH_EXTRA\":\"a=b\"},\"cwd\":\"C:/tmp\",\"aslr\":false,\"timeout\":30}"))))
(check "stdio files, input and the other limits too"
       (equal '("stdin=C:/in.txt" "stdout=C:/out.txt" "stderr=C:/err.txt" "input=payload"
                "maxstack=1048576" "maxfd=64" "maxproc=8")
              (omp-re::build-run-directives
               (json-of "{\"stdin\":\"C:/in.txt\",\"stdout\":\"C:/out.txt\",\"stderr\":\"C:/err.txt\",\"input\":\"payload\",\"maxstack\":1048576,\"maxfd\":64,\"maxproc\":8}"))))
(check "aslr true is yes, and a fractional limit is floored"
       (equal '("aslr=yes" "maxfd=7")
              (omp-re::build-run-directives (json-of "{\"aslr\":true,\"maxfd\":7.9}"))))
(dolist (case '(("{\"stdin\":\"!rm -rf /\"}" "omp-re: debug: run.stdin does not accept command targets")
                ("{\"stdout\":\"!cmd\"}" "omp-re: debug: run.stdout does not accept command targets")
                ("{\"stderr\":\"!cmd\"}" "omp-re: debug: run.stderr does not accept command targets")
                ("{\"stdin\":5}" "omp-re: debug: run.stdin must be a file path")
                ("{\"args\":[\"line\\nbreak\"]}" "omp-re: debug: run.args must not contain line breaks")
                ("{\"cwd\":\"a\\rb\"}" "omp-re: debug: run.cwd must not contain line breaks")
                ("{\"input\":\"a\\nb\"}" "omp-re: debug: run.input must not contain line breaks")
                ("{\"env\":{\"OK\":\"a\\nb\"}}" "omp-re: debug: run.env must not contain line breaks")
                ("{\"env\":{\"BAD-NAME\":\"v\"}}" "omp-re: debug: run.env: bad variable name \"BAD-NAME\"")
                ("{\"env\":{\"OK\":1}}" "omp-re: debug: run.env.OK must be a string")
                ("{\"env\":[\"A=b\"]}" "omp-re: debug: run.env must be an object")
                ("{\"cwd\":1}" "omp-re: debug: run.cwd must be a string")
                ("{\"input\":1}" "omp-re: debug: run.input must be a string")
                ("{\"aslr\":\"yes\"}" "omp-re: debug: run.aslr must be true or false")
                ("{\"timeout\":-1}" "omp-re: debug: run.timeout must be a positive number")
                ("{\"maxproc\":\"8\"}" "omp-re: debug: run.maxproc must be a positive number")
                ("{\"bogus\":1}" "omp-re: debug: run.bogus is not a supported rz-run setting (args, env, cwd, stdin, stdout, stderr, input, aslr, maxstack, maxfd, maxproc, timeout)")
                ("{\"args\":\"not-a-list\"}" "omp-re: debug: run.args must be a list of strings")
                ("{\"args\":[1]}" "omp-re: debug: run.args must be a list of strings")
                ("\"not-an-object\"" "omp-re: debug: run must be an object of rz-run settings")
                ("[1]" "omp-re: debug: run must be an object of rz-run settings")))
  (destructuring-bind (run message) case
    (check (format nil "refused: ~a" run)
           (equal message (refusal (lambda () (omp-re::build-run-directives (json-of run))))))))
(check "more than 64 arguments, and more than 64 KiB of input, are refused"
       (and (equal "omp-re: debug: run.args supports at most 64 arguments"
                   (refusal (lambda ()
                              (omp-re::build-run-directives
                               (omp-re:obj "args" (make-array 65 :initial-element "x"))))))
            (equal "omp-re: debug: run.input is limited to 64 KiB"
                   (refusal (lambda ()
                              (omp-re::build-run-directives
                               (omp-re:obj "input" (make-string 65537 :initial-element #\a))))))))

(suite "debug: the attach target")
(check "no attach is the default launch"
       (null (omp-re::build-debug-target :absent)))
(check "a pid becomes the target string; a gdb or windbg URI passes through"
       (and (equal "1234" (omp-re::build-debug-target (json-of "{\"pid\":1234}")))
            (equal "gdb://127.0.0.1:1234" (omp-re::build-debug-target (json-of "{\"remote\":\"gdb://127.0.0.1:1234\"}")))
            (equal "windbg://pipe/com_1" (omp-re::build-debug-target (json-of "{\"remote\":\"windbg://pipe/com_1\"}")))))
(dolist (case '(("{\"pid\":0}" "omp-re: debug: attach.pid must be a positive integer (got 0)")
                ("{\"pid\":-1}" "omp-re: debug: attach.pid must be a positive integer (got -1)")
                ("{\"pid\":1.5}" "omp-re: debug: attach.pid must be a positive integer (got 1.5)")
                ("{\"pid\":\"12\"}" "omp-re: debug: attach.pid must be a positive integer (got \"12\")")
                ("{\"remote\":\"http://evil\"}" "omp-re: debug: attach.remote must be a gdb:// or windbg:// URI (got \"http://evil\")")
                ("{\"remote\":\"gdb://host; rm -rf /\"}" "omp-re: debug: attach.remote must be a gdb:// or windbg:// URI (got \"gdb://host; rm -rf /\")")
                ("{\"remote\":\"-R\"}" "omp-re: debug: attach.remote must be a gdb:// or windbg:// URI (got \"-R\")")
                ("{\"remote\":7}" "omp-re: debug: attach.remote must be a gdb:// or windbg:// URI (got 7)")
                ("{}" "omp-re: debug: attach needs exactly one of pid or remote")
                ("{\"pid\":1,\"remote\":\"gdb://h:1\"}" "omp-re: debug: attach needs exactly one of pid or remote")
                ("\"nope\"" "omp-re: debug: attach must be an object with a pid or remote")
                ("[1]" "omp-re: debug: attach must be an object with a pid or remote")))
  (destructuring-bind (attach message) case
    (check (format nil "refused: ~a" attach)
           (equal message (refusal (lambda () (omp-re::build-debug-target (json-of attach))))))))

(suite "debug: the command line")
(check "a launch is -d <binary>, the binary last"
       (equal '("-d" "/bin/ls") (omp-re::debug-argv "/bin/ls")))
(check "run directives ride as one -R element each, before -d"
       (equal '("-R" "arg0=-l" "-R" "arg1=two words" "-R" "setenv=LANG=C" "-R" "aslr=no" "-d" "/bin/ls")
              (omp-re::debug-argv "/bin/ls"
                              :run-directives (omp-re::build-run-directives
                                               (json-of "{\"args\":[\"-l\",\"two words\"],\"env\":{\"LANG\":\"C\"},\"aslr\":false}")))))
(check "a raw target's load flags come first, as the static session loads it"
       (equal '("-a" "arm" "-b" "32" "-m" "0x8000000" "-R" "arg0=x" "-d" "/tmp/blob.bin")
              (omp-re::debug-argv "/tmp/blob.bin"
                              :load (omp-re:obj "arch" "arm" "bits" 32 "map" "0x8000000")
                              :run-directives '("arg0=x"))))
(check "an attach is -d <target> <binary>, with no load flags and no directives"
       (and (equal '("-d" "4242" "/bin/ls")
                   (omp-re::debug-argv "/bin/ls" :target "4242"
                                             :load (omp-re:obj "arch" "arm")
                                             :run-directives '("arg0=x")))
            (equal '("-d" "gdb://127.0.0.1:1234" "/bin/ls")
                   (omp-re::debug-argv "/bin/ls" :target "gdb://127.0.0.1:1234"))))
(with-environment ("OMPRE_RIZIN_LOAD_USER_CONFIG" nil)
  (check "the whole argv: the shared flags, then the debug half"
         (equal '("rizin" "-q0" "-e" "scr.color=0" "-e" "scr.utf8=false" "-N" "-R" "arg0=-l" "-d" "/bin/ls")
                (cons "rizin" (append (omp-re::base-rizin-flags)
                                      (omp-re::debug-argv "/bin/ls" :run-directives '("arg0=-l")))))))

(suite "debug: validators and the bits note")
(check "a register name"
       (and (equal "rax" (omp-re::validate-reg-name "rax"))
            (equal "omp-re: debug: bad register name \"rax;id\""
                   (refusal (lambda () (omp-re::validate-reg-name "rax;id"))))
            (refusal (lambda () (omp-re::validate-reg-name "1ax")))
            (refusal (lambda () (omp-re::validate-reg-name "")))))
(check "a register value is decimal or 0x hex"
       (and (equal "0x1234" (omp-re::validate-reg-value "0x1234"))
            (equal "42" (omp-re::validate-reg-value "42"))
            (equal "omp-re: debug: bad register value \"0xzz\" — use decimal or 0x hex"
                   (refusal (lambda () (omp-re::validate-reg-value "0xzz"))))
            (refusal (lambda () (omp-re::validate-reg-value "1;!id")))
            (refusal (lambda () (omp-re::validate-reg-value "rbx")))))
(check "hex bytes: an even number of digits, blanks dropped"
       (and (equal "4889e5" (omp-re::validate-debug-hex "48 89 e5"))
            (equal "omp-re: debug: bad hex bytes \"zz\" — an even number of hex digits, e.g. 9090 or 4889e5"
                   (refusal (lambda () (omp-re::validate-debug-hex "zz"))))
            (has "bad hex bytes \"9\"" (refusal (lambda () (omp-re::validate-debug-hex "9"))))
            (refusal (lambda () (omp-re::validate-debug-hex "90;!id")))
            (refusal (lambda () (omp-re::validate-debug-hex "")))))
(check "a symbol or library name"
       (and (equal "libc.so.6" (omp-re::validate-symbol-query "libc.so.6"))
            (equal "omp-re: debug: bad symbol/library name \"system;id\""
                   (refusal (lambda () (omp-re::validate-symbol-query "system;id"))))
            (refusal (lambda () (omp-re::validate-symbol-query "a b")))))
(check "a watchpoint's access"
       (and (equal "rw" (omp-re::validate-watch-perm nil))
            (equal "w" (omp-re::validate-watch-perm "W"))
            (equal "omp-re: debug: watch perm must be r, w, or rw (got \"x\")"
                   (refusal (lambda () (omp-re::validate-watch-perm "x"))))))
(check "a count is clamped to its range, and floored"
       (and (= 1 (omp-re::clamped-count nil 1 100000)) (= 16 (omp-re::clamped-count nil 16 1024))
            (= 1 (omp-re::clamped-count 0 1 100000)) (= 1 (omp-re::clamped-count -5 1 100000))
            (= 100000 (omp-re::clamped-count 1000000000 1 100000)) (= 3 (omp-re::clamped-count 3.9 1 100000))))
(check "the build's bits are read from rizin -v's first line"
       (and (eql 64 (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ linux-x86-64"))
            (eql 32 (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ windows-x86-32"))
            (eql 64 (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ linux-x86_64 build"))
            (eql 64 (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ darwin-arm64"))
            (eql 64 (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ linux-aarch64"))
            (eql 32 (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ linux-i386"))
            (eql 32 (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ linux-arm"))
            (null (omp-re::parse-rizin-version-arch "rizin 0.9.1 @ plan9-mips"))
            (null (omp-re::parse-rizin-version-arch ""))))
(check "the debug budget is OMPRE_DEBUG_TIMEOUT_MS, 60 seconds when unset or nonsense"
       (and (with-environment ("OMPRE_DEBUG_TIMEOUT_MS" nil) (= 60 (omp-re::dynamic-seconds)))
            (with-environment ("OMPRE_DEBUG_TIMEOUT_MS" "2500") (= 5/2 (omp-re::dynamic-seconds)))
            (with-environment ("OMPRE_DEBUG_TIMEOUT_MS" "soon") (= 60 (omp-re::dynamic-seconds)))))

;;; --- the tool with no debug session ---------------------------------------------------

(suite "debug: before start")
(with-cell (:debugger t)
  (let ((id (fresh-session)))
    (in-session (id)
      (check "start with no binary open says how to open one, and launches nothing"
             (and (has "no binary open" (debug-refusal :action "start"))
                  (null (omp-re::session-dbg (omp-re:find-session id)))))
      (setf (omp-re::session-binary-path (omp-re:find-session id)) *binary*)
      (check "every action but start and stop is refused: nothing is launched implicitly"
             (every (lambda (action)
                      (equal "omp-re: no debug session — run the debug tool with action 'start' first (it launches the process)."
                             (debug-refusal :action action :addr "entry0")))
                    (set-difference omp-re::+debug-actions+ '("start" "stop") :test #'string=)))
      (check "stop with nothing to stop says so, twice over"
             (and (equal "debug: no debug session to stop" (debug-call :action "stop"))
                  (equal "debug: no debug session to stop" (debug-call :action "stop"))))
      (check "an action outside the list is refused by the schema"
             (has "action must be one of" (debug-refusal :action "detonate")))
      (check "a member of the wrong type is refused, never coerced"
             (and (has "count must be a number" (debug-refusal :action "step" :count "3"))
                  (has "size must be a number" (debug-refusal :action "read_memory" :size "8"))
                  (has "addr must be a string" (debug-refusal :action "break_add" :addr 4096))
                  (has "action is required" (debug-refusal :addr "entry0"))))
      (check "a bad attach is refused before anything starts"
             (and (has "gdb:// or windbg://"
                       (debug-refusal :action "start" :attach '(:remote "http://nope")))
                  (has "positive integer" (debug-refusal :action "start" :attach '(:pid 0)))
                  (has "exactly one" (debug-refusal :action "start" :attach (omp-re:obj)))
                  (has "attach must be an object" (debug-refusal :action "start" :attach "4242"))
                  (has "attach must be an object" (debug-refusal :action "start" :attach "not json"))))
      (check "attach cannot be combined with run"
             (equal "omp-re: debug: attach cannot be combined with run (there is no new process to configure)"
                    (debug-refusal :action "start" :attach '(:pid 4242) :run '(:args ("x")))))
      (check "bad run settings are refused before anything launches"
             (and (has "does not accept command targets"
                       (debug-refusal :action "start" :run '(:stdout "!id")))
                  (has "run must be an object" (debug-refusal :action "start" :run "-R"))
                  (has "is not a supported rz-run setting"
                       (debug-refusal :action "start" :run '(:system "id")))))
      (check "and none of those refusals started a process"
             (null (omp-re::session-dbg (omp-re:find-session id))))
      (check "the calls were audited, and none is evidence"
             (let ((log (omp-re::read-text-file (omp-re::state-path "audit" (format nil "~a.log" id)))))
               (and (has "\"tool\":\"rizin_debug\"" log)
                    (has "\"action\":\"stop\"" log)
                    (null (omp-re::evidence-records (omp-re:find-session id)))))))))

;;; --- the tool against a stand-in for rizin ----------------------------------------------
;;; The stand-in is a shell script speaking the pipe protocol. It is found
;;; the way a real one would be: through the per-bits override that picks the
;;; rizin for the open binary. It answers `-v' as a 32-bit build, so a launch
;;; of the 64-bit test binary must carry the bits note.

(defparameter *stand-in-log* (uiop:native-namestring (merge-pathnames "stand-in" *scratch*)))
(defparameter *stand-in* (uiop:native-namestring (merge-pathnames "stand-in-rizin.sh" *scratch*)))

(defun write-stand-in (bits)
  (with-open-file (out *stand-in* :direction :output :if-exists :supersede)
    (format out "#!/bin/sh
LOG='~a'
if [ \"$1\" = \"-v\" ]; then echo 'rizin 0.9.1 @ linux-x86-~d'; exit 0; fi
: > \"$LOG.argv\"
for a in \"$@\"; do printf '%s\\n' \"$a\" >> \"$LOG.argv\"; done
printf '\\0'
while IFS= read -r line; do
  case \"$line\" in
    'echo '*) printf '%s\\n\\0' \"${line#echo }\" ;;
    *) printf '%s\\n' \"$line\" >> \"$LOG.cmds\"
       case \"$line\" in
         'dr rip') printf 'rip = 0x0000000000401000\\n\\0' ;;
         '?v '*) printf '0x401000\\n\\0' ;;
         'p8 '*) printf 'deadbeef\\n\\0' ;;
         'dblj') printf '[]\\n\\0' ;;
         'dtsf '*) echo 'ERROR: stand-in has no session to load' >&2; printf '\\0' ;;
         *) printf '\\0' ;;
       esac ;;
  esac
done
" *stand-in-log* bits))
  (sb-posix:chmod *stand-in* #o755))

(defun log-lines (suffix)
  (remove "" (omp-re:split-lines (or (omp-re::read-text-file (concatenate 'string *stand-in-log* suffix)) ""))
          :test #'string=))

(defun sent (&rest arguments)
  "The commands one call sent to the stand-in, in order."
  (ignore-errors (delete-file (concatenate 'string *stand-in-log* ".cmds")))
  (apply #'debug-call arguments)
  (log-lines ".cmds"))

(defun sent-nothing-p (&rest arguments)
  "The refusal of a call, provided it sent the stand-in nothing."
  (ignore-errors (delete-file (concatenate 'string *stand-in-log* ".cmds")))
  (let ((message (apply #'debug-refusal arguments)))
    (and (null (log-lines ".cmds")) message)))

(defun shared-flags ()
  (omp-re::base-rizin-flags))

(let* ((bits (omp-re::read-binary-bits *binary*))
       (override (and bits (format nil "OMPRE_RIZIN_PATH_~d" bits)))
       (output (uiop:native-namestring (merge-pathnames "debug-out/" *scratch*))))
  (cond
    ((not (and bits (probe-file "/bin/sh") (probe-file *binary*)))
     (suite "debug: against a stand-in")
     (format t "  SKIPPED — needs /bin/sh and a test binary whose bits are known (~a)~%" *binary*))
    (t
     (write-stand-in (if (= bits 64) 32 64))
     (with-environment (override *stand-in*)
       (with-environment ("OMPRE_OUTPUT_DIR" output)
         (suite "debug: a launch, against a stand-in")
         (with-cell (:debugger t)
           (let* ((id (fresh-session))
                  (session (in-session (id) (omp-re:find-session id))))
             (in-session (id)
               (setf (omp-re::session-binary-path session) *binary*)
               (let ((text (debug-call :action "start"
                                       :run '(:args ("-l" "two words") :env ("LANG" "C") :cwd "/tmp" :aslr :false))))
                 (check "start spawns rizin with the shared flags, each directive as -R, then -d <binary>"
                        (equal (append (shared-flags)
                                       (list "-R" "arg0=-l" "-R" "arg1=two words" "-R" "setenv=LANG=C"
                                             "-R" "chdir=/tmp" "-R" "aslr=no" "-d" *binary*))
                               (log-lines ".argv")))
                 (check "the launch runs light analysis, then reads the program counter"
                        (equal '("aa" "dr rip") (log-lines ".cmds")))
                 (check "the result opens with the loud warning and says what was launched"
                        (and (starts (format nil "debug: started ~a~%~a~%Stopped at entry. Target env: arg0=-l, arg1=two words, setenv=LANG=C, chdir=/tmp, aslr=no."
                                                      *binary* omp-re::+debug-launch-warning+)
                                              text)
                             (has (format nil "~%rip = 0x0000000000401000~%Set breakpoints (break_add), then continue or step.") text)))
                 (check "a build of the wrong bits is called out in the result"
                        (has (format nil "~%rizin build is ~d-bit but the target is ~d-bit — debugger and emulator results will follow the build's arch, not the target's. Set OMPRE_RIZIN_PATH_~d to a matching build.~%"
                                     (if (= bits 64) 32 64) bits bits)
                             text))
                 (check "the launch is not evidence"
                        (and (not (has "[evidence" text)) (null (omp-re::evidence-records session)))))
               (let ((dbg (omp-re::session-dbg session)))
                 (check "the debug process is the session's, and no static rizin was started for it"
                        (and (omp-re::rz-alive-p dbg) (null (omp-re::session-rz session))))
                 (check "the status line says a process is running under the debugger"
                        (has "debugger: enabled — a process is running under it" (re:status)))
                 (check "start again answers the one already running, and launches nothing"
                        (and (equal '("dr rip") (sent :action "start" :run '(:args ("again"))))
                             (equal (format nil "debug: already running~%rip = 0x0000000000401000")
                                    (debug-call :action "start"))
                             (eq dbg (omp-re::session-dbg session))
                             (not (member "arg0=again" (log-lines ".argv") :test #'string=))))

                 (suite "debug: every action's rizin command")
                 (dolist (case '(((:action "continue") ("dc" "dr rip"))
                                 ((:action "continue_until" :addr "entry0") ("dcu entry0" "dr rip"))
                                 ((:action "continue_to_syscall") ("dcs" "dr rip"))
                                 ((:action "continue_to_call") ("dcc" "dr rip"))
                                 ((:action "continue_to_ret") ("dcr" "dr rip"))
                                 ((:action "step") ("ds 1" "dr rip"))
                                 ((:action "step" :count 3) ("ds 3" "dr rip"))
                                 ((:action "step" :count 0) ("ds 1" "dr rip"))
                                 ((:action "step" :count 1000000000) ("ds 100000" "dr rip"))
                                 ((:action "step_over" :count 2) ("dso 2" "dr rip"))
                                 ((:action "trace_start") ("dts+"))
                                 ((:action "trace_stop") ("dts-"))
                                 ((:action "step_back" :count 2) ("dsb 2" "dr rip"))
                                 ((:action "continue_back") ("dcb" "dr rip"))
                                 ((:action "registers") ("drj"))
                                 ((:action "registers_telescope") ("drr"))
                                 ((:action "write_register" :reg "rax" :value "0x1234") ("dr rax=0x1234" "dr rax"))
                                 ((:action "read_memory" :addr "rip") ("pxj 64 @ rip"))
                                 ((:action "read_memory" :addr "rip" :size 8) ("pxj 8 @ rip"))
                                 ((:action "read_memory" :addr "rip" :size 99999) ("pxj 4096 @ rip"))
                                 ((:action "write_memory" :addr "rsp" :bytes "90 90") ("wx 9090 @ rsp" "p8 2 @ rsp"))
                                 ((:action "disassemble") ("dr rip" "pdj 16 @ 0x0000000000401000"))
                                 ((:action "disassemble" :addr "main" :count 3) ("pdj 3 @ main"))
                                 ((:action "resolve_symbol" :name "system") ("dmi system"))
                                 ((:action "resolve_symbol" :lib "libc.so.6" :name "system") ("dmi libc.so.6 system"))
                                 ((:action "break_add" :addr "entry0") ("db @ entry0" "dblj"))
                                 ((:action "break_add_hw" :addr "main") ("dbH @ main" "dblj"))
                                 ((:action "break_remove" :addr "entry0") ("db- @ entry0" "dblj"))
                                 ((:action "break_list") ("dblj"))
                                 ((:action "break_enable" :addr "entry0") ("dbe @ entry0" "dblj"))
                                 ((:action "break_disable" :addr "entry0") ("dbd @ entry0" "dblj"))
                                 ((:action "break_condition" :addr "entry0" :condition "rax>0") ("dbC 'rax>0' @ entry0" "dblj"))
                                 ((:action "break_condition" :addr "entry0" :condition "a;!id 'x'") ("dbC 'a;!id \\'x\\'' @ entry0" "dblj"))
                                 ((:action "watch_add" :addr "rsp") ("dbw rw @ rsp" "dblj"))
                                 ((:action "watch_add" :addr "rsp" :perm "W" :size 4) ("dbw w 4 @ rsp" "dblj"))
                                 ((:action "watch_add" :addr "rsp" :perm "r" :size 100) ("dbw r 8 @ rsp" "dblj"))
                                 ((:action "backtrace") ("dbtj"))
                                 ((:action "maps") ("dmj"))
                                 ((:action "modules") ("dmmj"))
                                 ((:action "libraries") ("dmij"))
                                 ((:action "sections") ("dmSj"))
                                 ((:action "processes") ("dpj"))
                                 ((:action "threads") ("dpTj"))
                                 ((:action "fds") ("ddlj"))
                                 ((:action "signals") ("dklj"))
                                 ((:action "windows") ("dW"))
                                 ((:action "heaps") ("dmhwj"))
                                 ((:action "heap_blocks") ("dmhwbj"))
                                 ((:action "heap_blocks" :addr "0x1000") ("dmhwbj @ 0x1000"))
                                 ((:action "heap_arenas") ("dmhga"))
                                 ((:action "heap_chunks") ("dmhgj"))
                                 ((:action "heap_chunks" :addr "0x1000") ("dmhgj @ 0x1000"))
                                 ((:action "heap_bins") ("dmhgd"))
                                 ((:action "heap_bins" :addr "tcache") ("dmhgd tcache"))
                                 ((:action "heap_bins" :addr "main") ("dmhgd"))))
                   (destructuring-bind (arguments commands) case
                     (check (format nil "~{~(~a~) ~s~^ ~} sends ~{~a~^ ; ~}" arguments commands)
                            (equal commands (apply #'sent arguments)))))

                 (suite "debug: what the actions answer")
                 (check "a resume answers what rizin said, or (resumed), then the program counter"
                        (equal (format nil "debug: continue~%(resumed)~%rip = 0x0000000000401000")
                               (debug-call :action "continue")))
                 (check "a step answers the program counter under its count"
                        (equal (format nil "debug: step 3~%rip = 0x0000000000401000")
                               (debug-call :action "step" :count 3)))
                 (check "a read with nothing to show says so in the engine's words"
                        (and (equal (format nil "debug: maps~%(no maps)") (debug-call :action "maps"))
                             (equal (format nil "debug: modules~%(no modules — continue past the loader to see them)")
                                    (debug-call :action "modules"))
                             (equal (format nil "debug: heap_bins tcache~%(no bin info — continue until glibc is mapped and has allocated)")
                                    (debug-call :action "heap_bins" :addr "tcache"))
                             (equal (format nil "debug: resolve_symbol libc system~%(no match — the library may not be mapped yet; continue past the loader)")
                                    (debug-call :action "resolve_symbol" :lib "libc" :name "system"))))
                 (check "a breakpoint action answers the list as it now stands"
                        (and (equal (format nil "debug: break_add entry0~%[]") (debug-call :action "break_add" :addr "entry0"))
                             (equal (format nil "debug: watch_add rw @ rsp~%[]") (debug-call :action "watch_add" :addr "rsp"))))
                 (check "write_memory reads the bytes back; write_register reads the register back"
                        (and (equal (format nil "debug: write_memory 2 bytes @ rsp~%wrote 9090; now reads deadbeef")
                                    (debug-call :action "write_memory" :addr "rsp" :bytes "9090"))
                             (equal (format nil "debug: write_register rax=7~%(set)")
                                    (debug-call :action "write_register" :reg "rax" :value "7"))))
                 (check "trace_start and trace_stop say what to do next"
                        (and (equal (format nil "debug: trace_start~%trace session started~%Step backward with step_back / continue_back; stop recording with trace_stop.")
                                    (debug-call :action "trace_start"))
                             (equal "debug: trace_stop — trace session ended" (debug-call :action "trace_stop"))))
                 (check "none of it is evidence" (null (omp-re::evidence-records session)))

                 (suite "debug: refusals that guard rizin's pipe")
                 (check "an address is validated like every other tool's"
                        (and (equal "omp-re: invalid address or expression: \"rip;id\""
                                    (sent-nothing-p :action "read_memory" :addr "rip;id"))
                             (has "invalid address" (sent-nothing-p :action "break_add" :addr "main @@ sym.*"))
                             (has "invalid address" (sent-nothing-p :action "continue_until" :addr "$(id)"))
                             (has "invalid address" (sent-nothing-p :action "heap_bins" :addr "tcache;!id"))
                             (has "invalid address" (sent-nothing-p :action "registers" :addr "a b"))))
                 (check "an action that needs an address says so"
                        (every (lambda (action)
                                 (equal (format nil "omp-re: debug ~a needs addr" action)
                                        (sent-nothing-p :action action)))
                               '("continue_until" "read_memory" "dump_memory" "write_memory" "break_add"
                                 "break_add_hw" "break_remove" "break_enable" "break_disable"
                                 "break_condition" "break_command" "watch_add")))
                 (check "write_register refuses a bad name and a bad value before touching rizin"
                        (and (equal "omp-re: debug: bad register name \"rax;id\""
                                    (sent-nothing-p :action "write_register" :reg "rax;id" :value "1"))
                             (equal "omp-re: debug: bad register value \"0xzz\" — use decimal or 0x hex"
                                    (sent-nothing-p :action "write_register" :reg "rax" :value "0xzz"))
                             (has "bad register value" (sent-nothing-p :action "write_register" :reg "rax" :value "1;!id"))
                             (equal "omp-re: debug write_register needs reg and value"
                                    (sent-nothing-p :action "write_register" :reg "rax"))))
                 (check "write_memory refuses non-hex and odd-length bytes"
                        (and (has "bad hex bytes \"zz\"" (sent-nothing-p :action "write_memory" :addr "rsp" :bytes "zz"))
                             (has "bad hex bytes \"9\"" (sent-nothing-p :action "write_memory" :addr "rsp" :bytes "9"))
                             (has "bad hex bytes" (sent-nothing-p :action "write_memory" :addr "rsp" :bytes "90;!id"))
                             (equal "omp-re: debug write_memory needs bytes (hex)"
                                    (sent-nothing-p :action "write_memory" :addr "rsp"))))
                 (check "watch_add refuses an access that is not r, w or rw"
                        (equal "omp-re: debug: watch perm must be r, w, or rw (got \"x;id\")"
                               (sent-nothing-p :action "watch_add" :addr "rsp" :perm "x;id")))
                 (check "resolve_symbol refuses a name that is not one, and needs a name or a lib"
                        (and (equal "omp-re: debug: bad symbol/library name \"system;id\""
                                    (sent-nothing-p :action "resolve_symbol" :name "system;id"))
                             (has "bad symbol/library name" (sent-nothing-p :action "resolve_symbol" :lib "libc ~x" :name "system"))
                             (equal "omp-re: debug resolve_symbol needs a name (and optionally a lib)"
                                    (sent-nothing-p :action "resolve_symbol"))))
                 (check "break_condition needs a condition, and refuses a line break in one"
                        (and (equal "omp-re: debug break_condition needs condition"
                                    (sent-nothing-p :action "break_condition" :addr "entry0"))
                             (equal "omp-re: invalid argument: contains a newline or NUL"
                                    (sent-nothing-p :action "break_condition" :addr "entry0"
                                                    :condition (format nil "rax>0~%!id")))))
                 (check "break_command needs a command"
                        (equal "omp-re: debug break_command needs command"
                               (sent-nothing-p :action "break_command" :addr "main")))
                 (cond
                   ((not *rizin*)
                    (format t "  SKIPPED — the on-hit policy reads rizin's own catalog, and there is no rizin~%"))
                   (t
                    (check "break_command refuses a shell escape, a write, a pipe and a second command"
                           (and (has "omp-re: debug break_command: omp-re: break_command:"
                                     (sent-nothing-p :action "break_command" :addr "main" :command "!id"))
                                (every (lambda (command)
                                         (let ((message (sent-nothing-p :action "break_command" :addr "main"
                                                                        :command command)))
                                           (or (has "not a read-only on-hit command" message)
                                               (has "is not allowed in an on-hit command" message))))
                                       '("!id" "w hello" "wx 9090" "drj;!id" "drj | sh" "drj > /tmp/x"
                                         "drj @@ sym.*" "e cfg.sandbox=false" "o /etc/passwd" "#!pipe id"
                                         "dmj~x" "`!id`" "$(id)"))))
                    (check "break_command refuses debugger control: an on-hit command logs, it never drives"
                           (every (lambda (command)
                                    (has (format nil "omp-re: debug break_command: omp-re: break_command: ~s is not a read-only on-hit command. Allowed: read-only debugger state"
                                                 (subseq command 0 (position #\Space command)))
                                         (sent-nothing-p :action "break_command" :addr "main" :command command)))
                                  '("dc" "ds 5" "dk 9" "db main" "dts+" "doo" "dx 9090")))
                    (check "break_command refuses a register assignment through the read form"
                           (has "omp-re: break_command: \"dr\" with `=` would assign/select (a write); use the bare read form to log state"
                                (sent-nothing-p :action "break_command" :addr "main" :command "dr rax=0")))
                    (check "break_command refuses an empty command"
                           (has "omp-re: break_command: empty command"
                                (sent-nothing-p :action "break_command" :addr "main" :command "  ")))
                    (check "break_command lets a vetted debugger-state read and a static read through, as written"
                           (and (equal '("dbc drj @ main" "dblj")
                                       (sent :action "break_command" :addr "main" :command " drj "))
                                (equal '("dbc dmj @ main" "dblj")
                                       (sent :action "break_command" :addr "main" :command "dmj"))
                                (equal '("dbc px 16 @ main" "dblj")
                                       (sent :action "break_command" :addr "main" :command "px 16"))))))

                 (suite "debug: what is written to disk")
                 (check "dump_memory refuses a size that is not positive, and one past 16 MiB"
                        (and (equal "omp-re: debug dump_memory needs a positive size (bytes)"
                                    (sent-nothing-p :action "dump_memory" :addr "rip"))
                             (has "needs a positive size" (sent-nothing-p :action "dump_memory" :addr "rip" :size 0))
                             (has "needs a positive size" (sent-nothing-p :action "dump_memory" :addr "rip" :size -4))
                             (equal "omp-re: debug dump_memory: 16777217 bytes exceeds the 16777216-byte limit; dump a smaller region"
                                    (sent-nothing-p :action "dump_memory" :addr "rip" :size 16777217))))
                 (check "dump_memory refuses a name that would leave the output directory, before any read"
                        (every (lambda (file)
                                 (ignore-errors (delete-file (concatenate 'string *stand-in-log* ".cmds")))
                                 (let ((message (debug-refusal :action "dump_memory" :addr "rip" :size 16 :file file)))
                                   (and (has "invalid output filename" message)
                                        (notany (lambda (command) (starts "p8" command))
                                                (log-lines ".cmds")))))
                               '("../escape.bin" "/etc/cron.d/x" "a/b.bin" ".." "sub\\x.bin" "x y.bin" "~root")))
                 (check "and nothing was written outside it"
                        (and (not (probe-file (merge-pathnames "escape.bin" *scratch*)))
                             (null (uiop:directory-files output))))
                 (let* ((text (progn (ignore-errors (delete-file (concatenate 'string *stand-in-log* ".cmds")))
                                     (debug-call :action "dump_memory" :addr "rip" :size 4 :file "entry.bin")))
                        (path (concatenate 'string output "entry.bin")))
                   (check "dump_memory resolves the base, reads over the pipe, and writes the file in the output directory"
                          (and (equal '("?v rip" "p8 4 @ rip+0") (log-lines ".cmds"))
                               (equal (format nil "debug: dump_memory 4 bytes @ rip~%wrote 4 bytes to ~a~%sha256: ~a~%first bytes: deadbeef"
                                              path
                                              "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953")
                                      text)))
                   (check "the file holds exactly those bytes"
                          (equalp #(#xde #xad #xbe #xef)
                                  (with-open-file (in path :element-type '(unsigned-byte 8))
                                    (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
                                      (read-sequence bytes in)
                                      bytes)))))
                 (check "a short read is said, and the generated name carries the base and the size"
                        (let ((text (debug-call :action "dump_memory" :addr "rip" :size 8)))
                          (and (has (format nil "wrote 4 bytes (short read: 8 requested, memory ended) to ~adump_401000_8.bin" output)
                                    text)
                               (probe-file (concatenate 'string output "dump_401000_8.bin")))))
                 (check "trace_save makes the folder in the output directory and hands rizin its quoted path"
                        (let ((commands (sent :action "trace_save" :file "t_session")))
                          (and (equal (list (format nil "dtst '~at_session'" output)) commands)
                               (uiop:directory-exists-p (concatenate 'string output "t_session/"))
                               (equal (format nil "debug: trace_save t_session~%wrote the trace session to ~at_session~%Restore it later with trace_load file=\"t_session\"."
                                              output)
                                      (debug-call :action "trace_save" :file "t_session")))))
                 (check "trace_save with no name generates one, inside the output directory"
                        (let ((command (first (sent :action "trace_save"))))
                          (and (starts (format nil "dtst '~atrace_" output) command)
                               (ppcre:scan "trace_[0-9]+'$" command))))
                 (check "trace_save and trace_load refuse a name that would leave the output directory"
                        (and (has "invalid output filename" (sent-nothing-p :action "trace_save" :file "../escape"))
                             (has "invalid output filename" (sent-nothing-p :action "trace_save" :file "/tmp/escape"))
                             (has "invalid output filename" (sent-nothing-p :action "trace_load" :file "../escape"))
                             (not (probe-file (merge-pathnames "escape/" *scratch*)))))
                 (check "trace_load needs a name, and one that was saved"
                        (and (equal "omp-re: debug trace_load needs file (a trace directory from a prior trace_save)"
                                    (sent-nothing-p :action "trace_load"))
                             (equal (format nil "omp-re: debug trace_load: no saved trace at ~anope_not_saved (save one first with trace_save)"
                                            output)
                                    (sent-nothing-p :action "trace_load" :file "nope_not_saved"))
                             (not (probe-file (concatenate 'string output "nope_not_saved/")))))
                 (check "what rizin says on stderr for a load fails the call, in its words"
                        (equal "omp-re: debug trace_load: ERROR: stand-in has no session to load"
                               (debug-refusal :action "trace_load" :file "t_session")))

                 (suite "debug: stop, and never a respawn")
                 (check "stop kills the debuggee, then ends the debug process"
                        (and (equal '("dk 9") (sent :action "stop"))
                             (null (omp-re::session-dbg session))
                             (process-gone-p (omp-re::rz-process dbg))))
                 (check "stop is idempotent"
                        (and (equal "debug: no debug session to stop" (debug-call :action "stop"))
                             (equal "debug: no debug session to stop" (debug-call :action "stop"))))
                 (check "after stop an action is refused; it does not start the program again"
                        (and (has "no debug session" (sent-nothing-p :action "continue"))
                             (null (omp-re::session-dbg session)))))

               (check "a fresh start after stop says stopped when stopped"
                      (and (has "debug: started" (debug-call :action "start"))
                           (equal "debug: stopped — process killed and debug session closed"
                                  (debug-call :action "stop"))))

               ;; The debug process dies on its own. Respawning it would run the program again.
               (debug-call :action "start")
               (let ((dbg (omp-re::session-dbg session)))
                 (ignore-errors (delete-file (concatenate 'string *stand-in-log* ".argv")))
                 (sb-ext:process-kill (omp-re::rz-process dbg) 9)
                 (process-gone-p (omp-re::rz-process dbg))
                 (check "a debug process that died is not respawned by the next action"
                        (and (has "no debug session" (debug-refusal :action "registers"))
                             (has "no debug session" (debug-refusal :action "continue"))
                             (null (log-lines ".argv"))))
                 (check "nor does the status line claim one is running"
                        (not (has "a process is running under it" (re:status))))
                 (check "and stop then has nothing to stop"
                        (equal "debug: no debug session to stop" (debug-call :action "stop"))))

               (suite "debug: an attach, against a stand-in")
               (let ((text (debug-call :action "start" :attach '(:pid 4242))))
                 (check "attaching to a pid spawns rizin -d <pid> <binary>: no directives, no load flags"
                        (equal (append (shared-flags) (list "-d" "4242" *binary*)) (log-lines ".argv")))
                 (check "the result says what is controlled, with the warning and no bits note"
                        (and (equal (format nil "debug: attached to PID 4242~%~a~%Controlling the live process (attached to PID 4242), symbols from ~a.~%rip = 0x0000000000401000~%Set breakpoints (break_add), then continue or step."
                                            omp-re::+debug-launch-warning+ *binary*)
                                    text)
                             (not (has "rizin build is" text)))))
               (debug-call :action "stop")
               (let ((text (debug-call :action "start" :attach '(:remote "gdb://127.0.0.1:1234"))))
                 (check "a remote stub is -d <uri> <binary>"
                        (and (equal (append (shared-flags) (list "-d" "gdb://127.0.0.1:1234" *binary*))
                                    (log-lines ".argv"))
                             (starts "debug: connected to gdb://127.0.0.1:1234" text))))
               (debug-call :action "stop")

               (suite "debug: a raw target, against a stand-in")
               (setf (omp-re::session-load-options session) (omp-re:obj "arch" "x86" "bits" bits "map" "0x400000"))
               (debug-call :action "start" :run '(:args ("x")))
               (check "a launch loads the target as the static session did: load flags, then -R, then -d"
                      (equal (append (shared-flags)
                                     (list "-a" "x86" "-b" (princ-to-string bits) "-m" "0x400000"
                                           "-R" "arg0=x" "-d" *binary*))
                             (log-lines ".argv")))
               (debug-call :action "stop")
               (debug-call :action "start" :attach '(:pid 77))
               (check "an attach drops them: the target brings its own arch and memory"
                      (equal (append (shared-flags) (list "-d" "77" *binary*)) (log-lines ".argv")))
               (debug-call :action "stop")
               (setf (omp-re::session-load-options session) nil)

               (suite "debug: shutdown")
               (debug-call :action "start")
               (let ((dbg (omp-re::session-dbg session)))
                 (omp-re::reap-idle-sessions 0)
                 (check "an idle session's debug process is closed, and not brought back"
                        (and (process-gone-p (omp-re::rz-process dbg))
                             (null (omp-re::session-dbg session))
                             (has "no debug session" (debug-refusal :action "registers"))))))

             ;; Two sessions each with a debug process; the cell stops.
             (let ((other (fresh-session)))
               (in-session (id) (debug-call :action "start"))
               (in-session (other)
                 (setf (omp-re::session-binary-path (omp-re:find-session other)) *binary*)
                 (debug-call :action "start"))
               (let ((processes (list (omp-re::session-dbg session)
                                      (omp-re::session-dbg (omp-re:find-session other)))))
                 (check "two sessions each own a debug process"
                        (and (every #'omp-re::rz-alive-p processes)
                             (not (eq (first processes) (second processes)))))
                 (stop-running-cell)
                 (check "stopping the cell leaves no debug process alive"
                        (every (lambda (rz) (process-gone-p (omp-re::rz-process rz))) processes))))))))))

  ;;; --- one real launch ----------------------------------------------------------------
  ;;; The test binary, a benign system program, is launched under rizin's debugger and held at its entry. Where the
  ;;; sandbox forbids ptrace the launch fails, which must be a clean refusal.

  (suite "debug: a real debug session")
  (cond
    ((not *rizin*)
     (format t "  SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*))
    ((not (member *binary* '("/bin/ls" "/bin/true") :test #'string=))
     (format t "  SKIPPED — only /bin/ls or /bin/true is ever launched here, not ~a~%" *binary*))
    (t
     (with-environment ("OMPRE_OUTPUT_DIR" output)
       (with-cell (:debugger t)
         (let* ((id (fresh-session))
                (session (in-session (id) (omp-re:find-session id)))
                (started nil)
                (rizin-pid nil)
                (debuggees '()))
           (in-session (id)
             (setf (omp-re::session-binary-path session) *binary*)
             (multiple-value-bind (text failed)
                 (omp-re::call-tool session "rizin_debug" (omp-re:obj "action" "start"))
               (cond
                 (failed
                  (format t "  NOTE  the launch failed here (ptrace not permitted?): ~a~%" text)
                  (check "a launch that fails is reported in words, and leaves no debug session"
                         (and (starts "omp-re: " text)
                              (null (omp-re::session-dbg session))
                              (has "no debug session" (debug-refusal :action "registers")))))
                 (t
                  (setf started t
                        rizin-pid (rizin-pid (omp-re::session-dbg session))
                        debuggees (children-of rizin-pid))
                  (check "start launches the process with the loud warning and a stopped program counter"
                         (and (has omp-re::+debug-launch-warning+ text)
                              (has "Stopped at entry." text)
                              (ppcre:scan "(?m)^\\w+ = 0x[0-9a-f]+$" text)
                              (omp-re::rz-alive-p (omp-re::session-dbg session))))
                  (check "the debuggee is a child of the debug rizin" (and debuggees t))
                  (check "a breakpoint at the entry, and continue reaches it"
                         (and (has "\"enabled\":true" (debug-call :action "break_add" :addr "entry0"))
                              (ppcre:scan "(?m)^\\w+ = 0x[0-9a-f]+$" (debug-call :action "continue"))))
                  (check "registers, backtrace and maps read the stopped process"
                         (and (ppcre:scan "\"(rip|pc)\":\\d+" (debug-call :action "registers"))
                              (has "debug: backtrace" (debug-call :action "backtrace"))
                              (has (file-namestring *binary*) (debug-call :action "maps"))))
                  (check "a step moves the program counter"
                         (let ((before (debug-call :action "registers")))
                           (debug-call :action "step" :count 1)
                           (string/= before (debug-call :action "registers"))))
                  (check "read_memory answers bytes, and disassemble live instructions"
                         (and (ppcre:scan "(?m)^\\[.*\\]$" (debug-call :action "read_memory" :addr "entry0" :size 8))
                              (has "\"opcode\"" (debug-call :action "disassemble" :count 3))))
                  (check "dump_memory writes live memory to the output directory, with its size and hash"
                         (let* ((text (debug-call :action "dump_memory" :addr "entry0" :size 64 :file "live.bin"))
                                (path (concatenate 'string output "live.bin")))
                           (and (has (format nil "wrote 64 bytes to ~a" path) text)
                                (has (omp-re::sha256-file path) text)
                                (= 64 (with-open-file (in path :element-type '(unsigned-byte 8))
                                        (file-length in))))))
                  (check "an on-hit command is installed when read-only, refused when not"
                         (and (has "drj" (debug-call :action "break_command" :addr "entry0" :command "drj"))
                              (has "not a read-only on-hit command"
                                   (debug-refusal :action "break_command" :addr "entry0" :command "dc"))))
                  (check "a condition's `>' stays text"
                         (has "rax>0" (debug-call :action "break_condition" :addr "entry0" :condition "rax>0")))
                  (check "stop kills the debuggee and ends the debug session"
                         (and (has "stopped" (debug-call :action "stop"))
                              (null (omp-re::session-dbg session))
                              (pid-gone-p rizin-pid)
                              (every #'pid-gone-p debuggees)))
                  (check "stop again has nothing to stop"
                         (has "no debug session" (debug-call :action "stop")))))))
           (when started
             ;; Once more, left running: the cell's stop must end it.
             (in-session (id)
               (debug-call :action "start")
               (setf rizin-pid (rizin-pid (omp-re::session-dbg session))
                     debuggees (children-of rizin-pid)))
             (stop-running-cell)
             ;; The debuggee is killed through rizin first, then rizin and
             ;; what is left of its children.
             (check "stopping the cell ends the debug rizin, and no process of the session is left"
                    (and debuggees (pid-gone-p rizin-pid) (every #'pid-gone-p debuggees))))))))))
