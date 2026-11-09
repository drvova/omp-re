;;;; debug.lisp --- the opt-in debugger: the one tool that runs the sample.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Ported from omp-re's extensions/re/tools-debug.ts (the rizin_debug tool),
;;;; the debug half of runtime.ts (startDebug / stopDebug / requireDebug) and
;;;; the debug half of rizin.ts (spawnDebug's argv, debugTimeoutMs, and the
;;;; build-bits check: parseRizinVersionArch, rizinBuildBits,
;;;; rizinBitsMismatch).
;;;;
;;;; Dynamic analysis is a bridge to rizin's debugger, which LAUNCHES the
;;;; target process so it can be stepped and inspected while it runs. It is
;;;; the one capability that executes the sample, so it is off unless the
;;;; operator switched it on (the re section's debugger setting, or
;;;; OMPRE_ENABLE_DEBUGGER): until then the tool is not offered at all. It
;;;; runs in a rizin of its own, `rizin -q0 ... -d', kept apart from the
;;;; static session, which only ever reads the file. That process is started
;;;; by action `start' and by nothing else: a debug rizin that died is never
;;;; respawned on its own, because respawning it would silently run the
;;;; program again. `stop' ends it, and so does the session's shutdown.
;;;;
;;;; It is a plain debugger — breakpoints, stepping, registers, memory,
;;;; backtrace — with no facility for evading detection or hiding the
;;;; debuggee. Every value the model supplies is checked before it reaches
;;;; rizin's pipe, a breakpoint's on-hit command passes the read-only on-hit
;;;; policy, and the two things written to disk (a memory dump, a trace
;;;; session) go to the output directory under a bare name. Run untrusted
;;;; samples only in an isolated, disposable environment; see SECURITY.md.

(in-package #:nodecode-re)

(defparameter +max-dump-bytes+ (* 16 1024 1024)
  "The largest memory dump dump_memory pulls over the command pipe (16 MiB);
a bigger region is refused with its size, so the caller can narrow it.")

(defparameter +dump-chunk+ #x10000
  "Bytes a `p8' read when dumping, so one huge command never crosses the pipe.")

(defparameter +debug-launch-warning+
  "⚠ The target is now RUNNING under a debugger on this machine. Only debug untrusted samples in an isolated, disposable VM or container."
  "What a launch says first: neither the model nor the transcript should
miss that a real process started.")

(defparameter +debug-actions+
  '("start" "continue" "continue_until" "continue_to_syscall" "continue_to_call" "continue_to_ret"
    "step" "step_over" "trace_start" "trace_stop" "trace_save" "trace_load" "step_back"
    "continue_back" "registers" "registers_telescope" "write_register" "read_memory" "dump_memory"
    "write_memory" "disassemble" "resolve_symbol" "break_add" "break_add_hw" "break_remove"
    "break_list" "break_enable" "break_disable" "break_condition" "break_command" "watch_add"
    "backtrace" "maps" "modules" "libraries" "sections" "processes" "threads" "fds" "signals"
    "windows" "heaps" "heap_blocks" "heap_arenas" "heap_chunks" "heap_bins" "stop"))

(defun debug-seconds ()
  "The budget for one step or continue: a resumed process runs until it hits
a breakpoint, signals or exits, and one that never returns — blocked on
input — is killed at this bound."
  (let ((ms (ignore-errors (parse-integer (or (env "OMPRE_DEBUG_TIMEOUT_MS") "")))))
    (if (and ms (plusp ms)) (/ ms 1000) 60)))

;;; --- what may reach rizin's pipe -------------------------------------------------------

(defun validate-reg-name (reg)
  "A register name for `dr <reg>=...'."
  (unless (js-scan "^[A-Za-z][A-Za-z0-9_]*$" reg)
    (fail "omp-re: debug: bad register name ~a" (js-string reg)))
  reg)

(defun validate-reg-value (value)
  "A register value for `dr <reg>=<value>': decimal or 0x hex."
  (unless (js-scan "^0x[0-9a-fA-F]+$|^[0-9]+$" value)
    (fail "omp-re: debug: bad register value ~a — use decimal or 0x hex" (js-string value)))
  value)

(defun validate-debug-hex (bytes)
  "Hex bytes for `wx <bytes>': an even number of hex digits, blanks dropped."
  (let ((hex (ppcre:regex-replace-all "\\s+" bytes "")))
    (unless (and (js-scan "^[0-9a-fA-F]+$" hex) (evenp (length hex)))
      (fail "omp-re: debug: bad hex bytes ~a — an even number of hex digits, e.g. 9090 or 4889e5"
            (js-string bytes)))
    hex))

(defun validate-symbol-query (name)
  "A library or symbol name for `dmi': the dots and versions of a name like
libc.so.6 pass."
  (unless (js-scan "^[A-Za-z0-9_.+-]+$" name)
    (fail "omp-re: debug: bad symbol/library name ~a" (js-string name)))
  name)

(defun validate-watch-perm (perm)
  "A watchpoint's access for `dbw <perm>': r, w or rw, rw when not given."
  (let ((lowered (string-downcase (or perm "rw"))))
    (unless (member lowered '("r" "w" "rw") :test #'string=)
      (fail "omp-re: debug: watch perm must be r, w, or rw (got ~a)" (js-string perm)))
    lowered))

(defun clamp-int (value fallback max)
  "VALUE as a whole number between 1 and MAX; FALLBACK when it was not given."
  (if (realp value)
      (max 1 (min (floor value) max))
      fallback))

(defun json-object-p (value)
  (hash-table-p value))

(defun json-array-p (value)
  (and (vectorp value) (not (stringp value))))

(defun build-debug-target (attach)
  "The `-d <target>' string an attach object spells: a pid (\"1234\") or a
remote stub's URI (gdb://host:port, windbg://...); NIL when ATTACH is :ABSENT
and the open binary is to be launched. Exactly one of pid and remote. The
URI reaches rizin through argv, with no shell, but a flag-shaped or spaced
value is still refused here, in words."
  (cond ((eq attach :absent) nil)
        ((not (json-object-p attach))
         (fail "omp-re: debug: attach must be an object with a pid or remote"))
        (t
         (multiple-value-bind (pid has-pid) (gethash "pid" attach)
           (multiple-value-bind (remote has-remote) (gethash "remote" attach)
             (when (eq (and has-pid t) (and has-remote t))
               (fail "omp-re: debug: attach needs exactly one of pid or remote"))
             (cond (has-pid
                    (unless (and (realp pid) (= pid (floor pid)) (> pid 0))
                      (fail "omp-re: debug: attach.pid must be a positive integer (got ~a)"
                            (json-encode pid)))
                    (format nil "~d" (floor pid)))
                   (t
                    (unless (and (stringp remote)
                                 (js-scan "^(gdb|windbg)://[A-Za-z0-9._:\\-[\\]/]+$" remote))
                      (fail "omp-re: debug: attach.remote must be a gdb:// or windbg:// URI (got ~a)"
                            (json-encode remote)))
                    remote)))))))

(defun build-run-directives (run)
  "The rz-run directives a run object spells for the debug launch, which
rizin loads as `-R directive' flags; NIL when RUN is :ABSENT or says
nothing. A directive is one argv element, so a value with spaces needs no
quoting; a line break would break the profile format and is refused
everywhere. A `!' stdio target runs a shell command on this machine and
stays out of the contract."
  (cond
    ((eq run :absent) nil)
    ((not (json-object-p run))
     (fail "omp-re: debug: run must be an object of rz-run settings"))
    (t
     (let ((directives '()))
       (flet ((clean (key value)
                (when (find-if (lambda (char) (member char '(#\Return #\Newline))) value)
                  (fail "omp-re: debug: run.~a must not contain line breaks" key))
                value)
              (add (directive) (push directive directives)))
         (maphash
          (lambda (key raw)
            (cond
              ((string= key "args")
               (unless (and (json-array-p raw) (every #'stringp raw))
                 (fail "omp-re: debug: run.args must be a list of strings"))
               (when (> (length raw) 64)
                 (fail "omp-re: debug: run.args supports at most 64 arguments"))
               (loop for argument across raw
                     for index from 0
                     do (add (format nil "arg~d=~a" index (clean key argument)))))
              ((string= key "env")
               (unless (json-object-p raw)
                 (fail "omp-re: debug: run.env must be an object"))
               (maphash (lambda (name value)
                          (unless (js-scan "^[A-Za-z_][A-Za-z0-9_]*$" name)
                            (fail "omp-re: debug: run.env: bad variable name ~a" (js-string name)))
                          (unless (stringp value)
                            (fail "omp-re: debug: run.env.~a must be a string" name))
                          (add (format nil "setenv=~a=~a" name (clean key value))))
                        raw))
              ((string= key "cwd")
               (unless (stringp raw)
                 (fail "omp-re: debug: run.cwd must be a string"))
               (add (format nil "chdir=~a" (clean key raw))))
              ((member key '("stdin" "stdout" "stderr") :test #'string=)
               (unless (stringp raw)
                 (fail "omp-re: debug: run.~a must be a file path" key))
               (when (starts-with "!" raw)
                 (fail "omp-re: debug: run.~a does not accept command targets" key))
               (add (format nil "~a=~a" key (clean key raw))))
              ((string= key "input")
               (unless (stringp raw)
                 (fail "omp-re: debug: run.input must be a string"))
               (when (> (length raw) 65536)
                 (fail "omp-re: debug: run.input is limited to 64 KiB"))
               (add (format nil "input=~a" (clean key raw))))
              ((string= key "aslr")
               (unless (member raw '(t nil))
                 (fail "omp-re: debug: run.aslr must be true or false"))
               (add (format nil "aslr=~:[no~;yes~]" raw)))
              ((member key '("maxstack" "maxfd" "maxproc" "timeout") :test #'string=)
               (unless (and (realp raw) (> raw 0))
                 (fail "omp-re: debug: run.~a must be a positive number" key))
               (add (format nil "~a=~d" key (floor raw))))
              (t
               (fail "omp-re: debug: run.~a is not a supported rz-run setting (args, env, cwd, stdin, stdout, stderr, input, aslr, maxstack, maxfd, maxproc, timeout)"
                     key))))
          run))
       (nreverse directives)))))

;;; --- the debug process a session owns --------------------------------------------------

(defun debug-argv (binary-path &key load run-directives target)
  "Everything after the shared flags on the debug rizin's command line. By
default `<load flags> -R <directive>... -d <binary>', which LAUNCHES the
target stopped at its entry; each directive is one argv element before -d,
with no shell between. With TARGET — a pid or a remote stub's URI — it is
`-d <target> <binary>': rizin attaches instead, the open binary serves as
the symbol source, and the launch directives and raw-load flags are dropped,
there being no new local process to configure."
  (if target
      (list "-d" target binary-path)
      (append (build-load-flags load)
              (loop for directive in run-directives append (list "-R" directive))
              (list "-d" binary-path))))

(defun start-debug (&key run-directives target (session *session*))
  "SESSION's debug rizin, launched now unless one is already running. This
is the one place the engine drives a live process."
  (let ((existing (session-dbg session)))
    (if (rz-alive-p existing)
        existing
        (let* ((binary-path (require-binary session))
               ;; A pid or a remote stub brings its own arch and memory: the
               ;; raw-load options and the bits check are about launching
               ;; the open file. A launch loads the target the way the
               ;; static session did, so stepping agrees with the analysis.
               (load (and (not target) (session-load-options session)))
               (rizin-path (resolve-rizin-path binary-path (and load (jget load "bits")))))
          (unless target
            ;; The debugger executes the process: a build of the wrong bits
            ;; gives wrong-arch semantics, which must not pass as results.
            (let ((mismatch (rizin-bits-mismatch binary-path)))
              (when mismatch (warn "omp-re: ~a" mismatch))))
          (when existing (rz-close existing))
          ;; Light `aa', not `aaa': symbols resolve and the launch stays quick.
          (setf (session-dbg session)
                (spawn-rz rizin-path binary-path
                          :debug-argv (debug-argv binary-path :load load
                                                              :run-directives run-directives
                                                              :target target)
                          :analysis "aa"))))))

(defun stop-debug (&optional (session *session*))
  "End SESSION's debug rizin, leaving the static one alone => whether there
was one to end."
  (let ((dbg (session-dbg session)))
    (setf (session-dbg session) nil)
    (cond ((rz-alive-p dbg) (rz-close dbg) t)
          (t (rz-close dbg) nil))))

(defun require-debug (&optional (session *session*))
  "SESSION's running debug rizin, or the refusal that says to start one.
Nothing is launched here: a debug session begins with `start' and only there."
  (let ((dbg (session-dbg session)))
    (unless (rz-alive-p dbg)
      (fail "omp-re: no debug session — run the debug tool with action 'start' first (it launches the process)."))
    dbg))

;;; --- reading the live process ----------------------------------------------------------

(defun program-counter (dbg)
  "The debuggee's program counter as a `<reg> = 0x...' line. `dr rip' is the
x86-64 name; `dr PC' is rizin's alias on every arch, tried second. Empty
when neither answers — the process already exited."
  (let ((rip (trimmed (rz-cmd dbg "dr rip"))))
    (if (plusp (length rip))
        rip
        (trimmed (rz-cmd dbg "dr PC")))))

(defun read-live-bytes (dbg ea size)
  "SIZE bytes of the live process at EA, read over the pipe in +DUMP-CHUNK+
pieces => the octets. A short read — an unmapped page partway — ends the
dump at what was read, which the caller reports."
  (let ((bytes (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop while (< (length bytes) size)
          do (let* ((want (min +dump-chunk+ (- size (length bytes))))
                    (hex (trimmed (rz-cmd dbg (format nil "p8 ~d @ ~a+~d" want ea (length bytes)))))
                    (count (floor (length hex) 2)))
               ;; Anything but hex, or nothing: unmapped, or the end of readable memory.
               (when (or (zerop count) (notevery (lambda (char) (digit-char-p char 16)) hex))
                 (return))
               (dotimes (index count)
                 (vector-push-extend (parse-integer hex :start (* 2 index) :end (+ 2 (* 2 index)) :radix 16)
                                     bytes (max 4096 (length bytes))))
               (when (< count want) (return))))
    (coerce bytes '(simple-array (unsigned-byte 8) (*)))))

(defun write-octets-file (path octets)
  (with-open-file (out (uiop:parse-native-namestring path)
                       :direction :output :element-type '(unsigned-byte 8)
                       :if-exists :supersede :if-does-not-exist :create)
    (write-sequence octets out))
  path)

(defun epoch-milliseconds ()
  (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
    (+ (* 1000 seconds) (floor microseconds 1000))))

(defun text-or (text fallback)
  (if (plusp (length text)) text fallback))

;;; --- the tool --------------------------------------------------------------------------

(defun object-argument (arguments name)
  "The member NAME of ARGUMENTS, which the tool takes as the text of a JSON
object, decoded; :ABSENT when it was not given. Text that is not JSON is
answered as it stands, so the builder refuses it as not an object."
  (multiple-value-bind (text present) (gethash name arguments)
    (if present
        (or (json-parse text) text)
        :absent)))

(defun debug-start (arguments)
  "Action `start': launch the open binary under the debugger, or attach."
  (let ((existing (session-dbg *session*)))
    (if (rz-alive-p existing)
        (plain-result (format nil "debug: already running~%~a" (program-counter existing)))
        (let* ((binary (require-binary))
               ;; Both builders refuse before anything starts.
               (attach (object-argument arguments "attach"))
               (run (object-argument arguments "run"))
               (target (build-debug-target attach)))
          (when (and target (not (eq run :absent)))
            (fail "omp-re: debug: attach cannot be combined with run (there is no new process to configure)"))
          (let* ((directives (build-run-directives run))
                 (dbg (start-debug :run-directives directives :target target))
                 (pc (program-counter dbg)))
            (if target
                (let ((how (if (js-scan "^\\d+$" target)
                               (format nil "attached to PID ~a" target)
                               (format nil "connected to ~a" target))))
                  (text-result (format nil "debug: ~a" how)
                               (format nil "~a~%Controlling the live process (~a), symbols from ~a.~@[~%~a~]~%Set breakpoints (break_add), then continue or step."
                                       +debug-launch-warning+ how binary (text-or pc nil))))
                ;; START-DEBUG already warned of a bits mismatch; said again
                ;; here so the text the model reads carries it.
                (text-result (format nil "debug: started ~a" binary)
                             (format nil "~a~%Stopped at entry.~@[ Target env: ~{~a~^, ~}.~]~@[~%~a~]~@[~%~a~]~%Set breakpoints (break_add), then continue or step."
                                     +debug-launch-warning+ directives (rizin-bits-mismatch binary)
                                     (text-or pc nil)))))))))

(defun debug-stop ()
  "Action `stop': kill the debuggee, then end the debug rizin."
  (let ((dbg (session-dbg *session*)))
    (when (rz-alive-p dbg)
      ;; Best effort: closing the process below ends the session regardless.
      (ignore-errors (rz-cmd dbg "dk 9" :seconds 5))))
  (plain-result (if (stop-debug)
                    "debug: stopped — process killed and debug session closed"
                    "debug: no debug session to stop")))

(defparameter +debug-reads+
  '(("registers" "drj" "(no registers)" t)
    ;; `drr' resolves each register to what it points at — a string, a
    ;; symbol, a pointer chain — which says far more than raw values.
    ("registers_telescope" "drr" "(no registers)" t)
    ("break_list" "dblj" "(no breakpoints)" t)
    ("backtrace" "dbtj" "(no backtrace)" t)
    ("maps" "dmj" "(no maps)")
    ("modules" "dmmj" "(no modules — continue past the loader to see them)")
    ("libraries" "dmij" "(no libraries)")
    ("sections" "dmSj" "(no sections)")
    ("processes" "dpj" "(no processes)")
    ("threads" "dpTj" "(no threads)")
    ("fds" "ddlj" "(no file descriptors)")
    ("signals" "dklj" "(no signal info)")
    ("windows" "dW" "(no windows)")
    ;; Windows heaps: display commands only.
    ("heaps" "dmhwj" "(no heap info)")
    ;; glibc's heap says "Can't find glibc mapped in memory" until the
    ;; loader has run and something has allocated.
    ("heap_arenas" "dmhga" "(no arenas — continue until glibc is mapped and has allocated)"))
  "The actions that are one read-only command with no parameter:
(ACTION COMMAND WHAT-TO-SAY-FOR-NOTHING NAMED), NAMED when the result is
filed under the tool's name.")

(defparameter +debug-resumes+
  '(("continue" . "dc") ("continue_to_syscall" . "dcs") ("continue_to_call" . "dcc")
    ("continue_to_ret" . "dcr"))
  "The actions that resume the debuggee until something stops it: ACTION . COMMAND.")

(defmacro action-case (action &body clauses)
  "CASE over the string ACTION; a clause is headed by one name, a list of
names, or T."
  (let ((value (gensym "ACTION")))
    `(let ((,value ,action))
       (cond ,@(mapcar (lambda (clause)
                         (destructuring-bind (names &rest body) clause
                           `(,(cond ((eq names t) t)
                                    ((stringp names) `(string= ,value ,names))
                                    (t `(member ,value ',names :test #'string=)))
                             ,@body)))
                       clauses)))))

(defun debug-action (action arguments dbg)
  "Every action but start and stop, against the running debug rizin DBG."
  (let* ((seconds (debug-seconds))
         (addr (jstring arguments "addr"))
         (ea (and addr (validate-addr addr)))
         (read (assoc action +debug-reads+ :test #'string=))
         (resume (cdr (assoc action +debug-resumes+ :test #'string=))))
    (labels ((run (command &optional (seconds +command-seconds+))
               (trimmed (rz-cmd dbg command :seconds seconds)))
             (pc () (program-counter dbg))
             (need-addr ()
               (or ea (fail "omp-re: debug ~a needs addr" action)))
             (named (header body)
               (text-result header body :tool "rizin_debug"))
             (breakpoints (header &optional (empty "(no breakpoints)"))
               (named header (text-or (run "dblj") empty)))
             (resumed (header command)
               (let ((out (run command seconds)))
                 (text-result header (format nil "~a~%~a" (text-or out "(resumed)") (pc)))))
             (steps (fallback max)
               (clamp-int (jnumber arguments "count") fallback max)))
      (cond
        (read
         (destructuring-bind (command empty &optional named) (rest read)
           (let ((header (format nil "debug: ~a" action))
                 (body (text-or (run command) empty)))
             (if named (named header body) (text-result header body)))))
        (resume
         (resumed (format nil "debug: ~a" action) resume))
        (t
         (action-case action
           ("continue_until"
            (need-addr)
            (resumed (format nil "debug: continue_until ~a" ea) (format nil "dcu ~a" ea)))
           ("step"
            (let ((n (steps 1 100000)))
              (run (format nil "ds ~d" n) seconds)
              (text-result (format nil "debug: step ~d" n) (pc))))
           ("step_over"
            (let ((n (steps 1 100000)))
              (run (format nil "dso ~d" n) seconds)
              (text-result (format nil "debug: step_over ~d" n) (pc))))
           ;; Reverse debugging: record a trace with trace_start, then step or
           ;; continue backward through it. The reverse actions answer rizin's
           ;; own error until a trace session exists.
           ("trace_start"
            (text-result "debug: trace_start"
                         (format nil "~a~%Step backward with step_back / continue_back; stop recording with trace_stop."
                                 (text-or (run "dts+" seconds) "trace session started"))))
           ("trace_stop"
            (run "dts-")
            (plain-result "debug: trace_stop — trace session ended"))
           ("trace_save"
            ;; `dtst <dir>' writes the trace session — registers, memory,
            ;; checkpoints — into a folder. The name is checked and the
            ;; folder made before rizin is touched, and the path is quoted
            ;; native: rizin makes the folders itself, and on Windows that
            ;; chokes on a forward-slash drive prefix.
            (let* ((name (or (jstring arguments "file") (format nil "trace_~d" (epoch-milliseconds))))
                   (directory (output-subdirectory name t))
                   (errors (trimmed (nth-value 1 (rz-run dbg (format nil "dtst ~a" (rz-quote directory)))))))
              (when (plusp (length errors))
                (fail "omp-re: debug trace_save: ~a" errors))
              (named (format nil "debug: trace_save ~a" name)
                     (format nil "wrote the trace session to ~a~%Restore it later with trace_load file=~a."
                             directory (js-string name)))))
           ("trace_load"
            (let ((file (jstring arguments "file")))
              (unless file
                (fail "omp-re: debug trace_load needs file (a trace directory from a prior trace_save)"))
              (let ((directory (output-subdirectory file nil)))
                (unless (or (uiop:directory-exists-p (uiop:ensure-directory-pathname
                                                      (uiop:parse-native-namestring directory)))
                            (uiop:file-exists-p (uiop:parse-native-namestring directory)))
                  (fail "omp-re: debug trace_load: no saved trace at ~a (save one first with trace_save)"
                        directory))
                (let ((errors (trimmed (nth-value 1 (rz-run dbg (format nil "dtsf ~a" (rz-quote directory)))))))
                  (when (plusp (length errors))
                    (fail "omp-re: debug trace_load: ~a" errors)))
                (named (format nil "debug: trace_load ~a" file)
                       (format nil "loaded the trace session from ~a~%Step backward with step_back / continue_back."
                               directory)))))
           ("step_back"
            (let* ((n (steps 1 100000))
                   (out (run (format nil "dsb ~d" n) seconds)))
              (text-result (format nil "debug: step_back ~d" n)
                           (format nil "~@[~a~%~]~a" (text-or out nil)
                                   (text-or (pc) "(no trace session — run trace_start first)")))))
           ("continue_back"
            (let ((out (run "dcb" seconds)))
              (text-result "debug: continue_back"
                           (format nil "~@[~a~%~]~a" (text-or out nil)
                                   (text-or (pc) "(no trace session — run trace_start first)")))))
           ("write_register"
            (unless (and (jstring arguments "reg") (jstring arguments "value"))
              (fail "omp-re: debug write_register needs reg and value"))
            (let ((reg (validate-reg-name (jstring arguments "reg")))
                  (value (validate-reg-value (jstring arguments "value"))))
              (run (format nil "dr ~a=~a" reg value))
              (named (format nil "debug: write_register ~a=~a" reg value)
                     (text-or (run (format nil "dr ~a" reg)) "(set)"))))
           ("read_memory"
            (need-addr)
            (let ((n (clamp-int (jnumber arguments "size") 64 4096)))
              (named (format nil "debug: read_memory ~d @ ~a" n ea)
                     (text-or (run (format nil "pxj ~d @ ~a" n ea)) "(no output)"))))
           ("dump_memory"
            (need-addr)
            (let ((given (jnumber arguments "size")))
              (unless (and given (> given 0))
                (fail "omp-re: debug dump_memory needs a positive size (bytes)"))
              (let ((size (floor given)))
                (when (> size +max-dump-bytes+)
                  (fail "omp-re: debug dump_memory: ~d bytes exceeds the ~d-byte limit; dump a smaller region"
                        size +max-dump-bytes+))
                ;; A concrete numeric base, so the generated name and the
                ;; reads agree even for a symbol or an expression.
                (let* ((base (text-or (run (format nil "?v ~a" ea)) ea))
                       (name (or (jstring arguments "file")
                                 (format nil "dump_~a_~d.bin" (ppcre:regex-replace "^0x" base "") size)))
                       ;; The name is checked here: a bad one is refused before any read.
                       (path (prepare-output-path name))
                       (bytes (read-live-bytes dbg ea size)))
                  (when (zerop (length bytes))
                    (fail "omp-re: debug dump_memory: read nothing at ~a (unmapped or unreadable); no file written"
                          ea))
                  (write-octets-file path bytes)
                  (named (format nil "debug: dump_memory ~d bytes @ ~a" (length bytes) ea)
                         (format nil "wrote ~d bytes~@[ (short read: ~d requested, memory ended)~] to ~a~%sha256: ~a~%first bytes: ~a"
                                 (length bytes) (and (< (length bytes) size) size) path
                                 (hex (sha256-octets bytes))
                                 (hex (subseq bytes 0 (min 32 (length bytes))))))))))
           ("write_memory"
            (need-addr)
            (unless (jstring arguments "bytes")
              (fail "omp-re: debug write_memory needs bytes (hex)"))
            (let* ((hex (validate-debug-hex (jstring arguments "bytes")))
                   (count (floor (length hex) 2)))
              (run (format nil "wx ~a @ ~a" hex ea))
              (named (format nil "debug: write_memory ~d bytes @ ~a" count ea)
                     (format nil "wrote ~a; now reads ~a" hex (run (format nil "p8 ~d @ ~a" count ea))))))
           ("disassemble"
            ;; Live memory: self-modified and unpacked code the static view cannot show.
            (let* ((n (steps 16 1024))
                   (at (or ea
                           (let* ((line (pc))
                                  (equals (position #\= line)))
                             (and equals
                                  (let ((end (position #\= line :start (1+ equals))))
                                    (text-or (trimmed (subseq line (1+ equals) end)) nil)))))))
              (named (format nil "debug: disassemble ~d~:[ @ pc~;~:* @ ~a~]" n at)
                     (text-or (run (format nil "pdj ~d~@[ @ ~a~]" n at)) "(no output)"))))
           ("resolve_symbol"
            ;; `dmi [lib] <name>' answers the live, post-ASLR address of a loaded symbol.
            (let ((lib (jstring arguments "lib"))
                  (name (jstring arguments "name")))
              (unless (or lib name)
                (fail "omp-re: debug resolve_symbol needs a name (and optionally a lib)"))
              (let ((query (format nil "~{~a~^ ~}"
                                   (mapcar #'validate-symbol-query (remove nil (list lib name))))))
                (named (format nil "debug: resolve_symbol ~a" query)
                       (text-or (run (format nil "dmi ~a" query))
                                "(no match — the library may not be mapped yet; continue past the loader)")))))
           ("break_add"
            (need-addr)
            (run (format nil "db @ ~a" ea))
            (breakpoints (format nil "debug: break_add ~a" ea)))
           ("break_remove"
            (need-addr)
            (run (format nil "db- @ ~a" ea))
            (breakpoints (format nil "debug: break_remove ~a" ea)))
           ("break_add_hw"
            ;; The debug registers: breaks on read-only, self-modifying and
            ;; packed pages without patching an int3 into them.
            (need-addr)
            (run (format nil "dbH @ ~a" ea))
            (breakpoints (format nil "debug: break_add_hw ~a" ea)))
           (("break_enable" "break_disable")
            (need-addr)
            (run (format nil "~:[dbd~;dbe~] @ ~a" (string= action "break_enable") ea))
            (breakpoints (format nil "debug: ~a ~a" action ea)))
           ("break_condition"
            ;; Single-quoted, so `>', `<' and `==' in the expression are text,
            ;; not rizin's redirects and compares.
            (need-addr)
            (unless (jstring arguments "condition")
              (fail "omp-re: debug break_condition needs condition"))
            (run (format nil "dbC ~a @ ~a" (rz-quote (jstring arguments "condition")) ea))
            (breakpoints (format nil "debug: break_condition ~a" ea)))
           ("break_command"
            ;; A command run each time the breakpoint hits, to log state. It
            ;; passes the read-only on-hit policy — vetted reads of the
            ;; debugger's state, and the static print/info/search reads — so
            ;; it can never reach a `!' shell, a write, config or debugger
            ;; control.
            (need-addr)
            (unless (jstring arguments "command")
              (fail "omp-re: debug break_command needs command"))
            (let* ((catalog (load-catalog))
                   (line (handler-case
                             (check-debug-on-hit-command catalog (jstring arguments "command"))
                           (re-error (condition)
                             (fail "omp-re: debug break_command: ~a" condition)))))
              (run (format nil "dbc ~a @ ~a" line ea))
              (breakpoints (format nil "debug: break_command ~a" ea))))
           ("watch_add"
            ;; A hardware watchpoint at the seek; it lives in the breakpoint
            ;; list, so break_remove takes it off.
            (need-addr)
            (let ((perm (validate-watch-perm (jstring arguments "perm")))
                  (size (and (jnumber arguments "size") (clamp-int (jnumber arguments "size") 4 8))))
              (run (format nil "dbw ~a~@[ ~d~] @ ~a" perm size ea))
              (breakpoints (format nil "debug: watch_add ~a @ ~a" perm ea) "(no watchpoints)")))
           ("heap_blocks"
            (text-result (format nil "debug: heap_blocks~@[ @ ~a~]" ea)
                         (text-or (run (format nil "dmhwbj~@[ @ ~a~]" ea)) "(no blocks)")))
           ("heap_chunks"
            (text-result (format nil "debug: heap_chunks~@[ @ ~a~]" ea)
                         (text-or (run (format nil "dmhgj~@[ @ ~a~]" ea))
                                  "(no chunks — continue until glibc is mapped and has allocated)")))
           ("heap_bins"
            ;; All bins, or one kind of them: addr doubles as the selector.
            (let ((bin (and addr (js-scan "^(tcache|fast|unsorted|small|large)$" addr) addr)))
              (text-result (format nil "debug: heap_bins~@[ ~a~]" bin)
                           (text-or (run (format nil "dmhgd~@[ ~a~]" bin))
                                    "(no bin info — continue until glibc is mapped and has allocated)"))))
           (t
            (fail "omp-re: debug: unknown action ~a" (js-string action)))))))))

(define-tool "rizin_debug"
    (:label "debugger" :tier :exec
     :description "Dynamic analysis: launch the open binary under rizin's debugger and drive it — breakpoints and watchpoints, continue (incl. to the next syscall/call/return), single-step, reverse-step (record a trace with trace_start, then step_back / continue_back), read and write registers and memory, disassemble live (post-unpacking) memory, backtrace, and inspect maps, modules, libraries, sections, processes, threads, file descriptors, signals, Windows and glibc heaps. 'start' can instead attach to a running pid or connect to a remote gdb/windbg stub (via `attach`) — e.g. a sample running in an isolated VM. This drives a live process; use only in an isolated, disposable environment. Start with action 'start', then set breakpoints and continue/step; 'stop' ends it. The static analysis tools are unaffected."
     ;; Opt-in only: without the operator's switch the sample is never executed.
     :available (lambda () (debugger-enabled-p)))
    (("action" :string :required t :enum +debug-actions+
      :doc "start: launch the open binary under the debugger, stopped at entry (EXECUTES it); or, with `attach`, control a running pid or a remote gdb/windbg stub instead.
continue: resume until a breakpoint, signal, or exit. continue_until: resume to `addr`.
continue_to_syscall / continue_to_call / continue_to_ret: resume until the next syscall, call, or return.
step: one instruction (or `count`). step_over: step over calls.
trace_start / trace_stop: record a trace so you can go backward. step_back / continue_back: step or continue BACKWARD through the recorded trace (reverse debugging). trace_save / trace_load: persist the recorded trace to (and restore it from) a directory in omp-re's output directory, named by `file`.
registers: all register values. registers_telescope: each register resolved to what it points at. write_register: set `reg` to `value`.
read_memory: `size` bytes at `addr` (returned inline as hex). dump_memory: write `size` bytes of live memory at `addr` to a file in omp-re's output directory (for an unpacked/decrypted region too large to return inline) — returns its path, size, and SHA-256. write_memory: write `bytes` (hex) at `addr`. disassemble: `count` instructions at `addr` (default PC) from live memory. resolve_symbol: live address of `name` (optionally in `lib`).
break_add / break_add_hw (hardware) / break_remove at `addr`. break_list: list breakpoints and watchpoints. break_enable / break_disable at `addr`. break_condition: only stop when `condition` holds. break_command: run a read-only `command` on hit. watch_add: watchpoint at `addr` (perm r/w/rw, size). backtrace: call stack.
maps / modules / libraries / sections / processes / threads / fds / signals / windows: inspect process state.
heaps / heap_blocks: Windows heaps. heap_arenas / heap_chunks / heap_bins: glibc heap (arena in `addr`/`bin` where relevant).
stop: kill the process and end the debug session.")
     ("addr" :string :doc "Address or symbol for continue_until, read_memory, write_memory, disassemble, break_add, break_remove, watch_add, heap_chunks/heap_bins (arena/bin).")
     ("count" :number :doc "Instruction count for step / step_over (default 1), or instructions to show for disassemble (default 16).")
     ("size" :number :doc "Bytes to read for read_memory (default 64) or dump_memory (required, up to 16 MiB), or watchpoint size for watch_add (1/2/4/8).")
     ("file" :string :doc "A bare name (no path) inside omp-re's output directory: the output file for dump_memory (omit for an auto-generated name), or the trace-session directory for trace_save/trace_load (required for trace_load).")
     ("reg" :string :doc "Register name for write_register, e.g. rip, rax, eflags.")
     ("value" :string :doc "New register value for write_register (decimal or 0x hex).")
     ("bytes" :string :doc "Hex bytes for write_memory, e.g. 9090 or 4889e5 (written to the live process at addr).")
     ("perm" :string :doc "Watchpoint access for watch_add: r, w, or rw (default rw).")
     ("condition" :string :doc "Breakpoint condition for break_condition, e.g. `rax==0` or `rdi>0x10` — the breakpoint stops only when it holds.")
     ("command" :string :doc "A read-only rizin command for break_command to run each time the breakpoint is hit (e.g. `drj` to log registers, `dmj` maps, `dbtj` backtrace). Restricted to vetted debugger-state reads plus the static print/info/search reads — never shell, writes, config, or debugger control.")
     ("lib" :string :doc "Library name for resolve_symbol (optional), e.g. libc.")
     ("name" :string :doc "Symbol name for resolve_symbol, e.g. system — resolves its live (post-ASLR) address.")
     ;; The engine's schema has these two as nested objects, which a tool's
     ;; parameter types here cannot spell: each is the text of a JSON object,
     ;; decoded and held to the same rules.
     ("run" :string :doc "rz-run environment for start: the target's arguments, env, cwd, stdio redirections, and limits. Only read alongside action 'start' when launching (not with attach). A JSON object as text, e.g. {\"args\":[\"-l\"],\"env\":{\"LANG\":\"C\"},\"aslr\":false}. Members: args — program arguments (arg0..argN); env — environment variables for the debuggee; cwd — working directory for the debuggee; stdin / stdout / stderr — file to read the debuggee's stdin from / write its stdout / stderr to; input — string passed to the debuggee via stdin; aslr — enable or disable ASLR for the debuggee; maxstack — maximum stack size (bytes); maxfd — maximum number of file descriptors; maxproc — maximum number of processes; timeout — seconds before the debuggee is killed.")
     ("attach" :string :doc "For action 'start': attach to a running pid or a remote stub instead of launching the open binary. Exactly one of pid/remote; not combined with run. The open binary is used as the symbol source. A JSON object as text, e.g. {\"pid\":1234} or {\"remote\":\"gdb://127.0.0.1:1234\"}. Members: pid — attach to this already-running process id instead of launching the open binary; remote — connect to a remote debug stub instead of launching: a gdb:// or windbg:// URI (e.g. a sample running in an isolated VM)."))
    (arguments)
  (let ((action (jstring arguments "action")))
    (action-case action
      ("start" (debug-start arguments))
      ("stop" (debug-stop))
      ;; Nothing below launches anything: with no debug session, it is refused.
      (t (debug-action action arguments (require-debug))))))
