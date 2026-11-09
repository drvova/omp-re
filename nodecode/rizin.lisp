;;;; rizin.lisp --- one rizin process speaking the NUL-framed pipe protocol.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Ported from omp-re's extensions/re/rizin.ts. In `-q0' mode rizin ends
;;;; every response with one 0x00 byte, including an empty frame for a
;;;; command that only wrote to stderr, and emits one empty banner frame at
;;;; startup. A unique `echo <marker>' is written right after each command;
;;;; rizin takes stdin lines strictly in order, so everything read before the
;;;; marker's own frame is that command's response, whatever number of frames
;;;; a future rizin chooses to emit.
;;;;
;;;; There is no reader thread. The caller reads the child's stdout itself,
;;;; under the session's lock, draining stderr as it goes so a noisy binary
;;;; can never fill that pipe and wedge the child mid-write. A read keeps its
;;;; partial frame on the session, and a command that was left before its
;;;; marker arrived — an interrupted eval — leaves the marker's name behind,
;;;; so the next command first reads up to it: the stream stays aligned and
;;;; the process, with its analysis and annotations, survives. Only a
;;;; timeout kills it.

(in-package #:nodecode-re)

(defparameter +command-seconds+ 60 "One ordinary rizin command's ceiling.")
(defparameter +stderr-tail+ 4096 "How much of rizin's stderr is kept for an error line.")

(defun analysis-seconds ()
  "The budget for the one `aaa' on open: full analysis of a large or packed
binary routinely runs minutes."
  (let ((ms (ignore-errors (parse-integer (or (env "OMPRE_ANALYSIS_TIMEOUT_MS") "")))))
    (if (and ms (plusp ms)) (/ ms 1000) 300)))

(defstruct (rz (:copier nil))
  pid process input output errors
  binary-path
  (lock (sb-thread:make-mutex :name "rizin session"))
  (frame (make-array 4096 :element-type 'character :adjustable t :fill-pointer 0))
  (stderr-tail "")
  (stderr-seen 0)
  (counter 0)
  (pending-marker nil)                  ; a marker written whose frame was never read
  (decompiler :unknown)
  (closed-p nil))

(defun now-seconds ()
  (/ (get-internal-real-time) internal-time-units-per-second))

(defun rz-alive-p (rz)
  (and rz
       (not (rz-closed-p rz))
       (null (ignore-errors (nlk:child-exit (rz-pid rz) (rz-process rz))))))

(defun rz-close (rz)
  "End RZ's process. Idempotent."
  (when (and rz (not (rz-closed-p rz)))
    (setf (rz-closed-p rz) t)
    (ignore-errors (nlk:kill-tree (rz-pid rz)))
    (dolist (stream (list (rz-input rz) (rz-output rz) (rz-errors rz)))
      (when stream (ignore-errors (close stream :abort t)))))
  nil)

(defun drain-stderr (rz)
  "Take whatever RZ's stderr holds, without waiting."
  (let ((stream (rz-errors rz)))
    (when stream
      (let ((text (with-output-to-string (out)
                    (loop for char = (ignore-errors (read-char-no-hang stream nil :eof))
                          while (characterp char)
                          do (write-char char out)))))
        (when (plusp (length text))
          (incf (rz-stderr-seen rz) (length text))
          (let ((tail (concatenate 'string (rz-stderr-tail rz) text)))
            (setf (rz-stderr-tail rz)
                  (subseq tail (max 0 (- (length tail) +stderr-tail+))))))))))

(defun stderr-detail (rz)
  (let ((detail (trimmed (rz-stderr-tail rz))))
    (if (plusp (length detail)) (format nil " (stderr: ~a)" detail) "")))

(defun read-frame (rz deadline what seconds)
  "The next frame RZ writes — the text up to a NUL — or a refusal: the
process exited, or DEADLINE passed, in which case it is killed so the next
call starts clean. WHAT names the command for that message."
  (let* ((stream (rz-output rz))
         (fd (sb-sys:fd-stream-fd stream))
         (frame (rz-frame rz)))
    (loop
      (drain-stderr rz)
      ;; One character moves from the pipe to the session's buffer with
      ;; interrupts held off, so an interrupted eval never drops one.
      (let ((char (sb-sys:without-interrupts
                    (let ((char (handler-case (read-char-no-hang stream nil :eof)
                                  (error () :eof))))
                      (when (and (characterp char) (char/= char #\Nul))
                        (vector-push-extend char frame))
                      char))))
        (cond ((eq char :eof)
               (rz-close rz)
               (fail "omp-re: rizin process exited~a" (stderr-detail rz)))
              ((null char)
               (let ((remaining (- deadline (now-seconds))))
                 (when (<= remaining 0)
                   (let ((detail (stderr-detail rz)))
                     (rz-close rz)
                     (fail "omp-re: rizin command timed out after ~dms: ~a~a"
                           (round (* 1000 seconds)) what detail)))
                 (sb-sys:wait-until-fd-usable fd :input (min remaining 0.05))))
              ((char= char #\Nul)
               ;; rizin on Windows ends lines with CRLF; the frame delimiter is the NUL.
               (let ((text (ppcre:regex-replace-all "\\r\\n" (copy-seq frame) (string #\Newline))))
                 (setf (fill-pointer frame) 0)
                 (return (coerce text 'simple-string)))))))))

(defun rz-run (rz command &key (seconds +command-seconds+))
  "Run the raw rizin COMMAND => (values OUTPUT STDERR), STDERR being what
rizin wrote there while the command ran."
  (sb-thread:with-mutex ((rz-lock rz))
    (when (rz-closed-p rz)
      (fail "omp-re: rizin process exited"))
    (let ((deadline (+ (now-seconds) seconds)))
      ;; A command left before its marker arrived: read up to that marker first.
      (when (rz-pending-marker rz)
        (loop for frame = (read-frame rz deadline command seconds)
              until (string= (trimmed frame) (rz-pending-marker rz)))
        (setf (rz-pending-marker rz) nil))
      (let ((marker (format nil "__OMPRE_SYNC_~(~36r~)_~(~36r~)__"
                            (incf (rz-counter rz)) (get-internal-real-time)))
            (stderr-start (rz-stderr-seen rz))
            (collected '()))
        (setf (rz-pending-marker rz) marker)
        (handler-case
            (let ((stream (rz-input rz)))
              (format stream "~a~%echo ~a~%" command marker)
              (finish-output stream))
          (error ()
            (rz-close rz)
            (fail "omp-re: rizin process exited~a" (stderr-detail rz))))
        ;; The bound is a ceiling against a genuinely desynced stream, not the expected path.
        (dotimes (i 8)
          (let ((frame (read-frame rz deadline command seconds)))
            (when (string= (trimmed frame) marker)
              (setf (rz-pending-marker rz) nil)
              (let ((output (format nil "~{~a~}" (nreverse collected))))
                ;; stderr is a separate pipe: give a final fragment one moment to arrive.
                (when (and (blank-p output) (rz-errors rz))
                  (ignore-errors
                   (sb-sys:wait-until-fd-usable (sb-sys:fd-stream-fd (rz-errors rz)) :input 0.02)))
                (drain-stderr rz)
                (let* ((written (- (rz-stderr-seen rz) stderr-start))
                       (tail (rz-stderr-tail rz)))
                  (return-from rz-run
                    (values output
                            (if (plusp written)
                                (subseq tail (- (length tail) (min written (length tail))))
                                ""))))))
            (push frame collected)))
        (let ((detail (stderr-detail rz)))
          (rz-close rz)
          (fail "omp-re: rizin protocol desync waiting for sync marker after: ~a~a" command detail))))))

(defun rz-cmd (rz command &key (seconds +command-seconds+))
  "The output of the raw rizin COMMAND."
  (values (rz-run rz command :seconds seconds)))

(defun rz-cmdj (rz command &key (seconds +command-seconds+))
  "The JSON value COMMAND prints, or NIL for empty output (rizin's reply to
an invalid address or an unknown command) and for anything that is not JSON."
  (let ((raw (trimmed (rz-cmd rz command :seconds seconds))))
    (and (plusp (length raw))
         (find (char raw 0) "{[")
         (json-parse raw))))

(defun resolve-numeric-addr (rz addr)
  "ADDR resolved to a number through rizin's `%v', which never errors on an
unresolvable input: it prints 0x0. Failing here gives a clear error instead
of treating address 0 as real."
  (let* ((raw (trimmed (rz-cmd rz (format nil "%v ~a" (validate-addr addr)))))
         (value (ignore-errors
                 (parse-integer raw :start (if (starts-with "0x" raw) 2 0) :radix 16 :junk-allowed t))))
    (unless (and value (/= value 0))
      (fail "omp-re: could not resolve address: ~a" addr))
    value))

;;; --- spawn flags ------------------------------------------------------------------

(defun base-rizin-flags ()
  "The flags every rizin process shares: `-q0' is the pipe protocol; color
and UTF-8 box drawing off keep output plain; `-N' skips the user's rizinrc so
the output parsed here is stock rizin's, while plugins still load."
  (append (list "-q0" "-e" "scr.color=0" "-e" "scr.utf8=false")
          (unless (env-on-p "OMPRE_RIZIN_LOAD_USER_CONFIG") (list "-N"))))

(defun build-load-flags (load)
  "The -a/-b/-B/-m/-F flags the JSON object LOAD spells, each value checked
so a nonsense or flag-shaped one fails here, in words."
  (when load
    (let ((arch (jget load "arch")) (bits (jget load "bits")) (base (jget load "base"))
          (map (jget load "map")) (format (jget load "format")))
      (append
       (when arch
         (unless (and (stringp arch) (ppcre:scan "^[A-Za-z][A-Za-z0-9_.]*$" arch))
           (fail "omp-re: load: invalid arch ~a — a plugin name like x86, arm, mips (see rizin -L)"
                 (js-string arch)))
         (list "-a" arch))
       (when bits
         (unless (member bits '(8 16 32 64))
           (fail "omp-re: load: invalid bits ~a — one of 8, 16, 32, 64" bits))
         (list "-b" (princ-to-string bits)))
       (when base (list "-B" (validate-addr base)))
       (when map (list "-m" (validate-addr map)))
       (when format
         (unless (and (stringp format) (ppcre:scan "^[A-Za-z][A-Za-z0-9_.]*$" format))
           (fail "omp-re: load: invalid format ~a — a bin plugin name like elf, pe, mach0, or any for raw (see rizin -L)"
                 (js-string format)))
         (list "-F" format))))))

(defun spawn-rz (rizin-path binary-path &key load debug-argv (analysis "aaa"))
  "Start rizin on BINARY-PATH, consume the startup banner and run ANALYSIS
=> a ready RZ. DEBUG-ARGV, when given, is the whole argument list after the
shared flags (the debugger's launch)."
  (let ((argv (cons rizin-path
                    (append (base-rizin-flags)
                            (or debug-argv
                                (append (build-load-flags load) (list binary-path)))))))
    (multiple-value-bind (pid output errors process input)
        (handler-case (nlk:spawn-program argv :input :stream :output :stream :error-output :stream)
          (error (condition)
            (fail "omp-re: rizin spawn failed: ~a" condition)))
      (let ((rz (make-rz :pid pid :process process :input input :output output :errors errors
                         :binary-path binary-path))
            (ready nil))
        (unwind-protect
             (progn
               (sb-thread:with-mutex ((rz-lock rz))
                 (read-frame rz (+ (now-seconds) +command-seconds+) "<startup banner>" +command-seconds+))
               (when analysis
                 (rz-cmd rz analysis :seconds (analysis-seconds)))
               (setf ready t)
               rz)
          ;; A half-analyzed process holds nothing worth keeping.
          (unless ready (rz-close rz)))))))

;;; --- finding rizin ------------------------------------------------------------------

(defun executable-p (path)
  (and path
       (let ((file (probe-file path)))
         (and file
              (not (uiop:directory-pathname-p file))
              #-win32 (eql 0 (ignore-errors (sb-posix:access (native file) sb-posix:x-ok)))
              #+win32 t))))

(defun find-on-path (name)
  "NAME resolved against PATH => its full path, or NIL."
  (dolist (directory (uiop:split-string (or (uiop:getenv "PATH") "")
                                        :separator #+win32 '(#\;) #-win32 '(#\:)))
    (when (plusp (length directory))
      (dolist (candidate (list name #+win32 (concatenate 'string name ".exe")))
        (let ((path (concatenate 'string (string-right-trim "/\\" directory) "/" candidate)))
          (when (executable-p path)
            (return-from find-on-path path)))))))

(defparameter *common-rizin-paths*
  #+win32 '("C:\\Program Files\\rizin\\bin\\rizin.exe" "C:\\Program Files (x86)\\rizin\\bin\\rizin.exe")
  #-win32 '("/opt/homebrew/bin/rizin" "/usr/local/bin/rizin" "/usr/bin/rizin" "/opt/rizin/bin/rizin"
            "/snap/bin/rizin" "~/.local/bin/rizin")
  "Where a package manager drops rizin, checked when it is not on PATH: an
organism launched from a desktop often inherits a minimal one.")

(defvar *configured-rizin* nil
  "A function answering the operator's own rizin path (the cell's rizin_path
setting), or NIL. Set by the cell at start.")

(defun read-binary-bits (path)
  "The target's pointer width from its file header: ELF, PE and thin Mach-O
are read; anything else answers NIL rather than a guess."
  (ignore-errors
   (with-open-file (in path :element-type '(unsigned-byte 8))
     (let* ((buffer (make-array 1024 :element-type '(unsigned-byte 8) :initial-element 0))
            (read (read-sequence buffer in)))
       (flet ((u16 (at) (logior (aref buffer at) (ash (aref buffer (1+ at)) 8)))
              (u32 (at) (logior (aref buffer at) (ash (aref buffer (+ at 1)) 8)
                                (ash (aref buffer (+ at 2)) 16) (ash (aref buffer (+ at 3)) 24))))
         (cond ((< read 4) nil)
               ((and (= (aref buffer 0) #x7f) (= (aref buffer 1) #x45)
                     (= (aref buffer 2) #x4c) (= (aref buffer 3) #x46))
                (case (aref buffer 4) (1 32) (2 64)))
               ((and (= (aref buffer 0) #x4d) (= (aref buffer 1) #x5a))
                (let ((lfanew (u32 #x3c)))
                  (when (and (plusp lfanew) (<= (+ lfanew 6) read) (= (u32 lfanew) #x00004550))
                    (case (u16 (+ lfanew 4))
                      ((#x8664 #xaa64) 64)
                      ((#x014c #x01c0) 32)))))
               ((= (u32 0) #xfeedfacf) 64)
               ((= (u32 0) #xfeedface) 32)))))))

(defun resolve-rizin-path (&optional binary-path bits)
  "The rizin to run: a per-bits override when the target's width is known,
then the operator's configured path, then PATH, then the common install
places; the bare name when none is found, so the not-found refusal fires."
  (let ((bits (or bits (and binary-path (read-binary-bits binary-path)))))
    (or (and (eql bits 64) (env "OMPRE_RIZIN_PATH_64"))
        (and (eql bits 32) (env "OMPRE_RIZIN_PATH_32"))
        (let ((configured (and *configured-rizin* (funcall *configured-rizin*))))
          (and configured (not (blank-p configured)) (native (uiop:parse-native-namestring configured))))
        (env "OMPRE_RIZIN_PATH")
        (find-on-path "rizin")
        (loop for candidate in *common-rizin-paths*
              for path = (if (starts-with "~/" candidate)
                             (native (merge-pathnames (subseq candidate 2) (user-homedir-pathname)))
                             candidate)
              when (executable-p path) return path)
        "rizin")))

(defun rizin-available-p (&optional (path (resolve-rizin-path)))
  (if (find-if (lambda (char) (find char "/\\")) path)
      (executable-p path)
      (and (find-on-path path) t)))

(defun assert-rizin-available ()
  (unless (rizin-available-p)
    (fail "omp-re: rizin not found on PATH or common install locations — install rizin (https://rizin.re), or set the re section's rizin_path (or OMPRE_RIZIN_PATH) to its full path (the output of `which rizin` in your shell). An organism launched from a desktop may not inherit your shell's PATH, so rizin can work in your terminal yet be invisible here.")))

(defun resolve-rizin-tool (tool)
  "The path of a sibling rizin program (rz-bin, rz-diff, ...): beside the
configured rizin when that is a path, else the bare name for PATH."
  (let* ((rizin (resolve-rizin-path))
         (slash (position-if (lambda (char) (find char "/\\")) rizin :from-end t))
         (extension (if (ends-with ".exe" (string-downcase rizin)) ".exe" "")))
    (if slash
        (concatenate 'string (subseq rizin 0 (1+ slash)) tool extension)
        (concatenate 'string tool extension))))

(defun run-program (argv &key (seconds 60) input)
  "Run ARGV to completion => (values STDOUT STDERR STATUS), STATUS an exit
code or :TIMEOUT. A program that cannot be started answers status 127 with
the reason as its stderr."
  (handler-case
      (multiple-value-bind (out err status)
          (if input
              (nlk:run-bounded argv :seconds seconds :input input)
              (nlk:run-bounded argv :seconds seconds))
        (values (or out "") (or err "") status))
    (error (condition)
      (values "" (princ-to-string condition) 127))))

(defun rizin-version ()
  "`rizin -v''s first line, or NIL when it cannot be run."
  (multiple-value-bind (out err status) (run-program (list (resolve-rizin-path) "-v") :seconds 20)
    (declare (ignore err))
    (and (eql status 0)
         (let ((line (trimmed (first (split-lines out)))))
           (and (plusp (length line)) line)))))

(defun resolve-binary-path (input)
  "INPUT resolved to an absolute, existing, readable file."
  (let ((file (ignore-errors (probe-file (uiop:parse-native-namestring input)))))
    (unless (and file (not (uiop:directory-pathname-p file))
                 (ignore-errors (with-open-file (in file :element-type '(unsigned-byte 8)) t)))
      (fail "omp-re: no such binary: ~a" input))
    (native file)))

;;; --- rizin's own catalog of commands --------------------------------------------------

(defvar *catalogs* (make-hash-table :test #'equal)
  "rizin path => its catalog, a table from command name to the spec object
`?*j' gives it. Read once per process.")
(defvar *catalog-lock* (sb-thread:make-mutex :name "rizin catalog"))

(defun read-catalog (rizin-path)
  (multiple-value-bind (out err status)
      (run-program (append (list rizin-path "-e" "scr.color=0")
                           (unless (env-on-p "OMPRE_RIZIN_LOAD_USER_CONFIG") (list "-N"))
                           (list "-qc" "?*j" "--"))
                   :seconds 60)
    (let ((parsed (and (eql status 0) (json-parse out))))
      (unless (hash-table-p parsed)
        (fail "omp-re: could not read rizin's command catalog from ~a~@[: ~a~]"
              rizin-path (and (not (blank-p err)) (trimmed err))))
      (let ((catalog (make-hash-table :test #'equal)))
        (maphash (lambda (command spec)
                   (when (hash-table-p spec)
                     (setf (gethash "cmd" spec) command
                           (gethash command catalog) spec)))
                 parsed)
        catalog))))

(defun load-catalog (&optional (rizin-path (resolve-rizin-path)))
  "The catalog of the rizin at RIZIN-PATH. A failed read is not kept, so
installing rizin mid-session works."
  (sb-thread:with-mutex (*catalog-lock*)
    (or (gethash rizin-path *catalogs*)
        (setf (gethash rizin-path *catalogs*) (read-catalog rizin-path)))))
