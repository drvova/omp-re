;;;; bridge.lisp --- the engine process, and one request to it.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The engine is omp-re's own TypeScript (extensions/re), run headless by
;;;; nodecode/bridge.ts under bun: one child process, started at the first
;;;; request and kept, because the rizin session it owns is expensive to
;;;; rebuild. The wire is one JSON object per line each way; a request
;;;; carries an id and gets exactly one reply with that id (bridge.ts lists
;;;; the frames).
;;;;
;;;; There is no reader thread. A caller writes its request, then takes turns
;;;; with every other caller at reading the child's stdout in short slices
;;;; under the lock, filing each reply under its id; so two sessions' calls
;;;; overlap in the engine and neither waits for the other's answer. A line a
;;;; slice ends in the middle of stays on the bridge, in a buffer of its own,
;;;; so neither a deadline nor an interrupted eval can tear a frame.
;;;;
;;;; The child's stderr is appended to a log under the state directory, never
;;;; to this image's fd 2: the first question about an engine that died is
;;;; what it printed.

(in-package #:nodecode-re)

(defparameter *slice-seconds* 0.1
  "How long one caller holds the read side before letting the next look.")

(defparameter *stop-grace-seconds* 3
  "How long STOP-BRIDGE waits for the engine to close its rizin sessions and
exit after its stdin closes, before the tree is killed.")

(defstruct (bridge (:copier nil))
  pid                                   ; the child, leading a process group
  process                               ; its SB-EXT:PROCESS on the fork path
  input                                 ; the child's stdin, ours to write
  output                                ; the child's stdout, ours to read
  log-path
  (line (make-array 256 :element-type 'character :adjustable t :fill-pointer 0))
  (next-id 0)
  (replies (make-hash-table))           ; id => reply object, until its caller takes it
  (abandoned (make-hash-table))         ; ids whose caller left before the answer
  (catalog nil)                         ; the `hello' reply, once asked
  (closed-p nil))

(defvar *bridge* nil
  "The running engine process, or NIL before the first request and after a stop.")

(defun now-seconds ()
  (/ (get-internal-real-time) internal-time-units-per-second))

(defun native (path)
  (uiop:native-namestring path))

;;; --- where things are ---------------------------------------------------------

(defun repository-root ()
  "The folder this cell was loaded from: the omp-re checkout."
  (asdf:system-source-directory "nodecode-re"))

(defun state-directory ()
  "Where the engine keeps session branches, evidence, the audit log and
reports: the section's state_dir, or omp-re/ under the organism's home."
  (let ((named (nlk:trimmed (or (setting :state-dir) ""))))
    (uiop:ensure-directory-pathname
     (if (plusp (length named))
         (nlk:expand-home named)
         (nlk:home "omp-re/")))))

(defun engine-environment ()
  "This process's environment with the engine's own switches laid over it."
  (let ((rizin (nlk:trimmed (or (setting :rizin-path) ""))))
    (nlk:environment-with
     (append (list (format nil "PI_CODING_AGENT_DIR=~a" (native (state-directory))))
             (when (plusp (length rizin))
               (list (format nil "OMPRE_RIZIN_PATH=~a" (native (nlk:expand-home rizin)))))
             (when (setting :debugger)
               (list "OMPRE_ENABLE_DEBUGGER=1"))))))

;;; --- the process ----------------------------------------------------------------

(defun exit-text (bridge)
  "How BRIDGE's child ended, and where what it printed is."
  (let ((status (and (bridge-pid bridge)
                     (ignore-errors (nlk:child-exit (bridge-pid bridge) (bridge-process bridge))))))
    (format nil "~:[it is still running~;it exited with status ~:*~a~]; its log is ~a"
            status (native (bridge-log-path bridge)))))

(defun launch ()
  "Start the engine => a BRIDGE. Refuses, in words the model can act on, when
the engine's dependencies were never installed or its runtime cannot be run."
  (let* ((root (repository-root))
         (script (merge-pathnames "nodecode/bridge.ts" root))
         (command (setting :command))
         (log-path (merge-pathnames "bridge.log" (state-directory))))
    (unless (probe-file script)
      (fail "the engine is not beside the cell: ~a is missing. Install the whole omp-re repository as the cell folder, not nodecode/ alone."
            (native script)))
    (unless (probe-file (merge-pathnames "node_modules/@oh-my-pi/omptype/package.json" root))
      (fail "the engine's dependencies are not installed: run (sh \"bun install\" :directory ~s) once, then call again."
            (native root)))
    (ensure-directories-exist log-path)
    ;; Create the log (an append opens without creating it) and stamp the launch.
    (with-open-file (out log-path :direction :output :if-exists :append :if-does-not-exist :create)
      (format out "~&;; nodecode-re: launched~{ ~a~} ~a~%" command (native script)))
    (handler-case
        (multiple-value-bind (pid output errors process input)
            (nlk:spawn-program (append command (list (native script)))
                               :directory root
                               :input :stream
                               :error-output log-path
                               :environment (engine-environment))
          (declare (ignore errors))
          (make-bridge :pid pid :process process :input input :output output :log-path log-path))
      (error (condition)
        (fail "the engine could not be started with ~{~a~^ ~}: ~a. Install bun (https://bun.sh), or set the re section's command to the argv that runs it."
              command condition)))))

(defun live-p (bridge)
  (and bridge
       (not (bridge-closed-p bridge))
       (null (ignore-errors (nlk:child-exit (bridge-pid bridge) (bridge-process bridge))))))

(defun ensure-bridge ()
  "The running engine, started now when there is none or the last one died."
  (running-settings)
  (with-re-lock
    (unless (live-p *bridge*)
      (when *bridge*
        (close-streams *bridge*))
      (setf *bridge* (launch)))
    *bridge*))

(defun close-streams (bridge)
  (setf (bridge-closed-p bridge) t)
  (ignore-errors (close (bridge-input bridge)))
  (ignore-errors (close (bridge-output bridge))))

(defun stop-bridge ()
  "End the engine: its stdin closes, which is its signal to close every rizin
session and exit; a child that outstays the grace is killed with its tree."
  (let ((bridge (with-re-lock (prog1 *bridge* (setf *bridge* nil)))))
    (when bridge
      (setf (bridge-closed-p bridge) t)
      (ignore-errors (close (bridge-input bridge)))
      (loop repeat (ceiling (* *stop-grace-seconds* 10))
            while (null (ignore-errors (nlk:child-exit (bridge-pid bridge) (bridge-process bridge))))
            do (sleep 0.1))
      (unless (ignore-errors (nlk:child-exit (bridge-pid bridge) (bridge-process bridge)))
        (ignore-errors (nlk:kill-tree (bridge-pid bridge))))
      (ignore-errors (close (bridge-output bridge))))
    t))

;;; --- the wire -------------------------------------------------------------------

(defun send-line (bridge text)
  "Write one frame. Called under the lock."
  (handler-case
      (let ((stream (bridge-input bridge)))
        (write-string text stream)
        (write-char #\Newline stream)
        (finish-output stream))
    (error (condition)
      (setf (bridge-closed-p bridge) t)
      (fail "the engine stopped taking requests (~a): ~a" condition (exit-text bridge)))))

(defun file-frame (bridge text)
  "File the reply TEXT spells under its id, unless nobody waits for it."
  (let* ((reply (ignore-errors (nlk:decode-json text)))
         (id (and (hash-table-p reply) (nlk:json-value reply :integer "id"))))
    (cond ((null id))                   ; not a reply: nothing waits for it
          ((gethash id (bridge-abandoned bridge))
           (remhash id (bridge-abandoned bridge)))
          (t (setf (gethash id (bridge-replies bridge)) reply)))))

(defun read-slice (bridge seconds)
  "Read what the child has written, waiting at most SECONDS for more; every
whole line read is filed. Called under the lock. => :CLOSED at end of file."
  (let* ((stream (bridge-output bridge))
         (fd (sb-sys:fd-stream-fd stream))
         (line (bridge-line bridge))
         (waited nil))
    (loop
      ;; One character moves from the stream to the buffer, or one whole line
      ;; from the buffer to the table, with interrupts held off: an eval
      ;; interrupted here leaves the frame where the next reader finds it.
      (let ((char (sb-sys:without-interrupts
                    (let ((char (read-char-no-hang stream nil :eof)))
                      (cond ((not (characterp char)))
                            ((char= char #\Newline)
                             (file-frame bridge (copy-seq line))
                             (setf (fill-pointer line) 0))
                            (t (vector-push-extend char line)))
                      char))))
        (cond ((eq char :eof)
               (setf (bridge-closed-p bridge) t)
               (return :closed))
              ((null char)
               (when (or waited (not (sb-sys:wait-until-fd-usable fd :input seconds)))
                 (return nil))
               (setf waited t)))))))

(defun take-reply (bridge id)
  "The reply filed under ID, taken, or NIL. Called under the lock."
  (let ((reply (gethash id (bridge-replies bridge))))
    (when reply
      (remhash id (bridge-replies bridge)))
    reply))

(defun exchange (request &key (seconds (setting :timeout-seconds)))
  "Send REQUEST, a JSON object without an id, and wait at most SECONDS for
its reply => the reply object. A caller that leaves first — the deadline, an
interrupted eval — cancels its call in the engine on the way out."
  (let* ((bridge (ensure-bridge))
         (deadline (+ (now-seconds) seconds))
         (id nil)
         (answered nil))
    (with-re-lock
      (setf id (incf (bridge-next-id bridge))
            (gethash "id" request) id)
      (send-line bridge (nlk:encode-json-object request)))
    (unwind-protect
         (loop
           (let ((reply (with-re-lock
                          (or (take-reply bridge id)
                              (progn (unless (bridge-closed-p bridge)
                                       (read-slice bridge *slice-seconds*))
                                     (take-reply bridge id))))))
             (when reply
               (setf answered t)
               (return reply)))
           (when (bridge-closed-p bridge)
             (setf answered t)
             (fail "the engine exited before it answered: ~a. The next call starts it again; an open binary and its annotations are restored from the session's record."
                   (exit-text bridge)))
           (when (>= (now-seconds) deadline)
             (fail "the engine did not answer in ~a seconds, and the call was cancelled. Raise the re section's timeout_seconds for a slow analysis, or ask for less."
                   seconds)))
      (unless answered
        (ignore-errors
         (with-re-lock
           (setf (gethash id (bridge-abandoned bridge)) t)
           (send-line bridge (nlk:encode-json-object
                              (nlk:make-json-object "op" "cancel" "id" id)))))))))

(defun catalog ()
  "The engine's own description of itself — its version, tools and commands —
asked once per process."
  (let ((bridge (ensure-bridge)))
    (or (bridge-catalog bridge)
        (let ((reply (exchange (nlk:make-json-object "op" "hello") :seconds 60)))
          (unless (nlk:json-value reply :boolean "ok")
            (fail "the engine would not describe itself: ~a"
                  (or (nlk:json-value reply :string "error") "no reason given")))
          (setf (bridge-catalog bridge) reply)))))
