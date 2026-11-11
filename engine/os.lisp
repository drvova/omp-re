;;;; os.lisp --- child processes, bounded runs, atomic writes.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; What the engine needs of the operating system, on SBCL and UIOP alone, so
;;;; the core loads in a plain image whichever host runs it, on Windows as
;;;; elsewhere. One function differs by platform, KILL-PROCESS-TREE; nothing
;;;; else here names a POSIX call.

(in-package #:omp-re)

;;; --- child processes ----------------------------------------------------------------

(defun spawn-program (argv)
  "Start ARGV with all three of its streams as pipes => the SB-EXT process.
What a binary prints is not always UTF-8, so a byte that is not reads as ?
rather than signalling."
  (sb-ext:run-program (first argv) (rest argv)
                      :search t :wait nil
                      :input :stream :output :stream :error :stream
                      :external-format '(:utf-8 :replacement #\?)))

#-win32
(defun process-descendants (pid)
  "The pids of PID's children and theirs. Linux says so under /proc;
anywhere else the answer is none and only the process itself is killed."
  (let ((children (ignore-errors
                   (with-open-file (in (format nil "/proc/~d/task/~d/children" pid pid))
                     (loop for child = (read in nil nil) while (integerp child) collect child)))))
    (append children (mapcan #'process-descendants (copy-list children)))))

(defun kill-process-tree (process)
  "Kill PROCESS and what it started. rizin_cli's programs and the triage
tools start children of their own, and a timeout must not leave them
running. Never signals."
  ;; Windows has no signal to send a group: taskkill walks the tree itself.
  #+win32
  (progn
    (ignore-errors
     (sb-ext:run-program "taskkill" (list "/T" "/F" "/PID" (princ-to-string (sb-ext:process-pid process)))
                         :search t :input nil :output nil :error nil))
    (ignore-errors (sb-ext:process-kill process 9)))
  #-win32
  (let ((descendants (ignore-errors (process-descendants (sb-ext:process-pid process)))))
    (ignore-errors (sb-ext:process-kill process 9))
    (dolist (pid descendants)
      (ignore-errors (sb-posix:kill pid 9))))
  nil)

(defun scratch-name ()
  (format nil "omp-re-~36r" (random (expt 36 12))))

(defun run-bounded (argv seconds)
  "Run ARGV to completion or for SECONDS => (values OUTPUT ERROR-OUTPUT
STATUS), STATUS the exit code or :TIMEOUT. stdout is read here to its end
and stderr goes to a file, so a child that fills one pipe while the other is
read cannot wedge; a watchdog thread enforces the bound."
  (let* ((errors (uiop:native-namestring
                  (merge-pathnames (format nil "~a.err" (scratch-name)) (uiop:temporary-directory))))
         (process (sb-ext:run-program (first argv) (rest argv)
                                      :search t :wait nil :input nil
                                      :output :stream :error errors :if-error-exists :supersede
                                      :external-format '(:utf-8 :replacement #\?)))
         (timed-out nil)
         (watchdog (sb-thread:make-thread
                    (lambda ()
                      (loop repeat (ceiling (* seconds 20))
                            while (sb-ext:process-alive-p process)
                            do (sleep 0.05))
                      (when (sb-ext:process-alive-p process)
                        (setf timed-out t)
                        (kill-process-tree process)))
                    :name "omp-re run bound")))
    (let ((out (with-output-to-string (collected)
                 (loop for char = (read-char (sb-ext:process-output process) nil nil)
                       while char do (write-char char collected)))))
      (sb-ext:process-wait process)
      (sb-thread:join-thread watchdog :default nil)
      (close (sb-ext:process-output process))
      (let ((err (or (read-text-file errors) "")))
        (ignore-errors (delete-file errors))
        (values out err (if timed-out :timeout (sb-ext:process-exit-code process)))))))

;;; --- files ---------------------------------------------------------------------------

(defun expand-home (text)
  "TEXT as a pathname, a leading ~/ read as the user's home."
  (let ((text (string-trim '(#\Space #\Tab) text)))
    (if (uiop:string-prefix-p "~/" text)
        (merge-pathnames (uiop:parse-native-namestring (subseq text 2)) (user-homedir-pathname))
        (uiop:parse-native-namestring text))))

(defun write-file-atomically (path content)
  "CONTENT, a string, to PATH through a temporary file beside it and one
rename, so a reader never sees half of it."
  ;; The temporary has no type: RENAME-FILE fills a target that has none from
  ;; its source, and a blob is named by its hash alone.
  (let ((temporary (make-pathname :name (format nil ".~a" (scratch-name)) :type nil
                                  :defaults (merge-pathnames path))))
    (write-text-file temporary content)
    (rename-file temporary (merge-pathnames path))
    path))
