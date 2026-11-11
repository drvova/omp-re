;;;; files.lisp --- which files the engine reads, and the one directory it writes to.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A path the model or the operator names is read in one place: against the
;;;; directory the session works in when it is relative, links followed, and
;;;; held to the operator's allow-list. The engine never writes to the sample
;;;; on disk. A few tools must emit a separate file — a project, a signature
;;;; file, a dump of a live process's memory. Those go to one dedicated
;;;; directory and nowhere else, never a path the model chose, so a tool
;;;; cannot traverse out of it or overwrite an arbitrary file.

(in-package #:omp-re)

;;; --- reading ---------------------------------------------------------------------------------

(defun session-file (path &optional (session *session*))
  "PATH as it was written — ~/ and all, its spaces kept — read against the
directory SESSION works in when it is relative. Every entry point's paths
come through here: a tool's argument, a /re line, a verb."
  (let ((path (expand-home path)))
    (if (or (uiop:absolute-pathname-p path) (null session))
        path
        (let ((directory (ask-host :directory (session-id session))))
          (if directory
              (merge-pathnames path (uiop:ensure-directory-pathname directory))
              path)))))

(defun assert-path-allowed (file)
  "FILE — an existing file's true name, links already followed — when it lies
under one of the allowed directories, or when there is no allow-list. The
comparison is against each directory's own true name plus a separator, so
neither a link that points out of an allowed folder nor a sibling folder
whose name merely starts the same (/samples-evil beside /samples) passes."
  (let ((allowed (setting-value :allowed-dirs)))
    (when allowed
      (let ((path (uiop:native-namestring file)))
        (unless (some (lambda (directory)
                        (let ((real (ignore-errors
                                     (probe-file (uiop:ensure-directory-pathname
                                                  (expand-home directory))))))
                          (and real (uiop:string-prefix-p (uiop:native-namestring real) path))))
                      allowed)
          (fail "omp-re: ~a is outside the directories files may be opened from (~a: ~{~a~^, ~})"
                path (voice :allowed-dirs) allowed)))))
  file)

(defun resolve-readable-file (input)
  "INPUT resolved to an existing, readable, allowed file's native path, or NIL
when there is no such file. A file outside the allow-list is a refusal."
  (let ((file (ignore-errors (probe-file (session-file input)))))
    (and file
         (not (uiop:directory-pathname-p file))
         (ignore-errors (with-open-file (in file :element-type '(unsigned-byte 8)) t))
         (uiop:native-namestring (assert-path-allowed file)))))

(defun resolve-binary-path (input)
  (or (resolve-readable-file input)
      (fail "omp-re: no such binary: ~a" input)))

;;; --- writing ---------------------------------------------------------------------------------

(defun write-user-file (path text)
  "Write TEXT to PATH, which the operator named: read against the session's
directory like any path of theirs, and its folder is not made for it — a
report written somewhere that does not exist is a mistake to say, not to
paper over."
  (with-open-file (out (session-file path)
                       :direction :output :if-exists :supersede :if-does-not-exist :create
                       :external-format :utf-8)
    (write-string text out))
  path)

(defun output-directory ()
  "OMPRE_OUTPUT_DIR when set, else omp-re-out under the system's temporary directory."
  (uiop:ensure-directory-pathname
   (let ((configured (setting-value :output-dir)))
     (if configured
         (merge-pathnames (uiop:parse-native-namestring configured) (uiop:getcwd))
         (merge-pathnames "omp-re-out/" (uiop:temporary-directory))))))

(defun safe-basename (name)
  "NAME when it is a bare file name of safe characters: no separator, no
`..', not absolute. This is the guard that keeps a chosen name inside the
output directory."
  (let ((name (trimmed name)))
    (when (member name '("" "." "..") :test #'string=)
      (fail "omp-re: invalid output filename ~a" (js-string name)))
    (unless (and (js-scan "^[A-Za-z0-9._-]+$" name) (not (search ".." name)))
      (fail "omp-re: invalid output filename ~a — use a bare name of letters, digits, '.', '_' or '-' (no path separators)"
            (js-string name)))
    name))

(defun to-rizin-path (path)
  "PATH with forward slashes, which rizin accepts on every platform."
  (substitute #\/ #\\ (if (stringp path) path (uiop:native-namestring path))))

(defun rizin-path-arg (path)
  "PATH as one single-quoted rizin argument, so rizin takes every byte of it
literally — a `~' in a Windows short name is otherwise its grep operator."
  (rz-quote (to-rizin-path path)))

(defun prepare-output-path (basename)
  (let ((full (merge-pathnames (safe-basename basename) (output-directory))))
    (ensure-directories-exist full)
    (uiop:native-namestring full)))

(defun rizin-output-path (basename)
  "Like PREPARE-OUTPUT-PATH, for a file rizin itself writes: the path must
survive the pipe, and the one thing quoting cannot carry is a line break."
  (let ((full (prepare-output-path basename)))
    (when (ends-pipe-line-p full)
      (fail "omp-re: the output path ~a contains a line break or NUL" (js-string full)))
    full))

(defun output-subdirectory (basename &optional create)
  "The native path of the folder BASENAME inside the output directory, made
when CREATE."
  (let ((full (uiop:ensure-directory-pathname
               (merge-pathnames (safe-basename basename) (output-directory)))))
    (when create (ensure-directories-exist full))
    (string-right-trim "/\\" (uiop:native-namestring full))))
