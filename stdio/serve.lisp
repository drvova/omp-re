;;;; serve.lisp --- start the engine for omp.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --noinform --no-sysinit --no-userinit --disable-debugger --load stdio/serve.lisp
;;;;
;;;; omp's side (extensions/re/engine.ts) runs this, once for the omp
;;;; process. Standard output is the wire and belongs to the protocol alone:
;;;; before anything is loaded it is put aside for the server, and everything
;;;; that prints — a compiler note on a first load, a warning, a backtrace —
;;;; goes to standard error, which omp keeps as a log. The first line on the
;;;; wire is {"ready": PROTOCOL}, or {"fatal": TEXT} when the engine could
;;;; not be loaded, TEXT saying what to install.

(in-package #:cl-user)

(defvar *wire*
  ;; The descriptor SBCL itself holds for standard output, whatever a
  ;; descriptor is on this platform (a HANDLE on Windows).
  (sb-sys:make-fd-stream (sb-sys:fd-stream-fd sb-sys:*stdout*)
                         :output t :buffering :full
                         :external-format '(:utf-8 :replacement #\?)))

(defvar *wire-in*
  (sb-sys:make-fd-stream (sb-sys:fd-stream-fd sb-sys:*stdin*)
                         :input t :buffering :full
                         :external-format '(:utf-8 :replacement #\?)))

(let ((log (sb-sys:make-fd-stream (sb-sys:fd-stream-fd sb-sys:*stderr*)
                                  :output t :buffering :line
                                  :external-format '(:utf-8 :replacement #\?))))
  (setf *standard-output* log
        *error-output* log
        *trace-output* log
        *terminal-io* (make-two-way-stream (make-concatenated-stream) log)))

(defun fatal (control &rest arguments)
  ;; No JSON library is loaded yet: the text is escaped by hand.
  (let ((text (apply #'format nil control arguments)))
    (write-string "{\"fatal\":\"" *wire*)
    (loop for char across text
          do (cond ((char= char #\") (write-string "\\\"" *wire*))
                   ((char= char #\\) (write-string "\\\\" *wire*))
                   ((char= char #\Newline) (write-string "\\n" *wire*))
                   ((< (char-code char) 32) (write-char #\Space *wire*))
                   (t (write-char char *wire*))))
    (write-string "\"}" *wire*)
    (terpri *wire*)
    (finish-output *wire*)
    (sb-ext:exit :code 3 :abort t)))

(require :asdf)

;; Where Quicklisp is installed, cl-ppcre may only be there.
(let ((quicklisp (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname))))
  (when (and (not (find-package '#:quicklisp)) (probe-file quicklisp))
    (ignore-errors (load quicklisp))))

(let ((root (uiop:pathname-parent-directory-pathname
             (uiop:pathname-directory-pathname (or *load-truename* *default-pathname-defaults*)))))
  (push root asdf:*central-registry*)
  (unless (ignore-errors (asdf:find-system "cl-ppcre"))
    (fatal "omp-re: the Common Lisp library cl-ppcre was not found. Install it — Debian/Ubuntu: apt install cl-ppcre; with Quicklisp: (ql:quickload \"cl-ppcre\"); otherwise put it where ASDF looks (~~/common-lisp/cl-ppcre/) — and start omp again."))
  (handler-case
      (handler-bind ((warning #'muffle-warning))
        (let ((*compile-verbose* nil) (*compile-print* nil) (*load-verbose* nil))
          (asdf:load-system "omp-re-stdio" :verbose nil)))
    (error (condition)
      (fatal "omp-re: the engine could not be loaded by ~a ~a: ~a"
             (lisp-implementation-type) (lisp-implementation-version) condition))))

(format *wire* "{\"ready\":~d}~%" (symbol-value (find-symbol "+PROTOCOL+" '#:omp-re-stdio)))
(finish-output *wire*)

(uiop:symbol-call '#:omp-re-stdio '#:serve *wire-in* *wire*)
(sb-ext:exit :code 0 :abort t)
