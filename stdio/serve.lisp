;;;; serve.lisp --- start the engine for omp from its source.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --noinform --no-sysinit --no-userinit --disable-debugger --load stdio/serve.lisp
;;;;
;;;; omp's side (extensions/re/image.ts) runs this, once for the omp process,
;;;; when it has no saved image of the engine to run instead. It loads the
;;;; system (stdio/load.lisp) and hands over to the server's MAIN
;;;; (stdio/server.lisp), which is also what an image starts with: from the
;;;; first line on the wire, {"ready": PROTOCOL}, the two are one program.
;;;;
;;;; What is here is what only a load from source needs. Standard output is
;;;; the wire, so before anything is loaded everything that prints — a
;;;; compiler note on a first load, a warning — is sent to standard error,
;;;; which omp writes to its log. And an engine that cannot be loaded says
;;;; so on the wire as {"fatal": TEXT}, TEXT saying what to install, and
;;;; exits with status 3.

(in-package #:cl-user)

(let ((log (sb-sys:make-fd-stream (sb-sys:fd-stream-fd sb-sys:*stderr*)
                                  :output t :buffering :line
                                  :external-format '(:utf-8 :replacement #\?))))
  (setf *standard-output* log
        *error-output* log
        *trace-output* log
        *terminal-io* (make-two-way-stream (make-concatenated-stream) log)))

(defun fatal (text)
  ;; No JSON library may be loaded: the text is escaped by hand.
  (let ((wire (sb-sys:make-fd-stream (sb-sys:fd-stream-fd sb-sys:*stdout*)
                                     :output t :buffering :full
                                     :external-format '(:utf-8 :replacement #\?))))
    (write-string "{\"fatal\":\"" wire)
    (loop for char across text
          do (cond ((char= char #\") (write-string "\\\"" wire))
                   ((char= char #\\) (write-string "\\\\" wire))
                   ((char= char #\Newline) (write-string "\\n" wire))
                   ((< (char-code char) 32) (write-char #\Space wire))
                   (t (write-char char wire))))
    (write-string "\"}" wire)
    (terpri wire)
    (finish-output wire)
    (sb-ext:exit :code 3 :abort t)))

(handler-case (load (merge-pathnames "load.lisp" (or *load-truename* *default-pathname-defaults*)))
  (error (condition) (fatal (princ-to-string condition))))

(uiop:symbol-call '#:omp-re-stdio '#:main)
(sb-ext:exit :code 0 :abort t)
