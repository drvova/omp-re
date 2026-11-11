;;;; build-image.lisp --- save the engine, loaded and ready to serve omp, as one executable.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --script scripts/build-image.lisp <output> [<identity>]
;;;;
;;;; The Lisp half of scripts/build-image.ts, which is the one way an image
;;;; of the engine is made and is who runs this. <output> becomes an
;;;; executable holding SBCL's runtime and the system omp-re-stdio. Started,
;;;; it does what `sbcl --load stdio/serve.lisp' does once the system is
;;;; loaded (IMAGE-MAIN in stdio/server.lisp), without the loading: it needs
;;;; no SBCL, no cl-ppcre and no source beside it. It is for this operating
;;;; system and processor only. <identity> is kept in it as what it was
;;;; built from; started with `--identity <other>' it refuses to serve.
;;;;
;;;; <output> is written in place, so a reader could meet half of it: the
;;;; caller names a file nobody reads yet and moves it when this has exited
;;;; 0. The image is not compressed; docs/install.md has what compression
;;;; would cost at every start.
;;;;
;;;; Exits 2 when called wrong, and 1 with the reason on standard error when
;;;; the engine could not be loaded.

(in-package #:cl-user)

(defun refuse (code control &rest arguments)
  (format *error-output* "~&~?~%" control arguments)
  (finish-output *error-output*)
  (sb-ext:exit :code code :abort t))

(handler-case (load (merge-pathnames "../stdio/load.lisp" (or *load-truename* *default-pathname-defaults*)))
  (error (condition) (refuse 1 "~a" condition)))

(destructuring-bind (&optional output identity &rest more) (uiop:command-line-arguments)
  (when (or (null output) more)
    (refuse 2 "usage: sbcl --script scripts/build-image.lisp <output> [<identity>]"))
  (setf (symbol-value (uiop:find-symbol* '#:*identity* '#:omp-re-stdio)) identity)
  ;; What ASDF worked out about this machine and this checkout is not the
  ;; image's to keep; IMAGE-MAIN works it out again where the image runs.
  (uiop:call-image-dump-hook)
  (sb-ext:save-lisp-and-die (merge-pathnames (uiop:parse-native-namestring output) (uiop:getcwd))
                            :executable t :save-runtime-options t
                            :toplevel (uiop:find-symbol* '#:image-main '#:omp-re-stdio)))
