;;;; slash.lisp --- the /re command: how a subcommand is declared and a line run.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; /re is the operator's command, not a tool: a line is not written to the
;;;; audit log and `/re off' does not gate it, since off and on are lines
;;;; themselves and the gate is for what the model calls. A subcommand is
;;;; declared once, with where it stands in the help and the row it has in
;;;; the dialog a host may draw; the help, the dialog and what a host is told
;;;; of the command all read that declaration.

(in-package #:omp-re)

;;; --- subcommands ---------------------------------------------------------------------------

(defstruct (slash (:copier nil))
  (name "" :type string)
  usage description
  (order 1000)                          ; where /re help lists it
  row                                   ; (POSITION LABEL &key detail ask placeholder verb), or NIL for no row
  function)                             ; (lambda (WORDS LINE)) => (values TEXT FAILED REPLY)

(defstruct (draft (:copier nil))
  "What a line would put in the operator's input box, where the host has
one, and what the line then says instead of its text."
  (text "" :type string)
  (notice "" :type string))

(defvar *slash-commands* '() "The /re subcommands, in the order /re help lists them.")

(defun register-slash (slash)
  (setf *slash-commands*
        (stable-sort (append (remove (slash-name slash) *slash-commands* :key #'slash-name :test #'string=)
                             (list slash))
                     #'< :key #'slash-order))
  (slash-name slash))

(defmacro define-slash (name (&key usage description (order 1000) row) (words &optional (line (gensym "LINE")))
                        &body body)
  "Define the /re subcommand NAME. The body runs in the session, with WORDS
bound to the words after the subcommand and LINE to the text after it as it
was typed — a path keeps its spaces — and answers the text, (values TEXT T)
for a line that failed, and as a third value what else the reply carries, a
plist of :DRAFT (a DRAFT), :LEVEL (:INFO, :WARNING or :ERROR, where it is
not what failing or not implies) and :USER-MESSAGE (text to send the model
as the operator's next message). ORDER
places it in /re help; ROW, (POSITION LABEL &key detail ask placeholder
verb), is its row in the dialog of what /re offers: one that runs the line,
or with ASK one that asks for a word first."
  `(register-slash
    (make-slash :name ,name :usage ,usage :description ,description :order ,order :row ',row
                :function (lambda (,words ,line) (declare (ignorable ,words ,line)) ,@body))))

(defun slash-help ()
  (join-lines
   (loop for slash in *slash-commands*
         collect (format nil "/re ~22a ~a"
                         (format nil "~a~@[ ~a~]" (slash-name slash) (slash-usage slash))
                         (slash-description slash)))))

(defun run-slash-line (session line &key by-model)
  "One /re LINE in SESSION — a session or the id of one
=> (values TEXT FAILED REPLY), REPLY as DEFINE-SLASH's body answers it.
/re is the operator's command. Where the model can reach its lines too (a
verb in eval), BY-MODEL says so, and `/re off' then gates the line as it
gates a tool call: the operator's own lines, off and on among them, are
never gated."
  (let* ((line (trimmed line))
         (end (or (position-if (lambda (char) (find char '(#\Space #\Tab #\Newline #\Return))) line)
                  (length line)))
         (name (if (zerop end) "help" (engine-name (subseq line 0 end))))
         (rest (trimmed (subseq line end)))
         (slash (find name *slash-commands* :key #'slash-name :test #'string=)))
    (if (null slash)
        (values (format nil "omp-re: unknown /re subcommand ~a — try /re help" (js-string name)) t)
        (in-session (session (format nil "/re ~a" name))
          (when (and by-model (session-tools-off *session*))
            (fail +tools-off+))
          (multiple-value-bind (text failed reply) (funcall (slash-function slash) (words rest) rest)
            (values (or text "(done)") failed reply))))))

(defun line-flags (line &key switches valued)
  "Take the flags out of a subcommand's LINE => (values REST FLAGS): FLAGS a
plist of each word of SWITCHES that was there (T) and each word of VALUED
with the word after it, keyed by the flag as written; REST the line without
them, otherwise as typed, so a path keeps its spaces."
  (let ((flags '())
        (kept '())
        (at 0))
    (flet ((next-word ()
             (let* ((start (position-if-not (lambda (char) (find char '(#\Space #\Tab))) line :start at))
                    (end (and start (or (position-if (lambda (char) (find char '(#\Space #\Tab))) line
                                                     :start start)
                                        (length line)))))
               (when start
                 (setf at end)
                 (values (subseq line start end) start end)))))
      (loop
        (let ((before at))
          (multiple-value-bind (word start end) (next-word)
            (declare (ignore start))
            (cond ((null word) (return))
                  ((member word switches :test #'string=)
                   (setf (getf flags (intern (string-upcase word) :keyword)) t))
                  ((member word valued :test #'string=)
                   (setf (getf flags (intern (string-upcase word) :keyword)) (next-word)))
                  (t (push (subseq line before end) kept)))))))
    (values (trimmed (format nil "~{~a~}" (nreverse kept))) flags)))
