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

(in-package #:nodecode-re)

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
  (let ((place (undeclared-place (slash-name slash))))
    (unless (slash-row slash) (setf (slash-row slash) (getf place :row)))
    (when (getf place :order) (setf (slash-order slash) (getf place :order))))
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

(defun run-slash-line (session line)
  "One /re LINE in SESSION — a session or the id of one
=> (values TEXT FAILED REPLY), REPLY as DEFINE-SLASH's body answers it."
  (let* ((line (trimmed line))
         (end (or (position-if (lambda (char) (find char '(#\Space #\Tab #\Newline #\Return))) line)
                  (length line)))
         (name (if (zerop end) "help" (engine-name (subseq line 0 end))))
         (rest (trimmed (subseq line end)))
         (slash (find name *slash-commands* :key #'slash-name :test #'string=)))
    (if (null slash)
        (values (format nil "omp-re: unknown /re subcommand ~a — try /re help" (js-string name)) t)
        (in-session (session (format nil "/re ~a" name))
          (multiple-value-bind (text failed reply) (funcall (slash-function slash) (words rest) rest)
            (values (or text "(done)") failed reply))))))

;;; --- names the tool groups still call; removed when they move to the above ---------------
;;; A subcommand defined with no :order and :row (undo, findings, report,
;;;     verify, carry) → say them in its DEFINE-SLASH, as written here.
;;; REST-OF-LINE words → the body's second parameter, the line as typed.
;;; *STATUS-LINES* (annotate.lisp, findings.lisp push a function of no
;;;     arguments) → (contribute NAME :order N :status (lambda (session) ...)),
;;;     annotations at 60 and findings at 70.

(defparameter +undeclared-places+
  '(("findings" :order 70 :row (80 "Findings" :detail "the conclusions recorded, each on its evidence"))
    ("undo" :order 80 :row (110 "Undo the last annotation"))
    ("report" :order 90 :row (100 "Write the report" :ask "File" :placeholder "analysis.md" :verb "write"))
    ("verify" :order 100 :row (90 "Verify" :detail "re-run the evidence and compare"))
    ("carry" :order 110)))

(defun undeclared-place (name)
  (rest (assoc name +undeclared-places+ :test #'string=)))

(defun rest-of-line (words)
  (format nil "~{~a~^ ~}" words))

(defvar *status-lines* '())

(contribute "status lines" :order 65
  :status (lambda (session)
            (declare (ignore session))
            (loop for lines in *status-lines* append (funcall lines))))
