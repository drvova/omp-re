;;;; slash.lisp --- the /re command: how a subcommand is declared and a line run.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A /re line is a command the model runs, where a tool is something it
;;;; calls with arguments: `report out.md', `verify --strict', `evidence'.
;;;; The name is from when an operator typed these after /re; no host has
;;;; that command now, and each says in its own voice how its model runs a
;;;; line (host.lisp, :SLASH). A line is not written to the audit log; the
;;;; reads it makes are. A subcommand is declared once, with where it stands
;;;; in the help. One that lists things (DEFINE-LIST) says its rows once:
;;;; the line prints them, and a host with a screen opens the same rows as a
;;;; panel (views.lisp).

(in-package #:omp-re)

;;; --- subcommands ---------------------------------------------------------------------------

(defstruct (slash (:copier nil))
  (name "" :type string)
  usage description
  (order 1000)                          ; where /re help lists it
  immediate                             ; answers from what the session holds now, not after a call that holds it
  listing                               ; of a subcommand DEFINE-LIST declared
  function)                             ; (lambda (WORDS LINE)) => (values TEXT FAILED)

(defvar *slash-commands* '() "The /re subcommands, in the order /re help lists them.")

(defun register-slash (slash)
  (setf *slash-commands*
        (stable-sort (append (remove (slash-name slash) *slash-commands* :key #'slash-name :test #'string=)
                             (list slash))
                     #'< :key #'slash-order))
  (slash-name slash))

(defmacro define-slash (name (&key usage description (order 1000) immediate)
                        (words &optional (line (gensym "LINE")))
                        &body body)
  "Define the /re subcommand NAME. The body runs in the session, with WORDS
bound to the words after the subcommand and LINE to the text after it as it
was given — a path keeps its spaces — and answers the text, or (values
TEXT T) for a line that failed. ORDER places it in /re help. IMMEDIATE is
for a line that needs nothing of rizin — help, status, tools, doc: while a
long call holds the session (a large binary still being analyzed) it
answers at once, from what the session holds, instead of after it."
  `(register-slash
    (make-slash :name ,name :usage ,usage :description ,description :order ,order
                :immediate ,immediate
                :function (lambda (,words ,line) (declare (ignorable ,words ,line)) ,@body))))

;;; --- a subcommand that lists ------------------------------------------------------------------

(defstruct (listing (:copier nil))
  enter                                 ; what choosing a row does, in a word: open, cite, discuss
  none                                  ; what to say when there are no rows, or NIL to show the empty list
  rows)                                 ; (lambda ()) => the rows, in the running session

(defstruct (list-row (:copier nil))
  value label description
  enter                                 ; what choosing it on a screen does: {draft TEXT} or {view {kind, arg}}
  line)                                 ; the row as a line of text

(defun list-row (value label &key description enter line)
  "One row of a list: LABEL and under it DESCRIPTION on a screen, where
choosing it does ENTER; as text LINE, or the label and then the description."
  (make-list-row :value value :label label :description description :enter enter
                 :line (or line (format nil "~a~@[  ~a~]" label (and (plusp (length description)) description)))))

(defparameter +list-characters+ 4000 "How much of a list a notice can carry.")

(defun clip-list (title lines)
  (let ((text (format nil "~a~%~a" title (if lines (join-lines lines) "(nothing to show)"))))
    (if (> (length text) +list-characters+)
        (format nil "~a~%… cut at ~d characters; ~a"
                (subseq text 0 +list-characters+) +list-characters+ (voice :read-more))
        text)))

(defun find-list (name)
  "The subcommand NAME when it is a list, or NIL."
  (let ((slash (find name *slash-commands* :key #'slash-name :test #'string=)))
    (and slash (slash-listing slash) slash)))

(defun list-title (slash)
  (format nil "omp-re: ~a" (slash-name slash)))

(defun list-text (slash)
  (let* ((listing (slash-listing slash))
         (rows (funcall (listing-rows listing))))
    (if (and (null rows) (listing-none listing))
        (listing-none listing)
        (clip-list (list-title slash) (mapcar #'list-row-line rows)))))

(defmacro define-list (name (&key description (order 1000) enter none one) &body body)
  "Define the /re subcommand NAME as a list: BODY answers its rows (LIST-ROW)
in the running session. The line prints them; a host with a screen opens
them as a panel by the same name, where choosing a row does what ENTER says
in a word. NONE is said in place of an empty list. ONE, (lambda (WORD)),
answers the line when it names one row, as a body of DEFINE-SLASH answers."
  `(register-slash
    (make-slash :name ,name :usage ,(and one "[id]") :description ,description :order ,order
                :listing (make-listing :enter ,enter :none ,none :rows (lambda () ,@body))
                :function (lambda (words line)
                            (declare (ignore line))
                            ,(if one
                                 `(if words
                                      (funcall ,one (first words))
                                      (list-text (find-list ,name)))
                                 `(progn words (list-text (find-list ,name))))))))

(defun slash-help ()
  (join-lines
   (loop for slash in *slash-commands*
         collect (format nil "/re ~22a ~a"
                         (format nil "~a~@[ ~a~]" (slash-name slash) (slash-usage slash))
                         (slash-description slash)))))

(defun run-slash-line (session line)
  "One /re LINE in SESSION — a session or the id of one
=> (values TEXT FAILED)."
  (let* ((line (trimmed line))
         (end (or (position-if (lambda (char) (find char '(#\Space #\Tab #\Newline #\Return))) line)
                  (length line)))
         (name (if (zerop end) "help" (engine-name (subseq line 0 end))))
         (rest (trimmed (subseq line end)))
         (slash (find name *slash-commands* :key #'slash-name :test #'string=)))
    (if (null slash)
        (values (format nil "omp-re: unknown /re subcommand ~a — try /re help" (js-string name)) t)
        (in-session (session (format nil "/re ~a" name) :wait (not (slash-immediate slash)))
          (multiple-value-bind (text failed) (funcall (slash-function slash) (words rest) rest)
            (values (or text "(done)") failed))))))

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
