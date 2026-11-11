;;;; verbs.lisp --- what the model calls from eval.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; nodecode's model has one tool, eval, and the engine's design is the same
;;;; idea from the other side: one tool to read the binary and a handful of
;;;; stateful ones, composed in code rather than listed as schemas. So the
;;;; native surface here is verbs — (re:open ...), (re:cmd ...), (re:call
;;;; ...) — that an eval form loops over, filters and defines helpers around,
;;;; and what the model defines that way the organism keeps.
;;;;
;;;; Every verb answers a string, but (re:json ...), which answers a *j
;;;; command's output already decoded. The verbs are a thin user of the
;;;; engine's surface (engine.lisp): each is one ENGINE-CALL or
;;;; ENGINE-COMMAND for the running turn's session, and an answer that
;;;; failed is RE-ERROR carrying the engine's own words, so eval marks the
;;;; form failed and the model reads why.
;;;;
;;;; omp's model has the same verbs in its eval, in JavaScript and Python.
;;;; So that the three stay the same verbs they are written from one
;;;; description, recipes/api.json: this file holds what a verb is written
;;;; in — a keyword list onto the engine's JSON, one call, one line — and
;;;; verb-forms.lisp, which is generated, the verbs.

(in-package #:nodecode-re)

;;; --- Lisp arguments onto the engine's JSON ------------------------------------------

(defun wire-value (value &optional schema)
  "VALUE as JSON: a string, a number and T as themselves, :FALSE as false, a
keyword as its lowercase name, a list or vector as an array. Where the
tool's SCHEMA says the parameter is an object, a keyword plist is one —
(:pid 1234) — and where it says an array of objects, a list of those."
  (cond ((eq value :false) nil)
        ((member value '(t :null)) value)
        ((stringp value) value)
        ((keywordp value) (string-downcase (symbol-name value)))
        ((hash-table-p value) value)
        ((and (equal (jstring schema "type") "object") (listp value))
         (wire-arguments value schema))
        ((or (listp value) (vectorp value))
         (map 'simple-vector (lambda (item) (wire-value item (jget schema "items"))) value))
        ((realp value) value)
        (t (fail "~s has no JSON form: pass a string, a number, T, :false, or a list of those" value))))

(defun wire-arguments (plist &optional schema)
  "The JSON object a keyword PLIST of tool arguments spells, read against
the tool's SCHEMA. A NIL value is a parameter left out — false is :FALSE, an
empty array is #()."
  (unless (evenp (length plist))
    (fail "tool arguments are keyword and value pairs; ~s has an odd one out" plist))
  (let ((object (obj)))
    (loop for (key value) on plist by #'cddr
          do (unless (or (keywordp key) (stringp key))
               (fail "a tool argument is named by a keyword, not ~s" key))
             (unless (null value)
               ;; A map's keys are the caller's own (an environment variable's
               ;; name); a parameter's are spelled the engine's way.
               (let ((name (if (and schema (null (jget schema "properties")))
                               (string key)
                               (engine-name key))))
                 (setf (gethash name object)
                       (wire-value value (or (jget schema "properties" name)
                                             (jget schema "additionalProperties")))))))
    object))

;;; --- one call ---------------------------------------------------------------------

(defun answer-text (answer)
  "The text of an engine ANSWER, or RE-ERROR carrying it when it failed."
  (if (jget answer "failed")
      (fail "~a" (jstring answer "text"))
      (jstring answer "text")))

(defun call-for-turn (name arguments)
  (let ((tool (find name (engine-tools) :key (lambda (tool) (jstring tool "name")) :test #'string=)))
    (engine-call (turn-session-id) name (wire-arguments arguments (and tool (jget tool "parameters"))))))

;;; --- what a verb answers -----------------------------------------------------------
;;; The verbs themselves are written from recipes/api.json into
;;; verb-forms.lisp; these are what they are written in.

(defun line-for-turn (line)
  "The engine's answer to one /re LINE for the running turn's session."
  (engine-command (turn-session-id) (or line "")))

(defun answer-data (command answer)
  "The data a *j COMMAND printed, from the engine's ANSWER to it: objects as
EQUAL hash tables, arrays as vectors => (values DATA EVIDENCE-ID). The whole
output is read, even past the size cap a result's text is cut at. RE-ERROR
when the answer failed or is not JSON."
  (answer-text answer)
  (values (handler-case (json-decode (trimmed (jstring answer "raw")))
            (json-refusal ()
              (fail "~a did not answer JSON; read it with (re:cmd ~s) instead" command command)))
          (and (jstring answer "evidenceId") (shown-id (jstring answer "evidenceId")))))
