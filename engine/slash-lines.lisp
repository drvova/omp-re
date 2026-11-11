;;;; slash-lines.lisp --- /re help, open, status, tools, doc, the lists, evidence, cite.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; What a row of a list does when it is chosen on a screen is a view
;;;; (views.lisp), named here by the request for it.

(in-package #:omp-re)

(define-slash "help" (:immediate t :description "show this list" :order 150) (words)
  (slash-help))

(define-slash "open" (:usage "<path>" :description "open a binary and analyze it with rizin" :order 10)
    (words path)
  (if (null words)
      (values "Usage: /re open <path>" t)
      (values (open-binary path))))

;;; --- /re status --------------------------------------------------------------------------------

(defun decompiler-label (kind)
  (let ((plugin (cdr (assoc kind +decompilers+ :test #'equal))))
    (cond (plugin (format nil "~a (~a)" plugin kind))
          (kind (format nil "~a (plugin)" kind))
          (t (format nil "none — ~{~a~^ and ~} need a decompiler plugin (~{~a~^, ~})"
                     (mapcar #'car +decompilers+) (mapcar #'cdr +decompilers+))))))

(defun rizin-status-lines ()
  (let ((version (rizin-version))
        ;; A rizin that cannot be asked for its catalog is said by the first line.
        (catalog (ignore-errors (load-catalog))))
    (cons (format nil "rizin: ~a" (or version (format nil "not found (~a)" (resolve-rizin-path))))
          (when catalog
            (let ((missing (missing-required-commands catalog))
                  (present (available-decompilers catalog)))
              (append
               (list (if missing
                         (missing-commands-warning missing)
                         (format nil "rizin commands: all ~d omp-re sends are present (~d in this build; rizin_help searches them)"
                                 (length +required-commands+) (hash-table-count catalog)))
                     (format nil "decompiler: ~a" (decompiler-label (first present))))
               (when (rest present)
                 (list (format nil "  also available: ~{~a~^, ~} (reorder with ~a)"
                               (mapcar #'decompiler-label (rest present))
                               (setting-variable :decompiler))))))))))

(defun binary-status-lines (session)
  (if (session-binary-path session)
      (append (list (format nil "binary: ~a" (session-binary-path session)))
              ;; The record binds evidence to the bytes that were opened. A
              ;; file rebuilt since then is a different binary under the
              ;; same name, and reading on would mix the two.
              (let ((opened (session-binary-sha256 session))
                    (now (ignore-errors (sha256-file (session-binary-path session)))))
                (cond ((null now)
                       (list "  the file is no longer readable there"))
                      ((and opened (string/= opened now))
                       (list "  CHANGED ON DISK since it was opened: evidence so far is of the earlier bytes — open it again to analyze what is there now"))))
              (unless (rz-alive-p (session-rz session))
                (list "rizin process: not running (starts on next use)")))
      (list (format nil "binary: none — ~a" (voice :open-first)))))

(define-slash "status" (:immediate t :description "rizin, decompiler, binary, and evidence status" :order 120)
    (words)
  (join-lines
   (append (rizin-status-lines)
           (binary-status-lines *session*)
           (loop for contribution in *contributions*
                 when (contribution-status contribution)
                   append (funcall (contribution-status contribution) *session*)))))

;;; --- /re tools and /re doc ---------------------------------------------------------------------
;;; What the tools are and what one takes, as the model reads it. How a call
;;; is written and what an argument's name and type look like there are the
;;; host's (host.lisp, +VOICE+): the schema is the engine's.

(defun first-sentence (text)
  (let* ((text (substitute #\Space #\Newline (or text "")))
         (stop (search ". " text)))
    (if stop (subseq text 0 (1+ stop)) text)))

(defun argument-name (name)
  (let ((spell (voice :argument-name)))
    (if spell (funcall spell name) name)))

(defun parameter-lines (schema)
  "One line per property of a tool's JSON SCHEMA: how it is named where the
model calls the tool, what it takes, what it means."
  (flet ((names (properties)
           (and properties
                (loop for key being the hash-keys of properties collect (argument-name key)))))
    (let ((required (jlist schema "required")))
      (loop for name being the hash-keys of (jget schema "properties") using (hash-value property)
            collect (format nil "  ~a  ~a~:[~;, required~]~@[ — ~a~]"
                            (argument-name name)
                            (let ((enum (jlist property "enum"))
                                  (type (jstring property "type")))
                              (cond (enum (format nil "one of ~{~a~^, ~}" (mapcar #'json-encode enum)))
                                    ((equal type "boolean") (voice :type-boolean))
                                    ((equal type "object")
                                     (format nil (voice :type-object) (names (jget property "properties"))))
                                    ((and (equal type "array") (equal (jstring property "items" "type") "object"))
                                     (format nil (voice :type-objects)
                                             (names (jget property "items" "properties"))))
                                    ((equal type "array") (voice :type-strings))
                                    (t type)))
                            (member name required :test #'equal)
                            (jstring property "description"))))))

(define-slash "tools" (:immediate t :description "the tools, one line each" :order 160) (words)
  (join-lines (map 'list
                   (lambda (tool)
                     (format nil "~a — ~a" (jstring tool "name")
                             (first-sentence (jstring tool "description"))))
                   (engine-tools))))

(define-slash "doc" (:immediate t :usage "<tool>" :description "what one tool does and the arguments it takes"
                     :order 170)
    (words)
  (if (null words)
      (values "Usage: /re doc <tool>" t)
      (let* ((name (engine-name (first words)))
             (found (find name (engine-tools) :key (lambda (tool) (jstring tool "name")) :test #'string=)))
        (unless found
          (fail "omp-re: no tool named ~a~a" (js-string name) (voice :list-tools)))
        (format nil "~a~%~a~%~?~%~{~a~^~%~}"
                name (jstring found "description") (voice :doc-takes) (list name)
                (or (parameter-lines (jget found "parameters")) '("  nothing"))))))

;;; --- lists -------------------------------------------------------------------------------------

(defun rizin-rows (command)
  "The rows of the JSON array COMMAND prints on the session's rizin."
  (jlist (rz-cmdj (ensure-rizin) command)))

(define-list "functions" (:description "the functions rizin found, with address and size" :order 20
                          :enter "open")
  (loop for function in (rizin-rows "aflj")
        for addr = (row-address function)
        for size = (or (jnumber function "realsz") (jnumber function "size"))
        when addr
          collect (let ((ea (ea-from-offset addr)))
                    (list-row ea (jstring function "name")
                              :description (format nil "~a~@[ · ~db~]" ea size)
                              :enter (code-request ea (jstring function "name"))))))

(define-list "strings" (:description "the strings rizin found, with address" :order 30 :enter "open")
  (loop for entry in (rizin-rows "izj")
        when (jnumber entry "vaddr")
          collect (let ((ea (ea-from-offset (jnumber entry "vaddr"))))
                    (list-row ea (jstring entry "string") :description ea
                              :line (format nil "~a  ~a" ea (jstring entry "string"))
                              :enter (view-request "string-xrefs" "addr" ea "label" (jstring entry "string"))))))

(define-list "imports" (:description "the imports, with address" :order 40 :enter "open")
  (loop for entry in (rizin-rows "iij")
        ;; An import that is bound at load time has no stub of its own.
        collect (let ((ea (and (jnumber entry "plt") (plusp (jnumber entry "plt"))
                               (ea-from-offset (jnumber entry "plt")))))
                  (list-row (or ea "") (jstring entry "name") :description (or ea "(no PLT)")
                            :line (format nil "~a~@[  ~a~]" (jstring entry "name") ea)
                            :enter (view-request "import-callers" "addr" (or ea "")
                                                 "name" (jstring entry "name"))))))

;;; --- evidence ----------------------------------------------------------------------------------

(defun named-evidence (id)
  "The evidence record the operator's ID names => (values RECORD NIL), or
(values NIL WHY-NOT) in the line's words."
  (multiple-value-bind (record reason why) (find-evidence id)
    (cond (record (values record nil))
          ((eq why :missing) (values nil (format nil "omp-re: no evidence found with id ~a" id)))
          (t (values nil (format nil "omp-re: evidence id ~a" reason))))))

(defun evidence-detail (record)
  (format nil "[~a:~a]~%~%~a~@[~%~%full output: ~a~]"
          (jstring record "tool") (or (jstring record "ea") "?") (jstring record "summary")
          (and (jstring record "artifactId") (locate-artifact (jstring record "artifactId")))))

(define-list "evidence" (:description "evidence recorded on this branch" :order 50
                         :enter "cite"
                         :one (lambda (id)
                                (multiple-value-bind (record why-not) (named-evidence id)
                                  (if record
                                      (evidence-detail record)
                                      (values why-not t)))))
  (mapcar (lambda (record)
            (list-row (jstring record "id")
                      (format nil "[~a] ~a" (shown-id (jstring record "id")) (evidence-place record))
                      :description (let ((line (or (first (split-lines (jstring record "summary"))) "")))
                                     (subseq line 0 (min 80 (length line))))
                      :enter (obj "draft" (format nil "~a~%~%" (cite-text record)))))
          (evidence-records)))

(define-slash "cite" (:usage "<id>" :description "an evidence record as the opening of a message about it" :order 60)
    (words)
  (if (null words)
      (values "Usage: /re cite <id>" t)
      (multiple-value-bind (record why-not) (named-evidence (first words))
        (if (null record)
            (values why-not t)
            (cite-text record)))))
