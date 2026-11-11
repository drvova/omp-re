;;;; slash-lines.lisp --- /re help, open, on, off, status, the lists, evidence, cite.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; What a row of a list does when it is chosen on a screen is a view
;;;; (views.lisp), named here by the request for it.

(in-package #:omp-re)

(define-slash "help" (:immediate t :description "show this list" :order 150 :row (140 "Help")) (words)
  (slash-help))

(define-slash "open" (:usage "<path>" :description "open a binary and analyze it with rizin" :order 10
                      :row (10 "Open a binary" :ask "Path" :placeholder "/path/to/binary" :verb "open"))
    (words path)
  (if (null words)
      (values "Usage: /re open <path>" t)
      (multiple-value-bind (text failures) (open-binary path)
        (values text nil (and (plusp failures) (list :level :warning))))))

(define-slash "on" (:immediate t :description "enable the RE tools for this session" :order 130
                    :row (130 "Turn the tools on"))
    (words)
  (setf (session-tools-off *session*) nil)
  "omp-re: RE tools enabled for this session")

(define-slash "off" (:immediate t :description "disable the RE tools for this session" :order 140
                     :row (120 "Turn the tools off"))
    (words)
  (setf (session-tools-off *session*) t)
  "omp-re: RE tools disabled for this session — /re on to re-enable")

;;; --- /re status --------------------------------------------------------------------------------

(defun decompiler-label (kind)
  (cond ((equal kind "pdg") "rz-ghidra (pdg)")
        ((equal kind "pdd") "jsdec (pdd)")
        (kind (format nil "~a (plugin)" kind))
        (t "none — pdg and pdd need a decompiler plugin (rz-ghidra, jsdec)")))

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
                       (list "  CHANGED ON DISK since it was opened: evidence so far is of the earlier bytes — /re open it again to analyze what is there now"))))
              (unless (rz-alive-p (session-rz session))
                (list "rizin process: not running (starts on next use)")))
      (list "binary: none — /re open <path>")))

(define-slash "status" (:immediate t :description "rizin, decompiler, binary, and evidence status" :order 120
                        :row (20 "Status" :detail "rizin, the open binary, evidence and findings"))
    (words)
  (join-lines
   (append (rizin-status-lines)
           (binary-status-lines *session*)
           (loop for contribution in *contributions*
                 when (contribution-status contribution)
                   append (funcall (contribution-status contribution) *session*)))))

;;; --- lists -------------------------------------------------------------------------------------

(defun rizin-rows (command)
  "The rows of the JSON array COMMAND prints on the session's rizin."
  (jlist (rz-cmdj (ensure-rizin) command)))

(define-list "functions" (:description "the functions rizin found, with address and size" :order 20
                          :row (30 "Functions") :enter "open")
  (loop for function in (rizin-rows "aflj")
        for addr = (row-address function)
        for size = (or (jnumber function "realsz") (jnumber function "size"))
        when addr
          collect (let ((ea (ea-from-offset addr)))
                    (list-row ea (jstring function "name")
                              :description (format nil "~a~@[ · ~db~]" ea size)
                              :enter (code-request ea (jstring function "name"))))))

(define-list "strings" (:description "the strings rizin found, with address" :order 30
                        :row (40 "Strings") :enter "open")
  (loop for entry in (rizin-rows "izj")
        when (jnumber entry "vaddr")
          collect (let ((ea (ea-from-offset (jnumber entry "vaddr"))))
                    (list-row ea (jstring entry "string") :description ea
                              :line (format nil "~a  ~a" ea (jstring entry "string"))
                              :enter (view-request "string-xrefs" "addr" ea "label" (jstring entry "string"))))))

(define-list "imports" (:description "the imports, with address" :order 40 :row (50 "Imports") :enter "open")
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
                         :completes :evidence
                         :row (60 "Evidence" :detail "what has been observed on this branch")
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

(define-slash "cite" (:usage "<id>" :description "cite an evidence entry in your next message" :order 60
                      :completes :evidence
                      :row (70 "Cite evidence" :ask "Evidence id" :placeholder "1a2b3c4d" :verb "cite"))
    (words)
  (if (null words)
      (values "Usage: /re cite <id>" t)
      (multiple-value-bind (record why-not) (named-evidence (first words))
        (if (null record)
            (values why-not t)
            (let* ((shown (shown-id (jstring record "id")))
                   (text (cite-text record)))
              (values text nil
                      (list :draft (make-draft :text (format nil "~a~%~%" text)
                                               :notice (format nil "Evidence ~a is in your draft."
                                                               shown)))))))))
