;;;; slash-lines.lisp --- /re help, open, on, off, status, the lists, evidence, cite.
;;;;
;;;; SPDX-License-Identifier: MIT

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

(defun decompiler-commands ()
  "The decompiler commands to look for, OMPRE_DECOMPILER's first."
  (remove-duplicates
   (append (remove-if-not (lambda (name) (js-scan "^[a-zA-Z][a-zA-Z0-9]*$" name))
                          (mapcar #'trimmed
                                  (uiop:split-string (or (setting-value :decompiler) "")
                                                     :separator '(#\,))))
           (list "pdg" "pdd"))
   :test #'string= :from-end t))

(defun decompiler-label (kind)
  (cond ((equal kind "pdg") "rz-ghidra (pdg)")
        ((equal kind "pdd") "jsdec (pdd)")
        (kind (format nil "~a (plugin)" kind))
        (t "none — pdg/pdd fall back to labeled disassembly")))

(defun rizin-status-lines ()
  (let ((version (rizin-version))
        ;; A rizin that cannot be asked for its catalog is said by the first line.
        (catalog (ignore-errors (load-catalog))))
    (cons (format nil "rizin: ~a" (or version (format nil "not found (~a)" (resolve-rizin-path))))
          (when catalog
            (let ((missing (missing-required-commands catalog))
                  (present (remove-if-not (lambda (command) (nth-value 1 (gethash command catalog)))
                                          (decompiler-commands))))
              (append
               (list (if missing
                         (missing-commands-warning missing)
                         (format nil "rizin commands: all ~d omp-re sends are present (~d in this build; rizin_help searches them)"
                                 (length +required-commands+) (hash-table-count catalog)))
                     (format nil "decompiler: ~a" (decompiler-label (first present))))
               (when (rest present)
                 (list (format nil "  also available: ~{~a~^, ~} (reorder with OMPRE_DECOMPILER)"
                               (mapcar #'decompiler-label (rest present)))))))))))

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

(defparameter +list-characters+ 4000 "How much of a list a notice can carry.")

(defun clip-list (title lines)
  (let ((text (format nil "~a~%~a" title (if lines (join-lines lines) "(nothing to show)"))))
    (if (> (length text) +list-characters+)
        (format nil "~a~%… cut at ~d characters; ~a"
                (subseq text 0 +list-characters+) +list-characters+ (voice :read-more))
        text)))

(define-slash "functions" (:description "the functions rizin found, with address and size" :order 20
                           :row (30 "Functions"))
    (words)
  (clip-list "omp-re: functions"
             (loop for function in (coerce (or (rz-cmdj (ensure-rizin) "aflj") #()) 'list)
                   for addr = (or (jnumber function "addr") (jnumber function "offset"))
                   for size = (or (jnumber function "realsz") (jnumber function "size"))
                   when addr
                     collect (format nil "~a  ~a~@[ · ~db~]" (jstring function "name")
                                     (ea-from-offset addr) size))))

(define-slash "strings" (:description "the strings rizin found, with address" :order 30
                         :row (40 "Strings"))
    (words)
  (clip-list "omp-re: strings"
             (loop for entry in (coerce (or (rz-cmdj (ensure-rizin) "izj") #()) 'list)
                   when (jnumber entry "vaddr")
                     collect (format nil "~a  ~a" (ea-from-offset (jnumber entry "vaddr"))
                                     (jstring entry "string")))))

(define-slash "imports" (:description "the imports, with address" :order 40 :row (50 "Imports"))
    (words)
  (clip-list "omp-re: imports"
             (loop for entry in (coerce (or (rz-cmdj (ensure-rizin) "iij") #()) 'list)
                   collect (format nil "~a~@[  ~a~]" (jstring entry "name")
                                   (and (jnumber entry "plt") (ea-from-offset (jnumber entry "plt")))))))

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

(define-slash "evidence" (:usage "[id]" :description "evidence recorded on this branch" :order 50
                          :row (60 "Evidence" :detail "what has been observed on this branch"))
    (words)
  (if words
      (multiple-value-bind (record why-not) (named-evidence (first words))
        (if record
            (evidence-detail record)
            (values why-not t)))
      (clip-list "omp-re: evidence"
                 (mapcar (lambda (record)
                           (format nil "[~a] ~a @ ~a~@[  ~a~]"
                                   (shown-id (jstring record "id")) (jstring record "tool")
                                   (or (jstring record "ea") "?")
                                   (let ((line (first (split-lines (jstring record "summary")))))
                                     (and line (subseq line 0 (min 80 (length line)))))))
                         (evidence-records)))))

(define-slash "cite" (:usage "<id>" :description "cite an evidence entry in your next message" :order 60
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
