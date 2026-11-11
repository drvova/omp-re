;;;; protocol.lisp --- the wire between omp and the engine, read from its one description.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; stdio/protocol.json says what may be said on the pipe: every method
;;;; each way, whether it is a request or a notification, its members and
;;;; their types, the version, and the constants both sides share. omp's
;;;; side is generated from the same file (scripts/gen-protocol.ts writes
;;;; extensions/re/protocol.ts and the tables of docs/engine-protocol.md),
;;;; so neither side holds a copy that can drift. Here it is loaded, and
;;;; what the server reads and writes is held to it: a method, a member or a
;;;; value the file does not have is an error, never a default.
;;;;
;;;; A type is one of
;;;;   "string" "integer" "number" "boolean" "null"
;;;;   "object"                 any JSON object
;;;;   "json"                   any JSON value
;;;;   "@name"                  the type NAME of the file's `types'
;;;;   {"enum": [...]}          one of these strings
;;;;   {"array": T}  {"tuple": [T...]}  {"map": T}  {"oneOf": [T...]}
;;;;   {"members": {...}}       an object of exactly these members; a name
;;;;                            ending in ? may be absent
;;;;
;;;; This file also makes the host's package.

(defpackage #:omp-re-stdio
  (:use #:cl #:omp-re)
  (:export #:serve #:+protocol+))

(in-package #:omp-re-stdio)

(defparameter *protocol*
  (let ((file (asdf:system-relative-pathname "omp-re-stdio" "stdio/protocol.json")))
    (or (json-parse (uiop:read-file-string file :external-format :utf-8))
        (error "omp-re: ~a is not JSON" file)))
  "stdio/protocol.json, decoded.")

(defparameter +protocol+ (jget *protocol* "version")
  "The version of the wire. omp's side is refused unless it speaks the same.")

(defun protocol-constant (name)
  (multiple-value-bind (value found) (gethash name (jget *protocol* "constants"))
    (unless found (error "omp-re: the protocol has no constant ~a" name))
    value))

(define-condition wire-violation (error)
  ((detail :initarg :detail))
  (:report (lambda (condition stream)
             (format stream "omp-re: not the protocol (stdio/protocol.json): ~a"
                     (slot-value condition 'detail)))))

(defun violation (control &rest arguments)
  (error 'wire-violation :detail (apply #'format nil control arguments)))

(defun optional-member-p (name)
  (char= #\? (char name (1- (length name)))))

(defun member-name (name)
  (if (optional-member-p name) (subseq name 0 (1- (length name))) name))

(defun shown (value)
  (let ((text (handler-case (json-encode value) (error () (princ-to-string value)))))
    (if (> (length text) 80) (format nil "~a…" (subseq text 0 80)) text)))

(defun conform (type value where)
  "Signal WIRE-VIOLATION unless VALUE, a decoded JSON value at WHERE, is of
TYPE => VALUE."
  (flet ((need (holds expected)
           (unless holds (violation "~a must be ~a, not ~a" where expected (shown value)))))
    (cond
      ((stringp type)
       (cond ((char= #\@ (char type 0))
              (conform (or (jget *protocol* "types" (subseq type 1))
                           (error "omp-re: the protocol has no type ~a" type))
                       value where))
             ((string= type "string") (need (stringp value) "a string"))
             ((string= type "integer") (need (integerp value) "an integer"))
             ((string= type "number") (need (realp value) "a number"))
             ((string= type "boolean") (need (member value '(t nil)) "true or false"))
             ((string= type "null") (need (eq value :null) "null"))
             ((string= type "object") (need (hash-table-p value) "an object"))
             ((string= type "json"))
             (t (error "omp-re: the protocol names no type ~a" type))))
      ((gethash "enum" type)
       (need (and (stringp value) (find value (gethash "enum" type) :test #'equal))
             (format nil "one of ~{~a~^, ~}" (coerce (gethash "enum" type) 'list))))
      ((gethash "array" type)
       ;; A list is written as an array (engine/json.lisp), the empty list as false.
       (need (or (json-array-p value) (consp value)) "an array")
       (let ((index -1))
         (map nil (lambda (item)
                    (conform (gethash "array" type) item (format nil "~a[~d]" where (incf index))))
              value)))
      ((gethash "tuple" type)
       (let ((types (gethash "tuple" type)))
         (need (and (json-array-p value) (= (length value) (length types)))
               (format nil "an array of ~d" (length types)))
         (loop for item across value
               for index from 0
               do (conform (aref types index) item (format nil "~a[~d]" where index)))))
      ((gethash "map" type)
       (need (hash-table-p value) "an object")
       (maphash (lambda (key item) (conform (gethash "map" type) item (format nil "~a.~a" where key)))
                value))
      ((gethash "oneOf" type)
       (let ((reasons '()))
         (unless (some (lambda (one)
                         (handler-case (progn (conform one value where) t)
                           (wire-violation (condition)
                             (push (slot-value condition 'detail) reasons)
                             nil)))
                       (gethash "oneOf" type))
           ;; The case that got furthest says the most: its complaint is the longest path.
           (violation "~a" (first (sort reasons #'> :key #'length))))))
      ((nth-value 1 (gethash "members" type))
       (conform-members (gethash "members" type) value where))
      (t (error "omp-re: the protocol has a type that is none of its kinds: ~a" (shown type)))))
  value)

(defun conform-members (members value where)
  (unless (hash-table-p value)
    (violation "~a must be an object, not ~a" where (shown value)))
  (let ((known '()))
    (maphash (lambda (spelled type)
               (let ((name (member-name spelled)))
                 (push name known)
                 (multiple-value-bind (member found) (gethash name value)
                   (cond (found (conform type member (format nil "~a.~a" where name)))
                         ((not (optional-member-p spelled))
                          (violation "~a lacks ~a" where name))))))
             members)
    (maphash (lambda (name member)
               (declare (ignore member))
               (unless (member name known :test #'string=)
                 (violation "~a has no member ~a" where name)))
             value))
  value)

(defun method-described (direction method)
  "The protocol's description of METHOD in DIRECTION, \"toEngine\" or
\"toHost\". A method it does not have is a WIRE-VIOLATION."
  (or (and (stringp method) (jget *protocol* direction method))
      (violation "there is no ~a method ~a" (if (string= direction "toEngine") "engine" "omp") (shown method))))

(defun conform-params (direction method params &key request)
  "Hold PARAMS to what the protocol says METHOD takes; REQUEST says whether
it came, or goes, with an id. => PARAMS"
  (let ((described (method-described direction method)))
    (unless (eq (and request t) (string= "request" (gethash "kind" described)))
      (violation "~a is a ~a" method (gethash "kind" described)))
    (conform-members (gethash "params" described) params (format nil "~a's params" method))))

(defun conform-result (direction method result)
  (conform (gethash "result" (method-described direction method)) result (format nil "~a's result" method)))

(defun method-ordered-p (method)
  (eq t (jget *protocol* "toEngine" method "ordered")))
