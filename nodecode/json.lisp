;;;; json.lisp --- the engine's own JSON: read, and written in a fixed order.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The engine signs what it writes (the audit log's HMAC is over a line's
;;;; exact bytes) and hashes what it stores, so the text an object encodes to
;;;; has to be a fact of this file and not of whichever codec the host image
;;;; carries. The shapes are the ones nodecode's kernel uses, so a value
;;;; passes between them unchanged: an object is an EQUAL hash table, written
;;;; in insertion order (SBCL iterates a table nothing was removed from in
;;;; that order); an array is a simple vector; true is T, false is NIL, null
;;;; is :NULL. The writer matches JavaScript's JSON.stringify byte for byte
;;;; for the values the engine writes, which is what lets a record written
;;;; here verify under omp and the other way round.

(in-package #:nodecode-re)

(define-condition json-refusal (error)
  ((detail :initarg :detail :reader json-refusal-detail))
  (:report (lambda (condition stream)
             (format stream "not JSON: ~a" (json-refusal-detail condition)))))

(defun json-decode (source)
  "The value the JSON text SOURCE spells; text after the first value is ignored.
Signals JSON-REFUSAL on anything else."
  (let ((index 0) (end (length source)))
    (labels ((refuse (control &rest arguments)
               (error 'json-refusal :detail (format nil "~? at ~a" control arguments index)))
             (peek () (and (< index end) (char source index)))
             (skip ()
               (loop while (and (< index end)
                                (member (char source index) '(#\Space #\Tab #\Newline #\Return)))
                     do (incf index)))
             (expect (word value)
               (unless (and (<= (+ index (length word)) end)
                            (string= word source :start2 index :end2 (+ index (length word))))
                 (refuse "expected ~a" word))
               (incf index (length word))
               value)
             (hex4 ()
               (unless (<= (+ index 4) end) (refuse "a cut \\u escape"))
               (prog1 (or (parse-integer source :start index :end (+ index 4) :radix 16 :junk-allowed t)
                          (refuse "a bad \\u escape"))
                 (incf index 4)))
             (read-string ()
               (incf index)
               (with-output-to-string (out)
                 (loop
                   (unless (< index end) (refuse "an unterminated string"))
                   (let ((char (char source index)))
                     (incf index)
                     (case char
                       (#\" (return))
                       (#\\ (unless (< index end) (refuse "a cut escape"))
                        (let ((escape (char source index)))
                          (incf index)
                          (case escape
                            (#\n (write-char #\Newline out))
                            (#\t (write-char #\Tab out))
                            (#\r (write-char #\Return out))
                            (#\b (write-char #\Backspace out))
                            (#\f (write-char #\Page out))
                            (#\u (let ((code (hex4)))
                                   (when (and (<= #xd800 code #xdbff)
                                              (<= (+ index 6) end)
                                              (string= "\\u" source :start2 index :end2 (+ index 2)))
                                     (incf index 2)
                                     (let ((low (hex4)))
                                       (setf code (+ #x10000 (ash (- code #xd800) 10) (- low #xdc00)))))
                                   (write-char (code-char code) out)))
                            (t (write-char escape out)))))
                       (t (write-char char out)))))))
             (read-number ()
               (let ((start index))
                 (loop while (and (< index end) (find (char source index) "+-0123456789.eE"))
                       do (incf index))
                 (when (= start index) (refuse "~s begins no value" (peek)))
                 (let ((text (subseq source start index)))
                   (handler-case
                       (if (find-if (lambda (char) (find char ".eE")) text)
                           (let ((*read-default-float-format* 'double-float)
                                 (*read-eval* nil))
                             (coerce (read-from-string text) 'double-float))
                           (parse-integer text))
                     (error () (refuse "~s is not a number" text))))))
             (read-value ()
               (skip)
               (case (peek)
                 ((nil) (refuse "the text ends where a value belongs"))
                 (#\{ (incf index)
                  (let ((object (make-hash-table :test #'equal)))
                    (skip)
                    (if (eql (peek) #\})
                        (incf index)
                        (loop
                          (skip)
                          (unless (eql (peek) #\") (refuse "an object key must be a string"))
                          (let ((key (read-string)))
                            (skip)
                            (expect ":" nil)
                            (setf (gethash key object) (read-value)))
                          (skip)
                          (if (eql (peek) #\,)
                              (incf index)
                              (progn (expect "}" nil) (return)))))
                    object))
                 (#\[ (incf index)
                  (let ((items '()))
                    (skip)
                    (if (eql (peek) #\])
                        (incf index)
                        (loop
                          (push (read-value) items)
                          (skip)
                          (if (eql (peek) #\,)
                              (incf index)
                              (progn (expect "]" nil) (return)))))
                    (coerce (nreverse items) 'simple-vector)))
                 (#\" (read-string))
                 (#\t (expect "true" t))
                 (#\f (expect "false" nil))
                 (#\n (expect "null" :null))
                 (t (read-number)))))
      (read-value))))

(defun json-parse (text)
  "TEXT's JSON value, or NIL when TEXT is not JSON (and for JSON false)."
  (handler-case (json-decode text)
    (json-refusal () nil)))

(defun write-json-string (string out)
  "STRING as JSON.stringify writes one."
  (write-char #\" out)
  (loop for char across string
        for code = (char-code char)
        do (case char
             (#\" (write-string "\\\"" out))
             (#\\ (write-string "\\\\" out))
             (#\Newline (write-string "\\n" out))
             (#\Return (write-string "\\r" out))
             (#\Tab (write-string "\\t" out))
             (#\Backspace (write-string "\\b" out))
             (#\Page (write-string "\\f" out))
             (t (if (< code 32)
                    (format out "\\u~(~4,'0x~)" code)
                    (write-char char out)))))
  (write-char #\" out))

(defun write-json (value out &optional indent (depth 0))
  "VALUE as JSON on OUT: compact, or with INDENT spaces a level as
JSON.stringify(value, null, INDENT) lays it out."
  (flet ((newline (depth)
           (when indent
             (write-char #\Newline out)
             (loop repeat (* indent depth) do (write-char #\Space out)))))
    (cond ((eq value t) (write-string "true" out))
          ((null value) (write-string "false" out))
          ((eq value :null) (write-string "null" out))
          ((stringp value) (write-json-string value out))
          ((integerp value) (format out "~d" value))
          ((floatp value)
           ;; An integral double prints as JavaScript prints it: no fraction.
           (if (and (= value (ffloor value)) (< (abs value) 1d15))
               (format out "~d" (truncate value))
               (let ((*read-default-float-format* 'double-float))
                 (format out "~f" value))))
          ((symbolp value) (write-json-string (string-downcase (symbol-name value)) out))
          ((hash-table-p value)
           (if (zerop (hash-table-count value))
               (write-string "{}" out)
               (let ((first t))
                 (write-char #\{ out)
                 (maphash (lambda (key member)
                            (if first (setf first nil) (write-char #\, out))
                            (newline (1+ depth))
                            (write-json-string key out)
                            (write-string (if indent ": " ":") out)
                            (write-json member out indent (1+ depth)))
                          value)
                 (newline depth)
                 (write-char #\} out))))
          ((vectorp value)
           (if (zerop (length value))
               (write-string "[]" out)
               (progn
                 (write-char #\[ out)
                 (loop for item across value
                       for first = t then nil
                       do (unless first (write-char #\, out))
                          (newline (1+ depth))
                          (write-json item out indent (1+ depth)))
                 (newline depth)
                 (write-char #\] out))))
          ((listp value) (write-json (coerce value 'simple-vector) out indent depth))
          (t (error "no JSON form for ~s" value)))))

(defun json-encode (value &key indent)
  (with-output-to-string (out) (write-json value out indent)))

(defun obj (&rest pairs)
  "A JSON object from alternating key and value PAIRS, in that order. A pair
whose value is the keyword :ABSENT is left out, so an optional member is
written inline: (obj \"ea\" (or ea :absent))."
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on pairs by #'cddr
          do (unless (eq value :absent)
               (setf (gethash key object) value)))
    object))

(defun jget (object &rest path)
  "The member of the decoded JSON OBJECT at the string keys PATH, with null
read as NIL; NIL as soon as a step is not an object."
  (let ((value object))
    (dolist (key path)
      (if (hash-table-p value)
          (setf value (gethash key value))
          (return-from jget nil)))
    (if (eq value :null) nil value)))

(defun jstring (object &rest path)
  (let ((value (apply #'jget object path)))
    (and (stringp value) value)))

(defun jstring-or-absent (object &rest path)
  "The member at PATH when it is a string, else :ABSENT — for OBJ, which
leaves an absent member out."
  (or (apply #'jstring object path) :absent))

(defun jstrings (object &rest path)
  "The strings of the array at PATH, as a list."
  (remove-if-not #'stringp (apply #'jlist object path)))

(defun jnumber (object &rest path)
  (let ((value (apply #'jget object path)))
    (and (realp value) value)))

(defun jlist (object &rest path)
  "The member at PATH when it is an array, as a list; else NIL."
  (let ((value (apply #'jget object path)))
    (and (vectorp value) (not (stringp value)) (coerce value 'list))))

(defun json-array-p (value)
  "Whether VALUE is a decoded JSON array: a vector that is not a string."
  (and (vectorp value) (not (stringp value))))

(defun format-json (data)
  "JSON for a model's context: an array is one compact row a line, anything
else is pretty-printed. Both are valid JSON."
  (cond ((not (and (vectorp data) (not (stringp data)))) (json-encode data :indent 2))
        ((zerop (length data)) "[]")
        (t (format nil "[~%~{  ~a~^,~%~}~%]" (map 'list #'json-encode data)))))
