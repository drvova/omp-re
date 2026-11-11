;;;; types.lisp --- the types of what crosses the engine's boundary.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A host and the engine exchange few kinds of thing: a session's id, JSON
;;;; as json.lisp reads and writes it, an answer, how loudly to say one, an
;;;; address, the id of a record, a hash. Each is a type here, and every
;;;; function engine/package.lisp exports is declared in those words beside
;;;; its definition (DECLAIM FTYPE). SBCL holds a declared function to its
;;;; type when it is called, and a caller to it when the caller is compiled:
;;;; a host that passes a list where an object belongs gets a warning, and
;;;; scripts/check-warnings.lisp makes that warning a failure.
;;;;
;;;; A type that is only a string by another name checks nothing a string
;;;; does not; it says which string is meant where a signature is read.

(in-package #:omp-re)

(deftype session-id ()
  "A host's own id for one of its sessions."
  'string)

(deftype json-object ()
  "A JSON object: an EQUAL hash table from member name to value, in the
order the members were put (OBJ, JSON-DECODE)."
  'hash-table)

(deftype json-array ()
  "A JSON array as it is decoded and as the engine answers one."
  'simple-vector)

(deftype json-value ()
  "Any value JSON-DECODE answers: true is T, false is NIL, null is :NULL."
  '(or json-object json-array string integer double-float (member t nil :null)))

(deftype answer ()
  "What a function of the surface answers a call or a /re line with: a JSON
object with at least `text' and `failed'."
  'json-object)

(deftype level ()
  "How loudly something is said to the operator."
  '(member :info :warning :error))

(defun address-text-p (value)
  (and (stringp value)
       (< 2 (length value))
       (string= "0x" value :end2 2)
       (every (lambda (char) (digit-char-p char 16)) (subseq value 2))
       (string= value (string-downcase value))))

(deftype address-text ()
  "An address as the engine writes one: 0x and lowercase hexadecimal digits.
An address travels as text because a 64-bit one does not survive a JSON
number in JavaScript."
  '(and string (satisfies address-text-p)))

(deftype record-id ()
  "The id of an evidence record or a finding. One made here is a UUID; one a
record carries from elsewhere is whatever it was given."
  'string)

(deftype evidence-id () 'record-id)
(deftype finding-id () 'record-id)

(defun sha256-hex-p (value)
  (and (stringp value)
       (= 64 (length value))
       (every (lambda (char) (find char "0123456789abcdef")) value)))

(deftype sha256-hex ()
  "A SHA-256 digest as 64 lowercase hexadecimal digits."
  '(and string (satisfies sha256-hex-p)))
