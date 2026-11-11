;;;; sha256.lisp --- SHA-256, HMAC-SHA256, hex and base64, with no dependency.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The evidence store is content-addressed by SHA-256, an open binary is
;;;; bound to its evidence by the hash of its bytes, and the audit log is
;;;; signed with HMAC-SHA256. nodecode's core names no digest library a cell
;;;; may lean on, so the engine carries the forty lines FIPS 180-4 takes.
;;;; test/nodecode checks it against the published vectors and sha256sum.

(in-package #:omp-re)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(declaim (type (simple-array (unsigned-byte 32) (64)) +sha256-k+))
(defparameter +sha256-k+
  (coerce
   '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
     #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
     #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
     #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
     #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
     #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
     #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
     #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
   '(simple-array (unsigned-byte 32) (64))))

(defstruct (sha256 (:constructor %make-sha256) (:copier nil))
  (state (coerce '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                   #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
                 '(simple-array (unsigned-byte 32) (8)))
   :type (simple-array (unsigned-byte 32) (8)))
  (block (make-array 64 :element-type '(unsigned-byte 8)) :type octets)
  (fill 0 :type fixnum)
  (length 0 :type unsigned-byte))

(declaim (inline rotr32))
(defun rotr32 (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 1 31) n))
  (logand #xffffffff (logior (ash x (- n)) (ash x (- 32 n)))))

(defun sha256-compress (state block)
  (declare (type (simple-array (unsigned-byte 32) (8)) state) (type octets block)
           (optimize (speed 3) (safety 1)))
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    (declare (dynamic-extent w))
    (dotimes (i 16)
      (setf (aref w i)
            (logior (ash (aref block (* 4 i)) 24) (ash (aref block (+ 1 (* 4 i))) 16)
                    (ash (aref block (+ 2 (* 4 i))) 8) (aref block (+ 3 (* 4 i))))))
    (loop for i from 16 below 64
          do (let* ((x (aref w (- i 15))) (y (aref w (- i 2)))
                    (s0 (logxor (rotr32 x 7) (rotr32 x 18) (ash x -3)))
                    (s1 (logxor (rotr32 y 17) (rotr32 y 19) (ash y -10))))
               (setf (aref w i)
                     (logand #xffffffff (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))
    (let ((a (aref state 0)) (b (aref state 1)) (c (aref state 2)) (d (aref state 3))
          (e (aref state 4)) (f (aref state 5)) (g (aref state 6)) (h (aref state 7)))
      (declare (type (unsigned-byte 32) a b c d e f g h))
      (dotimes (i 64)
        (let* ((s1 (logxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25)))
               (ch (logxor (logand e f) (logand (logxor e #xffffffff) g)))
               (t1 (logand #xffffffff (+ h s1 ch (aref +sha256-k+ i) (aref w i))))
               (s0 (logxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22)))
               (maj (logxor (logand a b) (logand a c) (logand b c)))
               (t2 (logand #xffffffff (+ s0 maj))))
          (declare (type (unsigned-byte 32) s1 ch t1 s0 maj t2))
          (setf h g g f f e
                e (logand #xffffffff (+ d t1))
                d c c b b a
                a (logand #xffffffff (+ t1 t2)))))
      (macrolet ((add (index value)
                   `(setf (aref state ,index) (logand #xffffffff (+ (aref state ,index) ,value)))))
        (add 0 a) (add 1 b) (add 2 c) (add 3 d) (add 4 e) (add 5 f) (add 6 g) (add 7 h))))
  state)

(defun sha256-update (digest octets &key (start 0) (end (length octets)))
  (declare (type sha256 digest) (type octets octets) (type fixnum start end))
  (let ((block (sha256-block digest)))
    (incf (sha256-length digest) (- end start))
    (loop while (< start end)
          do (let ((take (min (- 64 (sha256-fill digest)) (- end start))))
               (replace block octets :start1 (sha256-fill digest) :start2 start :end2 (+ start take))
               (incf (sha256-fill digest) take)
               (incf start take)
               (when (= (sha256-fill digest) 64)
                 (sha256-compress (sha256-state digest) block)
                 (setf (sha256-fill digest) 0)))))
  digest)

(defun sha256-finish (digest)
  (let* ((bits (* 8 (sha256-length digest)))
         (pad (let ((rest (mod (+ (sha256-length digest) 1 8) 64)))
                (if (zerop rest) 0 (- 64 rest))))
         (tail (make-array (+ 1 pad 8) :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref tail 0) #x80)
    (dotimes (i 8)
      (setf (aref tail (- (length tail) 1 i)) (ldb (byte 8 (* 8 i)) bits)))
    (sha256-update digest tail)
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 8 out)
        (let ((word (aref (sha256-state digest) i)))
          (dotimes (j 4)
            (setf (aref out (+ (* 4 i) j)) (ldb (byte 8 (* 8 (- 3 j))) word))))))))

(defun sha256-octets (octets)
  (sha256-finish (sha256-update (%make-sha256) octets)))

(defun utf-8 (string)
  (coerce (sb-ext:string-to-octets string :external-format :utf-8) 'octets))

(defun hex (octets)
  (with-output-to-string (out)
    (loop for octet across octets do (format out "~(~2,'0x~)" octet))))

(defun sha256-hex (string)
  (hex (sha256-octets (utf-8 string))))

(defun sha256-file (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((digest (%make-sha256))
          (buffer (make-array 65536 :element-type '(unsigned-byte 8))))
      (loop for read = (read-sequence buffer in)
            while (plusp read)
            do (sha256-update digest buffer :end read))
      (hex (sha256-finish digest)))))

(defun hmac-sha256 (key message)
  (let* ((key (if (> (length key) 64) (sha256-octets key) key))
         (inner (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x36))
         (outer (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x5c)))
    (dotimes (i (length key))
      (setf (aref inner i) (logxor (aref inner i) (aref key i))
            (aref outer i) (logxor (aref outer i) (aref key i))))
    (let ((digest (%make-sha256)))
      (sha256-update digest inner)
      (sha256-update digest message)
      (let ((first (sha256-finish digest))
            (digest (%make-sha256)))
        (sha256-update digest outer)
        (sha256-update digest first)
        (sha256-finish digest)))))

(defun base64 (octets)
  (let ((alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))
    (with-output-to-string (out)
      (loop for i from 0 below (length octets) by 3
            do (let* ((a (aref octets i))
                      (b (and (< (+ i 1) (length octets)) (aref octets (+ i 1))))
                      (c (and (< (+ i 2) (length octets)) (aref octets (+ i 2))))
                      (triple (logior (ash a 16) (ash (or b 0) 8) (or c 0))))
                 (write-char (char alphabet (ldb (byte 6 18) triple)) out)
                 (write-char (char alphabet (ldb (byte 6 12) triple)) out)
                 (write-char (if b (char alphabet (ldb (byte 6 6) triple)) #\=) out)
                 (write-char (if c (char alphabet (ldb (byte 6 0) triple)) #\=) out))))))
