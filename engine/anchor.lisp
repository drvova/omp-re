;;;; anchor.lisp --- a function's fingerprint, and finding the function again.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A report's manifest keeps, for each cited read pinned to an address, a
;;;; fingerprint of the function that address is in. /re carry uses it to find
;;;; the same code in another build, where the address and often the name
;;;; have changed. The fingerprint is the function's mnemonic sequence —
;;;; mnemonics, never operands, because a rebuild changes addresses and
;;;; registers long before it changes the instruction mix.

(in-package #:omp-re)

(defparameter +max-mnemonics+ 512
  "The most mnemonics kept in a fingerprint: plenty to identify a function,
few enough to keep the manifest and carry's comparison cheap.")

(defparameter +max-candidates+ 64
  "The most functions scored for one relocation; the size and block-count
prefilter usually leaves far fewer.")

(defparameter +relocate-threshold+ 4/5
  "The least mnemonic-sequence similarity at which a candidate counts as the
same function.")

(defun mnemonics-at (rz offset)
  "The mnemonic sequence of the function starting at OFFSET
=> (values MNEMONICS T), or (values NIL NIL) when rizin has no function
there — which is not the same as a function with no instructions."
  (let* ((listing (rz-cmdj rz (format nil "pdfj @ ~a" (ea-from-offset offset))))
         (ops (and (hash-table-p listing) (gethash "ops" listing))))
    (if (json-array-p ops)
        (let ((mnemonics (loop for op across ops
                               for text = (jstring op "disasm")
                               when (and text (not (equal (jget op "type") "invalid")))
                                 collect (string-downcase (or (first (words text)) "")))))
          (values (subseq mnemonics 0 (min +max-mnemonics+ (length mnemonics))) t))
        (values nil nil))))

(defun sequence-similarity (a b)
  "How alike the lists A and B are: 2·LCS / (|A| + |B|), a rational in [0, 1]."
  (if (and (null a) (null b))
      1
      (let* ((b (coerce b 'simple-vector))
             (width (length b))
             (previous (make-array (1+ width) :initial-element 0)))
        (dolist (item a)
          (let ((current (make-array (1+ width) :initial-element 0)))
            (loop for j from 1 to width
                  do (setf (aref current j)
                           (if (equal item (aref b (1- j)))
                               (1+ (aref previous (1- j)))
                               (max (aref previous j) (aref current (1- j))))))
            (setf previous current)))
        (/ (* 2 (aref previous width)) (+ (length a) width)))))

(defun relocate-anchor (rz fingerprint)
  "The function of the open build that best matches FINGERPRINT => an object
of its name (\"function\"), its start (\"offset\"), where to re-run the
command — the start plus the recorded delta (\"addr\") — and the
\"similarity\"; NIL when nothing is alike enough. Never signals.

The function list is first cut to sizes within half the recorded size and
block counts within half (and 2) of the recorded count, ranked by how close
both are, and only the nearest are scored by mnemonics. A tie goes to the
function with the recorded name."
  (ignore-errors
   (let* ((size (jnumber fingerprint "size"))
          (nbbs (jnumber fingerprint "nbbs"))
          (name (jstring fingerprint "function"))
          (wanted (jlist fingerprint "mnemonics"))
          (functions (jlist (rz-cmdj rz "aflj")))
          (near (remove-if-not
                 (lambda (function)
                   (and (hash-table-p function)
                        (jnumber function "offset") (jnumber function "size") (jnumber function "nbbs")
                        (<= (abs (- (jnumber function "size") size)) (* size 1/2))
                        (<= (abs (- (jnumber function "nbbs") nbbs)) (+ (* nbbs 1/2) 2))))
                 functions))
          (ranked (stable-sort near #'<
                               :key (lambda (function)
                                      (+ (if (zerop size)
                                             0
                                             (/ (abs (- (jnumber function "size") size)) size))
                                         (abs (- (jnumber function "nbbs") nbbs))))))
          (best nil)
          (best-similarity nil))
     (dolist (function (subseq ranked 0 (min +max-candidates+ (length ranked))))
       (multiple-value-bind (mnemonics found) (mnemonics-at rz (jnumber function "offset"))
         (when found
           (let ((similarity (sequence-similarity wanted mnemonics)))
             (when (or (null best)
                       (> similarity best-similarity)
                       (and (= similarity best-similarity) (equal (jstring function "name") name)))
               (setf best function best-similarity similarity))))))
     (when (and best (>= best-similarity +relocate-threshold+))
       (let ((thousandths (floor (+ (* best-similarity 1000) 1/2))))
         (obj "function" (or (jstring best "name") "")
              "offset" (ea-from-offset (jnumber best "offset"))
              "addr" (ea-from-offset (+ (jnumber best "offset") (jnumber fingerprint "delta")))
              ;; Three places, and a whole number written as one: manifests hold 1, not 1.0.
              "similarity" (if (zerop (mod thousandths 1000))
                               (/ thousandths 1000)
                               (/ thousandths 1000d0))))))))

(defun anchor-fingerprint (rz anchor)
  "A fingerprint of the function containing ANCHOR in the open build — name,
start, size, block count, the anchor's offset into it and its mnemonics.
NIL when the anchor is in no function or does not resolve; never signals."
  (ignore-errors
   (let* ((at (resolve-numeric-addr rz anchor))
          (function (function-row-at rz (ea-from-offset at)))
          (start (and function (jnumber function "offset")))
          (mnemonics (and start (mnemonics-at rz start))))
     (when mnemonics
       (obj "anchor" anchor
            "function" (or (jget function "name") :absent)
            "offset" (ea-from-offset start)
            "delta" (- at start)
            "size" (or (jget function "size") :absent)
            "nbbs" (or (jget function "nbbs") :absent)
            "mnemonics" (coerce mnemonics 'simple-vector))))))

(defun parse-anchor (raw)
  "RAW as a fingerprint, or NIL when it is not one — the entry then just
cannot be relocated. Untrusted: the name and the offset are only shown, the
delta becomes part of an address (so it must be a small whole number) and
the mnemonics only feed the similarity score."
  (flet ((whole (key most)
           (let ((value (gethash key raw)))
             (and (realp value) (= value (ffloor value)) (<= 0 value most) (truncate value)))))
    (when (hash-table-p raw)
      (let ((delta (whole "delta" (ash 1 24)))
            (size (whole "size" (ash 1 30)))
            (nbbs (whole "nbbs" (ash 1 24)))
            (mnemonics (gethash "mnemonics" raw)))
        (when (and (jstring raw "anchor") (jstring raw "function") (jstring raw "offset")
                   delta size nbbs
                   (json-array-p mnemonics) (plusp (length mnemonics)) (every #'stringp mnemonics))
          (obj "anchor" (jstring raw "anchor")
               "function" (jstring raw "function")
               "offset" (jstring raw "offset")
               "delta" delta "size" size "nbbs" nbbs
               "mnemonics" mnemonics))))))
