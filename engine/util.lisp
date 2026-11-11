;;;; util.lisp --- text, validators, and what a tool result is made of.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The validators and the quoting every model-supplied value passes through
;;;; before it reaches rizin's pipe; truncation; and the canonical projection
;;;; of rizin output that the reproducibility hashes are taken over. The
;;;; messages are fixed, word for word: the model has been taught to repair
;;;; from them.

(in-package #:omp-re)

;;; --- small things ---------------------------------------------------------------

(declaim (ftype (function ((or null string)) (values string &optional)) trimmed)
         (ftype (function ((or null string)) (values boolean &optional)) blank-p)
         (ftype (function (string) (values list &optional)) split-lines)
         (ftype (function (list) (values string &optional)) join-lines))
(defun trimmed (text)
  (string-trim '(#\Space #\Tab #\Return #\Newline) (or text "")))

(defun blank-p (text)
  (zerop (length (trimmed text))))

(defun split-lines (text)
  "TEXT's lines, as a split on newline gives them: a trailing newline leaves
an empty last line."
  (loop with start = 0
        for end = (position #\Newline text :start start)
        collect (subseq text start (or end (length text)))
        while end
        do (setf start (1+ end))))

(defun join-lines (lines)
  (format nil "~{~a~^~%~}" lines))

(defun unix-lines (text)
  "TEXT with each CRLF as one line feed: rizin and its sibling programs end
lines with CRLF on Windows."
  (ppcre:regex-replace-all "\\r\\n" text (string #\Newline)))

(defun path-basename (path)
  "The last component of the native PATH, read as text: a `*' or `[' in a
file's name is part of the name."
  (let ((slash (position-if (lambda (char) (find char "/\\")) path :from-end t)))
    (if slash (subseq path (1+ slash)) path)))

(defun words (text)
  (remove "" (uiop:split-string (or text "") :separator '(#\Space #\Tab #\Newline #\Return))
          :test #'string=))

(defun js-string (value)
  "VALUE the way JSON.stringify quotes a string in the engine's messages."
  (json-encode (if (stringp value) value (princ-to-string value))))

(defun utf-8-size (text)
  (length (sb-ext:string-to-octets text :external-format :utf-8)))

(defun clip-utf-8 (text max-octets)
  "TEXT cut to at most MAX-OCTETS of UTF-8, never inside a character."
  (if (<= (utf-8-size text) max-octets)
      text
      (let ((end (length text)) (size (utf-8-size text)))
        (loop while (> size max-octets)
              do (decf end)
                 (decf size (utf-8-size (string (char text end)))))
        (subseq text 0 end))))

(defun iso-now ()
  "The time as JavaScript's toISOString writes it: 2026-11-09T12:34:56.789Z."
  (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
    (multiple-value-bind (second minute hour day month year)
        (decode-universal-time (+ seconds #.(encode-universal-time 0 0 0 1 1 1970 0)) 0)
      (format nil "~4,'0d-~2,'0d-~2,'0dT~2,'0d:~2,'0d:~2,'0d.~3,'0dZ"
              year month day hour minute second (floor microseconds 1000)))))

(defun random-octets (count)
  "COUNT octets for an id: the kernel's where it offers a device, else — on
Windows, and where the device cannot be read — SBCL's own generator seeded
from the system."
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (unless #+win32 nil
            #-win32 (ignore-errors
                     (with-open-file (in "/dev/urandom" :element-type '(unsigned-byte 8))
                       (= count (read-sequence octets in))))
      (let ((state (sb-ext:seed-random-state t)))
        (dotimes (i count) (setf (aref octets i) (random 256 state)))))
    octets))

(declaim (ftype (function () (values record-id &optional)) uuid))
(defun uuid ()
  (let ((octets (random-octets 16)))
    (setf (aref octets 6) (logior #x40 (logand #x0f (aref octets 6)))
          (aref octets 8) (logior #x80 (logand #x3f (aref octets 8))))
    (let ((text (hex octets)))
      (format nil "~a-~a-~a-~a-~a" (subseq text 0 8) (subseq text 8 12) (subseq text 12 16)
              (subseq text 16 20) (subseq text 20)))))

(defun file-safe (name)
  "NAME as a file name of at most 128 characters: letters, digits, `.', `_'
and `-' kept, anything else an underscore."
  (let ((safe (map 'string (lambda (char)
                             (if (or (alphanumericp char) (find char "._-")) char #\_))
                   (subseq name 0 (min 128 (length name))))))
    (if (zerop (length safe)) "session" safe)))

(defun write-text-file (path text)
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output :if-exists :supersede :if-does-not-exist :create
                            :external-format :utf-8)
    (write-string text out))
  path)

(defun append-text-file (path text)
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output :if-exists :append :if-does-not-exist :create
                            :external-format :utf-8)
    (write-string text out)
    (finish-output out))
  path)

(defun write-octets-file (path octets)
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output :element-type '(unsigned-byte 8)
                            :if-exists :supersede :if-does-not-exist :create)
    (write-sequence octets out))
  path)

(defun read-text-file (path)
  "PATH's text, or NIL when it cannot be read. Bytes that are not UTF-8 read as ?."
  (handler-case
      (with-open-file (in path :external-format '(:utf-8 :replacement #\?))
        (let ((text (make-string (file-length in))))
          (subseq text 0 (read-sequence text in))))
    (error () nil)))

;;; --- patterns, read as JavaScript reads them -----------------------------------------
;;; The engine's patterns were written for JavaScript, where `$' is the end
;;; of the string and nothing else. In Perl syntax — cl-ppcre's
;;; — `$' also matches before a final newline, so "main\n" would pass a
;;; validator anchored with it, and a value ending in a newline ends the pipe
;;; line: what follows would run as a command of its own. Every pattern is
;;; therefore compiled through JS-SCANNER, which makes the anchor exact.

(defun js-scanner (regex)
  "A scanner for the pattern REGEX with JavaScript's `$': the very end."
  (ppcre:create-scanner
   (subst :modeless-end-anchor-no-newline :end-anchor (ppcre:parse-string regex))))

(defvar *js-scanners* (make-hash-table :test #'equal))
(defvar *js-scanners-lock* (sb-thread:make-mutex :name "omp-re patterns"))

(declaim (ftype (function (string string) (values boolean &optional)) js-scan))
(defun js-scan (regex text)
  "Whether the pattern REGEX matches in TEXT, as JavaScript's test() answers.
REGEX is a literal pattern; its scanner is compiled once."
  (let ((scanner (sb-thread:with-mutex (*js-scanners-lock*)
                   (or (gethash regex *js-scanners*)
                       (setf (gethash regex *js-scanners*) (js-scanner regex))))))
    (and (ppcre:scan scanner text) t)))

;;; --- validators: what may reach rizin's pipe ---------------------------------------

(defun validate-addr (addr)
  "ADDR when it is an address or expression of hex, flag names and
arithmetic. `@' is excluded so no value can smuggle in an iterator, and `(',
`;', `~', `|' and quotes so none can open a substitution, a separator, a grep
or a pipe."
  (unless (and (stringp addr) (js-scan "^[0-9a-zA-Z_.:$+-]+$" addr))
    (fail "omp-re: invalid address or expression: ~a" (js-string addr)))
  addr)

(defun normalize-addr (raw)
  "An address in one spelling — 0x, lowercase, no leading zeros — so 0x1100,
0X01100 and \"0x1100 \" key the same evidence; anything not 0x-prefixed is
lowercased as written."
  (let ((text (string-downcase (trimmed raw))))
    (if (not (uiop:string-prefix-p "0x" text))
        text
        (let ((digits (string-left-trim "0" (subseq text 2))))
          (cond ((= (length text) 2) "0x")
                ((zerop (length digits)) "0x0")
                (t (concatenate 'string "0x" digits)))))))

(defun validate-ident (key value)
  (unless (and (stringp value) (js-scan "^[A-Za-z_][A-Za-z0-9_.]*$" value))
    (fail "omp-re: invalid ~a: ~a" key (js-string value)))
  value)

(declaim (ftype (function ((integer 0)) (values address-text &optional)) ea-from-offset))
(defun ea-from-offset (offset)
  (format nil "0x~(~x~)" offset))

(defun ends-pipe-line-p (text)
  "Whether TEXT holds a line break or NUL: rizin reads its pipe a line at a
time, so either would end the command and start another."
  (and (find-if (lambda (char) (member char '(#\Newline #\Return #\Nul))) text) t))

(defun rz-quote (value)
  "VALUE as one single-quoted rizin argument. Inside single quotes rizin
takes `;', `@', `~', `|', `>', backticks, `$(...)' and `#' as text, so no
model-supplied comment or signature can end the command and start another."
  (when (ends-pipe-line-p value)
    (fail "omp-re: invalid argument: contains a newline or NUL"))
  (with-output-to-string (out)
    (write-char #\' out)
    (loop for char across value
          do (case char
               (#\\ (write-string "\\\\" out))
               (#\' (write-string "\\'" out))
               (t (write-char char out))))
    (write-char #\' out)))

(defun validate-type-like (key value)
  "VALUE when it carries no character no C type contains."
  (dolist (char '(#\; #\| #\& #\` #\$ #\Newline #\Nul) value)
    (when (find char value)
      (fail "omp-re: invalid ~a: forbidden character ~a" key (js-string (string char))))))

(defun validate-text (value)
  (when (ends-pipe-line-p value)
    (fail "omp-re: invalid text: contains forbidden character"))
  value)

;;; --- what a tool takes from its caller --------------------------------------------------

(defun plain-name-p (text)
  "Whether TEXT is a bare name — a register, a VM variable: a letter, then
letters, digits and underscores."
  (js-scan "^[A-Za-z][A-Za-z0-9_]*$" text))

(defun number-text-p (text)
  "Whether TEXT is a decimal or 0x hex number, the two forms rizin's
assignments take."
  (js-scan "^0x[0-9a-fA-F]+$|^[0-9]+$" text))

(defun hex-octets (text)
  "TEXT as the lowercase hex digits of whole octets — an optional 0x taken
off, blanks between octets dropped — or NIL when it is not that."
  (let* ((packed (ppcre:regex-replace-all "\\s+" text ""))
         (hex (if (js-scan "^0[xX]" packed) (subseq packed 2) packed)))
    (and (plusp (length hex)) (evenp (length hex)) (js-scan "^[0-9a-fA-F]+$" hex)
         (string-downcase hex))))

(defun clamped-count (value fallback most)
  "VALUE as a whole number between 1 and MOST; FALLBACK when none was given."
  (if (realp value)
      (max 1 (min (floor value) most))
      fallback))

;;; --- truncation ---------------------------------------------------------------------

(defparameter +max-lines+ 2000 "The most lines of a result the model is sent.")
(defparameter +max-octets+ (* 48 1024)
  "The most bytes of a result's body the model is sent: two KiB under omp's
own limit for a tool result, so that a header, a truncation note and an
evidence tag never push a result past it.")

(defun format-size (octets)
  (cond ((< octets 1024) (format nil "~dB" octets))
        ((< octets (* 1024 1024)) (format nil "~,1fKB" (/ octets 1024.0d0)))
        (t (format nil "~,1fMB" (/ octets (* 1024.0d0 1024))))))

(defun truncate-head (content)
  "Keep CONTENT's first lines within both limits, never a partial line.
=> (values KEPT TRUNCATED-P SHOWN-LINES TOTAL-LINES SHOWN-OCTETS TOTAL-OCTETS)"
  (let* ((total-octets (utf-8-size content))
         (lines (if (zerop (length content))
                    '()
                    (let ((lines (split-lines content)))
                      (if (uiop:string-suffix-p content (string #\Newline)) (butlast lines) lines))))
         (total-lines (length lines)))
    (cond ((and (<= total-lines +max-lines+) (<= total-octets +max-octets+))
           (values content nil total-lines total-lines total-octets total-octets))
          ((> (utf-8-size (or (first lines) "")) +max-octets+)
           (values "" t 0 total-lines 0 total-octets))
          (t (let ((kept '()) (octets 0))
               (loop for line in lines
                     for index from 0 below +max-lines+
                     for size = (+ (utf-8-size line) (if (plusp index) 1 0))
                     while (<= (+ octets size) +max-octets+)
                     do (push line kept)
                        (incf octets size))
               (setf kept (nreverse kept))
               (values (join-lines kept) t (length kept) total-lines octets total-octets))))))

;;; --- the canonical projection of rizin output ------------------------------------------

(defparameter +ansi-escape+ (ppcre:create-scanner "\\x1b\\[[0-9;?]*[A-Za-z]"))

(defun replace-all (text old new)
  (if (zerop (length old))
      text
      (with-output-to-string (out)
        (loop with start = 0
              for at = (search old text :start2 start)
              do (write-string text out :start start :end (or at (length text)))
              while at
              do (write-string new out)
                 (setf start (+ at (length old)))))))

(defun canonicalize-rizin-output (raw &optional binary-path)
  "RAW as an independent re-run on the same binary and rizin build would
print it: escapes stripped, line ends folded, lines right-trimmed, trailing
blank lines dropped, and the binary's own path redacted to <BINARY>."
  (let* ((text (ppcre:regex-replace-all +ansi-escape+ raw ""))
         (text (substitute #\Newline #\Return (unix-lines text)))
         (text (if (and binary-path (plusp (length binary-path)))
                   (replace-all text binary-path "<BINARY>")
                   text))
         (lines (mapcar (lambda (line) (string-right-trim '(#\Space #\Tab) line)) (split-lines text))))
    (loop while (and lines (string= "" (car (last lines))))
          do (setf lines (butlast lines)))
    (join-lines lines)))

(defun canonical-hash (raw &optional binary-path)
  (sha256-hex (canonicalize-rizin-output raw binary-path)))

(defun mask-addresses (canonical)
  "CANONICAL with the addresses that are positional, not semantic, masked,
so a rebuild that only moves code compares equal."
  (join-lines
   (mapcar
    (lambda (line)
      (when (js-scan "\\brip\\b" line)
        (setf line (ppcre:regex-replace-all "0x[0-9a-fA-F]+" line "<ADDR>")))
      (let* ((line (ppcre:regex-replace "^([\\s|\\\\/:.,=<>`'+*!^-]*)0x[0-9a-fA-F]+" line "\\1<ADDR>"))
             (line (ppcre:regex-replace-all "@ 0x[0-9a-fA-F]+" line "@ <ADDR>"))
             (line (ppcre:regex-replace-all
                    "\\b(call|jmp|j[a-z]{1,4}|bl|b|b\\.[a-z]{2}|cbn?z|tbn?z|loop[a-z]*)(\\s+)0x[0-9a-fA-F]+"
                    line "\\1\\2<ADDR>")))
        (ppcre:regex-replace-all "\\b(fcn|sub|loc|case|switch|entry|section)\\.[0-9a-fA-F]{4,}\\b"
                                 line "\\1.<ADDR>")))
    (split-lines canonical))))

(defun shift-hash (raw &optional binary-path)
  "SHA-256 of the address-masked canonical output: equal across builds that
differ only in where the code sits."
  (sha256-hex (mask-addresses (canonicalize-rizin-output raw binary-path))))

(defparameter +excerpt-lines+ 20)
(defparameter +excerpt-characters+ 1024
  "An excerpt this long was cut, mid-line.")

(defun canonical-excerpt (raw &optional binary-path)
  "The first lines of the canonical output, kept for a human to diff."
  (let* ((lines (split-lines (canonicalize-rizin-output raw binary-path)))
         (head (join-lines (subseq lines 0 (min +excerpt-lines+ (length lines))))))
    (if (<= (length head) +excerpt-characters+) head (subseq head 0 +excerpt-characters+))))
