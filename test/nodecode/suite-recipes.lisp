;;;; suite-recipes.lisp --- the recipe verbs (re:triage, re:scan-imports,
;;;; re:inspect-function, re:find-comparisons, re:find-crypto) as the engine
;;;; sees them, the directory allow-list, and the changed-on-disk line.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; What a recipe's report says, line for line, is not checked here: its
;;;; wording and tables are data (recipes/tables.json, which
;;;; scripts/gen-recipes.ts refuses to generate from when a table is unsound),
;;;; and test/recipes-eval.test.ts holds the whole of every report to what
;;;; omp's two eval kernels answer. Here is what only this engine can show:
;;;; that each read is a real, audited, re-runnable record, that a finding
;;;; can cite it, that `/re off' stops a recipe, the bounds and the refusals.

(in-package #:nodecode-re-test)

(defun cited-ids (text)
  "Every evidence id TEXT cites, in order, without duplicates."
  (let ((ids '()))
    (ppcre:do-register-groups (id) ("\\[evidence ([0-9a-f]{8})\\]" text)
      (pushnew id ids :test #'string=))
    (nreverse ids)))

(defun write-octets (path octets)
  (with-open-file (out path :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
    (write-sequence (coerce octets '(vector (unsigned-byte 8))) out))
  path)

(defun hex-octets (hex)
  (loop for i from 0 below (length hex) by 2
        collect (parse-integer hex :start i :end (+ i 2) :radix 16)))

(defun recorded-commands (session-id)
  "The command of every evidence record of the session, oldest first."
  (mapcar (lambda (record) (gethash "command" (gethash "args" record)))
          (re::evidence-records (re::find-session session-id))))

;;; --- the allow-list ------------------------------------------------------------------------

(defun kept-out (path)
  "The allow-list's refusal of (re:open PATH), or NIL when the list let it
through — whatever became of the open after that."
  (let ((said (refusal (lambda () (re:open path)))))
    (and said (has "outside the directories" said) said)))

(suite "recipes: allowed directories")
(let* ((allowed (ensure-directories-exist (merge-pathnames "samples/" *scratch*)))
       (sibling (ensure-directories-exist (merge-pathnames "samples-evil/" *scratch*)))
       (inside (uiop:native-namestring (merge-pathnames "in.bin" allowed)))
       (outside (uiop:native-namestring (merge-pathnames "out.bin" sibling)))
       (link (uiop:native-namestring (merge-pathnames "link.bin" allowed))))
  (uiop:copy-file "/bin/sh" inside)
  (uiop:copy-file "/bin/sh" outside)
  (ignore-errors (sb-posix:symlink outside link))
  (with-cell (:allowed-dirs (list (uiop:native-namestring allowed)))
    (in-session ((fresh-session))
      (check "a file under an allowed directory may be opened"
             (not (kept-out inside)))
      (check "a file elsewhere is refused, naming the setting"
             (has "allowed_dirs" (kept-out "/bin/sh")))
      (check "a sibling directory whose name only starts the same is refused"
             (kept-out outside))
      (check "a link inside an allowed directory that points out of it is refused"
             (kept-out link))))
  (with-cell ()
    (in-session ((fresh-session))
      (check "with no allow-list any readable file may be opened"
             (not (kept-out "/bin/sh"))))))

;;; --- with rizin ---------------------------------------------------------------------------

(cond
  ((not *rizin*)
   (suite "recipes: rizin")
   (format t "  SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*))
  (t
   (suite (format nil "recipes: rizin (~a)" *binary*))
   (with-cell ()
     (let ((id (fresh-session)))
       (in-session (id)
         (check "the recipes are verbs, not tools: the tool list does not grow"
                (let ((tools (re:tools)))
                  (and (notany (lambda (name) (has name tools))
                               '("scan_imports" "inspect_function" "find_comparisons" "find_crypto"))
                       (every (lambda (name) (eq :external (nth-value 1 (find-symbol name "NODECODE-RE"))))
                              '("TRIAGE" "SCAN-IMPORTS" "INSPECT-FUNCTION" "FIND-COMPARISONS" "FIND-CRYPTO")))))
         (check "a recipe needs a binary open, like any read"
                (has "no binary open" (refusal (lambda () (re:triage)))))
         (re:open *binary*)

         (let* ((triage (re:triage))
                (ids (cited-ids triage))
                (session (re::find-session id)))
           (check "every part cites an evidence id, and every id cited is a real record of a rizin_command read"
                  (and (>= (length ids) 6)
                       (every (lambda (short)
                                (let ((record (re::find-evidence short session)))
                                  (and record (equal "rizin_command" (gethash "tool" record))
                                       (= 64 (length (gethash "reproHash" record))))))
                              ids)))
           (check "each read a recipe makes is a rizin_command call in the audit log"
                  (let ((log (re::read-text-file (re::state-path "audit" (format nil "~a.log" id)))))
                    (and (has "\"command\":\"iSj entropy\"" log) (has "\"command\":\"iej\"" log))))
           (check "/re off stops a recipe at its first read, like any call"
                  (let ((before (length (recorded-commands id))))
                    (re:slash "off")
                    (prog1 (and (has "RE tools are off" (refusal (lambda () (re:triage))))
                                (= before (length (recorded-commands id))))
                      (re:slash "on"))))
           (check "a finding can cite what triage read, and passes the gate"
                  (stringp (re:call "record_finding"
                                    :claim "The build has a stack canary and non-executable data pages."
                                    :evidence (list (first ids)) :confidence "confirmed")))
           (check "what triage read verifies like any other evidence"
                  (has "0 FAILED" (re:slash "verify")))
           (check "the list sizes are the caller's to bound, and a cut list says so"
                  (let ((short (re:triage :max-functions 2 :max-strings 1)))
                    (and (has "more functions not shown" short)
                         (< (length short) (length triage))))))

         (check "scan_imports without callers makes the one read"
                (let ((before (length (recorded-commands id))))
                  (re:scan-imports :callers :false)
                  (equal '("iij") (nthcdr before (recorded-commands id)))))

         (check "an address that is no function is refused in words"
                (has "no function at" (refusal (lambda () (re:inspect-function "0x1")))))
         (check "a function named by something other than a string is refused in the engine's voice, naming the recipe, before any read"
                (let ((before (length (recorded-commands id))))
                  (and (has "omp-re: inspect_function: a function is named by a string, not 4096"
                            (refusal (lambda () (re:inspect-function 4096))))
                       (has "omp-re: find_comparisons: a function is named by a string"
                            (refusal (lambda () (re:find-comparisons nil))))
                       (= before (length (recorded-commands id))))))
         (check "an address that could open another command is refused by the engine at the first read, and nothing is recorded of it"
                (let ((before (length (recorded-commands id))))
                  (and (has "invalid address" (refusal (lambda () (re:inspect-function "main;!id"))))
                       (has "invalid address" (refusal (lambda () (re:find-comparisons "main;!id"))))
                       (= before (length (recorded-commands id))))))

         (check "find_comparisons bounds its list and says what was left out"
                (has "more comparisons not shown" (re:find-comparisons "main" :max-items 20)))

         (check "in find_crypto every search is a read on the record, the ones that find nothing too"
                (let ((before (length (recorded-commands id))))
                  (re:find-crypto :references :false)
                  (let ((searches (remove-if-not (lambda (command) (re::starts-with "/xj " command))
                                                 (nthcdr before (recorded-commands id)))))
                    (and (plusp (length searches))
                         (= (length searches) (length (remove-duplicates searches :test #'string=)))
                         (= (1+ (length searches)) (- (length (recorded-commands id)) before))))))))

     ;; A file made of published constants: the recipe must find each where it lies.
     (let* ((id (fresh-session))
            (blob (uiop:native-namestring (merge-pathnames "tables.bin" *scratch*))))
       (write-octets blob (append (make-list 64 :initial-element 0)
                                  (hex-octets "637c777bf26b6fc53001672bfed7ab76")      ; AES S-box, at 0x40
                                  (make-list 48 :initial-element #x90)
                                  (hex-octets "982f8a4291443771cffbc0b5a5dbb5e9")      ; SHA-256 K, at 0x80
                                  (make-list 48 :initial-element 0)
                                  (hex-octets "657870616e642033322d62797465206b")      ; "expand 32-byte k", at 0xc0
                                  (make-list 64 :initial-element 0)))
       (in-session (id)
         (re:open blob :arch "x86" :bits 64 :format "any")
         (let ((crypto (re:find-crypto :references :false)))
           (check "find_crypto finds an AES S-box, SHA-256 constants and the ChaCha sigma where they lie"
                  (and (has "0x40  AES — S-box" crypto)
                       (has "0x80  SHA-256" crypto)
                       (has "0xc0  ChaCha / Salsa20" crypto)))
           (check "each hit cites the search that found it: three, and rizin's own search"
                  (= 4 (length (cited-ids crypto)))))))

     ;; The same name, different bytes.
     (let* ((id (fresh-session))
            (copy (uiop:native-namestring (merge-pathnames "moving.bin" *scratch*))))
       (uiop:copy-file *binary* copy)
       (in-session (id)
         (re:open copy)
         (check "a binary unchanged on disk is not called changed"
                (not (has "CHANGED ON DISK" (re:status))))
         (uiop:copy-file "/bin/sh" copy)
         (check "a binary rewritten since it was opened is called out in status"
                (has "CHANGED ON DISK" (re:status))))))))
