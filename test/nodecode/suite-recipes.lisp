;;;; suite-recipes.lisp --- the recipe verbs (re:triage, re:scan-imports,
;;;; re:inspect-function, re:find-comparisons, re:find-crypto), the directory
;;;; allow-list, and the changed-on-disk line.
;;;;
;;;; SPDX-License-Identifier: MIT

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

;;; --- the tables, with no rizin -----------------------------------------------------------

(suite "recipes: tables")
(check "an import is named as the tables spell it, whatever a linker or fortified libc added"
       (equal '("strcpy" "strcpy" "scanf" "gets" "CreateProcessA" "printf")
              (mapcar #'re::bare-import-name
                      '("__strcpy_chk" "sym.imp.strcpy" "__isoc99_scanf" "_gets" "imp.CreateProcessA" "__printf_chk"))))
(check "a risky import carries its category, severity and reason"
       (and (equal '("memory" "high") (subseq (re::risky-import "gets") 0 2))
            (equal "command" (first (re::risky-import "system")))
            (null (re::risky-import "strlen"))))
(check "a capability is read off an import, and one import can show two"
       (and (equal '("network") (re::import-capabilities "connect"))
            (member "anti-analysis" (re::import-capabilities "ptrace") :test #'string=)
            (member "process control" (re::import-capabilities "ptrace") :test #'string=)
            (null (re::import-capabilities "strlen"))))
(check "every constant in the crypto table is whole bytes of hex, and none is listed twice"
       (and (every (lambda (entry) (and (evenp (length (third entry))) (re::js-scan "^[0-9a-f]+$" (third entry))))
                   re::*crypto-constants*)
            (= (length re::*crypto-constants*)
               (length (remove-duplicates re::*crypto-constants* :key #'third :test #'string=)))))
(check "no import is in two risk rows, so a name has one verdict"
       (let ((names (loop for (nil nil nil . names) in re::*risky-imports* append names)))
         (= (length names) (length (remove-duplicates names :test #'string=)))))
(check "what a conditional jump tests is said in words"
       (and (has "not equal" (re::branch-meaning "jne"))
            (has "unsigned" (re::branch-meaning "JA"))
            (has "signed" (re::branch-meaning "jl"))))

;;; --- the allow-list, with no rizin ---------------------------------------------------------

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
    (check "a file under an allowed directory resolves"
           (has "in.bin" (re::resolve-binary-path inside)))
    (check "a file elsewhere is refused, naming the setting"
           (has "allowed_dirs" (refusal (lambda () (re::resolve-binary-path "/bin/sh")))))
    (check "a sibling directory whose name only starts the same is refused"
           (has "outside the directories" (refusal (lambda () (re::resolve-binary-path outside)))))
    (check "a link inside an allowed directory that points out of it is refused"
           (has "outside the directories" (refusal (lambda () (re::resolve-binary-path link)))))
    (check "the refusal reaches the model through the verb"
           (in-session ((fresh-session))
             (has "outside the directories" (refusal (lambda () (re:open "/bin/sh")))))))
  (with-cell ()
    (check "with no allow-list any readable file resolves"
           (has "sh" (re::resolve-binary-path "/bin/sh")))))

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
           (check "triage says what the binary is and which protections the build has"
                  (and (has "Identity" triage) (has "ELF" triage) (has "stack canary:" triage)
                       (has "NX:" triage) (has "PIE:" triage) (has "RELRO:" triage)))
           (check "it lists sections with their entropy, imports, strings, the largest functions and entry points"
                  (and (has ".text" triage) (has "entropy" triage) (has "Imports:" triage)
                       (has "Strings:" triage) (has "largest by code size" triage) (has "Entry points" triage)))
           (check "every part cites an evidence id, and every id cited is a real record of a rizin_command read"
                  (and (>= (length ids) 6)
                       (every (lambda (short)
                                (let ((record (re::find-evidence short session)))
                                  (and record (equal "rizin_command" (gethash "tool" record))
                                       (= 64 (length (gethash "reproHash" record))))))
                              ids)))
           (check "it ends with the list of reads it took, by id and command"
                  (and (has "Evidence taken" triage) (has "iIj" triage) (has "iSj entropy" triage)))
           (check "each read a recipe makes is a rizin_command call in the audit log"
                  (let ((log (re::read-text-file (re::state-path "audit" (format nil "~a.log" id)))))
                    (and (has "\"command\":\"iSj entropy\"" log) (has "\"command\":\"iej\"" log))))
           (check "/re off stops a recipe at its first read, like any call"
                  (progn (re:slash "off")
                         (prog1 (has "RE tools are off" (refusal (lambda () (re:triage))))
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

         (let ((scan (re:scan-imports)))
           (check "scan_imports reads reach off the imports and lists the ones worth a look, with why"
                  (and (has "Reach, by what it links" scan) (has "worth a reviewer's look" scan)
                       (has "An import is a lead" scan)))
           (check "a risky import ls really links is listed with its callers and their evidence"
                  (and (has "called from" scan) (>= (length (cited-ids scan)) 2)))
           (check "without callers it makes the one read"
                  (= 1 (length (cited-ids (re:scan-imports :callers :false))))))

         (let ((function (re:inspect-function "main")))
           (check "inspect_function gives a function's shape, variables, callers, callees and strings"
                  (and (has "cyclomatic complexity" function) (has "basic blocks" function)
                       (has "Variables:" function) (has "Called from" function)
                       (has "distinct target" function) (has "Refers to" function)))
           (check "its callees are the calls rizin disassembled, by name"
                  (has "sym.imp." function))
           (check "an address that is no function is refused in words"
                  (has "no function at" (refusal (lambda () (re:inspect-function "0x1")))))
           (check "an address that could open another command never reaches rizin"
                  (has "invalid address" (refusal (lambda () (re:inspect-function "main;!id"))))))

         (let ((comparisons (re:find-comparisons "main" :max-items 20)))
           (check "find_comparisons pairs each compare with the branch that follows and where it goes"
                  (and (has "Compares and the branches that follow" comparisons)
                       (has "->" comparisons) (has "taken when" comparisons) (has ", to 0x" comparisons)))
           (check "it bounds its list and says what was left out"
                  (has "more comparisons not shown" comparisons))
           (check "it says it lists comparisons, not their meaning"
                  (has "not what the comparison means" comparisons)))

         (check "find_crypto on a binary with no crypto tables says so, and records only what it found"
                (let ((crypto (re:find-crypto)))
                  (and (has "find_crypto:" crypto) (has "rizin's search for keys and certificates" crypto))))))

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
           (check "each hit cites the search that found it, and a constant that is absent costs no record"
                  (let ((records (re::evidence-records (re::find-session id))))
                    (and (= 3 (count-if (lambda (record)
                                          (re::starts-with "/xj " (gethash "command" (gethash "args" record))))
                                        records))
                         (= 4 (length (cited-ids crypto))))))
           (check "it says what a table's presence does and does not show"
                  (has "linked in" crypto)))))

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
