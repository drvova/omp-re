;;;; suite-carry.lisp --- /re carry: a report's manifest replayed on another build.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The first half needs no rizin: reading a manifest, the diff and the
;;;; roll-up. The second half
;;;; writes a real report on a copy of the test binary and carries it — onto
;;;; the same bytes, onto a different program (a copy of /bin/cat), and, for
;;;; the classifications two unrelated binaries cannot produce, from
;;;; manifests written by hand around what rizin really prints. No binary is
;;;; ever run.

(in-package #:omp-re-test)

(defun carry-sha (char) (make-string 64 :initial-element char))

(defun carry-keys (object)
  (loop for key being the hash-keys of object collect key))

(defun write-manifest (name object)
  "OBJECT written as the manifest NAME in the scratch home => its path."
  (let ((path (scratch-path name)))
    (omp-re::write-text-file path (omp-re:json-encode object :indent 2))
    path))

(defun manifest-row (id &rest members)
  "A manifest entry as /re report writes one, MEMBERS over the defaults."
  (let ((row (omp-re:obj "evidenceId" id "tool" "rizin_command" "args" :null "command" :null "commands" :null
                      "reproHash" :null "canonicalExcerpt" :null "shiftHash" :null "anchor" :null
                      "binarySha256" (carry-sha #\a) "status" "reproducible" "claims" (vector))))
    (loop for (key value) on members by #'cddr
          do (setf (gethash key row) value))
    row))

(defun parsed-entry (&rest members)
  (first (omp-re::carry-manifest-entries
          (omp-re::parse-manifest (omp-re:json-encode (omp-re:obj "entries" (vector (apply #'manifest-row "e" members))))))))

(defun row-of (result id)
  (find id (coerce (gethash "evidence" result) 'list)
        :key (lambda (row) (gethash "evidenceId" row)) :test #'string=))

(defun carried (path &rest options)
  "Carry the manifest at PATH in the running turn's session => the result
object, as --out writes it beside the report, and the text and the failure
as further values; a refusal is signalled."
  (let* ((out (scratch-path "carried.md"))
         (json (format nil "~a.json" out)))
    (uiop:delete-file-if-exists json)
    (multiple-value-bind (text failed)
        (omp-re::in-session (nle:*stub-session* "carry")
          (apply #'omp-re::carry-manifest-file path :out out options))
      (unless (probe-file json) (omp-re::fail "~a" text))
      (values (omp-re:json-parse (omp-re::read-text-file json))
              (omp-re:join-lines (remove-if (lambda (line) (starts "carry report written to " line))
                                            (omp-re:split-lines text)))
              failed))))

;;; --- the pieces ---------------------------------------------------------------------------------

(suite "carry: reading a manifest")
(check "text that is not JSON is refused, and so is JSON with more after it"
       (and (has "omp-re: carry: manifest is not valid JSON ("
                 (refusal (lambda () (omp-re::parse-manifest "{nope"))))
            (has "not valid JSON" (refusal (lambda () (omp-re::parse-manifest ""))))
            (has "not valid JSON" (refusal (lambda () (omp-re::parse-manifest "{\"entries\":[]} x"))))))
(check "JSON that is not a manifest is refused in words that say which file to pass"
       (every (lambda (text)
                (equal "omp-re: carry: not a verification manifest (no `entries` array) — pass the <report>.manifest.json written by /re report <path>"
                       (refusal (lambda () (omp-re::parse-manifest text)))))
              '("{\"claims\":[]}" "[1,2]" "null" "{\"entries\":{}}" "\"entries\"")))
(check "missing optional members are tolerated and malformed entries dropped"
       (let* ((manifest (omp-re::parse-manifest
                         (format nil "{\"binarySha256\":\"~a\",\"entries\":[{\"evidenceId\":\"e1\",\"claims\":[\"c\",7]},{\"tool\":\"x\"},null,7,{\"evidenceId\":3}]}"
                                 (carry-sha #\a))))
              (entry (first (omp-re::carry-manifest-entries manifest))))
         (and (equal (carry-sha #\a) (omp-re::carry-manifest-binary-sha256 manifest))
              (= 1 (length (omp-re::carry-manifest-entries manifest)))
              (equal "unknown" (omp-re::manifest-entry-tool entry))
              (equal '("c") (omp-re::manifest-entry-claims entry))
              (null (omp-re::manifest-entry-read entry))
              (null (omp-re::manifest-entry-repro-hash entry))
              (null (omp-re::manifest-entry-anchor entry))
              (null (omp-re::carry-manifest-findings manifest)))))
(check "the read keeps an address only when it is a non-empty string"
       (and (equal '("command" "addr")
                   (carry-keys (omp-re::manifest-entry-read
                                (parsed-entry "reproHash" "aa" "args" (omp-re:obj "command" "pdf" "addr" "main")))))
            (equal '("command")
                   (carry-keys (omp-re::manifest-entry-read (parsed-entry "reproHash" "aa" "args" (omp-re:obj "command" "pdf" "addr" "")))))
            (null (omp-re::manifest-entry-read (parsed-entry "reproHash" "aa" "args" (omp-re:obj "addr" "main"))))))
(let ((good (omp-re:obj "anchor" "sym.f" "function" "sym.f" "offset" "0x1100" "delta" 0 "size" 40 "nbbs" 3
                     "mnemonics" (vector "push" "mov" "ret"))))
  (check "a well-formed fingerprint is kept, member for member"
         (let ((anchor (omp-re::manifest-entry-anchor (parsed-entry "anchor" good))))
           (and (equal '("anchor" "function" "offset" "delta" "size" "nbbs" "mnemonics") (carry-keys anchor))
                (string= (omp-re:json-encode good) (omp-re:json-encode anchor)))))
  (check "a malformed one is dropped: a negative or fractional delta, no mnemonics, a name that is no string"
         (flet ((dropped (key value)
                  (let ((bad (omp-re:json-decode (omp-re:json-encode good))))
                    (setf (gethash key bad) value)
                    (null (omp-re::manifest-entry-anchor (parsed-entry "anchor" bad))))))
           (and (dropped "delta" -1) (dropped "delta" 1.5d0) (dropped "delta" (ash 1 25))
                (dropped "mnemonics" (vector)) (dropped "mnemonics" (vector "push" 1))
                (dropped "function" 7) (dropped "size" "40")
                (null (omp-re::manifest-entry-anchor (parsed-entry "anchor" "sym.f")))))))
(check "findings are read with their evidence ids; an unknown confidence is likely"
       (let ((findings (omp-re::carry-manifest-findings
                        (omp-re::parse-manifest "{\"entries\":[],\"findings\":[{\"id\":\"f1\",\"claim\":\"c\",\"evidenceIds\":[\"e1\",2],\"addr\":null,\"confidence\":\"sure\"},{\"id\":\"f2\",\"claim\":\"d\",\"evidenceIds\":[],\"addr\":\"main\",\"confidence\":\"confirmed\"},{\"id\":\"f3\",\"claim\":\"no ids\"},null]}"))))
         (and (= 2 (length findings))
              (equal '("e1") (omp-re::manifest-finding-evidence-ids (first findings)))
              (null (omp-re::manifest-finding-addr (first findings)))
              (equal "likely" (omp-re::manifest-finding-confidence (first findings)))
              (equal "main" (omp-re::manifest-finding-addr (second findings)))
              (equal "confirmed" (omp-re::manifest-finding-confidence (second findings))))))

(suite "carry: what to re-run")
(flet ((request (&rest members)
         (let ((request (omp-re::evidence-read (apply #'manifest-row "e" members))))
           (and request (list (gethash "command" request) (gethash "addr" request))))))
  (check "the structured args win"
         (equal '("pdf" "sym.main")
                (request "args" (omp-re:obj "command" "pdf" "addr" "sym.main") "commands" (vector "ignored"))))
  (check "a legacy recorded line is split at its trailing ` @ addr`"
         (and (equal '("pdf" "sym.main") (request "commands" (vector "pdf @ sym.main")))
              (equal '("iHj" nil) (request "command" "iHj"))
              (equal '("px 16" "0x10") (request "command" "  px 16   @  0x10 "))))
  (check "`@!<blocksize>` stays part of the command, not a seek"
         (equal '("ph sha256 @!32" nil) (request "commands" (vector "ph sha256 @!32"))))
  (check "several recorded lines leave only the display line to split, and no line is nothing to run"
         (and (equal '("afij @ a ; pdfj" "a")
                     (request "command" "afij @ a ; pdfj @ a" "commands" (vector "afij @ a" "pdfj @ a")))
              (null (request))
              (null (request "command" ""))))
  (check "another tool's entry is never re-run, whatever it recorded"
         (null (request "tool" "triage_capa" "args" (omp-re:obj "command" "pdf") "commands" (vector "pdf")))))

(suite "carry: similarity, the diff, the roll-up")
(check "similarity is 1 for the same sequence and falls as they diverge"
       (and (= 1 (omp-re::sequence-similarity '("push" "mov" "ret") '("push" "mov" "ret")))
            (= 3/4 (omp-re::sequence-similarity '("push" "mov" "add" "ret") '("push" "mov" "sub" "ret")))
            (= 0 (omp-re::sequence-similarity '("a") '("b")))
            (= 1 (omp-re::sequence-similarity '() '()))
            (= 0 (omp-re::sequence-similarity '("a") '()))))
(check "the address mask hides where code sits and keeps what it says"
       (let ((v1 (format nil "0x00001139      and   eax, 0x0f~%0x0000113c      call  0x00001100"))
             (v2 (format nil "0x00001149      and   eax, 0x0f~%0x0000114c      call  0x00001110")))
         (and (string= (omp-re::mask-addresses v1) (omp-re::mask-addresses v2))
              (has "and   eax, 0x0f" (omp-re::mask-addresses v1))
              (string/= (omp-re::mask-addresses (omp-re::replace-all v1 "0x0f" "0x1f")) (omp-re::mask-addresses v2)))))
(check "a diff marks removed and added lines around the common ones"
       (and (equal '("  a" "- b" "+ B" "  c")
                   (omp-re::line-diff (format nil "a~%b~%c") (format nil "a~%B~%c")))
            (equal '("+ x") (omp-re::line-diff "" "x"))
            (equal '("- x") (omp-re::line-diff "x" ""))
            (null (omp-re::line-diff "" ""))))
(check "under the mask a line that only moved is unchanged, and shown in its new form"
       (equal '("  0x14 jmp 0x24" "- 0x12 add" "+ 0x16 sub")
              (omp-re::line-diff (format nil "0x10 jmp 0x20~%0x12 add") (format nil "0x14 jmp 0x24~%0x16 sub")
                             #'omp-re::mask-addresses)))
(check "the hunk view keeps changes with their context and elides the rest once"
       (and (equal '("  …" "  c" "  c2" "- d" "+ D" "  e" "  e2" "  …")
                   (omp-re::compact-diff '("  a" "  b" "  c" "  c2" "- d" "+ D" "  e" "  e2" "  f" "  g")))
            (equal '("  a" "- b") (omp-re::compact-diff '("  a" "- b")))))
(check "a claim takes its worst checked evidence; with nothing checked it stays unchecked"
       (let* ((manifest (omp-re::parse-manifest
                         (omp-re:json-encode
                          (omp-re:obj "entries"
                                   (vector (manifest-row "e1" "claims" (vector "A" "B"))
                                           (manifest-row "e2" "claims" (vector "A"))
                                           (manifest-row "e3" "claims" (vector "B"))
                                           (manifest-row "e4" "claims" (vector "C"))
                                           (manifest-row "e5" "claims" (vector "D" "A")))))))
              (rows (mapcar (lambda (pair) (omp-re:obj "evidenceId" (car pair) "status" (cdr pair)))
                            '(("e1" . "holds") ("e2" . "drifted") ("e3" . "relocated") ("e4" . "unchecked")
                              ("e5" . "broken"))))
              (claims (omp-re::roll-up-claims manifest rows)))
         (and (equal '(("A" "broken" ("e1" "e2" "e5")) ("B" "relocated" ("e1" "e3"))
                       ("C" "unchecked" ("e4")) ("D" "broken" ("e5")))
                     (mapcar (lambda (claim)
                               (list (gethash "text" claim) (gethash "status" claim)
                                     (coerce (gethash "evidenceIds" claim) 'list)))
                             claims))
              (equal '("text" "status" "evidenceIds") (carry-keys (first claims))))))
(check "the summary counts the claims and lists those that do not hold first"
       (string= (format nil "omp-re: carry aaaaaaaaaaaa… → unknown — 1 hold, 1 relocated, 1 drifted, 1 BROKEN, 1 unchecked (of 5 claim(s))~%  BROKEN    b~%  DRIFTED   d~%  UNCHECKED u~%  RELOCATED r~%  HOLDS     h")
                (omp-re::format-carry-summary
                 (omp-re:obj "fromSha256" (carry-sha #\a) "toSha256" :null
                          "claims" (map 'vector (lambda (pair) (omp-re:obj "text" (car pair) "status" (cdr pair)))
                                        '(("h" . "holds") ("r" . "relocated") ("d" . "drifted")
                                          ("b" . "broken") ("u" . "unchecked")))))))
(check "an address follows a relocation by name or by start, and otherwise stays"
       (let ((relocation (omp-re:obj "fromName" "sym.fib" "fromOffset" "0x1139"
                                     "toName" "sym.fibonacci" "toOffset" "0x1149")))
         (and (equal "sym.fibonacci" (omp-re::follow-relocation "sym.fib" relocation))
              (equal "0x1149" (omp-re::follow-relocation "0x00001139" relocation))
              (null (omp-re::follow-relocation "sym.other" relocation)))))

;;; --- /re carry, before any rizin --------------------------------------------------------------------

(suite "carry: the /re line")
(with-cell ()
  (in-session ((fresh-session))
    (check "/re help lists carry"
           (has "/re carry <manifest>" (re:slash "help")))
    (check "with no manifest it says how it is used, flags or no flags"
           (every (lambda (line)
                    (equal "Usage: /re carry <report.md.manifest.json> [--against <binary>] [--inherit | --resolve] [--strict] [--out <path>]"
                           (refusal (lambda () (re:slash line)))))
                  '("carry" "carry --strict --inherit" "carry --out x.md" "carry --against")))
    (check "a manifest that is not there is refused by name, as is a folder"
           (and (equal "omp-re: carry: could not read manifest /nonexistent/r.md.manifest.json: no such file"
                       (refusal (lambda () (re:slash "carry /nonexistent/r.md.manifest.json"))))
                (equal "omp-re: carry: could not read manifest no  such.json: no such file"
                       (refusal (lambda () (re:slash "carry no  such.json --strict"))))
                (equal (format nil "omp-re: carry: could not read manifest ~a: it is a directory"
                               (scratch-path "carry-dir"))
                       (progn (ensure-directories-exist (merge-pathnames "carry-dir/" *scratch*))
                              (refusal (lambda () (re:slash (format nil "carry ~a" (scratch-path "carry-dir")))))))))
    (check "a file that is not JSON, or not a manifest, is refused before anything is asked of the binary"
           (let ((junk (scratch-path "junk.manifest.json"))
                 (wrong (scratch-path "wrong.manifest.json")))
             (omp-re::write-text-file junk "# Analysis Report")
             (omp-re::write-text-file wrong "{\"claims\": []}")
             (and (has "omp-re: carry: manifest is not valid JSON ("
                       (refusal (lambda () (re:slash (format nil "carry ~a" junk)))))
                  (equal "omp-re: carry: not a verification manifest (no `entries` array) — pass the <report>.manifest.json written by /re report <path>"
                         (refusal (lambda () (re:slash (format nil "carry ~a" wrong))))))))
    (check "a real manifest with no binary open says to open the new build"
           (equal "omp-re: carry: no binary open — /re open <the new build> first, or pass --against <path>"
                  (refusal (lambda ()
                             (re:slash (format nil "carry ~a" (write-manifest "empty.manifest.json"
                                                                              (omp-re:obj "entries" (vector)))))))))))

;;; --- on the test binary ---------------------------------------------------------------------------------

(suite "carry: a report carried onto the same build, and onto another program")
(if (not (and *rizin* (probe-file "/bin/cat")))
    (format t "  SKIPPED (no rizin, test binary or /bin/cat)~%")
    (with-cell ()
      (let* ((v1 (scratch-path "carry-v1"))
             (other (scratch-path "carry-other"))
             (report (scratch-path "carry-report.md"))
             (manifest-path (format nil "~a.manifest.json" report))
             (other-flags '())
             (gone-flag nil)
             (v1-sha nil))
        (uiop:copy-file *binary* v1)
        (uiop:copy-file "/bin/cat" other)

        ;; What the other program has no flag for: an anchor that will be gone.
        (let ((id (fresh-session)))
          (in-session (id)
            (re:open other)
            (setf other-flags (map 'list (lambda (flag) (gethash "name" flag))
                                   (omp-re::rz-cmdj (omp-re::session-rz (omp-re:find-session id)) "flj")))))

        ;; The report, written in one session.
        (let ((id (fresh-session)))
          (in-session (id)
            (re:open v1)
            (setf v1-sha (omp-re::session-binary-sha256 (omp-re:find-session id))
                  gone-flag (find-if (lambda (name)
                                       (and (starts "str." name)
                                            (not (member name other-flags :test #'string=))))
                                     (map 'list (lambda (flag) (gethash "name" flag))
                                          (omp-re::rz-cmdj (omp-re::session-rz (omp-re:find-session id)) "flj"))))
            (flet ((finding (claim command &optional addr)
                     (apply #'re:call "record_finding" :claim claim :confidence "confirmed"
                            :evidence (list (tagged-evidence (re:cmd command addr)))
                            (and addr (list :addr addr)))))
              (finding "It targets x86." "e asm.arch")
              (finding "Its header is this build's." "iIj")
              (finding "entry0 begins with endbr64." "pd 4" "entry0")
              (finding "It holds a string of its own." "px 16" gone-flag))
            (check "the report and its manifest are written"
                   (and gone-flag
                        (has "omp-re: report written to" (re:slash (format nil "report ~a" report)))
                        (probe-file manifest-path)))))

        ;; A fresh session on the same bytes.
        (let* ((id (fresh-session))
               (session (omp-re:find-session id)))
          (in-session (id)
            (re:open v1)
            (let ((text (re:slash (format nil "carry ~a" manifest-path))))
              (check "on the same build every claim holds, and the line says this is /re verify"
                     (string= (format nil "omp-re: carry ~a… → ~a… — 4 hold, 0 relocated, 0 drifted, 0 BROKEN, 0 unchecked (of 4 claim(s))~%  (same binary the report was written against — this is /re verify; open the new build to carry onto it)~%  HOLDS     It targets x86.~%  HOLDS     Its header is this build's.~%  HOLDS     entry0 begins with endbr64.~%  HOLDS     It holds a string of its own."
                                      (subseq v1-sha 0 12) (subseq v1-sha 0 12))
                              text)))
            (check "carrying recorded nothing: no evidence, no findings"
                   (and (null (omp-re::evidence-records session))
                        (null (omp-re::live-findings session))))
            (check "and --strict has nothing to fail on"
                   (has "4 hold, 0 relocated, 0 drifted, 0 BROKEN, 0 unchecked" (re:slash (format nil "carry --strict ~a" manifest-path))))
            (multiple-value-bind (result text failed) (carried manifest-path)
              (declare (ignore text))
              (check "each row holds on identical output and keeps what reproduced it"
                     (and (not failed)
                          (equal '("fromSha256" "toSha256" "toPath" "evidence" "claims") (carry-keys result))
                          (equal v1 (gethash "toPath" result))
                          (every (lambda (row)
                                   (and (equal "holds" (gethash "status" row))
                                        (equal "output identical" (gethash "detail" row))
                                        (equal '("evidenceId" "tool" "command" "status" "detail" "rerun")
                                               (carry-keys row))))
                                 (gethash "evidence" result))
                          (equal '("pd 4" "entry0")
                                 (let ((rerun (gethash "rerun" (aref (gethash "evidence" result) 2))))
                                   (list (gethash "command" rerun) (gethash "addr" rerun))))
                          (equal "pd 4 @ entry0" (gethash "command" (aref (gethash "evidence" result) 2))))))))

        ;; --against opens the binary first.
        (let ((id (fresh-session)))
          (in-session (id)
            (check "--against opens that binary, then carries onto it"
                   (and (has "4 hold, 0 relocated" (re:slash (format nil "carry ~a --against ~a" manifest-path v1)))
                        (equal v1 (omp-re::session-binary-path (omp-re:find-session id)))
                        (has (format nil "binary: ~a" v1) (re:status))))))

        ;; Another program altogether.
        (let* ((id (fresh-session))
               (session (omp-re:find-session id))
               (out (scratch-path "carry-out.md"))
               (other-sha nil))
          (in-session (id)
            (re:open other)
            (setf other-sha (omp-re::session-binary-sha256 session))
            (let ((text (refusal (lambda () (re:slash (format nil "carry ~a" manifest-path))))))
              (check "on another program the gone anchor BREAKS the claim and fails the line, word for word"
                     (string= (format nil "omp-re: carry ~a… → ~a… — 2 hold, 0 relocated, 1 drifted, 1 BROKEN, 0 unchecked (of 4 claim(s))~%  BROKEN    It holds a string of its own.~%  DRIFTED   Its header is this build's.~%  HOLDS     It targets x86.~%  HOLDS     entry0 begins with endbr64."
                                      (subseq v1-sha 0 12) (subseq other-sha 0 12))
                              text)))
            (multiple-value-bind (result text failed) (carried manifest-path)
              (declare (ignore text))
              (let ((rows (gethash "evidence" result)))
                (check "each row says why: identical, identical but for addresses, changed, gone"
                       (and failed
                            (equal "output identical" (gethash "detail" (aref rows 0)))
                            (equal "drifted" (gethash "status" (aref rows 1)))
                            (equal "output changed" (gethash "detail" (aref rows 1)))
                            (equal "output identical apart from shifted addresses" (gethash "detail" (aref rows 2)))
                            (equal "broken" (gethash "status" (aref rows 3)))
                            (equal (format nil "anchor `~a` no longer resolves in this binary" gone-flag)
                                   (gethash "detail" (aref rows 3)))
                            (equal (format nil "px 16 @ ~a" gone-flag) (gethash "command" (aref rows 3)))))
                (check "a drifted row carries the diff of the recorded excerpt against the new one, and no rerun"
                       (let ((diff (coerce (gethash "diff" (aref rows 1)) 'list)))
                         (and (equal '("evidenceId" "tool" "command" "status" "detail" "diff")
                                     (carry-keys (aref rows 1)))
                              (some (lambda (line) (starts "- {" line)) diff)
                              (some (lambda (line) (starts "+ {" line)) diff))))))

            ;; --out.
            (let ((text (refusal (lambda () (re:slash (format nil "carry ~a --out ~a" manifest-path out))))))
              (check "--out says where the carry report went, even on a failing line"
                     (has (format nil "~%carry report written to ~a (+ ~a.json)" out out) text)))
            (let ((markdown (omp-re::read-text-file out)))
              (check "the carry report: manifest, both hashes, the claim matrix, the evidence"
                     (and (starts
                           (format nil "# Carry Report~%~%- **Manifest:** `~a`~%- **From binary:** `~a`~%- **To binary:** `~a` (~a)~%- **Claims:** 2 hold · 0 relocated · 1 drifted · 1 broken · 0 unchecked~%~%## Claims~%~%| Status | Claim | Evidence |~%| --- | --- | --- |~%| holds | It targets x86. | `"
                                   manifest-path v1-sha other-sha other)
                           markdown)
                          (has "| broken | It holds a string of its own. | `" markdown)
                          (has (format nil "` broken |~%~%## Evidence~%~%### `") markdown)
                          (has (format nil "` — drifted~%~%- **Tool:** rizin_command~%- **Command:** `iIj`~%- **Detail:** output changed~%~%```diff~%- {")
                               markdown)
                          (has (format nil "- **Command:** `px 16 @ ~a`~%- **Detail:** anchor `~a` no longer resolves in this binary~%"
                                       gone-flag gone-flag)
                               markdown))))
            (let ((sidecar (omp-re:json-decode (omp-re::read-text-file (format nil "~a.json" out)))))
              (check "and beside it the whole result as JSON"
                     (and (equal '("fromSha256" "toSha256" "toPath" "evidence" "claims") (carry-keys sidecar))
                          (equal v1-sha (gethash "fromSha256" sidecar))
                          (equal other-sha (gethash "toSha256" sidecar))
                          (= 4 (length (gethash "evidence" sidecar)))
                          (equal '("holds" "drifted" "holds" "broken")
                                 (map 'list (lambda (claim) (gethash "status" claim)) (gethash "claims" sidecar)))
                          (ends (format nil "}~%") (omp-re::read-text-file (format nil "~a.json" out))))))
            (check "a carry report that cannot be written is said, and is not what fails the line"
                   (has (format nil "~%carry report not written: ")
                        (refusal (lambda ()
                                   (re:slash (format nil "carry ~a --out ~a" manifest-path
                                                     (scratch-path "no-such-folder/out.md")))))))

            ;; --strict, on a manifest with nothing broken in it.
            (let* ((manifest (omp-re:json-decode (omp-re::read-text-file manifest-path)))
                   (drift-only (progn
                                 (setf (gethash "entries" manifest) (subseq (gethash "entries" manifest) 0 2)
                                       (gethash "findings" manifest) (subseq (gethash "findings" manifest) 0 2))
                                 (write-manifest "drift.manifest.json" manifest))))
              (check "drift alone passes by default"
                     (string= (format nil "omp-re: carry ~a… → ~a… — 1 hold, 0 relocated, 1 drifted, 0 BROKEN, 0 unchecked (of 2 claim(s))~%  DRIFTED   Its header is this build's.~%  HOLDS     It targets x86."
                                      (subseq v1-sha 0 12) (subseq other-sha 0 12))
                              (re:slash (format nil "carry ~a" drift-only))))
              (check "and fails under --strict, with the same lines"
                     (string= (re:slash (format nil "carry ~a" drift-only))
                              (refusal (lambda () (re:slash (format nil "carry ~a --strict" drift-only)))))))
            (check "nothing so far recorded anything here"
                   (and (null (omp-re::evidence-records session)) (null (omp-re::live-findings session))))

            ;; --inherit.
            (let ((text (refusal (lambda () (re:slash (format nil "carry ~a --inherit" manifest-path))))))
              (check "--inherit re-proves what held, and puts the rest on an agenda under the summary"
                     (and (has (format nil "~%inherit: 2 finding(s) re-proven on this build and recorded, 2 need another look~%These findings from the earlier report do not carry over unchanged to this build (`~a…`). For each one, re-examine it with the RE tools, then record_finding a revised claim on fresh evidence, or leave it out if it no longer stands:~%~%1. [drifted] Its header is this build's.~%   - evidence "
                                       (subseq other-sha 0 12))
                               text)
                          (has (format nil " `iIj`: drifted — output changed~%     ```diff~%     - {") text)
                          (has (format nil "~%     ```~%2. [broken] It holds a string of its own.~%   - evidence ") text)
                          (ends (format nil " `px 16 @ ~a`: broken — anchor `~a` no longer resolves in this binary"
                                                 gone-flag gone-flag)
                                         text)
                          (not (has "resolve:" text)))))
            (let ((evidence (omp-re::evidence-records session))
                  (findings (omp-re::entries-of "re.finding" session)))
              (check "the evidence is recorded as rizin_command records it, bound to THIS binary"
                     (and (= 2 (length evidence))
                          (every (lambda (record)
                                   (and (equal "rizin_command" (gethash "tool" record))
                                        (equal other-sha (gethash "binarySha256" record))
                                        (= 64 (length (gethash "reproHash" record)))
                                        (= 64 (length (gethash "shiftHash" record)))
                                        (stringp (gethash "canonicalExcerpt" record))
                                        (omp-re::read-blob (gethash "outputHash" record))))
                                 evidence)
                          (equal '("command") (carry-keys (gethash "args" (first evidence))))
                          (equal '("command" "addr") (carry-keys (gethash "args" (second evidence))))
                          (equalp #("pd 4 @ entry0") (gethash "commands" (second evidence)))
                          (starts "0x" (gethash "ea" (second evidence)))))
              (check "an inherited finding has its fields in the record's order, citing only the fresh evidence"
                     (and (= 2 (length findings))
                          (equal '("id" "claim" "evidenceIds" "confidence" "audit" "binarySha256" "inherited")
                                 (carry-keys (first findings)))
                          (equal '("id" "claim" "evidenceIds" "addr" "confidence" "audit" "binarySha256" "inherited")
                                 (carry-keys (second findings)))
                          (equal "It targets x86." (gethash "claim" (first findings)))
                          (equalp (vector (gethash "id" (first evidence))) (gethash "evidenceIds" (first findings)))
                          (equal "entry0" (gethash "addr" (second findings)))
                          (equal "confirmed" (gethash "confidence" (second findings)))
                          (string= "{\"verdict\":\"inherited\",\"reason\":\"re-verified by /re carry; the report's support audit re-checks it\"}"
                                   (omp-re:json-encode (gethash "audit" (first findings))))
                          (equal other-sha (gethash "binarySha256" (first findings)))
                          (let ((inherited (gethash "inherited" (first findings)))
                                (original (aref (gethash "findings" (omp-re:json-decode (omp-re::read-text-file manifest-path))) 0)))
                            (and (equal '("fromBinarySha256" "fromFindingId" "carryStatus") (carry-keys inherited))
                                 (equal v1-sha (gethash "fromBinarySha256" inherited))
                                 (equal (gethash "id" original) (gethash "fromFindingId" inherited))
                                 (equal "holds" (gethash "carryStatus" inherited))))))
              (check "/re findings shows them, with where they came from, and the status line counts them"
                     (and (string= (format nil "omp-re: findings~%[~a] It targets x86.~%[~a] entry0 begins with endbr64."
                                           (subseq (gethash "id" (first findings)) 0 8)
                                           (subseq (gethash "id" (second findings)) 0 8))
                                   (re:slash "findings"))
                          (has (format nil "confidence: confirmed · at `entry0` · inherited from `~a…`, re-verified on this build (holds)"
                                       (subseq v1-sha 0 12))
                               (re:slash (format nil "findings ~a" (gethash "id" (second findings)))))
                          (has "findings on this branch: 2 (2 inherited)" (re:status))
                          (has "evidence on this branch: 2" (re:status))))
              (check "what was inherited verifies here like any other evidence"
                     (has "2 reproducible, 0 FAILED, 0 unverifiable" (re:slash "verify"))))

            ;; Again: a claim already live is not inherited twice. And --resolve.
            (let ((text (refusal (lambda () (re:slash (format nil "carry ~a --resolve" manifest-path))))))
              (check "a second carry inherits nothing twice, and --resolve says what a host with no turn to start does"
                     (and (has (format nil "~%inherit: 0 finding(s) re-proven on this build and recorded, 2 need another look, 2 already present~%resolve: a headless run cannot start a model turn from a command — the agenda for 2 finding(s) follows; pass it to the model as the next prompt~%These findings from the earlier report do not carry over unchanged")
                               text)
                          (= 2 (length (omp-re::evidence-records session)))
                          (= 2 (length (omp-re::live-findings session))))))
            ;; Where an operator is watching, the agenda is theirs to send.
            (with-service (:has-ui (lambda () t))
              (multiple-value-bind (text failed reply)
                  (omp-re::run-slash-line session (format nil "carry ~a --resolve" manifest-path))
                (check "with an operator watching, --resolve asks for the agenda to be sent as their next message, and the line only says so"
                       (and failed
                            (has "resolve: sent 2 finding(s) to the model to re-examine" text)
                            (not (has "These findings from the earlier report" text))
                            (starts "These findings from the earlier report" (getf reply :user-message))
                            (null (getf reply :draft))
                            (eq :error (getf reply :level)))))
              (multiple-value-bind (text failed reply)
                  (omp-re::run-slash-line session (format nil "carry ~a --inherit" manifest-path))
                (declare (ignore failed))
                (check "without --resolve the agenda is offered as a draft, under the summary as its notice"
                       (and (not (has "These findings from the earlier report" text))
                            (starts "These findings from the earlier report" (omp-re::draft-text (getf reply :draft)))
                            (string= text (omp-re::draft-notice (getf reply :draft)))
                            (null (getf reply :user-message))))))
            (multiple-value-bind (result text failed) (carried manifest-path :inherit t)
              (declare (ignore text failed))
              (let ((inheritance (gethash "inheritance" result)))
                (check "the result carries the inheritance: what was inherited, the agenda, what was already there"
                       (and (equal '("inherited" "agenda" "alreadyPresent") (carry-keys inheritance))
                            (= 0 (length (gethash "inherited" inheritance)))
                            (eql 2 (gethash "alreadyPresent" inheritance))
                            (equal '("fromId" "claim" "status" "rows")
                                   (carry-keys (aref (gethash "agenda" inheritance) 0)))
                            (equal '("drifted" "broken")
                                   (map 'list (lambda (item) (gethash "status" item)) (gethash "agenda" inheritance)))))))

            ;; The engine forgets the session; the record is the truth.
            (omp-re:shutdown-sessions)
            (check "inherited findings survive the engine forgetting the session"
                   (and (has "findings on this branch: 2 (2 inherited)" (re:status))
                        (has "It targets x86." (re:slash "findings"))))))

        ;; --inherit where everything holds, and a manifest with no findings.
        (let ((id (fresh-session)))
          (in-session (id)
            (re:open v1)
            (check "on the same build --inherit re-proves every finding and there is no agenda"
                   (ends (format nil "~%  HOLDS     It holds a string of its own.~%inherit: 4 finding(s) re-proven on this build and recorded, 0 need another look")
                                  (re:slash (format nil "carry ~a --resolve --strict" manifest-path))))
            (check "all four are live, inherited, and the report can be written from them"
                   (and (has "findings on this branch: 4 (4 inherited)" (re:status))
                        (has "_confidence: confirmed · inherited from `" (re:slash "report"))))
            (let ((manifest (omp-re:json-decode (omp-re::read-text-file manifest-path))))
              (remhash "findings" manifest)
              (check "a manifest from before findings has none to inherit, and the line says what to do"
                     (ends (format nil "~%inherit: 0 finding(s) re-proven on this build and recorded, 0 need another look (this manifest has no findings — record them with record_finding before /re report)")
                                    (re:slash (format nil "carry ~a --inherit"
                                                      (write-manifest "old.manifest.json" manifest))))))))

        ;; --- manifests written by hand, around what rizin really prints ---------------------------------
        (suite "carry: relocated, and the rest of the classifications")
        (let* ((id (fresh-session))
               (session (omp-re:find-session id)))
          (in-session (id)
            (re:open v1)
            (let* ((rz (omp-re::session-rz session))
                   (fingerprint (omp-re::anchor-fingerprint rz "main"))
                   (name (gethash "function" fingerprint))
                   (start (gethash "offset" fingerprint))
                   (listing (omp-re::rz-run rz (format nil "pdf @ ~a" start)))
                   (entry-ea (omp-re:ea-from-offset (omp-re::resolve-numeric-addr rz "entry0")))
                   (entry-listing (omp-re::rz-run rz "pd 4 @ entry0")))
              (flet ((anchor (&rest members)
                       (let ((anchor (omp-re:json-decode (omp-re:json-encode fingerprint))))
                         (loop for (key value) on members by #'cddr
                               do (setf (gethash key anchor) value))
                         anchor))
                     (reproducible (id command addr output &rest members)
                       (apply #'manifest-row id
                              "args" (omp-re:obj "command" command "addr" (or addr :absent))
                              "command" (format nil "~a~@[ @ ~a~]" command addr)
                              "commands" (vector (format nil "~a~@[ @ ~a~]" command addr))
                              "reproHash" (omp-re::canonical-hash output v1)
                              "canonicalExcerpt" (omp-re::canonical-excerpt output v1)
                              "shiftHash" (omp-re::shift-hash output v1)
                              members)))
                (let* ((renamed-listing (omp-re::replace-all listing name "sym.old_main"))
                       (path
                         (write-manifest
                          "hand.manifest.json"
                          (omp-re:obj
                           "binarySha256" (carry-sha #\a)
                           "findings"
                           (vector (omp-re:obj "id" "f-renamed" "claim" "old_main parses the arguments."
                                            "evidenceIds" (vector "ev-renamed") "addr" "sym.old_main"
                                            "confidence" "speculative")
                                   (omp-re:obj "id" "f-moved" "claim" "The code at 0x10 is main."
                                            "evidenceIds" (vector "ev-moved-empty" "ev-moved") "addr" "0x10"
                                            "confidence" "confirmed")
                                   (omp-re:obj "id" "f-prov" "claim" "main is a function."
                                            "evidenceIds" (vector "ev-prov" "ev-missing") "addr" :null
                                            "confidence" "likely"))
                           "entries"
                           (vector
                            ;; A symbol renamed: gone under its name, found by its fingerprint.
                            (reproducible "ev-renamed" "pdf" "sym.old_main" renamed-listing
                                          "anchor" (anchor "anchor" "sym.old_main" "function" "sym.old_main")
                                          "claims" (vector "old_main parses the arguments."))
                            ;; The same, with nothing to find it by.
                            (reproducible "ev-renamed-nofp" "pdf" "sym.old_main" renamed-listing
                                          "claims" (vector "old_main is called once."))
                            ;; A fingerprint nothing here matches.
                            (reproducible "ev-nomatch" "pdf" "sym.old_main" renamed-listing
                                          "anchor" (anchor "function" "sym.old_main" "size" 7 "nbbs" 1
                                                           "mnemonics" (vector "nop" "hlt"))
                                          "claims" (vector "old_main is small."))
                            ;; A numeric anchor where nothing is any more: the code moved.
                            (reproducible "ev-moved-empty" "pdf" "0x10" listing
                                          "anchor" (anchor "anchor" "0x10" "offset" "0x10")
                                          "claims" (vector "The code at 0x10 is main."))
                            ;; A numeric anchor that now shows other code: relocated all the same.
                            (reproducible "ev-moved" "pdf" entry-ea listing
                                          "anchor" (anchor "anchor" entry-ea "offset" entry-ea)
                                          "claims" (vector "The code at 0x10 is main."))
                            ;; A numeric anchor that drifted, with no fingerprint and with one that finds nothing.
                            (reproducible "ev-pinned" "pd 4" entry-ea entry-listing
                                          "reproHash" (carry-sha #\0) "shiftHash" (carry-sha #\0)
                                          "canonicalExcerpt" (format nil "0x00000010      nop~%0x00000011      ret")
                                          "claims" (vector "entry0 is two instructions."))
                            (reproducible "ev-pinned-fp" "pd 4" entry-ea entry-listing
                                          "reproHash" (carry-sha #\0) "shiftHash" :null
                                          "anchor" (anchor "size" 7 "nbbs" 1 "mnemonics" (vector "nop" "hlt"))
                                          "claims" (vector "entry0 changed further down."))
                            ;; A command that now prints nothing.
                            (reproducible "ev-silent" "pdf" "0x10" listing
                                          "claims" (vector "There is a function at 0x10."))
                            ;; What cannot be checked at all.
                            (manifest-row "ev-prov" "tool" "get_function" "command" "afij @ main"
                                                    "commands" (vector "afij @ main")
                                                    "claims" (vector "main is a function."))
                            (manifest-row "ev-legacy" "claims" (vector "Something was seen."))
                            (reproducible "ev-write" "wx 90" "entry0" "x" "claims" (vector "It can be patched."))
                            (reproducible "ev-addr" "pdf" "main;wx 90" "x" "claims" (vector "It can be patched."))
                            ;; An id listed twice is carried once.
                            (reproducible "ev-renamed" "pdf" "sym.no_such" "x"
                                          "claims" (vector "old_main parses the arguments.")))))))
                  (multiple-value-bind (result text failed) (carried path)
                    (flet ((status (id) (gethash "status" (row-of result id)))
                           (detail (id) (gethash "detail" (row-of result id))))
                      (check "an id listed twice is carried once"
                             (= 12 (length (gethash "evidence" result))))
                      (check "a renamed symbol is found again by its fingerprint: relocated, the name folded back"
                             (let ((row (row-of result "ev-renamed")))
                               (and (equal "relocated" (gethash "status" row))
                                    (equal (format nil "sym.old_main renamed to ~a (code similarity 1); output identical" name)
                                           (gethash "detail" row))
                                    (equal '("evidenceId" "tool" "command" "status" "detail" "relocation" "rerun")
                                           (carry-keys row))
                                    (equal (format nil "pdf @ ~a" start) (gethash "command" row))
                                    (string= (format nil "{\"from\":\"sym.old_main @ ~a\",\"to\":\"~a @ ~a\",\"fromName\":\"sym.old_main\",\"fromOffset\":\"~a\",\"toName\":\"~a\",\"toOffset\":\"~a\",\"addr\":\"~a\",\"similarity\":1}"
                                                     start name start start name start start)
                                             (omp-re:json-encode (gethash "relocation" row)))
                                    (string= (format nil "{\"command\":\"pdf\",\"addr\":\"~a\"}" start)
                                             (omp-re:json-encode (gethash "rerun" row))))))
                      (check "without a fingerprint the same anchor can only be broken"
                             (and (equal "broken" (status "ev-renamed-nofp"))
                                  (equal "anchor `sym.old_main` no longer resolves in this binary"
                                         (detail "ev-renamed-nofp"))))
                      (check "and with one that matches nothing, the line says it was looked for"
                             (and (equal "broken" (status "ev-nomatch"))
                                  (equal "anchor `sym.old_main` no longer resolves in this binary and no function matching its fingerprint was found"
                                         (detail "ev-nomatch"))))
                      (check "a numeric anchor with nothing at it any more is relocated to where the code went"
                             (and (equal "relocated" (status "ev-moved-empty"))
                                  (equal (format nil "~a moved from 0x10 to ~a (code similarity 1); output identical" name start)
                                         (detail "ev-moved-empty"))))
                      (check "a numeric anchor that now shows other code is relocated too"
                             (and (equal "relocated" (status "ev-moved"))
                                  (equal (format nil "~a moved from ~a to ~a (code similarity 1); output identical"
                                                 name entry-ea start)
                                         (detail "ev-moved"))))
                      (check "a drifted numeric anchor with no fingerprint says the code may have moved, with the diff"
                             (let ((row (row-of result "ev-pinned")))
                               (and (equal "drifted" (gethash "status" row))
                                    (equal (format nil "output changed; pinned to numeric address ~a — the code it named may have moved in this build"
                                                   entry-ea)
                                           (gethash "detail" row))
                                    (equal "- 0x00000010      nop" (aref (gethash "diff" row) 0))
                                    (some (lambda (line) (and (starts "+ " line) (has "endbr64" line)))
                                          (gethash "diff" row)))))
                      (check "one whose excerpt still matches drifted further down, and its fingerprint found nothing"
                             (let ((row (row-of result "ev-pinned-fp")))
                               (and (equal "drifted" (gethash "status" row))
                                    (equal (format nil "output changed beyond the recorded 20-line excerpt (re-run to see it); pinned to numeric address ~a; no function matching its fingerprint was found elsewhere"
                                                   entry-ea)
                                           (gethash "detail" row))
                                    (not (nth-value 1 (gethash "diff" row))))))
                      (check "a command that now prints nothing is broken"
                             (and (equal "broken" (status "ev-silent"))
                                  (starts "command now produces no output" (detail "ev-silent"))
                                  (equal "pdf @ 0x10" (gethash "command" (row-of result "ev-silent")))))
                      (check "another tool's record, and one with no hash, are unchecked and never run"
                             (and (equal "unchecked" (status "ev-prov"))
                                  (equal "provenance-only: no reproducible hash to compare (re-run by hand)" (detail "ev-prov"))
                                  (equal "afij @ main" (gethash "command" (row-of result "ev-prov")))
                                  (equal "unchecked" (status "ev-legacy"))
                                  (equal "legacy: no reproducible hash recorded" (detail "ev-legacy"))
                                  (equal '("evidenceId" "tool" "status" "detail") (carry-keys (row-of result "ev-legacy")))))
                      (check "the manifest is untrusted: a write, or an address that smuggles one in, is never sent"
                             (and (equal "unchecked" (status "ev-write"))
                                  (starts "not runnable here: omp-re: rizin_command: \"wx\" is not available here: only read-only"
                                                   (detail "ev-write"))
                                  (equal "wx 90" (gethash "command" (row-of result "ev-write")))
                                  (equal "unchecked" (status "ev-addr"))
                                  (equal "not runnable here: omp-re: invalid address or expression: \"main;wx 90\""
                                         (detail "ev-addr"))))
                      (check "the claims roll up, and a broken one fails the line"
                             (and failed
                                  (string= (format nil "omp-re: carry aaaaaaaaaaaa… → ~a… — 0 hold, 2 relocated, 2 drifted, 3 BROKEN, 3 unchecked (of 10 claim(s))~%  BROKEN    old_main is called once.~%  BROKEN    old_main is small.~%  BROKEN    There is a function at 0x10.~%  DRIFTED   entry0 is two instructions.~%  DRIFTED   entry0 changed further down.~%  UNCHECKED main is a function.~%  UNCHECKED Something was seen.~%  UNCHECKED It can be patched.~%  RELOCATED old_main parses the arguments.~%  RELOCATED The code at 0x10 is main."
                                                   (subseq v1-sha 0 12))
                                           text)))
                      (check "the carry report names each relocation"
                             (has (format nil "- **Relocated:** sym.old_main @ ~a → ~a @ ~a (similarity 1)~%- **Detail:** sym.old_main renamed to "
                                          start name start)
                                  (omp-re::format-carry-markdown result path)))))

                  ;; --inherit follows the relocation.
                  (let ((text (refusal (lambda () (re:slash (format nil "carry ~a --inherit" path))))))
                    (check "--inherit re-proves the relocated findings; one with nothing reproduced goes on the agenda"
                           (and (has (format nil "~%inherit: 2 finding(s) re-proven on this build and recorded, 1 need another look~%")
                                     text)
                                (has (format nil "~%1. [unchecked] main is a function.~%   - evidence ev-prov `afij @ main`: unchecked — provenance-only: no reproducible hash to compare (re-run by hand)")
                                     text))))
                  (let* ((findings (omp-re::entries-of "re.finding" session))
                         (renamed (first findings))
                         (moved (second findings)))
                    (check "the evidence is the command re-run where the code is now"
                           (equal (list (format nil "pdf @ ~a" start) (format nil "pdf @ ~a" start)
                                        (format nil "pdf @ ~a" start))
                                  (mapcar (lambda (record) (aref (gethash "commands" record) 0))
                                          (omp-re::evidence-records session))))
                    (check "a finding about the old name is now about the new one, and says how it got here"
                           (and (equal name (gethash "addr" renamed))
                                (equal "speculative" (gethash "confidence" renamed))
                                (= 1 (length (gethash "evidenceIds" renamed)))
                                (string= (format nil "{\"fromBinarySha256\":\"~a\",\"fromFindingId\":\"f-renamed\",\"carryStatus\":\"relocated\",\"relocation\":{\"from\":\"sym.old_main @ ~a\",\"to\":\"~a @ ~a\",\"similarity\":1}}"
                                                 (carry-sha #\a) start name start)
                                         (omp-re:json-encode (gethash "inherited" renamed)))
                                (has (format nil "confidence: speculative · at `~a` · inherited from `aaaaaaaaaaaa…`, re-verified on this build (relocated: sym.old_main @ ~a → ~a @ ~a)"
                                             name start name start)
                                     (re:slash (format nil "findings ~a" (gethash "id" renamed))))))
                    (check "a finding about the old address is now about the new one, on both rows' evidence"
                           (and (equal start (gethash "addr" moved))
                                (= 2 (length (gethash "evidenceIds" moved)))
                                (equal "relocated" (gethash "carryStatus" (gethash "inherited" moved)))))
                    (check "the status line counts them"
                           (has "findings on this branch: 2 (2 inherited)" (re:status))))))))))))
