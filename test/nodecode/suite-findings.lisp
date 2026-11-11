;;;; suite-findings.lisp --- findings, /re verify and /re report.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The first half needs no rizin: the gates read the record, so a record
;;;; written by hand is enough. The second half runs the whole loop on the
;;;; test binary through the verbs.

(in-package #:nodecode-re-test)

(defun sha-of (char) (make-string 64 :initial-element char))

(defun seeded-session (&key (sha (sha-of #\a)))
  "A fresh session whose record says a binary with hash SHA is open and
holds one reproducible rizin_command record. Nothing in it needs the binary
to exist. => the session's id."
  (let* ((id (fresh-session))
         (session (omp-re:find-session id)))
    (omp-re::append-entry "re.binary" (omp-re:obj "path" "/bin/sample" "sha256" sha) session)
    (omp-re::append-entry "re.evidence"
                      (omp-re:obj "id" "11111111-aaaa-bbbb-cccc-000000000001"
                               "tool" "rizin_command"
                               "args" (omp-re:obj "command" "pdf" "addr" "sym.f")
                               "commands" (vector "pdf @ sym.f")
                               "reproHash" (sha-of #\b)
                               "binarySha256" sha
                               "summary" "imul eax, eax, 0x21")
                      session)
    (setf (omp-re::session-binary-sha256 session) sha)
    id))

(defun live (id) (omp-re::live-findings (omp-re:find-session id)))

(defun keys (object)
  (loop for key being the hash-keys of object collect key))

(defmacro with-annotations ((&rest annotations) &body body)
  "BODY with LIVE-ANNOTATIONS answering ANNOTATIONS, whatever annotation
module is or is not loaded, and put back after."
  (let ((had (gensym "HAD")))
    `(let ((,had (and (fboundp 'omp-re::live-annotations) (fdefinition 'omp-re::live-annotations))))
       (unwind-protect
            (progn
              (setf (fdefinition 'omp-re::live-annotations)
                    (lambda (binary-path &optional session)
                      (declare (ignore binary-path session))
                      (list ,@annotations)))
              ,@body)
         (if ,had
             (setf (fdefinition 'omp-re::live-annotations) ,had)
             (fmakunbound 'omp-re::live-annotations))))))

(defun annotation (new-value evidence-id)
  (omp-re:obj "kind" "comment" "ea" "0x401000" "oldValue" "" "newValue" new-value "evidenceId" evidence-id))

;;; --- the pieces ---------------------------------------------------------------------------

(suite "report: indicators")
(check "a URL is defanged: scheme, dots, and nothing else"
       (and (string= "hxxp://185[.]220[.]101[.]99/update[.]php"
                     (omp-re::defang-ioc "http://185.220.101.99/update.php"))
            (string= "hxxps://evil[.]example/a" (omp-re::defang-ioc "HTTPS://evil.example/a"))))
(check "an IPv4 literal and an address are defanged; a path and a registry key keep their separators"
       (and (string= "10[.]0[.]0[.]1" (omp-re::defang-ioc "10.0.0.1"))
            (string= "/etc/cron.d/job" (omp-re::defang-ioc "/etc/cron.d/job"))
            (string= "HKLM\\Software.x" (omp-re::defang-ioc "HKLM\\Software.x"))
            (string= "a[@]b.c" (omp-re::defang-ioc "a@b.c"))))
(check "indicators are found in prose and raw JSON, never ending mid-punctuation"
       (equal '("/usr/share/locale" "http://185.220.101.99/update.php" "185.220.101.99" "HKLM\\Software")
              (omp-re::iocs-in "{\"s\":\"/usr/share/locale\", \"u\":\"http://185.220.101.99/update.php\"}, HKLM\\Software;")))
(check "a path needs three segments to be an indicator"
       (null (omp-re::iocs-in "/lib64/ld.so and 1.2.3")))
(check "claims are listed as localeCompare orders them (the order bun gives these)"
       (let ((ordered '("_x" "-x" ",x" ";x" ":x" "!x" "?x" ".x" "\"x" "(x" "[x" "{x" "@x" "*x" "/a/b/c" "\\x"
                        "&x" "#x" "%x" "`x" "^x" "+x" "<x" "=x" "|x" "~x" "$x" "0x" "10[.]0[.]0[.]1" "9x"
                        "a b" "a-b" "a.b" "a1" "aa" "ab" "alpha" "ax" "aX" "Ax" "beta" "Beta" "hxxp://x")))
         (and (equal ordered (stable-sort (reverse ordered) #'omp-re::locale-less-p))
              (equal ordered (stable-sort (sort (copy-list ordered) #'string<) #'omp-re::locale-less-p))
              (not (omp-re::locale-less-p "same" "same")))))

(suite "verify: what a record says of itself")
(check "a read with a repro hash, bound to a binary, is reproducible; another tool's record with one is not"
       (and (string= "reproducible"
                     (omp-re::evidence-status (omp-re:obj "tool" "rizin_command" "args" (omp-re:obj "command" "pdf")
                                                          "reproHash" (sha-of #\a) "binarySha256" (sha-of #\b))))
            (string= "provenance-only"
                     (omp-re::evidence-status (omp-re:obj "tool" "decompile" "commands" (vector "pdg @ main")
                                                          "reproHash" (sha-of #\a) "binarySha256" (sha-of #\b))))))
(check "what the report says of a record and what /re verify and /re carry do with it are one decision"
       (flet ((agree (record)
                (eq (and (omp-re::evidence-rerun record) t)
                    (and (member (omp-re::evidence-status record) '("reproducible") :test #'string=) t))))
         (and (agree (omp-re:obj "tool" "rizin_command" "args" (omp-re:obj "command" "pdf")
                                 "reproHash" (sha-of #\a) "binarySha256" (sha-of #\b)))
              (agree (omp-re:obj "tool" "decompile" "commands" (vector "pdg @ main")
                                 "reproHash" (sha-of #\a) "binarySha256" (sha-of #\b)))
              (agree (omp-re:obj "tool" "rizin_command" "args" (omp-re:obj "command" "pdf")))
              (agree (omp-re:obj "tool" "list_imports")))))
(check "a command but no repro hash is provenance-only"
       (string= "provenance-only"
                (omp-re::evidence-status (omp-re:obj "tool" "get_function" "commands" (vector "afij @ 0x4da0")))))
(check "neither is unverifiable (legacy)"
       (string= "unverifiable (legacy)" (omp-re::evidence-status (omp-re:obj "tool" "list_imports"))))
(check "the command shown is the recorded line, else the recorded arguments as a line"
       (and (string= "a ; b" (omp-re::evidence-command (omp-re:obj "commands" (vector "a" "b"))))
            (string= "pdf @ main"
                     (omp-re::evidence-command (omp-re:obj "args" (omp-re:obj "command" "pdf" "addr" "main"))))
            (null (omp-re::evidence-command (omp-re:obj "args" (omp-re:obj))))))

;;; --- the gates, on a record written by hand ---------------------------------------------------

(suite "findings: the gates")
(with-cell ()
  (check "the three tools and the three /re lines are there"
         (and (every (lambda (name) (has name (re:tools)))
                     '("record_finding" "adopt_finding" "retract_finding"))
              (every (lambda (line) (has line (re:slash "help")))
                     '("/re findings [id]" "/re report [path] [--audit=strict]" "/re verify [--strict]"))))
  (check "(re:doc) shows record_finding's parameters as the schema names them"
         (let ((text (re:doc "record_finding")))
           (and (has ":claim" text) (has ":evidence  list of strings, required" text)
                (has "one of \"confirmed\", \"likely\", \"speculative\"" text)
                (has ":override-audit" text) (has ":supersedes" text))))

  (let ((id (seeded-session)))
    (in-session (id)
      (check "no findings yet, and /re findings says who records them"
             (and (has "no findings on this branch yet" (re:slash "findings"))
                  (has "findings on this branch: 0" (re:status))))
      (let ((text (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111")
                                            :addr "sym.f" :confidence "confirmed")))
        (check "a finding citing an evidence prefix is recorded, and said to carry"
               (and (has "record_finding: recorded " text)
                    (has "claim: f multiplies by 33." text)
                    (has "evidence: 1 of 1 machine-reproducible — this finding will carry to the next build (/re carry)" text)))
        (check "with no side turn the support audit fails open: unaudited, word for word"
               (has "support audit: unaudited — no model / side turns unavailable" text)))
      (let ((entry (car (last (omp-re::entries-of "re.finding" (omp-re:find-session id))))))
        (check "the re.finding entry has its members in the record's fixed order"
               (and (equal '("id" "claim" "evidenceIds" "addr" "confidence" "audit" "binarySha256") (keys entry))
                    (equalp #("11111111-aaaa-bbbb-cccc-000000000001") (gethash "evidenceIds" entry))
                    (equal "confirmed" (gethash "confidence" entry))
                    (equal "sym.f" (gethash "addr" entry))
                    (equal (sha-of #\a) (gethash "binarySha256" entry))
                    (equal '("verdict" "reason") (keys (gethash "audit" entry)))
                    (equal "unaudited" (gethash "verdict" (gethash "audit" entry))))))
      (check "an unknown evidence id is refused, saying where ids come from"
             (let ((text (refusal (lambda () (re:call "record_finding" :claim "x" :evidence '("deadbeef"))))))
               (and (has "omp-re: record_finding: evidence not found — no id starting \"deadbeef\" on this branch." text)
                    (has "Cite ids from RE tool results on this branch (/re evidence lists them)." text))))
      (check "an id prefix shorter than six characters is refused as too short"
             (has "\"111\" is too short (use at least 6 characters of the id)"
                  (refusal (lambda () (re:call "record_finding" :claim "x" :evidence '("111"))))))
      (check "every bad id is named in the one refusal"
             (let ((text (refusal (lambda () (re:call "record_finding" :claim "x" :evidence '("deadbeef" "111"))))))
               (and (has "\"deadbeef\"" text) (has "; \"111\" is too short" text))))
      (check "a finding citing no evidence is refused"
             (and (has "evidence must cite 1 to 16 evidence ids (was 0)"
                       (refusal (lambda () (re:call "record_finding" :claim "x" :evidence #()))))
                  (has "evidence is required" (refusal (lambda () (re:call "record_finding" :claim "x"))))))
      (check "an empty claim and one past 600 characters are refused"
             (and (has "claim must be 1 to 600 characters (was 0)"
                       (refusal (lambda () (re:call "record_finding" :claim "" :evidence '("11111111")))))
                  (has "(was 601)"
                       (refusal (lambda () (re:call "record_finding" :claim (make-string 601 :initial-element #\x)
                                                                     :evidence '("11111111")))))))
      (check "a confidence outside the three is refused by the schema"
             (has "confidence must be one of"
                  (refusal (lambda () (re:call "record_finding" :claim "x" :evidence '("11111111")
                                                                :confidence "possible")))))
      (check "none of the refusals recorded anything" (= 1 (length (live id))))

      (let ((first-id (gethash "id" (first (live id)))))
        (check "superseding an unknown finding is refused"
               (has "omp-re: record_finding: cannot supersede — no id starting \"00000000\" on this branch"
                    (refusal (lambda () (re:call "record_finding" :claim "x" :evidence '("11111111")
                                                                  :supersedes "00000000")))))
        (check "supersedes replaces a finding, by a prefix of its id"
               (let ((text (re:call "record_finding" :claim "second" :evidence '("11111111")
                                                     :supersedes (subseq first-id 0 8))))
                 (and (has (format nil "(supersedes ~a)" (subseq first-id 0 8)) text)
                      (equal '("second") (mapcar (lambda (finding) (gethash "claim" finding)) (live id)))
                      (equal first-id (gethash "supersedes" (first (live id)))))))
        (check "the superseded finding can no longer be retracted"
               (has "omp-re: retract_finding: no id starting"
                    (refusal (lambda () (re:call "retract_finding" :id first-id :reason "gone"))))))
      (let ((second-id (gethash "id" (first (live id)))))
        (check "/re findings lists the live ones; an id shows one with its provenance and evidence"
               (and (has (format nil "omp-re: findings~%[~a] second" (subseq second-id 0 8)) (re:slash "findings"))
                    (string= (format nil "finding ~a: second~%confidence: likely~%evidence: 11111111"
                                     (subseq second-id 0 8))
                             (re:slash (format nil "findings ~a" (subseq second-id 0 8))))
                    (has "omp-re: no live finding with id nopenope"
                         (refusal (lambda () (re:slash "findings nopenope"))))
                    (has "omp-re: finding id \"nope\" is too short"
                         (refusal (lambda () (re:slash "findings nope"))))))
        (check "retract_finding withdraws one, with the reason, and writes a re.finding.retract entry"
               (let ((text (re:call "retract_finding" :id second-id :reason "wrong function")))
                 (and (string= (format nil "retract_finding: withdrew ~a — second~%reason: wrong function"
                                       (subseq second-id 0 8))
                               text)
                      (null (live id))
                      (equal '("id" "reason")
                             (keys (first (omp-re::entries-of "re.finding.retract" (omp-re:find-session id)))))))))
      (check "a retraction needs a reason"
             (has "reason must be 1 to 300 characters"
                  (refusal (lambda () (re:call "retract_finding" :id "11111111" :reason ""))))))

    (in-session (id)
      (setf (omp-re::session-binary-sha256 (omp-re:find-session id)) (sha-of #\c))
      (check "evidence taken against a different binary than the one open is refused"
             (has "omp-re: record_finding: evidence 11111111 was taken against a different binary than the one open — re-gather it on this binary."
                  (refusal (lambda () (re:call "record_finding" :claim "x" :evidence '("11111111"))))))
      (check "adopt_finding refuses a finding made on another binary before anything runs"
             (has "omp-re: adopt_finding: the finding was made on binary eeeeeeeeeeee… but cccccccccccc… is open — open the same binary first."
                  (refusal (lambda () (re:call "adopt_finding" :claim "c" :commands '((:command "pdf" :addr "sym.f"))
                                                               :expect-sha256 (sha-of #\e))))))
      (check "adopt_finding needs one to eight commands"
             (has "commands must hold 1 to 8 commands (was 9)"
                  (refusal (lambda () (re:call "adopt_finding" :claim "c"
                                                               :commands (make-list 9 :initial-element '(:command "pdf")))))))))

  (check "a finding's note carries inheritance, adoption and an audit override"
         (string= "confidence: likely · at `sym.fibonacci` · inherited from `aaaaaaaaaaaa…`, re-verified on this build (relocated: sym.fib @ 0x11fd → sym.fibonacci @ 0x11fd) · adopted from re-analyst, re-proven in this session · recorded over a support-audit \"overreach\" verdict — justification: it is djb2"
                  (omp-re::finding-note
                   (omp-re:obj "confidence" "likely" "addr" "sym.fibonacci"
                            "inherited" (omp-re:obj "fromBinarySha256" (sha-of #\a) "carryStatus" "relocated"
                                                 "relocation" (omp-re:obj "from" "sym.fib @ 0x11fd"
                                                                       "to" "sym.fibonacci @ 0x11fd"))
                            "adoptedFrom" "re-analyst"
                            "audit" (omp-re:obj "verdict" "overreach" "reason" "r" "override" "it is djb2")))))
  (let ((id (fresh-session)))
    (let ((session (omp-re:find-session id)))
      (omp-re::append-entry "re.finding" (omp-re:obj "id" "a" "claim" "kept" "evidenceIds" (vector "e" 7)
                                              "confidence" "certain")
                        session)
      (omp-re::append-entry "re.finding" (omp-re:obj "id" "b" "claim" "no evidence array") session)
      (omp-re::append-entry "re.finding" (omp-re:obj "id" "c" "claim" "inherited" "evidenceIds" (vector)
                                              "inherited" (omp-re:obj "carryStatus" "holds"))
                        session))
    (check "a record read back keeps what is a finding, with a known confidence and string ids only"
           (let ((findings (live id)))
             (and (equal '("a" "c") (mapcar (lambda (finding) (gethash "id" finding)) findings))
                  (equal "likely" (gethash "confidence" (first findings)))
                  (equalp #("e") (gethash "evidenceIds" (first findings))))))
    (check "the status line counts the inherited ones"
           (in-session (id) (has "findings on this branch: 2 (1 inherited)" (re:status))))))

;;; --- the report, on a record written by hand -------------------------------------------------

(suite "report: the gate and the page")
(with-cell ()
  (let ((id (fresh-session))
        (path (uiop:native-namestring (merge-pathnames "empty.md" *scratch*))))
    (in-session (id)
      (check "an empty record writes a trivial report without tripping the gate"
             (and (string= (format nil "omp-re: report written to ~a (+ ~a.manifest.json)" path path)
                           (re:slash (format nil "report ~a" path)))
                  (string= (format nil "# Analysis Report — Session ~a~%~%## Conclusion~%~%This report was generated from an automated analysis session.~%"
                                   id)
                           (omp-re::read-text-file path))))
      (check "its manifest is the three members, binarySha256 null"
             (let ((manifest (omp-re:json-decode (omp-re::read-text-file (format nil "~a.manifest.json" path)))))
               (and (equal '("binarySha256" "findings" "entries") (keys manifest))
                    (eq :null (gethash "binarySha256" manifest))
                    (equalp #() (gethash "findings" manifest))
                    (equalp #() (gethash "entries" manifest)))))
      (check "the title names a long session id by its last eight characters"
             (string= "Analysis Report — Session 23456789"
                      (omp-re::built-report-title
                       (omp-re::build-report (omp-re::make-session :id "session-0123456789")))))
      (check "a report that cannot be written says where and why, as a failure"
             (has "omp-re: could not write report to /nonexistent-dir/x.md: "
                  (refusal (lambda () (re:slash "report /nonexistent-dir/x.md")))))))

  (let* ((id (seeded-session))
         (session (omp-re:find-session id))
         (path (uiop:native-namestring (merge-pathnames "hand.md" *scratch*))))
    (in-session (id)
      (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111")
                                :addr "sym.f" :confidence "confirmed")
      (omp-re::append-entry "re.evidence"
                        (omp-re:obj "id" "ev-strings" "tool" "list_strings"
                                 "summary" "found string: http://185.220.101.99/update.php in .data section")
                        session)
      (omp-re::append-entry "re.evidence" (omp-re:obj "id" "ev-nosummary" "tool" "list_strings") session)
      (let ((markdown (re:slash "report")))
        (check "with no path the report itself is the answer: findings with provenance and anchors"
               (and (has (format nil "## Findings~%~%- f multiplies by 33.~%  _confidence: confirmed · at `sym.f`_~%  **Evidence:** [rizin_command:11111111-aaaa-bbbb-cccc-000000000001]~%")
                         markdown)
                    (has (format nil "## Indicators of Compromise~%~%- 185[.]220[.]101[.]99~%  **Evidence:** [list_strings:ev-strings]~%- hxxp://185[.]220[.]101[.]99/update[.]php~%  **Evidence:** [list_strings:ev-strings]~%")
                         markdown)))
        (check "the support audit cannot run here, and the report says so under its claims"
               (has (format nil "~%> _Claim–evidence support unaudited — no model / side turns unavailable._~%~%## Verification Manifest")
                    markdown))
        (check "the manifest table resolves each cited id: command, repro hash, status"
               (and (has (format nil "Binary SHA-256: `~a`" (sha-of #\a)) markdown)
                    (has "| `11111111` | rizin_command | `pdf @ sym.f` | `bbbbbbbbbbbb…` | reproducible |" markdown)
                    (has "| `ev-strin` | list_strings | — | — | unverifiable (legacy) |" markdown)
                    (ends (format nil "|~%") markdown)
                    (not (ends (format nil "|~%~%") markdown)))))
      (check "--no-audit and --audit=off skip the audit, so no note; --audit=strict fails open and still writes"
             (and (not (has "support unaudited" (re:slash "report --no-audit")))
                  (not (has "support unaudited" (re:slash "report --audit=off")))
                  (has "support unaudited" (re:slash "report --audit"))
                  (has "support unaudited" (re:slash "report --audit=strict"))
                  (has "report written to" (re:slash (format nil "report --audit=strict ~a" path)))
                  (has "support unaudited" (omp-re::read-text-file path))))
      (check "the flags are taken out wherever they stand and the rest is the path"
             (and (has (format nil "report written to ~a " path)
                       (re:slash (format nil "report ~a --no-audit" path)))
                  (not (has "support unaudited" (omp-re::read-text-file path)))))
      (let* ((manifest (omp-re:json-decode (omp-re::read-text-file (format nil "~a.manifest.json" path))))
             (entries (gethash "entries" manifest))
             (entry (aref entries 0)))
        (check "the manifest file is JSON.stringify(…, null, 2) and a newline"
               (let ((text (omp-re::read-text-file (format nil "~a.manifest.json" path))))
                 (and (starts (format nil "{~%  \"binarySha256\": \"~a\",~%  \"findings\": [~%    {~%      \"id\": "
                                               (sha-of #\a))
                                       text)
                      (ends (format nil "~%}~%") text))))
        (check "its findings block is what /re carry --inherit re-proves"
               (let ((finding (aref (gethash "findings" manifest) 0)))
                 (and (equal '("id" "claim" "evidenceIds" "addr" "confidence") (keys finding))
                      (equal "f multiplies by 33." (gethash "claim" finding))
                      (equal "sym.f" (gethash "addr" finding))
                      (equal "confirmed" (gethash "confidence" finding)))))
        (check "a manifest entry has every member, in the manifest's fixed order"
               (equal '("evidenceId" "tool" "args" "command" "commands" "reproHash" "canonicalExcerpt"
                        "shiftHash" "anchor" "binarySha256" "status" "claims")
                      (keys entry)))
        (check "a rizin_command entry carries its structured args, its hashes and the claims it backs"
               (and (equal "11111111-aaaa-bbbb-cccc-000000000001" (gethash "evidenceId" entry))
                    (equal '("command" "addr") (keys (gethash "args" entry)))
                    (equal "pdf @ sym.f" (gethash "command" entry))
                    (equalp #("pdf @ sym.f") (gethash "commands" entry))
                    (equal (sha-of #\b) (gethash "reproHash" entry))
                    (equal "reproducible" (gethash "status" entry))
                    (equalp #("f multiplies by 33.") (gethash "claims" entry))
                    ;; No such binary to fingerprint: the entry is whole, without an anchor.
                    (eq :null (gethash "anchor" entry))))
        (check "what a record lacks is null, never left out; one entry backs both its claims"
               (let ((strings (aref entries 1)))
                 (and (= 2 (length entries))
                      (every (lambda (key) (eq :null (gethash key strings)))
                             '("args" "command" "commands" "reproHash" "canonicalExcerpt" "shiftHash"
                               "anchor" "binarySha256"))
                      (equal "unverifiable (legacy)" (gethash "status" strings))
                      (equalp #("185[.]220[.]101[.]99" "hxxp://185[.]220[.]101[.]99/update[.]php")
                              (gethash "claims" strings))))))

      (check "/re verify: other tools' and legacy records are unverifiable, which fails only under --strict"
             (and (string= "omp-re: verify — 0 reproducible, 0 FAILED, 2 unverifiable (of 2 evidence record(s))"
                           (re:slash "verify"))
                  (let ((text (refusal (lambda () (re:slash "verify --strict")))))
                    (and (has "  UNVERIFIABLE ev-strin list_strings: legacy: no reproducible hash recorded" text)
                         ;; /bin/sample cannot be opened, so the re-run fails: unverifiable, never FAILED.
                         (has "  UNVERIFIABLE 11111111 rizin_command: re-run failed: " text)))))
      (setf (omp-re::session-binary-sha256 session) (sha-of #\c))
      (check "evidence bound to a different binary is unverifiable, not a false pass or fail"
             (has "UNVERIFIABLE 11111111 rizin_command: evidence was taken against a different binary — open sha aaaaaaaaaaaa… to verify"
                  (refusal (lambda () (re:slash "verify --strict")))))
      (setf (omp-re::session-binary-sha256 session) (sha-of #\a))

      ;; The write gate.
      (omp-re::append-entry "re.finding" (omp-re:obj "id" "22222222-0000" "claim" "It beacons to a C2."
                                              "evidenceIds" (vector))
                        session)
      (let ((withheld (uiop:native-namestring (merge-pathnames "withheld.md" *scratch*))))
        (check "a claim with no evidence withholds the whole report, naming the claim, and writes nothing"
               (and (string= (format nil "omp-re: report withheld — 1 claim(s) without evidence:~%  - It beacons to a C2.")
                             (refusal (lambda () (re:slash (format nil "report ~a" withheld)))))
                    (null (probe-file withheld))
                    (null (probe-file (format nil "~a.manifest.json" withheld)))))
        (check "the gate holds whatever the audit mode, and with no path too"
               (and (has "report withheld" (refusal (lambda () (re:slash "report --no-audit"))))
                    (has "report withheld" (refusal (lambda () (re:slash "report --audit=strict"))))))
        (re:call "retract_finding" :id "22222222" :reason "no evidence for it")
        (check "retracting the ungrounded finding lets the report through again"
               (has "report written to" (re:slash (format nil "report ~a" withheld)))))

      ;; Annotations, as annotate.lisp's LIVE-ANNOTATIONS answers them for the open binary.
      (setf (omp-re::session-binary-path session) "/bin/sample")
      (with-annotations ((annotation "http://evil-test.example/payload" ""))
        (check "an IOC in an annotation made on no evidence withholds the report"
               (let ((text (refusal (lambda () (re:slash "report")))))
                 (and (has "omp-re: report withheld — 1 claim(s) without evidence:" text)
                      (has "  - hxxp://evil-test[.]example/payload" text)))))
      (with-annotations ((annotation "http://evil-test.example/payload" "ann-evidence")
                         (annotation "see http://185.220.101.99/update.php" "11111111-aaaa-bbbb-cccc-000000000001")
                         (omp-re:obj "kind" "comment"))
        (let ((markdown (re:slash "report")))
          (check "an annotation's IOC is anchored to the evidence it was made on"
                 (and (has (format nil "- hxxp://evil-test[.]example/payload~%  **Evidence:** [annotation:ann-evidence]") markdown)
                      (has "| `ann-evid` | annotation | — | — | unverifiable (legacy) |" markdown)))
          (check "one indicator seen twice is one claim on both pieces of evidence"
                 (has (format nil "- hxxp://185[.]220[.]101[.]99/update[.]php~%  **Evidence:** [list_strings:ev-strings] [rizin_command:11111111-aaaa-bbbb-cccc-000000000001]")
                      markdown))))
      (check "with the annotations gone the report is as it was"
             (not (has "evil-test" (re:slash "report"))))
      (setf (omp-re::session-binary-path session) nil)

      ;; capa's capabilities, from the blob its record points at.
      (omp-re::append-entry
       "re.evidence"
       (omp-re:obj "id" "ev-capa" "tool" "triage_capa" "summary" "capa: 2 rules"
                "outputHash"
                (omp-re::write-blob
                 (format nil "capa: 2 rules~%~a"
                         (omp-re:json-encode
                          (vector (omp-re:obj "name" "encrypt data using RC4"
                                           "meta" (omp-re:obj "attack" (vector (omp-re:obj "id" "T1027" "technique" "Obfuscated Files"
                                                                                     "subtechnique" "Packing")
                                                                            "T1059")))
                                  (omp-re:obj "meta" (omp-re:obj "name" " create process " "attack" (vector "T9999"))))))))
       session)
      (let ((markdown (re:slash "report --no-audit")))
        (check "capa evidence gives a summary and an anchored capabilities and ATT&CK section"
               (and (has "## Summary" markdown)
                    (has "Analysis performed using **capa** on the provided sample: 2 capability rule(s) matched mapping to 3 ATT&CK technique(s)."
                         markdown)
                    (has (format nil "## Capabilities & MITRE ATT&CK Mapping~%~%- create process~%  **Evidence:** [triage_capa:ev-capa]~%- encrypt data using RC4~%")
                         markdown)
                    (has "- T1027 — Obfuscated Files: Packing" markdown)
                    (has "- T1059 — Command and Scripting Interpreter" markdown)
                    (has "- T9999 — (unmapped technique)" markdown)
                    (< (search "## Summary" markdown) (search "## Capabilities" markdown)
                       (search "## Findings" markdown) (search "## Indicators" markdown)
                       (search "## Conclusion" markdown))))))))

;;; --- with rizin ----------------------------------------------------------------------------------

(cond
  ((not *rizin*)
   (suite "findings, verify and report against a binary")
   (format t "  SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*))
  (t
   (suite (format nil "findings, verify and report (~a)" *binary*))
   (with-cell ()
     (let ((id (fresh-session))
           (path (uiop:native-namestring (merge-pathnames "ls.md" *scratch*))))
       (in-session (id)
         (re:open *binary*)
         (let* ((info-evidence (nth-value 1 (re:json "iIj")))
                (entry-evidence (tagged-evidence (re:cmd "pd 4" "entry0")))
                (session (omp-re:find-session id))
                (sha (omp-re::session-binary-sha256 session)))
           (let ((text (re:call "record_finding" :claim "The binary is a 64-bit ELF."
                                                 :evidence (list info-evidence) :confidence "confirmed")))
             (check "a finding citing the evidence id of a real read is recorded and will carry"
                    (and (has "record_finding: recorded " text)
                         (has "evidence: 1 of 1 machine-reproducible" text)
                         (equal sha (gethash "binarySha256" (first (live id))))
                         (starts info-evidence
                                          (aref (gethash "evidenceIds" (first (live id))) 0)))))
           (check "one citing an unknown id is refused, and one citing none"
                  (and (has "evidence not found — no id starting \"0badc0de\" on this branch"
                            (refusal (lambda () (re:call "record_finding" :claim "x" :evidence '("0badc0de")))))
                       (has "evidence must cite 1 to 16"
                            (refusal (lambda () (re:call "record_finding" :claim "x" :evidence #()))))
                       (= 1 (length (live id)))))
           (check "the same id cited twice is one piece of evidence"
                  (progn
                    (re:call "record_finding" :claim "entry0 clears ebp first." :addr "entry0"
                                              :evidence (list entry-evidence entry-evidence))
                    (= 1 (length (gethash "evidenceIds" (second (live id)))))))

           ;; adopt_finding: re-prove on this binary, then gate like record_finding.
           (let* ((before (length (omp-re::evidence-records session)))
                  (text (re:call "adopt_finding" :claim "entry0 begins with endbr64."
                                                 :commands '((:command "pd 2" :addr "entry0") (:command "iej"))
                                                 :addr "entry0" :confidence "possible" :source "re-analyst"
                                                 :expect-sha256 (string-upcase sha)))
                  (finding (third (live id)))
                  (records (mapcar (lambda (evidence-id) (omp-re::find-evidence evidence-id session))
                                   (coerce (gethash "evidenceIds" finding) 'list))))
             (check "adopt_finding re-runs each command here and records it as this session's evidence"
                    (and (= (+ before 2) (length (omp-re::evidence-records session)))
                         (equal '("rizin_command" "rizin_command")
                                (mapcar (lambda (record) (gethash "tool" record)) records))
                         (equal '("command" "addr") (keys (gethash "args" (first records))))
                         (equal "entry0" (gethash "addr" (gethash "args" (first records))))
                         (equal '("command") (keys (gethash "args" (second records))))
                         (equalp #("pd 2 @ entry0") (gethash "commands" (first records)))
                         (every (lambda (record)
                                  (and (= 64 (length (gethash "reproHash" record)))
                                       (equal sha (gethash "binarySha256" record))))
                                records)))
             (check "and says so: adopted from its source, re-proven on the new evidence"
                    (and (has "adopt_finding: recorded " text)
                         (has (format nil "adopted from re-analyst: re-proven in this session on evidence ~{~a~^, ~}"
                                      (mapcar (lambda (record) (subseq (gethash "id" record) 0 8)) records))
                              text)
                         (has "evidence: 2 of 2 machine-reproducible" text)))
             (check "the adopted finding keeps its source, and `possible' is taken as speculative"
                    (and (equal "re-analyst" (gethash "adoptedFrom" finding))
                         (equal "speculative" (gethash "confidence" finding))
                         (equal "entry0" (gethash "addr" finding))
                         (has "adopted from re-analyst, re-proven in this session"
                              (re:slash (format nil "findings ~a" (gethash "id" finding)))))))
           (check "a command that does not reproduce here refuses the adoption, and so does a write"
                  (let ((findings (length (live id))))
                    (and (has "omp-re: adopt_finding: `pdf @ sym.no_such_function` failed here: rizin> pdf @ sym.no_such_function"
                              (refusal (lambda () (re:call "adopt_finding" :claim "c"
                                                                           :commands '((:command "pdf" :addr "sym.no_such_function"))))))
                         (has "not available here"
                              (refusal (lambda () (re:call "adopt_finding" :claim "c" :commands '((:command "wx 90" :addr "entry0"))))))
                         (has "open the same binary first"
                              (refusal (lambda () (re:call "adopt_finding" :claim "c" :commands '((:command "iIj"))
                                                                           :expect-sha256 (sha-of #\e)))))
                         (= findings (length (live id))))))
           (check "with no source the finding is adopted from an external analysis"
                  (has "adopted from an external analysis: re-proven"
                       (re:call "adopt_finding" :claim "It has imports." :commands '((:command "iij")))))

           ;; supersede and retract.
           (let ((external (fourth (live id))))
             (re:call "record_finding" :claim "It imports from libc." :evidence (coerce (gethash "evidenceIds" external) 'list)
                                       :supersedes (gethash "id" external))
             (check "a revision takes the superseded finding's place in the list"
                    (equal '("The binary is a 64-bit ELF." "entry0 clears ebp first." "entry0 begins with endbr64."
                             "It imports from libc.")
                           (mapcar (lambda (finding) (gethash "claim" finding)) (live id)))))
           (re:call "retract_finding" :id (subseq (gethash "id" (fourth (live id))) 0 8) :reason "not shown by iij")
           (check "a retracted finding leaves /re findings and the status count"
                  (and (not (has "libc" (re:slash "findings")))
                       (has "entry0 clears ebp first." (re:slash "findings"))
                       (has "findings on this branch: 3" (re:status))))

           ;; verify.
           (let ((count (length (omp-re::evidence-records session))))
             (check "/re verify re-runs every record against the binary and finds them reproducible"
                    (string= (format nil "omp-re: verify — ~d reproducible, 0 FAILED, 0 unverifiable (of ~d evidence record(s))"
                                     count count)
                             (re:slash "verify")))
             (check "verifying recorded no new evidence"
                    (= count (length (omp-re::evidence-records session))))
             (check "and --strict has nothing to add while all of it reproduces"
                    (has "0 FAILED, 0 unverifiable" (re:slash "verify --strict")))
             ;; A record from before the reproducibility fields existed.
             (omp-re::append-entry "re.evidence" (omp-re:obj "id" "1e9ac100-legacy" "tool" "rizin_command"
                                                      "args" (omp-re:obj "command" "iIj") "summary" "old")
                               session)
             (check "a legacy record lacking the reproducibility fields is unverifiable, and does not fail the line"
                    (string= (format nil "omp-re: verify — ~d reproducible, 0 FAILED, 1 unverifiable (of ~d evidence record(s))"
                                     count (1+ count))
                             (re:slash "verify")))
             (check "under --strict it does, and the line says which record and why"
                    (let ((text (refusal (lambda () (re:slash "verify --strict")))))
                      (and (has "0 FAILED, 1 unverifiable" text)
                           (has "  UNVERIFIABLE 1e9ac100 rizin_command: legacy: no reproducible hash recorded" text))))
             ;; Tamper with what the record says the read answered.
             (let* ((record (omp-re::find-evidence entry-evidence session))
                    (true-hash (gethash "reproHash" record)))
               (setf (gethash "reproHash" record) (sha-of #\0))
               (check "a tampered repro hash makes /re verify FAIL, naming the record, its command and both hashes"
                      (let ((text (refusal (lambda () (re:slash "verify")))))
                        (and (has (format nil "omp-re: verify — ~d reproducible, 1 FAILED, 1 unverifiable (of ~d evidence record(s))"
                                          (1- count) (1+ count))
                                  text)
                             (has (format nil "  FAIL ~a rizin_command `pd 4 @ entry0`: output hash changed: recorded 000000000000… but re-run produced ~a…"
                                          entry-evidence (subseq true-hash 0 12))
                                  text)
                             (not (has "UNVERIFIABLE" text)))))
               (setf (gethash "reproHash" record) true-hash)
               (check "put back, it verifies again" (has " 0 FAILED" (re:slash "verify")))))

           ;; report.
           (let ((markdown (re:slash "report")))
             (check "/re report with no path answers the report: title, findings, provenance, anchors"
                    (and (starts (format nil "# Analysis Report — Session ~a~%~%## Findings~%~%- The binary is a 64-bit ELF.~%  _confidence: confirmed_~%  **Evidence:** [rizin_command:~a"
                                                  id info-evidence)
                                          markdown)
                         (has "  _confidence: likely · at `entry0`_" markdown)
                         (has "  _confidence: speculative · at `entry0` · adopted from re-analyst, re-proven in this session_"
                              markdown)
                         (not (has "libc" markdown))
                         (has "This report was generated from an automated analysis session." markdown)))
             (check "its Verification Manifest binds the binary's hash and each cited read's command"
                    (and (has (format nil "Binary SHA-256: `~a`" sha) markdown)
                         (has (format nil "| `~a` | rizin_command | `iIj` | `" info-evidence) markdown)
                         (has (format nil "| `~a` | rizin_command | `pd 4 @ entry0` | `" entry-evidence) markdown)
                         (has "| reproducible |" markdown)
                         (has "support unaudited — no model / side turns unavailable" markdown))))
           (check "/re report <path> writes the report and its manifest beside it"
                  (and (string= (format nil "omp-re: report written to ~a (+ ~a.manifest.json)" path path)
                                (re:slash (format nil "report ~a" path)))
                       (string= (re:slash "report") (omp-re::read-text-file path))))
           (check "a relative path is read against the process's directory"
                  (uiop:with-current-directory (*scratch*)
                    (and (string= "omp-re: report written to rel.md (+ rel.md.manifest.json)"
                                  (re:slash "report rel.md"))
                         (probe-file (merge-pathnames "rel.md" *scratch*))
                         (probe-file (merge-pathnames "rel.md.manifest.json" *scratch*)))))
           (let* ((manifest (omp-re:json-decode (omp-re::read-text-file (format nil "~a.manifest.json" path))))
                  (entries (coerce (gethash "entries" manifest) 'list))
                  (pinned (find-if (lambda (entry) (starts entry-evidence (gethash "evidenceId" entry)))
                                   entries))
                  (unpinned (find-if (lambda (entry) (starts info-evidence (gethash "evidenceId" entry)))
                                     entries)))
             (check "the manifest: the binary's hash, the live findings, one entry for each cited read"
                    (and (equal '("binarySha256" "findings" "entries") (keys manifest))
                         (equal sha (gethash "binarySha256" manifest))
                         (= 3 (length (gethash "findings" manifest)))
                         (= 4 (length entries))
                         (every (lambda (entry)
                                  (and (equal '("evidenceId" "tool" "args" "command" "commands" "reproHash"
                                                "canonicalExcerpt" "shiftHash" "anchor" "binarySha256" "status"
                                                "claims")
                                              (keys entry))
                                       (equal "reproducible" (gethash "status" entry))
                                       (equal sha (gethash "binarySha256" entry))
                                       (= 64 (length (gethash "reproHash" entry)))
                                       (= 64 (length (gethash "shiftHash" entry)))
                                       (stringp (gethash "canonicalExcerpt" entry))))
                                entries)))
             (check "a read with no address has args of its command alone and no anchor"
                    (and (equal '("command") (keys (gethash "args" unpinned)))
                         (equal "iIj" (gethash "command" unpinned))
                         (eq :null (gethash "anchor" unpinned))
                         (equalp #("The binary is a 64-bit ELF.") (gethash "claims" unpinned))))
             (check "an address-pinned read carries the fingerprint /re carry finds its function by"
                    (let ((anchor (gethash "anchor" pinned)))
                      (and (equal '("anchor" "function" "offset" "delta" "size" "nbbs" "mnemonics") (keys anchor))
                           (equal "entry0" (gethash "anchor" anchor))
                           (equal "entry0" (gethash "function" anchor))
                           (starts "0x" (gethash "offset" anchor))
                           (eql 0 (gethash "delta" anchor))
                           (plusp (gethash "size" anchor))
                           (plusp (gethash "nbbs" anchor))
                           (equal "endbr64" (aref (gethash "mnemonics" anchor) 0))
                           (every (lambda (mnemonic) (not (find #\Space mnemonic))) (gethash "mnemonics" anchor))
                           (equal '("command" "addr") (keys (gethash "args" pinned)))
                           (equal "pd 4 @ entry0" (gethash "command" pinned))))))

           ;; The gate, on the real record.
           (omp-re::append-entry "re.finding" (omp-re:obj "id" "33333333-0000" "claim" "It is ransomware."
                                                   "evidenceIds" (vector))
                             session)
           (check "a finding with nothing under it withholds the report"
                  (string= (format nil "omp-re: report withheld — 1 claim(s) without evidence:~%  - It is ransomware.")
                           (refusal (lambda () (re:slash "report")))))
           (re:call "retract_finding" :id "33333333" :reason "nothing shows it")

           ;; The engine forgets the session; the record is the truth.
           (let ((before (mapcar (lambda (finding) (gethash "id" finding)) (live id))))
             (omp-re:shutdown-sessions)
             (check "findings survive the engine forgetting the session: the same ones, in order"
                    (and (equal before (mapcar (lambda (finding) (gethash "id" finding)) (live id)))
                         (has "findings on this branch: 3" (re:status))
                         (has "The binary is a 64-bit ELF." (re:slash "findings"))
                         (not (has "libc" (re:slash "findings")))
                         (not (has "ransomware" (re:slash "findings")))))
             (check "the tampering, never written to the record, is gone with the memory it was done in"
                    (has " 0 FAILED, 1 unverifiable" (re:slash "verify")))
             (check "and the report is written from the record alone, on a rizin started for its anchors"
                    (and (has "## Findings" (re:slash "report"))
                         (has "report written to" (re:slash (format nil "report ~a" path)))
                         (let ((manifest (omp-re:json-decode (omp-re::read-text-file (format nil "~a.manifest.json" path)))))
                           (and (= 3 (length (gethash "findings" manifest)))
                                (some (lambda (entry) (hash-table-p (gethash "anchor" entry)))
                                      (gethash "entries" manifest)))))))))))))
