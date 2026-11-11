;;;; suite-audit.lisp --- the claim-support audit: the port, the gates, the judge.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Three halves, none needing rizin but one check. The audit alone: its
;;;; prompt, its reply parser, every outcome. Then the audit where the
;;;; engine uses it — record_finding and /re report — with a judge put in
;;;; the host port by hand. Then the cell's own
;;;; judge, which asks nodecode a side question: over the stand-in kernel,
;;;; so what is proven is what the cell asks for and what it makes of each
;;;; way a turn can end, never nodecode's side of it.

(in-package #:nodecode-re-test)

(defun audit-evidence (&rest members)
  (apply #'omp-re:obj members))

(defun audit-item (index claim &rest evidence)
  (omp-re::make-audit-item :index index :claim-text claim :evidence evidence))

(defun verdicts-of (outcome)
  "OUTCOME's verdicts as (INDEX VERDICT REASON) lists, in its order."
  (mapcar (lambda (audit)
            (list (omp-re::claim-audit-index audit) (omp-re::claim-audit-verdict audit) (omp-re::claim-audit-reason audit)))
          (omp-re::audit-outcome-by-index outcome)))

(defun judge-saying (verdict &optional (reason "because"))
  "A judge that gives every claim it is put VERDICT and REASON, as a reply
to parse."
  (lambda (prompt)
    (omp-re:json-encode
     (map 'vector (lambda (line)
                    (omp-re:obj "index" (parse-integer line :start 6 :junk-allowed t)
                             "verdict" verdict "reason" reason))
          (remove-if-not (lambda (line) (eql 0 (search "CLAIM " line))) (omp-re:split-lines prompt))))))

(defun audit-session ()
  "A fresh session whose record says a binary is open and holds one
reproducible rizin_command record => its id."
  (let* ((id (fresh-session))
         (session (omp-re:find-session id))
         (sha (make-string 64 :initial-element #\a)))
    (omp-re::append-entry "re.binary" (omp-re:obj "path" "/bin/sample" "sha256" sha) session)
    (omp-re::append-entry "re.evidence"
                      (omp-re:obj "id" "11111111-aaaa-bbbb-cccc-000000000001"
                               "tool" "rizin_command"
                               "args" (omp-re:obj "command" "pdf" "addr" "sym.f")
                               "commands" (vector "pdf @ sym.f")
                               "reproHash" (make-string 64 :initial-element #\b)
                               "binarySha256" sha
                               "summary" "imul eax, eax, 0x21")
                      session)
    (setf (omp-re::session-binary-sha256 session) sha)
    id))

(defun last-finding (id)
  (car (last (omp-re::entries-of "re.finding" (omp-re:find-session id)))))

(defun finding-count (id)
  (length (omp-re::live-findings (omp-re:find-session id))))

;;; --- the port ---------------------------------------------------------------------------------

(suite "audit: the prompt")
(let* ((long (make-string 900 :initial-element #\x))
       (prompt (omp-re::build-audit-prompt
                (list (audit-item 0 "f multiplies by 33."
                                  (audit-evidence "id" "11111111-aaaa-bbbb-cccc-000000000001"
                                                  "tool" "rizin_command" "summary" "imul eax, eax, 0x21"
                                                  "canonicalExcerpt" "imul eax, eax, 0x21"
                                                  "fullText" "the whole output"))
                      (audit-item 3 "g is called twice."
                                  (audit-evidence "id" "ev-b" "tool" "list_strings" "summary" "two calls"
                                                  "fullText" "call g; call g")
                                  (audit-evidence "id" "22222222-long" "tool" "rizin_command" "summary" "s"
                                                  "canonicalExcerpt" long)
                                  (audit-evidence "id" "ev-d" "tool" "rizin_command" "summary" "bare"))
                      (audit-item 4 "nothing quoted."))))
       (lines (omp-re:split-lines prompt)))
  (check "it opens with the auditor's brief, the verdicts and the reply shape, word for word"
         (and (string= (first lines)
                       "You are a strict reverse-engineering report auditor. For EACH numbered claim below, judge ONLY whether the quoted evidence actually supports what the claim asserts. Judge solely against the quoted evidence — do not use outside knowledge, and do not run or imagine any tools.")
              (string= (second lines)
                       "Verdicts: \"supported\" = the evidence directly establishes the claim; \"overreach\" = the evidence is related but the claim asserts more than the evidence shows (stronger, broader, or attributive); \"unsupported\" = the evidence does not establish the claim (misattribution or wrong evidence).")
              (string= (third lines) "Reply with ONLY a JSON array, one object per claim, and no prose outside it:")
              (string= (fourth lines)
                       "[{\"index\": <int>, \"verdict\": \"supported|unsupported|overreach\", \"reason\": \"<=1 line\"}]")
              (string= (fifth lines) "")))
  (check "a claim is a numbered line, each piece of evidence its tool, short id and summary"
         (equal (subseq lines 5 8)
                '("CLAIM 0: f multiplies by 33."
                  "  evidence [rizin_command:11111111] summary: imul eax, eax, 0x21"
                  "    output: imul eax, eax, 0x21")))
  (check "the canonical excerpt is quoted before the full text, the full text when there is no excerpt, nothing when neither"
         (and (not (has "the whole output" prompt))
              (equal (subseq lines 8 11)
                     '("CLAIM 3: g is called twice."
                       "  evidence [list_strings:ev-b] summary: two calls"
                       "    output: call g; call g"))
              (equal (subseq lines 13 15)
                     '("  evidence [rizin_command:ev-d] summary: bare"
                       "CLAIM 4: nothing quoted."))))
  (check "an output past 800 characters is cut there, with an ellipsis"
         (string= (nth 12 lines)
                  (format nil "    output: ~a…" (make-string 800 :initial-element #\x))))
  (check "a claim with no evidence says so, and the prompt ends without a newline"
         (and (string= (car (last lines)) "  (no evidence quoted)")
              (ends "(no evidence quoted)" prompt))))

(suite "audit: reading the reply")
(flet ((parsed (text) (mapcar (lambda (audit)
                                (list (omp-re::claim-audit-index audit) (omp-re::claim-audit-verdict audit)
                                      (omp-re::claim-audit-reason audit)))
                              (omp-re::parse-audit-reply text)))
       (parses (text) (nth-value 1 (omp-re::parse-audit-reply text))))
  (check "a fenced json block is read, whatever stands around it"
         (equal '((0 "overreach" "too strong"))
                (parsed (format nil "Here you go:~%```json~%[{\"index\":0,\"verdict\":\"overreach\",\"reason\":\"too strong\"}]~%```~%Hope it helps [not this]."))))
  (check "a fence with no language, and one spelt JSON, are read the same"
         (and (equal '((1 "supported" "ok")) (parsed "```[{\"index\":1,\"verdict\":\"supported\",\"reason\":\"ok\"}]```"))
              (equal '((1 "supported" "ok"))
                     (parsed (format nil "```JSON~%[{\"index\":1,\"verdict\":\"supported\",\"reason\":\"ok\"}]~%```")))))
  (check "with no fence the first balanced array is taken out of the prose"
         (equal '((0 "unsupported" "wrong evidence") (1 "supported" ""))
                (parsed "Verdicts: [{\"index\":0,\"verdict\":\"unsupported\",\"reason\":\"wrong evidence\"}, {\"index\":1,\"verdict\":\"supported\",\"reason\":\"\"}] — done [1].")))
  (check "a bracket or an escaped quote inside a string does not end the scan"
         (equal '((0 "supported" "a ] and a \" and a [ inside"))
                (parsed "[{\"index\":0,\"verdict\":\"supported\",\"reason\":\"a ] and a \\\" and a [ inside\"}] trailing")))
  (check "a reply with no JSON, one that is cut short, and one that is not JSON do not parse"
         (and (not (parses "I cannot produce JSON, sorry."))
              (not (parses "[{\"index\":0,\"verdict\":\"supported\""))
              (not (parses "[{index: 0}]"))
              (not (parses ""))))
  (check "an object is not an array of verdicts, fenced or bare"
         (and (not (parses "{\"index\":0,\"verdict\":\"supported\",\"reason\":\"ok\"}"))
              (not (parses "```json{\"index\":0}```"))))
  (check "an empty array parses, to no verdicts"
         (and (parses "[]") (null (parsed "[]"))))
  (check "a row that is no object or has no numeric index is passed over"
         (equal '((2 "supported" "kept"))
                (parsed "[1, \"x\", null, [0], {\"verdict\":\"supported\"}, {\"index\":\"0\",\"verdict\":\"supported\"}, {\"index\":2,\"verdict\":\"supported\",\"reason\":\"kept\"}]")))
  (check "a verdict the engine does not know reads as unaudited, and a reason that is no string as none"
         (equal '((0 "unaudited" "") (1 "unaudited" "r") (2 "unaudited" ""))
                (parsed "[{\"index\":0,\"verdict\":\"plausible\",\"reason\":7}, {\"index\":1,\"reason\":\"r\"}, {\"index\":2,\"verdict\":\"unaudited\"}]"))))

(defun audited (items mode &optional (judge nil judge-p))
  "The outcome of auditing ITEMS in MODE, with JUDGE as the host's when one is given."
  (if judge-p
      (with-service (:judge judge) (omp-re::audit-claims items mode))
      (omp-re::audit-claims items mode)))

(suite "audit: the outcome")
(let ((items (list (audit-item 0 "a" (audit-evidence "id" "ev-a" "tool" "t" "summary" "s"))
                   (audit-item 2 "b" (audit-evidence "id" "ev-b" "tool" "t" "summary" "s")))))
  (flet ((unaudited-p (outcome reason count)
           (and (not (omp-re::audit-outcome-audited outcome))
                (equal reason (omp-re::audit-outcome-unaudited-reason outcome))
                (null (omp-re::audit-outcome-by-index outcome))
                (= count (omp-re::audit-outcome-item-count outcome)))))
    (check "with no judge the audit is unaudited: no model / side turns unavailable"
           (and (unaudited-p (audited items "advisory" nil) "no model / side turns unavailable" 2)
                (unaudited-p (audited items "strict" nil) "no model / side turns unavailable" 2)
                (unaudited-p (audited '() "advisory" nil) "no model / side turns unavailable" 0)))
    (check "and with none bound, which is where the engine stands until the cell sets one"
           (let ((judge-now nil))
             (with-service (:judge judge-now)
             (unaudited-p (audited items "advisory") "no model / side turns unavailable" 2))))
    (check "mode off and no items ask nobody; with a judge there, no reason is given"
           (let* ((asked 0)
                  (judge (lambda (prompt) (declare (ignore prompt)) (incf asked) "[]")))
             (and (unaudited-p (audited items "off" judge) nil 0)
                  (unaudited-p (audited '() "advisory" judge) nil 0)
                  (zerop asked))))
    (check "a judge that signals, and a reply that cannot be read, leave no usable verdict"
           (and (unaudited-p (audited items "advisory" (lambda (prompt) (declare (ignore prompt)) (error "no active model")))
                             "the audit side turn returned no usable verdict" 2)
                (unaudited-p (audited items "strict" (lambda (prompt) (declare (ignore prompt)) "I cannot produce JSON, sorry."))
                             "the audit side turn returned no usable verdict" 2)
                (unaudited-p (audited items "advisory" (lambda (prompt) (declare (ignore prompt)) "{\"index\":0}"))
                             "the audit side turn returned no usable verdict" 2)))
    (check "a judge that cannot ask is no judge; one that says why is unaudited for that reason"
           (and (unaudited-p (audited items "advisory" (lambda (prompt) (declare (ignore prompt)) nil))
                             "no model / side turns unavailable" 2)
                (unaudited-p (audited items "advisory"
                                               (lambda (prompt) (declare (ignore prompt)) (values nil "the turn timed out")))
                             "the turn timed out" 2)))
    (check "each verdict comes back on its claim's index"
           (let ((outcome (audited
                           items "advisory"
                           (lambda (prompt) (declare (ignore prompt))
                             "[{\"index\":2,\"verdict\":\"overreach\",\"reason\":\"more than shown\"},{\"index\":0,\"verdict\":\"supported\",\"reason\":\"ok\"}]"))))
             (and (omp-re::audit-outcome-audited outcome)
                  (null (omp-re::audit-outcome-unaudited-reason outcome))
                  (= 2 (omp-re::audit-outcome-item-count outcome))
                  (equal '((2 "overreach" "more than shown") (0 "supported" "ok")) (verdicts-of outcome))
                  (string= "supported" (omp-re::claim-audit-verdict (omp-re::outcome-verdict outcome 0)))
                  (null (omp-re::outcome-verdict outcome 1)))))
    (check "a claim the judge left out is unaudited by itself: not returned by the auditor"
           (equal '((0 "unsupported" "wrong") (2 "unaudited" "not returned by the auditor"))
                  (verdicts-of (audited
                                items "advisory"
                                (lambda (prompt) (declare (ignore prompt))
                                  "[{\"index\":0,\"verdict\":\"unsupported\",\"reason\":\"wrong\"}]")))))
    (check "an empty reply audits, every claim unaudited; a second verdict for an index replaces the first"
           (and (equal '((0 "unaudited" "not returned by the auditor") (2 "unaudited" "not returned by the auditor"))
                       (verdicts-of (audited items "advisory" (lambda (prompt) (declare (ignore prompt)) "[]"))))
                (equal '((0 "overreach" "second") (2 "supported" ""))
                       (verdicts-of (audited
                                     items "advisory"
                                     (lambda (prompt) (declare (ignore prompt))
                                       "[{\"index\":0,\"verdict\":\"supported\",\"reason\":\"first\"},{\"index\":2,\"verdict\":\"supported\"},{\"index\":0,\"verdict\":\"overreach\",\"reason\":\"second\"}]"))))))
    (check "strict withholds on unsupported and overreach alone, never on unaudited"
           (and (equal '(0 2)
                       (mapcar #'omp-re::claim-audit-index
                               (omp-re::flagged-verdicts
                                (audited
                                 items "strict"
                                 (lambda (prompt) (declare (ignore prompt))
                                   "[{\"index\":0,\"verdict\":\"unsupported\"},{\"index\":2,\"verdict\":\"overreach\"},{\"index\":5,\"verdict\":\"supported\"}]")))))
                (null (omp-re::flagged-verdicts (audited items "strict" (lambda (prompt) (declare (ignore prompt)) "[]"))))
                (null (omp-re::flagged-verdicts (audited items "strict" nil)))))))

;;; --- where the engine wires it: a judge bound by hand ----------------------------------------------

(suite "audit: record_finding")
(with-cell ()
  (let ((id (audit-session)))
    (in-session (id)
      (let* ((seen nil)
             (text (let ((judge-now (lambda (prompt)
                                              (setf seen prompt)
                                              (funcall (judge-saying "supported") prompt))))
                     (with-service (:judge judge-now)
                     (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111")
                                               :addr "sym.f" :confidence "confirmed")))))
        (check "a supported finding is recorded, and its result says the auditor's verdict and reason"
               (and (has "record_finding: recorded " text)
                    (has (format nil "~%support audit: supported — because~%") text)
                    (has "this finding will carry to the next build" text)))
        (check "the auditor was put the claim and the evidence it cites, as claim 0"
               (and (has (format nil "~%CLAIM 0: f multiplies by 33.~%  evidence [rizin_command:11111111] summary: imul eax, eax, 0x21")
                         seen)
                    (not (has "CLAIM 1" seen))))
        (check "the stored audit member is the verdict and the reason, nothing else"
               (string= "{\"verdict\":\"supported\",\"reason\":\"because\"}"
                        (omp-re:json-encode (gethash "audit" (last-finding id))))))

      (let ((judge-now (judge-saying "overreach" "shows a multiply, not a hash")))
        (with-service (:judge judge-now)
        (check "an overreaching claim is refused, word for word, with the auditor's reason"
               (equal (format nil "record_finding: NOT recorded — the support auditor judged this claim overreach: shows a multiply, not a hash~%Narrow the claim to what the evidence shows, cite evidence that establishes it, or (only if the auditor is wrong) pass override_audit with a one-line justification.")
                      (refusal (lambda () (re:call "record_finding" :claim "f is the djb2 hash of the C2 key."
                                                                    :evidence '("11111111"))))))
        (check "and nothing was recorded; an empty override is no override"
               (and (= 1 (finding-count id))
                    (has "NOT recorded" (refusal (lambda () (re:call "record_finding" :claim "f is the djb2 hash of the C2 key."
                                                                                      :evidence '("11111111")
                                                                                      :override-audit ""))))
                    (= 1 (finding-count id))))
        (let ((text (re:call "record_finding" :claim "f is the djb2 hash of the C2 key." :evidence '("11111111")
                                              :override-audit "the constant 33 plus the loop is djb2")))
          (check "with a written override it is recorded, and the result says it was overridden"
                 (and (= 2 (finding-count id))
                      (has (format nil "~%support audit: overreach — shows a multiply, not a hash (overridden)~%") text)))
          (check "the stored audit member keeps the verdict, the reason and the override, in that order"
                 (string= "{\"verdict\":\"overreach\",\"reason\":\"shows a multiply, not a hash\",\"override\":\"the constant 33 plus the loop is djb2\"}"
                          (omp-re:json-encode (gethash "audit" (last-finding id)))))
          (check "/re findings and the report show the justification beside the finding"
                 (let ((note "recorded over a support-audit \"overreach\" verdict — justification: the constant 33 plus the loop is djb2"))
                   (and (has note (re:slash (format nil "findings ~a" (gethash "id" (last-finding id)))))
                        (has note (re:slash "report --no-audit"))))))))

      (let ((judge-now (judge-saying "unsupported" "wrong evidence")))
        (with-service (:judge judge-now)
        (check "an unsupported claim is refused the same way"
               (has "record_finding: NOT recorded — the support auditor judged this claim unsupported: wrong evidence"
                    (refusal (lambda () (re:call "record_finding" :claim "h decrypts." :evidence '("11111111"))))))))

      (let ((judge-now (judge-saying "supported" "")))
        (with-service (:judge judge-now)
        (re:call "record_finding" :claim "an override nobody needed." :evidence '("11111111")
                                  :override-audit "not needed")
        (check "an override is kept only when it overrode something, and an empty reason adds no dash"
               (and (string= "{\"verdict\":\"supported\",\"reason\":\"\"}"
                             (omp-re:json-encode (gethash "audit" (last-finding id))))
                    (has (format nil "~%support audit: supported~%")
                         (re:call "record_finding" :claim "no reason given." :evidence '("11111111")))))))

      (flet ((recorded-as (judge)
               (let ((judge-now judge))
                 (with-service (:judge judge-now)
                 (re:call "record_finding" :claim "fails open." :evidence '("11111111"))
                 (omp-re:json-encode (gethash "audit" (last-finding id)))))))
        (check "a reply that cannot be read, a judge that signals and a verdict left out all record the finding, unaudited"
               (and (string= "{\"verdict\":\"unaudited\",\"reason\":\"the audit side turn returned no usable verdict\"}"
                             (recorded-as (lambda (prompt) (declare (ignore prompt)) "no JSON here")))
                    (string= "{\"verdict\":\"unaudited\",\"reason\":\"the audit side turn returned no usable verdict\"}"
                             (recorded-as (lambda (prompt) (declare (ignore prompt)) (error "provider overloaded"))))
                    (string= "{\"verdict\":\"unaudited\",\"reason\":\"not returned by the auditor\"}"
                             (recorded-as (lambda (prompt) (declare (ignore prompt)) "[]")))
                    (string= "{\"verdict\":\"unaudited\",\"reason\":\"the turn timed out\"}"
                             (recorded-as (lambda (prompt) (declare (ignore prompt)) (values nil "the turn timed out"))))))
        (check "with no judge bound it is today's unaudited, word for word"
               (string= "{\"verdict\":\"unaudited\",\"reason\":\"no model / side turns unavailable\"}"
                        (recorded-as nil)))))))

(if (not *rizin*)
    (format t "  SKIPPED  adopt_finding's refusal: needs rizin and ~a~%" *binary*)
    (with-cell ()
      (let ((id (fresh-session)))
        (in-session (id)
          (re:open *binary*)
          (with-service (:judge (judge-saying "overreach" "a prologue, not a parser"))
            (let ((text (refusal (lambda () (re:call "adopt_finding" :claim "entry0 parses the arguments."
                                                                     :commands '((:command "pd 2" :addr "entry0")))))))
            (check "adopt_finding is refused the same way, and says the re-run evidence was kept"
                   (and (has "adopt_finding: NOT recorded — the support auditor judged this claim overreach: a prologue, not a parser" text)
                        (has (format nil "~%The re-run evidence was recorded (~a); cite it in record_finding to record a narrower claim."
                                     (subseq (gethash "id" (car (last (omp-re::evidence-records (omp-re:find-session id))))) 0 8))
                             text)
                        (zerop (finding-count id))))))))))

(suite "audit: /re report")
(with-cell ()
  (let* ((id (audit-session))
         (session (omp-re:find-session id))
         (path (uiop:native-namestring (merge-pathnames "audited.md" *scratch*)))
         (strict-path (uiop:native-namestring (merge-pathnames "strict.md" *scratch*))))
    (in-session (id)
      (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111"))
      (omp-re::append-entry "re.evidence"
                        (omp-re:obj "id" "ev-strings" "tool" "list_strings"
                                 "outputHash" (omp-re::write-blob "0x1 str http://185.220.101.99/beacon")
                                 "summary" "found string: http://185.220.101.99/beacon")
                        session)
      (let* ((seen nil)
             (markdown (let ((judge-now (lambda (prompt)
                                                  (setf seen prompt)
                                                  (funcall (judge-saying "supported" "ok") prompt))))
                         (with-service (:judge judge-now)
                         (re:slash "report")))))
        (check "advisory, all supported: no flag beside a claim, and a note that counts them"
               (and (not (has "⚠ Support audit" markdown))
                    (has (format nil "~%> _Claim–evidence support audit: 3 supported, 0 flagged, 0 unaudited._~%~%## Verification Manifest")
                         markdown)))
        (check "every evidence-backed claim was put, by its flat position, with the output where there is no excerpt"
               (and (has "CLAIM 0: f multiplies by 33." seen)
                    (has "CLAIM 1: 185[.]220[.]101[.]99" seen)
                    (has "CLAIM 2: hxxp://185[.]220[.]101[.]99/beacon" seen)
                    (has (format nil "  evidence [list_strings:ev-strin] summary: found string: http://185.220.101.99/beacon~%    output: 0x1 str http://185.220.101.99/beacon")
                         seen))))

      (let ((judge-now (lambda (prompt) (declare (ignore prompt))
                                 "[{\"index\":0,\"verdict\":\"supported\",\"reason\":\"ok\"},{\"index\":1,\"verdict\":\"unsupported\",\"reason\":\"evidence shows only an import\"}]")))
        (with-service (:judge judge-now)
        (check "advisory: a flagged claim says so under its evidence, and the report is still written"
               (and (has "report written to" (re:slash (format nil "report ~a" path)))
                    (let ((markdown (omp-re::read-text-file path)))
                      (and (has (format nil "- 185[.]220[.]101[.]99~%  **Evidence:** [list_strings:ev-strings]~%  _⚠ Support audit: unsupported — evidence shows only an import_~%")
                                markdown)
                           (has (format nil "- f multiplies by 33.~%  _confidence: likely_~%  **Evidence:** [rizin_command:11111111-aaaa-bbbb-cccc-000000000001]~%~%")
                                markdown)
                           (has "> _Claim–evidence support audit: 1 supported, 1 flagged, 1 unaudited._" markdown)))))
        (check "strict withholds the whole report on it, naming the claim, the verdict and the reason"
               (and (equal (format nil "omp-re: report withheld — 1 claim(s) not supported by their cited evidence:~%  - [unsupported] 185[.]220[.]101[.]99 — evidence shows only an import")
                           (refusal (lambda () (re:slash (format nil "report --audit=strict ~a" strict-path)))))
                    (not (probe-file strict-path))
                    (has "report withheld" (refusal (lambda () (re:slash "report --audit=strict"))))))))

      (let ((judge-now (judge-saying "overreach" "misattributed")))
        (with-service (:judge judge-now)
        (check "every flagged claim is listed, in the report's order"
               (equal (format nil "omp-re: report withheld — 3 claim(s) not supported by their cited evidence:~%  - [overreach] f multiplies by 33. — misattributed~%  - [overreach] 185[.]220[.]101[.]99 — misattributed~%  - [overreach] hxxp://185[.]220[.]101[.]99/beacon — misattributed")
                      (refusal (lambda () (re:slash "report --audit=strict")))))))

      (flet ((strict-report (judge)
               (let ((judge-now judge))
                 (with-service (:judge judge-now)
                 (ignore-errors (delete-file strict-path))
                 (re:slash (format nil "report --audit=strict ~a" strict-path))
                 (omp-re::read-text-file strict-path)))))
        (check "strict fails open: a judge that signals, an unreadable reply and no judge all still write, and say unaudited"
               (and (has "> _Claim–evidence support unaudited — the audit side turn returned no usable verdict._"
                         (strict-report (lambda (prompt) (declare (ignore prompt)) (error "no active model"))))
                    (has "> _Claim–evidence support unaudited — the audit side turn returned no usable verdict._"
                         (strict-report (lambda (prompt) (declare (ignore prompt)) "I cannot produce JSON, sorry.")))
                    (has "> _Claim–evidence support unaudited — the turn timed out._"
                         (strict-report (lambda (prompt) (declare (ignore prompt)) (values nil "the turn timed out"))))
                    (has "> _Claim–evidence support unaudited — no model / side turns unavailable._"
                         (strict-report nil)))))

      (let* ((asked 0)
             (judge-now (lambda (prompt) (incf asked) (funcall (judge-saying "unsupported") prompt))))
        (with-service (:judge judge-now)
        (check "--no-audit asks nobody and writes no note, whatever the judge would say"
               (let ((markdown (re:slash "report --no-audit")))
                 (and (zerop asked)
                      (not (has "Support audit" markdown))
                      (not (has "support audit" markdown))
                      (not (has "support unaudited" markdown)))))
        ;; A finding with no evidence under it: a claim with nothing behind it.
        (omp-re::append-entry "re.finding" (omp-re:obj "id" "22222222-0000" "claim" "It beacons to a C2."
                                                "evidenceIds" (vector))
                          session)
        (check "the existence gate runs first: an ungrounded claim withholds and the judge is never asked"
               (and (has "report withheld — 1 claim(s) without evidence"
                         (refusal (lambda () (re:slash "report --audit=strict"))))
                    (zerop asked))))))))

;;; --- the cell's judge, over the stand-in kernel ----------------------------------------------------

(suite "audit: the cell's judge")
(check "start sets the judge and stop clears it"
       (and (null (omp-re::host-service :judge))
            (with-cell () (eq (omp-re::host-service :judge) #'re::ask-judge))
            (null (omp-re::host-service :judge))))

(with-cell ()
  (with-open-store ()
    (let ((id (audit-session)))
      (nlk:create-session :id id)
      (in-session (id)
        (setf nlk:*stub-judge* "```json
[{\"index\":0,\"verdict\":\"supported\",\"reason\":\"the multiply is shown\"}]
```")
        (let* ((text (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111")))
               (asked (first nlk:*stub-submissions*))
               (child (gethash (getf asked :session) nlk:*stub-sessions*)))
          (check "the model's reply is the verdict the finding is recorded with"
                 (and (has (format nil "~%support audit: supported — the multiply is shown~%") text)
                      (string= "{\"verdict\":\"supported\",\"reason\":\"the multiply is shown\"}"
                               (omp-re:json-encode (gethash "audit" (last-finding id))))))
          (check "one question was asked, of a session made for it, with no tool it may call"
                 (and (= 1 (length nlk:*stub-submissions*))
                      (getf asked :tools-p)
                      (null (getf asked :tools))
                      (string/= id (getf asked :session))))
          (check "it was the audit's prompt, under the cell's own source and the asking session's id"
                 (and (has "You are a strict reverse-engineering report auditor." (getf asked :prompt))
                      (has "CLAIM 0: f multiplies by 33." (getf asked :prompt))
                      (string= "re-audit" (getf asked :source))
                      (string= id (getf asked :source-id))))
          (check "the session hangs under the one that asked, detached — none of its history — in its directory, and is named"
                 (and (string= id (nlk::durable-session-parent child))
                      (nlk::durable-session-detached child)
                      (null (nlk::durable-session-anchor-turn-id child))
                      (string= nlk:*stub-session-cwd* (nlk::durable-session-cwd child))
                      (string= "re: support audit" (nlk::durable-session-title child))))
          (check "nothing is left open or waiting"
                 (and (null (nlk:stub-open-turns)) (null re::*audit-turns*))))

        (setf nlk:*stub-judge* (judge-saying "overreach" "shows a multiply, not a hash"))
        (check "a verdict against the claim, read from the model, refuses it"
               (has "NOT recorded — the support auditor judged this claim overreach: shows a multiply, not a hash"
                    (refusal (lambda () (re:call "record_finding" :claim "f is djb2." :evidence '("11111111"))))))

        (flet ((audit-after (how)
                 (setf nlk:*stub-judge* how)
                 (re:call "record_finding" :claim "fails open." :evidence '("11111111"))
                 (gethash "reason" (gethash "audit" (last-finding id)))))
          (check "a turn that failed is unaudited, with what the failure said — its first line"
                 (and (string= "the audit side turn failed: provider overloaded"
                               (audit-after (list :fail (format nil "provider overloaded~%  at request 3"))))
                      (string= "unaudited" (gethash "verdict" (gethash "audit" (last-finding id))))))
          (check "a turn that was cancelled is unaudited, with why"
                 (string= "the audit side turn was cancelled: stopped by the operator"
                          (audit-after '(:cancel "stopped by the operator"))))
          (check "a turn that ended having said nothing is unaudited"
                 (string= "the audit side turn ended without an answer" (audit-after nil)))
          (check "an answer that is no verdict is the port's own unaudited"
                 (string= "the audit side turn returned no usable verdict" (audit-after "I would rather not say.")))
          (check "a question that could not be put is unaudited, with the refusal"
                 (string= "the audit side turn could not be asked: input is 900000 characters; the limit is 400000"
                          (audit-after '(:error "input is 900000 characters; the limit is 400000")))))

        (let ((before (length nlk:*stub-submissions*)))
          (setf nlk:*stub-judge* (judge-saying "unsupported" "misattributed"))
          (check "(re:slash \"report\") from eval is audited by the model too, and strict withholds on its verdict"
                 (and (has "report withheld — "
                           (refusal (lambda () (re:slash "report --audit=strict"))))
                      (= (1+ before) (length nlk:*stub-submissions*))))
          (check "a /re line typed as a command does not wait on a model turn: nothing is asked, and the report says why"
                 (let ((markdown (let ((nle:*stub-session* nil)) (re::run-slash "report --audit=strict" id))))
                   (and (has "> _Claim–evidence support unaudited — a /re line typed as a command does not wait for the audit's side question; (re:slash \"report\") from eval asks it._"
                             markdown)
                        (= (1+ before) (length nlk:*stub-submissions*)))))))

      ;; A session the store does not hold: there is no parent to hang the question under.
      (let ((id (audit-session)))
        (in-session (id)
          (setf nlk:*stub-judge* (judge-saying "supported" "ok"))
          (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111"))
          (let* ((asked (first nlk:*stub-submissions*))
                 (child (gethash (getf asked :session) nlk:*stub-sessions*)))
            (check "asked from a session the store does not hold, the question goes to a session with no parent"
                   (and (string= "supported" (gethash "verdict" (gethash "audit" (last-finding id))))
                        (null (nlk::durable-session-parent child))
                        (not (nlk::durable-session-detached child))
                        (null (getf asked :source-id))
                        (null (getf asked :tools))
                        (getf asked :tools-p)))))))))

(let ((poll re::*audit-poll-seconds*))
  (unwind-protect
       (progn
         (setf re::*audit-poll-seconds* 1/20)
         (with-cell (:audit-seconds 1)
           (with-open-store ()
             (let ((id (audit-session)))
               (in-session (id)
                 (setf nlk:*stub-judge* :never)
                 (let* ((began (get-internal-real-time))
                        (text (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111")))
                        (took (/ (- (get-internal-real-time) began) internal-time-units-per-second)))
                   (check "a turn that never ends is waited for audit_seconds and no longer; the finding is unaudited, naming the timeout"
                          (and (has "support audit: unaudited — the audit side turn did not end within audit_seconds (1 s)" text)
                               (< 0.9 took 5)))
                   (check "the turn was asked to stop, and nothing is left open or waiting"
                          (and (= 1 (length nlk:*stub-cancels*))
                               (has "audit_seconds" (third (first nlk:*stub-cancels*)))
                               (null (nlk:stub-open-turns))
                               (null re::*audit-turns*))))))))

         (with-cell (:audit-seconds 60)
           (with-open-store ()
             (let* ((id (audit-session))
                    (answer nil)
                    (thread (progn
                              (setf nlk:*stub-judge* :never)
                              (sb-thread:make-thread
                               (lambda ()
                                 (let ((nle:*stub-session* id))
                                   (setf answer (ignore-errors
                                                 (re:call "record_finding" :claim "f multiplies by 33."
                                                                           :evidence '("11111111"))))))
                               :name "audit under stop"))))
               (loop repeat 200 until (nlk:stub-open-turns) do (sleep 1/50))
               (check "an audit is waiting on its turn"
                      (and (= 1 (length (nlk:stub-open-turns))) (= 1 (length re::*audit-turns*))))
               (stop-running-cell)
               (sb-thread:join-thread thread :default nil :timeout 10)
               (check "stopping the cell ends the wait at once: the turn is asked to stop and the call returns"
                      (and (not (sb-thread:thread-alive-p thread))
                           (stringp answer)
                           (has "support audit: unaudited — " answer)
                           (or (has "the nodecode-re cell stopped before the audit side turn ended" answer)
                               (has "the audit side turn was cancelled: the nodecode-re cell stopped" answer))))
               (check "nothing is left running after stop: no open turn, no waiter, no judge"
                      (and (null (nlk:stub-open-turns))
                           (null re::*audit-turns*)
                           (null (omp-re::host-service :judge))
                           (equal "the nodecode-re cell stopped" (third (first nlk:*stub-cancels*)))))))))
    (setf re::*audit-poll-seconds* poll)))

(with-cell (:audit nil)
  (with-open-store ()
    (let ((id (audit-session)))
      (nlk:create-session :id id)
      (in-session (id)
        (setf nlk:*stub-judge* (judge-saying "overreach" "would have refused"))
        (check "with audit false nobody is asked, and the finding is today's unaudited"
               (and (has "support audit: unaudited — no model / side turns unavailable"
                         (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111")))
                    (has "> _Claim–evidence support unaudited — no model / side turns unavailable._"
                         (re:slash "report --audit=strict"))
                    (null nlk:*stub-submissions*)
                    (= 1 (hash-table-count nlk:*stub-sessions*))))))))

(with-cell ()
  (let ((id (audit-session)))
    (in-session (id)
      (setf nlk:*stub-judge* (judge-saying "overreach" "would have refused"))
      (unwind-protect
           (check "and so it is with the setting on and no store to hold a session"
                  (and (not (nlk:store-open-p))
                       (has "support audit: unaudited — no model / side turns unavailable"
                            (re:call "record_finding" :claim "f multiplies by 33." :evidence '("11111111")))
                       (null nlk:*stub-submissions*)))
        (nlk:stub-forget-sessions)))))
