;;;; findings.lisp --- the model's own conclusions as gated, carried claims.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Ported from omp-re's findings.ts, the collectEvidence half of entries.ts
;;;; it reads through, the `/re findings' panel of ui.ts (its headless
;;;; branch) and the findings line of index.ts's status text.
;;;;
;;;; A report's other claims come from machinery — capa's capability lines,
;;;; IOC strings mined from evidence. The conclusions that matter in reverse
;;;; engineering ("checksum is djb2") would otherwise live only in chat,
;;;; outside every gate. A finding puts one into the record:
;;;;
;;;; - record_finding takes a claim and the evidence ids it rests on. It is
;;;;   gated at record time, while the model can still act on the answer:
;;;;   every id must resolve in this session's record (existence), have been
;;;;   taken against the open binary (binding), and the claim goes to the
;;;;   same support audit /re report uses (audit-claims.lisp) — an
;;;;   unsupported or overreaching claim is refused with the auditor's
;;;;   reason unless the model overrides it with a written justification,
;;;;   which is kept and shown.
;;;; - adopt_finding re-proves a finding made elsewhere by re-running its
;;;;   commands here, so the claim rests on evidence this session observed.
;;;; - retract_finding withdraws one; `supersedes' revises one.
;;;;
;;;; Findings are re.finding / re.finding.retract entries of the record, read
;;;; back from it like all other state, so they survive a restart.

(in-package #:nodecode-re)

;;; --- reading the record --------------------------------------------------------------------

(defparameter +confidences+ '("confirmed" "likely" "speculative"))

(defparameter +min-id-prefix+ 6
  "The shortest evidence or finding id prefix accepted — a result shows 8 characters.")

(defun collected-evidence (&optional (session *session*))
  "The record's evidence as collectEvidence reads it: a row needs an id, a
tool and a summary to count, where the spine's EVIDENCE-RECORDS asks only
for an id. A finding, the report and /re verify must not rest on less."
  (remove-if-not (lambda (record)
                   (and (jstring record "id") (jstring record "tool") (jstring record "summary")))
                 (entries-of "re.evidence" session)))

(defun string-member (object key)
  "OBJECT's member KEY when it is a string, else :ABSENT — for OBJ."
  (or (jstring object key) :absent))

(defun normalized-finding (data)
  "One re.finding entry's DATA as a finding, or NIL when it is not one: only
the members a finding has, a confidence the engine knows."
  (let ((ids (and (hash-table-p data) (gethash "evidenceIds" data))))
    (when (and (hash-table-p data) (jstring data "id") (jstring data "claim")
               (vectorp ids) (not (stringp ids)))
      (obj "id" (jstring data "id")
           "claim" (jstring data "claim")
           "evidenceIds" (coerce (remove-if-not #'stringp ids) 'simple-vector)
           "addr" (string-member data "addr")
           "confidence" (if (member (jstring data "confidence") +confidences+ :test #'equal)
                            (jstring data "confidence")
                            "likely")
           "supersedes" (string-member data "supersedes")
           "audit" (if (hash-table-p (jget data "audit")) (jget data "audit") :absent)
           "binarySha256" (string-member data "binarySha256")
           "inherited" (if (hash-table-p (jget data "inherited")) (jget data "inherited") :absent)
           "adoptedFrom" (string-member data "adoptedFrom")))))

(defun live-findings (&optional (session *session*))
  "The findings in effect, in order: every re.finding minus those a later
finding superseded or a re.finding.retract withdrew."
  (let ((live '()))                     ; (id . finding), oldest first
    (flet ((drop (id)
             (setf live (remove id live :key #'car :test #'equal))))
      (loop for entry across (session-entries session)
            for kind = (jstring entry "customType")
            for data = (jget entry "data")
            do (cond ((equal kind "re.finding.retract")
                      (when (jstring data "id") (drop (jstring data "id"))))
                     ((equal kind "re.finding")
                      (let ((finding (normalized-finding data)))
                        (when finding
                          (when (jstring finding "supersedes") (drop (jstring finding "supersedes")))
                          ;; An id recorded twice keeps its first place, as a Map's set does.
                          (let ((held (assoc (jstring finding "id") live :test #'equal)))
                            (if held
                                (setf (cdr held) finding)
                                (setf live (append live (list (cons (jstring finding "id") finding)))))))))))
      (mapcar #'cdr live))))

(defun short-id (id)
  (subseq id 0 (min 8 (length id))))

(defun resolve-id (items id)
  "The one of ITEMS whose id is ID or uniquely begins with it
=> (values ITEM NIL), or (values NIL REASON)."
  (let ((exact (find id items :key (lambda (item) (jstring item "id")) :test #'equal)))
    (cond (exact (values exact nil))
          ((< (length id) +min-id-prefix+)
           (values nil (format nil "~a is too short (use at least ~d characters of the id)"
                               (js-string id) +min-id-prefix+)))
          (t
           (let ((matches (remove-if-not (lambda (item) (starts-with id (jstring item "id"))) items)))
             (cond ((= 1 (length matches)) (values (first matches) nil))
                   ((null matches)
                    (values nil (format nil "no id starting ~a on this branch" (js-string id))))
                   (t (values nil (format nil "~a is ambiguous (~d matches)"
                                          (js-string id) (length matches))))))))))

(defun finding-note (finding)
  "One line of a finding's provenance for the report and /re findings:
confidence, inheritance, and any audit override."
  (let ((parts (list (format nil "confidence: ~a" (jstring finding "confidence"))))
        (inherited (jget finding "inherited"))
        (audit (jget finding "audit")))
    (when (plusp (length (jstring finding "addr")))
      (push (format nil "at `~a`" (jstring finding "addr")) parts))
    (when inherited
      (let ((from (jstring inherited "fromBinarySha256"))
            (relocation (jget inherited "relocation")))
        (push (format nil "inherited from ~a, re-verified on this build (~a~a)"
                      (if (plusp (length from))
                          (format nil "`~a…`" (subseq from 0 (min 12 (length from))))
                          "an earlier build")
                      (or (jget inherited "carryStatus") "undefined")
                      (if relocation
                          (format nil ": ~a → ~a" (jget relocation "from") (jget relocation "to"))
                          ""))
              parts)))
    (when (plusp (length (jstring finding "adoptedFrom")))
      (push (format nil "adopted from ~a, re-proven in this session" (jstring finding "adoptedFrom")) parts))
    (when (and audit (jget audit "override"))
      (push (format nil "recorded over a support-audit \"~a\" verdict — justification: ~a"
                    (jget audit "verdict") (jget audit "override"))
            parts))
    (format nil "~{~a~^ · ~}" (nreverse parts))))

;;; --- the gate every finding passes ------------------------------------------------------------

(defun schema-refusal (tool problem &rest arguments)
  "Refuse a call whose arguments break a bound the tool's schema states —
the lengths and counts the TypeScript's zod schema holds and the spine's
parameter types cannot say — in the words the spine uses for the rest."
  (fail "omp-re: ~a was called with arguments that do not fit its schema: ~?" tool problem arguments))

(defun check-text-length (tool name text least most)
  (unless (<= least (length text) most)
    (schema-refusal tool "~a must be ~d to ~d characters (was ~d)" name least most (length text))))

(defun gate-and-record (tool resolved &key claim addr confidence supersedes adopted-from override-audit)
  "The gate every recorded finding passes once its evidence is resolved:
the support audit — refused on unsupported or overreach unless
OVERRIDE-AUDIT justifies it; fails open to `unaudited' — then the re.finding
entry and a result that says whether the finding can carry. Shared by
record_finding and adopt_finding, so the two can never gate differently."
  (let* ((outcome (audit-claims
                   (list (make-audit-item
                          :index 0
                          :claim-text claim
                          :evidence (mapcar (lambda (record)
                                              (obj "id" (jstring record "id")
                                                   "tool" (jstring record "tool")
                                                   "summary" (jstring record "summary")
                                                   "canonicalExcerpt" (string-member record "canonicalExcerpt")))
                                            resolved)))
                   "advisory"))
         (verdict (outcome-verdict outcome 0))
         (refused (and verdict (flagged-p verdict)))
         (override (and (plusp (length override-audit)) override-audit))
         (evidence-list (format nil "~{~a~^, ~}"
                                (mapcar (lambda (record) (short-id (jstring record "id"))) resolved))))
    (when (and refused (not override))
      (return-from gate-and-record
        (failed-result
         (format nil "~a: NOT recorded — the support auditor judged this claim ~a: ~a~%Narrow the claim to what the evidence shows, cite evidence that establishes it, or (only if the auditor is wrong) pass override_audit with a one-line justification.~@[~%The re-run evidence was recorded (~a); cite it in record_finding to record a narrower claim.~]"
                 tool (claim-audit-verdict verdict) (claim-audit-reason verdict)
                 (and (string= tool "adopt_finding") evidence-list)))))
    (let* ((id (uuid))
           (open-sha (session-binary-sha256 *session*))
           (audit (if verdict
                      (obj "verdict" (claim-audit-verdict verdict)
                           "reason" (claim-audit-reason verdict)
                           "override" (if refused override :absent))
                      (obj "verdict" "unaudited"
                           "reason" (or (audit-outcome-unaudited-reason outcome) "side turn unavailable"))))
           (reproducible (count "reproducible" resolved :key #'recorded-status :test #'equal)))
      (append-entry "re.finding"
                    (obj "id" id
                         "claim" claim
                         "evidenceIds" (map 'simple-vector (lambda (record) (jstring record "id")) resolved)
                         "addr" (if (plusp (length addr)) addr :absent)
                         "confidence" (or confidence "likely")
                         "supersedes" (if (plusp (length supersedes)) supersedes :absent)
                         "audit" audit
                         "binarySha256" (if (plusp (length open-sha)) open-sha :absent)
                         "adoptedFrom" (if (plusp (length adopted-from)) adopted-from :absent)))
      (plain-result
       (join-lines
        (append
         (list (format nil "~a: recorded ~a~@[ (supersedes ~a)~]" tool (short-id id)
                       (and (plusp (length supersedes)) (short-id supersedes)))
               (format nil "claim: ~a" claim))
         (when (plusp (length adopted-from))
           (list (format nil "adopted from ~a: re-proven in this session on evidence ~a"
                         adopted-from evidence-list)))
         (list (format nil "support audit: ~a~@[ — ~a~]~:[~; (overridden)~]"
                       (jstring audit "verdict")
                       (and (plusp (length (jstring audit "reason"))) (jstring audit "reason"))
                       refused)
               (if (plusp reproducible)
                   (format nil "evidence: ~d of ~d machine-reproducible — this finding will carry to the next build (/re carry)"
                           reproducible (length resolved))
                   "evidence: none machine-reproducible — the finding is in the report but cannot carry; cite rizin_command evidence to make it carryable"))))
       (and (plusp (length addr)) addr)))))

;;; --- the tools ----------------------------------------------------------------------------------

(define-tool "record_finding"
    (:label "Record Finding" :tier :read
     :description "Record an analytical conclusion as a finding in the report, backed by the evidence ids that establish it — each RE tool result ends with an `[evidence xxxxxxxx]` tag; cite those ids. Refused when an id doesn't resolve or was taken against a different binary; the claim is then checked by a support auditor and refused, with the reason, if the evidence doesn't establish it or it claims more than the evidence shows — narrow the claim or cite better evidence. Cite rizin_command evidence where you can: only that is machine-reproducible, so only those findings carry to the next build (/re carry). Use supersedes to revise a finding; retract_finding to withdraw one.")
    (("claim" :string :required t :doc "The conclusion, stated as narrowly as the evidence supports — one finding per claim.")
     ("evidence" :strings :required t :doc "Evidence ids the claim rests on: the 8-character id in the `[evidence xxxxxxxx]` tag at the end of each RE tool result.")
     ("addr" :string :doc "The address or function the finding is about, when it is about one.")
     ("confidence" :string :enum '("confirmed" "likely" "speculative") :doc "How sure the claim is (default likely).")
     ("supersedes" :string :doc "Id of an earlier finding this one revises; the old one leaves the report.")
     ("override_audit" :string :doc "Only if the support auditor refused this claim and you are confident it is wrong: a one-line justification, recorded and shown beside the finding."))
    (arguments)
  (let ((cited (jlist arguments "evidence"))
        (evidence (collected-evidence))
        (resolved '())
        (problems '()))
    (check-text-length "record_finding" "claim" (jstring arguments "claim") 1 600)
    (unless (<= 1 (length cited) 16)
      (schema-refusal "record_finding" "evidence must cite 1 to 16 evidence ids (was ~d)" (length cited)))
    (dolist (raw cited)
      (multiple-value-bind (record reason) (resolve-id evidence (trimmed raw))
        (cond (reason (push reason problems))
              ((not (member record resolved)) (push record resolved)))))
    (setf resolved (nreverse resolved))
    (when problems
      (fail "omp-re: record_finding: evidence not found — ~{~a~^; ~}. Cite ids from RE tool results on this branch (/re evidence lists them)."
            (nreverse problems)))
    ;; Binding: a finding is about the open binary, so its evidence must be too.
    (let* ((open-sha (session-binary-sha256 *session*))
           (foreign (and open-sha
                         (remove-if-not (lambda (record)
                                          (let ((sha (jstring record "binarySha256")))
                                            (and (plusp (length sha)) (string/= sha open-sha))))
                                        resolved))))
      (when foreign
        (fail "omp-re: record_finding: evidence ~{~a~^, ~} was taken against a different binary than the one open — re-gather it on this binary."
              (mapcar (lambda (record) (short-id (jstring record "id"))) foreign))))
    (let ((supersedes nil))
      (when (plusp (length (jstring arguments "supersedes")))
        (multiple-value-bind (finding reason)
            (resolve-id (live-findings) (trimmed (jstring arguments "supersedes")))
          (when reason
            (fail "omp-re: record_finding: cannot supersede — ~a" reason))
          (setf supersedes (jstring finding "id"))))
      (gate-and-record "record_finding" resolved
                       :claim (jstring arguments "claim")
                       :addr (jstring arguments "addr")
                       :confidence (jstring arguments "confidence")
                       :supersedes supersedes
                       :override-audit (jstring arguments "override_audit")))))

(defun adopt-command (text)
  "One of adopt_finding's commands => (values COMMAND ADDR). The TypeScript
takes an object {command, addr?}; the spine's parameter types have no
object, so each arrives as a string: the line as the re-analyst writes it in
`reproduce' — `pdf @ sym.f', split at its ` @ ' — or that object as JSON."
  (let ((object (and (starts-with "{" (trimmed text)) (json-parse text))))
    (cond ((hash-table-p object)
           (unless (jstring object "command")
             (schema-refusal "adopt_finding" "a command given as an object needs a string `command` (was ~a)"
                             (json-encode object)))
           (values (jstring object "command") (jstring object "addr")))
          (t
           (let ((at (search " @ " text)))
             (if at
                 (values (trimmed (subseq text 0 at)) (trimmed (subseq text (+ at 3))))
                 (values text nil)))))))

(define-tool "adopt_finding"
    (:label "Adopt Finding" :tier :read
     :description "Adopt a finding made elsewhere — typically one returned by the re-analyst subagent, whose evidence lives in its own session — by re-proving it here: each given rizin command is re-run read-only on the open binary and recorded as evidence in THIS session, then the claim passes the same gates as record_finding (support audit included). Refused if expect_sha256 doesn't match the open binary or a command fails. Use the subagent's `reproduce` lines as the commands.")
    (("claim" :string :required t :doc "The finding's claim, as narrowly as its evidence supports.")
     ("commands" :strings :required t :doc "The rizin command(s) that reproduce the finding's evidence — re-run here and recorded as this session's evidence. Each is a read-only rizin command line, e.g. `pdf @ sym.decrypt_config` or `px 64 @ 0x4012a0` (the address after ` @ `), or a JSON object {\"command\": \"pdf\", \"addr\": \"sym.decrypt_config\"}.")
     ("addr" :string :doc "The address or function the finding is about.")
     ("confidence" :string :enum '("confirmed" "likely" "speculative" "possible") :doc "How sure the claim is (default likely); the re-analyst's `possible` is taken as speculative.")
     ("source" :string :doc "Who made the finding originally, e.g. \"re-analyst\".")
     ("expect_sha256" :string :doc "SHA-256 of the binary the finding was made on (the subagent's sha256); refused if a different binary is open.")
     ("override_audit" :string :doc "Only if the support auditor refused the claim and you are confident it is wrong: a one-line justification."))
    (arguments)
  (let ((commands (jlist arguments "commands"))
        (expected (jstring arguments "expect_sha256"))
        (open-sha (session-binary-sha256 *session*))
        (resolved '()))
    (check-text-length "adopt_finding" "claim" (jstring arguments "claim") 1 600)
    (unless (<= 1 (length commands) 8)
      (schema-refusal "adopt_finding" "commands must hold 1 to 8 commands (was ~d)" (length commands)))
    (when (jstring arguments "source")
      (check-text-length "adopt_finding" "source" (jstring arguments "source") 0 80))
    (when (and (plusp (length expected)) open-sha (string/= (string-downcase expected) open-sha))
      (fail "omp-re: adopt_finding: the finding was made on binary ~a… but ~a… is open — open the same binary first."
            (subseq expected 0 (min 12 (length expected))) (subseq open-sha 0 (min 12 (length open-sha)))))
    ;; Re-prove: every command runs through rizin_command's own read-only gate
    ;; and is recorded exactly as a live rizin_command result, bound to the
    ;; open binary. A claim is adopted only on evidence this session observed
    ;; itself — and that evidence stays in the record whatever becomes of the claim.
    (dolist (text commands)
      (multiple-value-bind (command addr) (adopt-command text)
        (let* ((addr (and (plusp (length addr)) addr))
               (result (run-rizin-command command addr)))
          (when (result-failed result)
            (let ((said (result-text result)))
              (fail "omp-re: adopt_finding: `~a~@[ @ ~a~]` failed here: ~a"
                    command addr (subseq said 0 (min 300 (length said))))))
          (let* ((id (record-evidence "rizin_command"
                                      (obj "command" command "addr" (or addr :absent))
                                      (result-text result) (result-details result)))
                 (record (find id (collected-evidence) :key (lambda (record) (jstring record "id"))
                                                       :test #'equal)))
            (when record (push record resolved))))))
    (gate-and-record "adopt_finding" (nreverse resolved)
                     :claim (jstring arguments "claim")
                     :addr (jstring arguments "addr")
                     :confidence (if (equal (jstring arguments "confidence") "possible")
                                     "speculative"
                                     (jstring arguments "confidence"))
                     :adopted-from (or (jstring arguments "source") "an external analysis")
                     :override-audit (jstring arguments "override_audit"))))

(define-tool "retract_finding"
    (:label "Retract Finding" :tier :read
     :description "Withdraw a finding recorded earlier with record_finding (it leaves the report). Give the reason; to revise rather than withdraw, call record_finding with supersedes instead.")
    (("id" :string :required t :doc "Id (or ≥6-char prefix) of the finding to withdraw.")
     ("reason" :string :required t :doc "Why it no longer stands."))
    (arguments)
  (check-text-length "retract_finding" "reason" (jstring arguments "reason") 1 300)
  (multiple-value-bind (finding reason) (resolve-id (live-findings) (trimmed (jstring arguments "id")))
    (when reason
      (fail "omp-re: retract_finding: ~a" reason))
    (append-entry "re.finding.retract"
                  (obj "id" (jstring finding "id") "reason" (jstring arguments "reason")))
    (plain-result (format nil "retract_finding: withdrew ~a — ~a~%reason: ~a"
                          (short-id (jstring finding "id")) (jstring finding "claim")
                          (jstring arguments "reason")))))

;;; --- /re findings and the status line -------------------------------------------------------------

(defun finding-detail (finding)
  (format nil "finding ~a: ~a~%~a~%evidence: ~{~a~^, ~}"
          (short-id (jstring finding "id")) (jstring finding "claim") (finding-note finding)
          (mapcar #'short-id (jlist finding "evidenceIds"))))

(define-slash "findings" (:usage "[id]" :description "findings the model recorded on this branch") (words)
  (let ((all (live-findings))
        (id (first words)))
    (cond (id
           (let ((match (or (find id all :key (lambda (finding) (jstring finding "id")) :test #'equal)
                            (find-if (lambda (finding) (starts-with id (jstring finding "id"))) all))))
             (if match
                 (finding-detail match)
                 (values (format nil "omp-re: no live finding with id ~a" id) t))))
          ((null all)
           "omp-re: no findings on this branch yet — the model records them with record_finding")
          (t
           (clip-list "omp-re: findings"
                      (mapcar (lambda (finding)
                                (format nil "[~a] ~a" (short-id (jstring finding "id")) (jstring finding "claim")))
                              all))))))

(defun findings-status-lines ()
  (let* ((findings (live-findings))
         (inherited (count-if (lambda (finding) (jget finding "inherited")) findings)))
    (list (format nil "findings on this branch: ~d~[~:; (~:*~d inherited)~]" (length findings) inherited))))

;; Named, not a closure, so loading this file again does not say it twice.
(setf *status-lines* (append (remove 'findings-status-lines *status-lines*)
                             (list 'findings-status-lines)))
