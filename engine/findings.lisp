;;;; findings.lisp --- the model's own conclusions as gated, carried claims.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A report's other claims come from machinery — indicators mined from
;;;; evidence. The conclusions that matter in reverse engineering ("checksum
;;;; is djb2") would otherwise live only in chat, outside every gate. A
;;;; finding puts one into the record:
;;;;
;;;; - record_finding takes a claim and the evidence ids it rests on. It is
;;;;   gated at record time, while the model can still act on the answer:
;;;;   every id must resolve in this session's record (existence), have been
;;;;   taken against the open binary (binding), and the claim goes to the
;;;;   same support audit /re report uses (audit-claims.lisp) — an
;;;;   unsupported or overreaching claim is refused with the auditor's
;;;;   reason unless the model overrides it with a written justification,
;;;;   which is kept and shown.
;;;; - adopt_finding re-proves a finding made elsewhere by making its reads
;;;;   here (OBSERVE-READ), so the claim rests on evidence this session
;;;;   observed.
;;;; - retract_finding withdraws one; `supersedes' revises one.
;;;;
;;;; Findings are re.finding / re.finding.retract entries of the record, read
;;;; back from it like all other state, so they survive a restart.

(in-package #:omp-re)

;;; --- reading the record --------------------------------------------------------------------

(defparameter +confidences+ '("confirmed" "likely" "speculative"))

(defparameter +confidence-aliases+ '(("possible" . "speculative"))
  "What a confidence said elsewhere is here: the re-analyst subagent's
findings say `possible'.")

(defun known-confidence (confidence)
  "CONFIDENCE as the engine says it, or the middle one when it says no such."
  (let ((confidence (or (cdr (assoc confidence +confidence-aliases+ :test #'equal)) confidence)))
    (if (member confidence +confidences+ :test #'equal) confidence "likely")))

(defun normalized-finding (data)
  "One re.finding entry's DATA as a finding, or NIL when it is not one: only
the members a finding has, a confidence the engine knows."
  (let ((ids (and (hash-table-p data) (gethash "evidenceIds" data))))
    (when (and (hash-table-p data) (jstring data "id") (jstring data "claim")
               (json-array-p ids))
      (obj "id" (jstring data "id")
           "claim" (jstring data "claim")
           "evidenceIds" (coerce (remove-if-not #'stringp ids) 'simple-vector)
           "addr" (jstring-or-absent data "addr")
           "confidence" (known-confidence (jstring data "confidence"))
           "supersedes" (jstring-or-absent data "supersedes")
           "audit" (if (hash-table-p (jget data "audit")) (jget data "audit") :absent)
           "binarySha256" (jstring-or-absent data "binarySha256")
           "inherited" (if (hash-table-p (jget data "inherited")) (jget data "inherited") :absent)
           "adoptedFrom" (jstring-or-absent data "adoptedFrom")))))

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
                          ;; An id recorded twice keeps its first place.
                          (let ((held (assoc (jstring finding "id") live :test #'equal)))
                            (if held
                                (setf (cdr held) finding)
                                (setf live (append live (list (cons (jstring finding "id") finding)))))))))))
      (mapcar #'cdr live))))

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
                          (format nil "`~a…`" (shown-hash from))
                          "an earlier build")
                      (or (jget inherited "carryStatus") "status not recorded")
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

;;; --- writing one ------------------------------------------------------------------------------

(defun record-finding (&key claim evidence-ids addr confidence supersedes audit adopted-from inherited
                            (session *session*))
  "Write one re.finding entry => its id. The one writer: a finding recorded
by the model, one adopted from elsewhere and one inherited from an earlier
build differ only in which of these they say."
  (let ((id (uuid))
        (open-sha (session-binary-sha256 session)))
    (append-entry "re.finding"
                  (obj "id" id
                       "claim" claim
                       "evidenceIds" (coerce evidence-ids 'simple-vector)
                       "addr" (if (plusp (length addr)) addr :absent)
                       "confidence" (known-confidence confidence)
                       "supersedes" (if (plusp (length supersedes)) supersedes :absent)
                       "audit" audit
                       ;; Binds the finding to the bytes it is about.
                       "binarySha256" (if (plusp (length open-sha)) open-sha :absent)
                       "inherited" (or inherited :absent)
                       "adoptedFrom" (if (plusp (length adopted-from)) adopted-from :absent))
                  session)
    id))

;;; --- the gate every finding passes ------------------------------------------------------------

(defun schema-refusal (tool problem &rest arguments)
  "Refuse a call whose arguments break a bound the tool's schema states —
the lengths and counts a parameter's type cannot say — in the words the
engine uses for the rest."
  (fail "omp-re: ~a was called with arguments that do not fit its schema: ~?" tool problem arguments))

(defun check-text-length (tool name text least most)
  (unless (<= least (length text) most)
    (schema-refusal tool "~a must be ~d to ~d characters (was ~d)" name least most (length text))))

(defun gate-and-record (tool resolved &key claim addr confidence supersedes adopted-from override-audit)
  "The gate every recorded finding passes once its evidence is resolved:
the support audit — refused on unsupported or overreach unless
OVERRIDE-AUDIT justifies it; fails open to `unaudited' — then the re.finding
entry and a result that says whether the finding can carry. Shared by
record_finding and adopt_finding, so the two can never gate differently.
ADOPTED-FROM says the evidence was taken just now for this claim: a refusal
then says it stays on the record."
  (let* ((outcome (audit-claims
                   (list (make-audit-item
                          :index 0
                          :claim-text claim
                          :evidence (mapcar (lambda (record)
                                              (obj "id" (jstring record "id")
                                                   "tool" (jstring record "tool")
                                                   "summary" (jstring record "summary")
                                                   "canonicalExcerpt" (jstring-or-absent record "canonicalExcerpt")))
                                            resolved)))
                   "advisory"))
         (verdict (outcome-verdict outcome 0))
         (refused (and verdict (flagged-p verdict)))
         (override (and (plusp (length override-audit)) override-audit))
         (evidence-list (format nil "~{~a~^, ~}"
                                (mapcar (lambda (record) (shown-id (jstring record "id"))) resolved))))
    (when (and refused (not override))
      (return-from gate-and-record
        (failed-result
         (format nil "~a: NOT recorded — the support auditor judged this claim ~a: ~a~%Narrow the claim to what the evidence shows, cite evidence that establishes it, or (only if the auditor is wrong) pass override_audit with a one-line justification.~@[~%The re-run evidence was recorded (~a); cite it in record_finding to record a narrower claim.~]"
                 tool (claim-audit-verdict verdict) (claim-audit-reason verdict)
                 (and adopted-from evidence-list)))))
    (let* ((audit (if verdict
                      (obj "verdict" (claim-audit-verdict verdict)
                           "reason" (claim-audit-reason verdict)
                           "override" (if refused override :absent))
                      (obj "verdict" "unaudited"
                           "reason" (or (audit-outcome-unaudited-reason outcome) "side turn unavailable"))))
           (reproducible (count-if #'evidence-rerun resolved))
           (id (record-finding :claim claim
                               :evidence-ids (mapcar (lambda (record) (jstring record "id")) resolved)
                               :addr addr :confidence confidence :supersedes supersedes
                               :audit audit :adopted-from adopted-from)))
      (plain-result
       (join-lines
        (append
         (list (format nil "~a: recorded ~a~@[ (supersedes ~a)~]" tool (shown-id id)
                       (and (plusp (length supersedes)) (shown-id supersedes)))
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
     :render '(:title "record_finding" :subject "claim")
     :description "Record an analytical conclusion as a finding in the report, backed by the evidence ids that establish it — each RE tool result ends with an `[evidence xxxxxxxx]` tag; cite those ids. Refused when an id doesn't resolve or was taken against a different binary; the claim is then checked by a support auditor and refused, with the reason, if the evidence doesn't establish it or it claims more than the evidence shows — narrow the claim or cite better evidence. Cite rizin_command evidence where you can: only that is machine-reproducible, so only those findings carry to the next build (/re carry). Use supersedes to revise a finding; retract_finding to withdraw one.")
    (("claim" :string :required t :doc "The conclusion, stated as narrowly as the evidence supports — one finding per claim.")
     ("evidence" :strings :required t :doc "Evidence ids the claim rests on: the 8-character id in the `[evidence xxxxxxxx]` tag at the end of each RE tool result.")
     ("addr" :string :doc "The address or function the finding is about, when it is about one.")
     ("confidence" :string :enum '("confirmed" "likely" "speculative") :doc "How sure the claim is (default likely).")
     ("supersedes" :string :doc "Id of an earlier finding this one revises; the old one leaves the report.")
     ("override_audit" :string :doc "Only if the support auditor refused this claim and you are confident it is wrong: a one-line justification, recorded and shown beside the finding."))
    (arguments)
  (let ((cited (jlist arguments "evidence"))
        (evidence (evidence-records))
        (resolved '())
        (problems '()))
    (check-text-length "record_finding" "claim" (jstring arguments "claim") 1 600)
    (unless (<= 1 (length cited) 16)
      (schema-refusal "record_finding" "evidence must cite 1 to 16 evidence ids (was ~d)" (length cited)))
    (dolist (raw cited)
      (multiple-value-bind (record reason) (find-by-id evidence (trimmed raw))
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
              (mapcar (lambda (record) (shown-id (jstring record "id"))) foreign))))
    (let ((supersedes nil))
      (when (plusp (length (jstring arguments "supersedes")))
        (multiple-value-bind (finding reason)
            (find-by-id (live-findings) (trimmed (jstring arguments "supersedes")))
          (when reason
            (fail "omp-re: record_finding: cannot supersede — ~a" reason))
          (setf supersedes (jstring finding "id"))))
      (gate-and-record "record_finding" resolved
                       :claim (jstring arguments "claim")
                       :addr (jstring arguments "addr")
                       :confidence (jstring arguments "confidence")
                       :supersedes supersedes
                       :override-audit (jstring arguments "override_audit")))))

(define-tool "adopt_finding"
    (:label "Adopt Finding" :tier :read
     :render '(:title "adopt_finding" :subject "claim")
     :description "Adopt a finding made elsewhere — typically one returned by the re-analyst subagent, whose evidence lives in its own session — by re-proving it here: each given rizin command is re-run read-only on the open binary and recorded as evidence in THIS session, then the claim passes the same gates as record_finding (support audit included). Refused if expect_sha256 doesn't match the open binary or a command fails. Use the subagent's `reproduce` lines as the commands.")
    (("claim" :string :required t :doc "The finding's claim, as narrowly as its evidence supports.")
     ("commands" :objects :required t
      :doc "The rizin command(s) that reproduce the finding's evidence — re-run here and recorded as this session's evidence."
      :properties (("command" :string :required t :doc "A read-only rizin command, e.g. `pdf` or `px 64`.")
                   ("addr" :string :doc "Where to run it (address or name).")))
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
            (shown-hash expected) (shown-hash open-sha)))
    ;; Re-prove: a claim is adopted only on evidence this session observed
    ;; itself — and that evidence stays in the record whatever becomes of the
    ;; claim.
    (dolist (given commands)
      (let ((command (jstring given "command"))
            (addr (and (plusp (length (jstring given "addr"))) (jstring given "addr"))))
        (multiple-value-bind (result id) (observe-read command addr)
          (when (result-failed result)
            (let ((said (result-text result)))
              (fail "omp-re: adopt_finding: `~a~@[ @ ~a~]` failed here: ~a"
                    command addr (subseq said 0 (min 300 (length said))))))
          (let ((record (and id (find-evidence id))))
            (when record (push record resolved))))))
    (gate-and-record "adopt_finding" (nreverse resolved)
                     :claim (jstring arguments "claim")
                     :addr (jstring arguments "addr")
                     :confidence (jstring arguments "confidence")
                     :adopted-from (or (jstring arguments "source") "an external analysis")
                     :override-audit (jstring arguments "override_audit"))))

(define-tool "retract_finding"
    (:label "Retract Finding" :tier :read
     :render '(:title "retract_finding" :subject "id")
     :description "Withdraw a finding recorded earlier with record_finding (it leaves the report). Give the reason; to revise rather than withdraw, call record_finding with supersedes instead.")
    (("id" :string :required t :doc "Id (or ≥6-char prefix) of the finding to withdraw.")
     ("reason" :string :required t :doc "Why it no longer stands."))
    (arguments)
  (check-text-length "retract_finding" "reason" (jstring arguments "reason") 1 300)
  (multiple-value-bind (finding reason) (find-by-id (live-findings) (trimmed (jstring arguments "id")))
    (when reason
      (fail "omp-re: retract_finding: ~a" reason))
    (append-entry "re.finding.retract"
                  (obj "id" (jstring finding "id") "reason" (jstring arguments "reason")))
    (plain-result (format nil "retract_finding: withdrew ~a — ~a~%reason: ~a"
                          (shown-id (jstring finding "id")) (jstring finding "claim")
                          (jstring arguments "reason")))))

;;; --- /re findings and the status line -------------------------------------------------------------

(defun finding-detail (finding)
  (format nil "finding ~a: ~a~%~a~%evidence: ~{~a~^, ~}"
          (shown-id (jstring finding "id")) (jstring finding "claim") (finding-note finding)
          (mapcar #'shown-id (jlist finding "evidenceIds"))))

(define-list "findings" (:description "findings the model recorded on this branch" :order 70
                         :row (80 "Findings" :detail "the conclusions recorded, each on its evidence")
                         :enter "discuss"
                         :none "omp-re: no findings on this branch yet — the model records them with record_finding"
                         :one (lambda (id)
                                (multiple-value-bind (match reason why) (find-by-id (live-findings) id)
                                  (cond (match (finding-detail match))
                                        ((eq why :missing)
                                         (values (format nil "omp-re: no live finding with id ~a" id) t))
                                        (t (values (format nil "omp-re: finding id ~a" reason) t))))))
  (mapcar (lambda (finding)
            (list-row (jstring finding "id")
                      (format nil "[~a] ~a" (shown-id (jstring finding "id")) (jstring finding "claim"))
                      :line (format nil "[~a] ~a" (shown-id (jstring finding "id")) (jstring finding "claim"))
                      :description (format nil "~a~:[~; · inherited~]~@[ · ~a~]"
                                           (jstring finding "confidence")
                                           (jget finding "inherited")
                                           (let ((addr (jstring finding "addr")))
                                             (and (plusp (length addr)) addr)))
                      :enter (obj "draft" (format nil "Re: ~a~%~%" (finding-detail finding)))))
          (live-findings)))

(contribute "findings" :order 70
  :status (lambda (session)
            (let* ((findings (live-findings session))
                   (inherited (count-if (lambda (finding) (jget finding "inherited")) findings)))
              (list (format nil "findings on this branch: ~d~[~:; (~:*~d inherited)~]"
                            (length findings) inherited)))))
