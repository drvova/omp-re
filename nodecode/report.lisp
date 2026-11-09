;;;; report.lisp --- /re report: the evidence-gated report and its manifest.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Ported from omp-re's report.ts and the fingerprint half of anchor.ts the
;;;; manifest needs.
;;;;
;;;; A report has two hard properties: IOCs are defanged, and the write gate
;;;; refuses to emit a report containing any claim with zero backing
;;;; evidence. Every rendered claim anchors to the evidence it actually came
;;;; from (`[tool:id]'), tracked per claim, and the anchors resolve into a
;;;; Verification Manifest — in the markdown, and as `<report>.manifest.json'
;;;; beside it, the file /re carry and omp itself read: same members, same
;;;; order, same spelling as the TypeScript writes.
;;;;
;;;; The third gate, the claim-support audit (audit-claims.lisp), asks the
;;;; model in a side question whether each claim's evidence supports it. It
;;;; is advisory by default: a claim judged unsupported or overreaching is
;;;; flagged where it stands and the report is still written.
;;;; --audit=strict withholds the report on such a verdict, and on nothing
;;;; else: an audit that could not run fails open, and the report says under
;;;; its claims that their support went unaudited.

(in-package #:nodecode-re)

;;; --- what a piece of evidence recorded ---------------------------------------------------------

(defun evidence-output (record)
  "The full text RECORD's tool answered: the session artifact when the
result was cut (the artifact is whole), else the content-addressed blob.
NIL when neither can be read — a claim then gets no extra evidence, the
report never fails for it."
  (or (let ((artifact (jstring record "artifactId")))
        (and (plusp (length artifact)) (ignore-errors (read-text-file (artifact-path artifact)))))
      (ignore-errors (read-blob (jstring record "outputHash")))))

(defun evidence-json (raw)
  "RAW parsed as JSON => (values DATA T), or (values NIL NIL). A JSON result
is a header line and then the JSON body, never pure JSON: try the whole
text first so a blob that is pure JSON still works, then without its first
line."
  (handler-case (values (json-decode raw) t)
    (error ()
      (let ((newline (position #\Newline raw)))
        (if newline
            (handler-case (values (json-decode (subseq raw (1+ newline))) t)
              (error () (values nil nil)))
            (values nil nil))))))

(defstruct (report-claim (:copier nil))
  (text "" :type string)
  ;; The evidence and annotation ids backing the claim. None means
  ;; ungrounded: the write gate blocks on this.
  (evidence-ids '())
  ;; A provenance line shown under the claim. Display only — never part of
  ;; the claim text, which is what carry matches on.
  (note nil))

(defstruct (report-section (:copier nil))
  (title "" :type string)
  ;; Prose before the claims. Never gated: only claims are checked for grounding.
  (intro nil)
  (claims '()))

(defstruct (built-report (:copier nil))
  (title "" :type string)
  (sections '())
  (tool-by-id (make-hash-table :test #'equal))      ; the tool behind each cited id, for anchors
  (evidence-by-id (make-hash-table :test #'equal))  ; the whole record, for the manifest
  (binary-sha256 nil)                               ; of the binary this record last opened
  (findings '()))

(defun report-annotations (&optional (session *session*))
  "The annotations in effect on the open binary, as the report reads them.
annotate.lisp owns that answer (after /re undo); with no annotation module
loaded there are none."
  (let ((binary-path (session-binary-path session)))
    (remove-if-not
     (lambda (annotation)
       (and (hash-table-p annotation) (jstring annotation "kind") (jstring annotation "ea")))
     (cond ((null binary-path) '())
           ((fboundp 'live-annotations) (funcall 'live-annotations binary-path session))
           (*live-annotations* (funcall *live-annotations* binary-path session))
           (t '())))))

;;; --- indicators of compromise ------------------------------------------------------------------

(defparameter +ioc-scanners+
  (mapcar #'ppcre:create-scanner
          '("(?:/[^/\\s]+){3,}|(?:[A-Za-z]:\\\\[^\\\\\\s]+){3,}"                   ; paths
            "(?i)(?:https?|hxxps?)://[A-Za-z0-9_\\-.~:/?#\\[\\]@!$&'()*+,;=%]+"     ; URLs
            "\\b[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\b"               ; IPv4
            "(?:HKLM|HKCU)\\\\[^\\\\\\s]+"))                                        ; registry keys
  "What counts as an indicator, in the order a text is scanned for them.")

(defun iocs-in (text)
  "Every indicator in TEXT. The text scanned includes raw JSON (an
evidence summary), whose quoting and delimiters can hang off a real match,
so trailing punctuation is trimmed: an IOC never ends mid-punctuation."
  (loop for scanner in +ioc-scanners+
        append (mapcar (lambda (match) (ppcre:regex-replace "[\"'),;.]+$" match ""))
                       (ppcre:all-matches-as-strings scanner text))))

(defun defang-ioc (ioc)
  "IOC made safe to paste: it can be neither clicked nor resolved. http(s)
becomes hxxp(s), `.' becomes `[.]' in a URL or an IPv4 literal — only
there, so a path's or a registry key's separators are left alone — and `@'
becomes `[@]'."
  (let* ((out (ppcre:regex-replace "(?i)^https?" ioc
                                   (lambda (target start end match-start match-end reg-starts reg-ends)
                                     (declare (ignore start end reg-starts reg-ends))
                                     (ppcre:regex-replace
                                      "tt" (string-downcase (subseq target match-start match-end)) "xx"))))
         (out (if (or (js-scan "(?i)^(?:https?|hxxps?)://" ioc)
                      (js-scan "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$" ioc))
                  (replace-all out "." "[.]")
                  out)))
    (replace-all out "@" "[@]")))

(defun json-strings (value)
  "Every string anywhere in the decoded JSON VALUE, in document order."
  (cond ((stringp value) (list value))
        ((vectorp value) (loop for item across value append (json-strings item)))
        ((hash-table-p value) (loop for item being the hash-values of value append (json-strings item)))
        (t '())))

(defparameter +string-tools+ '("floss" "strings" "triage_floss" "list_strings")
  "The tools whose whole output is strings worth scanning, not just the summary.")

(defun ioc-claims (evidence annotations)
  "One claim for each distinct indicator found in the EVIDENCE summaries
(and, for the string tools, their whole output) and in the ANNOTATIONS'
values, each grounded on where it was seen — an annotation made with no
evidence under it grounds nothing, and that is what the gate catches."
  (let ((claims '()))                   ; (text . ids), first seen first
    (flet ((note (ioc ids)
             (let* ((text (defang-ioc ioc))
                    (held (assoc text claims :test #'string=)))
               (if held
                   (setf (cdr held) (remove-duplicates (append (cdr held) ids) :test #'equal :from-end t))
                   (setf claims (append claims (list (cons text (copy-list ids)))))))))
      (dolist (record evidence)
        (let ((texts (list (jstring record "summary"))))
          (when (member (string-downcase (jstring record "tool")) +string-tools+ :test #'string=)
            (let ((raw (evidence-output record)))
              (when (plusp (length raw))
                (multiple-value-bind (data parsed) (evidence-json raw)
                  (setf texts (append texts (if parsed (json-strings data) (list raw))))))))
          (dolist (text texts)
            (dolist (ioc (iocs-in text))
              (note ioc (list (jstring record "id")))))))
      (dolist (annotation annotations)
        (let ((evidence-id (jstring annotation "evidenceId")))
          (dolist (text (list (or (jstring annotation "oldValue") "") (or (jstring annotation "newValue") "")))
            (dolist (ioc (iocs-in text))
              (note ioc (and (plusp (length evidence-id)) (list evidence-id))))))))
    (mapcar (lambda (claim) (make-report-claim :text (car claim) :evidence-ids (cdr claim)))
            (stable-sort claims #'locale-less-p :key #'car))))

;;; --- capa's capabilities -----------------------------------------------------------------------

(defparameter +mitre-attack+
  '(("T1059" . "Command and Scripting Interpreter")
    ("T1059.004" . "Unix Shell")
    ("T1059.003" . "Windows Command Shell")
    ("T1059.007" . "JavaScript")
    ("T1204" . "User Execution")
    ("T1086" . "PowerShell")
    ("T1053" . "Scheduled Task/Job")
    ("T1547" . "Boot or Logon Autostart Execution")
    ("T1027" . "Obfuscated Files or Information")
    ("T1082" . "System Information Discovery")
    ("T1036" . "Masquerading")
    ("T1543" . "Create or Modify System Process")
    ("T1078" . "Valid Accounts")
    ("T1112" . "Modify Registry")
    ("T1006" . "Direct Volume Access")
    ("T1003" . "OS Credential Dumping")
    ("T1548" . "Abuse Elevation Control Mechanism")
    ("T1070" . "Indicator Removal on Host")
    ("T1021" . "Remote Services")
    ("T1090" . "Proxy")
    ("T1568" . "Dynamic Resolution")
    ("T1480" . "Execution Guardrails"))
  "The technique names used when capa gave an ATT&CK id and no label of its own.")

(defun capability-claims (capa-evidence)
  "What the capa records matched => (values CAPABILITY-CLAIMS ATTACK-CLAIMS).
A capa record is the flat array of {name, meta} the triage tool stores; a
record that is cut or malformed contributes nothing and never fails the
report. The latest record to name a capability is the one it is anchored to."
  (let ((capabilities (make-hash-table :test #'equal)) ; name -> evidence id
        (attacks (make-hash-table :test #'equal))      ; ATT&CK id -> evidence id
        (labels (make-hash-table :test #'equal)))      ; ATT&CK id -> capa's own label
    (dolist (record capa-evidence)
      (let* ((raw (evidence-output record))
             (rules (and (plusp (length raw)) (evidence-json raw)))
             (id (jstring record "id")))
        (when (and (vectorp rules) (not (stringp rules)))
          (loop for rule across rules
                do (let ((name (find-if (lambda (name) (plusp (length name)))
                                        (list (trimmed (jstring rule "meta" "name"))
                                              (trimmed (jstring rule "name"))))))
                     (when name (setf (gethash name capabilities) id))
                     (dolist (entry (jlist rule "meta" "attack"))
                       (if (stringp entry)
                           (unless (blank-p entry) (setf (gethash (trimmed entry) attacks) id))
                           (let ((attack (trimmed (jstring entry "id"))))
                             (when (plusp (length attack))
                               (setf (gethash attack attacks) id)
                               (let ((label (remove-if #'blank-p (list (jstring entry "technique")
                                                                       (jstring entry "subtechnique")))))
                                 (when label
                                   (setf (gethash attack labels) (format nil "~{~a~^: ~}" label)))))))))))))
    (flet ((sorted-keys (table)
             (sort (loop for key being the hash-keys of table collect key) #'string<)))
      (values
       (mapcar (lambda (name)
                 (make-report-claim :text name :evidence-ids (list (gethash name capabilities))))
               (sorted-keys capabilities))
       (mapcar (lambda (attack)
                 (make-report-claim
                  :text (format nil "~a — ~a" attack
                                (or (gethash attack labels)
                                    (cdr (assoc attack +mitre-attack+ :test #'string=))
                                    "(unmapped technique)"))
                  :evidence-ids (list (gethash attack attacks))))
               (sorted-keys attacks))))))

;;; --- building it --------------------------------------------------------------------------------

(defun last-recorded-binary-sha256 (&optional (session *session*))
  (let ((last nil))
    (dolist (binary (entries-of "re.binary" session) last)
      (when (jstring binary "sha256") (setf last (jstring binary "sha256"))))))

(defun build-report (&optional (session *session*))
  "Read the record into a report: capa's capabilities, the model's findings,
the indicators, each claim with the ids it rests on."
  (let* ((evidence (collected-evidence session))
         (annotations (report-annotations session))
         (findings (live-findings session))
         (report (make-built-report
                  :title (let ((id (session-id session)))
                           (format nil "Analysis Report — Session ~a"
                                   (if (> (length id) 8) (subseq id (- (length id) 8)) id)))
                  :binary-sha256 (last-recorded-binary-sha256 session)
                  :findings findings))
         (tool-by-id (built-report-tool-by-id report))
         (sections '()))
    (dolist (record evidence)
      (setf (gethash (jstring record "id") tool-by-id) (jstring record "tool")
            (gethash (jstring record "id") (built-report-evidence-by-id report)) record))
    (dolist (annotation annotations)
      (let ((id (jstring annotation "evidenceId")))
        (when (and (plusp (length id)) (not (gethash id tool-by-id)))
          (setf (gethash id tool-by-id) "annotation"))))
    (let ((capa (remove-if-not (lambda (record)
                                 (member (string-downcase (jstring record "tool")) '("capa" "triage_capa")
                                         :test #'string=))
                               evidence)))
      (when capa
        (multiple-value-bind (capabilities attacks) (capability-claims capa)
          (push (make-report-section
                 :title "Summary"
                 :intro (format nil "Analysis performed using **capa** on the provided sample: ~d capability rule(s) matched~@[ mapping to ~d ATT&CK technique(s)~]. See Capabilities & MITRE ATT&CK Mapping below for the full, evidence-anchored list."
                                (length capabilities) (and attacks (length attacks))))
                sections)
          (when (or capabilities attacks)
            (push (make-report-section :title "Capabilities & MITRE ATT&CK Mapping"
                                       :claims (append capabilities attacks))
                  sections)))))
    ;; The model's own conclusions: gated when they were recorded, and gated
    ;; again here like every other claim.
    (when findings
      (push (make-report-section
             :title "Findings"
             :claims (mapcar (lambda (finding)
                               (make-report-claim :text (jstring finding "claim")
                                                  :evidence-ids (jlist finding "evidenceIds")
                                                  :note (finding-note finding)))
                             findings))
            sections))
    (let ((iocs (ioc-claims evidence annotations)))
      (when iocs
        (push (make-report-section :title "Indicators of Compromise" :claims iocs) sections)))
    (push (make-report-section :title "Conclusion"
                               :intro "This report was generated from an automated analysis session.")
          sections)
    (setf (built-report-sections report) (nreverse sections))
    report))

(defun report-claims (report)
  "Every claim of REPORT, in the order rendered."
  (loop for section in (built-report-sections report) append (report-section-claims section)))

(defun cited-ids (report)
  "Each distinct id a claim of REPORT cites, in the order first cited."
  (remove-duplicates (loop for claim in (report-claims report) append (report-claim-evidence-ids claim))
                     :test #'equal :from-end t))

(defun ungrounded-claims (report)
  "The claims with no id behind them. One is enough to withhold the whole
report: a partial or annotated report is no substitute, the point of the
gate is that an ungrounded report never reaches a ticket."
  (remove-if #'report-claim-evidence-ids (report-claims report)))

(defun audit-inputs (report with-full-text)
  "What the support audit is put: one item for each claim citing at least
one evidence RECORD — an annotation's id carries no tool output to judge —
with each record's summary and canonical excerpt and, WITH-FULL-TEXT (only
when a judge will run), the output itself where it is short. An item's
index is the claim's flat position in the report, which the verdicts come
back on and the markdown flags by."
  (let ((items '())
        (texts (make-hash-table :test #'equal))
        (index 0))
    (dolist (claim (report-claims report))
      (let ((evidence '()))
        (dolist (id (report-claim-evidence-ids claim))
          (let ((record (gethash id (built-report-evidence-by-id report))))
            (when record
              (when (and with-full-text (not (nth-value 1 (gethash id texts))))
                (let ((raw (evidence-output record)))
                  (setf (gethash id texts) (and (plusp (length raw)) (<= (length raw) 1200) raw))))
              (push (obj "id" (jstring record "id")
                         "tool" (jstring record "tool")
                         "summary" (jstring record "summary")
                         "canonicalExcerpt" (string-member record "canonicalExcerpt")
                         "fullText" (or (gethash id texts) :absent))
                    evidence))))
        (when evidence
          (push (make-audit-item :index index :claim-text (report-claim-text claim)
                                 :evidence (nreverse evidence))
                items))
        (incf index)))
    (nreverse items)))

(defun claim-audit-lines (outcome)
  "The support audit's summary note. Prose, never a claim, so the gate does
not see it. Nothing when nothing was audited; else one line of counts, or
the note that says the audit could not run. A claim's own flag is rendered
beside the claim."
  (cond ((zerop (audit-outcome-item-count outcome)) '())
        ((not (audit-outcome-audited outcome))
         (list (format nil "> _Claim–evidence support unaudited — ~a._"
                       (or (audit-outcome-unaudited-reason outcome) "side turn unavailable"))
               ""))
        (t
         (let ((verdicts (audit-outcome-by-index outcome)))
           (list (format nil "> _Claim–evidence support audit: ~d supported, ~d flagged, ~d unaudited._"
                         (count "supported" verdicts :key #'claim-audit-verdict :test #'string=)
                         (count-if #'flagged-p verdicts)
                         (count "unaudited" verdicts :key #'claim-audit-verdict :test #'string=))
                 "")))))

;;; --- the markdown --------------------------------------------------------------------------------

(defun manifest-table-lines (report)
  "The Verification Manifest: one row for each distinct cited id — the table
the `[tool:id]' anchors resolve into — so anyone with the binary can
re-derive each claim. Prose and a table, never a claim, so the gate does
not see it."
  (let ((cited (cited-ids report)))
    (when cited
      (append
       (list "## Verification Manifest" ""
             (format nil "Binary SHA-256: `~a`" (or (built-report-binary-sha256 report) "unbound (legacy)")) ""
             "Each `reproducible` row can be re-derived from the binary: re-run its command read-only and compare the output hash (`/re verify`)." ""
             "| Evidence | Tool | Command | Output hash (repro) | Status |"
             "| --- | --- | --- | --- | --- |")
       (mapcar (lambda (id)
                 (let* ((record (gethash id (built-report-evidence-by-id report)))
                        (command (and record (recorded-command record)))
                        (repro (and record (jstring record "reproHash"))))
                   (format nil "| `~a` | ~a | ~a | ~a | ~a |"
                           (short-id id)
                           (or (gethash id (built-report-tool-by-id report)) "unknown")
                           (if command (format nil "`~a`" command) "—")
                           (if (plusp (length repro))
                               (format nil "`~a…`" (subseq repro 0 (min 12 (length repro))))
                               "—")
                           (if record (recorded-status record) "unverifiable (legacy)"))))
               cited)
       (list "")))))

(defun format-markdown (report &optional outcome)
  "REPORT as markdown. OUTCOME is the support audit's: a claim it flagged
says so under its evidence, and a note under the claims sums it up."
  (let ((lines (list "" (format nil "# ~a" (built-report-title report))))
        (claim-index 0))
    (flet ((say (&rest more) (dolist (line more) (push line lines))))
      (dolist (section (built-report-sections report))
        (say (format nil "## ~a" (report-section-title section)) "")
        (when (report-section-intro section)
          (say (report-section-intro section) ""))
        (when (report-section-claims section)
          (dolist (claim (report-section-claims section))
            (say (format nil "- ~a" (report-claim-text claim)))
            (when (plusp (length (report-claim-note claim)))
              (say (format nil "  _~a_" (report-claim-note claim))))
            (when (report-claim-evidence-ids claim)
              (say (format nil "  **Evidence:** ~{~a~^ ~}"
                           (mapcar (lambda (id)
                                     (format nil "[~a:~a]"
                                             (or (gethash id (built-report-tool-by-id report)) "unknown") id))
                                   (report-claim-evidence-ids claim)))))
            (let ((audit (and outcome (outcome-verdict outcome claim-index))))
              (when (and audit (flagged-p audit))
                (say (format nil "  _⚠ Support audit: ~a — ~a_"
                             (claim-audit-verdict audit) (claim-audit-reason audit)))))
            (incf claim-index))
          (say "")))
      (when outcome
        (apply #'say (claim-audit-lines outcome)))
      (apply #'say (manifest-table-lines report)))
    (format nil "~a~%" (string-right-trim '(#\Space #\Tab #\Newline #\Return)
                                          (join-lines (nreverse lines))))))

;;; --- the manifest beside it ----------------------------------------------------------------------

(defparameter +max-mnemonics+ 512
  "The most mnemonics kept in a fingerprint: plenty to identify a function,
few enough to keep the manifest and carry's comparison cheap.")

(defun report-anchor-fingerprint (rz anchor)
  "A fingerprint of the function containing ANCHOR in the open build — name,
start, size, block count, the anchor's offset into it and its mnemonic
sequence — so /re carry can find the code again in another build. NIL when
the anchor is in no function or does not resolve; never signals. Mnemonics
only, never operands: a rebuild changes addresses and registers long before
it changes the instruction mix. (anchor.ts's fingerprintAnchor.)"
  (ignore-errors
   (let* ((at (resolve-numeric-addr rz anchor))
          (functions (rz-cmdj rz (format nil "afij @ ~a" (ea-from-offset at))))
          (function (and (vectorp functions) (plusp (length functions)) (aref functions 0)))
          (start (and function (jnumber function "offset"))))
     (when start
       (let* ((listing (rz-cmdj rz (format nil "pdfj @ ~a" (ea-from-offset start))))
              (mnemonics (loop for op in (jlist listing "ops")
                               for text = (jstring op "disasm")
                               when (and text (not (equal (jget op "type") "invalid")))
                                 collect (string-downcase (or (first (words text)) "")))))
         (when mnemonics
           (obj "anchor" anchor
                "function" (or (jget function "name") :absent)
                "offset" (ea-from-offset start)
                "delta" (- at start)
                "size" (or (jget function "size") :absent)
                "nbbs" (or (jget function "nbbs") :absent)
                "mnemonics" (coerce (subseq mnemonics 0 (min +max-mnemonics+ (length mnemonics)))
                                    'simple-vector))))))))

(defun rizin-command-arguments (record)
  "A rizin_command RECORD's {command, addr} — what /re carry re-runs on
another binary — or NIL for any other tool or a malformed record."
  (let ((command (jstring record "args" "command"))
        (addr (jstring record "args" "addr")))
    (and (equal (jstring record "tool") "rizin_command")
         command
         (obj "command" command "addr" (if (plusp (length addr)) addr :absent)))))

(defun collect-anchors (report &optional (session *session*))
  "A fingerprint for every cited, address-pinned rizin_command record — but
only while the binary that evidence was taken against is the one open, since
a fingerprint of any other build would point /re carry at the wrong code.
Best effort: with no rizin the manifest is complete, just without them."
  (let ((anchors (make-hash-table :test #'equal))
        (open-sha (session-binary-sha256 session)))
    (when (and (session-binary-path session) open-sha)
      (ignore-errors
       (dolist (id (cited-ids report))
         (let* ((record (gethash id (built-report-evidence-by-id report)))
                (addr (and record
                           (equal (jstring record "binarySha256") open-sha)
                           (jstring (rizin-command-arguments record) "addr"))))
           (when addr
             (let ((fingerprint (report-anchor-fingerprint (ensure-rizin session) addr)))
               (when fingerprint (setf (gethash id anchors) fingerprint))))))))
    anchors))

(defun recorded-commands-array (record)
  "RECORD's commands as the array recorded — an empty one included, which
the TypeScript writes as [] and not null — or NIL when it recorded none."
  (let ((commands (jget record "commands")))
    (and (vectorp commands) (not (stringp commands)) (every #'stringp commands) commands)))

(defun manifest-json (report anchors)
  "The machine-readable manifest: the binary's hash, the findings (what
/re carry --inherit re-proves on another build), and one entry for each
distinct cited id — its command, its hashes, its anchor, its recorded
status and the claims it backs. Absent is null, never left out: readers
index these members by name."
  (let ((claims-by-id (make-hash-table :test #'equal))
        (ids '()))
    (dolist (claim (report-claims report))
      (dolist (id (report-claim-evidence-ids claim))
        (unless (nth-value 1 (gethash id claims-by-id)) (push id ids))
        (setf (gethash id claims-by-id)
              (append (gethash id claims-by-id) (list (report-claim-text claim))))))
    (obj "binarySha256" (or (built-report-binary-sha256 report) :null)
         "findings" (map 'simple-vector
                         (lambda (finding)
                           (obj "id" (jstring finding "id")
                                "claim" (jstring finding "claim")
                                "evidenceIds" (gethash "evidenceIds" finding)
                                "addr" (or (jstring finding "addr") :null)
                                "confidence" (jstring finding "confidence")))
                         (built-report-findings report))
         "entries" (map 'simple-vector
                        (lambda (id)
                          (let ((record (gethash id (built-report-evidence-by-id report))))
                            (obj "evidenceId" id
                                 "tool" (or (gethash id (built-report-tool-by-id report)) "unknown")
                                 "args" (or (and record (rizin-command-arguments record)) :null)
                                 "command" (or (and record (recorded-command record)) :null)
                                 "commands" (or (and record (recorded-commands-array record)) :null)
                                 "reproHash" (or (and record (jstring record "reproHash")) :null)
                                 "canonicalExcerpt" (or (and record (jstring record "canonicalExcerpt")) :null)
                                 "shiftHash" (or (and record (jstring record "shiftHash")) :null)
                                 "anchor" (or (gethash id anchors) :null)
                                 "binarySha256" (or (and record (jstring record "binarySha256")) :null)
                                 "status" (if record (recorded-status record) "unverifiable (legacy)")
                                 "claims" (coerce (gethash id claims-by-id) 'simple-vector))))
                        (nreverse ids)))))

;;; --- writing it ----------------------------------------------------------------------------------

(defun write-report-file (path text)
  "Write TEXT to PATH, which is the user's own: read against the process's
directory when relative, and its folder is not made for it."
  (with-open-file (out (merge-pathnames (uiop:parse-native-namestring path) (uiop:getcwd))
                       :direction :output :if-exists :supersede :if-does-not-exist :create
                       :external-format :utf-8)
    (write-string text out))
  path)

(defun write-report (&key output-path (audit "advisory") (session *session*))
  "Build the report for SESSION and write it to OUTPUT-PATH, or answer the
markdown itself when there is none => (values TEXT FAILED-P).

The write gate is hard: if any claim has no evidence id, the whole report is
withheld — never partly written — and the answer says which claims are
ungrounded. Then the third gate, the semantic one: does each grounded claim's evidence
support it? AUDIT is its mode. \"advisory\" flags claims and never blocks;
\"strict\" withholds the whole report on an explicit unsupported or
overreach verdict, and fails open when the audit could not run, so a strict
report stays emittable with no model to ask; \"off\" skips it. The two
deterministic gates block in every mode."
  (let* ((report (build-report session))
         (ungrounded (ungrounded-claims report)))
    (when ungrounded
      (return-from write-report
        (values (format nil "omp-re: report withheld — ~d claim(s) without evidence:~%~{  - ~a~^~%~}"
                        (length ungrounded) (mapcar #'report-claim-text ungrounded))
                t)))
    (let* ((judge (and (not (equal audit "off")) *claim-judge*))
           (outcome (audit-claims (and (not (equal audit "off")) (audit-inputs report (and judge t)))
                                  audit judge))
           (flagged (and (equal audit "strict") (flagged-verdicts outcome)))
           (markdown (and (null flagged) (format-markdown report outcome))))
      (when flagged
        (return-from write-report
          (values (let ((claims (report-claims report)))
                    (format nil "omp-re: report withheld — ~d claim(s) not supported by their cited evidence:~%~{~a~^~%~}"
                            (length flagged)
                            (mapcar (lambda (verdict)
                                      (let ((index (claim-audit-index verdict)))
                                        (format nil "  - [~a] ~a — ~a"
                                                (claim-audit-verdict verdict)
                                                ;; A verdict for an index the report has no claim at names none.
                                                (if (and (= index (round index)) (< -1 index (length claims)))
                                                    (report-claim-text (nth (round index) claims))
                                                    "")
                                                (claim-audit-reason verdict))))
                                    flagged)))
                  t)))
      (if (null output-path)
          (values markdown nil)
          (let ((manifest-path (format nil "~a.manifest.json" output-path)))
            (handler-case (write-report-file output-path markdown)
              (error (condition)
                (fail "omp-re: could not write report to ~a: ~a" output-path condition)))
            (values
             (format nil "omp-re: report written to ~a~a" output-path
                     ;; The report is already on disk; a sidecar that could
                     ;; not be written must not undo that — say so and carry on.
                     (handler-case
                         (progn
                           (write-report-file
                            manifest-path
                            (format nil "~a~%" (json-encode (manifest-json report (collect-anchors report session))
                                                            :indent 2)))
                           (format nil " (+ ~a)" manifest-path))
                       (error (condition)
                         (format nil " (manifest sidecar not written: ~a)" condition))))
             nil))))))

(define-slash "report" (:usage "[path] [--audit=strict]"
                        :description "write the evidence-gated report (claim-support audit advisory by default; --audit=strict gates it, --no-audit skips)")
    (words)
  ;; The flag words are taken out and the rest joins back into the path.
  (let ((audit "advisory")
        (path '()))
    (dolist (word words)
      (cond ((member word '("--no-audit" "--audit=off") :test #'string=) (setf audit "off"))
            ((member word '("--audit" "--audit=advisory") :test #'string=) (setf audit "advisory"))
            ((string= word "--audit=strict") (setf audit "strict"))
            (t (push word path))))
    (write-report :output-path (and path (rest-of-line (nreverse path))) :audit audit)))
