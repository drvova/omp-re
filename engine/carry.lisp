;;;; carry.lisp --- /re carry: replay a report's manifest against another build.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A report's verification manifest (`<report>.manifest.json', report.lisp)
;;;; is already a test suite: claim, exact read-only rizin command, canonical
;;;; output hash. /re verify runs it against the SAME binary to prove
;;;; reproducibility; carry runs it against whatever binary is open now — the
;;;; next sample of a family, a firmware update, a patched build — and
;;;; classifies each piece of evidence, then each claim:
;;;;
;;;; - holds: the re-run's canonical output hash is identical, or identical
;;;;   once positional addresses are masked — the code did not change, the
;;;;   build just moved it.
;;;; - relocated: the anchor vanished (a renamed symbol) or a numeric anchor
;;;;   now points elsewhere, but the function it named was found again by its
;;;;   fingerprint and the command re-run there says the same thing.
;;;; - drifted: the command still runs but its output changed. The recorded
;;;;   excerpt is line-diffed against the new one with addresses masked, so
;;;;   the diff keeps to what really changed.
;;;; - broken: the anchor is gone and nothing matches its fingerprint, or the
;;;;   command now produces nothing.
;;;; - unchecked: the evidence had no reproducible hash, or its command is no
;;;;   longer runnable in this rizin.
;;;;
;;;; A claim takes the worst status among its checked evidence. Read-only
;;;; like /re verify: the manifest is untrusted input, so every command goes
;;;; back through the policy gate and every address through VALIDATE-ADDR, and
;;;; a line is sent to the process directly, not as a tool call, so carrying
;;;; records nothing — until --inherit, which re-proves the findings that
;;;; held by making their reads again as rizin_command calls (OBSERVE-READ),
;;;; audited and recorded here like any other.
;;;;
;;;; The summary and, under it, the agenda are the answer, and a broken claim
;;;; fails the line — which is what makes a report a regression test for the
;;;; next build.

(in-package #:omp-re)

(defparameter +max-diff-lines+ (* 2 +excerpt-lines+)
  "The most diff lines shown for one drifted record: both excerpts whole,
so this only bites on a total rewrite.")

(defparameter +diff-context+ 2
  "How many unchanged lines a shown diff keeps around each change.")

;;; --- reading a manifest --------------------------------------------------------------------------

(defstruct (manifest-entry (:copier nil))
  "One entry of a manifest, as read back. Everything but the id may be
missing: a manifest is untrusted, and may be older than a member."
  (evidence-id "" :type string)
  (tool "unknown" :type string)
  (read nil)                            ; {command, addr?} to re-run, as EVIDENCE-RERUN answers it,
  (unrunnable nil)                      ; or why it cannot be
  (command nil)                         ; the recorded line, for display
  (repro-hash nil)
  (canonical-excerpt nil)
  (shift-hash nil)
  (anchor nil)                          ; a fingerprint object or NIL
  (binary-sha256 nil)
  (claims '()))

(defstruct (manifest-finding (:copier nil))
  "One finding of a manifest's `findings' — what --inherit re-proves."
  (id "" :type string)
  (claim "" :type string)
  (evidence-ids '())
  (addr nil)
  (confidence "likely"))

(defstruct (carry-manifest (:copier nil))
  (binary-sha256 nil)
  (entries '())
  (findings '()))                       ; none on a manifest older than findings

(defun parse-manifest (text)
  "TEXT as a manifest. Anything that is not one is refused in words that say
which file to pass; an entry or a finding that is malformed is dropped, a
member that is missing is read as absent."
  (let ((raw (flet ((refuse (detail)
                      (fail "omp-re: carry: manifest is not valid JSON (~a)" detail)))
               ;; The engine's reader stops after the first value. Read as the
               ;; one item of an array, text after the value is refused too,
               ;; as JSON.parse refuses it.
               (let ((values (handler-case (json-decode (format nil "[~a]" text))
                               (json-refusal (condition) (refuse (json-refusal-detail condition))))))
                 (unless (= 1 (length values))
                   (refuse (if (zerop (length values))
                               "the text ends where a value belongs"
                               "text after the value")))
                 (aref values 0)))))
    (unless (and (hash-table-p raw) (json-array-p (gethash "entries" raw)))
      (fail "omp-re: carry: not a verification manifest (no `entries` array) — pass the <report>.manifest.json written by /re report <path>"))
    (make-carry-manifest
     :binary-sha256 (jstring raw "binarySha256")
     :entries
     (loop for row across (gethash "entries" raw)
           when (and (hash-table-p row) (jstring row "evidenceId"))
             collect (multiple-value-bind (read why) (evidence-rerun row)
                       (make-manifest-entry
                        :evidence-id (jstring row "evidenceId")
                        :tool (or (jstring row "tool") "unknown")
                        :read read
                        :unrunnable why
                        :command (jstring row "command")
                        :repro-hash (jstring row "reproHash")
                        :canonical-excerpt (jstring row "canonicalExcerpt")
                        :shift-hash (jstring row "shiftHash")
                        :anchor (parse-anchor (gethash "anchor" row))
                        :binary-sha256 (jstring row "binarySha256")
                        :claims (jstrings row "claims"))))
     :findings
     (let ((findings (gethash "findings" raw)))
       (loop for row across (if (json-array-p findings) findings #())
             when (and (hash-table-p row) (jstring row "id") (jstring row "claim")
                       (json-array-p (gethash "evidenceIds" row)))
               collect (make-manifest-finding
                        :id (jstring row "id")
                        :claim (jstring row "claim")
                        :evidence-ids (jstrings row "evidenceIds")
                        :addr (jstring row "addr")
                        :confidence (known-confidence (gethash "confidence" row))))))))

;;; --- a diff a person can start from --------------------------------------------------------------

(defun line-diff (before after &optional (key #'identity))
  "A line diff (LCS) of two short texts: an unchanged line begins `  ', a
removed one `- ', an added one `+ '. Lines are matched on KEY of the line
and printed as written, so under an address mask a line that only moved
shows as unchanged, in its new form."
  (let* ((a (coerce (if (string= before "") '() (split-lines before)) 'simple-vector))
         (b (coerce (if (string= after "") '() (split-lines after)) 'simple-vector))
         (key-a (map 'simple-vector key a))
         (key-b (map 'simple-vector key b))
         (lcs (make-array (list (1+ (length a)) (1+ (length b))) :initial-element 0))
         (out '())
         (i 0)
         (j 0))
    (loop for i from (1- (length a)) downto 0
          do (loop for j from (1- (length b)) downto 0
                   do (setf (aref lcs i j)
                            (if (string= (aref key-a i) (aref key-b j))
                                (1+ (aref lcs (1+ i) (1+ j)))
                                (max (aref lcs (1+ i) j) (aref lcs i (1+ j)))))))
    (loop while (and (< i (length a)) (< j (length b)))
          do (cond ((string= (aref key-a i) (aref key-b j))
                    (push (format nil "  ~a" (aref b j)) out)
                    (incf i)
                    (incf j))
                   ((>= (aref lcs (1+ i) j) (aref lcs i (1+ j)))
                    (push (format nil "- ~a" (aref a i)) out)
                    (incf i))
                   (t
                    (push (format nil "+ ~a" (aref b j)) out)
                    (incf j))))
    (loop while (< i (length a))
          do (push (format nil "- ~a" (aref a i)) out)
             (incf i))
    (loop while (< j (length b))
          do (push (format nil "+ ~a" (aref b j)) out)
             (incf j))
    (nreverse out)))

(defun compact-diff (diff)
  "DIFF cut to its changed lines and +DIFF-CONTEXT+ unchanged lines around
each, the rest elided as `  …': a hunk view of a LINE-DIFF."
  (let* ((context +diff-context+)
         (diff (coerce diff 'simple-vector))
         (changed (map 'simple-vector (lambda (line) (not (uiop:string-prefix-p "  " line))) diff))
         (out '()))
    (dotimes (i (length diff) (nreverse out))
      (cond ((find t changed :start (max 0 (- i context)) :end (min (length diff) (+ i context 1)))
             (push (aref diff i) out))
            ((not (equal (first out) "  …"))
             (push "  …" out))))))

;;; --- classifying the evidence -----------------------------------------------------------------------

(defun carry-row (entry status detail &key command relocation rerun diff)
  "One evidence row of a carry: a JSON object, since `--out' writes the
rows as they stand. COMMAND is the exact line re-run, or that would have
been. RELOCATION is set when the anchor was found again elsewhere by its
fingerprint: where it was and is, as `from' and `to' for a reader and
member by member for --inherit to follow; RERUN, on a row that reproduced, is the {command, addr} that
did — what --inherit runs to record fresh evidence; DIFF, on a drifted row,
is the recorded excerpt against the new one."
  (obj "evidenceId" (manifest-entry-evidence-id entry)
       "tool" (manifest-entry-tool entry)
       "command" (or command :absent)
       "status" status
       "detail" detail
       "relocation" (or relocation :absent)
       "rerun" (or rerun :absent)
       "diff" (if diff (coerce diff 'simple-vector) :absent)))

(defun compare-output (entry output binary-path)
  "Whether a re-run's OUTPUT still says what ENTRY recorded => the words for
how it holds, or NIL when it really changed. The exact canonical hash, or —
when the manifest carries one — the address-masked hash, which forgives a
rebuild that only moved code."
  (cond ((equal (canonical-hash output binary-path) (manifest-entry-repro-hash entry))
         "output identical")
        ((and (plusp (length (manifest-entry-shift-hash entry)))
              (equal (shift-hash output binary-path) (manifest-entry-shift-hash entry)))
         "output identical apart from shifted addresses")))

(defun excerpt-diff (recorded-excerpt output binary-path)
  "The line diff of RECORDED-EXCERPT against OUTPUT's own excerpt, capped;
NIL when the two say the same — the change then lies further down."
  (let ((new-excerpt (canonical-excerpt output binary-path)))
    (unless (string= recorded-excerpt new-excerpt)
      ;; An excerpt that hit its cap ends mid-line, at a different column on
      ;; each side; that partial line is dropped so it never shows as a change.
      (flet ((whole (excerpt)
               (if (>= (length excerpt) +excerpt-characters+)
                   (subseq excerpt 0 (or (position #\Newline excerpt :from-end t) 0))
                   excerpt)))
        (let ((diff (line-diff (whole recorded-excerpt) (whole new-excerpt) #'mask-addresses)))
          (when (notevery (lambda (line) (uiop:string-prefix-p "  " line)) diff)
            (if (> (length diff) +max-diff-lines+)
                (append (subseq diff 0 +max-diff-lines+)
                        (list (format nil "  … ~d more diff line(s)" (- (length diff) +max-diff-lines+))))
                diff)))))))

(defun try-relocated (rz entry request fingerprint binary-path)
  "Find the anchor's function in this build by FINGERPRINT and re-run the
command there => a row — relocated when the output then matches, drifted
with the relocation noted and a diff when it does not — or NIL when nothing
matches the fingerprint or the relocated line may not run. The new
function's name is folded back to the recorded one before comparing, so a
pure rename compares equal."
  (let* ((found (relocate-anchor rz fingerprint))
         (line (and found
                    (handler-case (gate-read (jstring request "command") (jstring found "addr"))
                      (re-error () nil)))))
    (when line
      (let* ((output (run-gated-line line))
             (old-name (jstring fingerprint "function"))
             (new-name (jstring found "function"))
             (old-offset (jstring fingerprint "offset"))
             (new-offset (jstring found "offset"))
             (renamed (string/= new-name old-name))
             (moved (string/= (normalize-addr new-offset) (normalize-addr old-offset)))
             (folded (if renamed (replace-all output new-name old-name) output))
             (similarity (js-number (gethash "similarity" found)))
             (relocation (obj "from" (format nil "~a @ ~a" old-name old-offset)
                              "to" (format nil "~a @ ~a" new-name new-offset)
                              "fromName" old-name "fromOffset" old-offset
                              "toName" new-name "toOffset" new-offset
                              "addr" (jstring found "addr")
                              "similarity" (gethash "similarity" found)))
             (where (format nil "~a ~a (code similarity ~a)" old-name
                            (cond ((and renamed moved) (format nil "moved to ~a @ ~a" new-name new-offset))
                                  (renamed (format nil "renamed to ~a" new-name))
                                  (moved (format nil "moved from ~a to ~a" old-offset new-offset))
                                  (t (format nil "found at ~a" new-offset)))
                            similarity))
             (same (compare-output entry folded binary-path)))
        (if same
            (carry-row entry "relocated" (format nil "~a; ~a" where same)
                       :command line :relocation relocation
                       :rerun (obj "command" (jstring request "command") "addr" (jstring found "addr")))
            (let ((diff (excerpt-diff (or (manifest-entry-canonical-excerpt entry) "") folded binary-path)))
              (carry-row entry "drifted"
                         (format nil "~a; output changed~:[ beyond the recorded ~d-line excerpt~;~]"
                                 where diff +excerpt-lines+)
                         :command line :relocation relocation :diff diff)))))))

(defun carry-entry (entry binary-path)
  "Re-run ENTRY on the open binary and classify it => a row. Never signals:
whatever goes wrong with one entry leaves that entry unchecked (the engine's
trouble) or broken (the anchor is gone)."
  (let* ((request (manifest-entry-read entry))
         (command (jstring request "command"))
         (addr (jstring request "addr"))
         (fingerprint (manifest-entry-anchor entry))
         (recorded-excerpt (or (manifest-entry-canonical-excerpt entry) ""))
         (line nil))
    (when (null request)
      (return-from carry-entry
        (carry-row entry "unchecked" (rerun-refusal (manifest-entry-unrunnable entry))
                   :command (manifest-entry-command entry))))
    (handler-case
        (setf line (gate-read command addr))
      (error (condition)
        (return-from carry-entry
          (carry-row entry "unchecked" (format nil "not runnable here: ~a" condition) :command command))))
    (handler-case
        (let ((rz (ensure-rizin))
              ;; A numeric anchor always "resolves", so it is judged by its
              ;; output, and relocated by fingerprint when that output changed.
              (numeric (and addr (number-text-p addr))))
          (flet ((relocated ()
                   (and fingerprint (try-relocated rz entry request fingerprint binary-path))))
            ;; A symbolic anchor (sym.decrypt_config, a flag) that no longer
            ;; resolves means the thing the claim is about is gone under that
            ;; name. With a fingerprint it may only have been renamed, so it
            ;; is looked for before it is called broken.
            (when (and addr (not numeric)
                       (not (ignore-errors (resolve-numeric-addr rz addr))))
              (return-from carry-entry
                (or (relocated)
                    (carry-row entry "broken"
                               (format nil "anchor `~a` no longer resolves in this binary~:[~; and no function matching its fingerprint was found~]"
                                       addr fingerprint)
                               :command line))))
            (multiple-value-bind (output stderr) (run-gated-line line)
              (when (blank-p output)
                (let ((errors (clean-stderr stderr)))
                  (when (or (plusp (length errors)) (not (blank-p recorded-excerpt)))
                    (return-from carry-entry
                      (or (and numeric (relocated))
                          (carry-row entry "broken"
                                     (format nil "command now produces no output~@[: ~a~]"
                                             (and (plusp (length errors))
                                                  (car (last (split-lines errors)))))
                                     :command line))))))
              (let ((same (compare-output entry output binary-path)))
                (when same
                  (return-from carry-entry
                    (carry-row entry "holds" same :command line :rerun request))))
              ;; Drifted at a numeric anchor: the code it named may simply have
              ;; moved. The drift is kept only if that code is found nowhere else.
              (when numeric
                (let ((moved (relocated)))
                  (when (and moved (not (equal (jstring moved "relocation" "addr") (normalize-addr addr))))
                    (return-from carry-entry moved))))
              (let ((diff (excerpt-diff recorded-excerpt output binary-path)))
                (carry-row entry "drifted"
                           (format nil "~a~@[; ~a~]"
                                   (if diff
                                       "output changed"
                                       (format nil "output changed beyond the recorded ~d-line excerpt (re-run to see it)"
                                               +excerpt-lines+))
                                   (and numeric
                                        (format nil "pinned to numeric address ~a~:[ — the code it named may have moved in this build~;; no function matching its fingerprint was found elsewhere~]"
                                                addr fingerprint)))
                           :command line :diff diff)))))
      (error (condition)
        (carry-row entry "unchecked" (format nil "re-run failed: ~a" condition) :command line)))))

(defparameter +carry-rank+
  '(("unchecked" . 0) ("holds" . 1) ("relocated" . 2) ("drifted" . 3) ("broken" . 4)))

(defun carry-rank (status)
  (cdr (assoc status +carry-rank+ :test #'string=)))

(defun roll-up-claims (manifest evidence)
  "The EVIDENCE rows' statuses rolled up to MANIFEST's claims: the worst
checked status wins, and a claim with nothing checked stays unchecked.
Claims come in the order the manifest first names them."
  (let ((claims '()))                   ; (text . ids), first seen first
    (dolist (entry (carry-manifest-entries manifest))
      (dolist (text (manifest-entry-claims entry))
        (let ((held (assoc text claims :test #'string=)))
          (cond ((null held)
                 (setf claims (append claims (list (list text (manifest-entry-evidence-id entry))))))
                ((not (member (manifest-entry-evidence-id entry) (cdr held) :test #'string=))
                 (setf (cdr held) (append (cdr held) (list (manifest-entry-evidence-id entry)))))))))
    (mapcar (lambda (claim)
              (let ((status "unchecked"))
                (dolist (id (cdr claim))
                  (let* ((row (find id evidence :key (lambda (row) (jstring row "evidenceId"))
                                                :test #'string= :from-end t))
                         (said (if row (jstring row "status") "unchecked")))
                    (when (> (carry-rank said) (carry-rank status)) (setf status said))))
                (obj "text" (car claim) "status" status
                     "evidenceIds" (coerce (cdr claim) 'simple-vector))))
            claims)))

(defun build-carry (manifest &optional (session *session*))
  "Re-run every reproducible entry of MANIFEST against the binary open now
=> the carry's result, a JSON object: the two binaries' hashes, the path
carried onto, a row for each distinct piece of evidence and one for each claim."
  (let ((binary-path (or (session-binary-path session)
                         (fail "omp-re: carry: no binary open — /re open <the new build> first, or pass --against <path>")))
        (seen '())
        (evidence '()))
    (dolist (entry (carry-manifest-entries manifest))
      (unless (member (manifest-entry-evidence-id entry) seen :test #'string=)
        (push (manifest-entry-evidence-id entry) seen)
        (push (carry-entry entry binary-path) evidence)))
    (setf evidence (nreverse evidence))
    (obj "fromSha256" (or (carry-manifest-binary-sha256 manifest) :null)
         "toSha256" (or (session-binary-sha256 session)
                        (ignore-errors (sha256-file binary-path))
                        :null)
         "toPath" binary-path
         "evidence" (coerce evidence 'simple-vector)
         "claims" (coerce (roll-up-claims manifest evidence) 'simple-vector))))

;;; --- saying it ----------------------------------------------------------------------------------------

(defun carry-count (status rows)
  (count status rows :key (lambda (row) (jstring row "status")) :test #'string=))

(defun short-sha (sha)
  (if (plusp (length sha))
      (format nil "~a…" (shown-hash sha))
      "unknown"))

(defun format-carry-summary (result)
  "The one-line summary and a line for each claim, those that do not hold first."
  (let ((claims (jlist result "claims"))
        (from (jstring result "fromSha256"))
        (to (jstring result "toSha256")))
    (join-lines
     (append
      (list (format nil "omp-re: carry ~a → ~a — ~d hold, ~d relocated, ~d drifted, ~d BROKEN, ~d unchecked (of ~d claim(s))"
                    (short-sha from) (short-sha to)
                    (carry-count "holds" claims) (carry-count "relocated" claims)
                    (carry-count "drifted" claims) (carry-count "broken" claims)
                    (carry-count "unchecked" claims) (length claims)))
      (when (and (plusp (length from)) (equal from to))
        (list "  (same binary the report was written against — this is /re verify; open the new build to carry onto it)"))
      (loop for status in '("broken" "drifted" "unchecked" "relocated" "holds")
            append (loop for claim in claims
                         when (string= status (jstring claim "status"))
                           collect (format nil "  ~9a ~a" (string-upcase status) (jstring claim "text"))))))))

(defun format-carry-markdown (result manifest-path)
  "The whole carry as markdown: the claim matrix, then each piece of
evidence with what became of it and, where it drifted, the diff."
  (let* ((claims (jlist result "claims"))
         (evidence (jlist result "evidence"))
         (lines '()))
    (flet ((say (&rest more) (dolist (line more) (push line lines)))
           (cell (text)
             (replace-all (replace-all text "|" "\\|") (string #\Newline) " "))
           (status-of (id)
             (let ((row (find id evidence :key (lambda (row) (jstring row "evidenceId"))
                                          :test #'string= :from-end t)))
               (if row (jstring row "status") "unchecked"))))
      (say "# Carry Report"
           ""
           (format nil "- **Manifest:** `~a`" manifest-path)
           (format nil "- **From binary:** `~a`" (or (jstring result "fromSha256") "unknown"))
           (format nil "- **To binary:** `~a`~@[ (~a)~]" (or (jstring result "toSha256") "unknown")
                   (let ((path (jstring result "toPath"))) (and (plusp (length path)) path)))
           (format nil "- **Claims:** ~d hold · ~d relocated · ~d drifted · ~d broken · ~d unchecked"
                   (carry-count "holds" claims) (carry-count "relocated" claims)
                   (carry-count "drifted" claims) (carry-count "broken" claims)
                   (carry-count "unchecked" claims))
           ""
           "## Claims"
           ""
           "| Status | Claim | Evidence |"
           "| --- | --- | --- |")
      (dolist (claim claims)
        (say (format nil "| ~a | ~a | ~{~a~^, ~} |" (jstring claim "status") (cell (jstring claim "text"))
                     (mapcar (lambda (id) (format nil "`~a` ~a" (shown-id id) (status-of id)))
                             (jlist claim "evidenceIds")))))
      (say "" "## Evidence" "")
      (dolist (row evidence)
        (say (format nil "### `~a` — ~a" (shown-id (jstring row "evidenceId")) (jstring row "status"))
             ""
             (format nil "- **Tool:** ~a" (jstring row "tool")))
        (when (plusp (length (jstring row "command")))
          (say (format nil "- **Command:** `~a`" (jstring row "command"))))
        (let ((relocation (jget row "relocation")))
          (when relocation
            (say (format nil "- **Relocated:** ~a → ~a (similarity ~a)"
                         (jstring relocation "from") (jstring relocation "to")
                         (js-number (gethash "similarity" relocation))))))
        (say (format nil "- **Detail:** ~a" (jstring row "detail")) "")
        (when (jlist row "diff")
          (say "```diff")
          (apply #'say (compact-diff (jlist row "diff")))
          (say "```" ""))))
    (join-lines (nreverse lines))))

;;; --- --inherit: this build's starting point -----------------------------------------------------------

(defun follow-relocation (addr relocation)
  "ADDR mapped through RELOCATION: the old function's name becomes the new
name, its old start the new start; anything else is left where it was (NIL)."
  (let ((to-name (jstring relocation "toName")))
    (cond ((and (equal addr (jstring relocation "fromName")) (plusp (length to-name))) to-name)
          ((string= (normalize-addr addr) (normalize-addr (jstring relocation "fromOffset")))
           (jstring relocation "toOffset")))))

(defun inherit-findings (manifest result &optional (session *session*))
  "Turn the carry into this build's starting point => the outcome object.
For each finding of MANIFEST whose claim holds or relocated, every evidence
row that reproduced is read again as a rizin_command call and so recorded
as fresh evidence bound to THIS binary — never copied from the manifest —
and the finding is recorded citing only that evidence, with where
it came from. A finding with nothing reproduced, or one that drifted or
broke, goes on the agenda instead. A claim already live here is not
inherited twice."
  (let ((claims (jlist result "claims"))
        (rows (jlist result "evidence"))
        (present (mapcar (lambda (finding) (jstring finding "claim")) (live-findings session)))
        (inherited '())
        (agenda '())
        (already-present 0))
    (dolist (finding (carry-manifest-findings manifest))
      (let* ((claim (manifest-finding-claim finding))
             (claim-row (find claim claims :key (lambda (row) (jstring row "text"))
                                           :test #'string= :from-end t))
             (status (if claim-row (jstring claim-row "status") "unchecked"))
             (cited (loop for id in (manifest-finding-evidence-ids finding)
                          for row = (find id rows :key (lambda (row) (jstring row "evidenceId"))
                                                  :test #'string= :from-end t)
                          when row collect row))
             (reproduced (remove-if-not (lambda (row)
                                          (and (member (jstring row "status") '("holds" "relocated")
                                                       :test #'string=)
                                               (jget row "rerun")))
                                        cited)))
        (flet ((put-on-agenda (status)
                 (push (obj "fromId" (manifest-finding-id finding) "claim" claim "status" status
                            "rows" (coerce cited 'simple-vector))
                       agenda)))
          (cond
            ((member claim present :test #'string=) (incf already-present))
            ((or (not (member status '("holds" "relocated") :test #'string=)) (null reproduced))
             (put-on-agenda status))
            (t
             (let ((new-evidence
                     (loop for row in reproduced
                           for rerun = (jget row "rerun")
                           for id = (nth-value 1 (observe-read (jstring rerun "command")
                                                               (jstring rerun "addr") session))
                           when id collect id)))
               (if (null new-evidence)
                   (put-on-agenda "unchecked")
                   ;; An address the finding was about follows its evidence's
                   ;; anchor when that anchor relocated.
                   (let* ((relocation (some (lambda (row) (jget row "relocation")) reproduced))
                          (addr (manifest-finding-addr finding))
                          (followed (and relocation (plusp (length addr))
                                         (follow-relocation addr relocation)))
                          (id (record-finding
                               :claim claim
                               :evidence-ids new-evidence
                               :addr (or followed addr)
                               :confidence (manifest-finding-confidence finding)
                               :audit (obj "verdict" "inherited"
                                           "reason" "re-verified by /re carry; the report's support audit re-checks it")
                               :inherited
                               (obj "fromBinarySha256" (or (carry-manifest-binary-sha256 manifest) :null)
                                    "fromFindingId" (manifest-finding-id finding)
                                    "carryStatus" status
                                    "relocation" (if relocation
                                                     (obj "from" (jstring relocation "from")
                                                          "to" (jstring relocation "to")
                                                          "similarity" (gethash "similarity" relocation))
                                                     :absent))
                               :session session)))
                     (push claim present)
                     (push (obj "fromId" (manifest-finding-id finding) "toId" id "claim" claim "status" status)
                           inherited)))))))))
    (obj "inherited" (coerce (nreverse inherited) 'simple-vector)
         "agenda" (coerce (nreverse agenda) 'simple-vector)
         "alreadyPresent" already-present)))

(defun format-agenda-prompt (outcome to-sha256)
  "The agenda as a prompt for the model: each finding that no longer holds
as written, with what became of its evidence under it."
  (join-lines
   (append
    (list (format nil "These findings from the earlier report do not carry over unchanged to this build~@[ (`~a…`)~]. For each one, re-examine it with the RE tools, then record_finding a revised claim on fresh evidence, or leave it out if it no longer stands:"
                  (and (plusp (length to-sha256)) (shown-hash to-sha256)))
          "")
    (loop for item in (jlist outcome "agenda")
          for number from 1
          append (cons (format nil "~d. [~a] ~a" number (jstring item "status") (jstring item "claim"))
                       (loop for row in (jlist item "rows")
                             append (cons (format nil "   - evidence ~a~@[ `~a`~]: ~a — ~a"
                                                  (shown-id (jstring row "evidenceId"))
                                                  (let ((command (jstring row "command")))
                                                    (and (plusp (length command)) command))
                                                  (jstring row "status") (jstring row "detail"))
                                          (when (jlist row "diff")
                                            (append (list "     ```diff")
                                                    (mapcar (lambda (line) (format nil "     ~a" line))
                                                            (compact-diff (jlist row "diff")))
                                                    (list "     ```"))))))))))

;;; --- /re carry ----------------------------------------------------------------------------------------

(defun read-manifest-file (path)
  "The text of the manifest at PATH — the user's own path — or a refusal
that names it."
  (let ((file (session-file path)))
    (or (and (not (uiop:directory-exists-p (uiop:ensure-directory-pathname file)))
             (read-text-file file))
        (fail "omp-re: carry: could not read manifest ~a: ~a" path
              (cond ((uiop:directory-exists-p (uiop:ensure-directory-pathname file)) "it is a directory")
                    ((not (uiop:file-exists-p file)) "no such file")
                    (t "the file cannot be read"))))))

(defun carry-manifest-file (manifest-path &key strict out inherit resolve (session *session*))
  "Carry the manifest at MANIFEST-PATH onto the open binary and say what
became of its claims => (values TEXT FAILED-P REPLY), REPLY what
else a /re line's answer carries (DEFINE-SLASH). A broken claim fails; under
STRICT so does a relocated, drifted or unchecked one. OUT also writes the
markdown carry report and, beside it, `<out>.json' with the whole result.
INHERIT re-proves the manifest's findings here.

What is left to re-examine is an agenda for the model. Where an operator is
watching it is offered as a draft, or with RESOLVE asked to be sent as
their next message. Where nobody is, a command cannot start a turn: the
line says so and the agenda follows the summary, to be passed on as the
next prompt."
  (let* ((manifest (parse-manifest (read-manifest-file manifest-path)))
         (result (build-carry manifest session))
         (claims (jlist result "claims"))
         (failed (or (plusp (carry-count "broken" claims))
                     (and strict
                          (or (plusp (carry-count "relocated" claims))
                              (plusp (carry-count "drifted" claims))
                              (plusp (carry-count "unchecked" claims))))))
         (lines (list (format-carry-summary result)))
         (agenda-prompt nil))
    (when inherit
      (let* ((outcome (inherit-findings manifest result session))
             (agenda (length (jlist outcome "agenda")))
             (already-present (gethash "alreadyPresent" outcome)))
        (setf (gethash "inheritance" result) outcome)
        ;; Findings recorded by a line, with no model turn to follow: a host
        ;; that writes a session lazily is asked to write this one now.
        (when (jlist outcome "inherited")
          (handler-case
              (ask-host :keep-session session
                        (format nil "re carry ~a~@[ → ~a~]" (path-basename manifest-path)
                                (and (session-binary-path session)
                                     (path-basename (session-binary-path session)))))
            (re-error (condition)
              (notify :warning "omp-re: carry: the inherited findings are recorded, but ~a" condition))))
        (push (format nil "inherit: ~d finding(s) re-proven on this build and recorded, ~d need another look~[~:;, ~:*~d already present~]~:[~; (this manifest has no findings — record them with record_finding before /re report)~]"
                      (length (jlist outcome "inherited")) agenda already-present
                      (null (carry-manifest-findings manifest)))
              lines)
        (when (plusp agenda)
          (setf agenda-prompt (format-agenda-prompt outcome (jstring result "toSha256"))))))
    (when (plusp (length out))
      (push (handler-case
                (progn
                  (write-user-file out (format-carry-markdown result manifest-path))
                  (write-user-file (format nil "~a.json" out)
                                     (format nil "~a~%" (json-encode result :indent 2)))
                  (format nil "carry report written to ~a (+ ~a.json)" out out))
              (error (condition)
                (format nil "carry report not written: ~a" condition)))
            lines))
    (let* ((watched (ignore-errors (ask-host :has-ui)))
           (resolving (and resolve inherit agenda-prompt))
           (level (cond (failed :error)
                        ((plusp (carry-count "drifted" claims)) :warning)
                        (t :info))))
      (cond ((and resolving watched)
             (push (format nil "resolve: sent ~d finding(s) to the model to re-examine"
                           (length (jlist result "inheritance" "agenda")))
                   lines))
            (resolving
             (push (format nil "resolve: a headless run cannot start a model turn from a command — the agenda for ~d finding(s) follows; pass it to the model as the next prompt~@[ ~a~]"
                           (length (jlist result "inheritance" "agenda")) (voice :next-prompt))
                   lines)))
      (let ((summary (join-lines (reverse lines))))
        (values (if (and agenda-prompt (not watched))
                    (format nil "~a~%~a" summary agenda-prompt)
                    summary)
                (and failed t)
                (append (list :level level)
                        (cond ((and resolving watched) (list :user-message agenda-prompt))
                              ((and agenda-prompt watched)
                               (list :draft (make-draft :text agenda-prompt :notice summary))))))))))

(define-slash "carry" (:usage "<manifest>"
                       :description "replay a report on another build (--against, --inherit, --resolve, --strict, --out)"
                       :order 110)
    (words line)
  (multiple-value-bind (path flags)
      (line-flags line :switches '("--strict" "--inherit" "--resolve") :valued '("--against" "--out"))
    (if (zerop (length path))
        (values "Usage: /re carry <report.md.manifest.json> [--against <binary>] [--inherit | --resolve] [--strict] [--out <path>]"
                t)
        ;; The open says something only when the record had something to
        ;; put back; otherwise the carry's own lines are the answer.
        (multiple-value-bind (opened failures applied)
            (if (getf flags :--against) (open-binary (getf flags :--against)) (values nil 0 0))
          (multiple-value-bind (text failed reply)
              ;; --resolve implies --inherit: re-prove what holds, then hand over the rest.
              (carry-manifest-file path
                                   :strict (getf flags :--strict) :out (getf flags :--out)
                                   :inherit (or (getf flags :--inherit) (getf flags :--resolve))
                                   :resolve (getf flags :--resolve))
            (values (if (plusp (+ failures applied))
                        (format nil "~a~%~a" opened text)
                        text)
                    failed
                    reply))))))
