;;;; audit-claims.lisp --- does the cited evidence support what the claim says?
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The third grounding gate, after the two deterministic ones (existence: a
;;;; claim with no evidence id withholds the report; reproducibility: the
;;;; repro hash and /re verify). Those prove a claim is cited and
;;;; reproducible; this one asks what they cannot: whether the cited evidence
;;;; actually supports the claim, or the claim is a misattribution or an
;;;; overreach.
;;;;
;;;; The judge is a side question put to the model: no tools, no history
;;;; written. There is no structured-output path for it, so the prompt asks
;;;; for JSON in prose and the reply is parsed defensively — a fenced block,
;;;; then a balanced scan. Everything here is model-agnostic given the
;;;; host's :JUDGE service (host.lisp), which a test installs its own. The
;;;; operator's `audit' setting switches the question off: claims then go
;;;; unaudited, as they do under a host with nobody to ask.
;;;;
;;;; Fail-open by design: whenever the side question cannot be asked or its
;;;; reply cannot be read, the audit degrades to "unaudited" and never blocks
;;;; or weakens the two deterministic gates. In strict mode only an explicit
;;;; unsupported or overreach verdict withholds — a failure of the machinery
;;;; never fails closed, so a strict report stays emittable.

(in-package #:omp-re)

(defparameter +no-judge-reason+ "no model / side turns unavailable"
  "Why claims went unaudited when there is no judge to ask.")

(defparameter +no-verdict-reason+ "the audit side turn returned no usable verdict"
  "Why claims went unaudited when the judge was asked and nothing usable came back.")

(defparameter +excerpt-max+ 800
  "The most of one piece of evidence's output quoted to the judge.")

(defparameter +real-verdicts+ '("supported" "unsupported" "overreach")
  "The verdicts a judge may give; anything else it says reads as unaudited.")

(defstruct (audit-item (:copier nil))
  ;; The claim's flat position across the whole report (sections in order,
  ;; claims in order): the key verdicts are matched back on.
  (index 0)
  (claim-text "" :type string)
  ;; Objects with the members id, tool, summary and, when there is one,
  ;; canonicalExcerpt and fullText.
  (evidence '()))

(defstruct (claim-audit (:copier nil))
  (index 0)
  (verdict "unaudited" :type string)
  (reason "" :type string))

(defstruct (audit-outcome (:copier nil))
  (audited nil)
  (unaudited-reason nil)
  ;; The verdicts: in the judge's own order, then the claims it left out.
  (by-index '())
  ;; How many evidence-backed claims were put to the audit. None means
  ;; there was nothing to audit, and no note is rendered.
  (item-count 0))

(defun outcome-verdict (outcome index)
  (find index (audit-outcome-by-index outcome) :key #'claim-audit-index :test #'=))

(defun flagged-p (audit)
  (and (member (claim-audit-verdict audit) '("unsupported" "overreach") :test #'string=) t))

;;; --- the prompt ---------------------------------------------------------------------------------

(defun build-audit-prompt (items)
  "The adversarial per-claim prompt: one batched question over all the
evidence-backed claims. JSON is asked for in prose because a side question
has no structured-output path."
  (let ((lines (list "You are a strict reverse-engineering report auditor. For EACH numbered claim below, judge ONLY whether the quoted evidence actually supports what the claim asserts. Judge solely against the quoted evidence — do not use outside knowledge, and do not run or imagine any tools."
                     "Verdicts: \"supported\" = the evidence directly establishes the claim; \"overreach\" = the evidence is related but the claim asserts more than the evidence shows (stronger, broader, or attributive); \"unsupported\" = the evidence does not establish the claim (misattribution or wrong evidence)."
                     "Reply with ONLY a JSON array, one object per claim, and no prose outside it:"
                     "[{\"index\": <int>, \"verdict\": \"supported|unsupported|overreach\", \"reason\": \"<=1 line\"}]"
                     "")))
    (flet ((say (control &rest arguments)
             (setf lines (append lines (list (apply #'format nil control arguments))))))
      (dolist (item items)
        (say "CLAIM ~a: ~a" (audit-item-index item) (audit-item-claim-text item))
        (when (null (audit-item-evidence item))
          (say "  (no evidence quoted)"))
        (dolist (evidence (audit-item-evidence item))
          (say "  evidence [~a:~a] summary: ~a"
               (jget evidence "tool") (shown-id (jstring evidence "id")) (jget evidence "summary"))
          ;; The excerpt when one was recorded — an empty one included,
          ;; which then quotes nothing — else the output itself.
          (let ((excerpt (or (jstring evidence "canonicalExcerpt") (jstring evidence "fullText"))))
            (when (plusp (length excerpt))
              (say "    output: ~a"
                   (if (<= (length excerpt) +excerpt-max+)
                       excerpt
                       (format nil "~a…" (subseq excerpt 0 +excerpt-max+)))))))))
    (join-lines lines)))

;;; --- the reply ----------------------------------------------------------------------------------

(defun extract-json (text)
  "The JSON array or object in the free-text reply TEXT: a fenced block
first, else a balanced structure from the first `[' or `{'. NIL when there
is none."
  (let ((fenced (nth-value 1 (ppcre:scan-to-strings "(?i)```(?:json)?\\s*([\\s\\S]*?)```" text))))
    (when (and fenced (plusp (length (aref fenced 0))))
      (return-from extract-json (trimmed (aref fenced 0)))))
  (let* ((bracket (position #\[ text))
         (brace (position #\{ text))
         (start (cond ((null bracket) brace)
                      ((null brace) bracket)
                      (t (min bracket brace)))))
    (when start
      (let* ((opener (char text start))
             (closer (if (char= opener #\[) #\] #\}))
             (depth 0)
             (in-string nil)
             (escaped nil))
        (loop for i from start below (length text)
              for c = (char text i)
              do (cond (in-string
                        (cond (escaped (setf escaped nil))
                              ((char= c #\\) (setf escaped t))
                              ((char= c #\") (setf in-string nil))))
                       ((char= c #\") (setf in-string t))
                       ((char= c opener) (incf depth))
                       ((and (char= c closer) (zerop (decf depth)))
                        (return (subseq text start (1+ i))))))))))

(defun parse-audit-reply (reply-text)
  "The judge's free-text reply as verdicts => (values VERDICTS T), or
(values NIL NIL) when it does not parse or is not an array: degrade, never
signal. A row with no numeric index is passed over; a verdict the engine
does not know reads as unaudited."
  (let* ((raw (extract-json reply-text))
         (parsed (and raw (ignore-errors (json-decode raw)))))
    (if (not (json-array-p parsed))
        (values nil nil)
        (values (loop for row across parsed
                      when (and (hash-table-p row) (realp (gethash "index" row)))
                        collect (let ((verdict (gethash "verdict" row))
                                      (reason (gethash "reason" row)))
                                  (make-claim-audit
                                   :index (gethash "index" row)
                                   :verdict (if (and (stringp verdict)
                                                     (member verdict +real-verdicts+ :test #'string=))
                                                verdict
                                                "unaudited")
                                   :reason (if (stringp reason) reason ""))))
                t))))

;;; --- the audit ----------------------------------------------------------------------------------

(defun audit-judge-p ()
  "Whether there is a judge to put a claim to: the operator left audits on
and the host has one."
  (and (setting-value :audit) (host-service :judge) t))

(defun audit-claims (items mode)
  "Put ITEMS to the host's judge and assemble the outcome. MODE \"off\" audits
nothing and says nothing. No items and no judge are unaudited; a judge that
cannot ask, signals or answers nothing readable is unaudited with the
reason. A readable reply is audited, each claim the judge left out marked
unaudited by itself."
  (flet ((unaudited (reason)
           (make-audit-outcome :audited nil :unaudited-reason reason :item-count (length items))))
    (cond
      ((equal mode "off") (make-audit-outcome))
      ((not (audit-judge-p)) (unaudited +no-judge-reason+))
      ((null items) (unaudited nil))
      (t
        (multiple-value-bind (reply why)
            (handler-case (ask-host :judge (build-audit-prompt items))
              (error () (values nil +no-verdict-reason+)))
          (if (not (stringp reply))
              (unaudited (if (plusp (length why)) why +no-judge-reason+))
              (multiple-value-bind (verdicts parsed) (parse-audit-reply reply)
                (if (not parsed)
                    (unaudited +no-verdict-reason+)
                    (let ((by-index '()))
                      ;; A second verdict for an index takes the first one's place.
                      (dolist (verdict verdicts)
                        (let ((held (member (claim-audit-index verdict) by-index
                                            :key #'claim-audit-index :test #'=)))
                          (if held
                              (setf (car held) verdict)
                              (setf by-index (append by-index (list verdict))))))
                      (dolist (item items)
                        (unless (find (audit-item-index item) by-index :key #'claim-audit-index :test #'=)
                          (setf by-index
                                (append by-index
                                        (list (make-claim-audit :index (audit-item-index item)
                                                                :verdict "unaudited"
                                                                :reason "not returned by the auditor"))))))
                      (make-audit-outcome :audited t :by-index by-index
                                          :item-count (length items)))))))))))

(defun flagged-verdicts (outcome)
  "The claims a strict audit must withhold on: an explicit unsupported or
overreach verdict — never an unaudited one; strict fails open."
  (remove-if-not #'flagged-p (audit-outcome-by-index outcome)))
