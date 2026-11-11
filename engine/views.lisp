;;;; views.lisp --- what an operator's own surface shows: lists, code, the binary's facts.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A host with a screen draws more than text: a band of facts about the
;;;; open binary, lists to pick from (functions, strings, imports, evidence,
;;;; findings), a function's disassembly and decompiled code, the cross
;;;; references to follow from it. What those show is said here, as data, so
;;;; a host draws it and holds no rizin command, no record walk and no text
;;;; of its own. Also here: the lines a host folds into a summary when it
;;;; compacts a conversation, so the model does not lose the session.
;;;;
;;;; Nothing here is evidence. Evidence means the model observed something;
;;;; recording an operator's browsing would let a claim rest on what the
;;;; model never saw.

(in-package #:omp-re)

;;; --- the open binary's facts ---------------------------------------------------------------

;;; A band is drawn beside whatever call holds the session, so it may not
;;; ask rizin anything: the pipe answers one command at a time, and behind a
;;; long one a band would wait minutes. What it shows of the analysis is
;;; kept on the session by the call that changed it.

(defun keep-analysis-facts (session rz)
  "Keep what a band shows of RZ's analysis: what `ij' and `iej' say of the
binary, which holds for the life of the process and is asked once of each,
and how many functions rizin knows now."
  (let* ((held (session-held session "analysis facts"))
         (same (eq (first held) rz))
         (entries (and (not same) (jlist (ignore-errors (rz-cmdj rz "iej")))))
         (program (or (find "program" entries :key (lambda (entry) (jstring entry "type")) :test #'equal)
                      (first entries))))
    (setf (session-held session "analysis facts")
          (list rz
                (if same (second held) (ignore-errors (rz-cmdj rz "ij")))
                (if same (third held) (and program (jnumber program "vaddr")))
                (function-count rz)))))

(contribute "status band" :analyzed #'keep-analysis-facts)

(defun session-facts (&optional (session *session*))
  "The facts a status band shows of SESSION's binary =>
  {name, path?, size?, format?, arch?, os?, entry?, prot, fnCount, findings,
   evidence}
from what the session holds: nothing is asked of rizin, and none is started.
A session whose rizin is not running shows the binary's name and no more."
  (let* ((path (session-binary-path session))
         (rz (session-rz session))
         (held (session-held session "analysis facts"))
         (live (and (rz-alive-p rz) (eq rz (first held)))))
    (destructuring-bind (&optional info entry (functions 0)) (and live (rest held))
      (let ((bin (jget info "bin")))
        (obj "name" (if path (path-basename path) "no binary")
             "path" (or path :absent)
             "size" (or (jnumber info "core" "size") :absent)
             "format" (or (jstring bin "class") :absent)
             "arch" (if (jstring bin "arch")
                        (format nil "~a/~a" (jstring bin "arch") (jget bin "bits"))
                        :absent)
             "os" (or (jstring bin "os") :absent)
             "entry" (if entry (ea-from-offset entry) :absent)
             "prot" (coerce (loop for (member name) in '(("stripped" "stripped") ("static" "static")
                                                          ("pie" "pie") ("nx" "nx") ("canary" "canary"))
                                  when (eq t (jget bin member)) collect name)
                            'simple-vector)
             "fnCount" functions
             "findings" (length (live-findings session))
             "evidence" (length (evidence-records session)))))))

;;; --- what survives a compaction ------------------------------------------------------------

(defparameter +preserved-evidence+ 8
  "How many of the latest evidence records a compaction summary names; the
rest stay in the record.")

(defparameter +preserved-findings+ 24
  "How many findings a compaction summary restates: they are the session's
conclusions, so the cap is generous.")

(defun preserved-lines (&optional (session *session*))
  "The lines to fold into the summary when the host compacts SESSION's
conversation, or NIL when nothing was reverse engineered in it. The record
survives a compaction; the model's memory of which binary is open and what
it established does not."
  (let* ((path (session-binary-path session))
         (evidence (evidence-records session))
         (findings (live-findings session)))
    (when (or path evidence)
      (append
       (list "omp-re reverse-engineering session (preserve — the model must not lose this):"
             (format nil "- Open binary: ~a"
                     (if path
                         (format nil "~a (~a)" (path-basename path) path)
                         "none currently open — reopen with open_binary before using other RE tools"))
             (format nil "- Recorded: ~d evidence item(s), ~d annotation(s) in effect. They persist on the session branch; list them with `/re evidence` and recall one with `/re cite <id>`."
                     (length evidence) (if path (length (live-annotations path session)) 0)))
       (when evidence
         (cons "- Most recent evidence (id · tool · where):"
               (mapcar (lambda (record)
                         (format nil "  · ~a · ~a~@[ @ ~a~]" (shown-id (jstring record "id"))
                                 (jstring record "tool") (jstring record "ea")))
                       (last evidence +preserved-evidence+))))
       (when findings
         (cons (format nil "- Recorded findings (~d; already in the report — revise with record_finding supersedes, withdraw with retract_finding, don't re-record):"
                       (length findings))
               (mapcar (lambda (finding)
                         (format nil "  · ~a [~a~:[~;, inherited~]] ~a~@[ (at ~a)~]"
                                 (shown-id (jstring finding "id")) (jstring finding "confidence")
                                 (jget finding "inherited") (jstring finding "claim")
                                 (let ((addr (jstring finding "addr")))
                                   (and (plusp (length addr)) addr))))
                       (last findings +preserved-findings+))))
       (list "- Every address stated after this must still come from tool output on this branch; do not invent one from the summary.")))))

;;; --- a function's code -----------------------------------------------------------------------

(defun base64-text (text)
  "The UTF-8 text the base64 TEXT spells, or NIL when it is not base64."
  (ignore-errors
   (let ((octets (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
         (bits 0) (count 0))
     (loop for char across (string-right-trim "=" text)
           for value = (or (position char "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                           (error "not base64"))
           do (setf bits (logior (ash bits 6) value))
              (incf count 6)
              (when (>= count 8)
                (decf count 8)
                (vector-push-extend (ldb (byte 8 count) bits) octets)))
     (sb-ext:octets-to-string (coerce octets '(simple-array (unsigned-byte 8) (*)))
                              :external-format '(:utf-8 :replacement #\?)))))

(defun disassembly-lines (op)
  "One `pdfj' op as its lines: the flags at its address, when it has any,
then the instruction, its comment (base64 in rizin's JSON) and the
references to it folded in after a semicolon."
  (let ((addr (row-address op)))
    (when addr
      (let* ((flags (jstrings op "flags"))
             (comment (let ((decoded (and (jstring op "comment") (base64-text (jstring op "comment")))))
                        (and decoded (plusp (length (trimmed decoded))) (trimmed decoded))))
             (xrefs (loop for xref in (jlist op "xrefs_to")
                          when (row-address xref)
                            collect (format nil "~a ~a" (jstring xref "type") (ea-from-offset (row-address xref)))))
             (notes (append (and comment (list comment))
                            (and xrefs (list (format nil "xrefs: ~{~a~^, ~}" xrefs))))))
        (append (and flags (list (format nil "~{~a~^, ~}:" flags)))
                (list (format nil "~a  ~a~@[  ; ~{~a~^ | ~}~]" (ea-from-offset addr) (jstring op "disasm")
                              notes)))))))

(defun disassemble-at (rz ea)
  "The function containing EA as disassembly lines, or NIL when rizin knows
no function there."
  (let ((ops (jlist (rz-cmdj rz (format nil "pdfj @ ~a" ea)) "ops")))
    (mapcan #'disassembly-lines ops)))

(defparameter +decompile-seconds+ 180
  "A real decompile — rz-ghidra's especially — runs far longer than a plain command.")

(defparameter +disassembly-only+ "(disassembly only — no decompiler plugin available)"
  "Said over disassembly shown in place of decompiled code, so nobody reads
a fallback as a decompile.")

(defparameter +decompiler-silent+ "(disassembly only — the decompiler produced no output for this function)")

(defun decompile-at (rz ea)
  "The function at EA decompiled => (values KIND CODE): the decompiler
command and its output, or NIL and NIL when no decompiler is loaded or it
said nothing — KIND then being :SILENT for one that is loaded."
  (let ((kind (first (available-decompilers (load-catalog)))))
    (if kind
        (let ((code (string-left-trim '(#\Newline)
                                      (rz-cmd rz (format nil "~a @ ~a" kind ea) :seconds +decompile-seconds+))))
          (if (blank-p code)
              (values :silent nil)
              (values kind code)))
        (values nil nil))))

;;; --- views -----------------------------------------------------------------------------------
;;; A view is what one screen shows, a JSON object of one of three types:
;;;   {type "panel", title, hint, rows}     a list to pick from; a row is
;;;       {value, label, description?, enter}, ENTER being what choosing it
;;;       does: {draft TEXT} puts TEXT in the operator's input box and closes
;;;       the list; {view {kind, arg}} asks for that view and shows it over
;;;       the list, or, when it answers a notice, says it and closes the list
;;;   {type "code", title, disasm, decompile?, noDecompile, ask, xrefs}
;;;       a function: its disassembly lines; its decompiled code {label,
;;;       note, tone, code, language?} when there is any; what to say when
;;;       there is none; the draft a hand-off to the model starts from; the
;;;       view {kind, arg} of the references to it
;;;   {type "notice", text, level}          nothing to draw, something to say

(defparameter +view-depth+ 8
  "How far a chain of references is followed from view to view.")

(defun notice-view (level control &rest arguments)
  (obj "type" "notice" "text" (apply #'format nil control arguments) "level" (string-downcase level)))

(defun panel-view (title hint rows)
  (obj "type" "panel" "title" title "hint" hint "rows" (coerce rows 'simple-vector)))

(defun view-request (kind &rest members)
  (obj "view" (obj "kind" kind "arg" (apply #'obj members))))

(defun code-request (ea name &optional (depth 0))
  (view-request "code" "addr" ea "name" (or name :absent) "depth" depth))

(defun reference-rows (rz ea depth)
  "A row for each place that refers to EA, named by the function it is in.
rizin's `axtj' names none, so each is asked — for the first 64; past that a
row keeps its bare address."
  (loop for row in (jlist (rz-cmdj rz (format nil "axtj @ ~a" ea)))
        for index from 0
        for from = (jnumber row "from")
        when from
          collect (let* ((site (ea-from-offset from))
                         (name (and (< index 64)
                                    (jstring (ignore-errors (function-row-at rz site)) "name")))
                         (label (if name (format nil "~a (~a)" name site) site)))
                    (obj "value" site "label" label "description" (jstring row "type")
                         "enter" (code-request site label depth)))))

(defun references-view (rz ea title depth &key none one)
  "The places that refer to EA as a panel under TITLE; NONE, a view, when
there are none; with ONE, a single reference is shown as its code at once."
  (let ((rows (reference-rows rz ea depth)))
    (cond ((null rows) none)
          ((and one (null (rest rows))) (code-view rz (jstring (first rows) "value") nil depth))
          (t (panel-view title (voice :references-hint) rows)))))

(defun code-view (rz ea name depth)
  (if (> depth +view-depth+)
      (notice-view :info "omp-re: xref chain too deep — stopping to avoid an unbounded loop")
      (let ((disasm (ignore-errors (disassemble-at rz ea)))
            (shown (or name ea)))
        (multiple-value-bind (kind code) (handler-case (decompile-at rz ea)
                                           (error () (values nil nil)))
          (if (and (null disasm) (null code))
              (notice-view :error "omp-re: no code at ~a" ea)
              (obj "type" "code"
                   "title" shown
                   "disasm" (coerce disasm 'simple-vector)
                   "decompile" (cond (code
                                      (obj "label" "decompile"
                                           "note" (format nil "// decompiled with ~a" kind)
                                           "tone" "dim"
                                           "code" code
                                           "language" "c"))
                                     (disasm
                                      (obj "label" "decompile (disassembly only)"
                                           "note" (if (eq kind :silent) +decompiler-silent+ +disassembly-only+)
                                           "tone" "warning"
                                           "code" (join-lines disasm)))
                                     (t :absent))
                   "noDecompile" "omp-re: no decompiler output for this function"
                   "ask" (format nil "Analyze function ~a at ~a. Use the RE tools to gather evidence first; report only what the evidence supports."
                                 shown ea)
                   "xrefs" (jget (view-request "xrefs" "addr" ea "name" shown "depth" (1+ depth)) "view")))))))

(defun list-view (slash)
  "The list the subcommand SLASH prints, as a panel to pick from."
  (let* ((listing (slash-listing slash))
         (rows (funcall (listing-rows listing))))
    (if (and (null rows) (listing-none listing))
        (notice-view :info "~a" (listing-none listing))
        (panel-view (list-title slash) (format nil (voice :list-hint) (listing-enter listing))
                    (mapcar (lambda (row)
                              (obj "value" (list-row-value row) "label" (list-row-label row)
                                   "description" (or (list-row-description row) :absent)
                                   "enter" (list-row-enter row)))
                            rows)))))

(defun view (kind argument)
  (let ((addr (jstring argument "addr"))
        (depth (or (jnumber argument "depth") 0)))
    (cond
      ((find-list kind) (list-view (find-list kind)))
      ((string= kind "code")
       (code-view (ensure-rizin) (validate-addr addr) (jstring argument "name") depth))
      ((string= kind "xrefs")
       (references-view (ensure-rizin) (validate-addr addr)
                        (format nil "omp-re: xrefs to ~a" (or (jstring argument "name") addr)) depth
                        :none (notice-view :info "omp-re: no xrefs to ~a" addr)))
      ((string= kind "string-xrefs")
       (let ((label (or (jstring argument "label") "")))
         (references-view (ensure-rizin) (validate-addr addr)
                          (format nil "omp-re: xrefs to ~a" (js-string (subseq label 0 (min 40 (length label)))))
                          depth
                          :one t
                          :none (notice-view :info "omp-re: no xrefs to that string"))))
      ((string= kind "import-callers")
       (if (blank-p addr)
           (notice-view :info "omp-re: no PLT stub for that import")
           (let ((rz (ensure-rizin)))
             (references-view rz (validate-addr addr)
                              (format nil "omp-re: callers of ~a" (jstring argument "name")) depth
                              :none (code-view rz addr (jstring argument "name") depth)))))
      (t (fail "omp-re: no view named ~a" (js-string kind))))))
