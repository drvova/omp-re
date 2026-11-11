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

(defun binary-information (session rz)
  "What `ij' and `iej' say of the binary RZ analyzes => (values INFO ENTRY).
They hold for the life of the process, so they are asked once of each."
  (let ((held (session-held session "binary information")))
    (unless (eq (first held) rz)
      (let* ((entries (coerce (or (ignore-errors (rz-cmdj rz "iej")) #()) 'list))
             (program (or (find "program" entries :key (lambda (entry) (jstring entry "type")) :test #'equal)
                          (first entries))))
        (setf held (list rz (ignore-errors (rz-cmdj rz "ij")) (and program (jnumber program "vaddr")))
              (session-held session "binary information") held)))
    (values (second held) (third held))))

(defun session-facts (&optional (session *session*))
  "The facts a status band shows of SESSION's binary =>
  {name, path?, size?, format?, arch?, os?, entry?, prot, fnCount, findings,
   evidence}
Only a rizin that is already running is asked: a band never starts one."
  (let* ((path (session-binary-path session))
         (rz (session-rz session))
         (live (rz-alive-p rz)))
    (multiple-value-bind (info entry) (if live (binary-information session rz) (values nil nil))
      (let ((bin (jget info "bin")))
        (obj "name" (if path (file-namestring path) "no binary")
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
             "fnCount" (if live (function-count rz) 0)
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
                         (format nil "~a (~a)" (file-namestring path) path)
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

(defun offset-of (object)
  "The address a rizin JSON row is at: `addr', or `offset' as older rows say it."
  (or (jnumber object "addr") (jnumber object "offset")))

(defun disassembly-lines (op)
  "One `pdfj' op as its lines: the flags at its address, when it has any,
then the instruction, its comment (base64 in rizin's JSON) and the
references to it folded in after a semicolon."
  (let ((addr (offset-of op)))
    (when addr
      (let* ((flags (jstrings op "flags"))
             (comment (let ((decoded (and (jstring op "comment") (base64-text (jstring op "comment")))))
                        (and decoded (plusp (length (trimmed decoded))) (trimmed decoded))))
             (xrefs (loop for xref in (jlist op "xrefs_to")
                          when (offset-of xref)
                            collect (format nil "~a ~a" (jstring xref "type") (ea-from-offset (offset-of xref)))))
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
  "Said over disassembly shown in place of decompiled code. The re-triage
skill and WATCHDOG.md quote it, so the model and an advisor can tell a
fallback from a decompile.")

(defparameter +decompiler-silent+ "(disassembly only — the decompiler produced no output for this function)")

(defun session-decompiler (session rz)
  "The decompiler command RZ has, OMPRE_DECOMPILER's first, or NIL. rizin
ships none: rz-ghidra (pdg) and jsdec (pdd) are plugins, and a command whose
plugin is not loaded answers its own help with nothing. Asked once of each
process; an answer that could not be had is not kept."
  (let ((held (session-held session "decompiler")))
    (if (eq (car held) rz)
        (cdr held)
        (let ((kind (find-if (lambda (command)
                               (let ((reply (trimmed (rz-cmd rz (format nil "~a?" command)))))
                                 (and (plusp (length reply))
                                      (not (search "does not exist" reply))
                                      (not (uiop:string-prefix-p "ERROR" reply)))))
                             (decompiler-commands))))
          (setf (session-held session "decompiler") (cons rz kind))
          kind))))

(defun decompile-at (session rz ea)
  "The function at EA decompiled => (values KIND CODE): the decompiler
command and its output, or NIL and NIL when no decompiler is loaded or it
said nothing — KIND then being :SILENT for one that is loaded."
  (let ((kind (session-decompiler session rz)))
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
  (loop for row in (coerce (or (rz-cmdj rz (format nil "axtj @ ~a" ea)) #()) 'list)
        for index from 0
        for from = (jnumber row "from")
        when from
          collect (let* ((site (ea-from-offset from))
                         (name (and (< index 64)
                                    (jstring (first (coerce (or (ignore-errors
                                                                 (rz-cmdj rz (format nil "afij @ ~a" site)))
                                                                #())
                                                            'list))
                                             "name")))
                         (label (if name (format nil "~a (~a)" name site) site)))
                    (obj "value" site "label" label "description" (jstring row "type")
                         "enter" (code-request site label depth)))))

(defun references-view (rz ea title depth &key none one)
  "The places that refer to EA as a panel under TITLE; NONE, a view, when
there are none; with ONE, a single reference is shown as its code at once."
  (let ((rows (reference-rows rz ea depth)))
    (cond ((null rows) none)
          ((and one (null (rest rows))) (code-view rz (jstring (first rows) "value") nil depth))
          (t (panel-view title "enter open · esc back" rows)))))

(defun code-view (rz ea name depth)
  (if (> depth +view-depth+)
      (notice-view :info "omp-re: xref chain too deep — stopping to avoid an unbounded loop")
      (let ((disasm (ignore-errors (disassemble-at rz ea)))
            (shown (or name ea)))
        (multiple-value-bind (kind code) (handler-case (decompile-at *session* rz ea)
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

(defun list-view (kind)
  (flet ((rows (command row)
           (loop for item in (coerce (or (rz-cmdj (ensure-rizin) command) #()) 'list)
                 for made = (funcall row item)
                 when made collect made)))
    (cond
      ((string= kind "functions")
       (panel-view "omp-re: functions" "enter open · type to filter · esc close"
                   (rows "aflj"
                         (lambda (function)
                           (let ((addr (offset-of function))
                                 (size (or (jnumber function "realsz") (jnumber function "size"))))
                             (when addr
                               (let ((ea (ea-from-offset addr)))
                                 (obj "value" ea "label" (jstring function "name")
                                      "description" (format nil "~a~@[ · ~db~]" ea size)
                                      "enter" (code-request ea (jstring function "name"))))))))))
      ((string= kind "strings")
       (panel-view "omp-re: strings" "enter open · type to filter · esc close"
                   (rows "izj"
                         (lambda (entry)
                           (when (jnumber entry "vaddr")
                             (let ((ea (ea-from-offset (jnumber entry "vaddr"))))
                               (obj "value" ea "label" (jstring entry "string") "description" ea
                                    "enter" (view-request "string-xrefs" "addr" ea
                                                          "label" (jstring entry "string")))))))))
      ((string= kind "imports")
       (panel-view "omp-re: imports" "enter open · type to filter · esc close"
                   (rows "iij"
                         (lambda (entry)
                           (let ((ea (and (jnumber entry "plt") (plusp (jnumber entry "plt"))
                                          (ea-from-offset (jnumber entry "plt")))))
                             (obj "value" (or ea "") "label" (jstring entry "name")
                                  "description" (or ea "(no PLT)")
                                  "enter" (view-request "import-callers" "addr" (or ea "")
                                                        "name" (jstring entry "name"))))))))
      ((string= kind "evidence")
       (panel-view "omp-re: evidence" "enter cite · type to filter · esc close"
                   (mapcar (lambda (record)
                             (obj "value" (jstring record "id")
                                  "label" (format nil "[~a] ~a @ ~a" (shown-id (jstring record "id"))
                                                  (jstring record "tool") (or (jstring record "ea") "?"))
                                  "description" (let ((line (or (first (split-lines (jstring record "summary"))) "")))
                                                  (subseq line 0 (min 80 (length line))))
                                  "enter" (obj "draft" (format nil "~a~%~%" (cite-text record)))))
                           (evidence-records))))
      ((string= kind "findings")
       (let ((findings (live-findings)))
         (if (null findings)
             (notice-view :info "omp-re: no findings on this branch yet — the model records them with record_finding")
             (panel-view "omp-re: findings" "enter discuss · type to filter · esc close"
                         (mapcar (lambda (finding)
                                   (obj "value" (jstring finding "id")
                                        "label" (format nil "[~a] ~a" (shown-id (jstring finding "id"))
                                                        (jstring finding "claim"))
                                        "description" (format nil "~a~:[~; · inherited~]~@[ · ~a~]"
                                                              (jstring finding "confidence")
                                                              (jget finding "inherited")
                                                              (let ((addr (jstring finding "addr")))
                                                                (and (plusp (length addr)) addr)))
                                        "enter" (obj "draft" (format nil "Re: ~a~%~%" (finding-detail finding)))))
                                 findings))))))))

(defparameter +list-views+ '("functions" "strings" "imports" "evidence" "findings")
  "The lists a host may open by name; each is also a /re subcommand, whose
line answers the same list as text where there is no screen.")

(defun view (kind argument)
  "The view KIND for the JSON object ARGUMENT, in the running session."
  (let ((addr (jstring argument "addr"))
        (depth (or (jnumber argument "depth") 0)))
    (cond
      ((member kind +list-views+ :test #'string=) (list-view kind))
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
