;;;; recipes.lisp --- wide reads composed over the one read tool: triage,
;;;; imports, one function, comparisons, cryptographic constants.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; These are not tools. rizin_command is the one way to read the binary and
;;;; eval is where reads are composed; a recipe is that composition, written
;;;; once: the dozen reads every analysis opens with and a plain reading of
;;;; them — which protections the build has, which sections look packed,
;;;; which imports give the program its reach, where the big functions are.
;;;; So they are verbs, called from eval like (re:cmd ...), and each read one
;;;; makes is a rizin_command call in its own right: gated, audited, recorded
;;;; as evidence. skills/re-triage/recipes.js is the same five for omp's
;;;; eval, over tool.rizin_command; the tables both read are generated from
;;;; recipes/tables.json (recipe-data.lisp), and a test holds the two
;;;; outputs to each other.
;;;;
;;;; A recipe is not an oracle and must not read like one. Every section of
;;;; what it answers names the evidence id of the read it rests on, so a line
;;;; here is never a conclusion the model may repeat: it is a pointer to an
;;;; observation the model can open, and a finding still has to cite those
;;;; ids to pass the report gate. The tables — which imports are risky and
;;;; why, which byte strings betray which algorithm — are judgement, and are
;;;; worded as "worth a look", never as a verdict.
;;;;
;;;; Composite analyses over a disassembler are common ground (IDA and Ghidra
;;;; scripts, capa, radare2-mcp's analysis tools, which prompted this file);
;;;; the code, tables and wording here are this project's own, written
;;;; against rizin's JSON.

(in-package #:nodecode-re)

;;; --- one observation -------------------------------------------------------------------

(defvar *recipe-evidence* nil
  "While a recipe runs: the (LABEL . EVIDENCE-ID) of each read it made, newest first.")

(defun observe (command &optional addr)
  "One rizin_command call — the same gate, audit line and evidence record as
any other — answering its whole output => (values RAW EVIDENCE-ID). RAW is
\"\" when rizin printed nothing; a refused or failed read is RE-ERROR."
  (multiple-value-bind (text failed raw)
      (call-tool-in-session "rizin_command" (obj "command" command "addr" (or addr :absent)))
    (when failed (fail "~a" text))
    (let ((id (evidence-id-of text)))
      (when id
        (push (cons (if addr (format nil "~a @ ~a" command addr) command) id) *recipe-evidence*))
      (values (or raw "") id))))

(defun observe-json (command &optional addr)
  "OBSERVE for a *j command => (values DATA EVIDENCE-ID), DATA being NIL when
the output was empty or not JSON."
  (multiple-value-bind (raw id) (observe command addr)
    (values (json-parse (trimmed raw)) id)))

(defun cite (id)
  "How a line names the read it rests on; nothing when the read left no record."
  (if id (format nil "[evidence ~a]" id) ""))

(defun rows (data)
  "A decoded JSON array as a list; anything else as no rows."
  (if (and (vectorp data) (not (stringp data))) (coerce data 'list) '()))

(defun take (count list)
  (subseq list 0 (min count (length list))))

(defun more-line (shown total what)
  "The line that says a list was cut, so a short list is never read as a whole one."
  (when (> total shown)
    (list (format nil "  … ~d more ~a not shown" (- total shown) what))))

(defun recipe-text (title sections)
  "TITLE over SECTIONS — lists of lines — and the reads the recipe took, so
every line can be traced and cited."
  (join-lines
   (append (list title)
           (loop for section in sections append (cons "" section))
           (list "" "Evidence taken (cite these in record_finding; each is a rizin_command read you can re-run):")
           (loop for (label . id) in (reverse *recipe-evidence*)
                 collect (format nil "  ~a  ~a" id label)))))

(defmacro define-recipe (name lambda-list documentation &body body)
  "A verb that composes reads for the running turn's session: BODY runs with
the session's lock held, so the reads are one sequence no other call cuts
into, and answers the recipe's text."
  `(define-verb ,name ,lambda-list ,documentation
     (with-session ((current-session))
       (let ((*recipe-evidence* '())
             (*recipe-functions* :unread))
         (require-binary)
         ,@body))))

(defun bounded (value default least most)
  "VALUE when it is an integer within LEAST..MOST, the nearer bound when it
is outside, DEFAULT when it was not given."
  (if (integerp value) (max least (min most value)) default))

;;; --- what an import is called ------------------------------------------------------------

(defun bare-import-name (name)
  "An import's name as the tables spell it: decorations a linker or a
fortified libc adds are taken off, so __strcpy_chk, _strcpy and
__isoc99_scanf read as strcpy, strcpy and scanf."
  (let* ((name (or name ""))
         (name (let ((at (search "imp." name)))
                 (if at (subseq name (+ at 4)) name)))
         (name (if (starts-with "__isoc99_" name) (subseq name 9) name))
         (name (string-left-trim "_" name))
         (name (if (ends-with "_chk" name) (subseq name 0 (- (length name) 4)) name)))
    name))

(defun risky-import (bare)
  "The (CATEGORY SEVERITY WHY) of the risky import BARE, or NIL."
  (loop for (category severity why . names) in *risky-imports*
        when (member bare names :test #'string=)
          return (list category severity why)))

(defun import-capabilities (bare)
  (loop for (capability . names) in *capability-imports*
        when (member bare names :test #'string=) collect capability))

(defvar *recipe-functions* :unread
  "While a recipe runs: the function list, read at most once and only when a
caller has to be named — (LOW HIGH NAME) rows — or :UNREAD.")

(defun function-containing (address)
  "ADDRESS as \"function+0xoffset\" when it lies in a function rizin found,
else as the bare address. The function list is one more read, taken the
first time a name is wanted."
  (when (eq *recipe-functions* :unread)
    (setf *recipe-functions*
          (loop for function in (rows (observe-json "aflj"))
                for low = (or (jnumber function "offset") (jnumber function "addr"))
                for high = (or (jnumber function "maxbound")
                               (and low (+ low (or (jnumber function "size") 0))))
                when (and low high)
                  collect (list low high (jstring function "name")))))
  (let ((function (find-if (lambda (row) (and (<= (first row) address) (< address (second row))))
                           *recipe-functions*)))
    (cond ((null function) (ea-from-offset address))
          ((= address (first function)) (third function))
          (t (format nil "~a+0x~(~x~)" (third function) (- address (first function)))))))

(defun callers-of (address)
  "Where ADDRESS is referenced from, each as \"function+0xoffset\", with the
evidence id of the read => (values PLACES ID)."
  (multiple-value-bind (data id) (observe-json "axtj" (ea-from-offset address))
    (values (remove-duplicates
             (loop for row in (rows data)
                   for from = (jnumber row "from")
                   when from collect (function-containing from))
             :test #'string= :from-end t)
            id)))

;;; --- triage ------------------------------------------------------------------------------

(defun mitigation-lines (info)
  "The build's protections, read from rizin's own fields rather than scraped
from text, each with what its absence would mean."
  (flet ((yes (key) (eq t (jget info key))))
    (let ((relro (or (jstring info "relro") "none")))
      (list (format nil "  stack canary: ~:[NO — a stack overflow reaches the return address unchecked~;yes~]" (yes "canary"))
            (format nil "  NX: ~:[NO — data pages are executable~;yes~]" (yes "nx"))
            (format nil "  PIE: ~:[NO — the image loads at a fixed address~;yes~]" (yes "pie"))
            (format nil "  RELRO: ~a~a" relro
                    (cond ((string= relro "full") "")
                          ((string= relro "partial") " — the GOT stays writable")
                          (t " — the GOT and other relocated data stay writable")))
            (format nil "  fortified libc calls: ~:[no~;yes~]" (yes "fortify_source"))
            (format nil "  stripped: ~:[no~;yes~]   static: ~:[no~;yes~]" (yes "stripped") (yes "static"))))))

(defun section-entropy (section)
  (let ((text (jget section "entropy")))
    (cond ((realp text) text)
          ((stringp text) (ignore-errors (let ((*read-eval* nil)) (float (read-from-string text) 1d0)))))))

(defun section-notes (section)
  "What stands out about SECTION: writable and executable at once, or data
that looks compressed or encrypted where code should be."
  (let ((perm (or (jstring section "perm") ""))
        (entropy (section-entropy section))
        (name (string-downcase (or (jstring section "name") ""))))
    (append (when (and (find #\w perm) (find #\x perm)) (list "writable+executable"))
            (when (and entropy (>= entropy 7.2)) (list "very high entropy (compressed or encrypted data)"))
            (when (and entropy (>= entropy 6.8) (< entropy 7.2) (find #\x perm))
              (list "high entropy for code"))
            (when (js-scan +packer-section-names+ name)
              (list "a name packers use")))))

(define-recipe triage (&key max-strings max-functions)
  "A first look at the open binary, composed from rizin's own reads: what it
is, which protections the build has, its sections with entropy, the imports
that give it reach, the strings worth a first look, its largest functions
and its entry points. MAX-STRINGS (default 25) and MAX-FUNCTIONS (default
15) bound the lists. Every part names the evidence id of the read it rests
on; nothing here is a finding until one is recorded citing those ids."
    (let ((max-strings (bounded max-strings 25 1 200))
          (max-functions (bounded max-functions 15 1 100)))
      (multiple-value-bind (info info-id) (observe-json "iIj")
        (multiple-value-bind (sections sections-id) (observe-json "iSj entropy")
          (multiple-value-bind (imports imports-id) (observe-json "iij")
            (multiple-value-bind (strings strings-id) (observe-json "izj")
              (multiple-value-bind (functions functions-id) (observe-json "aflj")
                (multiple-value-bind (entries entries-id) (observe-json "iej")
                  (let* ((sections (remove-if (lambda (section) (blank-p (jstring section "name"))) (rows sections)))
                         (flagged (remove-if-not #'section-notes sections))
                         (imports (rows imports))
                         (bare (mapcar (lambda (import) (bare-import-name (jstring import "name"))) imports))
                         (risky (remove-duplicates (remove-if-not #'risky-import bare) :test #'string=))
                         (capabilities (remove-duplicates (loop for name in bare append (import-capabilities name))
                                                          :test #'string= :from-end t))
                         (strings (rows strings))
                         (notable (loop for (kind pattern) in *string-interest*
                                        append (loop for entry in strings
                                                     for text = (or (jstring entry "string") "")
                                                     when (js-scan pattern text)
                                                       collect (list kind entry))))
                         (functions (sort (copy-list (rows functions)) #'>
                                          :key (lambda (function)
                                                 (or (jnumber function "realsz") (jnumber function "size") 0)))))
                    (recipe-text
                     (format nil "triage: ~a" (session-binary-path *session*))
                     (list
                      (list (format nil "Identity ~a" (cite info-id))
                            (format nil "  ~a, ~a ~a-bit ~a, ~a~@[, language ~a~]~@[, interpreter ~a~]"
                                    (or (jstring info "class") (jstring info "bintype") "unknown format")
                                    (or (jstring info "arch") "?") (or (jnumber info "bits") "?")
                                    (or (jstring info "endian") "") (or (jstring info "os") "?")
                                    (jstring info "lang") (jstring info "intrp")))
                      (cons (format nil "Build protections ~a" (cite info-id)) (mitigation-lines info))
                      (append
                       (list (format nil "Sections: ~d ~a" (length sections) (cite sections-id)))
                       (loop for section in sections
                             collect (format nil "  ~18a ~4a ~9d bytes  entropy ~:[   ?~;~:*~4,2f~]~@[  <- ~{~a~^; ~}~]"
                                             (jstring section "name") (or (jstring section "perm") "")
                                             (or (jnumber section "size") 0) (section-entropy section)
                                             (section-notes section)))
                       (when flagged
                         (list (format nil "  ~d section~:p stand~:[~;s~] out; high entropy in code, or a section both writable and executable, is what a packed or self-modifying binary looks like — read it before trusting the function list."
                                       (length flagged) (= 1 (length flagged))))))
                      (append
                       (list (format nil "Imports: ~d ~a" (length imports) (cite imports-id)))
                       (if capabilities
                           (list (format nil "  reach, by what it links: ~{~a~^, ~}" capabilities))
                           (list "  none of the capability groups (network, process control, injection, …) is linked"))
                       (when risky
                         (list (format nil "  worth a reviewer's look: ~{~a~^, ~} — scan_imports says why and who calls them"
                                       (take 20 risky))))
                       (when (and (< (length imports) 8) (not (eq t (jget info "static"))))
                         (list "  very few imports for a dynamic binary: resolved at run time, or packed")))
                      (append
                       (list (format nil "Strings: ~d; notable ~d ~a" (length strings) (length notable) (cite strings-id)))
                       (loop for (kind entry) in (take max-strings notable)
                             collect (format nil "  ~11a ~a  ~a" kind
                                             (if (jnumber entry "vaddr") (ea-from-offset (jnumber entry "vaddr")) "?")
                                             (let ((text (substitute #\Space #\Newline (jstring entry "string"))))
                                               (subseq text 0 (min 100 (length text))))))
                       (more-line (min max-strings (length notable)) (length notable) "notable strings"))
                      (append
                       (list (format nil "Functions: ~d; largest by code size ~a" (length functions) (cite functions-id)))
                       (loop for function in (take max-functions functions)
                             collect (format nil "  ~a  ~7d bytes  ~@[~d blocks  ~]~a"
                                             (ea-from-offset (or (jnumber function "offset") (jnumber function "addr") 0))
                                             (or (jnumber function "realsz") (jnumber function "size") 0)
                                             (jnumber function "nbbs") (jstring function "name")))
                       (more-line (min max-functions (length functions)) (length functions) "functions"))
                      (cons (format nil "Entry points ~a" (cite entries-id))
                            (or (loop for entry in (rows entries)
                                      when (jnumber entry "vaddr")
                                        collect (format nil "  ~a  ~a" (ea-from-offset (jnumber entry "vaddr"))
                                                        (or (jstring entry "type") "")))
                                (list "  none reported"))))))))))))))

;;; --- scan_imports ------------------------------------------------------------------------

(define-recipe scan-imports (&key (callers t) max-callers)
  "The imports a reviewer would stop at — unbounded copies, shell and exec
calls, non-literal format sinks, race-prone file calls, weak randomness —
each with why it matters and, unless CALLERS is :FALSE, who calls it (at
most MAX-CALLERS each, default 12); plus what the program can reach, read
off what it links. An import is a lead, not a bug: whether a call is safe is
decided at its call site, which is what the callers are listed for."
    (let ((with-callers (not (member callers '(nil :false))))
          (max-callers (bounded max-callers 12 1 100)))
      (multiple-value-bind (imports imports-id) (observe-json "iij")
        (let* ((imports (rows imports))
               (risky (sort (loop for import in imports
                                  for bare = (bare-import-name (jstring import "name"))
                                  for verdict = (risky-import bare)
                                  when verdict collect (list* import bare verdict))
                            #'< :key (lambda (entry)
                                       (or (position (fourth entry) *severity-order* :test #'string=) 9))))
               (reach (loop for (capability . nil) in *capability-imports*
                            for names = (remove-duplicates
                                         (loop for import in imports
                                               for bare = (bare-import-name (jstring import "name"))
                                               when (member capability (import-capabilities bare) :test #'string=)
                                                 collect bare)
                                         :test #'string=)
                            when names collect (cons capability names))))
          (recipe-text
           (format nil "scan_imports: ~d imports, ~d worth a look" (length imports) (length risky))
           (list
            (cons (format nil "Reach, by what it links ~a" (cite imports-id))
                  (or (loop for (capability . names) in reach
                            collect (format nil "  ~18a ~{~a~^, ~}" capability names))
                      (list "  none of the capability groups is linked")))
            (cons (format nil "Imports worth a reviewer's look ~a" (cite imports-id))
                  (or (loop for (import bare category severity why) in risky
                            for address = (jnumber import "plt")
                            for linked = (jstring import "name")
                            append (cons (format nil "  [~a] ~a~:[ (linked as ~a)~;~*~] (~a)~@[ @ ~a~] — ~a"
                                                 severity bare (string= bare linked) linked category
                                                 (and address (ea-from-offset address)) why)
                                         (when (and with-callers address)
                                           (multiple-value-bind (callers id) (callers-of address)
                                             (append
                                              (list (if callers
                                                        (format nil "      called from ~d place~:p ~a: ~{~a~^, ~}"
                                                                (length callers) (cite id) (take max-callers callers))
                                                        (format nil "      no caller found by analysis ~a" (cite id))))
                                              (more-line (min max-callers (length callers)) (length callers)
                                                         "callers"))))))
                      (list "  none of the imports in the table is linked")))
            (list "An import is a lead. Read each call site (rizin_command pdg or pdf at the caller) before saying what it does.")))))))

;;; --- inspect_function --------------------------------------------------------------------

(defun function-ops (data)
  "The instruction objects of a pdfj reply."
  (rows (jget data "ops")))

(defun op-targets (op)
  "Every address an instruction refers to."
  (remove nil (append (list (jnumber op "ptr") (jnumber op "jump"))
                      (mapcar (lambda (reference) (jnumber reference "addr"))
                              (append (jlist op "xrefs_from") (jlist op "refs"))))))

(define-recipe inspect-function (addr &key max-items)
  "One function, read from every side at once: its size, complexity and
signature, its variables, who calls it and what it calls, and the strings it
refers to — the context to read before its code. ADDR is its address or
name; MAX-ITEMS (default 30) bounds each list. Follow it with
(re:cmd \"pdg\" addr) for the code itself."
    (let* ((addr (validate-addr (if (stringp addr) addr (fail "a function is named by a string, not ~s" addr))))
           (limit (bounded max-items 30 1 300)))
      (multiple-value-bind (info info-id) (observe-json "afij" addr)
        (let ((info (first (rows info))))
          (unless info
            (fail "omp-re: inspect_function: no function at ~a — list them with (re:json \"aflj\"), or define one with define_function"
                  addr))
          (multiple-value-bind (body body-id) (observe-json "pdfj" addr)
            (multiple-value-bind (variables variables-id) (observe-json "afvlj" addr)
              (multiple-value-bind (strings strings-id) (observe-json "izj")
                (multiple-value-bind (callers callers-id)
                    (callers-of (or (jnumber info "offset") (jnumber info "addr") 0))
                  (let* ((ops (function-ops body))
                         (string-at (let ((table (make-hash-table)))
                                      (dolist (entry (rows strings) table)
                                        (when (jnumber entry "vaddr")
                                          (setf (gethash (jnumber entry "vaddr") table) (jstring entry "string"))))))
                         (referenced (remove-duplicates
                                      (loop for op in ops
                                            append (loop for target in (op-targets op)
                                                         for text = (gethash target string-at)
                                                         when text collect (cons target text)))
                                      :key #'car))
                         (calls (remove-duplicates
                                 (loop for op in ops
                                       when (member (jstring op "type") '("call" "ucall" "rcall" "icall" "ccall")
                                                    :test #'equal)
                                         collect (ppcre:regex-replace "^call\\s+" (or (jstring op "disasm") "") ""))
                                 :test #'string= :from-end t))
                         (compares (count-if (lambda (op) (member (jstring op "type") '("cmp" "acmp") :test #'equal)) ops))
                         (branches (count "cjmp" ops :key (lambda (op) (jstring op "type")) :test #'equal))
                         (variable-count (loop for kind being the hash-values of (or variables (obj))
                                               sum (if (vectorp kind) (length kind) 0))))
                    (recipe-text
                     (format nil "inspect_function: ~a" (or (jstring info "name") addr))
                     (list
                      (list (format nil "Shape ~a" (cite info-id))
                            (format nil "  ~a at ~a" (or (jstring info "signature") (jstring info "name") addr)
                                    (ea-from-offset (or (jnumber info "offset") (jnumber info "addr") 0)))
                            (format nil "  ~d bytes of code, ~d basic blocks, ~d edges, cyclomatic complexity ~d, ~d loop~:p"
                                    (or (jnumber info "realsz") (jnumber info "size") 0) (or (jnumber info "nbbs") 0)
                                    (or (jnumber info "edges") 0) (or (jnumber info "cc") 0) (or (jnumber info "loops") 0))
                            (format nil "  calling convention ~a, stack frame ~d bytes~:[~;, does not return~]"
                                    (or (jstring info "calltype") "?") (or (jnumber info "stackframe") 0)
                                    (eq t (jget info "noreturn"))))
                      (list (format nil "Body ~a" (cite body-id))
                            (format nil "  ~d instructions, ~d compare~:p, ~d conditional branch~:*~[es~;~:;es~] — find_comparisons lists them"
                                    (length ops) compares branches))
                      (list (format nil "Variables: ~d ~a" variable-count (cite variables-id)))
                      (append (list (format nil "Called from ~d place~:p ~a" (length callers) (cite callers-id)))
                              (mapcar (lambda (caller) (format nil "  ~a" caller)) (take limit callers))
                              (more-line (min limit (length callers)) (length callers) "callers"))
                      (append (list (format nil "Calls ~d distinct target~:p ~a" (length calls) (cite body-id)))
                              (mapcar (lambda (call) (format nil "  ~a" call)) (take limit calls))
                              (more-line (min limit (length calls)) (length calls) "callees"))
                      (append (list (format nil "Refers to ~d string~:p ~a ~a" (length referenced)
                                            (cite body-id) (cite strings-id)))
                              (loop for (address . text) in (take limit referenced)
                                    collect (format nil "  ~a  ~a" (ea-from-offset address)
                                                    (let ((text (substitute #\Space #\Newline text)))
                                                      (subseq text 0 (min 100 (length text))))))
                              (more-line (min limit (length referenced)) (length referenced) "strings")))))))))))))

;;; --- find_comparisons --------------------------------------------------------------------

(defun branch-meaning (mnemonic)
  "What a conditional jump tests, in words."
  (let ((mnemonic (string-downcase mnemonic)))
    (cond ((member mnemonic '("je" "jz") :test #'string=) "taken when equal / zero")
          ((member mnemonic '("jne" "jnz") :test #'string=) "taken when not equal / not zero")
          ((member mnemonic '("ja" "jnbe") :test #'string=) "taken when above (unsigned >)")
          ((member mnemonic '("jae" "jnb" "jnc") :test #'string=) "taken when above or equal (unsigned >=)")
          ((member mnemonic '("jb" "jc" "jnae") :test #'string=) "taken when below (unsigned <)")
          ((member mnemonic '("jbe" "jna") :test #'string=) "taken when below or equal (unsigned <=)")
          ((member mnemonic '("jg" "jnle") :test #'string=) "taken when greater (signed >)")
          ((member mnemonic '("jge" "jnl") :test #'string=) "taken when greater or equal (signed >=)")
          ((member mnemonic '("jl" "jnge") :test #'string=) "taken when less (signed <)")
          ((member mnemonic '("jle" "jng") :test #'string=) "taken when less or equal (signed <=)")
          ((member mnemonic '("js") :test #'string=) "taken when negative")
          ((member mnemonic '("jns") :test #'string=) "taken when not negative")
          (t "conditional"))))

(defun printable-note (op)
  "When an instruction compares against a constant that is a printable
character, say which: a run of these is a string compared a byte at a time."
  (let ((value (or (jnumber op "val") (jnumber op "ptr"))))
    (and value (integerp value) (<= 32 value 126)
         (format nil " ; ~s" (string (code-char value))))))

(define-recipe find-comparisons (addr &key max-items)
  "What the function at ADDR decides on: every compare or test with the
conditional branch that follows it (which way it goes, and where to), every
call to something that compares or validates, and the strings on the way —
the static skeleton of validation logic, with no emulation and nothing run.
MAX-ITEMS (default 80) bounds the list. It lists what is compared, not what
the comparison means."
    (let ((addr (validate-addr (if (stringp addr) addr (fail "a function is named by a string, not ~s" addr))))
          (limit (bounded max-items 80 1 1000)))
      (multiple-value-bind (body body-id) (observe-json "pdfj" addr)
        (let ((ops (function-ops body)))
          (unless ops
            (fail "omp-re: find_comparisons: no function at ~a — list them with (re:json \"aflj\")" addr))
          (multiple-value-bind (strings strings-id) (observe-json "izj")
            (let* ((string-at (let ((table (make-hash-table)))
                                (dolist (entry (rows strings) table)
                                  (when (jnumber entry "vaddr")
                                    (setf (gethash (jnumber entry "vaddr") table) (jstring entry "string"))))))
                   (decisions
                     (loop for (op next) on ops
                           for type = (jstring op "type")
                           when (member type '("cmp" "acmp") :test #'equal)
                             collect (format nil "  ~a  ~a~@[~a~]~@[  ->  ~a~]"
                                             (ea-from-offset (or (jnumber op "offset") 0))
                                             (or (jstring op "disasm") "")
                                             (printable-note op)
                                             (and next (equal "cjmp" (jstring next "type"))
                                                  (format nil "~a: ~a~@[, to ~a~]~@[, else ~a~]"
                                                          (or (jstring next "disasm") "")
                                                          (branch-meaning (first (words (or (jstring next "disasm") ""))))
                                                          (and (jnumber next "jump") (ea-from-offset (jnumber next "jump")))
                                                          (and (jnumber next "fail") (ea-from-offset (jnumber next "fail"))))))))
                   (deciding-calls
                     (loop for op in ops
                           for disasm = (or (jstring op "disasm") "")
                           when (and (member (jstring op "type") '("call" "ucall" "rcall" "icall") :test #'equal)
                                     (ppcre:scan +comparing-calls+ disasm))
                             collect (format nil "  ~a  ~a" (ea-from-offset (or (jnumber op "offset") 0)) disasm)))
                   (referenced
                     (remove-duplicates
                      (loop for op in ops
                            append (loop for target in (op-targets op)
                                         for text = (gethash target string-at)
                                         when text
                                           collect (format nil "  ~a  refers to ~a  ~a"
                                                           (ea-from-offset (or (jnumber op "offset") 0))
                                                           (ea-from-offset target)
                                                           (let ((text (substitute #\Space #\Newline text)))
                                                             (subseq text 0 (min 100 (length text)))))))
                      :test #'string=)))
              (recipe-text
               (format nil "find_comparisons: ~a" (or (jstring body "name") addr))
               (list
                (append (list (format nil "Compares and the branches that follow: ~d ~a" (length decisions) (cite body-id)))
                        (take limit decisions)
                        (more-line (min limit (length decisions)) (length decisions) "comparisons"))
                (cons (format nil "Calls that compare or validate: ~d ~a" (length deciding-calls) (cite body-id))
                      (or (take limit deciding-calls) (list "  none by name")))
                (cons (format nil "Strings on the way: ~d ~a ~a" (length referenced) (cite body-id) (cite strings-id))
                      (or (take limit referenced) (list "  none")))
                (list "This lists what is compared, not what the comparison means: which branch is the accepting one is for you to read from the code each leads to.")))))))))

;;; --- find_crypto -------------------------------------------------------------------------

(defparameter +short-constant+ 8
  "A constant this many hex digits or fewer is four bytes: common enough by
chance that a hit means little on its own.")

(define-recipe find-crypto (&key (references t))
  "Where cryptographic material lies in the open binary: rizin's own search
for keys and certificates, and a search for the published constants of
common algorithms, each hit with its address and — unless REFERENCES is
:FALSE — what refers to it. A constant's presence says the tables are linked
in, not that they are used, nor on what; a four-byte constant can occur by
chance and is marked weak."
    (let* ((with-references (not (member references '(nil :false))))
           (rz (ensure-rizin))
           (hits '()))
      (multiple-value-bind (material material-id) (observe-json "/cmj")
        (loop for (algorithm what hex) in *crypto-constants*
              for command = (format nil "/xj ~a" hex)
              ;; A miss is the common case and is not worth an evidence record
              ;; each: the search is probed quietly, and only a hit is taken
              ;; as an observation, by running it again through the pipeline.
              do (when (rows (rz-cmdj rz (check-rizin-command (load-catalog) command)))
                   (multiple-value-bind (data id) (observe-json command)
                     (dolist (row (rows data))
                       (let ((address (or (jnumber row "address") (jnumber row "offset") (jnumber row "addr"))))
                         (when address
                           (push (list algorithm what address id (<= (length hex) +short-constant+)) hits)))))))
        (let ((hits (nreverse hits)))
          (recipe-text
           (format nil "find_crypto: ~d constant hit~:p" (length hits))
           (list
            (cons (format nil "rizin's search for keys and certificates ~a" (cite material-id))
                  (or (loop for row in (take 40 (rows material))
                            collect (format nil "  ~a" (json-encode row)))
                      (list "  nothing found")))
            (cons "Published constants"
                  (or (loop for (algorithm what address id weak) in (take 60 hits)
                            append (cons (format nil "  ~a  ~a — ~a ~a~:[~; (weak: four bytes can occur by chance)~]"
                                                 (ea-from-offset address) algorithm what (cite id) weak)
                                         (when with-references
                                           (multiple-value-bind (callers callers-id) (callers-of address)
                                             (list (if callers
                                                       (format nil "      referred to from ~{~a~^, ~} ~a"
                                                               (take 8 callers) (cite callers-id))
                                                       (format nil "      no reference found by analysis ~a — reached by computed address, or unused"
                                                               (cite callers-id))))))))
                      (list "  none of the constants in the table was found")))
            (list "A table's presence shows the algorithm is linked in. What it is used on, and with which key, is in the code that refers to it.")))))))
