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
;;;; So they are verbs, called from eval like (re:cmd ...), and every read one
;;;; makes — a search that finds nothing included — is a rizin_command call
;;;; in its own right: gated, audited, recorded as evidence.
;;;;
;;;; A recipe is not an oracle and must not read like one. Every section of
;;;; what it answers names the evidence id of the read it rests on, so a line
;;;; here is never a conclusion the model may repeat: it is a pointer to an
;;;; observation the model can open, and a finding still has to cite those
;;;; ids to pass the report gate. The tables — which imports are risky and
;;;; why, which byte strings betray which algorithm — are judgement, and are
;;;; worded as "worth a look", never as a verdict.
;;;;
;;;; skills/re-triage/recipes.js and recipes.py are the same five for the two
;;;; kernels of omp's eval, over tool.rizin_command. All three answer the same
;;;; text for the same binary, reads and all, and test/recipes-eval.test.ts
;;;; holds them to it. What a recipe reads, in which order, how each section
;;;; is worded, its options and their bounds, the tables and every sentence
;;;; are data: recipes/tables.json, which scripts/gen-recipes.ts writes into
;;;; recipe-data.lisp (and says the meaning of). This file keeps what Lisp
;;;; forces on it — the bridge for one read, how a number is printed — the
;;;; loop that renders a recipe from that data, and the few facts a section
;;;; needs code for. A change to any of those is a change in the other two.
;;;;
;;;; Composite analyses over a disassembler are common ground (IDA and Ghidra
;;;; scripts, capa, radare2-mcp's analysis tools, which prompted this file);
;;;; the code, tables and wording here are this project's own, written
;;;; against rizin's JSON.

(in-package #:nodecode-re)

(defun table (&rest path)
  "The member of the recipes' data at PATH."
  (apply #'jget *recipe-tables* path))

;;; --- rizin's JSON, as JavaScript would read it ---------------------------------------------

(defun rows (data)
  "A decoded JSON array as a list; anything else as no rows."
  (if (and (vectorp data) (not (stringp data))) (coerce data 'list) '()))

(defun vec (list)
  "LIST as a JSON array, so that an empty one is still a list and not false."
  (coerce list 'simple-vector))

(defun num (object key)
  "The member KEY of OBJECT when it is a number. JavaScript has one number
type, so 4096.0 is 4096 there and prints as it: a whole value is an integer."
  (let ((value (jnumber object key)))
    (if (and (floatp value) (= value (ffloor value)) (< (abs value) 1d21))
        (truncate value)
        value)))

(defun number-text (value)
  (if (integerp value) (format nil "~d" value) (json-encode value)))

(defun hex-text (value)
  (if (integerp value) (ea-from-offset value) (format nil "0x~a" (number-text value))))

(defun fixed-2 (value)
  "VALUE to two decimal places, a half rounded away from zero, as JavaScript's
toFixed(2) rounds the double's exact value."
  (multiple-value-bind (whole hundredths) (floor (floor (+ (* 100 (abs (rational value))) 1/2)) 100)
    (format nil "~:[~;-~]~d.~2,'0d" (minusp value) whole hundredths)))

(defun number-from-text (text)
  "The number a string of digits spells — rizin writes a section's entropy
as one — or NIL."
  (when (js-scan "^[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?$" text)
    (let ((*read-default-float-format* 'double-float)
          (*read-eval* nil))
      (coerce (read-from-string text) 'double-float))))

;;; --- text ----------------------------------------------------------------------------------

(defparameter *space* (map 'list #'code-char (table "whitespace"))
  "White space is the data's list on every host, not each language's own idea of it.")

(defun trim-space (text)
  (string-trim *space* text))

(defun split-words (text)
  (let ((found '()) (start nil))
    (dotimes (index (length text))
      (cond ((member (char text index) *space*)
             (when start (push (subseq text start index) found))
             (setf start nil))
            ((null start) (setf start index))))
    (when start (push (subseq text start) found))
    (nreverse found)))

(defun after-word (text word)
  "TEXT without a leading WORD and the white space after it; as it stands
when it does not open that way."
  (let ((at (length word)))
    (if (and (starts-with word text) (< at (length text)) (member (char text at) *space*))
        (string-left-trim *space* (subseq text at))
        text)))

(defun one-line (text)
  (let ((text (substitute #\Space #\Newline text)))
    (subseq text 0 (min (table "limits" "lineWidth") (length text)))))

(defun take (count list)
  (if count (subseq list 0 (min count (length list))) list))

(defun unique-first (list &key (key #'identity))
  "Without duplicates, keeping each value where it first stood."
  (remove-duplicates list :key key :test #'equal :from-end t))

(defun unique-last (list &key (key #'identity))
  "Without duplicates, keeping each value where it last stood."
  (remove-duplicates list :key key :test #'equal))

(defun bounded (value default least most)
  "VALUE when it is an integer within LEAST..MOST, the nearer bound when it
is outside, DEFAULT when it was not given."
  (if (integerp value) (max least (min most value)) default))

;;; --- a template, filled --------------------------------------------------------------------

;;; scripts/gen-recipes.ts says what a template may hold; what it writes into
;;; the tables is walked here.

(defun fact (facts name)
  (let ((value (gethash name facts)))
    (if (eq value :null) nil value)))

(defun lookup (path facts row)
  "What PATH names: a fact, or (when it opens with \".\") ROW, and then
members of it."
  (let ((value (if (string= "." (aref path 0)) row facts)))
    (loop for index from 1 below (length path)
          do (setf value (jget value (aref path index))))
    (if (eq value :null) nil value)))

(defun there (value)
  (or (eq value t) (and (rows value) t)))

(defun size (value)
  (cond ((realp value) value)
        (t (length (rows value)))))

(defun formatted (as value)
  "VALUE in the format AS, or :MISSING when it is not what the format takes."
  (flet ((when-number (text) (if (realp value) (funcall text value) :missing))
         (when-string (text) (if (stringp value) (funcall text value) :missing)))
    (cond ((string= as "text") (when-string #'identity))
          ((string= as "d") (when-number #'number-text))
          ((string= as "x") (when-number #'hex-text))
          ((string= as "f2") (when-number #'fixed-2))
          ((string= as "line") (when-string #'one-line))
          ((string= as "json") (json-encode value)))))

(defun template-piece (node facts row)
  (flet ((at (key) (lookup (gethash key node) facts row)))
    (cond ((stringp node) node)
          ((gethash "group" node)
           (let ((inner (fill-template (gethash "group" node) facts row)))
             (if (eq inner :missing) "" inner)))
          ((or (gethash "if" node) (gethash "unless" node))
           (let* ((wanted (and (gethash "if" node) t))
                  (value (at (if wanted "if" "unless")))
                  (holds (if (nth-value 1 (gethash "is" node))
                             (equal value (gethash "is" node))
                             (there value))))
             (if (eq (and holds t) wanted) "" :missing)))
          ((gethash "choose" node) (gethash (if (there (at "choose")) "yes" "no") node))
          ;; How a line names the read it rests on; nothing when the read left no record.
          ((gethash "cite" node)
           (let ((id (at "cite")))
             (if (stringp id) (format nil "[evidence ~a]" id) "")))
          ((gethash "count" node) (format nil "~d" (length (rows (at "count")))))
          ((gethash "join" node)
           (with-output-to-string (out)
             (loop for (item . more) on (rows (at "join"))
                   do (write-string item out)
                      (when more (write-string (gethash "with" node) out)))))
          ((gethash "plural" node) (gethash (if (eql 1 (size (at "plural"))) "one" "many") node))
          (t
           (let ((text (or (loop for path across (gethash "get" node)
                                 for text = (formatted (gethash "as" node) (lookup path facts row))
                                 unless (eq text :missing) return text)
                           (gethash "or" node))))
             (cond ((null text) :missing)
                   ((gethash "padLeft" node) (format nil "~v@a" (gethash "padLeft" node) text))
                   ((gethash "padRight" node) (format nil "~va" (gethash "padRight" node) text))
                   (t text)))))))

(defun fill-template (nodes facts row)
  "A template's text, or :MISSING when something it needs is not there."
  (with-output-to-string (out)
    (loop for node across nodes
          for part = (template-piece node facts row)
          do (when (eq part :missing) (return-from fill-template :missing))
             (write-string part out))))

(defun written (nodes facts &optional row)
  "A template as the lines it adds: one, or none when it cannot be written
or comes out empty."
  (let ((text (fill-template nodes facts row)))
    (if (or (eq text :missing) (string= text "")) '() (list text))))

(defun section-lines (section facts &optional row)
  "The lines of one section."
  (flet ((each (key function) (loop for item across (gethash key section) append (funcall function item)))
         (one (key) (and (gethash key section) (written (gethash key section) facts row))))
    (when (and (gethash "when" section) (not (there (lookup (gethash "when" section) facts row))))
      (return-from section-lines '()))
    (append
     (one "title")
     (each "lines" (lambda (line) (written line facts row)))
     (when (gethash "rows" section)
       (let* ((all (rows (lookup (gethash "rows" section) facts row)))
              (most (and (gethash "limit" section) (gethash (gethash "limit" section) facts)))
              (total (length all))
              (lines
                (if (gethash "line" section)
                    (progn (setf (gethash "shown" facts) (vec (take most all)))
                           (and all (one "line")))
                    (let ((listed (loop for item in all
                                        for text = (written (gethash "row" section) facts item)
                                        when text collect (cons item (first text)))))
                      (setf total (length listed))
                      (loop for (item . text) in (take most listed)
                            append (cons text (each "under" (lambda (inner) (section-lines inner facts item)))))))))
         (append lines
                 (and (zerop total) (one "empty"))
                 ;; So a short list is never read as a whole one.
                 (and (gethash "more" section) most (> total most)
                      (written (table "text" "more") (obj "hidden" (- total most) "what" (gethash "more" section)))))))
     (each "after" (lambda (line) (written line facts row))))))

(defun refuse (name facts)
  (fail "~a" (fill-template (table "text" "refusals" name) facts nil)))

;;; --- one observation -------------------------------------------------------------------

(defvar *recipe-evidence* nil
  "While a recipe runs: the {label, id} of each read it made, newest first.")

(defun observe (command &optional addr)
  "One rizin_command call — the same gate, audit line and evidence record as
any other — answering its whole output => (values RAW EVIDENCE-ID). RAW is
\"\" when rizin printed nothing; a refused or failed read is RE-ERROR."
  (multiple-value-bind (text failed raw)
      (call-tool-in-session "rizin_command" (obj "command" command "addr" (or addr :absent)))
    (when failed (fail "~a" text))
    (let ((id (evidence-id-of text)))
      (when id
        (push (obj "label" (if addr (format nil "~a @ ~a" command addr) command) "id" id) *recipe-evidence*))
      (values (or raw "") id))))

(defun observe-json (command &optional addr)
  "OBSERVE for a *j command => (values DATA EVIDENCE-ID), DATA being NIL when
the output was empty or not JSON."
  (multiple-value-bind (raw id) (observe command addr)
    (values (json-parse (trim-space raw)) id)))

;;; --- what an import is called ------------------------------------------------------------

(defun bare-import-name (name)
  "An import's name as the tables spell it: the decorations a linker or a
fortified libc adds are taken off, by the data's rules in their order."
  (let ((name (or name "")))
    (loop for entry across (table "importNameRules")
          for rule = (gethash "rule" entry)
          for text = (gethash "text" entry)
          do (setf name
                   (cond ((string= rule "dropThrough")
                          (let ((at (search text name)))
                            (if at (subseq name (+ at (length text))) name)))
                         ((string= rule "dropPrefix")
                          (if (starts-with text name) (subseq name (length text)) name))
                         ((string= rule "dropLeading")
                          (loop while (starts-with text name)
                                do (setf name (subseq name (length text)))
                                finally (return name)))
                         ((string= rule "dropSuffix")
                          (if (ends-with text name) (subseq name 0 (- (length name) (length text))) name)))))
    name))

(defun names-it (row bare)
  (find bare (gethash "names" row) :test #'string=))

(defun risky-import (bare)
  "The table's row for the risky import BARE, or NIL."
  (find-if (lambda (row) (names-it row bare)) (table "riskyImports")))

(defun import-capabilities (bare)
  (loop for row across (table "capabilities")
        when (names-it row bare) collect (gethash "capability" row)))

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
                for low = (or (num function "offset") (num function "addr"))
                for high = (or (num function "maxbound")
                               (and low (+ low (or (num function "size") 0))))
                when (and low high)
                  collect (list low high (or (jstring function "name") (table "text" "nameless"))))))
  (let ((function (find-if (lambda (row) (and (<= (first row) address) (< address (second row))))
                           *recipe-functions*)))
    (cond ((null function) (hex-text address))
          ((= address (first function)) (third function))
          (t (format nil "~a+~a" (third function) (hex-text (- address (first function))))))))

(defun trace-into (record address)
  "Put into RECORD where ADDRESS is referenced from, each place as
\"function+0xoffset\", with the evidence id of the read: what a row is
traced with."
  (multiple-value-bind (data id) (observe-json "axtj" (hex-text address))
    (setf (gethash "traced" record) t
          (gethash "places" record) (vec (unique-first (loop for row in (rows data)
                                                             for from = (num row "from")
                                                             when from collect (function-containing from))))
          (gethash "@places" record) id)
    record))

;;; --- what a pdfj reply holds ---------------------------------------------------------------

(defun function-ops (body)
  (rows (jget body "ops")))

(defun op-is (op kind)
  (find (jstring op "type") (table "opTypes" kind) :test #'equal))

(defun op-targets (op)
  "Every address an instruction refers to."
  (remove nil (append (list (num op "ptr") (num op "jump"))
                      (mapcar (lambda (reference) (num reference "addr"))
                              (append (jlist op "xrefs_from") (jlist op "refs"))))))

(defun string-references (ops string-data)
  "Each string an instruction of OPS refers to, as (OP TARGET TEXT)."
  (let ((string-at (make-hash-table)))
    (dolist (entry (rows string-data))
      (when (num entry "vaddr")
        (setf (gethash (num entry "vaddr") string-at) (jstring entry "string"))))
    (loop for op in ops
          append (loop for target in (op-targets op)
                       for text = (gethash target string-at)
                       when text collect (list op target text)))))

;;; --- the facts a section needs code for ----------------------------------------------------

;;; Each is a step some recipe names in the data; it leaves the facts the
;;; data's `facts' lists for it.

(defun set-facts (facts &rest names-and-values)
  (loop for (name value) on names-and-values by #'cddr
        do (setf (gethash name facts) value)))

(defun triage-facts (facts)
  (let* ((sections
           (loop for section in (rows (fact facts "sectionData"))
                 for name = (or (jstring section "name") "")
                 for perm = (or (jstring section "perm") "")
                 for given = (jget section "entropy")
                 for entropy = (cond ((realp given) given)
                                     ((stringp given) (number-from-text (trim-space given))))
                 unless (string= "" (trim-space name))
                   ;; What stands out: writable and executable at once, or data that
                   ;; looks compressed or encrypted where code should be.
                   collect (obj "section" section
                                "entropy" (or entropy :absent)
                                "notes" (vec (append
                                              (when (and (find #\w perm) (find #\x perm))
                                                (list (table "sectionNotes" "writableExecutable")))
                                              (cond ((null entropy) nil)
                                                    ((>= entropy (table "thresholds" "veryHighEntropy"))
                                                     (list (table "sectionNotes" "veryHighEntropy")))
                                                    ((and (>= entropy (table "thresholds" "highEntropyForCode")) (find #\x perm))
                                                     (list (table "sectionNotes" "highEntropyForCode"))))
                                              (when (js-scan (table "packerSectionNames") name)
                                                (list (table "sectionNotes" "packerName"))))))))
         (imports (rows (fact facts "imports")))
         (bare (mapcar (lambda (import) (bare-import-name (jstring import "name"))) imports))
         (strings (rows (fact facts "strings"))))
    (set-facts facts
               "sections" (vec sections)
               "flagged" (vec (remove-if (lambda (section) (zerop (length (gethash "notes" section)))) sections))
               "reach" (vec (unique-first (loop for name in bare append (import-capabilities name))))
               "riskyShown" (vec (take (table "limits" "triageRiskyImports") (unique-last (remove-if-not #'risky-import bare))))
               "fewImports" (and (< (length imports) (table "thresholds" "fewImports"))
                                 (not (eq t (jget (fact facts "info") "static"))))
               "notable" (vec (loop for interest across (table "stringInterest")
                                    append (loop for entry in strings
                                                 when (js-scan (gethash "pattern" interest) (or (jstring entry "string") ""))
                                                   collect (obj "kind" (gethash "kind" interest) "entry" entry))))
               ;; Largest first; functions of one size stay in rizin's order.
               "functions" (vec (stable-sort (rows (fact facts "functionData")) #'>
                                             :key (lambda (function)
                                                    (or (num function "realsz") (num function "size") 0)))))))

(defun scan-imports-facts (facts)
  (let* ((named (loop for entry in (rows (fact facts "imports"))
                      collect (cons entry (bare-import-name (jstring entry "name")))))
         (risky (stable-sort (loop for (entry . bare) in named
                                   for verdict = (risky-import bare)
                                   when verdict collect (list entry bare verdict))
                             #'< :key (lambda (found)
                                        (position (gethash "severity" (third found)) (table "severityOrder")
                                                  :test #'string=)))))
    (set-facts facts
               "reach" (vec (loop for row across (table "capabilities")
                                  for linked = (unique-last (loop for (nil . bare) in named
                                                                  when (names-it row bare) collect bare))
                                  when linked
                                    collect (obj "capability" (gethash "capability" row) "names" (vec linked))))
               "risky" (vec (loop for (entry bare verdict) in risky
                                  for plt = (num entry "plt")
                                  ;; An import rizin gives no name is its own bare name: nothing to say it was linked as.
                                  for linked = (or (jstring entry "name") bare)
                                  for row = (obj "severity" (gethash "severity" verdict)
                                                 "category" (gethash "category" verdict)
                                                 "why" (gethash "why" verdict)
                                                 "bare" bare
                                                 "linkedAs" (if (string= linked bare) :absent linked)
                                                 "plt" (or plt :absent))
                                  collect (if (and (fact facts "callers") plt) (trace-into row plt) row))))))

(defun the-function (facts)
  (let ((info (first (rows (fact facts "infoData")))))
    (unless (hash-table-p info) (refuse "noFunction" facts))
    (set-facts facts "info" info)))

(defun inspect-function-facts (facts)
  (let* ((info (fact facts "info"))
         (ops (function-ops (fact facts "body")))
         (variables (fact facts "variables"))
         (traced (trace-into (obj) (or (num info "offset") (num info "addr") 0))))
    (set-facts facts
               "callers" (gethash "places" traced)
               "@callers" (gethash "@places" traced)
               "ops" (vec ops)
               "calls" (vec (unique-first (loop for op in ops
                                                when (op-is op "call")
                                                  collect (after-word (or (jstring op "disasm") "") (table "calleeAfter")))))
               "compares" (count-if (lambda (op) (op-is op "compare")) ops)
               "branches" (count-if (lambda (op) (op-is op "branch")) ops)
               "variableCount" (if (hash-table-p variables)
                                   (loop for kind being the hash-values of variables sum (length (rows kind)))
                                   0)
               "referenced" (vec (unique-last (loop for (nil target text) in (string-references ops (fact facts "strings"))
                                                    collect (obj "address" target "text" text))
                                              :key (lambda (reference) (gethash "address" reference)))))))

(defun function-body (facts)
  (let ((ops (function-ops (fact facts "body"))))
    (unless ops (refuse "noInstructions" facts))
    (set-facts facts "ops" (vec ops))))

(defun branch-meaning (mnemonic)
  (let ((row (find-if (lambda (row) (find mnemonic (gethash "mnemonics" row) :test #'string=))
                      (table "branchMeanings"))))
    (if row (gethash "meaning" row) (table "otherBranch"))))

(defun find-comparisons-facts (facts)
  (let ((ops (rows (fact facts "ops"))))
    (set-facts facts
               "decisions"
               (vec (loop for (op following) on ops
                          ;; The branch that follows it, when one does: which way it goes is the mnemonic's to say.
                          for next = (and (op-is following "branch") following)
                          ;; A compare against a printable character says which: a run of
                          ;; these is a string compared a byte at a time.
                          for value = (or (num op "val") (num op "ptr"))
                          when (op-is op "compare")
                            collect (obj "op" op
                                         "printable" (if (and (integerp value) (<= 32 value 126))
                                                         (format nil "~:[~;\\~]~c" (find (code-char value) "\"\\") (code-char value))
                                                         :absent)
                                         "next" (or next :absent)
                                         "meaning" (if next
                                                       (branch-meaning (string-downcase (or (first (split-words (or (jstring next "disasm") ""))) "")))
                                                       :absent))))
               "decidingCalls"
               (vec (remove-if-not (lambda (op)
                                     (and (op-is op "decidingCall")
                                          (js-scan (table "comparingCalls") (or (jstring op "disasm") ""))))
                                   ops))
               "onTheWay"
               (vec (unique-last (loop for (op target text) in (string-references ops (fact facts "strings"))
                                       collect (obj "offset" (or (num op "offset") 0) "target" target "text" text))
                                 :key (lambda (reference)
                                        (cons (gethash "offset" reference) (gethash "target" reference))))))))

(defun find-crypto-facts (facts)
  (let ((hits (loop for constant across (table "cryptoConstants")
                    for hex = (gethash "hex" constant)
                    ;; Each search is a read on the record whether or not it finds anything; only a hit is reported.
                    append (multiple-value-bind (data id) (observe-json (format nil "/xj ~a" hex))
                             (loop for row in (rows data)
                                   for address = (or (num row "address") (num row "offset") (num row "addr"))
                                   when address
                                     collect (obj "algorithm" (gethash "algorithm" constant)
                                                  "what" (gethash "what" constant)
                                                  "address" address
                                                  "@hit" (or id :absent)
                                                  ;; So few bytes occur by chance: a hit means little on its own.
                                                  "weak" (<= (length hex) (table "thresholds" "shortConstantHexDigits"))))))))
    (when (fact facts "references")
      (dolist (hit (take (table "limits" "cryptoHits") hits))
        (trace-into hit (gethash "address" hit))))
    (set-facts facts "hits" (vec hits))))

(defparameter *fact-steps*
  '(("triage" . triage-facts)
    ("scanImports" . scan-imports-facts)
    ("theFunction" . the-function)
    ("inspectFunction" . inspect-function-facts)
    ("functionBody" . function-body)
    ("findComparisons" . find-comparisons-facts)
    ("findCrypto" . find-crypto-facts))
  "The steps the data calls `derive', by name.")

;;; --- one recipe, from the data ---------------------------------------------------------------

(defun run-recipe (name addr given)
  "The recipe NAME run as the data spells it: its options settled from GIVEN
(an alist by option name), its steps taken in order — a read, or a fact
worked out above — and its title and sections filled from what those left,
over the list of the reads it took, so every line can be traced and cited.
It runs with the session's lock held, so the reads are one sequence no other
call cuts into."
  (let ((recipe (find name (table "recipes") :key (lambda (recipe) (gethash "name" recipe)) :test #'string=))
        (facts (obj "recipe" name "listFunctions" (table "host" "listFunctions"))))
    (maphash (lambda (limit value) (setf (gethash limit facts) value)) (table "limits"))
    (when (gethash "takes" recipe)
      ;; The engine judges what may follow `@' on every read, so only what it
      ;; cannot be asked is refused here.
      (unless (stringp addr)
        (setf (gethash "given" facts)
              (cond ((null addr) "null") ((realp addr) (number-text addr)) (t (prin1-to-string addr))))
        (refuse "notAString" facts))
      (setf (gethash "addr" facts) addr))
    (loop for option across (gethash "options" recipe)
          for value = (cdr (assoc (gethash "name" option) given :test #'string=))
          do (setf (gethash (gethash "name" option) facts)
                   (if (gethash "flag" option)
                       (not (member value '(nil :false)))
                       (bounded value (gethash "default" option) (gethash "least" option) (gethash "most" option)))))
    (with-session ((current-session))
      (let ((*recipe-evidence* '())
            (*recipe-functions* :unread))
        (loop for step across (gethash "steps" recipe)
              do (if (gethash "derive" step)
                     (funcall (cdr (assoc (gethash "derive" step) *fact-steps* :test #'string=)) facts)
                     (multiple-value-bind (data id)
                         (observe-json (gethash "command" step) (and (gethash "at" step) addr))
                       (set-facts facts (gethash "read" step) data
                                  (format nil "@~a" (gethash "read" step)) id))))
        (join-lines
         (append (written (gethash "title" recipe) facts)
                 (loop for section across (gethash "sections" recipe)
                       append (cons "" (section-lines section facts)))
                 (list "" (table "text" "evidenceTaken"))
                 (loop for read in (reverse *recipe-evidence*)
                       append (written (table "text" "evidenceRow") facts read))))))))

(defmacro define-recipes ()
  "A verb for each recipe in the data, with the options it lists as keywords."
  (flet ((name (text) (intern text '#:nodecode-re)))
    `(progn
       ,@(loop for recipe across (jget *recipe-tables* "recipes")
               for options = (coerce (gethash "options" recipe) 'list)
               for takes = (gethash "takes" recipe)
               collect `(define-verb ,(name (gethash "call" recipe))
                            (,@(and takes '(addr))
                             &key ,@(loop for option in options
                                          for key = (name (gethash "key" option))
                                          collect (if (gethash "flag" option) `(,key t) key)))
                          ,(gethash "doc" recipe)
                          (run-recipe ,(gethash "name" recipe) ,(and takes 'addr)
                                      (list ,@(loop for option in options
                                                    collect `(cons ,(gethash "name" option)
                                                                   ,(name (gethash "key" option)))))))))))

(define-recipes)
