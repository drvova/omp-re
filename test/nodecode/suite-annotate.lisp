;;;; suite-annotate.lisp --- the annotations: their commands, the fifteen
;;;; tools, /re undo, and the replay into a fresh rizin.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; In the rizin half each tool's change is read back independently, through
;;;; the read verb, so a wrong command template fails here even where a
;;;; tool's own check agreed with it.

(in-package #:omp-re-test)

(defun ann-commands (&rest arguments)
  (apply #'omp-re::annotation-commands arguments))

(defun ann-refused (&rest arguments)
  (refusal (lambda () (apply #'omp-re::annotation-commands arguments))))

(defun ann-entry (customtype data &optional (id (format nil "e~d" (random 1000000))))
  (omp-re:obj "type" "custom" "id" id "customType" customtype "data" data))

(defun ann-record (&rest entries)
  "A session nothing has stored, holding ENTRIES."
  (let ((session (omp-re::make-session :id "annotate-pure")))
    (dolist (entry entries session)
      (vector-push-extend entry (omp-re::session-entries session)))))

;;; --- the commands an annotation is --------------------------------------------------

(suite "annotations: what each kind is in rizin commands")
(check "a rename quotes the name and seeks to the address"
       (equal '("afn 'parse' @ 0x10") (ann-commands "rename_function" "0x10" "parse" "main")))
(check "a variable rename addresses the variable by the name it has"
       (equal '("afvn 'len' 'var_8h' @ 0x10") (ann-commands "rename_variable" "0x10" "len" "var_8h")))
(check "a comment is clear-then-write, and its text is one quoted argument"
       (equal '("CC- @ 0x10" "CC 'x; !id @ 0 ~ | > f `y` $(z) #' @ 0x10")
              (ann-commands "set_comment" "0x10" "x; !id @ 0 ~ | > f `y` $(z) #" "")))
(check "a quote or a backslash in a comment cannot close the quoting"
       (equal '("CC- @ 0x10" "CC 'it\\'s a \\\\ here' @ 0x10")
              (ann-commands "set_comment" "0x10" "it's a \\ here" "")))
(check "an empty comment only clears"
       (equal '("CC- @ 0x10") (ann-commands "set_comment" "0x10" "" "old")))
(check "a comment with a line break is refused"
       (equal "omp-re: invalid text: contains forbidden character"
              (ann-refused "set_comment" "0x10" (format nil "a~%!id") "")))
(check "a prototype is quoted; undoing onto no signature sends nothing"
       (and (equal '("afs 'int f(char *s)' @ 0x10") (ann-commands "set_prototype" "0x10" "int f(char *s)" ""))
            (null (ann-commands "set_prototype" "0x10" "" "int f(void)"))))
(check "a prototype with a command separator is refused"
       (equal "omp-re: invalid sig: forbidden character \";\""
              (ann-refused "set_prototype" "0x10" "int f(void); !id" "")))
(check "a variable type names the variable in its target, and refuses without one"
       (and (equal '("afvt 'buf' 'char *' @ 0x10") (ann-commands "set_variable_type" "0x10" "char *" "int" "buf"))
            (equal "omp-re: set_variable_type annotation is missing the variable name"
                   (ann-refused "set_variable_type" "0x10" "char *" "int"))))
(check "a variable is defined on the stack or in a register, and removed by name"
       (and (equal '("afvs 0x30 buf 'char *' @ 0x10") (ann-commands "define_variable" "0x10" "stack 0x30 char *" "" "buf"))
            (equal '("afvs -8 n @ 0x10") (ann-commands "define_variable" "0x10" "stack -8" "" "n"))
            (equal '("afvr rdi fd 'int' @ 0x10") (ann-commands "define_variable" "0x10" "reg rdi int" "" "fd"))
            (equal '("afv- buf @ 0x10") (ann-commands "define_variable" "0x10" "" "stack 0x30" "buf"))))
(check "a malformed variable definition is refused in words"
       (and (equal "omp-re: invalid stack delta: \"0x30;!id\" — a decimal or 0x-hex offset"
                   (ann-refused "define_variable" "0x10" "stack 0x30;!id" "" "buf"))
            (equal "omp-re: invalid reg: \"rdi;!id\"" (ann-refused "define_variable" "0x10" "reg rdi;!id" "" "buf"))
            (equal "omp-re: invalid variable storage: \"heap\" — stack or reg"
                   (ann-refused "define_variable" "0x10" "heap 8" "" "buf"))
            (equal "omp-re: define_variable needs a location (a stack delta or a register)"
                   (ann-refused "define_variable" "0x10" "stack" "" "buf"))
            (equal "omp-re: define_variable annotation is missing the variable name"
                   (ann-refused "define_variable" "0x10" "stack 8" ""))))
(check "a global is added at the address and deleted by name"
       (and (equal '("avga key 'unsigned int' @ 0x10") (ann-commands "define_global" "0x10" "unsigned int" "" "key"))
            (equal '("avgm key") (ann-commands "define_global" "0x10" "" "int" "key"))))
(check "a function is defined, and undefined on undo"
       (and (equal '("af @ 0x10") (ann-commands "define_function" "0x10" "fcn.00000010" ""))
            (equal '("af- @ 0x10") (ann-commands "define_function" "0x10" "" "fcn.00000010"))))
(check "a calling convention is an identifier"
       (and (equal '("afc ms @ 0x10") (ann-commands "set_calling_convention" "0x10" "ms" "amd64"))
            (equal "omp-re: invalid cc: \"ms;!id\"" (ann-refused "set_calling_convention" "0x10" "ms;!id" "amd64"))))
(check "a flag drops the name that was there and adds the new one; either may be none"
       (and (equal '("f- old.name" "f new_name @ 0x10") (ann-commands "set_flag" "0x10" "new_name" "old.name"))
            (equal '("f new_name @ 0x10") (ann-commands "set_flag" "0x10" "new_name" ""))
            (equal '("f- new_name") (ann-commands "set_flag" "0x10" "" "new_name"))
            (equal "omp-re: invalid flag: \"a b\"" (ann-refused "set_flag" "0x10" "a b" ""))))
(check "an arch hint is aha and/or ahb, and both are deleted on undo"
       (and (equal '("aha arm @ 0x10" "ahb 16 @ 0x10") (ann-commands "set_arch_hint" "0x10" "arch=arm;bits=16" ""))
            (equal '("ahb 32 @ 0x10") (ann-commands "set_arch_hint" "0x10" "bits=32" ""))
            (equal '("aha- @ 0x10" "ahb- @ 0x10") (ann-commands "set_arch_hint" "0x10" "" "arch=arm"))))
(check "a malformed arch hint is refused in words"
       (and (equal "omp-re: invalid arch hint bits: \"17\" — one of 8, 16, 32, 64"
                   (ann-refused "set_arch_hint" "0x10" "bits=17" ""))
            (equal "omp-re: invalid arch hint \"endian=big\" — use arch=<name> and/or bits=<n>"
                   (ann-refused "set_arch_hint" "0x10" "endian=big" ""))
            (equal "omp-re: invalid arch: \"arm !id\"" (ann-refused "set_arch_hint" "0x10" "arch=arm !id" ""))))
(check "each hint kind is its own ah command, deleted by the same letter"
       (and (equal '("ahi h @ 0x10") (ann-commands "set_hint" "0x10" " h " "" "immediate_base"))
            (equal '("aho nop @ 0x10") (ann-commands "set_hint" "0x10" "nop" "" "opcode_type"))
            (equal '("ahs 4 @ 0x10") (ann-commands "set_hint" "0x10" "4" "" "opcode_size"))
            (equal '("ahc 0x4000 @ 0x10") (ann-commands "set_hint" "0x10" "0x4000" "" "jump_target"))
            (equal '("ahr 0x1 @ 0x10") (ann-commands "set_hint" "0x10" "0x1" "" "return_value"))
            (equal '("ahc- @ 0x10") (ann-commands "set_hint" "0x10" "" "0x4000" "jump_target"))))
(check "a malformed hint value is refused before rizin sees it"
       (and (equal "omp-re: invalid immediate_base: \"bogus\" — one of 2, 8, 10, 10u, 16, b, o, h, i, p, S, s"
                   (ann-refused "set_hint" "0x10" "bogus" "" "immediate_base"))
            (equal "omp-re: invalid opcode_type: \"nop; !id\" — a lowercase opcode type such as call, jmp, ret, nop, mov"
                   (ann-refused "set_hint" "0x10" "nop; !id" "" "opcode_type"))
            (equal "omp-re: invalid opcode_size: \"0\" — a positive integer"
                   (ann-refused "set_hint" "0x10" "0" "" "opcode_size"))
            (equal "omp-re: invalid address or expression: \"0x10;!id\""
                   (ann-refused "set_hint" "0x10" "0x10;!id" "" "jump_target"))
            (equal "omp-re: invalid return_value: \"-1\" — a decimal or 0x-hex integer"
                   (ann-refused "set_hint" "0x10" "-1" "" "return_value"))
            (equal "omp-re: unknown hint kind: esil" (ann-refused "set_hint" "0x10" "1" "" "esil"))
            (equal "omp-re: set_hint annotation is missing the hint kind" (ann-refused "set_hint" "0x10" "1" ""))))
(check "data, string and format marks, and their removal"
       (and (equal '("Cd 4 @ 0x10") (ann-commands "set_data" "0x10" "4" ""))
            (equal '("Cd 4 8 @ 0x10") (ann-commands "set_data" "0x10" "4:8" ""))
            (equal '("Cd- @ 0x10") (ann-commands "set_data" "0x10" "" "4"))
            (equal '("Cs @ 0x10") (ann-commands "set_string" "0x10" "auto" ""))
            (equal '("Cs 12 @ 0x10") (ann-commands "set_string" "0x10" "12" ""))
            (equal '("Cs- @ 0x10") (ann-commands "set_string" "0x10" "" "auto"))
            (equal '("Cf 8 xxdd f1 f2 @ 0x10") (ann-commands "set_format" "0x10" "8 xxdd f1 f2" ""))
            (equal '("Cf- @ 0x10") (ann-commands "set_format" "0x10" "" "8 xx"))))
(check "a malformed mark is refused in words"
       (and (equal "omp-re: invalid size: \"4;!id\" — a positive integer" (ann-refused "set_data" "0x10" "4;!id" ""))
            (equal "omp-re: invalid repeat: \"0\" — a positive integer" (ann-refused "set_data" "0x10" "4:0" ""))
            (equal "omp-re: invalid size: \"big\" — a positive integer" (ann-refused "set_string" "0x10" "big" ""))
            (equal "omp-re: invalid pf format: \"xx;!id\"" (ann-refused "set_format" "0x10" "8 xx;!id" ""))
            (equal "omp-re: set_format needs a size and a pf format, e.g. `8 xxdd field1 field2`"
                   (ann-refused "set_format" "0x10" "8" ""))))
(check "an address that could carry a second command is refused for every kind"
       (loop for kind in '("rename_function" "set_comment" "define_function" "set_flag" "set_data")
             always (equal "omp-re: invalid address or expression: \"0x10; !id\""
                           (ann-refused kind "0x10; !id" "x" ""))))
(check "a name or an address ending in a newline does not pass as its own last line"
       (and (equal "omp-re: invalid address or expression: \"main\\n\""
                   (ann-refused "set_comment" (format nil "main~%") "x" ""))
            (equal "omp-re: invalid flag: \"x\\n\"" (ann-refused "set_flag" "0x10" (format nil "x~%") ""))
            (equal "omp-re: invalid cc: \"ms\\n\""
                   (ann-refused "set_calling_convention" "0x10" (format nil "ms~%") "amd64"))))
(check "an unknown kind is refused"
       (equal "omp-re: unknown annotation kind: patch_bytes" (ann-refused "patch_bytes" "0x10" "x" "")))

;;; --- what is in effect ---------------------------------------------------------------

(suite "annotations: what is in effect")
(let* ((first (omp-re:obj "kind" "rename_function" "ea" "0x10" "oldValue" "main" "newValue" "a"))
       (session (ann-record
                 (ann-entry "re.binary" (omp-re:obj "path" "/a") "b1")
                 (ann-entry "re.annotation" first "n1")
                 (ann-entry "re.annotation" (omp-re:obj "kind" "set_comment" "ea" "0x20" "newValue" "c") "n2")
                 (ann-entry "re.binary" (omp-re:obj "path" "/b") "b2")
                 (ann-entry "re.annotation" (omp-re:obj "kind" "set_flag" "ea" "0x30" "oldValue" "" "newValue" "f") "n3")
                 (ann-entry "re.annotation" (omp-re:obj "kind" "nameless") "n4")
                 (ann-entry "re.binary" (omp-re:obj "path" "/a") "b3")
                 (ann-entry "re.annotation" (omp-re:obj "kind" "set_hint" "ea" "0x40" "oldValue" "" "newValue" "16"
                                                     "target" "immediate_base" "evidenceId" "ev" "ungrounded" nil)
                            "n5")
                 (ann-entry "re.undo" (omp-re:obj "undidEntryId" "n2") "u1"))))
  (check "an annotation belongs to the binary opened last before it, across a reopen"
         (and (equal '("0x10" "0x40")
                     (mapcar (lambda (data) (gethash "ea" data)) (omp-re::live-annotations "/a" session)))
              (equal '("0x30") (mapcar (lambda (data) (gethash "ea" data)) (omp-re::live-annotations "/b" session)))
              (null (omp-re::live-annotations "/c" session))))
  (check "an undone annotation is not in effect, and one with no address never was"
         (notany (lambda (data) (member (gethash "ea" data) '("0x20" nil) :test #'equal))
                 (append (omp-re::live-annotations "/a" session) (omp-re::live-annotations "/b" session))))
  (check "the data keeps its fields, with a missing value read as empty"
         (and (string= "{\"kind\":\"set_hint\",\"ea\":\"0x40\",\"oldValue\":\"\",\"newValue\":\"16\",\"target\":\"immediate_base\",\"evidenceId\":\"ev\",\"ungrounded\":false}"
                       (omp-re:json-encode (second (omp-re::live-annotations "/a" session))))
              (string= "{\"kind\":\"rename_function\",\"ea\":\"0x10\",\"oldValue\":\"main\",\"newValue\":\"a\"}"
                       (omp-re:json-encode (first (omp-re::live-annotations "/a" session))))))
  (check "the fingerprint is the ids of the entries in effect"
         (and (string= "n1,n5" (omp-re::annotation-fingerprint session "/a"))
              (string= "n3" (omp-re::annotation-fingerprint session "/b"))
              (string= "" (omp-re::annotation-fingerprint session "/c"))))
  (check "an annotation that no longer applies is a failure line, and does not stop the replay"
         (let ((session (ann-record
                         (ann-entry "re.binary" (omp-re:obj "path" "/a"))
                         (ann-entry "re.annotation" (omp-re:obj "kind" "patch_bytes" "ea" "0x10" "newValue" "90"))
                         (ann-entry "re.annotation" (omp-re:obj "kind" "set_flag" "ea" "0x20" "newValue" "a b")))))
           ;; Both are refused before a command is built, so no process is needed.
           (equal '("patch_bytes @ 0x10: omp-re: unknown annotation kind: patch_bytes"
                    "set_flag @ 0x20: omp-re: invalid flag: \"a b\"")
                  (omp-re::replay-annotations session nil "/a")))))

;;; --- against rizin --------------------------------------------------------------------

(defun ann-data (id type)
  "The data of the last entry of TYPE in the session ID's record."
  (car (last (omp-re::entries-of type (omp-re:find-session id)))))

(defun ann-function (addr)
  (aref (re:json "afij" addr) 0))

(defun ann-variables (addr)
  "The function's variables as (NAME . TYPE), every storage group."
  (loop for group being the hash-values of (re:json "afvlj" addr)
        append (map 'list (lambda (variable) (cons (gethash "name" variable) (gethash "type" variable)))
                    group)))

(defun ann-comment (addr)
  (re:cmd "CC." addr))

(defun ann-hints (addr)
  "The first row of the hints at ADDR; an object with nothing in it when
there is none. A hint deleted by its own letter can leave a row holding only
the address, so a test asks for the key, not for the row."
  (let ((rows (ignore-errors (re:json "ahl.j" addr))))
    (if (and (vectorp rows) (plusp (length rows))) (aref rows 0) (omp-re:obj))))

(defun ann-unhinted-p (addr)
  (notany (lambda (key) (gethash key (ann-hints addr))) '("arch" "bits" "immbase" "type" "size" "jump" "ret")))

(defun ann-marks (addr)
  (map 'list (lambda (meta) (gethash "type" meta)) (or (ignore-errors (re:json "C.j" addr)) #())))

(defun ann-global (name)
  (find name (coerce (re:json "avglj") 'list) :key (lambda (global) (gethash "name" global)) :test #'equal))

(defun ann-flag (addr)
  (or (ignore-errors (gethash "name" (re:json "fdj" addr))) ""))

(defun ann-count (id)
  (let ((session (omp-re:find-session id)))
    (length (omp-re::live-annotations (omp-re::session-binary-path session) session))))

(defun ann-in-step-p (id)
  "Whether the session says its rizin holds exactly the record's annotations."
  (let ((session (omp-re:find-session id)))
    (string= (omp-re::applied-fingerprint session "annotations")
             (omp-re::annotation-fingerprint session (omp-re::session-binary-path session)))))

(if (not *rizin*)
    (format t "~&annotations against rizin: SKIPPED (no rizin, or no ~a)~%" *binary*)
    (progn
      (suite (format nil "annotations against rizin (~a)" *binary*))
      (with-cell ()
        (check "the fifteen tools are offered, and none is an observation"
               (loop for name in '("rename_function" "rename_variable" "set_comment" "set_prototype"
                                   "set_variable_type" "define_variable" "define_global" "define_function"
                                   "set_calling_convention" "set_flag" "set_arch_hint" "set_hint" "set_data"
                                   "set_string" "set_format")
                     always (let ((tool (described-tool name)))
                              (and tool (not (gethash "evidence" tool))))))
        (check "/re help lists undo"
               (has "/re undo" (re:slash "help")))
        (check "with no binary open a tool says how to open one, undo has nothing, and status is silent"
               (in-session ((fresh-session))
                 (and (has "no binary open" (refusal (lambda () (re:call "set_comment" :addr "main" :text "x"))))
                      (equal "omp-re: no annotation left to undo" (refusal (lambda () (re:slash "undo"))))
                      (not (has "annotations in effect" (re:status))))))

        (let ((id (fresh-session)))
          (in-session (id)
            (re:open *binary*)
            (check "status counts none on a fresh binary"
                   (has "annotations in effect: 0" (re:status)))
            (check "nothing to undo on a fresh binary"
                   (equal "omp-re: no annotation left to undo" (refusal (lambda () (re:slash "undo")))))

            ;; --- rename_function: the first call, before anything was read at main
            (check "rename_function refuses a name that is no identifier, in the engine's words"
                   (and (equal "omp-re: invalid new: \"1bad\""
                               (refusal (lambda () (re:call "rename_function" :addr "main" :new "1bad"))))
                        (equal "omp-re: invalid new: \"x; !id\""
                               (refusal (lambda () (re:call "rename_function" :addr "main" :new "x; !id"))))))
            (check "an address that would carry a second command is refused"
                   (equal "omp-re: invalid address or expression: \"main; !id\""
                          (refusal (lambda () (re:call "rename_function" :addr "main; !id" :new "x")))))
            (check "an address rizin cannot resolve is refused, not read as zero"
                   (equal "omp-re: could not resolve address: no_such_symbol"
                          (refusal (lambda () (re:call "rename_function" :addr "no_such_symbol" :new "x")))))
            (check "a refused call records nothing"
                   (zerop (ann-count id)))
            (let* ((renamed (re:call "rename_function" :addr "main" :new "omp_re_main"))
                   (main (subseq renamed (+ 3 (search " @ " renamed))))
                   (session (omp-re:find-session id)))
              (check "rename_function says what it replaced, keyed on the function's start"
                     (and (equal (format nil "rename_function: \"main\" -> \"omp_re_main\" @ ~a" main) renamed)
                          (starts "0x" main)))
              (check "the rename is visible to a following read"
                     (equal "omp_re_main" (gethash "name" (ann-function main))))
              (check "the re.annotation entry has the engine's fields, ungrounded with no evidence there"
                     (equal (format nil "{\"kind\":\"rename_function\",\"ea\":~s,\"oldValue\":\"main\",\"newValue\":\"omp_re_main\",\"evidenceId\":\"\",\"ungrounded\":true}"
                                    main)
                            (omp-re:json-encode (ann-data id "re.annotation"))))
              (check "the entry is on disk, not only in memory"
                     (has "\"customType\":\"re.annotation\"" (omp-re::read-text-file (omp-re::record-path session))))
              (check "the session says its rizin holds the record's annotations"
                     (and (ann-in-step-p id) (plusp (length (omp-re::applied-fingerprint session "annotations")))))
              (check "status counts it"
                     (has "annotations in effect: 1" (re:status)))

              ;; --- set_comment
              (let ((evidence (omp-re::evidence-id-at main session)))
                (check "set_comment stores `; !id' as text, and rizin runs none of it"
                       (and (equal (format nil "set_comment: \"\" -> \"x; !id\" @ ~a" main)
                                   (re:call "set_comment" :addr main :text "x; !id"))
                            (has (format nil "~%x; !id~%") (ann-comment main))
                            (not (has "uid=" (ann-comment main)))))
                (check "an annotation at an address something was read at is grounded on that evidence"
                       (let ((data (ann-data id "re.annotation")))
                         (and evidence
                              (equal evidence (gethash "evidenceId" data))
                              (null (gethash "ungrounded" data))
                              (has "\"ungrounded\":false" (omp-re:json-encode data))))))
              (check "every rizin metacharacter in a comment is stored literally"
                     (let ((text "y; echo INJECTED @ 0x0 ~ | > out `z` $(w) # 'q' \\"))
                       (re:call "set_comment" :addr main :text text)
                       (let ((read (ann-comment main)))
                         (and (has (format nil "~%~a~%" text) read)
                              (not (has (format nil "~%INJECTED") read))))))
              (check "a comment replaces, never appends, and records what it replaced"
                     (progn (re:call "set_comment" :addr main :text "first")
                            (re:call "set_comment" :addr main :text "  second  ")
                            (and (has (format nil "~%second~%") (ann-comment main))
                                 (not (has "first" (ann-comment main)))
                                 (equal "first" (gethash "oldValue" (ann-data id "re.annotation")))
                                 (equal "second" (gethash "newValue" (ann-data id "re.annotation"))))))
              (check "a comment with a line break is refused, and the one there stays"
                     (and (equal "omp-re: invalid text: contains forbidden character"
                                 (refusal (lambda () (re:call "set_comment" :addr main :text (format nil "a~%!id")))))
                          (has "second" (ann-comment main))))
              (check "an empty comment clears"
                     (and (equal (format nil "set_comment: \"second\" -> \"\" @ ~a" main)
                                 (re:call "set_comment" :addr main :text ""))
                          (has "(no output)" (ann-comment main))))
              (check "/re undo steps back through the comment's history, one entry each"
                     (and (equal (format nil "omp-re: undid set_comment @ ~a (restored \"second\")" main)
                                 (re:slash "undo"))
                          (has (format nil "~%second~%") (ann-comment main))
                          (equal "omp-re: undid set_comment @ 0x" (subseq (re:slash "undo") 0 30))
                          (has (format nil "~%first~%") (ann-comment main))))
              (check "the re.undo entry names the entry it took back"
                     (let ((marker (ann-data id "re.undo")))
                       (and (equal '("undidEntryId") (loop for key being the hash-keys of marker collect key))
                            (find (gethash "undidEntryId" marker) (omp-re::session-entries session)
                                  :key (lambda (entry) (gethash "id" entry)) :test #'equal)
                            (ann-in-step-p id))))

              ;; --- rename_variable, set_variable_type
              (let* ((variable (first (ann-variables main)))
                     (name (car variable)))
                (check "rename_variable names the variables there are when asked for one that is not"
                       (let ((text (refusal (lambda () (re:call "rename_variable" :addr main :old "no_such_var" :new "x")))))
                         (and (has "omp-re: rename_variable: omp_re_main has no variable \"no_such_var\" (has: " text)
                              (has name text))))
                (check "rename_variable refuses a malformed name"
                       (and (equal "omp-re: invalid new: \"1bad\""
                                   (refusal (lambda () (re:call "rename_variable" :addr main :old name :new "1bad"))))
                            (equal "omp-re: invalid old: \"a b\""
                                   (refusal (lambda () (re:call "rename_variable" :addr main :old "a b" :new "x"))))))
                (check "rename_variable lands, read back through afvlj"
                       (and (equal (format nil "rename_variable: ~s -> \"omp_re_var\" @ ~a" name main)
                                   (re:call "rename_variable" :addr "omp_re_main" :old name :new "omp_re_var"))
                            (let ((names (mapcar #'car (ann-variables main))))
                              (and (member "omp_re_var" names :test #'equal)
                                   (not (member name names :test #'equal))))))
                (check "set_variable_type lands, and its entry carries the variable as target"
                       (and (equal (format nil "set_variable_type: omp_re_var: ~a -> \"char *\" @ ~a"
                                           (omp-re::js-string (cdr variable)) main)
                                   (re:call "set_variable_type" :addr main :var "omp_re_var" :type "char *"))
                            (equal "char *" (cdr (assoc "omp_re_var" (ann-variables main) :test #'equal)))
                            (let ((data (ann-data id "re.annotation")))
                              (and (equal "omp_re_var" (gethash "target" data))
                                   (equal (cdr variable) (gethash "oldValue" data))
                                   (equal '("kind" "ea" "oldValue" "newValue" "target" "evidenceId" "ungrounded")
                                          (loop for key being the hash-keys of data collect key))))))
                (check "set_variable_type refuses an unknown variable and a type with a separator"
                       (and (equal "omp-re: set_variable_type: omp_re_main has no variable \"no_such_var\""
                                   (refusal (lambda () (re:call "set_variable_type" :addr main :var "no_such_var" :type "int"))))
                            (equal "omp-re: invalid type: forbidden character \";\""
                                   (refusal (lambda () (re:call "set_variable_type" :addr main :var "omp_re_var"
                                                                                    :type "int; !id")))))))

              ;; --- set_prototype
              (check "set_prototype lands, tolerating rizin's own punctuation"
                     (let ((sig "int omp_re_main(int argc, char **argv)"))
                       (and (has (format nil " -> ~s @ ~a" sig main) (re:call "set_prototype" :addr main :sig sig))
                            (equal (format nil "~a;" sig) (gethash "signature" (ann-function main))))))
              (check "set_prototype refuses a separator before rizin sees it"
                     (equal "omp-re: invalid sig: forbidden character \";\""
                            (refusal (lambda () (re:call "set_prototype" :addr main :sig "int f(void); !id")))))

              ;; --- define_variable
              (check "define_variable adds a stack local and a register variable"
                     (and (equal (format nil "define_variable: omp_re_local: \"\" -> \"stack 0x44 int\" @ ~a" main)
                                 (re:call "define_variable" :addr main :storage "stack" :location "0x44"
                                                            :name "omp_re_local" :type "int"))
                          (equal (format nil "define_variable: omp_re_reg: \"\" -> \"reg rbx\" @ ~a" main)
                                 (re:call "define_variable" :addr main :storage "reg" :location "rbx"
                                                            :name "omp_re_reg"))
                          (let ((variables (ann-variables main)))
                            (and (equal "int" (cdr (assoc "omp_re_local" variables :test #'equal)))
                                 (assoc "omp_re_reg" variables :test #'equal)))))
              (check "define_variable refuses a name already there, a bad location, and a storage it has not"
                     (and (equal "omp-re: define_variable: omp_re_main already has a variable \"omp_re_local\""
                                 (refusal (lambda () (re:call "define_variable" :addr main :storage "reg"
                                                                                 :location "rcx" :name "omp_re_local"))))
                          (equal "omp-re: invalid stack delta: \"0x50;!id\" — a decimal or 0x-hex offset"
                                 (refusal (lambda () (re:call "define_variable" :addr main :storage "stack"
                                                                                 :location "0x50;!id" :name "omp_re_x"))))
                          (has "storage must be one of"
                               (refusal (lambda () (re:call "define_variable" :addr main :storage "heap"
                                                                               :location "8" :name "omp_re_x"))))
                          (not (assoc "omp_re_x" (ann-variables main) :test #'equal))))

              ;; --- define_global, set_flag, the marks: at ordinary addresses past main's start
              (let* ((base (parse-integer main :start 2 :radix 16))
                     (global-ea (format nil "0x~(~x~)" (+ base #x408)))
                     (flag-ea (format nil "0x~(~x~)" (+ base #x400)))
                     (data-ea (format nil "0x~(~x~)" (+ base #x200)))
                     (format-ea (format nil "0x~(~x~)" (+ base #x220)))
                     (doomed-ea (format nil "0x~(~x~)" (+ base #x10)))
                     (string-ea (let ((row (find-if (lambda (row) (>= (gethash "size" row) 4))
                                                    (re:json "izj"))))
                                  (format nil "0x~(~x~)" (gethash "vaddr" row)))))
                (check "define_global names and types a data address"
                       (and (equal (format nil "define_global: omp_re_glob: \"\" -> \"char *\" @ ~a" global-ea)
                                   (re:call "define_global" :addr global-ea :name "omp_re_glob" :type "char *"))
                            (equal "char *" (gethash "type" (ann-global "omp_re_glob")))
                            (equal global-ea (gethash "addr" (ann-global "omp_re_glob")))))
                (check "define_global refuses a name already there, and a name that is none"
                       (and (equal "omp-re: define_global: a global named \"omp_re_glob\" already exists"
                                   (refusal (lambda () (re:call "define_global" :addr data-ea :name "omp_re_glob"
                                                                                 :type "int"))))
                            (equal "omp-re: invalid name: \"g; !id\""
                                   (refusal (lambda () (re:call "define_global" :addr data-ea :name "g; !id"
                                                                                 :type "int"))))))

                (check "set_calling_convention lands, read back from the function's row"
                       (and (equal (format nil "set_calling_convention: \"amd64\" -> \"ms\" @ ~a" main)
                                   (re:call "set_calling_convention" :addr "omp_re_main" :cc "ms"))
                            (equal "ms" (gethash "calltype" (ann-function main)))))
                (check "set_calling_convention refuses a convention rizin does not know, and one that is no name"
                       (and (has "omp-re: set_calling_convention: mutation did not land: expected \"nonexistent_cc\", rizin has \"ms\""
                                 (refusal (lambda () (re:call "set_calling_convention" :addr main :cc "nonexistent_cc"))))
                            (equal "omp-re: invalid cc: \"ms; !id\""
                                   (refusal (lambda () (re:call "set_calling_convention" :addr main :cc "ms; !id"))))
                            (equal "ms" (gethash "calltype" (ann-function main)))))

                (let ((old (ann-flag flag-ea)))
                  (check "set_flag names the address, replacing the flag that was there"
                         (and (equal (format nil "set_flag: ~a -> \"omp_re.label\" @ ~a" (omp-re::js-string old) flag-ea)
                                     (re:call "set_flag" :addr flag-ea :name "omp_re.label"))
                              (equal "omp_re.label" (ann-flag flag-ea))
                              ;; rizin now resolves the name, which is the point of a flag
                              (has (format nil "@ omp_re.label") (re:cmd "pd 1" "omp_re.label")))))
                (check "set_flag refuses a name that is no identifier"
                       (equal "omp-re: invalid name: \"bad name; !id\""
                              (refusal (lambda () (re:call "set_flag" :addr flag-ea :name "bad name; !id")))))

                (check "set_arch_hint sets arch and bits, and /re undo deletes the hint"
                       (and (equal (format nil "set_arch_hint: \"\" -> \"arch=arm;bits=16\" @ ~a" main)
                                   (re:call "set_arch_hint" :addr main :arch "arm" :bits 16))
                            (let ((hint (ann-hints main)))
                              (and (equal "arm" (gethash "arch" hint)) (eql 16 (gethash "bits" hint))))
                            (equal (format nil "omp-re: undid set_arch_hint @ ~a (restored \"\")" main)
                                   (re:slash "undo"))
                            (ann-unhinted-p main)))
                (check "set_arch_hint refuses with neither, a word size it has not, and an arch that is no name"
                       (and (equal "omp-re: set_arch_hint needs arch and/or bits"
                                   (refusal (lambda () (re:call "set_arch_hint" :addr main))))
                            (has "bits must be one of 8, 16, 32, 64"
                                 (refusal (lambda () (re:call "set_arch_hint" :addr main :bits 17))))
                            (equal "omp-re: invalid arch: \"arm; !id\""
                                   (refusal (lambda () (re:call "set_arch_hint" :addr main :arch "arm; !id"))))
                            (ann-unhinted-p main)))

                (check "set_hint records what rizin stored, not what was asked"
                       (and (equal (format nil "set_hint: immediate_base: \"\" -> \"16\" @ ~a" main)
                                   (re:call "set_hint" :addr main :hint "immediate_base" :value "h"))
                            (eql 16 (gethash "immbase" (ann-hints main)))
                            (let ((data (ann-data id "re.annotation")))
                              (and (equal "immediate_base" (gethash "target" data))
                                   (equal "16" (gethash "newValue" data))))))
                (check "set_hint sets an opcode type and a jump target, and undo takes each away"
                       (and (equal (format nil "set_hint: opcode_type: \"\" -> \"nop\" @ ~a" main)
                                   (re:call "set_hint" :addr main :hint "opcode_type" :value "nop"))
                            (equal "nop" (gethash "type" (ann-hints main)))
                            (re:slash "undo")
                            (null (gethash "type" (ann-hints main)))
                            (equal (format nil "set_hint: jump_target: \"\" -> ~s @ ~a" flag-ea main)
                                   (re:call "set_hint" :addr main :hint "jump_target" :value flag-ea))
                            (re:slash "undo")
                            (null (gethash "jump" (ann-hints main)))
                            (eql 16 (gethash "immbase" (ann-hints main)))))
                (check "set_hint refuses a value its hint does not take, and a hint it has not"
                       (and (equal "omp-re: invalid opcode_size: \"0\" — a positive integer"
                                   (refusal (lambda () (re:call "set_hint" :addr main :hint "opcode_size" :value "0"))))
                            (has "omp-re: invalid immediate_base: \"bogus\""
                                 (refusal (lambda () (re:call "set_hint" :addr main :hint "immediate_base" :value "bogus"))))
                            (equal "omp-re: invalid address or expression: \"0x10; !id\""
                                   (refusal (lambda () (re:call "set_hint" :addr main :hint "jump_target"
                                                                           :value "0x10; !id"))))
                            (has "hint must be one of"
                                 (refusal (lambda () (re:call "set_hint" :addr main :hint "esil" :value "1"))))))

                (check "set_data marks an array of data"
                       (and (equal (format nil "set_data: \"\" -> \"4:4\" @ ~a" data-ea)
                                   (re:call "set_data" :addr data-ea :size 4 :count 4))
                            (member "Cd" (ann-marks data-ea) :test #'equal)))
                (check "set_data refuses a size that is no positive integer"
                       (and (equal "omp-re: set_data: size must be a positive integer"
                                   (refusal (lambda () (re:call "set_data" :addr main :size 0))))
                            (equal "omp-re: set_data: size must be a positive integer"
                                   (refusal (lambda () (re:call "set_data" :addr main :size 2.5))))
                            (has "size must be a number"
                                 (refusal (lambda () (re:call "set_data" :addr main :size "4; !id"))))))
                (check "set_string marks a string, its length found by rizin"
                       (and (equal (format nil "set_string: \"\" -> \"auto\" @ ~a" string-ea)
                                   (re:call "set_string" :addr string-ea))
                            (member "Cs" (ann-marks string-ea) :test #'equal)))
                (check "set_string with a size, undone; and a size that is none refused"
                       (and (re:slash "undo")
                            (not (member "Cs" (ann-marks string-ea) :test #'equal))
                            (equal (format nil "set_string: \"\" -> \"4\" @ ~a" string-ea)
                                   (re:call "set_string" :addr string-ea :size 4))
                            (member "Cs" (ann-marks string-ea) :test #'equal)
                            (equal "omp-re: set_string: size must be a positive integer"
                                   (refusal (lambda () (re:call "set_string" :addr string-ea :size -1))))))
                (check "set_format overlays a struct format"
                       (and (equal (format nil "set_format: \"\" -> \"8 xxdd f1 f2 f3 f4\" @ ~a" format-ea)
                                   (re:call "set_format" :addr format-ea :size 8 :format " xxdd f1 f2 f3 f4 "))
                            (member "Cf" (ann-marks format-ea) :test #'equal)))
                (check "set_format refuses a format that could carry a command, and a size that is none"
                       (and (equal "omp-re: invalid pf format: \"xx; !id\""
                                   (refusal (lambda () (re:call "set_format" :addr data-ea :size 8 :format "xx; !id"))))
                            (equal "omp-re: set_format: size must be a positive integer"
                                   (refusal (lambda () (re:call "set_format" :addr data-ea :size 0 :format "xx"))))
                            (not (member "Cf" (ann-marks data-ea) :test #'equal))))

                ;; --- define_function: a gap is made the way the engine's own test
                ;; makes one, by undefining a function rizin found.
                (let* ((victim (let ((row (find-if (lambda (row)
                                                     (and (/= (gethash "offset" row) base)
                                                          (> (gethash "size" row) 16)
                                                          (starts "fcn." (gethash "name" row))))
                                                   (re:json "aflj"))))
                                 (format nil "0x~(~x~)" (gethash "offset" row)))))
                  (check "define_function refuses where a function already begins"
                         (equal (format nil "omp-re: define_function: a function already begins at ~a (\"omp_re_main\"); nothing to define"
                                        main)
                                (refusal (lambda () (re:call "define_function" :addr main)))))
                  (omp-re::rz-cmd (omp-re::session-rz session) (format nil "af- @ ~a" victim))
                  (check "define_function defines one where rizin has none, and names it in the entry"
                         (and (not (omp-re::function-starting-at (omp-re::session-rz session) victim))
                              (has (format nil "define_function: \"\" -> \"fcn.") (re:call "define_function" :addr victim))
                              (eql (parse-integer victim :start 2 :radix 16)
                                   (gethash "offset" (ann-function victim)))
                              (starts "fcn." (gethash "newValue" (ann-data id "re.annotation")))))
                  (check "/re undo undefines it again"
                         (and (equal (format nil "omp-re: undid define_function @ ~a (restored \"\")" victim)
                                     (re:slash "undo"))
                              (not (omp-re::function-starting-at (omp-re::session-rz session) victim)))))

                ;; --- one more made and taken back, to be absent after a respawn
                (re:call "set_comment" :addr doomed-ea :text "doomed")
                (check "an annotation made and undone is out of effect"
                       (let ((before (ann-count id)))
                         (and (has "doomed" (ann-comment doomed-ea))
                              (re:slash "undo")
                              (= (1- before) (ann-count id))
                              (has "(no output)" (ann-comment doomed-ea)))))
                (check "status counts what is in effect, and the session is in step"
                       (and (has (format nil "annotations in effect: ~d" (ann-count id)) (re:status))
                            (ann-in-step-p id)
                            (> (ann-count id) 8)))

                (flet ((everything-holds ()
                         (let ((variables (ann-variables main))
                               (function (ann-function main)))
                           (and (equal "omp_re_main" (gethash "name" function))
                                (equal "int omp_re_main(int argc, char **argv);" (gethash "signature" function))
                                (equal "ms" (gethash "calltype" function))
                                (has (format nil "~%first~%") (ann-comment main))
                                (equal "char *" (cdr (assoc "omp_re_var" variables :test #'equal)))
                                (equal "int" (cdr (assoc "omp_re_local" variables :test #'equal)))
                                (assoc "omp_re_reg" variables :test #'equal)
                                (equal "char *" (gethash "type" (ann-global "omp_re_glob")))
                                (equal "omp_re.label" (ann-flag flag-ea))
                                (eql 16 (gethash "immbase" (ann-hints main)))
                                (member "Cd" (ann-marks data-ea) :test #'equal)
                                (member "Cs" (ann-marks string-ea) :test #'equal)
                                (member "Cf" (ann-marks format-ea) :test #'equal))))
                       (undone-stay-undone ()
                         (let ((hint (ann-hints main)))
                           (and (null (gethash "arch" hint))
                                (null (gethash "bits" hint))
                                (null (gethash "type" hint))
                                (null (gethash "jump" hint))
                                (has "(no output)" (ann-comment doomed-ea))
                                (not (has "second" (ann-comment main)))))))
                  (check "every annotation in effect reads back before the process is touched"
                         (and (everything-holds) (undone-stay-undone)))

                  ;; The process dies; the record is the truth.
                  (let ((old (omp-re::session-rz session))
                        (count (ann-count id)))
                    (kill-rizin id)
                    (check "a killed rizin comes back with every annotation replayed"
                           (and (everything-holds)
                                (not (eq old (omp-re::session-rz session)))))
                    (check "and with the undone ones not replayed"
                           (undone-stay-undone))
                    (check "the fresh process is in step with the record"
                           (and (ann-in-step-p id) (= count (ann-count id))))
                    (check "the replay of this record has no failure line"
                           (null (omp-re::replay-annotations session (omp-re::session-rz session)
                                                         (omp-re::session-binary-path session))))

                    ;; The engine forgets the session; the record brings it back.
                    (omp-re:shutdown-sessions)
                    (check "a forgotten session still counts its annotations, from the record alone"
                           (let ((status (re:status)))
                             (and (has "not running" status)
                                  (has (format nil "annotations in effect: ~d" count) status))))
                    (check "and its next read finds every annotation replayed, the undone ones not"
                           (and (everything-holds) (undone-stay-undone) (ann-in-step-p id)))
                    (check "/re undo works across the restart: the marker is the record's"
                           (and (has "omp-re: undid set_format @ " (re:slash "undo"))
                                (not (member "Cf" (ann-marks format-ea) :test #'equal))
                                (= (1- count) (ann-count id))))
                    (check "opening the binary again says how many annotations it put back"
                           (has (format nil "Re-applied ~d of ~d annotation(s) recorded earlier for this binary."
                                        (1- count) (1- count))
                                (re:open *binary*)))
                    (check "and they are there, the one just undone not among them"
                           (and (equal "omp_re_main" (gethash "name" (ann-function main)))
                                (equal "omp_re.label" (ann-flag flag-ea))
                                (member "Cd" (ann-marks data-ea) :test #'equal)
                                (not (member "Cf" (ann-marks format-ea) :test #'equal))
                                (ann-in-step-p id))))

                  ;; --- all the way back
                  (check "/re undo, repeated, takes every annotation back and then says there is none"
                         (and (loop repeat 100
                                    while (plusp (ann-count id))
                                    always (has "omp-re: undid " (re:slash "undo")))
                              (zerop (ann-count id))
                              (equal "omp-re: no annotation left to undo" (refusal (lambda () (re:slash "undo"))))
                              (has "annotations in effect: 0" (re:status))))
                  (check "rizin is back to what its own analysis said"
                         (let ((function (ann-function main)))
                           (and (equal "main" (gethash "name" function))
                                (equal "amd64" (gethash "calltype" function))
                                (has "(no output)" (ann-comment main))
                                (not (ann-global "omp_re_glob"))
                                (not (equal "omp_re.label" (ann-flag flag-ea)))
                                (ann-unhinted-p main)
                                (not (member "Cd" (ann-marks data-ea) :test #'equal))
                                (not (member "Cs" (ann-marks string-ea) :test #'equal))
                                (notany (lambda (variable) (starts "omp_re" (car variable)))
                                        (ann-variables main)))))
                  (check "and a rizin started from that record has nothing put back into it"
                         ;; The session was forgotten above: this is the one restored since.
                         (let* ((session (omp-re:find-session id))
                                (old (omp-re::session-rz session)))
                           (kill-rizin id)
                           (and (equal "main" (gethash "name" (ann-function main)))
                                (not (eq old (omp-re::session-rz session)))
                                (string= "" (omp-re::applied-fingerprint session "annotations")))))))))))))
