;;;; extras.lisp --- the remaining static tools: maps, passes, signatures,
;;;; projects, the rz-* programs, external triage, and the RzIL emulator.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Three of these change what the rizin process holds without being
;;;; annotations: a mapped file, an extra analysis pass, a custom signature
;;;; file. Each is recorded (re.mapfile, re.analysis, re.signature) and put
;;;; back on every fresh process, in that order and before the annotations:
;;;; a map must be there for a pass to see it, a pass must have found the
;;;; functions a signature names, and an annotation may sit on any of them.
;;;; None is undoable — reopening the binary is how one starts clean.
;;;;
;;;; None of these tools is evidence: rizin_command is the one way to observe
;;;; the binary on the record.

(in-package #:omp-re)

;;; --- small things several tools share ------------------------------------------------------

(defun file-octets (path)
  "The size of the file at PATH in octets, or NIL when there is no such file."
  (ignore-errors
   (with-open-file (in (uiop:parse-native-namestring path) :element-type '(unsigned-byte 8))
     (file-length in))))

(defun path-basename (path)
  "The last component of the native PATH, as node's basename gives it."
  (let ((slash (position-if (lambda (char) (find char "/\\")) path :from-end t)))
    (if slash (subseq path (1+ slash)) path)))

(defun function-count (rz)
  "How many functions RZ knows of; 0 when it does not say."
  (or (ignore-errors (parse-integer (trimmed (rz-cmd rz "aflc")))) 0))

;;; --- map_file ------------------------------------------------------------------------------
;;; The file is opened with `o', never `o+', so it is mapped read-only and
;;; never written on disk. The path is single-quoted so a path with odd
;;; characters cannot start a second command; the address and the permission
;;; are validated.

(defun validate-map-perm (perm)
  "PERM when it is an IO-map permission string (r, rw, rwx, ...): the access
the mapped region allows, not a file write mode."
  (unless (js-scan "^[rwx]+$" perm)
    (fail "omp-re: map_file: invalid permission ~a — use r, w, x characters (e.g. r, rw, rx)"
          (js-string perm)))
  perm)

(defun map-file-command (path addr &optional perm)
  "The `o <file> <addr> [<perm>]' line that maps PATH at ADDR."
  (format nil "o ~a ~a~@[ ~a~]" (rz-quote path) (validate-addr addr)
          (and perm (validate-map-perm perm))))

(defun recorded-map-files (binary-path &optional (session *session*))
  "The files mapped against BINARY-PATH, once per path and address, in the
order first mapped => a list of (PATH ADDR PERM)."
  (let ((maps '()))
    (dolist (data (binary-entries "re.mapfile" binary-path session) (nreverse maps))
      (let ((path (jget data "path")) (addr (jget data "addr")) (perm (jget data "perm")))
        (when (and (stringp path) (stringp addr)
                   (notany (lambda (seen) (and (string= path (first seen)) (string= addr (second seen))))
                           maps))
          (push (list path addr (and (stringp perm) perm)) maps))))))

(defun replay-map-files (session rz binary-path)
  "Map the recorded files into the fresh RZ, in order. A map that no longer
applies — the file moved since it was recorded — is a failure line, never
the end of the replay."
  (loop for (path addr perm) in (recorded-map-files binary-path session)
        append (handler-case (progn (rz-cmd rz (map-file-command path addr perm)) nil)
                 (error (condition)
                   (list (format nil "map ~a @ ~a: ~a" path addr condition))))))

(define-tool "map_file"
    (:label "Map File" :tier :exec
     :reason '(:cases
                ((("path" :string))
                 "Map {path} into the session's address space at {addr!} (read-only; re-applied on respawn). The file on disk is not modified.")
                (()
                 "Map a file into the session's address space at {addr!} (read-only; re-applied on respawn). The file on disk is not modified."))
     :render '(:title "Map file" :subject "path")
     :description "Open an additional file into the current session at a virtual address (`o <file> <addr>`), alongside the primary binary — e.g. overlay a dumped/unpacked region over the packed image, or map a library for cross-module analysis. The file is mapped read-only (never written on disk) and the map is re-applied automatically on resume/respawn. To just analyze a dump on its own, use open_binary instead. Not an undoable annotation: reopen the binary to drop the map.")
    (("path" :string :required t :doc "Path to the file to map into the session (a memory dump, a library, a raw blob).")
     ("addr" :string :required t :doc "Virtual address to map it at, e.g. 0x50000 — pick a range the primary binary doesn't already occupy.")
     ("perm" :string :doc "Map permissions as r/w/x characters (default rizin's own, usually r). The file stays read-only on disk regardless."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (binary (require-binary))
         (addr (validate-addr (jstring arguments "addr")))
         (perm (and (jstring arguments "perm") (validate-map-perm (jstring arguments "perm"))))
         ;; Resolved to an absolute, readable file with the engine's own
         ;; refusal, so rizin's working directory does not matter.
         (path (resolve-binary-path (jstring arguments "path")))
         (before (length (or (rz-cmdj rz "omlj") #()))))
    (let ((stderr (trimmed (nth-value 1 (rz-run rz (map-file-command path addr perm))))))
      (unless (blank-p stderr)
        (fail "omp-re: map_file: ~a" stderr)))
    (unless (> (length (or (rz-cmdj rz "omlj") #())) before)
      (fail "omp-re: map_file: no map was added for ~a at ~a (unreadable or zero-length file?)" path addr))
    ;; Recorded for replay once per path and address on this binary.
    (unless (find-if (lambda (seen) (and (string= path (first seen)) (string= addr (second seen))))
                     (recorded-map-files binary))
      (append-entry "re.mapfile" (obj "path" path "addr" addr "perm" (or perm :absent))))
    (let ((sample (trimmed (rz-cmd rz (format nil "p8 16 @ ~a" addr)))))
      (text-result (format nil "map_file: ~a @ ~a" path addr)
                   (format nil "mapped ~a at ~a~@[ (~a)~]; first bytes: ~a~%Re-applied automatically on resume/respawn; reopen the binary to drop it."
                           path addr perm (if (blank-p sample) "(unreadable)" sample))
                   :tool "map_file"))))

;;; --- analyze -------------------------------------------------------------------------------
;;; open_binary's `aaa' is the baseline and runs again on every fresh
;;; process; the deeper and format-specific passes below do not, so a pass
;;; the analyst ran is recorded and re-run. Every one only adds analysis.

(defparameter +analysis-passes+
  '(("calls" . "aac")                   ; analyze function calls
    ("xrefs" . "aar")                   ; analyze cross-references
    ("pointers" . "aav")                ; values that reference a section/map
    ("preludes" . "aap")                ; functions by prologue byte patterns (stripped code)
    ("all_functions" . "aaf")           ; analyze all functions
    ("data_refs" . "aad")               ; data references to code
    ("autoname" . "aan")                ; name functions from the strings/calls they use
    ("types" . "aaft")                  ; recursive type matching across all functions
    ("struct_offsets" . "aat")          ; immediates to linked structure-member offsets
    ("golang" . "aalg")                 ; recover Go functions and strings
    ("objc" . "aalor")                  ; Objective-C references from selector usage
    ("rtti_classes" . "avrr")           ; C++ class info from all RTTI
    ("emulate_functions" . "aaef"))     ; references by emulating every function (slow)
  "The passes the analyze tool offers, each with the rizin command that runs
it: the one map the tool and the replay share.")

(defun analysis-pass-command (pass)
  (cdr (assoc pass +analysis-passes+ :test #'string=)))

(defun recorded-analysis-passes (binary-path &optional (session *session*))
  "The passes run against BINARY-PATH, each once, in the order first run."
  (let ((passes '()))
    (dolist (data (binary-entries "re.analysis" binary-path session) (nreverse passes))
      (let ((pass (jget data "pass")))
        (when (and (stringp pass) (not (member pass passes :test #'string=)))
          (push pass passes))))))

(defun replay-analysis-passes (session rz binary-path)
  "Re-run the recorded passes on the freshly analyzed RZ, in order. An
unknown or failing pass is a failure line, never the end of the replay."
  (loop for pass in (recorded-analysis-passes binary-path session)
        for command = (analysis-pass-command pass)
        append (if (null command)
                   (list (format nil "analysis pass ~a: unknown" pass))
                   (handler-case (progn (rz-cmd rz command :seconds (analysis-seconds)) nil)
                     (error (condition)
                       (list (format nil "analysis pass ~a: ~a" pass condition)))))))

(define-tool "analyze"
    (:label "Analyze" :tier :exec
     :reason '(:cases
                ((("pass" :string))
                 "Run rizin analysis pass {pass} — this changes the analysis (it adds functions, xrefs, names, or types).")
                (()
                 "Run rizin analysis pass ? — this changes the analysis (it adds functions, xrefs, names, or types)."))
     :render '(:title "analyze" :subject "pass")
     :description "Re-run a rizin analysis pass to recover more than open_binary's baseline `aaa` found: prelude scans for stripped code, Go/Objective-C recovery, pointer and call/xref analysis, recursive type matching, or per-function emulation. Reports the function count before and after. The pass is re-run automatically on resume/respawn; it is not an undoable annotation (reopen the binary to return to the baseline). Some passes (emulate_functions) can be slow.")
    (("pass" :string :required t :enum (mapcar #'car +analysis-passes+)
      :doc (join-lines
            '("calls: analyze function calls. xrefs: cross-references. pointers: values that reference a section/map."
              "preludes: recover functions by prologue byte patterns (finds code in stripped binaries aaa missed). all_functions: analyze all functions. data_refs: data references to code."
              "autoname: name functions from the strings/calls they use. types: recursive type matching across functions. struct_offsets: rewrite immediates as linked struct-member offsets."
              "golang: recover Go functions and strings. objc: recover Objective-C references from selector usage. rtti_classes: recover C++ classes from RTTI."
              "emulate_functions: analyze references by emulating every function with ESIL (thorough but slow)."))))
    (arguments)
  (let* ((rz (ensure-rizin))
         (binary (require-binary))
         (pass (jstring arguments "pass"))
         (command (analysis-pass-command pass))
         (before (function-count rz)))
    ;; Both streams are read: a pass like golang says "cannot recover ..." on
    ;; stderr, and that message is the whole answer.
    (multiple-value-bind (output stderr) (rz-run rz command :seconds (analysis-seconds))
      (let* ((after (function-count rz))
             (out (trimmed output))
             (err (trimmed stderr))
             (errored (not (blank-p err)))
             (delta (- after before)))
        ;; Recorded for replay only when the pass did real work: one that
        ;; errored or found nothing has nothing worth re-running.
        (when (and (not errored) (or (/= delta 0) (not (blank-p out)))
                   (not (member pass (recorded-analysis-passes binary) :test #'string=)))
          (append-entry "re.analysis" (obj "pass" pass)))
        (let ((result (text-result
                       (format nil "analyze: ~a" pass)
                       (if errored
                           (format nil "~a: ~a" command err)
                           (format nil "~a: functions ~d -> ~d~a.~a" command before after
                                   (if (/= delta 0) (format nil " (+~d)" delta) " (no change)")
                                   (if (blank-p out) "" (format nil "~%~a" out))))
                       :tool "analyze")))
          (if errored (as-failure result) result))))))

;;; --- FLIRT signatures ----------------------------------------------------------------------
;;; rizin's `aaa' applies the built-in signature database on open, so that
;;; needs no replay. A custom .sig/.pat file applied with `Fs' does: the
;;; names it produced live in the process.

(defun validate-signature-path (path)
  "PATH when it can cross the pipe; quoting makes everything else literal."
  (when (ends-pipe-line-p path)
    (fail "omp-re: apply_signatures: path must not contain a line break or NUL"))
  (when (blank-p path)
    (fail "omp-re: apply_signatures: empty path"))
  path)

(defun signature-apply-command (path)
  "The rizin line that applies one FLIRT file."
  (format nil "Fs ~a" (rz-quote (validate-signature-path path))))

(defun parse-applied-count (output)
  "The count in `Fs''s `Found <n> FLIRT signatures via <path>', or NIL."
  (multiple-value-bind (match groups) (ppcre:scan-to-strings "(?i)Found\\s+(\\d+)\\s+FLIRT signatures?" output)
    (and match (parse-integer (aref groups 0)))))

(defun recorded-signatures (binary-path &optional (session *session*))
  "The custom signature files applied against BINARY-PATH, in order."
  (loop for data in (binary-entries "re.signature" binary-path session)
        for path = (jget data "path")
        when (stringp path) collect path))

(defun replay-signatures (session rz binary-path)
  "Apply the recorded signature files to the freshly analyzed RZ, in order.
A file that no longer applies is a failure line, never the end of the replay."
  (loop for path in (recorded-signatures binary-path session)
        append (handler-case (progn (rz-cmd rz (signature-apply-command path)) nil)
                 (error (condition)
                   (list (format nil "signature ~a: ~a" path condition))))))

(define-tool "apply_signatures"
    (:label "Apply Signatures" :tier :exec
     :reason '(:cases
                ((("source" "file") ("path" :string))
                 "Apply the FLIRT signature file {path} — this renames matched functions.")
                (()
                 "Re-apply rizin's built-in signature database — this renames matched functions."))
     :render '(:title "Apply signatures" :subject "source")
     :description "Name library functions from FLIRT signatures. source 'sigdb' re-applies rizin's built-in signature database (already applied once by open_binary's analysis); source 'file' applies a custom .sig/.pat file you provide, which open_binary can't know about. This renames matched functions (it changes analysis). A custom file is re-applied automatically on resume/respawn. List the built-in database with rizin_command Flt.")
    (("source" :string :required t :enum '("sigdb" "file")
      :doc "sigdb: re-apply rizin's built-in signature database. file: apply a custom FLIRT .sig/.pat file (path required).")
     ("path" :string :doc "Path to a .sig/.pat file, required when source is 'file'."))
    (arguments)
  (let ((rz (ensure-rizin))
        (binary (require-binary)))
    (if (string= "sigdb" (jstring arguments "source"))
        (let ((before (function-count rz)))
          (rz-cmd rz "Fa")
          (text-result "apply_signatures: sigdb"
                       (format nil "Re-applied the built-in signature database. Functions: ~d before, ~d after."
                               before (function-count rz))))
        (progn
          (unless (jstring arguments "path")
            (fail "omp-re: apply_signatures: source 'file' needs a path"))
          (let* ((path (validate-signature-path (jstring arguments "path")))
                 (out (trimmed (rz-cmd rz (signature-apply-command path))))
                 (count (parse-applied-count out)))
            ;; Recorded for replay only when it applied something: a zero-match
            ;; or failed application has nothing to reproduce.
            (when (and count (plusp count)
                       (not (member path (recorded-signatures binary) :test #'string=)))
              (append-entry "re.signature" (obj "path" path)))
            (text-result (format nil "apply_signatures: ~a" path)
                         (cond (count (format nil "Applied ~d FLIRT signature(s) from ~a." count path))
                               ((blank-p out) "(applied)")
                               (t out))))))))

(define-tool "create_signature"
    (:label "Create Signature" :tier :exec
     :reason "Create a FLIRT signature file from the current analysis in omp-re's output directory — the analysis and the sample are not modified."
     :render '(:title "create_signature" :subject "file")
     :description "Build a FLIRT signature file (`Fc`) from the current binary's analyzed functions, to recognize those same functions in other samples (e.g. tracking a routine across a malware family). Written to omp-re's output directory as a `.pat` (text patterns) or `.sig` (compiled). Apply it elsewhere with apply_signatures (source 'file'). Reads the analysis and writes a file — it does not modify the analysis or the sample.")
    (("file" :string :doc "Output filename (a bare name, no path) written to omp-re's output directory; omit for one derived from the binary's name. End it `.pat` (text patterns, the default) or `.sig` (compiled)."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (binary (require-binary))
         (requested (or (jstring arguments "file") (format nil "~a.pat" (path-basename binary))))
         (name (if (js-scan "(?i)\\.(pat|sig)$" requested) requested (format nil "~a.pat" requested)))
         ;; The name is held to a bare file name before rizin is asked anything.
         (path (rizin-output-path name)))
    (let ((stderr (trimmed (nth-value 1 (rz-run rz (format nil "Fc ~a" (rizin-path-arg path)))))))
      (unless (blank-p stderr)
        (fail "omp-re: create_signature: ~a" stderr)))
    (let ((size (file-octets path)))
      (unless size
        (fail "omp-re: create_signature: rizin reported no error but wrote no signature file at ~a (are there analyzed functions? run analyze/open_binary first)"
              path))
      (when (zerop size)
        (fail "omp-re: create_signature: the signature file at ~a is empty (no functions to signature)" path))
      ;; Read back (`Fd' dumps a file's signatures): that it parses says it is
      ;; a FLIRT file, and its lines are the count.
      (let* ((dumped (trimmed (rz-cmd rz (format nil "Fd ~a" (rizin-path-arg path)))))
             (count (count-if-not #'blank-p (split-lines dumped))))
        (text-result (format nil "create_signature: ~a" name)
                     (format nil "wrote ~d function signature(s) to ~a (~d bytes)~%Apply it to another sample with apply_signatures (source 'file', path ~a)."
                             count path size path)
                     :tool "create_signature")))))

;;; --- export_project ------------------------------------------------------------------------
;;; Export only. Loading a project would replace the session's analysis with
;;; state the record does not know of, and the next fresh process would
;;; replay the record over it: a second source of truth.

(define-tool "export_project"
    (:label "Export Project" :tier :exec
     :reason "Write the current analysis to a rizin project file in omp-re's output directory — the sample and the analysis are not modified."
     :render '(:title "export_project" :subject "file")
     :description "Save the current analysis as a rizin project (.rzdb) — functions, names, comments, flags, and types, including every annotation omp-re has applied — so it can be opened in interactive rizin or Cutter (`Po <file>`). Written to omp-re's output directory, never the sample. Export only: omp-re does not load projects (it manages analysis state through its own session log). Returns the file path and size.")
    (("file" :string :doc "Project filename (a bare name, no path) written to omp-re's output directory; omit for one derived from the binary's name. `.rzdb` is appended if missing."))
    (arguments)
  (let* ((rz (ensure-rizin))
         (binary (require-binary))
         (requested (or (jstring arguments "file") (format nil "~a.rzdb" (path-basename binary))))
         (name (if (js-scan "(?i)\\.rzdb$" requested) requested (format nil "~a.rzdb" requested)))
         (path (rizin-output-path name)))
    (let ((stderr (trimmed (nth-value 1 (rz-run rz (format nil "Ps ~a" (rizin-path-arg path)))))))
      (unless (blank-p stderr)
        (fail "omp-re: export_project: ~a" stderr)))
    (let ((size (file-octets path)))
      (unless size
        (fail "omp-re: export_project: rizin reported no error but wrote no project file at ~a" path))
      (when (zerop size)
        (fail "omp-re: export_project: the project file at ~a is empty" path))
      (text-result (format nil "export_project: ~a" name)
                   (format nil "wrote the analysis to ~a (~d bytes)~%Open it in rizin or Cutter with: Po ~a"
                           path size path)
                   :tool "export_project"))))

;;; --- rizin_cli -----------------------------------------------------------------------------
;;; The rz-* programs are separate executables run by argv, never through a
;;; shell, so there is no `;' or `|' to guard. What is gated is the flags: the
;;; few that run a shell or rizin command, write to disk, fetch over the
;;; network or open an interactive view are refused before anything runs.
;;; rz-gg, rz-run, rz-sign, rz-ar and rz-test are left out: they generate
;;; code, launch a process, or are rizin's own plumbing.

(defparameter +rz-cli-seconds+ 180)

(defparameter +binary-placeholder+ "@binary"
  "What the model writes in args to mean the open binary's path.")

(defstruct (rz-cli (:copier nil))
  tool summary
  target                                ; :open — runs against the open binary; :args — the model names the files
  (denied-letters "")                   ; short-flag letters refused anywhere in a -xyz cluster
  (denied-tokens '())                   ; whole tokens refused (long options)
  (denied-repeated-letters "")          ; safe once, a network fetch when given twice
  (denied-flag-values '()))             ; ((LETTER VALUE ...) ...): a flag's value refused in every spelling

(defparameter +rz-cli-tools+
  (list
   (make-rz-cli
    :tool "rz-bin" :target :open
    :summary "Binary info without loading the whole core: headers (-H), imports (-i), exports (-E), symbols (-s), sections (-S), libraries (-l), strings (-z), classes (-c), entrypoint (-e), main (-M), checksums (-K), demangling (-D). JSON with -j."
    ;; -O/-o write or extract, -C creates a new binary, -x extracts sub-binaries to disk.
    :denied-letters "OoCx"
    ;; -dd downloads DWARF (debuginfod), -PP the PDB; a single -d/-P reads locally.
    :denied-repeated-letters "dP")
   (make-rz-cli
    :tool "rz-diff" :target :args
    :summary "Compare two files: edit distance (-d myers|leven|ssdeep) or structural diff (-t bytes|functions|imports|symbols|sections|strings|entries|fields|graphs). Pass both paths; -A compares addresses, -B runs full analysis first. JSON with -j."
    ;; -H/-S open an interactive view that would hang. -e (sets config) is not
    ;; refused: a letter-ban on `e' would catch any clustered value holding
    ;; one (-tbytes), and rz-diff runs on a throwaway process.
    :denied-letters "HS"
    ;; -t command runs a rizin command per file, and rizin's `!' is the shell.
    :denied-flag-values '(("t" "command" "commands")))
   (make-rz-cli
    :tool "rz-hash" :target :args
    :summary "Hash, entropy, and checksums of a file or input: -a <algo[,algo]> (md5, sha256, entropy, …), -B per-block, -b <size>, -c <value> to compare, -s/-x for string/hex input. -L lists algorithms. JSON with -j.")
   (make-rz-cli
    :tool "rz-find" :target :args
    :summary "Search a file for bytes or strings: -x <hex>, -s <string>, -w <widestring>, -e <regex>, -S/-I for symbol/import names, -m magic carve, -i identify filetype. -X shows a hexdump of hits. JSON with -j."
    ;; -E runs a shell command per hit, -R a rizin command per hit.
    :denied-letters "ER")
   (make-rz-cli
    :tool "rz-asm" :target :args
    :summary "Assemble or disassemble: `rz-asm -a x86 -b 64 'mov eax, 1'` assembles, `rz-asm -a x86 -b 64 -d 'b801000000'` disassembles hexpairs, -A shows analysis, -E ESIL, -I RzIL. -L lists arch plugins."
    ;; -O writes an output file; -o here is the start address and stays.
    :denied-letters "O")
   (make-rz-cli
    :tool "rz-ax" :target :args
    :summary "Base and format conversion: int/hex/bin/oct/float/base64/IP. `rz-ax 0xdead`, `rz-ax 10`, `rz-ax -E <b64>`, `rz-ax -s 414141` (hex→raw). A pure calculator; no file is touched."))
  "The curated set of rizin's standalone programs.")

(defun short-cluster-p (token)
  "Whether TOKEN is a single-dash run of letters (-ij, -qO): not --long, not
a negative number, not the bare - that means stdin."
  (and (js-scan "^-[A-Za-z]+$" token) t))

(defun rz-cli-flag-values (arguments letter)
  "Every value the short flag LETTER is given across ARGUMENTS, in each
getopt spelling: the rest of its cluster (-tcommand, -Xtcommand), or the
next token when the letter ends the cluster (-t command)."
  (loop for (token next) on arguments
        for at = (and (short-cluster-p token) (position letter token :start 1))
        when at
          append (cond ((< (1+ at) (length token)) (list (subseq token (1+ at))))
                       (next (list next)))))

(defun check-rz-cli (definition arguments)
  "NIL when ARGUMENTS may be given to DEFINITION's program, else why not.
getopt-aware: a refused flag is caught split, attached or clustered, and a
repeat-escalation flag however the repetition is spelt, so no respelling
carries a refused capability through."
  (let ((tool (rz-cli-tool definition))
        (repeats '()))
    (dolist (token arguments)
      (when (ends-pipe-line-p token)
        (return-from check-rz-cli "omp-re: rizin_cli: an argument contains a line break or NUL"))
      (when (member token (rz-cli-denied-tokens definition) :test #'string=)
        (return-from check-rz-cli
          (format nil "omp-re: rizin_cli: ~a ~a is not allowed here (it writes, runs code, or fetches over the network)"
                  tool token)))
      (when (short-cluster-p token)
        (loop for char across (subseq token 1)
              do (when (find char (rz-cli-denied-letters definition))
                   (return-from check-rz-cli
                     (format nil "omp-re: rizin_cli: ~a -~a is not allowed here (it writes a file, runs code, fetches over the network, or opens an interactive view)"
                             tool char)))
                 (when (find char (rz-cli-denied-repeated-letters definition))
                   (let ((seen (assoc char repeats)))
                     (if seen
                         (incf (cdr seen))
                         (setf repeats (append repeats (list (cons char 1))))))))))
    (loop for (char . count) in repeats
          do (when (>= count 2)
               (return-from check-rz-cli
                 (format nil "omp-re: rizin_cli: ~a -~a given ~d times fetches over the network (a single -~a reads locally and is allowed)"
                         tool char count char))))
    (loop for (flag . refused) in (rz-cli-denied-flag-values definition)
          do (dolist (value (rz-cli-flag-values arguments (char flag 0)))
               (when (member value refused :test #'string=)
                 (return-from check-rz-cli
                   (format nil "omp-re: rizin_cli: ~a -~a ~a is not allowed here (it runs a command, which can reach the shell)"
                           tool flag value)))))
    nil))

(defun available-rz-cli-tools ()
  "The rz-* programs installed beside rizin: they ship together, but a
minimal build may lack some. Asked each time, so one installed later is seen."
  (remove-if-not (lambda (definition) (program-available-p (resolve-rizin-tool (rz-cli-tool definition))))
                 +rz-cli-tools+))

(define-tool "rizin_cli"
    (:label "rizin CLI" :tier :exec
     :reason (list "Run " (approval-slot '(("tool" :missing "?") ("args" :prefix " ")) :clip 160) ".")
     :render '(:subject "tool")
     :description "Run one of rizin's standalone command-line tools (rz-bin, rz-diff, rz-hash, rz-find, rz-asm, rz-ax) with its own arguments, for analysis the in-core tools don't cover: quick binary info without full analysis, diffing two binaries, hashing and entropy, raw pattern search, standalone (dis)assembly, and base conversion. Argv only, no shell. Flags that write files, run code, fetch over the network, or open interactive views are refused. Pass `args: [\"-h\"]` for a tool's full help."
     ;; A tool that cannot run is worse than an absent one.
     :available (lambda () (and (available-rz-cli-tools) t)))
    (("tool" :string :required t :enum (mapcar #'rz-cli-tool +rz-cli-tools+)
      :doc (format nil "Which rizin CLI tool to run. ~a"
                   (join-lines (mapcar (lambda (definition)
                                         (format nil "~a: ~a" (rz-cli-tool definition) (rz-cli-summary definition)))
                                       +rz-cli-tools+))))
     ("args" :strings :required t
      :doc "The tool's own arguments as a list (no shell). Use `@binary` for the open binary's path; rz-bin uses it automatically. Pass `[\"-h\"]` for the tool's full help."))
    (arguments)
  (let* ((name (jstring arguments "tool"))
         (given (jlist arguments "args"))
         (definition (find name (available-rz-cli-tools) :key #'rz-cli-tool :test #'string=)))
    (unless definition
      (fail "omp-re: rizin_cli: unknown tool ~a" (js-string name)))
    (let ((refusal (check-rz-cli definition given)))
      (when refusal (fail "~a" refusal)))
    ;; @binary is substituted in place, and a binary-oriented tool gets the
    ;; open binary appended when the model did not place it.
    (let* ((placed (member +binary-placeholder+ given :test #'string=))
           (opens (eq :open (rz-cli-target definition)))
           (binary (and (or placed opens) (require-binary)))
           (argv (append (mapcar (lambda (argument)
                                   (if (string= argument +binary-placeholder+) binary argument))
                                 given)
                         (and opens (not placed) (list binary))))
           (header (trimmed (format nil "~a ~{~a~^ ~}" name argv))))
      (multiple-value-bind (out err)
          (run-program (cons (resolve-rizin-tool name) argv) :seconds +rz-cli-seconds+)
        ;; On Windows these end lines with CRLF; one line ending is what is read.
        (let ((stdout (string-right-trim '(#\Newline) (replace-all out (format nil "~c~c" #\Return #\Newline)
                                                                    (string #\Newline)))))
          (if (string= stdout "")
              ;; Many of these say "no match" or "no difference" with a
              ;; non-zero exit and nothing printed; only stderr is an error.
              (let ((said (trimmed (replace-all err (format nil "~c~c" #\Return #\Newline) (string #\Newline)))))
                (if (blank-p said)
                    (plain-result (format nil "~a~%(no output)" header))
                    (failed-result (format nil "~a~%(no output; ~a said:)~%~a" header name said))))
              (text-result header stdout :tool "rizin_cli")))))))

;;; --- external triage -----------------------------------------------------------------------
;;; capa, floss, Detect It Easy and yara, each run by argv against the open
;;; binary and offered only while its program is on PATH: an offered tool
;;; that always fails is worse than an absent one. PATH is asked each time, so
;;; a scanner installed while the organism runs is offered from then on. Each
;;; answers the findings themselves — rule names, strings, detections — not a
;;; count.

(defun resolve-existing-file (label value)
  "VALUE resolved to an existing, readable file, or the refusal naming LABEL."
  (or (resolve-readable-file value)
      (fail "omp-re: invalid ~a: ~a" label value)))

(defun capa-findings (parsed)
  "Each matched rule's name with its ATT&CK/MBC mapping. capa's top-level
`rules' is a map keyed by rule name, not an array."
  (let ((rules (and (hash-table-p parsed) (gethash "rules" parsed))))
    (and (hash-table-p rules)
         (coerce (loop for name being the hash-keys of rules using (hash-value rule)
                       collect (obj "name" name
                                    "meta" (if (hash-table-p rule)
                                               (multiple-value-bind (meta present) (gethash "meta" rule)
                                                 (if present meta :absent))
                                               :absent)))
                 'simple-vector))))

(defun floss-findings (parsed)
  "The decoded, stack and static strings themselves."
  (let ((strings (and (hash-table-p parsed) (gethash "strings" parsed))))
    (and (hash-table-p strings)
         (let ((found (obj)))
           (dolist (key '("stack_strings" "decoded_strings" "static_strings") found)
             (multiple-value-bind (value present) (gethash key strings)
               (when present (setf (gethash key found) value))))))))

(defun die-findings (parsed)
  "The per-scan detections."
  (let ((scans (and (hash-table-p parsed) (gethash "scans" parsed))))
    (and (vectorp scans) (not (stringp scans)) scans)))

(defun triage-failed-p (out status)
  "Whether a scanner never ran at all. Its exit code alone is advisory — capa
and yara answer \"no matches\" with a non-zero one — but nothing printed and a
non-zero exit must not read as \"0 findings\"."
  (and (not (eql status 0)) (blank-p out)))

(defun triage-exit (status)
  (if (eq status :timeout) "timeout" status))

(defun run-plain-triage (name program seconds finder)
  "Run PROGRAM -j on the open binary and answer what FINDER takes from its JSON."
  (let ((file (resolve-existing-file "file" (require-binary)))
        (tool (format nil "triage_~a" name)))
    (multiple-value-bind (out err status) (run-program (list program "-j" file) :seconds seconds)
      (when (triage-failed-p out status)
        (fail "omp-re: ~a failed (exit ~a): ~a" name (triage-exit status)
              (if (blank-p err) "no output" (trimmed err))))
      (multiple-value-bind (parsed decoded)
          (handler-case (values (json-decode out) t)
            (error () (values nil nil)))
        (if (not decoded)
            (text-result (format nil "~a: output was not valid JSON (schema not recognized)" name) out :tool tool)
            (let ((findings (funcall finder parsed)))
              (if (null findings)
                  (text-result (format nil "~a: expected JSON shape not found" name) out :tool tool)
                  (json-result (format nil "~a: ~d finding group(s)" name
                                       (if (hash-table-p findings) (hash-table-count findings) (length findings)))
                               findings :tool tool))))))))

(define-tool "triage_capa"
    (:label "Triage: capa" :tier :exec
     :reason "Run capa against the open binary."
     :render '(:body :json)
     :description "Run capa rules against the binary to detect capabilities and ATT&CK techniques."
     :available (lambda () (program-available-p "capa")))
    ()
    (arguments)
  (run-plain-triage "capa" "capa" 300 #'capa-findings))

(define-tool "triage_floss"
    (:label "Triage: floss" :tier :exec
     :reason "Run floss against the open binary."
     :render '(:body :json)
     :description "Extract obfuscated strings (stack, decoded, static) from the binary using FLOSS."
     :available (lambda () (program-available-p "floss")))
    ()
    (arguments)
  (run-plain-triage "floss" "floss" 600 #'floss-findings))

;; Detect It Easy's console program is diec; the tool keeps the short name.
(define-tool "triage_die"
    (:label "Triage: die" :tier :exec
     :reason "Run diec against the open binary."
     :render '(:body :json)
     :description "Detect packers, compilers, and file types using Detect It Easy."
     :available (lambda () (program-available-p "diec")))
    ()
    (arguments)
  (run-plain-triage "die" "diec" 60 #'die-findings))

(defun parse-yara-matches (stdout)
  "yara's plain output, `<rule> <file>' a line — it has no JSON mode — as an
array of objects. A line with no space (a warning) is skipped, not misread."
  (coerce (loop for raw in (split-lines stdout)
                for line = (trimmed raw)
                for space = (position #\Space line)
                when space
                  collect (obj "rule" (subseq line 0 space) "file" (trimmed (subseq line (1+ space)))))
          'simple-vector))

(define-tool "triage_yara"
    (:label "Triage: yara" :tier :exec
     :reason (list "Run yara with rules " (approval-slot '(("rules_path" :missing "?"))) " against the open binary.")
     :render '(:subject "rules_path" :body :json)
     :description "Scan the binary with user-supplied YARA rules."
     :available (lambda () (program-available-p "yara")))
    (("rules_path" :string :required t :doc "Path to a YARA rules file."))
    (arguments)
  (when (blank-p (jstring arguments "rules_path"))
    (fail "omp-re: yara: rules_path argument is required (no default ruleset ships)"))
  (let ((file (resolve-existing-file "file" (require-binary)))
        (rules (resolve-existing-file "rules_path" (jstring arguments "rules_path"))))
    (multiple-value-bind (out err status) (run-program (list "yara" rules file) :seconds 120)
      ;; A rules file that failed to compile must not read as "0 rules
      ;; matched": that would be a false all-clear from a security tool.
      (when (triage-failed-p out status)
        (fail "omp-re: yara failed (exit ~a): ~a" (triage-exit status)
              (if (blank-p err) "no output" (trimmed err))))
      (let ((matches (parse-yara-matches out)))
        (json-result (format nil "yara: ~d rule(s) matched" (length matches)) matches :tool "triage_yara")))))

;;; --- rizin_emulate -------------------------------------------------------------------------
;;; rizin's RzIL VM (the aez family; ESIL's ae* is deprecated upstream). The
;;; VM is stateful but contained: it interprets the target's code inside the
;;; static rizin session and no OS process runs. `aezi @ addr' starts it
;;; without moving the session's seek, so no other tool is disturbed.

(defun validate-vm-variable (name)
  "NAME when it is a VM variable's name (PC, rsp, rax, zf, xmm0): rizin
refuses anything else anyway, and refusing here keeps the message ours."
  (unless (plain-name-p name)
    (fail "omp-re: emulate: bad variable name ~a — use a name from the vars action" (js-string name)))
  name)

(defun validate-vm-value (value)
  "VALUE when it is a decimal or 0x hex number, the forms `aezv' takes."
  (unless (number-text-p value)
    (fail "omp-re: emulate: bad value ~a — use a decimal or 0x hex number" (js-string value)))
  value)

(defun validate-emulate-hex (value)
  "VALUE as the lowercase hex `wx' wants: an even number of digits, an
optional 0x taken off."
  (let ((hex (if (js-scan "^0[xX]" value) (subseq value 2) value)))
    (unless (and (plusp (length hex)) (evenp (length hex)) (js-scan "^[0-9a-fA-F]+$" hex))
      (fail "omp-re: emulate: bad bytes ~a — use an even number of hex digits, e.g. 41424344" (js-string value)))
    (string-downcase hex)))

(defun emulate-approval-reason ()
  '(:cases
    ((("action" "init")) "Set up the RzIL emulation state (no OS process runs — the code is interpreted inside rizin).")
    ((("action" "set_var")) "Set up the RzIL emulation state (no OS process runs — the code is interpreted inside rizin).")
    ((("action" "set_mem")) "Seed the RzIL VM's memory image (an io.cache overlay in memory — nothing is written to the file on disk).")
    ((("action" "step")) "Run the target's code logic inside rizin's RzIL VM (interpreted, no OS process).")
    ((("action" "step_until")) "Run the target's code logic inside rizin's RzIL VM (interpreted, no OS process).")
    ((("action" "vars")) "Read the RzIL VM state.")
    (() "Drive the RzIL emulation.")))

(define-tool "rizin_emulate"
    (:label "emulator" :tier :exec
     :reason (emulate-approval-reason)
     :render '(:subject "action")
     :description "Emulate code with rizin's RzIL VM: init at an address, step instructions and watch register/flag changes, step until an address, read and set VM variables, and seed the VM's memory (set_mem) so a routine can read an input buffer. No process runs — the target's logic is interpreted inside rizin, and the VM state lives in the analysis session (init resets registers; set_mem writes an in-memory overlay that persists and never touches the file on disk). External calls and syscalls are not emulated; keep runs small (a decryptor loop, an argument computation). To execute the real process instead, use the debugger tool.")
    (("action" :string :required t :enum '("init" "step" "step_until" "vars" "set_var" "set_mem")
      :doc (join-lines
            '("init: (re)start the RzIL VM at `addr` (required) — does not seek the session."
              "step: run `count` instructions (default 1), returning the VM change events (register/flag/PC writes)."
              "step_until: run until PC equals `addr` (required)."
              "vars: full VM state (registers, flags, PC) as JSON."
              "set_var: set VM variable `name` to `value` (e.g. the stack pointer before stepping)."
              "set_mem: write `bytes` (hex) into the VM's memory at `addr` — seed an input buffer a routine reads. In-memory overlay, never the file.")))
     ("addr" :string :doc "Address or symbol for init / step_until / set_mem.")
     ("count" :number :doc "Instruction count for step (default 1).")
     ("name" :string :doc "VM variable name for set_var (from the vars action).")
     ("value" :string :doc "Number (decimal or 0x hex) for set_var.")
     ("bytes" :string :doc "Hex bytes for set_mem, e.g. 41424344 — seeds the VM memory image at addr (must be a mapped address: a .data/.bss buffer or the VM stack region)."))
    (arguments)
  (let ((rz (ensure-rizin))
        (action (jstring arguments "action"))
        (addr (jstring arguments "addr")))
    (flet ((vm-state () (trimmed (rz-cmd rz "aezvj")))
           (answer (header body) (text-result header body :tool "rizin_emulate")))
      (cond
        ((string= action "init")
         (unless addr (fail "omp-re: emulate init needs addr"))
         (let ((ea (validate-addr addr)))
           (rz-cmd rz (format nil "aezi @ ~a" ea))
           (let ((vars (vm-state))
                 (note (rizin-bits-mismatch (require-binary))))
             (answer (format nil "emulate: VM initialized at ~a" ea)
                     (format nil "~@[~a~%~]~a" note (if (blank-p vars) "(no VM state)" vars))))))
        ((string= action "step")
         (let* ((count (clamped-count (jget arguments "count") 1 1000))
                (out (trimmed (rz-cmd rz (format nil "aezsej ~d" count) :seconds (dynamic-seconds)))))
           (answer (format nil "emulate: step ~d" count)
                   (if (blank-p out) "(no changes — init the VM first)" out))))
        ((string= action "step_until")
         (unless addr (fail "omp-re: emulate step_until needs addr"))
         (let ((ea (validate-addr addr)))
           (rz-cmd rz (format nil "aezsu ~a" ea) :seconds (dynamic-seconds))
           (let ((vars (vm-state)))
             (answer (format nil "emulate: step_until ~a" ea)
                     (if (blank-p vars) "(no VM state — the run may have stalled)" vars)))))
        ((string= action "vars")
         (let ((vars (vm-state)))
           (answer "emulate: vars" (if (blank-p vars) "(no VM state — init first)" vars))))
        ((string= action "set_var")
         (unless (and (jstring arguments "name") (jstring arguments "value"))
           (fail "omp-re: emulate set_var needs name and value"))
         (let* ((name (validate-vm-variable (jstring arguments "name")))
                (value (validate-vm-value (jstring arguments "value")))
                ;; The set form echoes the assignment ("rsp = 0x7ff000"); the
                ;; bare print form is empty in practice, so the echo is used.
                (out (trimmed (rz-cmd rz (format nil "aezv ~a ~a" name value)))))
           (answer (format nil "emulate: set_var ~a" name)
                   (if (blank-p out) (format nil "~a set" name) out))))
        ((string= action "set_mem")
         (unless (and addr (jstring arguments "bytes"))
           (fail "omp-re: emulate set_mem needs addr and bytes"))
         (let ((ea (validate-addr addr))
               (hex (validate-emulate-hex (jstring arguments "bytes"))))
           ;; The static session's IO is file-backed and read-only; io.cache
           ;; overlays the write in memory so the VM reads it and the file is
           ;; never touched (the cache is never committed). It stays on so
           ;; the seed survives across init and step calls.
           (rz-cmd rz "e io.cache=true")
           (let ((err (trimmed (nth-value 1 (rz-run rz (format nil "wx ~a @ ~a" hex ea))))))
             (if (not (blank-p err))
                 (as-failure (answer (format nil "emulate: set_mem @ ~a" ea)
                                      (format nil "wx ~a @ ~a: ~a" hex ea err)))
                 (let* ((size (/ (length hex) 2))
                        (back (trimmed (rz-cmd rz (format nil "pxj ~d @ ~a" size ea)))))
                   (answer (format nil "emulate: set_mem ~d byte(s) @ ~a" size ea)
                           (if (blank-p back) "(wrote; no readback)" back)))))))
        (t (fail "omp-re: emulate: unknown action ~a" (js-string action)))))))

;;; --- putting the record back on a fresh process ----------------------------------------------
;;; Mapped files bring address space, analysis passes find functions in it,
;;; signatures name the functions that now exist; the annotations (order 60)
;;; are the analyst's edits on top of all three.

(contribute "mapped files" :order 10 :noun "mapped file(s)" :replay #'replay-map-files)
(contribute "analysis passes" :order 20 :noun "analysis pass(es)" :replay #'replay-analysis-passes)
(contribute "signatures" :order 30 :noun "signature file(s)" :replay #'replay-signatures)
