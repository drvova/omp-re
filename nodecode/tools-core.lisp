;;;; tools-core.lisp --- open a binary, read it, and the /re command.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Ported from omp-re's index.ts (open_binary, /re, the status text),
;;;; tools-rizin.ts (rizin_help, rizin_command) and decompile.ts (which
;;;; decompiler this rizin has). rizin_command is the one way to read the
;;;; binary, and the one tool whose results are evidence.

(in-package #:nodecode-re)

;;; --- open ----------------------------------------------------------------------------------

(defun load-object (arguments)
  "The load settings in a tool's ARGUMENTS as their own object, or NIL when
none were given and rizin should autodetect from the header."
  (let ((load (obj)))
    (dolist (key '("arch" "bits" "base" "map" "format"))
      (multiple-value-bind (value present) (gethash key arguments)
        (when present (setf (gethash key load) value))))
    (and (plusp (hash-table-count load)) load)))

(defun missing-commands-warning (missing)
  (format nil "Warning: this rizin build lacks ~{~a~^, ~}, which omp-re's tools send; the tools that use them will fail. Upgrade rizin (omp-re is tested with 0.9.1)."
          missing))

(defun open-binary (path &key load (session *session*))
  "Open the binary at PATH for SESSION: hash its bytes, spawn and analyze a
fresh rizin, replay what the record holds for this binary, and record the
choice so a later start restores it => the text that says what happened."
  (let* ((resolved (resolve-binary-path path))
         ;; Bound into every evidence record taken from here on, so /re verify
         ;; knows it re-runs against the same bytes. A hash failure degrades to
         ;; an unbound session, it never blocks the open.
         (sha256 (ignore-errors (sha256-file resolved)))
         (failures (nth-value 1 (spawn-rizin resolved :load load :session session)))
         (replayed (if *live-annotations*
                       (length (funcall *live-annotations* resolved session))
                       0))
         (missing (ignore-errors (missing-required-commands (load-catalog)))))
    (setf (session-binary-sha256 session) sha256)
    (append-entry "re.binary"
                  (obj "path" resolved "load" (or load :absent) "sha256" (or sha256 :absent))
                  session)
    (join-lines
     (append (list (format nil "Binary opened: ~a" resolved))
             (when load
               (list (format nil "Loaded with forced settings (~{~a~^, ~})."
                             (loop for key being the hash-keys of load using (hash-value value)
                                   collect (format nil "~a=~a" key value)))))
             (when (plusp replayed)
               (list (format nil "Re-applied ~d of ~d annotation(s) recorded earlier for this binary."
                             (max 0 (- replayed (length failures))) replayed)))
             (mapcar (lambda (failure) (format nil "  could not re-apply ~a" failure)) failures)
             (when missing (list (missing-commands-warning missing)))))))

(define-tool "open_binary"
    (:label "Open binary" :tier :read
     :description "Open a binary for analysis in this session's rizin backend and run full analysis (aaa). Every other RE tool (rizin_command, rizin_cli, the annotate tools, ...) acts on whichever binary was most recently opened here — call this first. For a raw/headerless target (flat shellcode, firmware, a ROM dump) pass arch/bits/base/format so rizin loads it correctly instead of autodetecting from a header it doesn't have.")
    (("path" :string :required t :doc "Path to the binary file to open.")
     ("arch" :string :doc "Force the architecture for a raw/headerless target (rizin -a), e.g. x86, arm, mips. Omit for a normal file with a header.")
     ("bits" :integer :enum '(8 16 32 64) :doc "Force the word size (rizin -b): 8, 16, 32, or 64. Pair with arch for flat shellcode.")
     ("base" :string :doc "Rebase a formatted image (PE/ELF) at this address (rizin -B), e.g. 0x400000. For a raw/headerless file use `map` instead.")
     ("map" :string :doc "Map a raw/flat file at this address (rizin -m), e.g. 0x400000 — the right option for headerless shellcode or firmware dumps.")
     ("format" :string :doc "Force the bin plugin (rizin -F), e.g. elf, pe, mach0, or `any` to open raw bytes with no format."))
    (arguments)
  (plain-result (open-binary (jstring arguments "path") :load (load-object arguments))))

;;; --- the one directory the engine writes files to --------------------------------------------
;;; Ported from output.ts. The engine never writes to the sample on disk. A
;;; few tools must emit a separate file — a project, a signature file, a dump
;;; of a live process's memory. Those go here and nowhere else: one dedicated
;;; directory, never a path the model chose, so a tool cannot traverse out of
;;; it or overwrite an arbitrary file.

(defun output-directory ()
  "OMPRE_OUTPUT_DIR when set, else omp-re-out under the system's temporary directory."
  (uiop:ensure-directory-pathname
   (let ((configured (env "OMPRE_OUTPUT_DIR")))
     (if configured
         (merge-pathnames (uiop:parse-native-namestring configured) (uiop:getcwd))
         (merge-pathnames "omp-re-out/" (uiop:temporary-directory))))))

(defun safe-basename (name)
  "NAME when it is a bare file name of safe characters: no separator, no
`..', not absolute. This is the guard that keeps a chosen name inside the
output directory."
  (let ((name (trimmed name)))
    (when (member name '("" "." "..") :test #'string=)
      (fail "omp-re: invalid output filename ~a" (js-string name)))
    (unless (and (ppcre:scan "^[A-Za-z0-9._-]+$" name) (not (search ".." name)))
      (fail "omp-re: invalid output filename ~a — use a bare name of letters, digits, '.', '_' or '-' (no path separators)"
            (js-string name)))
    name))

(defun to-rizin-path (path)
  "PATH with forward slashes, which rizin accepts on every platform."
  (substitute #\/ #\\ (if (stringp path) path (native path))))

(defun rizin-path-arg (path)
  "PATH as one single-quoted rizin argument, so rizin takes every byte of it
literally — a `~' in a Windows short name is otherwise its grep operator."
  (rz-quote (to-rizin-path path)))

(defun prepare-output-path (basename)
  "The native path for BASENAME inside the output directory, which is created."
  (let* ((directory (output-directory))
         (full (merge-pathnames (safe-basename basename) directory)))
    (ensure-directories-exist full)
    (native full)))

(defun rizin-output-path (basename)
  "Like PREPARE-OUTPUT-PATH, for a file rizin itself writes: the path must
survive the pipe, and the one thing quoting cannot carry is a line break."
  (let ((full (prepare-output-path basename)))
    (when (find-if (lambda (char) (member char '(#\Newline #\Return #\Nul))) full)
      (fail "omp-re: the output path ~a contains a line break or NUL" (js-string full)))
    full))

(defun output-subdirectory (basename &optional create)
  "The native path of the folder BASENAME inside the output directory, made
when CREATE."
  (let ((full (uiop:ensure-directory-pathname
               (merge-pathnames (safe-basename basename) (output-directory)))))
    (when create (ensure-directories-exist full))
    (string-right-trim "/" (native full))))

;;; --- rizin_help and rizin_command -----------------------------------------------------------

(defparameter +rizin-command-seconds+ 120)

(defparameter +manual+
  "omp-re — reverse engineering with rizin, driven from code.

You observe the binary by running rizin's own commands through one tool,
rizin_command, which eval reaches as (re:cmd \"command\" &optional addr), or as
(re:json \"command\" &optional addr) for a *j command's decoded data. Define
helpers in eval and reuse them: what you define there stays.

Start here
  1. (re:open \"/path/to/binary\")        — spawn rizin + analyze (aaa).
     Every command acts on the binary opened last in this session.
  2. (re:call \"rizin_help\" :query \"<prefix or keywords>\")  — find the command
     (e.g. \"entropy\", \"call graph\", \"pdf\") and its exact arguments for THIS rizin.
  3. (re:cmd \"aflj\")                     — run it. Put an address in the second
     argument (sent as `@ addr`), never `@` in the command.

Reading the binary (prefer the JSON `*j` forms; they canonicalize for /re verify)
  functions   aflj            one function  afij  @ <fn>     decompile  pdg  @ <fn>  (or pdd)
  disassemble pdfj  @ <fn>     xrefs to      axtj @ <addr>   xrefs from axfj @ <addr>
  strings     izj              imports       iij             exports    iEj
  symbols     isj              sections      iSj             headers    iHj
  types       tsj              entropy       ph entropy      hexdump    px <n> @ <addr>
  search      /xj <hex>  /Rj (ROP)  /vj (value)             info       ij
  il lift     aoj @ <addr>  (esil+rzil)  esil calc  ae <rpn>  (ae 0x41,0x13,^)
  Anything else: rizin_help first, then rizin_command. Read-only; writes are refused here.
  Driving the RzIL VM (stateful) is the separate rizin_emulate tool.

How a result reads
  A read is recorded as evidence, so its text is: the header line (rizin> <cmd>),
  the body (JSON for a *j command), then a trailing [evidence …] tag line.
  (re:json …) parses the body for you and answers the evidence id as its second
  value. A big list (aflj, izj on a large binary) is cut at the size cap and ends
  with [Output truncated … Full output: <file>]: (re:json …) reads that file
  itself; otherwise read it, or run a narrower command.

The other (stateful) tools — (re:call \"<name>\" :key value …); (re:tools) lists
them and (re:doc \"<name>\") shows one's arguments
  open_binary, map_file, export_project            — session: open/overlay/save.
  rename_function, rename_variable, set_comment, set_prototype, set_variable_type,
  define_function, define_global, set_flag, set_calling_convention, set_arch_hint, …
                                                   — annotate; recorded and REPLAYED on restart.
  apply_signatures, create_signature               — FLIRT.        analyze — extra recovery passes.
  record_finding, adopt_finding, retract_finding   — gate report claims on evidence ids.
  rizin_cli                                        — the rz-* programs (rz-bin, rz-diff, rz-hash, …).
  triage_capa/floss/die/yara                       — external triage (present only when installed).
  rizin_debug (opt-in, executes the sample), rizin_emulate (RzIL)  — dynamic analysis.

Evidence & reports
  Every rizin_command read is recorded as evidence ((re:slash \"evidence\")); cite its
  [evidence xxxxxxxx] id in record_finding to gate a claim. (re:slash \"report\") writes
  the evidence-gated report; (re:slash \"verify\") re-runs cited commands to confirm they
  still reproduce.

Config
  the re section of config.jsonc (rizin_path, debugger, state_dir) ·
  OMPRE_DECOMPILER (pdg/pdd order) · OMPRE_AUDIT_HMAC_KEY.  (re:status) for live state."
  "What rizin_command answers for an empty command: usable before any binary is open.")

(defun clean-stderr (stderr)
  "rizin's stderr with terminal control sequences removed: a search redraws a
progress line there and leaves a bare clear-line escape behind when it finds
nothing, which is not an error message."
  (join-lines
   (remove-if #'blank-p
              (mapcar (lambda (line) (string-right-trim '(#\Space #\Tab) line))
                      (split-lines
                       (substitute #\Newline #\Return
                                   (ppcre:regex-replace-all +ansi-escape+ stderr "")))))))

(defun run-rizin-command (command addr &optional (session *session*))
  "The body of rizin_command: gate the line through the read-only policy,
run it, and build the result with its reproducibility fields. /re carry
re-runs a carried command through this, so it is recorded as the tool would."
  ;; No binary is said before the catalog is read, so the guidance needs no rizin.
  (let ((binary-path (require-binary session)))
    (let* ((line (check-rizin-command (load-catalog) command addr))
           (rz (ensure-rizin session))
           (ea (and addr (ignore-errors (ea-from-offset (resolve-numeric-addr rz addr)))))
           (header (format nil "rizin> ~a" line)))
      (multiple-value-bind (output stderr) (rz-run rz line :seconds +rizin-command-seconds+)
        (if (blank-p output)
            (let ((errors (clean-stderr stderr)))
              (if (plusp (length errors))
                  (failed-result (format nil "~a~%(no output; rizin said:)~%~a" header errors) ea)
                  (plain-result (format nil "~a~%(no output)" header) ea)))
            ;; The hashes are over the RAW output, canonicalized and bound to
            ;; the binary's path, so /re verify can re-run this exact line and
            ;; compare; what the model reads is still the trimmed, cut text.
            (text-result header (string-right-trim '(#\Newline) output)
                         :ea ea :tool "rizin_command" :commands (list line)
                         :repro-hash (canonical-hash output binary-path)
                         :canonical-excerpt (canonical-excerpt output binary-path)
                         :shift-hash (shift-hash output binary-path)))))))

(define-tool "rizin_help"
    (:label "rizin help" :tier :read
     :description "Look up rizin commands in the installed rizin's own help: the usage, typed arguments, and summary of a command or command family, or a keyword search across every command. Each entry says whether rizin_command can run it. Use before rizin_command when unsure of a command or its arguments.")
    (("query" :string :required t :doc "A command or prefix (`pd`, `afv`, `/R`, `ph`) for its usage and arguments, or keywords (`entropy`, `rop gadgets`, `call graph`) to find commands."))
    (arguments)
  (multiple-value-bind (header lines) (search-catalog (load-catalog) (jstring arguments "query"))
    (text-result header (join-lines lines) :tool "rizin_help")))

(define-tool "rizin_command"
    (:label "rizin command" :tier :exec :evidence t
     :description "omp-re's primary way to read a binary: run one read-only rizin command against the open binary and compose calls in eval. This is how you list functions (aflj), decompile (pdg/pdd), read strings/imports/exports/symbols/sections (izj, iij, iej, isj, iSj), xrefs (axtj, axfj), types (tsj), headers (iHj), hexdumps (px), entropy (ph entropy), and run byte/string/ROP searches (/xj, /Rj) — plus the rest of rizin's print, info, search, graph, and listing commands. Prefer the JSON `*j` forms. Commands that write, set config, open files, run shell commands, or change analysis are refused; annotate with the dedicated tools instead. Call rizin_help first for a command's exact arguments. Pass an empty command for the omp-re manual (needs no open binary).")
    (("command" :string :required t :doc "One read-only rizin command with its arguments, e.g. `aflj`, `pdg`, `izj`, `agc ascii`, `px 64`, `/xj 4889e5`, `ph entropy 4096`. No `;`, `|`, `>`, `@`, or `~`. Pass an empty string to get the omp-re manual.")
     ("addr" :string :doc "Address or name to run the command at (sent as `@ <addr>`)."))
    (arguments)
  (if (blank-p (jstring arguments "command"))
      ;; The manual observes nothing, so it must not be recorded as evidence.
      (let ((result (text-result "omp-re manual" +manual+)))
        (setf (gethash "manual" (result-details result)) t)
        result)
      (run-rizin-command (jstring arguments "command") (jstring arguments "addr"))))

;;; --- which decompiler this rizin has ----------------------------------------------------------

(defun decompiler-commands ()
  "The decompiler commands to probe, OMPRE_DECOMPILER's first."
  (remove-duplicates
   (append (remove-if-not (lambda (name) (ppcre:scan "^[a-zA-Z][a-zA-Z0-9]*$" name))
                          (mapcar #'trimmed
                                  (uiop:split-string (or (env "OMPRE_DECOMPILER") "") :separator '(#\,))))
           (list "pdg" "pdd"))
   :test #'string= :from-end t))

(defun decompiler-label (kind)
  (cond ((equal kind "pdg") "rz-ghidra (pdg)")
        ((equal kind "pdd") "jsdec (pdd)")
        (kind (format nil "~a (plugin)" kind))
        (t "none — pdg/pdd fall back to labeled disassembly")))

(defun resolve-decompiler (rz)
  "The first decompiler command RZ answers for, asked once per process, or NIL."
  (when (eq (rz-decompiler rz) :unknown)
    (setf (rz-decompiler rz)
          (find-if (lambda (command)
                     (let ((reply (trimmed (rz-cmd rz (format nil "~a?" command)))))
                       (and (plusp (length reply))
                            (not (search "does not exist" reply))
                            (not (starts-with "ERROR" reply)))))
                   (decompiler-commands))))
  (rz-decompiler rz))

(defvar *debugger-setting* nil
  "A function answering the cell's `debugger' setting, or NIL. Set by the cell at start.")

(defun debugger-enabled-p ()
  "Whether dynamic analysis — which executes the sample — was switched on:
the cell's debugger setting, or OMPRE_ENABLE_DEBUGGER."
  (or (and *debugger-setting* (funcall *debugger-setting*) t)
      (env-on-p "OMPRE_ENABLE_DEBUGGER")))

;;; --- /re ---------------------------------------------------------------------------------------

(defvar *slash-commands* '()
  "The /re subcommands: (NAME USAGE DESCRIPTION FUNCTION), in the order
defined. FUNCTION takes the words after the subcommand and answers the text,
or (values TEXT T) for a line that failed.")

(defmacro define-slash (name (&key usage description) (words) &body body)
  "Define the /re subcommand NAME; the body runs with WORDS bound to the
words after it, *SESSION* to the session, holding the session's lock."
  `(progn
     (setf *slash-commands*
           (append (remove ,name *slash-commands* :key #'first :test #'string=)
                   (list (list ,name ,usage ,description
                               (lambda (,words) (declare (ignorable ,words)) ,@body)))))
     ,name))

(defparameter *slash-order*
  '("open" "functions" "strings" "imports" "evidence" "cite" "findings" "undo" "report" "verify"
    "carry" "status" "on" "off" "help")
  "The order /re help lists the subcommands in: omp-re's own.")

(defun slash-help ()
  (join-lines
   (loop for entry in (sort (copy-list *slash-commands*) #'<
                            :key (lambda (entry)
                                   (or (position (first entry) *slash-order* :test #'string=) 99)))
         collect (destructuring-bind (name usage description function) entry
                   (declare (ignore function))
                   (format nil "/re ~22a ~a" (format nil "~a~@[ ~a~]" name usage) description)))))

(defun run-slash-line (session line)
  "One /re LINE for SESSION => (values TEXT FAILED-P)."
  (let* ((words (words line))
         (name (string-downcase (or (first words) "help")))
         (entry (find name *slash-commands* :key #'first :test #'string=)))
    (if (null entry)
        (values (format nil "omp-re: unknown /re subcommand ~a — try /re help" (js-string name)) t)
        (handler-case
            (with-session (session)
              (multiple-value-bind (text failed) (funcall (fourth entry) (rest words))
                (values (or text "(done)") failed)))
          (re-error (condition)
            (values (princ-to-string condition) t))
          (error (condition)
            (values (format nil "omp-re: /re ~a failed: ~a" name condition) t))))))

(defun rest-of-line (words)
  (format nil "~{~a~^ ~}" words))

(define-slash "help" (:description "show this list") (words)
  (slash-help))

(define-slash "open" (:usage "<path>" :description "open a binary and analyze it with rizin") (words)
  (if (null words)
      (values "Usage: /re open <path>" t)
      (open-binary (rest-of-line words))))

(define-slash "on" (:description "enable the RE tools for this session") (words)
  (setf (session-tools-off *session*) nil)
  "omp-re: RE tools enabled for this session")

(define-slash "off" (:description "disable the RE tools for this session") (words)
  (setf (session-tools-off *session*) t)
  "omp-re: RE tools disabled for this session — /re on to re-enable")

(defvar *status-lines* '()
  "Functions of no arguments, each answering a list of status lines, called
in order after the core's: how a tool group says its own state.")

(define-slash "status" (:description "rizin, decompiler, binary, and evidence status") (words)
  (let* ((session *session*)
         (version (rizin-version))
         (catalog (ignore-errors (load-catalog))))
    (join-lines
     (append
      (list (format nil "rizin: ~a" (or version (format nil "not found (~a)" (resolve-rizin-path)))))
      (when catalog
        (let ((missing (missing-required-commands catalog))
              (present (remove-if-not (lambda (command) (nth-value 1 (gethash command catalog)))
                                      (decompiler-commands))))
          (append
           (list (if missing
                     (missing-commands-warning missing)
                     (format nil "rizin commands: all ~d omp-re sends are present (~d in this build; rizin_help searches them)"
                             (length +required-commands+) (hash-table-count catalog)))
                 (format nil "decompiler: ~a" (decompiler-label (first present))))
           (when (rest present)
             (list (format nil "  also available: ~{~a~^, ~} (reorder with OMPRE_DECOMPILER)"
                           (mapcar #'decompiler-label (rest present))))))))
      (if (session-binary-path session)
          (append (list (format nil "binary: ~a" (session-binary-path session)))
                  (unless (rz-alive-p (session-rz session))
                    (list "rizin process: not running (starts on next use)")))
          (list "binary: none — /re open <path>"))
      (list (if (debugger-enabled-p)
                (format nil "debugger: enabled~:[ (the re section's debugger setting); executes the sample~; — a process is running under it~]"
                        (rz-alive-p (session-dbg session)))
                "debugger: off (set the re section's debugger to true to enable dynamic analysis — it executes the sample)"))
      (list (format nil "evidence on this branch: ~d" (length (evidence-records session))))
      (loop for lines in *status-lines* append (funcall lines))
      (list (format nil "audit log signing: ~a"
                    (if (env "OMPRE_AUDIT_HMAC_KEY") "HMAC-SHA256" "unsigned (set OMPRE_AUDIT_HMAC_KEY)")))))))

(defun clip-list (title lines)
  "TITLE over LINES, cut to what a notice can carry."
  (let ((text (format nil "~a~%~a" title (if lines (join-lines lines) "(nothing to show)"))))
    (if (> (length text) 4000)
        (format nil "~a~%… cut at 4000 characters; read the rest with (re:cmd …)" (subseq text 0 4000))
        text)))

(define-slash "functions" (:description "the functions rizin found, with address and size") (words)
  (let ((rz (ensure-rizin)))
    (clip-list "omp-re: functions"
               (loop for function in (coerce (or (rz-cmdj rz "aflj") #()) 'list)
                     for addr = (or (jnumber function "addr") (jnumber function "offset"))
                     for size = (or (jnumber function "realsz") (jnumber function "size"))
                     when addr
                       collect (format nil "~a  ~a~@[ · ~db~]" (jstring function "name")
                                       (ea-from-offset addr) size)))))

(define-slash "strings" (:description "the strings rizin found, with address") (words)
  (let ((rz (ensure-rizin)))
    (clip-list "omp-re: strings"
               (loop for entry in (coerce (or (rz-cmdj rz "izj") #()) 'list)
                     when (jnumber entry "vaddr")
                       collect (format nil "~a  ~a" (ea-from-offset (jnumber entry "vaddr"))
                                       (jstring entry "string"))))))

(define-slash "imports" (:description "the imports, with address") (words)
  (let ((rz (ensure-rizin)))
    (clip-list "omp-re: imports"
               (loop for entry in (coerce (or (rz-cmdj rz "iij") #()) 'list)
                     collect (format nil "~a~@[  ~a~]" (jstring entry "name")
                                     (and (jnumber entry "plt") (ea-from-offset (jnumber entry "plt"))))))))

(defun evidence-detail (record)
  (format nil "[~a:~a]~%~%~a~@[~%~%full output: ~a~]"
          (jstring record "tool") (or (jstring record "ea") "?") (jstring record "summary")
          (and (jstring record "artifactId") (native (artifact-path (jstring record "artifactId"))))))

(define-slash "evidence" (:usage "[id]" :description "evidence recorded on this branch") (words)
  (if words
      (let ((record (find-evidence (first words))))
        (if record
            (evidence-detail record)
            (values (format nil "omp-re: no evidence found with id ~a" (first words)) t)))
      (clip-list "omp-re: evidence"
                 (mapcar (lambda (record)
                           (format nil "[~a] ~a @ ~a~@[  ~a~]"
                                   (subseq (jstring record "id") 0 8) (jstring record "tool")
                                   (or (jstring record "ea") "?")
                                   (let ((line (first (split-lines (or (jstring record "summary") "")))))
                                     (and line (subseq line 0 (min 80 (length line)))))))
                         (evidence-records)))))

(define-slash "cite" (:usage "<id>" :description "one evidence record, as text to quote") (words)
  (let ((record (and words (find-evidence (first words)))))
    (cond ((null words) (values "Usage: /re cite <id>" t))
          ((null record) (values (format nil "omp-re: no evidence found with id ~a" (first words)) t))
          (t (format nil "Re: evidence ~a (~a @ ~a)~%~%~a"
                     (subseq (jstring record "id") 0 8) (jstring record "tool")
                     (or (jstring record "ea") "?") (jstring record "summary"))))))
