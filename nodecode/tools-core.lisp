;;;; tools-core.lisp --- open a binary, and read it.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; open_binary, rizin_help and rizin_command. rizin_command is the one way
;;;; to read the binary, and the one tool whose results are evidence.

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
         ;; knows it re-runs against the same bytes. A file that cannot be
         ;; hashed still opens: its evidence is then bound to no bytes, which
         ;; /re verify says of each record.
         (sha256 (ignore-errors (sha256-file resolved)))
         (replayed (nth-value 1 (spawn-rizin resolved :load load :session session)))
         ;; The warning is a courtesy: a catalog that cannot be read is said by /re status.
         (missing (ignore-errors (missing-required-commands (load-catalog)))))
    (setf (session-binary-sha256 session) sha256)
    (let ((opened (obj "path" resolved "load" (or load :absent) "sha256" (or sha256 :absent))))
      (append-entry "re.binary" opened session)
      (ask-host :transcript session "re.binary" (format nil "[re: opened ~a]" resolved) opened))
    (flet ((could-not (failures)
             (mapcar (lambda (failure) (format nil "  could not re-apply ~a" failure)) failures)))
      (join-lines
       (append (list (format nil "Binary opened: ~a" resolved))
               (when load
                 (list (format nil "Loaded with forced settings (~{~a~^, ~})."
                               (loop for key being the hash-keys of load using (hash-value value)
                                     collect (format nil "~a=~a" key value)))))
               ;; A group that counts what it re-applied says so, of its own
               ;; things alone, with its own failures under the line.
               (loop for (contribution failures applied) in replayed
                     when (and applied (plusp (+ applied (length failures))))
                       append (cons (format nil "Re-applied ~d of ~d ~a recorded earlier for this binary."
                                            applied (+ applied (length failures))
                                            (contribution-noun contribution))
                                    (could-not failures)))
               (loop for (nil failures applied) in replayed
                     unless applied append (could-not failures))
               (when missing (list (missing-commands-warning missing))))))))

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

;;; --- rizin_help and rizin_command -----------------------------------------------------------

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
  "The body of rizin_command: one gated read, and the result with its
reproducibility fields => (values RESULT RAW-OUTPUT). /re carry re-runs a
carried command through this, so it is recorded as the tool would; a recipe
reads RAW-OUTPUT, which is whole where the result's text may be cut."
  ;; No binary is said before the catalog is read, so the guidance needs no rizin.
  (let ((binary-path (require-binary session)))
    (multiple-value-bind (output stderr line) (run-read command addr session)
      (let ((ea (and addr (ignore-errors
                           (ea-from-offset (resolve-numeric-addr (ensure-rizin session) addr)))))
            (header (format nil "rizin> ~a" line)))
        (if (blank-p output)
            (let ((errors (clean-stderr stderr)))
              (values (if (plusp (length errors))
                          (failed-result (format nil "~a~%(no output; rizin said:)~%~a" header errors) ea)
                          (plain-result (format nil "~a~%(no output)" header) ea))
                      ""))
            ;; The hashes are over the RAW output, canonicalized and bound to
            ;; the binary's path, so /re verify can re-run this exact line and
            ;; compare; what the model reads is still the trimmed, cut text.
            (values (text-result header (string-right-trim '(#\Newline) output)
                                 :ea ea :tool "rizin_command" :commands (list line)
                                 :repro-hash (canonical-hash output binary-path)
                                 :canonical-excerpt (canonical-excerpt output binary-path)
                                 :shift-hash (shift-hash output binary-path))
                    output))))))

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
      (let ((result (text-result "omp-re manual" +manual+)))
        (setf (result-observation result) nil)
        result)
      ;; Both values: the result, and the whole output for code that composes reads.
      (run-rizin-command (jstring arguments "command") (jstring arguments "addr"))))
