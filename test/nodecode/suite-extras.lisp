;;;; suite-extras.lisp --- the remaining static tools: map_file, analyze,
;;;; the signature tools, export_project, rizin_cli, external triage and
;;;; rizin_emulate, and the three replays that put their record back.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The rizin half drives the verbs against the test binary. The triage
;;;; scanners (capa, floss, diec, yara) are rarely installed, so the suite
;;;; first shows each is not offered while absent, then puts stand-in
;;;; scripts of those names on PATH to show the tool appears without a
;;;; restart and reads the scanner's output as the engine says it does. The
;;;; stand-ins print fixed text; nothing under analysis is ever run.

(in-package #:nodecode-re-test)

(defun extras-cli-refusal (tool &rest arguments)
  "Why the rz-* policy refuses ARGUMENTS for TOOL, or NIL when it allows them."
  (re::check-rz-cli (find tool re::+rz-cli-tools+ :key #'re::rz-cli-tool :test #'string=) arguments))

(defun extras-kill-rizin (id)
  "Kill the session's rizin and wait until the engine sees it gone => the dead process."
  (let ((old (re::session-rz (re::find-session id))))
    (nlk:kill-tree (re::rz-pid old))
    (loop repeat 50 while (re::rz-alive-p old) do (sleep 0.1))
    old))

(defun extras-replay-warnings (thunk)
  "Run THUNK => the replay-failure warnings the engine raised while it ran."
  (let ((seen '()))
    (handler-bind ((warning (lambda (warning)
                              (let ((text (princ-to-string warning)))
                                (when (has "could not be replayed" text) (push text seen)))
                              (muffle-warning warning))))
      (funcall thunk))
    (nreverse seen)))

(defun extras-entries (kind id)
  (re::entries-of kind (re::find-session id)))

(defun extras-write (path text)
  (with-open-file (out path :direction :output :if-exists :supersede :external-format :utf-8)
    (write-string text out))
  (uiop:native-namestring path))

(defun extras-stand-in (directory name script)
  "An executable shell script NAME in DIRECTORY: a stand-in for a scanner."
  (let ((path (extras-write (merge-pathnames name directory) (format nil "#!/bin/sh~%~a~%" script))))
    (sb-posix:chmod path #o755)
    path))

(defun extras-files (directory)
  (sort (mapcar #'file-namestring (uiop:directory-files directory)) #'string<))

;;; --- the rz-* argument policy, which needs no program -------------------------------------

(suite "extras: the rz-* argument policy")
(check "ordinary read-only invocations are allowed"
       (notany #'identity
               (list (extras-cli-refusal "rz-bin" "-I" "-j")
                     (extras-cli-refusal "rz-bin" "-c")          ; classes, not the refused -C
                     (extras-cli-refusal "rz-asm" "-a" "x86" "-b" "64" "-o" "0x1000" "-d" "90")
                     (extras-cli-refusal "rz-hash" "-a" "sha256,entropy" "@binary")
                     (extras-cli-refusal "rz-diff" "-t" "functions" "a" "b")
                     (extras-cli-refusal "rz-diff" "-tbytes" "a" "b") ; the e in bytes is a value, not a flag
                     (extras-cli-refusal "rz-diff" "-A" "a" "b")
                     (extras-cli-refusal "rz-ax" "0xdead")
                     (extras-cli-refusal "rz-ax" "-1")
                     (extras-cli-refusal "rz-find" "-x" "7f454c46" "f"))))
(check "flags that run code are refused, alone or inside a cluster"
       (and (has "rz-find -E is not allowed here" (extras-cli-refusal "rz-find" "-E" "id" "f"))
            (has "rz-find -R is not allowed here" (extras-cli-refusal "rz-find" "-R" "w0" "f"))
            (has "rz-find -R" (extras-cli-refusal "rz-find" "-jR" "w0" "f"))))
(check "rz-diff -t command is refused in every getopt spelling"
       (every (lambda (arguments)
                (has "is not allowed here (it runs a command, which can reach the shell)"
                     (apply #'extras-cli-refusal "rz-diff" arguments)))
              '(("-t" "command" "-0" "!touch X" "a" "b")
                ("-tcommand" "-0" "!touch X" "a" "b")
                ("-t" "commands" "a" "b")
                ("-tcommands" "a" "b")
                ("-Xtcommand" "a" "b")
                ("-Xt" "command" "a" "b"))))
(check "flags that write or extract to disk are refused"
       (and (has "rz-bin -O" (extras-cli-refusal "rz-bin" "-O" "d/s/1"))
            (has "rz-bin -o" (extras-cli-refusal "rz-bin" "-o" "/tmp/x"))
            (has "rz-bin -C" (extras-cli-refusal "rz-bin" "-C" "elf:90:"))
            (has "rz-bin -x" (extras-cli-refusal "rz-bin" "-x"))
            (has "rz-bin -x" (extras-cli-refusal "rz-bin" "-xj"))
            (has "rz-asm -O" (extras-cli-refusal "rz-asm" "-O" "/tmp/out" "nop"))))
(check "a network fetch is refused however the repeat is spelt, and the single local read is kept"
       (and (every (lambda (arguments)
                     (has "fetches over the network" (apply #'extras-cli-refusal "rz-bin" arguments)))
                   '(("-dd") ("-d" "-d") ("-ddj") ("-jdd") ("-PP") ("-PPj")))
            (string= "omp-re: rizin_cli: rz-bin -d given 2 times fetches over the network (a single -d reads locally and is allowed)"
                     (extras-cli-refusal "rz-bin" "-d" "-d"))
            (notany (lambda (arguments) (apply #'extras-cli-refusal "rz-bin" arguments))
                    '(("-d") ("-dj") ("-P") ("-SS") ("-zzz")))))
(check "the interactive views of rz-diff are refused"
       (and (has "rz-diff -H" (extras-cli-refusal "rz-diff" "-H" "a" "b"))
            (has "rz-diff -S" (extras-cli-refusal "rz-diff" "-S" "80x25" "a" "b"))))
(check "a line break or NUL in an argument is refused"
       (and (has "line break or NUL" (extras-cli-refusal "rz-ax" (format nil "0x1~%0x2")))
            (has "line break or NUL" (extras-cli-refusal "rz-ax" (format nil "a~cb" (code-char 0))))))

(suite "extras: validators and parsers")
(check "a map permission is r, w, x characters and nothing else"
       (and (string= "rwx" (re::validate-map-perm "rwx"))
            (has "invalid permission \"bad\"" (refusal (lambda () (re::validate-map-perm "bad"))))
            (refusal (lambda () (re::validate-map-perm "")))))
(check "the map line quotes the path, so no path can start a second command"
       (and (string= "o '/tmp/a b; !id' 0x50000 rw" (re::map-file-command "/tmp/a b; !id" "0x50000" "rw"))
            (string= "o '/x' 0x1000" (re::map-file-command "/x" "0x1000"))
            (refusal (lambda () (re::map-file-command "/x" "0x1000;!id")))))
(check "the thirteen passes are the TypeScript's, each with its rizin command"
       (equal '(("calls" . "aac") ("xrefs" . "aar") ("pointers" . "aav") ("preludes" . "aap")
                ("all_functions" . "aaf") ("data_refs" . "aad") ("autoname" . "aan") ("types" . "aaft")
                ("struct_offsets" . "aat") ("golang" . "aalg") ("objc" . "aalor") ("rtti_classes" . "avrr")
                ("emulate_functions" . "aaef"))
              re::+analysis-passes+))
(check "a signature path is quoted, and one that cannot cross the pipe is refused"
       (and (string= "Fs '/tmp/my sigs/a.pat'" (re::signature-apply-command "/tmp/my sigs/a.pat"))
            (has "line break or NUL" (refusal (lambda () (re::signature-apply-command (format nil "a~%b")))))
            (has "empty path" (refusal (lambda () (re::signature-apply-command "  "))))))
(check "the applied count is read from rizin's own sentence"
       (and (eql 4 (re::parse-applied-count "Found 4 FLIRT signatures via /x.pat"))
            (eql 1 (re::parse-applied-count "found 1 flirt signature via x"))
            (null (re::parse-applied-count "nothing"))))
(check "the step count is held to 1..1000 whole instructions"
       (equal '(1 1 2 1000 1 7)
              (mapcar #'re::clamp-step-count '(nil 0 2.9 5000 -3 7))))
(check "the emulator's own validators say what a good value looks like"
       (and (string= "41424344" (re::validate-hex-bytes "0x41424344"))
            (string= "ab" (re::validate-hex-bytes "AB"))
            (has "even number of hex digits" (refusal (lambda () (re::validate-hex-bytes "abc"))))
            (refusal (lambda () (re::validate-hex-bytes "0x")))
            (refusal (lambda () (re::validate-hex-bytes "zz")))
            (has "bad variable name" (refusal (lambda () (re::validate-vm-variable "rax;!id"))))
            (has "bad value" (refusal (lambda () (re::validate-vm-value "1+1"))))
            (string= "0x10" (re::validate-vm-value "0x10"))))
(check "a build's width is read from rizin -v's first line"
       (equal '(64 64 32 32 64 nil)
              (mapcar #'re::version-line-bits
                      '("rizin 0.9.1 @ linux-x86-64" "rizin 0.9.1 @ darwin-arm64" "rizin 0.9.1 @ windows-x86-32"
                        "rizin 0.9.1 @ linux-arm" "rizin 0.9.1 @ linux-aarch64" "rizin 0.9.1 @ plan9-mips"))))
(check "capa's rule map becomes a list of names with their meta"
       (string= "[{\"name\":\"a\",\"meta\":{\"att&ck\":[]}},{\"name\":\"b\"}]"
                (re::json-encode (re::capa-findings (re::json-decode "{\"rules\":{\"a\":{\"meta\":{\"att&ck\":[]}},\"b\":{}}}")))))
(check "floss keeps the three string lists and die its scans; another shape is not findings"
       (and (string= "{\"stack_strings\":[\"s\"],\"static_strings\":[]}"
                     (re::json-encode (re::floss-findings
                                       (re::json-decode "{\"strings\":{\"stack_strings\":[\"s\"],\"other\":1,\"static_strings\":[]}}"))))
            (equalp #() (re::die-findings (re::json-decode "{\"scans\":[]}")))
            (null (re::die-findings (re::json-decode "{\"scans\":{}}")))
            (null (re::capa-findings (re::json-decode "[1]")))
            (null (re::floss-findings (re::json-decode "{\"strings\":3}")))))
(check "yara's lines are rule and file; a line with no space is skipped"
       (string= "[{\"rule\":\"r1\",\"file\":\"/bin/a b\"},{\"rule\":\"r2\",\"file\":\"/x\"}]"
                (re::json-encode (re::parse-yara-matches (format nil "r1 /bin/a b~%warning~%~%  r2 /x  ~%")))))

;;; --- the record's readers and the order of the replays -----------------------------------

(suite "extras: the record, scoped to the binary")
(let ((session (re::make-session :id "extras-record")))
  (flet ((entry (kind &rest data)
           (vector-push-extend (re::obj "type" "custom" "customType" kind "data" (apply #'re::obj data))
                               (re::session-entries session))))
    (entry "re.mapfile" "path" "/early" "addr" "0x1")          ; before any binary: belongs to none
    (entry "re.binary" "path" "/a")
    (entry "re.mapfile" "path" "/m" "addr" "0x1000")
    (entry "re.mapfile" "path" "/m" "addr" "0x1000" "perm" "rw") ; the same path and address again
    (entry "re.mapfile" "path" "/m" "addr" "0x2000" "perm" "rx")
    (entry "re.mapfile" "path" 7 "addr" "0x3000")              ; malformed
    (entry "re.analysis" "pass" "preludes")
    (entry "re.analysis" "pass" "calls")
    (entry "re.analysis" "pass" "preludes")
    (entry "re.signature" "path" "/s1.pat")
    (entry "re.binary" "path" "/b")
    (entry "re.analysis" "pass" "golang")
    (entry "re.signature" "path" "/s2.pat")
    (entry "re.binary" "path" "/a")
    (entry "re.signature" "path" "/s3.pat"))
  (check "mapped files are once per path and address, in first-map order, with the perm first recorded"
         (equal '(("/m" "0x1000" nil) ("/m" "0x2000" "rx")) (re::recorded-map-files "/a" session)))
  (check "passes are de-duplicated in first-run order"
         (and (equal '("preludes" "calls") (re::recorded-analysis-passes "/a" session))
              (equal '("golang") (re::recorded-analysis-passes "/b" session))))
  (check "signatures follow the binary they were applied to across a reopen"
         (and (equal '("/s1.pat" "/s3.pat") (re::recorded-signatures "/a" session))
              (equal '("/s2.pat") (re::recorded-signatures "/b" session))
              (null (re::recorded-signatures "/c" session)))))
(check "the replays run maps, then passes, then signatures, before any annotation"
       (let ((names (mapcar #'car re::*replay-hooks*)))
         (and (equal '("mapfiles" "passes" "signatures") (subseq names 0 (min 3 (length names)))))))

;;; --- with the cell, and with rizin --------------------------------------------------------

(suite "extras: what is offered")
(with-cell ()
  (check "none of these tools is evidence, and all are exec-tier"
         (every (lambda (name)
                  (let ((tool (find name re::*tools* :key #'re::tool-name :test #'string=)))
                    (and tool (not (re::tool-evidence tool)) (eq :exec (re::tool-tier tool)))))
                '("map_file" "analyze" "apply_signatures" "create_signature" "export_project" "rizin_cli"
                  "triage_capa" "triage_floss" "triage_die" "triage_yara" "rizin_emulate")))
  (check "analyze's schema names exactly the thirteen passes"
         (let ((text (re:doc "analyze")))
           (every (lambda (pass) (has (car pass) text)) re::+analysis-passes+)))
  (dolist (scanner '(("triage_capa" . "capa") ("triage_floss" . "floss") ("triage_die" . "diec")
                     ("triage_yara" . "yara")))
    (if (re::find-on-path (cdr scanner))
        (check (format nil "~a is offered: ~a is installed here" (car scanner) (cdr scanner))
               (has (car scanner) (re:tools)))
        (check (format nil "~a is not offered while ~a is absent, and a call says there is no such tool"
                       (car scanner) (cdr scanner))
               (and (not (has (car scanner) (re:tools)))
                    (has "no tool named" (refusal (lambda () (re:call (car scanner) :rules-path "/x"))))))))
  (check "every tool that needs the binary says so before one is open"
         (in-session ((fresh-session))
           (every (lambda (call) (has "no binary open" (refusal call)))
                  (list (lambda () (re:call "map_file" :path "/bin/sh" :addr "0x50000"))
                        (lambda () (re:call "analyze" :pass "calls"))
                        (lambda () (re:call "apply_signatures" :source "sigdb"))
                        (lambda () (re:call "create_signature"))
                        (lambda () (re:call "export_project"))
                        (lambda () (re:call "rizin_emulate" :action "vars")))))))

(cond
  ((not *rizin*)
   (suite "extras: rizin")
   (format t "  SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*))
  (t
   (let* ((out (merge-pathnames "extras-out/" *scratch*))
          (previous-output (uiop:getenv "OMPRE_OUTPUT_DIR"))
          (previous-path (uiop:getenv "PATH"))
          (overlay (extras-write (merge-pathnames "extras-overlay.bin" *scratch*) "MAPFILETOOLDATA7"))
          (overlay-hex "4d415046494c45544f4f4c4441544137"))
     (setf (uiop:getenv "OMPRE_OUTPUT_DIR") (uiop:native-namestring out))
     (unwind-protect
          (with-cell ()
            (let ((id (fresh-session)))
              (in-session (id)
                (re:open *binary*)
                (let ((binary (re::session-binary-path (re::find-session id))))

                  ;; --- rizin_cli ---------------------------------------------------------
                  (suite "extras: rizin_cli")
                  (cond
                    ((not (re::available-rz-cli-tools))
                     (check "rizin_cli is not offered: no rz-* program is installed"
                            (and (not (has "rizin_cli" (re:tools)))
                                 (has "no tool named" (refusal (lambda () (re:call "rizin_cli" :tool "rz-ax" :args '("1"))))))))
                    (t
                     (check "rizin_cli is offered, and its schema lists the six programs"
                            (and (has "rizin_cli" (re:tools))
                                 (let ((text (re:doc "rizin_cli")))
                                   (every (lambda (name) (has name text))
                                          '("rz-bin" "rz-diff" "rz-hash" "rz-find" "rz-asm" "rz-ax")))))
                     (check "rz-ax converts, touching no file"
                            (string= (format nil "rz-ax 0xdead~%57005")
                                     (re:call "rizin_cli" :tool "rz-ax" :args '("0xdead"))))
                     (check "rz-ax needs no open binary"
                            (in-session ((fresh-session))
                              (has "57005" (re:call "rizin_cli" :tool "rz-ax" :args '("0xdead")))))
                     (check "rz-bin is given the open binary when the arguments do not place it"
                            (let ((text (re:call "rizin_cli" :tool "rz-bin" :args '("-I" "-j"))))
                              (and (has (format nil "rz-bin -I -j ~a" binary) text) (has "\"bintype\"" text))))
                     (check "rz-bin with no binary open says how to open one"
                            (in-session ((fresh-session))
                              (has "no binary open"
                                   (refusal (lambda () (re:call "rizin_cli" :tool "rz-bin" :args '("-I")))))))
                     (check "@binary is substituted in place for a program that takes its files"
                            (let ((text (re:call "rizin_cli" :tool "rz-hash" :args '("-a" "sha256" "@binary"))))
                              (and (has (format nil "rz-hash -a sha256 ~a" binary) text)
                                   (has (format nil "sha256: ~a" (re::sha256-file binary)) text))))
                     (check "rz-asm disassembles a string of hex pairs"
                            (has "mov rbp, rsp"
                                 (re:call "rizin_cli" :tool "rz-asm" :args '("-a" "x86" "-b" "64" "-d" "4889e5"))))
                     (check "rz-diff compares two files"
                            (has "distance: 0"
                                 (re:call "rizin_cli" :tool "rz-diff" :args '("-d" "myers" "@binary" "@binary"))))
                     (check "rz-find finds a string, and no hit is (no output), not a failure"
                            (and (has "0x" (re:call "rizin_cli" :tool "rz-find" :args '("-s" "GNU" "@binary")))
                                 (has "(no output)"
                                      (re:call "rizin_cli" :tool "rz-find" :args '("-s" "zzqqzzqqzzqq" "@binary")))))
                     (check "a program's own help is one call away"
                            (has "Usage" (re:call "rizin_cli" :tool "rz-ax" :args '("-h"))))
                     (check "a program outside the curated set is refused by the schema"
                            (has "tool must be one of"
                                 (refusal (lambda () (re:call "rizin_cli" :tool "rz-gg" :args '("-h"))))))
                     (check "args is a list of strings and is required"
                            (and (has "args is required" (refusal (lambda () (re:call "rizin_cli" :tool "rz-ax"))))
                                 (has "args must be an array of strings"
                                      (refusal (lambda () (re:call "rizin_cli" :tool "rz-ax" :args "0xdead"))))))
                     (check "every refusal of the policy comes back through the verb, word for word"
                            (and (string= "omp-re: rizin_cli: rz-find -E is not allowed here (it writes a file, runs code, fetches over the network, or opens an interactive view)"
                                          (refusal (lambda () (re:call "rizin_cli" :tool "rz-find" :args '("-E" "id" "@binary")))))
                                 (has "rz-find -R" (refusal (lambda () (re:call "rizin_cli" :tool "rz-find" :args '("-jR" "w0" "@binary")))))
                                 (has "rz-bin -o" (refusal (lambda () (re:call "rizin_cli" :tool "rz-bin" :args '("-o" "x")))))
                                 (has "rz-bin -C" (refusal (lambda () (re:call "rizin_cli" :tool "rz-bin" :args '("-C" "elf:90:")))))
                                 (has "rz-bin -x" (refusal (lambda () (re:call "rizin_cli" :tool "rz-bin" :args '("-xj")))))
                                 (has "rz-asm -O" (refusal (lambda () (re:call "rizin_cli" :tool "rz-asm" :args '("-O" "o" "nop")))))
                                 (has "rz-diff -H" (refusal (lambda () (re:call "rizin_cli" :tool "rz-diff" :args '("-H" "a" "b")))))
                                 (has "rz-diff -S" (refusal (lambda () (re:call "rizin_cli" :tool "rz-diff" :args '("-S" "80x25" "a" "b")))))
                                 (string= "omp-re: rizin_cli: rz-diff -t command is not allowed here (it runs a command, which can reach the shell)"
                                          (refusal (lambda () (re:call "rizin_cli" :tool "rz-diff" :args '("-tcommand" "-0" "!id" "a" "b")))))
                                 (has "rz-diff -t commands"
                                      (refusal (lambda () (re:call "rizin_cli" :tool "rz-diff" :args '("-Xt" "commands" "a" "b")))))
                                 (has "rz-bin -P given 2 times fetches over the network"
                                      (refusal (lambda () (re:call "rizin_cli" :tool "rz-bin" :args '("-P" "-jP")))))
                                 (has "line break or NUL"
                                      (refusal (lambda () (re:call "rizin_cli" :tool "rz-ax" :args (list (format nil "1~%2"))))))))
                     (check "a refused flag never starts the program: the file it would write is not there"
                            (let ((marker (uiop:native-namestring (merge-pathnames "extras-should-not-exist" *scratch*))))
                              (and (has "rz-bin -O"
                                        (refusal (lambda ()
                                                   (re:call "rizin_cli" :tool "rz-bin"
                                                                        :args (list "-O" (format nil "d/s/~a" marker) "-o" marker)))))
                                   (not (probe-file marker)))))))

                  ;; --- map_file ----------------------------------------------------------
                  (suite "extras: map_file")
                  (check "a file is mapped at the address, and a read sees its bytes there"
                         (let ((text (re:call "map_file" :path overlay :addr "0x50000")))
                           (and (has (format nil "map_file: ~a @ 0x50000" overlay) text)
                                (has (format nil "mapped ~a at 0x50000; first bytes: ~a" overlay overlay-hex) text)
                                (has "Re-applied automatically on resume/respawn" text)
                                (has overlay-hex (re:cmd "p8 16" "0x50000")))))
                  (check "it is recorded as re.mapfile {path, addr}, by resolved path"
                         (equal (list (format nil "{\"path\":~a,\"addr\":\"0x50000\"}" (re::js-string overlay)))
                                (mapcar #'re::json-encode (extras-entries "re.mapfile" id))))
                  (check "a permission is said in the result and kept on the entry"
                         (and (has "at 0x70000 (rw); first bytes"
                                   (re:call "map_file" :path overlay :addr "0x70000" :perm "rw"))
                              (equal "rw" (gethash "perm" (second (extras-entries "re.mapfile" id))))))
                  (check "mapping the same file at the same address again records nothing more"
                         (progn (re:call "map_file" :path overlay :addr "0x50000")
                                (= 2 (length (extras-entries "re.mapfile" id)))))
                  (check "a path that is not a readable file, a bad permission and a bad address are refused"
                         (and (has "no such binary"
                                   (refusal (lambda () (re:call "map_file" :path (format nil "~anope.bin" (uiop:native-namestring *scratch*))
                                                                           :addr "0x60000"))))
                              (has "map_file: invalid permission \"bad\""
                                   (refusal (lambda () (re:call "map_file" :path overlay :addr "0x60000" :perm "bad"))))
                              (has "invalid address or expression"
                                   (refusal (lambda () (re:call "map_file" :path overlay :addr "0x60000;!id"))))
                              (has "addr is required" (refusal (lambda () (re:call "map_file" :path overlay))))
                              (= 2 (length (extras-entries "re.mapfile" id)))))
                  (check "the mapped file is opened read-only: its bytes on disk are as written"
                         (string= "MAPFILETOOLDATA7" (re::read-text-file overlay)))

                  ;; --- rizin_emulate -----------------------------------------------------
                  (suite "extras: rizin_emulate")
                  (check "vars before init says to init first"
                         (string= (format nil "emulate: vars~%(no VM state — init first)")
                                  (re:call "rizin_emulate" :action "vars")))
                  (let* ((rz (re::session-rz (re::find-session id)))
                         (seek (re::rz-cmd rz "s")))
                    (check "init starts the VM at the address and answers its state"
                           (let ((text (re:call "rizin_emulate" :action "init" :addr "main")))
                             (and (has "emulate: VM initialized at main" text) (has "\"PC\"" text) (has "\"rsp\"" text))))
                    (check "init does not move the session's seek"
                           (string= seek (re::rz-cmd rz "s"))))
                  (check "step answers the change events, one instruction by default"
                         (let ((text (re:call "rizin_emulate" :action "step")))
                           (and (has "emulate: step 1" text) (has "pc_write" text))))
                  (check "step takes a count, floored and clamped"
                         (and (has "emulate: step 2" (re:call "rizin_emulate" :action "step" :count 2))
                              (has "emulate: step 1" (re:call "rizin_emulate" :action "step" :count 0))
                              (has "emulate: step 2" (re:call "rizin_emulate" :action "step" :count 2.9))))
                  (check "set_var sets a VM variable, and vars shows it"
                         (and (string= (format nil "emulate: set_var rax~%rax = 0x1234")
                                       (re:call "rizin_emulate" :action "set_var" :name "rax" :value "0x1234"))
                              (has "\"rax\":\"0x0000000000001234\"" (re:call "rizin_emulate" :action "vars"))))
                  (check "set_mem seeds memory in an overlay and reads it back; the file on disk is untouched"
                         (and (string= (format nil "emulate: set_mem 4 byte(s) @ 0x70000~%[65,66,67,68]")
                                       (re:call "rizin_emulate" :action "set_mem" :addr "0x70000" :bytes "0x41424344"))
                              (has "41424344" (re:cmd "p8 4" "0x70000"))
                              (string= "MAPFILETOOLDATA7" (re::read-text-file overlay))))
                  (check "step_until runs to an address"
                         (progn (re:call "rizin_emulate" :action "init" :addr "main")
                                (let ((text (re:call "rizin_emulate" :action "step_until" :addr "main+4")))
                                  (and (has "emulate: step_until main+4" text) (has "\"PC\"" text)))))
                  (check "each action says which argument it lacks"
                         (and (string= "omp-re: emulate init needs addr"
                                       (refusal (lambda () (re:call "rizin_emulate" :action "init"))))
                              (string= "omp-re: emulate step_until needs addr"
                                       (refusal (lambda () (re:call "rizin_emulate" :action "step_until"))))
                              (string= "omp-re: emulate set_var needs name and value"
                                       (refusal (lambda () (re:call "rizin_emulate" :action "set_var" :name "rax"))))
                              (string= "omp-re: emulate set_mem needs addr and bytes"
                                       (refusal (lambda () (re:call "rizin_emulate" :action "set_mem" :addr "0x70000"))))))
                  (check "nothing that could open another command reaches rizin"
                         (and (has "invalid address" (refusal (lambda () (re:call "rizin_emulate" :action "init" :addr "main;!id"))))
                              (has "invalid address" (refusal (lambda () (re:call "rizin_emulate" :action "step_until" :addr "a @@ b"))))
                              (has "bad variable name \"rax;!id\""
                                   (refusal (lambda () (re:call "rizin_emulate" :action "set_var" :name "rax;!id" :value "1"))))
                              (has "bad value \"1;!id\""
                                   (refusal (lambda () (re:call "rizin_emulate" :action "set_var" :name "rax" :value "1;!id"))))
                              (has "bad bytes \"414\""
                                   (refusal (lambda () (re:call "rizin_emulate" :action "set_mem" :addr "0x70000" :bytes "414"))))
                              (has "invalid address"
                                   (refusal (lambda () (re:call "rizin_emulate" :action "set_mem" :addr "0x7 ; x" :bytes "41"))))
                              (has "action must be one of" (refusal (lambda () (re:call "rizin_emulate" :action "run"))))
                              (has "count must be a number"
                                   (refusal (lambda () (re:call "rizin_emulate" :action "step" :count "3"))))))

                  ;; --- analyze -----------------------------------------------------------
                  (suite "extras: analyze")
                  (check "a pass reports the function count before and after"
                         (ppcre:scan "^analyze: calls\\naac: functions \\d+ -> \\d+( \\(\\+\\d+\\)| \\(no change\\))\\."
                                     (re:call "analyze" :pass "calls")))
                  (check "a pass that does not apply fails with rizin's own message and is not recorded"
                         (let ((text (refusal (lambda () (re:call "analyze" :pass "golang")))))
                           (and (has "analyze: golang" text) (has "aalg: " text)
                                (ppcre:scan "(?i)cannot|no .*found|not a" text)
                                (notany (lambda (data) (equal "golang" (gethash "pass" data)))
                                        (extras-entries "re.analysis" id)))))
                  (check "a pass outside the thirteen is refused by the schema"
                         (and (has "pass must be one of" (refusal (lambda () (re:call "analyze" :pass "aaa"))))
                              (has "pass must be one of" (refusal (lambda () (re:call "analyze" :pass "calls;!id"))))
                              (has "pass is required" (refusal (lambda () (re:call "analyze"))))))
                  (let* ((before (parse-integer (second (re::split-lines (re:cmd "aflc")))))
                         (text (re:call "analyze" :pass "preludes"))
                         (after (parse-integer (second (re::split-lines (re:cmd "aflc"))))))
                    (check "a pass that found functions says how many, and is recorded as re.analysis {pass}"
                           (and (has (format nil "aap: functions ~d -> ~d" before after) text)
                                (or (= after before)
                                    (and (has (format nil "(+~d)" (- after before)) text)
                                         (equal '("{\"pass\":\"preludes\"}")
                                                (mapcar #'re::json-encode
                                                        (remove-if-not (lambda (data) (equal "preludes" (gethash "pass" data)))
                                                                       (extras-entries "re.analysis" id))))))))
                    (check "running it again records it no second time"
                           (progn (re:call "analyze" :pass "preludes")
                                  (>= 1 (count "preludes" (extras-entries "re.analysis" id)
                                               :key (lambda (data) (gethash "pass" data)) :test #'equal))))

                    ;; --- signatures -------------------------------------------------------
                    (suite "extras: apply_signatures and create_signature")
                    (check "source sigdb re-applies the built-in database and records nothing"
                           (and (ppcre:scan "Re-applied the built-in signature database\\. Functions: \\d+ before, \\d+ after\\."
                                            (re:call "apply_signatures" :source "sigdb"))
                                (null (extras-entries "re.signature" id))))
                    ;; A minimal FLIRT .pat matching main's first 16 bytes:
                    ;; <32 nibbles> <crc-len> <crc16> <len> :<off> <name>.
                    (let* ((bytes (string-upcase (second (re::split-lines (re:cmd "p8 32" "main")))))
                           (pattern (extras-write (merge-pathnames "extras fixture.pat" *scratch*)
                                                  (format nil "~a 00 0000 0020 :0000 omp_re_sig_main~%---~%"
                                                          (subseq bytes 0 32)))))
                      (flet ((flirt-flag-p ()
                               (find "flirt.omp_re_sig_main" (re:json "flj")
                                     :key (lambda (flag) (gethash "name" flag)) :test #'equal)))
                        (check "source file applies a custom .pat — at a path with a space — and names the match"
                               (and (ppcre:scan "Applied [1-9]\\d* FLIRT signature\\(s\\) from "
                                                (re:call "apply_signatures" :source "file" :path pattern))
                                    (flirt-flag-p)))
                        (check "it is recorded as re.signature {path}, once however often it is applied"
                               (progn (re:call "apply_signatures" :source "file" :path pattern)
                                      (equal (list (format nil "{\"path\":~a}" (re::js-string pattern)))
                                             (mapcar #'re::json-encode (extras-entries "re.signature" id)))))
                        (check "a file that matched nothing is not recorded"
                               (and (has "Applied 0 FLIRT signature(s)"
                                         (re:call "apply_signatures" :source "file" :path "/nonexistent/x.pat"))
                                    (= 1 (length (extras-entries "re.signature" id)))))
                        (check "source file without a path, a blank path and a path with a line break are refused"
                               (and (string= "omp-re: apply_signatures: source 'file' needs a path"
                                             (refusal (lambda () (re:call "apply_signatures" :source "file"))))
                                    (has "empty path" (refusal (lambda () (re:call "apply_signatures" :source "file" :path " "))))
                                    (has "must not contain a line break or NUL"
                                         (refusal (lambda () (re:call "apply_signatures" :source "file"
                                                                                           :path (format nil "a.pat~%!id")))))
                                    (has "source must be one of" (refusal (lambda () (re:call "apply_signatures" :source "url"))))))

                        (check "create_signature writes a .pat of the analyzed functions into the output directory"
                               (let ((text (re:call "create_signature" :file "fixture"))
                                     (path (uiop:native-namestring (merge-pathnames "fixture.pat" out))))
                                 (and (has "create_signature: fixture.pat" text)
                                      (ppcre:scan "wrote [1-9]\\d* function signature\\(s\\) to " text)
                                      (has (format nil "to ~a (~d bytes)" path (re::file-octets path)) text)
                                      (plusp (re::file-octets path)))))
                        (check "what it wrote is a FLIRT file the apply path takes"
                               (ppcre:scan "Applied [1-9]\\d* FLIRT signature"
                                           (re:call "apply_signatures" :source "file"
                                                                       :path (uiop:native-namestring (merge-pathnames "fixture.pat" out)))))
                        (check "with no name it derives one from the binary's, and keeps a .sig ending"
                               (and (ppcre:scan "\\.pat \\(\\d+ bytes\\)" (re:call "create_signature"))
                                    (probe-file (merge-pathnames (format nil "~a.pat" (file-namestring binary)) out))
                                    (has "create_signature: compiled.sig" (re:call "create_signature" :file "compiled.sig"))
                                    (probe-file (merge-pathnames "compiled.sig" out))))

                        ;; --- export_project -------------------------------------------------
                        (suite "extras: export_project")
                        (check "export_project writes a non-empty .rzdb into the output directory"
                               (let ((text (re:call "export_project" :file "handoff"))
                                     (path (uiop:native-namestring (merge-pathnames "handoff.rzdb" out))))
                                 (and (has "export_project: handoff.rzdb" text)
                                      (has (format nil "wrote the analysis to ~a (~d bytes)" path (re::file-octets path)) text)
                                      (has (format nil "Po ~a" path) text)
                                      (plusp (re::file-octets path)))))
                        (check "with no name it derives one from the binary's, and does not double the ending"
                               (and (has (format nil "export_project: ~a.rzdb" (file-namestring binary))
                                         (re:call "export_project"))
                                    (has "export_project: again.RZDB" (re:call "export_project" :file "again.RZDB"))))

                        ;; --- the one directory ----------------------------------------------
                        (suite "extras: nothing is written outside the output directory")
                        (check "a name with a separator, a `..', or an absolute path is refused by both writers"
                               (every (lambda (name)
                                        (and (has "invalid output filename"
                                                  (refusal (lambda () (re:call "create_signature" :file name))))
                                             (has "invalid output filename"
                                                  (refusal (lambda () (re:call "export_project" :file name))))))
                                      (list "../escape.pat" "a/b" "/tmp/abs" "a\\b" "x..y" ".." "sp ace" "a;b"
                                            (format nil "nl~%x"))))
                        (check "the output directory holds exactly what the tools said they wrote"
                               (equal (sort (list "fixture.pat" (format nil "~a.pat" (file-namestring binary)) "compiled.sig"
                                                  "handoff.rzdb" (format nil "~a.rzdb" (file-namestring binary)) "again.RZDB")
                                            #'string<)
                                      (extras-files out)))
                        (check "and nothing escaped beside it or into the scratch home"
                               (and (null (uiop:directory-files *scratch* "escape*"))
                                    (not (probe-file "/tmp/abs.pat")) (not (probe-file "/tmp/abs.rzdb"))
                                    (null (uiop:subdirectories out))))
                        (check "the sample itself is unchanged by all of it"
                               (string= (re::sha256-file binary)
                                        (re::session-binary-sha256 (re::find-session id))))

                        ;; --- replay -----------------------------------------------------------
                        (suite "extras: the record is put back on a fresh rizin")
                        (let ((old (extras-kill-rizin id))
                              (warnings nil)
                              (text nil))
                          (setf warnings (extras-replay-warnings
                                          (lambda () (setf text (re:cmd "p8 16" "0x50000")))))
                          (check "after rizin is killed the next read starts another, with no replay failure"
                                 (and (not (eq old (re::session-rz (re::find-session id)))) (null warnings)))
                          (check "the mapped file is there again, with the file's own bytes"
                                 (and (has overlay-hex text)
                                      (has overlay-hex (re:cmd "p8 16" "0x70000"))))
                          (check "the analysis pass was re-run: the functions it found are back"
                                 (= after (parse-integer (second (re::split-lines (re:cmd "aflc"))))))
                          (check "the custom signature file was re-applied: its name is back"
                                 (flirt-flag-p)))
                        (re::shutdown-sessions)
                        (check "a forgotten session comes back from its record the same way"
                               (let ((warnings (extras-replay-warnings
                                                (lambda () (re:cmd "p8 16" "0x50000")))))
                                 (and (null warnings)
                                      (has overlay-hex (re:cmd "p8 16" "0x50000"))
                                      (= after (parse-integer (second (re::split-lines (re:cmd "aflc")))))
                                      (flirt-flag-p))))
                        (check "a recorded pass this engine does not know is a failure line, and the rest still replays"
                               (progn
                                 (re::append-entry "re.analysis" (re::obj "pass" "bogus") (re::find-session id))
                                 (extras-kill-rizin id)
                                 (let ((warnings (extras-replay-warnings (lambda () (re:cmd "aflc")))))
                                   (and (= 1 (length warnings))
                                        (has "analysis pass bogus: unknown" (first warnings))
                                        (has overlay-hex (re:cmd "p8 16" "0x50000"))
                                        (flirt-flag-p)))))
                        (check "the replays answer no failure for a live process and the record as it stands"
                               (let* ((session (re::find-session id))
                                      (rz (re::session-rz session)))
                                 (and (null (re::replay-map-files session rz binary))
                                      (equal '("analysis pass bogus: unknown")
                                             (re::replay-analysis-passes session rz binary))
                                      (null (re::replay-signatures session rz binary)))))
                        (check "another binary opened in the session inherits none of it"
                               (let ((copy (uiop:native-namestring (merge-pathnames "extras-sample.bin" *scratch*))))
                                 (uiop:copy-file binary copy)
                                 (re:open copy)
                                 (let ((session (re::find-session id))
                                       (path (re::session-binary-path (re::find-session id))))
                                   (and (null (re::recorded-map-files path session))
                                        (null (re::recorded-analysis-passes path session))
                                        (null (re::recorded-signatures path session))
                                        (not (has overlay-hex (re:cmd "p8 16" "0x50000")))
                                        (not (flirt-flag-p))
                                        ;; and the first binary still has its own
                                        (= 2 (length (re::recorded-map-files binary session))))))))))

                  ;; --- triage, with stand-in scanners ---------------------------------------
                  (suite "extras: triage (stand-in scanners on PATH)")
                  (let ((bin (ensure-directories-exist (merge-pathnames "extras-bin/" *scratch*)))
                        (rules (extras-write (merge-pathnames "extras-rules.yar" *scratch*) "rule r1 { condition: true }"))
                        (open-binary (re::session-binary-path (re::find-session id))))
                    (setf (uiop:getenv "PATH")
                          (format nil "~a:~a" (string-right-trim "/" (uiop:native-namestring bin)) previous-path))
                    (extras-stand-in bin "capa" "echo '{\"rules\":{\"create process\":{\"meta\":{\"attack\":[\"T1106\"]}},\"bare\":{}}}'")
                    (extras-stand-in bin "floss" "echo \"{\\\"strings\\\":{\\\"stack_strings\\\":[\\\"$1 $2\\\"],\\\"decoded_strings\\\":[]}}\"")
                    (extras-stand-in bin "diec" "echo '{\"scans\":[{\"type\":\"compiler\",\"name\":\"gcc\"}]}'")
                    (extras-stand-in bin "yara" "echo \"r1 $2\"; echo \"r2 $2\"")
                    (check "a scanner installed while the cell runs is offered from then on"
                           (let ((text (re:tools)))
                             (every (lambda (name) (has name text))
                                    '("triage_capa" "triage_floss" "triage_die" "triage_yara"))))
                    (check "triage_capa answers the matched rules by name with their meta"
                           (let ((text (re:call "triage_capa")))
                             (and (has "capa: 2 finding group(s)" text) (has "\"create process\"" text)
                                  (has "T1106" text) (has "\"bare\"" text))))
                    (check "triage_floss runs the scanner as `-j <binary>' and answers the strings themselves"
                           (let ((text (re:call "triage_floss")))
                             (and (has "floss: 2 finding group(s)" text)
                                  (has (format nil "-j ~a" open-binary) text))))
                    (check "triage_die answers the detections"
                           (let ((text (re:call "triage_die")))
                             (and (has "die: 1 finding group(s)" text) (has "\"gcc\"" text))))
                    (check "triage_yara runs `yara <rules> <binary>' and answers rule and file"
                           (let ((text (re:call "triage_yara" :rules-path rules)))
                             (and (has "yara: 2 rule(s) matched" text) (has (format nil "{\"rule\":\"r1\",\"file\":~a}" (re::js-string open-binary)) text)
                                  (has (format nil "{\"rule\":\"r2\",\"file\":~a}" (re::js-string open-binary)) text))))
                    (check "triage_yara refuses a blank or missing rules file before running anything"
                           (and (string= "omp-re: yara: rules_path argument is required (no default ruleset ships)"
                                         (refusal (lambda () (re:call "triage_yara" :rules-path "  "))))
                                (string= "omp-re: invalid rules_path: /nonexistent/rules.yar"
                                         (refusal (lambda () (re:call "triage_yara" :rules-path "/nonexistent/rules.yar"))))
                                (has "rules_path is required" (refusal (lambda () (re:call "triage_yara"))))))
                    (check "a scanner that printed nothing and failed is a failure, never zero findings"
                           (progn
                             (extras-stand-in bin "yara" "echo 'error: syntax error' >&2; exit 3")
                             (extras-stand-in bin "capa" "exit 2")
                             (and (string= "omp-re: yara failed (exit 3): error: syntax error"
                                           (refusal (lambda () (re:call "triage_yara" :rules-path rules))))
                                  (string= "omp-re: capa failed (exit 2): no output"
                                           (refusal (lambda () (re:call "triage_capa")))))))
                    (check "a non-zero exit with output is still an answer: yara's no-match, capa's own codes"
                           (progn
                             (extras-stand-in bin "yara" "echo 'warning'; exit 1")
                             (extras-stand-in bin "capa" "echo '{\"rules\":{}}'; exit 1")
                             (and (has "yara: 0 rule(s) matched" (re:call "triage_yara" :rules-path rules))
                                  (has "capa: 0 finding group(s)" (re:call "triage_capa")))))
                    (check "output that is not JSON, or not the expected shape, comes back whole under a header that says so"
                           (progn
                             (extras-stand-in bin "capa" "echo 'capa 7.0 banner'")
                             (extras-stand-in bin "diec" "echo '{\"detects\":[]}'")
                             (and (string= (format nil "capa: output was not valid JSON (schema not recognized)~%capa 7.0 banner~%")
                                           (re:call "triage_capa"))
                                  (has "die: expected JSON shape not found" (re:call "triage_die")))))
                    (check "taken off PATH again, the scanner is no longer offered"
                           (progn
                             (setf (uiop:getenv "PATH") previous-path)
                             (or (re::find-on-path "capa")
                                 (and (not (has "triage_capa" (re:tools)))
                                      (has "no tool named" (refusal (lambda () (re:call "triage_capa"))))))))
                    (check "no triage call is evidence"
                           (notany (lambda (record) (re::starts-with "triage_" (gethash "tool" record)))
                                   (re::evidence-records (re::find-session id)))))))))
       (setf (uiop:getenv "PATH") previous-path)
       (setf (uiop:getenv "OMPRE_OUTPUT_DIR") (or previous-output ""))))))
