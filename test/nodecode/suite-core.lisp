;;;; suite-core.lisp --- the engine's spine: primitives, policy, the session,
;;;; the verbs, /re, start and stop.
;;;;
;;;; SPDX-License-Identifier: MIT

(in-package #:nodecode-re-test)

;;; --- primitives --------------------------------------------------------------------

(suite "primitives")
(check "SHA-256 of the empty string and of abc are the published vectors"
       (and (string= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (re::sha256-hex ""))
            (string= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" (re::sha256-hex "abc"))))
(check "SHA-256 across the block boundaries (55, 56, 64, 119 and 1000 octets) matches sha256sum"
       (loop for size in '(55 56 64 119 1000)
             for text = (make-string size :initial-element #\a)
             always (string= (re::sha256-hex text)
                             (subseq (uiop:run-program (list "sh" "-c" (format nil "printf '%s' ~a | sha256sum" text))
                                                       :output :string)
                                     0 64))))
(check "SHA-256 of a file is sha256sum's"
       (string= (re::sha256-file "/bin/sh")
                (subseq (uiop:run-program '("sha256sum" "/bin/sh") :output :string) 0 64)))
(check "HMAC-SHA256 is RFC 4231's second test case"
       (string= "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
                (re::hex (re::hmac-sha256 (re::utf-8 "Jefe") (re::utf-8 "what do ya want for nothing?")))))
(check "base64 pads as RFC 4648 says"
       (equal '("" "Zg==" "Zm8=" "Zm9v" "Zm9vYg==")
              (mapcar (lambda (text) (re::base64 (re::utf-8 text))) '("" "f" "fo" "foo" "foob"))))
(check "JSON round-trips, in insertion order, the way JSON.stringify writes it"
       (let ((text "{\"b\":1,\"a\":[true,false,null,\"x\\ny\\\"z\",-2.5],\"c\":{}}"))
         (string= text (re::json-encode (re::json-decode text)))))
(check "a surrogate pair decodes to one character and JSON that is not JSON is refused"
       (and (= 1 (length (re::json-decode "\"\\ud83d\\ude00\"")))
            (null (re::json-parse "{oops"))))
(check "pretty JSON is JSON.stringify(value, null, 2)"
       (string= (format nil "{~%  \"a\": 1,~%  \"b\": [~%    2~%  ]~%}")
                (re::json-encode (re::json-decode "{\"a\":1,\"b\":[2]}") :indent 2)))
(check "an address is normalized to one spelling"
       (equal '("0x1100" "0x1100" "0x0" "main")
              (mapcar #'re::normalize-addr '("0X01100" "0x1100 " "0x000" "Main"))))
(check "an address that could open another command is refused"
       (and (refusal (lambda () (re::validate-addr "main;!id")))
            (refusal (lambda () (re::validate-addr "0x10 @@ sym*")))
            (string= "sym.main+0x10" (re::validate-addr "sym.main+0x10"))))
(check "a quoted argument makes every rizin metacharacter literal"
       (string= "'x; !id \\\\ \\' @ ~'" (re::rz-quote "x; !id \\ ' @ ~")))
(check "a quoted argument refuses a line break"
       (refusal (lambda () (re::rz-quote (format nil "a~%b")))))
(check "canonical output strips escapes, folds line ends, trims and redacts the binary's path"
       (string= (format nil "<BINARY> a~%b")
                (re::canonicalize-rizin-output
                 (format nil "~c[31m/tmp/x~c[0m a  ~c~cb~%~%" (code-char 27) (code-char 27) #\Return #\Newline)
                 "/tmp/x")))
(check "the shift hash ignores where code sits and still sees a changed constant"
       (let ((a (format nil "0x00001000  call 0x2000~%0x00001005  mov eax, 0x10"))
             (b (format nil "0x00005000  call 0x7000~%0x00005005  mov eax, 0x10"))
             (c (format nil "0x00001000  call 0x2000~%0x00001005  mov eax, 0x11")))
         (and (string= (re::shift-hash a) (re::shift-hash b))
              (string/= (re::shift-hash a) (re::shift-hash c))
              (string/= (re::canonical-hash a) (re::canonical-hash b)))))
(check "truncation keeps whole lines within both limits"
       (multiple-value-bind (kept truncated shown total)
           (re::truncate-head (format nil "~{~a~^~%~}" (loop for i below 5000 collect (format nil "line ~d" i))))
         (and truncated (= shown 2000) (= total 5000) (not (re::ends-with (string #\Newline) kept)))))

;;; --- the read-only policy -----------------------------------------------------------

(suite "policy")
(check "read-only families run and their mutating siblings do not"
       (and (every #'re::runnable-p '("aflj" "pdf" "pdg" "izj" "iij" "axtj" "px" "p8" "/xj" "agc" "ph" "p=e" "el" "tsj" "CC." "afvlj"))
            (notany #'re::runnable-p '("afn" "CC" "wx" "o" "!" "dc" "pr" "po" "afvn" "ax" "ag-" "p=ev" "pfo" "/F" "s"))))
(check "every forbidden syntax is caught, and @!<n> is the one modifier allowed"
       (and (every #'re::forbidden-syntax-reason
                   (list "aflj;!id" "izj|sh" "px>f" "pd `x`" "px $(x)" "afl~main" "pd @ main" "pd @@ sym*"
                         "px \"a\"" "pd #x" "px \\x" (format nil "px~%!id") (format nil "px~cq" (code-char 0))))
            (null (re::forbidden-syntax-reason "ph entropy @!4096"))
            (null (re::forbidden-syntax-reason "px 64"))))

;;; --- the verbs' argument mapping ----------------------------------------------------

(suite "arguments")
(let ((object (re::wire-arguments
               '(:expect-sha256 "ab" :bits 32 :flag t :off :false :absent nil :items ("a" "b") :kind :elf))))
  (check "a keyword is spelt as the engine spells the parameter"
         (equal "ab" (gethash "expect_sha256" object)))
  (check "T is true, :false is false and present, NIL is left out"
         (and (eq t (gethash "flag" object))
              (multiple-value-bind (value present) (gethash "off" object) (and present (null value)))
              (not (nth-value 1 (gethash "absent" object)))))
  (check "a list is an array and a keyword value its lowercase name"
         (and (equalp #("a" "b") (gethash "items" object)) (equal "elf" (gethash "kind" object)))))
(check "an odd argument list is refused in words"
       (has "odd one out" (refusal (lambda () (re::wire-arguments '(:a))))))

;;; --- the cell, with no rizin needed ---------------------------------------------------

(suite "cell")
(check "a verb refuses while the cell is not running"
       (has "not running" (refusal (lambda () (re:status)))))
(check "the loader's contract: START-CELL is external in the system's package"
       (eq :external (nth-value 1 (find-symbol "START-CELL" "NODECODE-RE"))))

(with-cell ()
  (check "the help topic and the /re command are contributed"
         (and (assoc :re nle:*help*) (assoc "re" nle:*commands* :test #'string=)))
  (check "no tool is registered with nodecode" (null nle:*tools*))
  (check "(re:tools) lists the engine's tools"
         (let ((text (re:tools))) (and (has "rizin_command" text) (has "open_binary" text) (has "rizin_help" text))))
  (check "(re:doc) spells a tool's parameters as eval keywords"
         (let ((text (re:doc "open-binary"))) (and (has ":path" text) (has "required" text) (has "one of 8, 16, 32, 64" text))))
  (check "(re:doc) refuses an unknown tool" (has "no tool is named" (refusal (lambda () (re:doc "nope")))))
  (check "a call that does not fit the schema is RE-ERROR saying which member"
         (has "command is required" (refusal (lambda () (re:call "rizin_command")))))
  (check "a member of the wrong type is refused, never coerced"
         (has "bits must be an integer" (refusal (lambda () (re:call "open_binary" :path "/x" :bits "64")))))
  (check "an unknown tool is RE-ERROR" (has "no tool named" (refusal (lambda () (re:call "no_such_tool")))))
  (check "the manual needs no binary, and is not evidence"
         (let ((id (fresh-session)))
           (in-session (id)
             (let ((manual (re:cmd "")))
               (and (has "omp-re manual" manual) (has "(re:open" manual)
                    (null (re::evidence-records (re::find-session id))))))))
  (check "reading with no binary open says how to open one"
         (in-session ((fresh-session))
           (has "no binary open" (refusal (lambda () (re:cmd "aflj"))))))
  (check "/re typed alone answers a dialog of what it offers: rows that run a line, rows that ask for a word"
         (multiple-value-bind (text dialog)
             (funcall (cdr (assoc "re" nle:*commands* :test #'string=)) "" "cell")
           (let ((rows (getf (rest (rest dialog)) :rows)))
             (and (stringp text)
                  (find "/re status" rows :key (lambda (row) (second (getf row :run))) :test #'equal)
                  (equal "/re open" (getf (getf (find "Open a binary" rows :key (lambda (row) (getf row :label))
                                                      :test #'equal)
                                                :ask)
                                          :line))))))
  (check "/re help answers the list of subcommands as text"
         (let ((text (funcall (cdr (assoc "re" nle:*commands* :test #'string=)) "help" "cell")))
           (and (has "/re open" text) (has "/re status" text))))
  (check "an unknown /re line says so"
         (has "unknown /re subcommand" (refusal (lambda () (re:slash "frobnicate")))))
  (check "/re off refuses every tool call until /re on"
         (in-session ((fresh-session))
           (re:slash "off")
           (and (has "RE tools are off" (refusal (lambda () (re:cmd ""))))
                (progn (re:slash "on") (has "omp-re manual" (re:cmd "")))))))

(check "the cell registers no tool with nodecode: its model has one, eval, and the verbs live in it"
       (null nle:*tools*))
(check "stop takes the help topic and the command back"
       (and (null nle:*help*) (null nle:*commands*)))

;;; --- with rizin -----------------------------------------------------------------------

(cond
  ((not *rizin*)
   (suite "rizin")
   (format t "  SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*))
  (t
   (suite "policy against this rizin's catalog")
   (let ((catalog (re::load-catalog)))
     (check "the catalog holds the commands the engine itself sends"
            (and (> (hash-table-count catalog) 500) (null (re::missing-required-commands catalog))))
     (check "a known read-only command passes and its line carries the address"
            (string= "pdf @ entry0" (re::check-rizin-command catalog "pdf" "entry0")))
     (check "a table spec passes with a table-shaped tail and is refused otherwise"
            (and (re::check-rizin-command catalog "aflt:size/sort/dec:name/head/5")
                 (has "table spec" (refusal (lambda () (re::check-rizin-command catalog "aflt:$x"))))))
     (check "refusals: a write, a config set, a positional dual with an argument, an unknown command"
            (and (has "not available here" (refusal (lambda () (re::check-rizin-command catalog "wx 90"))))
                 (has "is a write" (refusal (lambda () (re::check-rizin-command catalog "e asm.arch=arm"))))
                 (has "only with no argument" (refusal (lambda () (re::check-rizin-command catalog "tn exit"))))
                 (has "has no command" (refusal (lambda () (re::check-rizin-command catalog "pzzzq"))))))
     (check "rizin_help answers a family and a keyword search"
            (and (has "afl" (nth-value 0 (re::search-catalog catalog "afl")))
                 (plusp (length (nth-value 1 (re::search-catalog catalog "entropy")))))))

   (suite (format nil "rizin (~a)" *binary*))
   (with-cell ()
     (let ((id (fresh-session)))
       (in-session (id)
         (check "(re:open) opens and analyzes the binary" (has "Binary opened" (re:open *binary*)))
         (check "(re:status) names it, and that rizin is running"
                (let ((status (re:status)))
                  (and (has (file-namestring *binary*) status) (not (has "not running" status)))))
         (let* ((functions (re:cmd "aflj"))
                (evidence (re::evidence-id-of functions)))
           (check "(re:cmd) reads it; the result has a header, and an evidence id on its last line"
                  (and (has "rizin> aflj" functions) (= 8 (length evidence))))
           (check "output past the size cap names a file that holds all of it"
                  (let* ((mark (search "Full output: " functions))
                         (file (and mark (subseq functions (+ mark 13) (position #\] functions :start mark)))))
                    (and file (probe-file file)
                         (vectorp (re::json-decode
                                   (let ((text (re::read-text-file file)))
                                     (subseq text (1+ (position #\Newline text)))))))))
           (multiple-value-bind (data id) (re:json "aflj")
             (check "(re:json) answers the decoded data, whole, and its evidence id"
                    (and (vectorp data) (> (length data) 10)
                         (stringp (gethash "name" (aref data 0))) (= 8 (length id)))))
           (check "(re:json) refuses a command that does not answer JSON"
                  (has "did not answer JSON" (refusal (lambda () (re:json "pd 1" "entry0")))))
           (check "a command at an address, with the address recorded on its evidence"
                  (let ((text (re:cmd "pd 3" "entry0")))
                    (and (has "rizin> pd 3 @ entry0" text)
                         (let ((record (re::find-evidence (re::evidence-id-of text) (re::find-session id))))
                           (and (re::starts-with "0x" (gethash "ea" record))
                                (equalp #("pd 3 @ entry0") (gethash "commands" record))
                                (= 64 (length (gethash "reproHash" record)))
                                (= 64 (length (gethash "binarySha256" record))))))))
           (check "the policy holds on the way in"
                  (and (has "not allowed" (refusal (lambda () (re:cmd "afl~main"))))
                       (has "not available here" (refusal (lambda () (re:cmd "wx 90" "entry0"))))))
           (check "a command rizin has nothing to say for answers (no output), not a failure"
                  (has "(no output)" (re:cmd "CC." "entry0")))
           (check "(re:call \"rizin_help\") searches this rizin's own catalog"
                  (has "rizin help: pdf" (re:call "rizin_help" :query "pdf")))
           (check "(re:slash \"evidence\") lists what was recorded, and one id shows it"
                  (and (has evidence (re:slash "evidence"))
                       (has "[rizin_command:" (re:slash (format nil "evidence ~a" evidence)))
                       (has "Re: evidence" (re:slash (format nil "cite ~a" evidence)))))
           (check "(re:slash \"functions\") lists names with addresses"
                  (has "0x" (re:slash "functions")))
           (check "the evidence blob is on disk under its own hash"
                  (let* ((record (re::find-evidence evidence (re::find-session id)))
                         (blob (re::read-blob (gethash "outputHash" record))))
                    (and blob (string= (gethash "outputHash" record) (re::sha256-hex blob)))))
           (check "every call was written to the session's audit log"
                  (let ((log (re::read-text-file (re::state-path "audit" (format nil "~a.log" id)))))
                    (and (has "\"tool\":\"open_binary\"" log) (has "\"tool\":\"rizin_command\"" log)
                         (has "\"command\":\"aflj\"" log))))

           ;; The process dies; the record is the truth.
           (let* ((session (re::find-session id))
                  (old (re::session-rz session)))
             (nlk:kill-tree (re::rz-pid old))
             (loop repeat 50 while (re::rz-alive-p old) do (sleep 0.1))
             (check "a killed rizin is replaced by the next call"
                    (and (has "rizin> iIj" (re:cmd "iIj"))
                         (not (eq old (re::session-rz session))))))

           ;; The engine forgets the session; the record brings it back.
           (re::shutdown-sessions)
           (check "a forgotten session is restored from its record: binary, hash, evidence"
                  (let ((status (re:status)))
                    (and (has (file-namestring *binary*) status)
                         (has "not running" status)
                         (re::find-evidence evidence (re::find-session id))
                         (= 64 (length (re::session-binary-sha256 (re::find-session id)))))))
           (check "and reads again without being reopened" (has "rizin> iIj" (re:cmd "iIj")))))

       (check "/re open reads a relative path against the session's directory"
              (let ((other (fresh-session)))
                (uiop:copy-file *binary* (merge-pathnames "sample.bin" *scratch*))
                (funcall (cdr (assoc "re" nle:*commands* :test #'string=)) "open sample.bin" other)
                (in-session (other) (has "sample.bin" (re:status)))))

       (check "two sessions read side by side, each its own binary and record"
              (let* ((results (make-array 4 :initial-element nil))
                     (ids (list id (fresh-session)))
                     (threads (loop for index below 4
                                    collect (let ((index index))
                                              (sb-thread:make-thread
                                               (lambda ()
                                                 (in-session ((nth (mod index 2) ids))
                                                   (setf (aref results index)
                                                         (ignore-errors
                                                          (if (evenp index)
                                                              (re:cmd "iIj")
                                                              (refusal (lambda () (re:cmd "iIj"))))))))))))
                     (done (mapc #'sb-thread:join-thread threads)))
                (declare (ignore done))
                (and (has "rizin> iIj" (aref results 0)) (has "rizin> iIj" (aref results 2))
                     (has "no binary open" (aref results 1)) (has "no binary open" (aref results 3)))))

       (check "an interrupted command leaves the stream aligned for the next"
              (in-session (id)
                (let* ((session (re::find-session id))
                       (rz (re::ensure-rizin session)))
                  ;; A command is written and its frames never read, as an interrupt would leave it.
                  (sb-thread:with-mutex ((re::rz-lock rz))
                    (setf (re::rz-pending-marker rz) "__LEFT__")
                    (format (re::rz-input rz) "pd 2~%echo __LEFT__~%")
                    (finish-output (re::rz-input rz)))
                  (let ((text (re:cmd "iIj")))
                    (and (has "\"arch\"" text) (not (has "__LEFT__" text)))))))

       (check "a command past its deadline kills rizin, and the next call starts another"
              (in-session (id)
                (let* ((session (re::find-session id))
                       (rz (re::ensure-rizin session)))
                  (and (has "timed out" (refusal (lambda () (re::rz-cmd rz "aaa" :seconds 0.01))))
                       (not (re::rz-alive-p rz))
                       (has "rizin> iIj" (re:cmd "iIj"))))))

       (check "idle sessions are reaped, and come back on the next call"
              (in-session (id)
                (let ((session (re::find-session id)))
                  (re::reap-idle-sessions 0)
                  (and (null (re::session-rz session))
                       (has "rizin> iIj" (re:cmd "iIj")))))))

     (let ((rz-before (loop for session being the hash-values of re::*sessions*
                            when (re::session-rz session) collect (re::session-rz session))))
       (nodecode-re::stop-cell)
       (check "stopping the cell ends every rizin process"
              (and rz-before (notany #'re::rz-alive-p rz-before)))))))
