;;;; suite-core.lisp --- the engine's spine: primitives, policy, the session,
;;;; the verbs, /re, start and stop.
;;;;
;;;; SPDX-License-Identifier: MIT

(in-package #:nodecode-re-test)

;;; --- primitives --------------------------------------------------------------------

(suite "primitives")
(check "SHA-256 of the empty string and of abc are the published vectors"
       (and (string= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (omp-re::sha256-hex ""))
            (string= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" (omp-re::sha256-hex "abc"))))
(check "SHA-256 across the block boundaries (55, 56, 64, 119 and 1000 octets) matches sha256sum"
       (loop for size in '(55 56 64 119 1000)
             for text = (make-string size :initial-element #\a)
             always (string= (omp-re::sha256-hex text)
                             (subseq (uiop:run-program (list "sh" "-c" (format nil "printf '%s' ~a | sha256sum" text))
                                                       :output :string)
                                     0 64))))
(check "SHA-256 of a file is sha256sum's"
       (string= (omp-re::sha256-file "/bin/sh")
                (subseq (uiop:run-program '("sha256sum" "/bin/sh") :output :string) 0 64)))
(check "HMAC-SHA256 is RFC 4231's second test case"
       (string= "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
                (omp-re::hex (omp-re::hmac-sha256 (omp-re::utf-8 "Jefe") (omp-re::utf-8 "what do ya want for nothing?")))))
(check "base64 pads as RFC 4648 says"
       (equal '("" "Zg==" "Zm8=" "Zm9v" "Zm9vYg==")
              (mapcar (lambda (text) (omp-re::base64 (omp-re::utf-8 text))) '("" "f" "fo" "foo" "foob"))))
(check "JSON round-trips, in insertion order, the way JSON.stringify writes it"
       (let ((text "{\"b\":1,\"a\":[true,false,null,\"x\\ny\\\"z\",-2.5],\"c\":{}}"))
         (string= text (omp-re:json-encode (omp-re:json-decode text)))))
(check "a surrogate pair decodes to one character and JSON that is not JSON is refused"
       (and (= 1 (length (omp-re:json-decode "\"\\ud83d\\ude00\"")))
            (null (omp-re:json-parse "{oops"))))
(check "pretty JSON is JSON.stringify(value, null, 2)"
       (string= (format nil "{~%  \"a\": 1,~%  \"b\": [~%    2~%  ]~%}")
                (omp-re:json-encode (omp-re:json-decode "{\"a\":1,\"b\":[2]}") :indent 2)))
(check "an address is normalized to one spelling"
       (equal '("0x1100" "0x1100" "0x0" "main")
              (mapcar #'omp-re::normalize-addr '("0X01100" "0x1100 " "0x000" "Main"))))
(check "an address that could open another command is refused"
       (and (refusal (lambda () (omp-re::validate-addr "main;!id")))
            (refusal (lambda () (omp-re::validate-addr "0x10 @@ sym*")))
            (string= "sym.main+0x10" (omp-re::validate-addr "sym.main+0x10"))))
(check "a quoted argument makes every rizin metacharacter literal"
       (string= "'x; !id \\\\ \\' @ ~'" (omp-re::rz-quote "x; !id \\ ' @ ~")))
(check "a quoted argument refuses a line break"
       (refusal (lambda () (omp-re::rz-quote (format nil "a~%b")))))
(check "canonical output strips escapes, folds line ends, trims and redacts the binary's path"
       (string= (format nil "<BINARY> a~%b")
                (omp-re::canonicalize-rizin-output
                 (format nil "~c[31m/tmp/x~c[0m a  ~c~cb~%~%" (code-char 27) (code-char 27) #\Return #\Newline)
                 "/tmp/x")))
(check "the shift hash ignores where code sits and still sees a changed constant"
       (let ((a (format nil "0x00001000  call 0x2000~%0x00001005  mov eax, 0x10"))
             (b (format nil "0x00005000  call 0x7000~%0x00005005  mov eax, 0x10"))
             (c (format nil "0x00001000  call 0x2000~%0x00001005  mov eax, 0x11")))
         (and (string= (omp-re::shift-hash a) (omp-re::shift-hash b))
              (string/= (omp-re::shift-hash a) (omp-re::shift-hash c))
              (string/= (omp-re::canonical-hash a) (omp-re::canonical-hash b)))))
(check "truncation keeps whole lines within both limits"
       (multiple-value-bind (kept truncated shown total)
           (omp-re::truncate-head (format nil "~{~a~^~%~}" (loop for i below 5000 collect (format nil "line ~d" i))))
         (and truncated (= shown 2000) (= total 5000) (not (ends (string #\Newline) kept)))))

;;; --- the read-only policy -----------------------------------------------------------

(suite "policy")
(check "read-only families run and their mutating siblings do not"
       (and (every #'omp-re::runnable-p '("aflj" "pdf" "pdg" "izj" "iij" "axtj" "px" "p8" "/xj" "agc" "ph" "p=e" "el" "tsj" "CC." "afvlj"))
            (notany #'omp-re::runnable-p '("afn" "CC" "wx" "o" "!" "dc" "pr" "po" "afvn" "ax" "ag-" "p=ev" "pfo" "/F" "s"))))
(check "every forbidden syntax is caught, and @!<n> is the one modifier allowed"
       (and (every #'omp-re::forbidden-syntax-reason
                   (list "aflj;!id" "izj|sh" "px>f" "pd `x`" "px $(x)" "afl~main" "pd @ main" "pd @@ sym*"
                         "px \"a\"" "pd #x" "px \\x" (format nil "px~%!id") (format nil "px~cq" (code-char 0))))
            (null (omp-re::forbidden-syntax-reason "ph entropy @!4096"))
            (null (omp-re::forbidden-syntax-reason "px 64"))))

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

(with-cell ()
  (check "the help topic and the /re command are contributed"
         (and (assoc :re nle:*help*) (assoc "re" nle:*commands* :test #'string=)))
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
                    (null (omp-re::evidence-records (omp-re:find-session id))))))))
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
  (check "/re help lists the subcommands in the order they declare"
         (equal '("open" "functions" "strings" "imports" "evidence" "cite" "findings" "undo" "report"
                  "verify" "carry" "status" "on" "off" "help")
                (mapcar (lambda (line) (second (omp-re::words line))) (omp-re:split-lines (re:slash "help")))))
  (check "(re:status) is RE-ERROR when the line fails, as (re:slash \"status\") is"
         (let ((host omp-re::*host*))
           (unwind-protect
                (progn (setf omp-re::*host* (list* :entries (lambda (session) (declare (ignore session))
                                                          (error "away"))
                                               host))
                       (in-session ((fresh-session))
                         (has "could not answer entries" (refusal (lambda () (re:status))))))
             (setf omp-re::*host* host))))
  (check "a tool, a parameter and a subcommand are named by one rule: lowercase, underscores"
         (and (has ":path" (re:doc "Open-Binary"))
              (has "command is required" (refusal (lambda () (re:call "Rizin-Command"))))
              (has "/re status" (re:slash "HELP"))))
  (check "/re off refuses every tool call until /re on"
         (in-session ((fresh-session))
           (typed "off")
           (and (has "RE tools are off" (refusal (lambda () (re:cmd ""))))
                (progn (typed "on") (has "omp-re manual" (re:cmd ""))))))
  (check "/re off gates the model's /re lines too — it cannot turn the tools back on — and never the operator's"
         (in-session ((fresh-session))
           (typed "off")
           (and (has "RE tools are off" (refusal (lambda () (re:slash "on"))))
                (has "RE tools are off" (refusal (lambda () (re:status))))
                (has "rizin:" (typed "status"))
                (progn (typed "on") (has "rizin:" (re:status)))))))

(check "stop takes the help topic and the command back"
       (and (null nle:*help*) (null nle:*commands*)))

;;; --- the host port --------------------------------------------------------------------

(suite "settings")
(check "config.example.jsonc is the declaration's own text"
       (string= (re::config-example)
                (omp-re::read-text-file (merge-pathnames "nodecode/config.example.jsonc" *root*))))
(check "with no host, a setting is its environment variable, else its default"
       (and (null (omp-re:setting-value :rizin-path))
            (with-environment ("OMPRE_RIZIN_PATH" " /opt/rz/rizin ")
              (string= "/opt/rz/rizin" (omp-re:setting-value :rizin-path)))
            (= 30 (omp-re:setting-value :idle-minutes))))
(check "the section wins where it says something other than the default, and only there"
       (with-environment ("OMPRE_RIZIN_PATH" "/from/environment")
         (with-environment ("OMPRE_ALLOWED_DIRS" "/a, /b")
           (and (with-cell (:rizin-path "/from/section")
                  (string= "/from/section" (omp-re:setting-value :rizin-path)))
                (with-cell ()
                  (and (string= "/from/environment" (omp-re:setting-value :rizin-path))
                       (equal '("/a" "/b") (omp-re:setting-value :allowed-dirs))))
                (with-cell (:allowed-dirs '("/c"))
                  (equal '("/c") (omp-re:setting-value :allowed-dirs)))))))
(check "debugger: false is the default and does not veto OMPRE_ENABLE_DEBUGGER; audit: false says something"
       (and (with-environment ("OMPRE_ENABLE_DEBUGGER" "1")
              (with-cell (:debugger nil) (omp-re:setting-value :debugger)))
            (with-cell (:audit nil) (not (omp-re:setting-value :audit)))
            (with-cell () (omp-re:setting-value :audit))))
(check "the signing key is taken as set: a blank one signs, and the status says so; an empty one is none"
       (flet ((signs-and-says (key)
                (with-environment ("OMPRE_AUDIT_HMAC_KEY" key)
                  (with-cell ()
                    (let ((id (fresh-session)))
                      (in-session (id)
                        (re:cmd "")
                        (list (has "\"hmac\":" (omp-re::read-text-file
                                                 (omp-re::state-path "audit" (format nil "~a.log" id))))
                              (has "audit log signing: HMAC-SHA256" (re:status)))))))))
         (and (equal '(t t) (signs-and-says "  "))
              (equal '(nil nil) (signs-and-says "")))))

(suite "the host's services")
(with-cell ()
  (check "a branch that cannot be read fails the call: nothing is read as if every entry were on it"
         (let ((id (seed-session)))
           (with-service (:entries (lambda (session) (declare (ignore session)) (error "the store is away")))
             (in-session (id)
               (has "the host could not answer entries: the store is away"
                    (refusal (lambda () (re:slash "evidence"))))))))
  (check "a turn that cannot be read fails the write: no entry goes in unstamped"
         (let* ((id (seed-session))
                (session (omp-re:find-session id))
                (before (length (omp-re:session-file-entries session))))
           (with-service (:append-entry (lambda (session type data)
                                          (omp-re:file-append-entry session type data
                                                                 (error "no turn can be read"))))
             (multiple-value-bind (text failed)
                 (omp-re::in-session (id "writing") (omp-re::append-entry "re.note" (omp-re:obj)))
               (and failed
                    (has "the host could not answer append-entry: no turn can be read" text)
                    (= before (length (omp-re:session-file-entries session))))))))
  (check "what the operator is told carries a level"
         (let ((told '()))
           (with-service (:notify (lambda (text level) (push (list level text) told)))
             (omp-re:notify :error "it ~a" "broke")
             (equal '((:error "it broke")) told)))))
(check "stop clears what start installed" (null omp-re::*host*))
(check "with no host a session's record is its own file, all of it on the branch"
       (let ((session (omp-re:find-session (fresh-session))))
         (omp-re::in-session (session "writing")
           (omp-re::append-entry "re.note" (omp-re:obj "n" 1)))
         (and (= 1 (length (omp-re::session-entries session)))
              (has "\"customType\":\"re.note\"" (omp-re::read-text-file (omp-re::record-path session))))))

(suite "acting in a session")
(with-cell ()
  (let ((id (fresh-session)))
    (check "a call inside a held session acts in it: no second lock, and its refusal is still text"
           (equal '("omp-re manual" t)
                  (multiple-value-list
                   (omp-re::in-session (id "a composed read")
                     (multiple-value-bind (text failed) (omp-re::call-tool id "rizin_command" (omp-re:obj "command" ""))
                       (multiple-value-bind (refused refused-p)
                           (omp-re::call-tool id "rizin_command" (omp-re:obj "command" "aflj"))
                         (values (and (not failed) (subseq text 0 13))
                                 (and refused-p (has "no binary open" refused)))))))))
    (check "a /re line inside a held session, too"
           (has "/re status" (omp-re::in-session (id "a composed line") (values (omp-re::run-slash-line id "help")))))
    (check "anything that goes wrong in a session is an answer naming what was being done"
           (equal '("omp-re: counting failed: lost count" t)
                  (multiple-value-list (omp-re::in-session (id "counting") (error "lost count")))))))

(suite "evidence ids")
(let ((records (list (omp-re:obj "id" "abcdef01-1") (omp-re:obj "id" "abcdef02-2") (omp-re:obj "id" "123456789"))))
  (check "an id is found by itself or by a prefix of six or more characters that names one record"
         (and (eq (third records) (omp-re::find-by-id records "123456"))
              (eq (first records) (omp-re::find-by-id records "abcdef01"))
              (eq (first records) (omp-re::find-by-id records "abcdef01-1"))))
  (check "a shorter prefix, one that names two, and one that names none are each refused in words"
         (equal '(:short :ambiguous :missing)
                (mapcar (lambda (id) (nth-value 2 (omp-re::find-by-id records id))) '("12345" "abcdef0" "999999")))))
(with-cell ()
  (in-session ((seed-session))
    (check "/re cite and /re evidence take the ids record_finding takes, and refuse the rest in its words"
           (and (has "Re: evidence 11111111" (re:slash "cite 111111"))
                (has "is too short" (refusal (lambda () (re:slash "cite 1111"))))
                (has "no evidence found with id 222222" (refusal (lambda () (re:slash "evidence 222222"))))))))

;;; The engine is a system of its own: a plain image with no host in it must
;;; load it clean and be answered through the surface alone.
(suite "the engine alone")
(let ((out (uiop:run-program
            (list "sbcl" "--noinform" "--non-interactive" "--no-sysinit" "--no-userinit"
                  "--eval" "(require :asdf)"
                  "--eval" (format nil "(asdf:load-asd ~s)"
                                   (uiop:native-namestring (merge-pathnames "omp-re.asd" *root*)))
                  "--eval" "(handler-bind ((warning (lambda (w) (unless (typep w (quote style-warning)) (format t \"~&WARNED: ~a~%\" w))))) (asdf:load-system \"omp-re\" :force t))"
                  "--eval" "(format t \"~&PACKAGES: ~{~a~^ ~}~%\" (mapcar (function package-name) (remove-if-not (lambda (p) (search \"NODECODE\" (package-name p))) (list-all-packages))))"
                  "--eval" "(format t \"~&HELP: ~a~%\" (omp-re:jstring (omp-re:engine-command \"alone\" \"help\") \"text\"))"
                  "--eval" "(format t \"~&CALL: ~a~%\" (omp-re:jstring (omp-re:engine-call \"alone\" \"rizin_command\" (omp-re:obj \"command\" \"aflj\")) \"text\"))"
                  "--eval" "(format t \"~&MANUAL: ~a~%\" (omp-re:jstring (omp-re:engine-call \"alone\" \"rizin_command\" (omp-re:obj \"command\" \"\")) \"text\"))")
            :output :string :error-output :output :ignore-error-status t)))
  (check "omp-re loads in a plain image with no warning and no host's package"
         (and (has "PACKAGES: " out) (not (has "PACKAGES: N" out)) (not (has "WARNED: " out))))
  (check "with no host the surface answers in the engine's own words"
         (and (has "HELP: /re open <path>" out)
              (has "CALL: omp-re: no binary open — use /re open <path> or the open_binary tool first" out)))
  (check "the manual is one text: the engine's tables between the host's parts, here the engine's own"
         (and (has "MANUAL: omp-re manual" out)
              (has "Reading the binary (prefer the JSON `*j` forms" out)
              (has "recorded as evidence (/re evidence)" out)
              (has "OMPRE_RIZIN_PATH (rizin if not on PATH)" out))))

(suite "the engine's surface")
(check "a tool is described with its JSON Schema, its approval class and whether it records evidence"
       (let ((tool (find "rizin_command" (omp-re:engine-tools) :key (lambda (tool) (gethash "name" tool))
                                                            :test #'string=)))
         (and (equal "exec" (gethash "approval" tool)) (eq t (gethash "evidence" tool))
              (equalp #("command") (gethash "required" (gethash "parameters" tool)))
              (equal "string" (omp-re:jstring tool "parameters" "properties" "addr" "type")))))
(check "a /re subcommand is described with its usage and its dialog row"
       (let ((open (find "open" (omp-re:engine-commands) :key (lambda (command) (gethash "name" command))
                                                      :test #'string=)))
         (and (equal "<path>" (gethash "usage" open))
              (equal "Path" (omp-re:jstring open "row" "ask")))))
(check "a call the engine refuses is an answer that failed, with the reason as its text"
       (let ((answer (omp-re:engine-call (fresh-session) "rizin_command" (omp-re:obj "command" "aflj"))))
         (and (eq t (gethash "failed" answer)) (has "no binary open" (gethash "text" answer)))))
(check "a /re line's answer says how loudly: error when it failed"
       (and (equal "info" (gethash "level" (omp-re:engine-command (fresh-session) "help")))
            (equal "error" (gethash "level" (omp-re:engine-command (fresh-session) "cite")))))

;;; --- with rizin -----------------------------------------------------------------------

(cond
  ((not *rizin*)
   (suite "rizin")
   (format t "  SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*))
  (t
   (suite "policy against this rizin's catalog")
   (let ((catalog (omp-re::load-catalog)))
     (check "the catalog holds the commands the engine itself sends"
            (and (> (hash-table-count catalog) 500) (null (omp-re::missing-required-commands catalog))))
     (check "a known read-only command passes and its line carries the address"
            (string= "pdf @ entry0" (omp-re::check-rizin-command catalog "pdf" "entry0")))
     (check "a table spec passes with a table-shaped tail and is refused otherwise"
            (and (omp-re::check-rizin-command catalog "aflt:size/sort/dec:name/head/5")
                 (has "table spec" (refusal (lambda () (omp-re::check-rizin-command catalog "aflt:$x"))))))
     (check "refusals: a write, a config set, a positional dual with an argument, an unknown command"
            (and (has "not available here" (refusal (lambda () (omp-re::check-rizin-command catalog "wx 90"))))
                 (has "is a write" (refusal (lambda () (omp-re::check-rizin-command catalog "e asm.arch=arm"))))
                 (has "only with no argument" (refusal (lambda () (omp-re::check-rizin-command catalog "tn exit"))))
                 (has "has no command" (refusal (lambda () (omp-re::check-rizin-command catalog "pzzzq"))))))
     (check "rizin_help answers a family and a keyword search"
            (and (has "afl" (nth-value 0 (omp-re::search-catalog catalog "afl")))
                 (plusp (length (nth-value 1 (omp-re::search-catalog catalog "entropy")))))))

   (suite (format nil "rizin (~a)" *binary*))
   (with-cell ()
     (let ((id (fresh-session)))
       (in-session (id)
         (check "(re:open) opens and analyzes the binary" (has "Binary opened" (re:open *binary*)))
         (check "(re:status) names it, and that rizin is running"
                (let ((status (re:status)))
                  (and (has (file-namestring *binary*) status) (not (has "not running" status)))))
         (let* ((functions (re:cmd "aflj"))
                (evidence (tagged-evidence functions)))
           (check "(re:cmd) reads it; the result has a header, and an evidence id on its last line"
                  (and (has "rizin> aflj" functions) (= 8 (length evidence))))
           (check "output past the size cap names a file that holds all of it, and the engine's answer says which"
                  (let* ((answer (omp-re:engine-call id "rizin_command" (omp-re:obj "command" "aflj")))
                         (file (gethash "artifactPath" answer)))
                    (and file (probe-file file)
                         (has (format nil "Full output: ~a]" file) (gethash "text" answer))
                         (eq t (omp-re:jget answer "details" "truncated"))
                         (string= (omp-re::read-text-file file)
                                  (format nil "rizin> aflj~%~a"
                                          (string-right-trim '(#\Newline) (gethash "raw" answer))))
                         (string= (tagged-evidence (gethash "text" answer))
                                  (subseq (gethash "evidenceId" answer) 0 8))
                         (equal (gethash "evidenceId" answer) (omp-re:jget answer "details" "evidenceId")))))
           (multiple-value-bind (data id) (re:json "aflj")
             (check "(re:json) answers the decoded data, whole, and its evidence id"
                    (and (vectorp data) (> (length data) 10)
                         (stringp (gethash "name" (aref data 0))) (= 8 (length id)))))
           (check "(re:json) refuses a command that does not answer JSON"
                  (has "did not answer JSON" (refusal (lambda () (re:json "pd 1" "entry0")))))
           (check "a command at an address, with the address recorded on its evidence"
                  (let ((text (re:cmd "pd 3" "entry0")))
                    (and (has "rizin> pd 3 @ entry0" text)
                         (let ((record (omp-re::find-evidence (tagged-evidence text) (omp-re:find-session id))))
                           (and (eql 0 (search "0x" (gethash "ea" record)))
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
                  (let* ((record (omp-re::find-evidence evidence (omp-re:find-session id)))
                         (blob (omp-re::read-blob (gethash "outputHash" record))))
                    (and blob (string= (gethash "outputHash" record) (omp-re::sha256-hex blob)))))
           (check "every call was written to the session's audit log"
                  (let ((log (omp-re::read-text-file (omp-re::state-path "audit" (format nil "~a.log" id)))))
                    (and (has "\"tool\":\"open_binary\"" log) (has "\"tool\":\"rizin_command\"" log)
                         (has "\"command\":\"aflj\"" log))))

           ;; The process dies; the record is the truth.
           (let ((old (kill-rizin id)))
             (check "a killed rizin is replaced by the next call"
                    (and (has "rizin> iIj" (re:cmd "iIj"))
                         (not (eq old (omp-re::session-rz (omp-re:find-session id)))))))

           ;; The engine forgets the session; the record brings it back.
           (omp-re:shutdown-sessions)
           (check "a forgotten session is restored from its record: binary, hash, evidence"
                  (let ((status (re:status)))
                    (and (has (file-namestring *binary*) status)
                         (has "not running" status)
                         (omp-re::find-evidence evidence (omp-re:find-session id))
                         (= 64 (length (omp-re::session-binary-sha256 (omp-re:find-session id)))))))
           (check "and reads again without being reopened" (has "rizin> iIj" (re:cmd "iIj")))))

       ;; One rule for a relative path, whichever way it comes in: it is read
       ;; against the session's directory, and its spaces are its own.
       (uiop:copy-file *binary* (merge-pathnames "sample  two.bin" *scratch*))
       (flet ((opens-p (open)
                (let ((other (fresh-session)))
                  (in-session (other)
                    (funcall open other)
                    (has (scratch-path "sample  two.bin") (re:status))))))
         (check "a typed /re open reads a relative path against the session's directory"
                (opens-p (lambda (other)
                           (funcall (cdr (assoc "re" nle:*commands* :test #'string=))
                                    "open sample  two.bin" other))))
         (check "and so does (re:slash \"open ...\")"
                (opens-p (lambda (other) (declare (ignore other)) (re:slash "open sample  two.bin"))))
         (check "and (re:open)"
                (opens-p (lambda (other) (declare (ignore other)) (re:open "sample  two.bin"))))
         (check "and (re:call \"open_binary\")"
                (opens-p (lambda (other) (declare (ignore other))
                           (re:call "open_binary" :path "sample  two.bin")))))

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
                (let* ((session (omp-re:find-session id))
                       (rz (omp-re::ensure-rizin session)))
                  ;; A command is written and its frames never read, as an interrupt would leave it.
                  (sb-thread:with-mutex ((omp-re::rz-lock rz))
                    (setf (omp-re::rz-pending-marker rz) "__LEFT__")
                    (format (omp-re::rz-input rz) "pd 2~%echo __LEFT__~%")
                    (finish-output (omp-re::rz-input rz)))
                  (let ((text (re:cmd "iIj")))
                    (and (has "\"arch\"" text) (not (has "__LEFT__" text)))))))

       (check "a command past its deadline kills rizin, and the next call starts another"
              (in-session (id)
                (let* ((session (omp-re:find-session id))
                       (rz (omp-re::ensure-rizin session)))
                  (and (has "timed out" (refusal (lambda () (omp-re::rz-cmd rz "aaa" :seconds 0.01))))
                       (not (omp-re::rz-alive-p rz))
                       (has "rizin> iIj" (re:cmd "iIj"))))))

       (check "idle sessions are reaped, and come back on the next call"
              (in-session (id)
                (let ((session (omp-re:find-session id)))
                  (omp-re::reap-idle-sessions 0)
                  (and (null (omp-re::session-rz session))
                       (has "rizin> iIj" (re:cmd "iIj")))))))

     (let ((rz-before (loop for session being the hash-values of omp-re::*sessions*
                            when (omp-re::session-rz session) collect (omp-re::session-rz session))))
       (stop-running-cell)
       (check "stopping the cell ends every rizin process"
              (and rz-before (notany #'omp-re::rz-alive-p rz-before)))))))
