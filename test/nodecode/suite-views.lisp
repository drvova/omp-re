;;;; suite-views.lisp --- what a host with a screen is given, and what the engine holds to underneath.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The lines kept through a compaction, the status band's facts and the
;;;; code view (engine/views.lisp); then results cut to size, how rizin is
;;;; started and found, and a rizin command that is cancelled or whose
;;;; process dies — the behaviours the TypeScript engine's own tests held
;;;; before the Lisp engine was the only one.

(in-package #:nodecode-re-test)

(defun record-of (&rest entries)
  "A session, outside the table, whose record holds ENTRIES, each (TYPE . DATA)."
  (let ((session (re::make-session :id (fresh-session))))
    (loop for (type . data) in entries
          for index from 0
          do (vector-push-extend (re::obj "type" "custom" "id" (format nil "e~d" index)
                                          "customType" type "data" data)
                                 (re::session-file-entries session)))
    (re::sync-to-branch session)
    session))

(defun evidence-entry (id &optional ea)
  (cons "re.evidence" (re::obj "id" id "tool" "rizin_command" "ea" (or ea :absent) "summary" "s")))

(defun finding-entry (id claim &rest more)
  (cons "re.finding" (apply #'re::obj "id" id "claim" claim "evidenceIds" (vector "ev000001-x")
                            "confidence" "likely" more)))

;;; --- what survives a compaction ------------------------------------------------------------

(suite "views: the lines kept through a compaction")
(check "a session nothing was reverse engineered in keeps nothing"
       (null (re::preserved-lines (record-of))))
(check "the open binary, the counts, and the latest evidence by id, tool and address"
       (let ((lines (re::preserved-lines
                     (record-of (cons "re.binary" (re::obj "path" "/samples/a.out"))
                                (evidence-entry "aaaaaaaa-1" "0x401000")
                                (evidence-entry "bbbbbbbb-2")
                                (cons "re.annotation" (re::obj "kind" "set_comment" "ea" "0x401000"
                                                               "newValue" "entry"))))))
         (and (equal "omp-re reverse-engineering session (preserve — the model must not lose this):" (first lines))
              (member "- Open binary: a.out (/samples/a.out)" lines :test #'string=)
              (some (lambda (line) (starts "- Recorded: 2 evidence item(s), 1 annotation(s) in effect." line)) lines)
              (member "  · aaaaaaaa · rizin_command @ 0x401000" lines :test #'string=)
              (member "  · bbbbbbbb · rizin_command" lines :test #'string=)
              (starts "- Every address stated after this must still come from tool output" (car (last lines))))))
(check "the findings in effect are restated, a superseded or retracted one is not, and an inherited one says so"
       (let ((lines (re::preserved-lines
                     (record-of (cons "re.binary" (re::obj "path" "/samples/a.out"))
                                (evidence-entry "ev000001-x")
                                (finding-entry "f1111111-a" "It parses a config." "addr" "0x4010")
                                (finding-entry "f2222222-b" "First guess.")
                                (finding-entry "f3333333-c" "Second guess." "supersedes" "f2222222-b")
                                (finding-entry "f4444444-d" "Withdrawn.")
                                (cons "re.finding.retract" (re::obj "id" "f4444444-d" "reason" "wrong"))
                                (finding-entry "f5555555-e" "Carried over."
                                               "inherited" (re::obj "fromBinarySha256" "ab" "carryStatus" "holds"))))))
         (and (some (lambda (line) (starts "- Recorded findings (3;" line)) lines)
              (member "  · f1111111 [likely] It parses a config. (at 0x4010)" lines :test #'string=)
              (member "  · f3333333 [likely] Second guess." lines :test #'string=)
              (member "  · f5555555 [likely, inherited] Carried over." lines :test #'string=)
              (notany (lambda (line) (or (has "First guess." line) (has "Withdrawn." line))) lines))))
(check "only the latest eight evidence records are named, under the count of all of them"
       (let ((lines (re::preserved-lines
                     (apply #'record-of (cons "re.binary" (re::obj "path" "/samples/a.out"))
                            (loop for index below 20
                                  collect (evidence-entry (format nil "~8,'0d-x" index)))))))
         (and (some (lambda (line) (starts "- Recorded: 20 evidence item(s)" line)) lines)
              (= 8 (count-if (lambda (line) (starts "  · " line)) lines))
              (member "  · 00000019 · rizin_command" lines :test #'string=)
              (not (member "  · 00000011 · rizin_command" lines :test #'string=)))))
(check "evidence with no binary open says to open one again"
       (member "- Open binary: none currently open — reopen with open_binary before using other RE tools"
               (re::preserved-lines (record-of (evidence-entry "aaaaaaaa-1")))
               :test #'string=))

;;; --- results cut to size ---------------------------------------------------------------------

(suite "views: a result cut to size")
(check "a body within both limits is passed whole, its lead at the first character with nothing put between"
       (let ((result (re::build-result "LEAD" (format nil "one~%two"))))
         (and (string= (format nil "LEADone~%two") (re::result-text result))
              (not (nth-value 1 (gethash "truncated" (re::result-details result))))
              (not (nth-value 1 (gethash "artifactId" (re::result-details result)))))))
(check "a body over the size limit but under the line limit is cut at a whole line, and says how much is shown"
       (let* ((body (format nil "~{~a~^~%~}" (loop for index below 1500 collect (make-string 100 :initial-element #\x))))
              (result (re::text-result "header" body)))
         (multiple-value-bind (kept truncated shown total octets) (re::truncate-head body)
           (and truncated (< shown 1500) (= 1500 total) (<= octets (* 48 1024))
                (= shown (length (re::split-lines kept)))
                (has (format nil "[Output truncated: ~d of 1500 lines (" shown) (re::result-text result))
                (eq t (gethash "truncated" (re::result-details result)))))))
(check "the part of a result its evidence record carries is at most 512 octets and never half a character"
       (let ((clipped (re::clip-utf-8 (make-string 400 :initial-element (code-char 233)) re::+summary-octets+)))
         (and (= 256 (length clipped)) (= 512 (re::utf-8-size clipped)))))
(with-cell ()
  (let ((id (fresh-session)))
    (in-session (id)
      (check "a call whose result is not cut keeps no artifact: its answer names none"
             (let ((answer (re::engine-call id "rizin_command" (re::obj "command" ""))))
               (and (null (gethash "artifactPath" answer))
                    (null (re::jget answer "details" "artifactId"))
                    (null (uiop:directory-files
                           (merge-pathnames "artifacts/" (re::session-directory (re::find-session id)))))))))))

;;; --- how rizin is started and found ----------------------------------------------------------

(suite "views: starting and finding rizin")
(check "load settings become rizin's flags, and nothing given is no flags"
       (and (null (re::build-load-flags nil))
            (null (re::build-load-flags (re::obj)))
            (equal '("-a" "x86" "-b" "32") (re::build-load-flags (re::obj "arch" "x86" "bits" 32)))
            (equal '("-B" "0x400000") (re::build-load-flags (re::obj "base" "0x400000")))
            (equal '("-m" "0x400000") (re::build-load-flags (re::obj "map" "0x400000")))
            (equal '("-F" "any") (re::build-load-flags (re::obj "format" "any")))))
(check "a load setting that is nonsense or shaped like a flag is refused in words before rizin starts"
       (and (has "omp-re: load: invalid bits" (refusal (lambda () (re::build-load-flags (re::obj "bits" 7)))))
            (has "omp-re: load: invalid arch" (refusal (lambda () (re::build-load-flags (re::obj "arch" "-rm")))))
            (has "omp-re: load: invalid format" (refusal (lambda () (re::build-load-flags (re::obj "format" "a b")))))
            (has "omp-re: invalid address" (refusal (lambda () (re::build-load-flags (re::obj "base" "0x1; id")))))))
(check "every rizin on a pipe gets the NUL-framed protocol, plain output and no user config; OMPRE_RIZIN_LOAD_USER_CONFIG lets the rizinrc load"
       (and (with-environment ("OMPRE_RIZIN_LOAD_USER_CONFIG" nil)
              (equal '("-q0" "-e" "scr.color=0" "-e" "scr.utf8=false" "-N") (re::base-rizin-flags)))
            (with-environment ("OMPRE_RIZIN_LOAD_USER_CONFIG" "1")
              (equal '("-q0" "-e" "scr.color=0" "-e" "scr.utf8=false") (re::base-rizin-flags)))))
(check "an rz-* program is taken from beside the configured rizin, with its extension; a bare rizin leaves it bare"
       (flet ((beside (rizin tool) (with-environment ("OMPRE_RIZIN_PATH" rizin) (re::resolve-rizin-tool tool))))
         (and (equal "rz-bin" (beside "rizin" "rz-bin"))
              (equal "/opt/rizin/bin/rz-bin" (beside "/opt/rizin/bin/rizin" "rz-bin"))
              (equal "C:\\rizin\\bin\\rz-hash.exe" (beside "C:\\rizin\\bin\\rizin.exe" "rz-hash"))
              (equal "rz-ax.exe" (beside "rizin.exe" "rz-ax")))))
(check "a path given to rizin has forward slashes, and is one quoted argument so a ~ short name is not its grep operator"
       (and (equal "C:/Users/runneradmin/AppData/Local/Temp/omp-re-out/a.rzdb"
                   (re::to-rizin-path "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\omp-re-out\\a.rzdb"))
            (equal "/tmp/omp-re-out/a.rzdb" (re::to-rizin-path "/tmp/omp-re-out/a.rzdb"))
            (equal "'C:/Users/RUNNER~1/AppData/Local/Temp/omp-re-out/a.rzdb'"
                   (re::rizin-path-arg "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\omp-re-out\\a.rzdb"))))
(check "the decompilers looked for are OMPRE_DECOMPILER's, then pdg and pdd; each has a name a status can say"
       (and (with-environment ("OMPRE_DECOMPILER" "pdd, r2dec ,;rm")
              (equal '("pdd" "r2dec" "pdg") (re::decompiler-commands)))
            (equal "rz-ghidra (pdg)" (re::decompiler-label "pdg"))
            (equal "jsdec (pdd)" (re::decompiler-label "pdd"))
            (equal "r2dec (plugin)" (re::decompiler-label "r2dec"))
            (equal "none — pdg/pdd fall back to labeled disassembly" (re::decompiler-label nil))))

;;; A rizin on Windows ends its lines with CRLF. A stand-in that does is
;;; enough to hold the engine to reading them as lines.
#-win32
(let ((stand-in (scratch-path "crlf-rizin.sh")))
  (write-scratch "crlf-rizin.sh"
                 (format nil "#!/bin/sh~%printf '\\0'~%while IFS= read -r line; do~%  case \"$line\" in~%    'echo '*) printf '%s\\r\\n\\0' \"${line#echo }\" ;;~%    *) printf 'int main() {\\r\\n  return 0;\\r\\n}\\r\\n\\0' ;;~%  esac~%done~%"))
  (sb-posix:chmod stand-in #o755)
  (let ((rz (re::spawn-rz stand-in *binary* :analysis nil)))
    (unwind-protect
         (check "what a rizin that ends lines with CRLF prints is read as plain lines"
                (string= (format nil "int main() {~%  return 0;~%}~%") (re::rz-cmd rz "pdg")))
      (re::rz-close rz))))

;;; --- against rizin -------------------------------------------------------------------------------

(suite "views: against rizin")
(if (not *rizin*)
    (format t "  SKIPPED (rizin or ~a is absent)~%" *binary*)
    (with-cell ()
      (let* ((id (fresh-session))
             (session (in-session (id) (re:open *binary*) (re::find-session id))))
        (in-session (id)
          (check "the status band's facts are read from the running rizin: format, arch, entry, protections, counts"
                 (let ((facts (re::engine-facts id)))
                   (and (equal (file-namestring *binary*) (gethash "name" facts))
                        (plusp (gethash "size" facts))
                        (stringp (gethash "format" facts))
                        (has "/" (gethash "arch" facts))
                        (starts "0x" (gethash "entry" facts))
                        (vectorp (gethash "prot" facts))
                        (plusp (gethash "fnCount" facts))
                        (eql 0 (gethash "evidence" facts)))))
          (check "a decompiler that is loaded but says nothing for the function is said so, over the disassembly"
                 (with-environment ("OMPRE_DECOMPILER" "echo")
                   (setf (re::session-held session "decompiler") nil)
                   (let ((code (re::engine-view id "code" (re::obj "addr" "main"))))
                     (and (equal "(disassembly only — the decompiler produced no output for this function)"
                                 (re::jstring code "decompile" "note"))
                          (equal "warning" (re::jstring code "decompile" "tone"))
                          (null (re::jget code "decompile" "language"))
                          (string= (re::jstring code "decompile" "code")
                                   (re::join-lines (coerce (gethash "disasm" code) 'list)))))))
          (check "one that answers is shown as code, named for the command that made it"
                 (with-environment ("OMPRE_DECOMPILER" "pdsf")
                   (setf (re::session-held session "decompiler") nil)
                   (let ((code (re::engine-view id "code" (re::obj "addr" "main"))))
                     (and (equal "// decompiled with pdsf" (re::jstring code "decompile" "note"))
                          (equal "c" (re::jstring code "decompile" "language"))
                          (plusp (length (re::jstring code "decompile" "code")))))))
          (setf (re::session-held session "decompiler") nil)
          (check "an import with no stub to follow says so in place of a list; the strings are a panel"
                 (and (equal "notice" (gethash "type" (re::engine-view id "import-callers"
                                                                       (re::obj "addr" "" "name" "free"))))
                      (member (gethash "type" (re::engine-view id "strings")) '("panel") :test #'equal)))
          (check "a chain of references is followed eight views deep and no further"
                 (and (equal "code" (gethash "type" (re::engine-view id "code" (re::obj "addr" "main" "depth" 8))))
                      (has "xref chain too deep"
                           (gethash "text" (re::engine-view id "code" (re::obj "addr" "main" "depth" 9))))))
          (check "a view of a session with no binary is a notice saying so, not an error"
                 (let ((view (re::engine-view (fresh-session) "functions")))
                   (and (equal "notice" (gethash "type" view)) (equal "error" (gethash "level" view))
                        (has "no binary open" (gethash "text" view)))))

          (let ((rz (re::session-rz session))
                (given-up nil))
            (check "a command whose caller gives up is left at once, and the next command still reads its own answer from the same process"
                   (with-service (:cancelled (lambda () given-up))
                     (let* ((began (get-internal-real-time))
                            (watcher (sb-thread:make-thread (lambda () (sleep 0.3) (setf given-up t))))
                            (said (refusal (lambda () (re::rz-cmd rz "sleep 2")))))
                       (sb-thread:join-thread watcher)
                       (setf given-up nil)
                       (and (equal "omp-re: rizin command \"sleep 2\" aborted" said)
                            (< (- (get-internal-real-time) began) internal-time-units-per-second)
                            (equal "aligned" (re::trimmed (re::rz-cmd rz "echo aligned")))
                            (eq rz (re::session-rz session))
                            (re::rz-alive-p rz))))))

          (check "two calls that find rizin dead share one respawn, and both are answered"
                 (let ((analyses 0)
                       (answers '()))
                   (kill-rizin id)
                   (with-service (:progress (lambda (text) (when text (incf analyses))))
                     (let ((threads (loop repeat 2
                                          collect (sb-thread:make-thread
                                                   (lambda ()
                                                     (let ((nle:*stub-session* id))
                                                       (re::engine-call id "rizin_command" (re::obj "command" "ij"))))))))
                       (setf answers (mapcar #'sb-thread:join-thread threads))))
                   (and (= 1 analyses)
                        (notany (lambda (answer) (gethash "failed" answer)) answers)
                        (every (lambda (answer) (starts "rizin> ij" (gethash "text" answer))) answers))))))))
