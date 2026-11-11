;;;; host.lisp --- the one port to the host: its settings and its services.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The engine runs inside a host — a nodecode organism (nodecode/), omp
;;;; through a stdio server (stdio/) — and a few things only the host can
;;;; say or do: what the operator configured, who is calling, where a
;;;; session's record is kept and which of it is on the current branch, how
;;;; to tell the operator something, whom to ask a side question. All of
;;;; that is here and nowhere else, so a second host is written without
;;;; touching the core.
;;;;
;;;; A setting the engine reads is declared once, in +SETTINGS+, and read
;;;; through SETTING-VALUE; a host that has a config file declares its
;;;; section from that table. The services are installed by the host at
;;;; start (INSTALL-HOST), cleared at stop, and asked through ASK-HOST. Each
;;;; has an answer for when no host is installed, so the core runs alone
;;;; (test/nodecode/suite-core.lisp loads it so).

(in-package #:omp-re)

;;; --- settings -------------------------------------------------------------------------

(defparameter +settings+
  '((:rizin-path :key "rizin_path" :type :path :default "" :env "OMPRE_RIZIN_PATH"
     :doc "the rizin to run when it is not the one on PATH")
    (:state-dir :key "state_dir" :type :directory :default "omp-re/"
     :doc "where session records, evidence, the audit log and reports are kept; a relative folder is under the home")
    (:allowed-dirs :key "allowed_dirs" :type :list :default () :env "OMPRE_ALLOWED_DIRS"
     :doc "directories binaries and other input files may be opened from; empty allows any file the organism can read")
    (:debugger :key "debugger" :type :boolean :default nil :env "OMPRE_ENABLE_DEBUGGER"
     :doc "offer rizin_debug, which EXECUTES the binary under analysis on this machine; leave off outside a sandbox")
    (:idle-minutes :key "idle_minutes" :type :integer :default 30 :min 1
     :doc "close the rizin process of a session unused this long; its next call restores it")
    (:audit :key "audit" :type :boolean :default t
     :doc "ask the model, in a side question that costs tokens, whether a finding's or a report claim's evidence supports it; off records them unaudited")
    (:rizin-path-64 :type :path :env "OMPRE_RIZIN_PATH_64")
    (:rizin-path-32 :type :path :env "OMPRE_RIZIN_PATH_32")
    (:load-user-config :type :boolean :default nil :env "OMPRE_RIZIN_LOAD_USER_CONFIG")
    (:analysis-timeout-ms :type :integer :default 300000 :env "OMPRE_ANALYSIS_TIMEOUT_MS")
    (:debug-timeout-ms :type :integer :default 60000 :env "OMPRE_DEBUG_TIMEOUT_MS")
    (:decompiler :type :string :env "OMPRE_DECOMPILER")
    (:output-dir :type :path :env "OMPRE_OUTPUT_DIR")
    (:audit-hmac-key :type :secret :env "OMPRE_AUDIT_HMAC_KEY"))
  "Every setting the engine reads, each (NAME &key key type default env doc
min): KEY its member of the `re' section, ENV its environment variable — a
setting may have either or both — and TYPE one of :path, :directory,
:string, :list (of strings; comma-separated in the environment), :boolean
(1, true, yes or on in the environment), :integer (a positive one) and
:secret, which is taken byte for byte: a signing key is not trimmed, or
logs signed before would no longer verify.")

(defun getenv (name)
  "The environment variable NAME as the host's process has it. A host that
runs the engine in a process of its own (the stdio server) says what its
environment holds; otherwise it is this process's."
  (if (host-service :environment)
      (values (ask-host :environment name))
      (uiop:getenv name)))

(defun env (name)
  (let ((value (getenv name)))
    (and value (not (blank-p value)) (trimmed value))))

(defun env-on-p (name)
  (let ((value (env name)))
    (and value (member value '("1" "true" "yes" "on") :test #'string-equal) t)))

(defun section-value (type value)
  "VALUE as the section gave it, in the one form the engine reads a setting
of TYPE in => (values VALUE SAID-P). A blank string and an empty list say
nothing. A :path or :directory may arrive as a string or a pathname."
  (ecase type
    ((:path :directory :string :secret)
     (let ((text (trimmed (if (pathnamep value) (uiop:native-namestring value) value))))
       (values (and (plusp (length text)) text) (plusp (length text)))))
    (:list
     (let ((items (remove-if #'blank-p
                             (mapcar #'trimmed (remove-if-not #'stringp (coerce value 'list))))))
       (values items (and items t))))
    (:boolean (values (and value t) t))
    (:integer (values value (integerp value)))))

(defun environment-value (type variable)
  (ecase type
    ((:path :directory :string) (env variable))
    (:secret (let ((value (getenv variable)))
               (and value (plusp (length value)) value)))
    (:list (remove-if #'blank-p
                      (mapcar #'trimmed
                              (uiop:split-string (or (env variable) "") :separator '(#\,)))))
    (:boolean (env-on-p variable))
    (:integer (let ((number (ignore-errors (parse-integer (or (env variable) "")))))
                (and number (plusp number) number)))))

(defun setting-value (name)
  "The setting NAME. One rule for all of them: what the operator's section
says, when it says something other than the declared default; else the
environment variable, when it is set; else the default. So `debugger: false'
— the default — does not veto OMPRE_ENABLE_DEBUGGER, and a rizin_path in the
section is taken over OMPRE_RIZIN_PATH. With no host there is no section."
  (destructuring-bind (&key key type default env &allow-other-keys)
      (rest (or (assoc name +settings+) (error "omp-re has no setting ~s" name)))
    (let ((default (section-value type default)))
      (multiple-value-bind (configured said)
          (multiple-value-bind (value present) (if key (ask-host :setting name) (values nil nil))
            (if present (section-value type value) (values nil nil)))
        (cond ((and said (not (equal configured default))) configured)
              ((and env (environment-value type env)))
              (t default))))))

(defun setting-variable (name)
  "The environment variable the setting NAME is read from, for a line that
tells the operator what to set."
  (or (getf (rest (assoc name +settings+)) :env)
      (error "omp-re: the setting ~s has no environment variable" name)))

;;; --- services ---------------------------------------------------------------------------

(defvar *host* '()
  "What the host does for the engine: a plist of functions installed at
start and cleared at stop. Every one is optional.
  :SETTING       (NAME)        the operator's section's value for the setting
                               NAME => (values VALUE PRESENT-P)
  :ENVIRONMENT   (NAME)        the environment variable NAME, where the
                               operator's environment is the host's process
                               and not this one => the value or NIL
  :VOICE         (KEY)         the host's own words for the phrase KEY (see
                               +VOICE+), or NIL for the engine's
  :HOME          ()            the directory a relative state_dir is under
  :TURN          ()            who is calling on this thread, a plist: the
                               engine reads its :SESSION-ID
  :DIRECTORY     (SESSION-ID)  the directory that session works in: what a
                               relative path in an argument is read against
  :ENTRIES       (SESSION)     the record store: SESSION's entries as its
                               current branch sees them, a vector, oldest
                               first, each a JSON object with members id,
                               customType and data. The same (EQ) vector
                               while nothing on the branch has changed
  :APPEND-ENTRY  (SESSION TYPE DATA)
                               write one entry of TYPE carrying the JSON
                               object DATA to SESSION's record, durably
                               => the entry
  :NOTIFY        (TEXT LEVEL)  tell the operator TEXT; LEVEL is :INFO,
                               :WARNING or :ERROR
  :JUDGE         (PROMPT)      a model's reply to a side question, or
                               (values NIL REASON)
  :PROGRESS      (TEXT)        a long analysis is under way (TEXT), or over
                               (NIL)
  :CANCELLED     ()            whether whoever asked for the call running on
                               this thread has given up on it
  :SAVE-ARTIFACT (SESSION CONTENT LABEL)
                               keep the whole of a result too large to send
                               => (values ID WHERE), WHERE being how a reader
                               is told to find it
  :READ-ARTIFACT (SESSION ID)  the whole text :SAVE-ARTIFACT kept under ID,
                               or NIL
  :LOCATE-ARTIFACT (SESSION ID)
                               how a reader is told to find the artifact ID:
                               what :SAVE-ARTIFACT answered as WHERE
  :TRANSCRIPT    (SESSION TYPE TEXT DETAILS)
                               show TEXT in the session's transcript as a
                               message of TYPE (re.binary), never sent to
                               the model
  :HAS-UI        ()            whether an operator is watching the call on
                               this thread and can be handed a draft or have
                               a message sent for them: without one a /re
                               line's answer is all that is said
  :KEEP-SESSION  (SESSION NAME)
                               what a /re line recorded must outlive the
                               process even if no model turn follows: write
                               the session now, and call it NAME where nobody
                               is watching and it has no name
With none installed — the engine alone — nothing is configured,
there is no turn, the record is the session's own file with every entry on
the branch, a notice is a line on the log, an artifact is a file beside the
record, nobody is watching and there is nobody to ask.")

(defun install-host (&rest services)
  "Make SERVICES — a plist as *HOST* describes — the host, and start what
the engine does for every host by itself: closing idle sessions' processes."
  (setf *host* services)
  (start-idle-reaper))

(defun clear-host ()
  (stop-idle-reaper)
  (setf *host* '()))

(defmacro with-host-service ((service function) &body body)
  "BODY with the host's SERVICE answered by FUNCTION, and the host as it was
after. Set, not bound: a thread BODY starts asks the same host."
  (let ((host (gensym "HOST")))
    `(let ((,host *host*))
       (setf *host* (list* ,service ,function ,host))
       (unwind-protect (progn ,@body)
         (setf *host* ,host)))))

(defun host-service (service)
  (getf *host* service))

(defun ask-host (service &rest arguments)
  "The host's answer to SERVICE for ARGUMENTS, all its values; NIL when the
host offers no such service. A service that signals is a refusal naming it:
whoever cannot go on without the answer lets that pass and so fails closed —
no entry is written unstamped because the turn could not be read, and none
is read because the branch could not be — and only a caller with a fallback
of its own handles it."
  (let ((function (host-service service)))
    (when function
      (handler-case (apply function arguments)
        (error (condition)
          (fail "omp-re: the host could not answer ~(~a~): ~a" service condition))))))

(defparameter +default-session+ "default"
  "The session a call outside any turn is for.")

(defun turn-session-id ()
  (or (getf (ask-host :turn) :session-id) +default-session+))

(defun notify (level control &rest arguments)
  "Tell the operator something outside any answer, at LEVEL — :INFO for what
is no fault, :WARNING, :ERROR. The one way the engine does: how loudly each
level is said is the host's. Without a host, or with one that could not be
told, it is a warning on the process's log."
  (let ((text (apply #'format nil control arguments)))
    (unless (and (host-service :notify)
                 (handler-case (progn (ask-host :notify text level) t)
                   (re-error () nil)))
      (warn "~a" text))
    text))

;;; --- the host's words ---------------------------------------------------------------------
;;; A few phrases name what only a host has: how its operator switches the
;;; debugger on, where a path to rizin is set, how eval reaches a tool, which
;;; keys a list answers to. The engine's text is otherwise one text; these
;;; are said in the host's voice, and a host says only the ones it says
;;; differently.

(defparameter +voice+
  '((:open-first . "use /re open <path> or the open_binary tool first")
    (:list-tools . "")
    (:read-more . "read the rest with rizin_command")
    (:debugger-switch . "OMPRE_ENABLE_DEBUGGER")
    (:debugger-enable . "set OMPRE_ENABLE_DEBUGGER")
    (:allowed-dirs . "OMPRE_ALLOWED_DIRS")
    (:rizin-path . "set OMPRE_RIZIN_PATH")
    (:launcher . "A program launched from a desktop")
    (:open-binary-note . "")
    (:help-keys . nil)
    (:list-hint . "~a")
    (:references-hint . "open")
    (:next-prompt . nil)
    (:slash . "/re ~a")
    (:manual-start . "omp-re — reverse engineering with rizin. Open a binary with open_binary, look a
command up with rizin_help, and read the binary with rizin_command.")
    (:manual-results . "How a result reads
  A read is recorded as evidence, so its text is: the header line (rizin> <cmd>),
  the body (JSON for a *j command), then a trailing [evidence …] tag line.")
    (:manual-tools . "The other (stateful) tools")
    (:manual-config . "Config
  OMPRE_RIZIN_PATH (rizin if not on PATH) · OMPRE_DECOMPILER (pdg/pdd order) ·
  OMPRE_ENABLE_DEBUGGER · OMPRE_AUDIT_HMAC_KEY.  Run /re status for live state."))
  "The phrases a host may say its own way, each with the engine's words for
it when no host does:
  :OPEN-FIRST        what to do when no binary is open
  :LIST-TOOLS        after `no tool named X', how the tools are listed
  :READ-MORE         after a list was cut, how the rest is read
  :DEBUGGER-SWITCH   what switched the debugger on
  :DEBUGGER-ENABLE   how to switch it on
  :ALLOWED-DIRS      what holds the directories files may be opened from
  :RIZIN-PATH        how the operator says where rizin is
  :LAUNCHER          what, started from a desktop, may not see the shell's PATH
  :OPEN-BINARY-NOTE  a sentence added to open_binary's description
  :HELP-KEYS         a last line of /re help: the keys the host binds
  :LIST-HINT         under a list on a screen, the keys it answers to; ~a
                     is what choosing a row does (open, cite, discuss)
  :REFERENCES-HINT   the same under a list of references
  :NEXT-PROMPT       where nobody is watching, how an agenda is passed on as
                     the next prompt: an example in brackets, or nothing
  :SLASH             how a /re line is run from where the model is; ~a is
                     the line
  :MANUAL-START      the manual rizin_command answers for an empty command
                     is the engine's (tools-core.lisp, MANUAL) around four
                     parts in the host's words. This one opens it: how the
                     model calls a tool here
  :MANUAL-RESULTS    its part on how a result reads here
  :MANUAL-TOOLS      the line over its list of the other tools
  :MANUAL-CONFIG     its last part: where the operator's settings are")

(defun voice (key)
  (or (and (host-service :voice) (ask-host :voice key))
      (cdr (or (assoc key +voice+) (error "omp-re has no phrase ~s" key)))))

(defun check-cancelled (what)
  "Leave, with a refusal naming WHAT was under way, a call whoever asked for
it has given up on. Called where a call waits — for rizin, for the session,
for a program — so a wait ends cleanly and nothing is left half-written."
  (when (and (host-service :cancelled) (ignore-errors (ask-host :cancelled)))
    (fail "omp-re: ~a aborted" what)))

(defun report-progress (text)
  "Say that a long analysis is under way, or with NIL that it is over.
Never signals: progress is a courtesy."
  (ignore-errors (ask-host :progress text))
  nil)

;;; --- where things are kept ----------------------------------------------------------------

(defun state-directory ()
  "The directory everything is kept under: state_dir, read against the
host's home when it is relative — and with no host, against the user's data
directory."
  (merge-pathnames (uiop:ensure-directory-pathname (expand-home (setting-value :state-dir)))
                   (or (ask-host :home) (uiop:xdg-data-home))))

(defun state-path (&rest parts)
  "A path under the state directory's re/ folder — the layout omp-re keeps
under omp's agent directory."
  (merge-pathnames (format nil "re/~{~a~^/~}" parts) (state-directory)))
