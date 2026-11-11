;;;; host.lisp --- the one port to the host: its settings and its services.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The engine runs inside a host — a nodecode organism (cell.lisp), omp
;;;; through a stdio server — and a few things only the host can say or do:
;;;; what the operator configured, who is calling, where a session's record
;;;; is kept and which of it is on the current branch, how to tell the
;;;; operator something, whom to ask a side question. All of that is here and
;;;; nowhere else, so a second host is written without touching the core.
;;;;
;;;; A setting is declared once, in +SETTINGS+, and read through
;;;; SETTING-VALUE; a host's own declaration of the section and
;;;; config.example.jsonc are written from that table. The services are
;;;; installed by the host at start (INSTALL-HOST), cleared at stop, and
;;;; asked through ASK-HOST. Each has an answer for when no host is
;;;; installed, so the core runs alone under a test.

(in-package #:nodecode-re)

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
    (:audit-seconds :key "audit_seconds" :type :integer :default 120 :min 1
     :doc "how long a support audit waits for its answer before the claim goes unaudited")
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
:secret, which is taken byte for byte: a signing key is not trimmed, since
the TypeScript engine signs with it as set.")

(defun env (name)
  "The environment variable NAME, trimmed, or NIL when unset or blank."
  (let ((value (uiop:getenv name)))
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
    (:secret (let ((value (uiop:getenv variable)))
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

(defun section-fields ()
  "The members of the `re' section as a nodecode cell declares them:
(KEY TYPE :default FORM [:min N] :doc TEXT)."
  (loop for (nil . options) in +settings+
        when (getf options :key)
          collect `(,(getf options :key) ,(getf options :type)
                    :default ,(getf options :default)
                    ,@(when (getf options :min) (list :min (getf options :min)))
                    :doc ,(format nil "~a~@[ (the engine's ~a)~]"
                                  (getf options :doc) (getf options :env)))))

(defun config-example ()
  "config.example.jsonc, written from the declaration."
  (with-output-to-string (out)
    (format out "// The section ~~/.nodecode/config.jsonc may carry for this cell —~%")
    (format out "// documentation, not config: the folder gets pushed and holds no secret.~%")
    (format out "// Written from the declaration in nodecode/host.lisp, and the Lisp suite~%")
    (format out "// checks the two agree. A present section is enabled; \"enabled\": false~%")
    (format out "// vetoes it. Every member is optional. Where a member names an environment~%")
    (format out "// variable, that variable is read while the member is left at its default.~%")
    (format out "{~%  \"re\": {~%    \"enabled\": true")
    (loop for (nil . options) in +settings+
          for doc = (getf options :doc)
          when (getf options :key)
            do (format out ",~%    // ~a~a.~@[ Environment: ~a.~]~%    ~a: ~a"
                       (char-upcase (char doc 0)) (subseq doc 1) (getf options :env)
                       (json-encode (getf options :key))
                       (ecase (getf options :type)
                         (:list (json-encode (coerce (getf options :default) 'simple-vector)))
                         (:boolean (if (getf options :default) "true" "false"))
                         ((:path :directory :integer) (json-encode (getf options :default))))))
    (format out "~%  }~%}~%")))

;;; --- services ---------------------------------------------------------------------------

(defvar *host* '()
  "What the host does for the engine: a plist of functions installed at
start and cleared at stop. Every one is optional.
  :SETTING       (NAME)        the operator's section's value for the setting
                               NAME => (values VALUE PRESENT-P)
  :HOME          ()            the directory a relative state_dir is under
  :TURN          ()            who is calling on this thread, a plist of
                               :SESSION-ID and :TURN-ID (the turn or leaf an
                               entry written now belongs to)
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
  :SAVE-ARTIFACT (SESSION CONTENT LABEL)
                               keep the whole of a result too large to send
                               => (values ID WHERE), WHERE being how a reader
                               is told to find it
  :READ-ARTIFACT (SESSION ID)  the whole text :SAVE-ARTIFACT kept under ID,
                               or NIL
  :TRANSCRIPT    (SESSION TYPE TEXT DETAILS)
                               show TEXT in the session's transcript as a
                               message of TYPE (re.binary), never sent to
                               the model
  :SEND-USER-MESSAGE (SESSION TEXT)
                               send TEXT to the model as the operator's
                               next message
  :HAS-UI        ()            whether an operator is watching: without one
                               a /re line's answer is all that is said
  :SESSION-NAME  (SESSION-ID)  what the operator calls that session
With none installed — the engine alone under a test — nothing is configured,
there is no turn, the record is the session's own file with every entry on
the branch, a notice is a line on the log, an artifact is a file beside the
record, nobody is watching and there is nobody to ask.")

(defun install-host (&rest services)
  (setf *host* services))

(defun clear-host ()
  (setf *host* '()))

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

(defun current-turn-id ()
  (getf (ask-host :turn) :turn-id))

(defun notify (level control &rest arguments)
  "Tell the operator something they should not miss, at LEVEL — :INFO,
:WARNING or :ERROR. Without a host, or with one that could not be told, it
is a warning on the process's log."
  (let ((text (apply #'format nil control arguments)))
    (unless (and (host-service :notify)
                 (handler-case (progn (ask-host :notify text level) t)
                   (re-error () nil)))
      (warn "~a" text))
    text))

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
