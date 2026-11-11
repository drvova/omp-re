;;;; verb-forms.lisp --- GENERATED from recipes/api.json. Do not edit.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Regenerate with: bun scripts/gen-api.ts
;;;; The verbs the model calls from eval. What each takes, what it does and
;;;; how it refuses is said once, so these and omp's two eval libraries
;;;; (skills/re-triage/recipes.js and recipes.py) are the same verbs.
;;;; verbs.lisp is what they call; scripts/gen-api.ts says what each part of
;;;; the description means.

(in-package #:nodecode-re)

(define-verb open (path &rest options &key &allow-other-keys)
  "Open the binary at PATH for this session and analyze it; every other verb acts on the binary
opened last. The options arch, bits, base, map and format force how a raw or headerless file is
loaded."
  (unless (and (stringp path) (not (blank-p path)))
    (fail "a path must be a non-empty string, not ~s" path))
  (answer-text (call-for-turn "open_binary" (list* :path path options))))

(define-verb cmd (command &optional addr)
  "Run one read-only rizin COMMAND on the open binary, at ADDR when given: the one way to read it. An
empty command answers the engine's manual."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (answer-text (call-for-turn "rizin_command" (list :command command :addr addr))))

(define-verb json (command &optional addr)
  "Run one read-only rizin COMMAND whose output is JSON, a *j command, and answer the data itself
with the id of the evidence record the read left. Reads the whole output even when it is past the
size cap a result's text is cut at."
  (unless (stringp command)
    (fail "a rizin command is a string, not ~s" command))
  (answer-data command (call-for-turn "rizin_command" (list :command command :addr addr))))

(define-verb call (tool &rest arguments)
  "Call the engine's TOOL, a name the verb tools lists, with its arguments."
  (unless (stringp tool)
    (fail "a tool is named by a string, as (re:tools) lists them, not ~s" tool))
  (answer-text (call-for-turn (engine-name tool) arguments)))

(define-verb tools ()
  "Every tool the engine offers, one line each."
  (answer-text (line-for-turn "tools")))

(define-verb doc (tool)
  "What the engine's TOOL does and the arguments it takes."
  (answer-text (line-for-turn (format nil "doc ~a" (engine-name tool)))))

(define-verb slash (line)
  "Run one of the lines the engine's text calls /re lines (\"functions\", \"evidence\", \"findings\",
\"verify\", \"report out.md\", \"undo\", \"help\") and answer what it says."
  (answer-text (line-for-turn line)))

(define-verb status ()
  "The engine's state for this session: rizin, the open binary, evidence and findings."
  (answer-text (line-for-turn "status")))
