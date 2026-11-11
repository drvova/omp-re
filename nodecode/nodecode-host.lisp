;;;; nodecode-host.lisp --- the engine inside a nodecode organism: its record on a branch.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The nodecode host is this folder: the only place a name of nodecode's
;;;; kernel (nlk:) or of its evolved layer (nle:) appears. It is a package of
;;;; its own over the engine's exports (engine/package.lisp). Here: the
;;;; package, and what the engine's port (host.lisp) asks about a session's
;;;; record, answered for nodecode.

;;; The package is named for the cell's system, which is how nodecode's
;;; folder loader finds START-CELL in it, and nicknamed RE, so an eval form
;;; reads (re:cmd "aflj"). The verbs are its exports; it is meant to be used
;;; qualified only. OPEN is a verb, so CL's is shadowed. RE-ERROR and FAIL
;;; are shadowed because this package has its own, below.
(defpackage #:nodecode-re
  (:use #:cl #:omp-re)
  (:nicknames #:re)
  (:shadow #:open #:re-error)
  (:export #:open #:cmd #:json #:call #:tools #:doc #:slash #:status
           #:triage #:scan-imports #:inspect-function #:find-comparisons #:find-crypto
           #:re-error))

(in-package #:nodecode-re)

;;; RE-ERROR and FAIL as nodecode makes every peripheral's, so eval renders
;;; a refusal here as it renders any other; *RE*, RUNNING-SETTINGS and
;;; DEFINE-VERB. The engine signals its own condition (OMP-RE:RE-ERROR) and
;;; knows nothing of this one. Its surface answers a failure as data, which
;;; a verb turns into this RE-ERROR (verbs.lisp, ANSWER-TEXT); where the
;;; engine's condition can still reach a verb — holding a session for a
;;; recipe — it is translated there.
(nlk:define-peripheral re :not-running t)

;;; --- the branch a session is on ----------------------------------------------------------
;;; A nodecode session is a tree of turns: /tree moves its head to an earlier
;;; turn and new turns branch from there, /redo goes back, and /fork opens a
;;; session that reads its parent's turns up to the fork point. Evidence,
;;; annotations and the open binary follow the active branch: after a rewind,
;;; what an abandoned branch renamed is rolled back in rizin and what it
;;; observed no longer grounds a claim.
;;;
;;; So the record is the engine's file of entries, each stamped with the turn
;;; it was written in, and what a call reads is the entries whose turn is on
;;; the session's branch — its own, and through a fork's lineage its
;;; ancestors'. Nothing is deleted: a redo makes the same entries visible
;;; again.

(defun turn-stamped-append (session type data)
  (file-append-entry session type data (getf (nle:turn) :turn-id)))

(defun branch-entries (session)
  "SESSION's record as its current branch sees it: the entries whose turn is
on the branch — its ancestors' first, through a fork's lineage, then its own
— and those written outside any turn. Where nodecode keeps no session tree,
every entry is on the branch. A tree that cannot be read is an error, which
the engine's port turns into a refusal: the call fails rather than read
what an abandoned branch left."
  (multiple-value-bind (visible lineage)
      (if (nlk:store-open-p)
          (values (nlk:session-visible-turn-set (session-id session))
                  (nlk:session-lineage (session-id session)))
          (values nil nil))
    (if (and (null visible) (null lineage))
        (session-file-entries session)
        (let* ((sources (append (loop for (ancestor) in lineage
                                      for known = (and (stringp ancestor)
                                                       (string/= ancestor (session-id session))
                                                       (find-session ancestor))
                                      when known collect (session-file-entries known))
                                (list (session-file-entries session))))
               (current (getf (nle:turn) :turn-id))
               (key (list visible current (mapcar #'length sources)))
               (held (session-held session "branch view")))
          (if (and held (equal key (car held)) (eq visible (first (car held))))
              (cdr held)
              (let ((view (make-array 0 :adjustable t :fill-pointer 0)))
                (dolist (entries sources)
                  (loop for entry across entries
                        for turn = (jstring entry "turn")
                        ;; The running turn is on the branch by definition,
                        ;; whatever the store has recorded of it so far.
                        do (when (or (null turn) (null visible) (equal turn current) (gethash turn visible))
                             (vector-push-extend entry view))))
                (setf (session-held session "branch view") (cons key view))
                view))))))
