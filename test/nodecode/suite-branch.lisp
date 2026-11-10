;;;; suite-branch.lisp --- the record follows the session's branch: /tree,
;;;; /redo and /fork; a citation as a draft; what lasts as a notice.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; nodecode's session is a tree of turns. The stand-in lets a test say
;;;; which turns are on a session's branch (nlk:*stub-visible*), which
;;;; sessions it was forked from (nlk:*stub-lineage*) and which turn is
;;;; running (nle:*stub-turn*), which is all the cell reads of the tree.

(in-package #:nodecode-re-test)

(defun branch (session-id &rest turns)
  "Say that SESSION-ID's branch is exactly TURNS."
  (let ((table (make-hash-table :test #'equal)))
    (dolist (turn turns) (setf (gethash turn table) t))
    (setf (gethash session-id nlk:*stub-visible*) table)))

(defmacro in-turn ((session-id turn) &body body)
  `(let ((nle:*stub-session* ,session-id) (nle:*stub-turn* ,turn)) ,@body))

(defun forget-tree ()
  (clrhash nlk:*stub-visible*)
  (clrhash nlk:*stub-lineage*))

(suite "branch: the record alone")
(with-cell ()
  (let* ((id (fresh-session))
         (session (re::find-session id)))
    (unwind-protect
         (progn
           (in-turn (id "t1") (re::with-session (session) (re::append-entry "re.note" (re::obj "n" 1))))
           (in-turn (id "t2") (re::with-session (session) (re::append-entry "re.note" (re::obj "n" 2))))
           (in-turn (id nil) (re::with-session (session) (re::append-entry "re.note" (re::obj "n" 0))))
           (check "an entry is stamped with the turn it was written in, and one written outside a turn with none"
                  (equal '("t1" "t2" nil)
                         (map 'list (lambda (entry) (gethash "turn" entry)) (re::session-all-entries session))))
           (check "with no session tree to read, every entry is on the branch"
                  (= 3 (length (re::session-entries session))))
           (branch id "t1" "t2")
           (check "on the branch that holds both turns, all three are read"
                  (equal '(1 2 0) (mapcar (lambda (data) (gethash "n" data)) (re::entries-of "re.note" session))))
           (branch id "t1")
           (check "after a rewind to the first turn, the second turn's entry is not read; the turnless one still is"
                  (equal '(1 0) (mapcar (lambda (data) (gethash "n" data)) (re::entries-of "re.note" session))))
           (check "nothing was deleted: the record on disk still holds all three"
                  (= 3 (length (re::split-lines (re::trimmed (re::read-text-file (re::record-path session)))))))
           (in-turn (id "t3")
             (check "the running turn's own entries are read whatever the store has recorded of it"
                    (progn (re::with-session (session) (re::append-entry "re.note" (re::obj "n" 3)))
                           (equal '(1 0 3) (mapcar (lambda (data) (gethash "n" data))
                                                   (re::entries-of "re.note" session))))))
           (branch id "t1" "t2")
           (check "a redo makes the abandoned branch's entry visible again"
                  (equal '(1 2 0) (mapcar (lambda (data) (gethash "n" data)) (re::entries-of "re.note" session))))
           ;; A fork reads its parent's turns up to the fork point.
           (let* ((fork (fresh-session))
                  (forked (progn (setf (gethash fork nlk:*stub-lineage*) (list (list id "t1" 10)))
                                 (branch fork "t1" "f1")
                                 (re::find-session fork))))
             (in-turn (fork "f1") (re::with-session (forked) (re::append-entry "re.note" (re::obj "n" 9))))
             (check "a fork reads its parent's entries up to the fork point, then its own"
                    (equal '(1 0 9) (mapcar (lambda (data) (gethash "n" data)) (re::entries-of "re.note" forked))))
             (check "and writes only to its own record: the parent does not see the fork's entry"
                    (notany (lambda (data) (eql 9 (gethash "n" data))) (re::entries-of "re.note" session)))))
      (forget-tree))))

(cond
  ((not *rizin*)
   (suite "branch: rizin")
   (format t "  SKIPPED — no rizin on PATH or no test binary at ~a~%" *binary*))
  (t
   (suite (format nil "branch: rizin (~a)" *binary*))
   (with-cell ()
     (let ((id (fresh-session)))
       (unwind-protect
            (progn
              (branch id "t1" "t2")
              (in-turn (id "t1")
                (re:open *binary*)
                (re:cmd "iIj"))
              (let (second-evidence)
                (in-turn (id "t2")
                  (setf second-evidence (re::evidence-id-of (re:cmd "pd 2" "entry0")))
                  (re:call "set_comment" :addr "entry0" :text "branch: second turn")
                  (re:call "record_finding" :claim "The entry point begins as rizin disassembles it."
                                            :evidence (list second-evidence))
                  (check "on the branch that made them: the comment is in rizin, the evidence and the finding are read"
                         (and (has "branch: second turn" (re:cmd "pd 1" "entry0"))
                              (has "annotations in effect: 1" (re:status))
                              (has "findings on this branch: 1" (re:status)))))
                (let ((rz (re::session-rz (re::find-session id))))
                  ;; /tree: back to the first turn. The second turn's work is on another branch now.
                  (branch id "t1" "t3")
                  (in-turn (id "t3")
                    (check "after a rewind the open binary stays, and what the abandoned branch did is not counted"
                           (let ((status (re:status)))
                             (and (has (file-namestring *binary*) status)
                                  (has "annotations in effect: 0" status)
                                  (has "findings on this branch: 0" status)
                                  (has "evidence on this branch: 1" status))))
                    (check "the rizin that carried the abandoned annotation is gone, and the fresh one does not have it"
                           (and (not (has "branch: second turn" (re:cmd "pd 1" "entry0")))
                                (not (eq rz (re::session-rz (re::find-session id))))))
                    (check "evidence from the abandoned branch no longer grounds a finding"
                           (refusal (lambda () (re:call "record_finding" :claim "Unsupported here."
                                                                         :evidence (list second-evidence)))))
                    (check "and there is no annotation of this branch to undo"
                           (refusal (lambda () (re:slash "undo")))))
                  ;; /redo: the branch that was left is the branch again.
                  (branch id "t1" "t2")
                  (in-turn (id "t2")
                    (check "after a redo its annotation is replayed and its finding is back"
                           (and (has "branch: second turn" (re:cmd "pd 1" "entry0"))
                                (has "findings on this branch: 1" (re:status)))))))

              ;; /fork at the first turn: the fork has the binary and the first turn's evidence only.
              (let ((fork (fresh-session)))
                (setf (gethash fork nlk:*stub-lineage*) (list (list id "t1" 10)))
                (branch fork "t1" "f1")
                (in-turn (fork "f1")
                  (check "a fork starts with its parent's binary open and reads at once, without reopening"
                         (and (has (file-namestring *binary*) (re:status))
                              (has "rizin> iIj" (re:cmd "iIj"))))
                  (check "it has the evidence of the turns before the fork point and none of the later work"
                         (let ((status (re:status)))
                           (and (has "annotations in effect: 0" status) (has "findings on this branch: 0" status))))
                  (re:call "set_comment" :addr "entry0" :text "branch: in the fork"))
                (in-turn (id "t2")
                  (check "what the fork annotates is the fork's: its parent's rizin and record are untouched"
                         (and (not (has "branch: in the fork" (re:cmd "pd 1" "entry0")))
                              (has "annotations in effect: 1" (re:status)))))))
         (forget-tree)))

     ;; A citation, where the caller has an input box.
     (let ((id (fresh-session)))
       (in-session (id)
         (re:open *binary*)
         (let* ((evidence (re::evidence-id-of (re:cmd "iIj")))
                (command (cdr (assoc "re" nle:*commands* :test #'string=))))
           (check "/re cite from a shell that takes a draft puts the citation in the input box"
                  (let ((nle:*slash-effects* '(:clipboard :draft)))
                    (multiple-value-bind (text dialog effects) (funcall command (format nil "cite ~a" evidence) id)
                      (and (has "is in your draft" text) (null dialog)
                           (eq :draft (first (first effects)))
                           (has (format nil "Re: evidence ~a" evidence) (second (first effects)))))))
           (check "from a caller with no input box the citation is the answer, and no effect is claimed"
                  (let ((nle:*slash-effects* nil))
                    (multiple-value-bind (text dialog effects) (funcall command (format nil "cite ~a" evidence) id)
                      (and (has (format nil "Re: evidence ~a" evidence) text) (null dialog) (null effects)))))))))

   (suite "branch: what lasts is a notice")
   (with-cell ()
     (let ((id (fresh-session)))
       (in-session (id)
         (re:open *binary*)
         (re:call "set_comment" :addr "entry0" :text "notice: fine")
         ;; A recorded annotation that cannot be replayed: its address resolves to nothing.
         (let ((session (re::find-session id)))
           (re::with-session (session)
             (re::append-entry "re.annotation"
                               (re::obj "kind" "comment" "ea" "0xffffffffffff0000" "oldValue" :null
                                        "newValue" "notice: lost" "evidenceId" :null "ungrounded" t)))
           (nlk:kill-tree (re::rz-pid (re::session-rz session)))
           (loop repeat 50 while (re::rz-alive-p (re::session-rz session)) do (sleep 0.1)))
         (re:cmd "iIj")
         (check "a replay that fails stands as a keyed notice the model reads, not a line in a log"
                (let ((notice (gethash "nodecode-re" nle:*notices*)))
                  (has "could not be replayed" notice))))))
   (check "stopping the cell clears its notice" (null (gethash "nodecode-re" nle:*notices*)))))
