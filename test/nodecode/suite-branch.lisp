;;;; suite-branch.lisp --- the record follows the session's branch: /tree,
;;;; /redo and /fork; a citation as a draft; what lasts as a notice.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; nodecode's session is a tree of turns. The stand-in lets a test say
;;;; which turns are on a session's branch (nlk:*stub-visible*), which
;;;; sessions it was forked from (nlk:*stub-lineage*) and which turn is
;;;; running (nle:*stub-turn*), which is all the cell reads of the tree.

(in-package #:omp-re-test)

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

(defun note (session-id turn n)
  "Write the note N to SESSION-ID's record in TURN."
  (in-turn (session-id turn)
    (omp-re::in-session (session-id "writing a note")
      (omp-re::append-entry "re.note" (omp-re:obj "n" n)))))

(defun notes (session-id)
  (mapcar (lambda (data) (gethash "n" data)) (omp-re::entries-of "re.note" (omp-re:find-session session-id))))

(suite "branch: the record alone")
(with-cell ()
  (let* ((id (fresh-session))
         (session (omp-re:find-session id)))
    (unwind-protect
         (progn
           (note id "t1" 1)
           (note id "t2" 2)
           (note id nil 0)
           (check "an entry is stamped with the turn it was written in, and one written outside a turn with none"
                  (equal '("t1" "t2" nil)
                         (map 'list (lambda (entry) (gethash "turn" entry)) (omp-re:session-file-entries session))))
           (check "with no session tree to read, every entry is on the branch"
                  (equal '(1 2 0) (notes id)))
           (branch id "t1" "t2")
           (check "on the branch that holds both turns, all three are read"
                  (equal '(1 2 0) (notes id)))
           (branch id "t1")
           (check "after a rewind to the first turn, the second turn's entry is not read; the turnless one still is"
                  (equal '(1 0) (notes id)))
           (check "nothing was deleted: the record on disk still holds all three"
                  (= 3 (length (omp-re:split-lines (omp-re:trimmed (omp-re::read-text-file (omp-re::record-path session)))))))
           (check "the running turn's own entries are read whatever the store has recorded of it"
                  (progn (note id "t3" 3)
                         (in-turn (id "t3") (equal '(1 0 3) (notes id)))))
           (branch id "t1" "t2")
           (check "a redo makes the abandoned branch's entry visible again"
                  (equal '(1 2 0) (notes id)))
           ;; A fork reads its parent's turns up to the fork point.
           (let ((fork (fresh-session)))
             (setf (gethash fork nlk:*stub-lineage*) (list (list id "t1" 10)))
             (branch fork "t1" "f1")
             (note fork "f1" 9)
             (check "a fork reads its parent's entries up to the fork point, then its own"
                    (in-turn (fork "f1") (equal '(1 0 9) (notes fork))))
             (check "and writes only to its own record: the parent does not see the fork's entry"
                    (not (member 9 (notes id))))))
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
                  (setf second-evidence (tagged-evidence (re:cmd "pd 2" "entry0")))
                  (re:call "set_comment" :addr "entry0" :text "branch: second turn")
                  (re:call "record_finding" :claim "The entry point begins as rizin disassembles it."
                                            :evidence (list second-evidence))
                  (check "on the branch that made them: the comment is in rizin, the evidence and the finding are read"
                         (and (has "branch: second turn" (re:cmd "pd 1" "entry0"))
                              (has "annotations in effect: 1" (re:status))
                              (has "findings on this branch: 1" (re:status)))))
                (let ((rz (omp-re::session-rz (omp-re:find-session id))))
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
                                (not (eq rz (omp-re::session-rz (omp-re:find-session id))))))
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

     ;; What a branch did to rizin without annotating — a mapped file, an
     ;; analysis pass, a signature file — goes with the branch too.
     (let ((id (fresh-session))
           (overlay (write-scratch "branch-overlay.bin" "BRANCHMAPPEDDATA")))
       (unwind-protect
            (progn
              (branch id "t1" "t2")
              (in-turn (id "t1")
                (re:open *binary*))
              (in-turn (id "t2")
                (re:call "map_file" :path overlay :addr "0x5f0000")
                (check "on the branch that mapped a file its bytes are read"
                       (has "4252414e43484d4150504544" (re:cmd "p8 12" "0x5f0000"))))
              (branch id "t1" "t3")
              (in-turn (id "t3")
                (check "after a rewind to before the map, rizin no longer has it"
                       (not (has "4252414e43484d4150504544" (re:cmd "p8 12" "0x5f0000")))))
              (branch id "t1" "t2")
              (in-turn (id "t2")
                (check "and after a redo it is mapped again"
                       (has "4252414e43484d4150504544" (re:cmd "p8 12" "0x5f0000")))))
         (forget-tree))))

   (suite "branch: what lasts is a notice")
   (with-cell ()
     (let ((id (fresh-session)))
       (in-session (id)
         (re:open *binary*)
         (re:call "set_comment" :addr "entry0" :text "notice: fine")
         ;; A recorded annotation that cannot be replayed: a comment at
         ;; something that is no address, which the engine will not send rizin.
         (omp-re::in-session (id "recording an annotation that cannot be replayed")
           (omp-re::append-entry "re.annotation"
                             (omp-re:obj "kind" "set_comment" "ea" "no;where" "oldValue" ""
                                      "newValue" "notice: lost" "evidenceId" :null "ungrounded" t)))
         (kill-rizin id)
         (re:cmd "iIj")
         (check "a replay that fails stands as a keyed notice the model reads, not a line in a log: it counts the annotation that was lost, names it, and the one that went back is in rizin"
                (let ((notice (gethash "nodecode-re" nle:*notices*)))
                  (and (has "omp-re: 1 annotation(s) could not be replayed:" notice)
                       (has "set_comment @ no;where: omp-re: invalid address or expression" notice)
                       (has "notice: fine" (re:cmd "pd 1" "entry0")))))
         (check "opening the binary again counts the annotations that went back out of those recorded"
                (let ((opened (re:open *binary*)))
                  (and (has "Re-applied 1 of 2 annotation(s) recorded earlier for this binary." opened)
                       (has "  could not re-apply set_comment @ no;where" opened)))))))
   (check "stopping the cell clears its notice" (null (gethash "nodecode-re" nle:*notices*)))))
