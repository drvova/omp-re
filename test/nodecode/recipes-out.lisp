;;;; recipes-out.lisp --- what the Lisp recipes answer, written out for omp's
;;;; twins to be held to.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --non-interactive --load test/nodecode/recipes-out.lisp BINARY BLOB OUT.json
;;;;
;;;; test/recipes-eval.test.ts runs this and compares OUT.json with what
;;;; skills/re-triage/recipes.js and recipes.py answer in omp's eval for the
;;;; same two files, under the same names: the recipes are one design in
;;;; three languages, and their reports must agree whole (evidence ids
;;;; aside). BINARY is opened as it is; BLOB is a headerless file of published
;;;; constants, opened as raw x86-64, which is what gives find_crypto
;;;; something to find. A recipe that refuses answers {"error": text}, so the
;;;; refusals are compared too.

(load (merge-pathnames "harness.lisp" (or *load-truename* *default-pathname-defaults*)))
(in-package #:nodecode-re-test)

(defun answer (thunk)
  "What THUNK returns, or the refusal it signals as {\"error\": text}."
  (handler-case (funcall thunk)
    (error (condition) (re::obj "error" (princ-to-string condition)))))

(let* ((arguments (last sb-ext:*posix-argv* 3))
       (binary (first arguments))
       (blob (second arguments))
       (out (third arguments))
       (answers (re::obj)))
  (flet ((take (name thunk) (setf (gethash name answers) (answer thunk))))
    (with-cell ()
      (in-session ((fresh-session))
        (take "noBinary" (lambda () (re:triage)))
        (re:open binary)
        (take "triage" (lambda () (re:triage)))
        (take "triageShort" (lambda () (re:triage :max-strings 1 :max-functions 2)))
        (take "scanImports" (lambda () (re:scan-imports)))
        (take "scanImportsBounded" (lambda () (re:scan-imports :max-callers 1)))
        (take "scanImportsNoCallers" (lambda () (re:scan-imports :callers :false)))
        (take "inspectFunction" (lambda () (re:inspect-function "main")))
        (take "inspectFunctionBounded" (lambda () (re:inspect-function "main" :max-items 3)))
        (take "inspectFunctionNone" (lambda () (re:inspect-function "0x1")))
        (take "inspectFunctionInvalid" (lambda () (re:inspect-function "main;!id")))
        (take "inspectFunctionNotAString" (lambda () (re:inspect-function 4096)))
        (take "findComparisons" (lambda () (re:find-comparisons "main")))
        (take "findComparisonsBounded" (lambda () (re:find-comparisons "main" :max-items 20)))
        (take "findComparisonsNone" (lambda () (re:find-comparisons "0x1")))
        (take "findComparisonsNotAString" (lambda () (re:find-comparisons nil)))
        (take "findCrypto" (lambda () (re:find-crypto))))
      (in-session ((fresh-session))
        (re:open blob :arch "x86" :bits 64 :format "any")
        (take "blobTriage" (lambda () (re:triage)))
        (take "blobScanImports" (lambda () (re:scan-imports)))
        (take "blobFindCrypto" (lambda () (re:find-crypto)))
        (take "blobFindCryptoNoReferences" (lambda () (re:find-crypto :references :false))))))
  (re::write-text-file out (re::json-encode answers))
  (ignore-errors (stop-running-cell))
  (uiop:delete-directory-tree *scratch* :validate t :if-does-not-exist :ignore)
  (sb-ext:exit :code 0 :abort t))
