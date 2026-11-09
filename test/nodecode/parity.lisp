;;;; parity.lisp --- answer a file of cases with the Lisp engine's primitives.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;;   sbcl --non-interactive --load test/nodecode/parity.lisp IN.json OUT.json
;;;;
;;;; test/nodecode-parity.test.ts writes IN.json, runs this, and compares
;;;; OUT.json with what the TypeScript engine answers for the same cases: the
;;;; two engines must agree on which commands run, on every refusal's words,
;;;; on what is quoted how, and on the hashes evidence is verified by.

(load (merge-pathnames "harness.lisp" (or *load-truename* *default-pathname-defaults*)))
(in-package #:nodecode-re-test)

(defun answer (thunk)
  "What THUNK returns, or the refusal it signals as {\"error\": text}."
  (handler-case (funcall thunk)
    (error (condition) (re::obj "error" (princ-to-string condition)))))

(let* ((arguments (rest sb-ext:*posix-argv*))
       (in (first (last arguments 2)))
       (out (first (last arguments)))
       (cases (re::json-decode (re::read-text-file in)))
       (catalog (let ((table (make-hash-table :test #'equal)))
                  ;; The catalog the TypeScript side read from rizin, handed over so both judge the same one.
                  (loop for spec across (or (re::jget cases "catalog") #())
                        do (setf (gethash (re::jstring spec "cmd") table) spec))
                  table))
       (strings (lambda (key) (coerce (or (re::jget cases key) #()) 'list))))
  (re::write-text-file
   out
   (re::json-encode
    (re::obj
     "runnable" (map 'vector (lambda (name) (and (re::runnable-p name) t)) (funcall strings "names"))
     "forbidden" (map 'vector (lambda (text) (or (re::forbidden-syntax-reason text) :null))
                      (funcall strings "lines"))
     "check" (map 'vector
                  (lambda (entry)
                    (answer (lambda ()
                              (multiple-value-bind (line name)
                                  (re::check-rizin-command catalog (re::jstring entry "command")
                                                           (re::jstring entry "addr"))
                                (re::obj "line" line "name" name)))))
                  (funcall strings "commands"))
     "onHit" (map 'vector
                  (lambda (command)
                    (answer (lambda () (re::obj "line" (re::check-debug-on-hit-command catalog command)))))
                  (funcall strings "onHit"))
     "help" (map 'vector
                 (lambda (query)
                   (multiple-value-bind (header lines) (re::search-catalog catalog query)
                     (re::obj "header" header "lines" (coerce lines 'simple-vector))))
                 (funcall strings "queries"))
     "quote" (map 'vector (lambda (text) (answer (lambda () (re::rz-quote text)))) (funcall strings "texts"))
     "addr" (map 'vector (lambda (text) (answer (lambda () (re::validate-addr text)))) (funcall strings "addrs"))
     "normalize" (map 'vector #'re::normalize-addr (funcall strings "addrs"))
     "ident" (map 'vector (lambda (text) (answer (lambda () (re::validate-ident "name" text))))
                  (funcall strings "addrs"))
     "typeLike" (map 'vector (lambda (text) (answer (lambda () (re::validate-type-like "type" text))))
                     (funcall strings "texts"))
     "canonical" (map 'vector (lambda (text) (re::canonicalize-rizin-output text "/tmp/sample bin"))
                      (funcall strings "outputs"))
     "canonicalHash" (map 'vector (lambda (text) (re::canonical-hash text "/tmp/sample bin"))
                          (funcall strings "outputs"))
     "shiftHash" (map 'vector (lambda (text) (re::shift-hash text "/tmp/sample bin"))
                      (funcall strings "outputs"))
     "excerpt" (map 'vector (lambda (text) (re::canonical-excerpt text "/tmp/sample bin"))
                    (funcall strings "outputs"))
     "sha256" (map 'vector #'re::sha256-hex (funcall strings "outputs"))
     "hmac" (map 'vector (lambda (text) (re::base64 (re::hmac-sha256 (re::utf-8 "audit key") (re::utf-8 text))))
                 (funcall strings "outputs"))
     "json" (map 'vector (lambda (text) (re::json-encode (re::json-decode text))) (funcall strings "json"))
     "formatJson" (map 'vector (lambda (text) (re::format-json (re::json-decode text))) (funcall strings "json"))
     "truncate" (map 'vector
                     (lambda (text)
                       (let ((result (re::text-result "head" text)))
                         (re::result-text result)))
                     (funcall strings "long"))))))
  (sb-ext:exit :code 0 :abort t))
