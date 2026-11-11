;;;; policy-data.lisp --- the read-only command policy's patterns and command lists.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; What rizin_command may run, as data: policy.lisp is the logic over it.
;;;; The patterns are written as JavaScript reads a regular expression, `$'
;;;; meaning the very end, and are compiled that way (JS-SCANNER).

(in-package #:omp-re)

(defparameter +allowed-command+
  "^(p|i|\\/|ag|ao|ab|ax[tf]|axl[jq]?|axgj?|aai[j]?|aau|afbr|afns[j]?|afsb[j]?|afcl[jlk]?|afcr[j]?|afd|afvf|afvc[j]?|id[jq]?|f(\\.l[jq]?|l[jqt.]?|i[jqt]?|g|sl[jq]?|ssl[j]?|tl[jl]?|z\\.[j]?|zl[j]?)|af(l|i|b|x|vl|vx|vR|vW|vd|o|M)|CC\\.|CCl|CCf|fd|c(c[jd]?|cc|X[j]?|u([1248]?|d))$|avj?$|avxt?$|avrD$|avg(l[jqt]?|p|x[jq]?|c[j]?)$|tp[vx]?$|ts[jlcd]?$|kj$|pmj?$|%(v|vi[1248]?|X|x|b64|b|o|u|lq?|h|f|s|btw|P|p|w|B[jqt]?|\\$|j)$|y[jqxs]?$|as(lj?|n|r)?$|ol[jqt]?$|obl[jqt]?$|oml[jqQt]?$|md[jt]?$|mi[jqt]?$|ml[jqt]?$|C\\.[jl]?$|shj?$|x[jc]?$|aL[jc]?$)"
  "The read-only command families rizin_command may run.")

(defparameter +denied-command+
  "^(po|pw|pkill|pr(?![xc])|p6d|pf(?![jq]?$|\\.[jq]?$|c$|d$|s$|v$)|\\/F|ag[enw]|afb[ce]|afii|ica|idp)|[+\\-=!*]"
  "The exceptions inside those families, and any name that adds, removes or sets.")

(defparameter +entropy-map+
  "^p={1,2}(?![0-9A-Za-z]*v$)[0-9A-Za-z]*$"
  "The p=/p== histogram family, read-only despite the = in its name.")

(defparameter +forbidden-syntax+
  '((";" . "`;` (command chaining)")
    ("\\|" . "`|` (pipes)")
    ("[<>]" . "`<`/`>` (redirection)")
    ("`" . "backticks (command substitution)")
    ("\\$[({]" . "`$(`/`${` (substitution)")
    ("~" . "`~` (grep)")
    ("@(?!!(?:0x[0-9a-fA-F]+|\\d+)(?:\\s|$))" . "`@` modifiers other than `@!<blocksize>` (use the addr parameter to seek)")
    ("\"" . "double quotes (use single quotes)")
    ("#" . "`#`")
    ("\\\\" . "backslashes")
    ("[\\n\\r\\0]" . "line breaks or NUL"))
  "Syntax refused anywhere in a command, each with the words that name it.")

(defparameter +read-only-extras+
  '(
    "e" "el" "elj" "elq" "ell" "elJ" "et" "es" "ahl" "ahlj" "ahl." "ahl.j" "ai" "aij" "acl"
    "aclj" "acll" "aci" "acij" "acil" "acg" "acbl" "acvl" "acvf" "C" "Cj" "Cl" "Csl" "Cslj"
    "Cslq" "Cs." "Cs.j" "Cs.q" "Cs.l" "Cdl" "Cdlj" "Cd." "Cfl" "Cflj" "Chl" "Chlj" "Cml" "Cmlj"
    "Ctl" "Ctlj" "CSl" "CSlj" "CSlq" "t" "tj" "tl" "tu" "tuj" "tul" "tuc" "tud" "te" "tej" "teb"
    "tec" "ted" "tef" "tt" "ttj" "ttc" "tf" "tfj" "tc" "tcd" "tcc" "tccj" "tcck" "tccl" "tx"
    "txf" "txg" "txl" "tk" "tkl" "tklj" "tkll" "tklt" "Ll" "Llj" "Llq" "Llt" "La" "Laj" "Laq"
    "Lat" "Lac" "Lacj" "Lc" "Lcj" "Lcq" "Lct" "LC" "LCj" "LCq" "LCt" "Lh" "Lhj" "Lhq" "Lht" "Li"
    "Lij" "Liq" "Lit" "Lp" "Lpj" "Lpq" "Lpt" "LD" "LDj" "LDq" "LDt" "Flt")
  "Read-only commands the family pattern does not cover, by exact name.")

(defparameter +noarg-duals+
  '(
    "tn" "tnj" "Ld" "Ldj" "Ldq" "Ldt" "Lo" "Loj" "Loq" "Lot")
  "Commands that list with no argument and mutate with one.")

(defparameter +debug-read-commands+
  '(
    "dr" "drj" "drq" "drt" "drr" "drrj" "dro" "droj" "droq" "drot" "drd" "dri" "drc" "drcc"
    "drA" "drAj" "drF" "drR" "drT" "drp" "drpj" "drpc" "dra" "draS" "drab" "dm" "dmj" "dmq"
    "dmt" "dm." "dmm" "dmmj" "dmm." "dmm.j" "dmi" "dmij" "dmiq" "dmi." "dmi.j" "dmia" "dmiaj"
    "dmiaq" "dmS" "dmSj" "dmh" "dmhg" "dmhgj" "dmhgb" "dmhgc" "dmhgm" "dmhgl" "dmhgt" "dmhja"
    "dmhjb" "dmhjc" "dbt" "dbtj" "dbtq" "dbtt" "dbtv" "dbta" "dp" "dpj" "dpt" "dpe" "dpl" "dplj"
    "dplt" "dpT" "dpTj" "dpTt" "di" "dij" "diq" "dkl" "dklj" "dklq" "dklt" "dkN" "dkn" "ddl"
    "ddlj" "ddlt")
  "Read-only debugger-state commands a breakpoint's on-hit command may run.")

(defparameter +required-commands+
  '(
    "aaa" "aflj" "aflc" "afij" "pdfj" "axtj" "axfj" "iij" "iEj" "isj" "izj" "iSj" "ij" "iej"
    "afvlj" "afn" "afvn" "afvt" "afs" "CC" "CC-" "CC." "fdj" "%v" "echo" "/xj" "/xrj" "/aj"
    "/vj" "/v1j" "/v2j" "/v4j" "/v8j" "/V1j" "/V2j" "/V4j" "/V8j" "/R" "/Rj" "/C" "/Cj" "tsj"
    "tej" "ttj" "tfj" "td" "tp" "aslj" "asn" "asr" "iIj" "irj" "flj" "icj")
  "Every rizin command the engine itself relies on.")
