;;;; recipe-data.lisp --- GENERATED from recipes/tables.json. Do not edit.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Regenerate with: bun scripts/gen-recipes.ts
;;;; What the recipes hold as data — the judgement they rest on, their options,
;;;; steps, sections and every sentence — kept once so it can be argued with,
;;;; and so the Lisp verbs and omp's two eval scripts (skills/re-triage/recipes.js
;;;; and recipes.py) say the same thing. recipes.lisp is the code over it;
;;;; scripts/gen-recipes.ts says what each part means.

(in-package #:nodecode-re)

(defparameter *recipe-tables*
  (obj
    "riskyImports" (vector
      (obj
        "category" "memory"
        "severity" "high"
        "why" "copies with no bound at all; any input longer than the buffer overruns it"
        "names" (vector "gets"))
      (obj
        "category" "memory"
        "severity" "high"
        "why" "copies or formats until a terminator with no destination size; safe only if every caller proves the length"
        "names" (vector
          "strcpy" "strcat" "stpcpy" "sprintf" "vsprintf" "wcscpy" "wcscat" "lstrcpyA" "lstrcpyW"
          "lstrcatA" "lstrcatW" "wsprintfA" "wsprintfW"))
      (obj
        "category" "memory"
        "severity" "medium"
        "why" "reads into a buffer; a %s or %[ without a width has no bound"
        "names" (vector "scanf" "sscanf" "fscanf" "vscanf" "vsscanf" "vfscanf"))
      (obj
        "category" "memory"
        "severity" "medium"
        "why" "the size comes from the caller and is often attacker-influenced"
        "names" (vector "alloca" "realpath" "getwd"))
      (obj
        "category" "memory"
        "severity" "low"
        "why" "bounded, but the bound is the caller's to get right (and strncpy leaves no terminator when it fills)"
        "names" (vector "strncpy" "strncat" "memcpy" "memmove" "bcopy" "wcsncpy" "snprintf" "vsnprintf"))
      (obj
        "category" "command"
        "severity" "high"
        "why" "hands a string to a shell; anything in it that came from outside is a command"
        "names" (vector
          "system" "popen" "wordexp" "WinExec" "ShellExecuteA" "ShellExecuteW" "ShellExecuteExA"
          "ShellExecuteExW"))
      (obj
        "category" "command"
        "severity" "medium"
        "why" "starts another program; what it runs and with which arguments is worth tracing"
        "names" (vector
          "execl" "execlp" "execle" "execv" "execvp" "execve" "execvpe" "posix_spawn" "posix_spawnp"
          "CreateProcessA" "CreateProcessW"))
      (obj
        "category" "format"
        "severity" "low"
        "why" "a format string that is not a literal lets its author read and write memory"
        "names" (vector
          "printf" "fprintf" "dprintf" "vprintf" "vfprintf" "syslog" "vsyslog" "err" "errx" "warn"
          "warnx"))
      (obj
        "category" "race"
        "severity" "high"
        "why" "chooses a file name before the file exists; another process can take it first"
        "names" (vector "mktemp" "tmpnam" "tempnam"))
      (obj
        "category" "race"
        "severity" "low"
        "why" "checks a path, then uses it; the file can change between the two"
        "names" (vector "access" "stat" "lstat"))
      (obj
        "category" "integer"
        "severity" "low"
        "why" "reports no error and no overflow; a caller cannot tell a bad number from zero"
        "names" (vector "atoi" "atol" "atoll" "atof"))
      (obj
        "category" "randomness"
        "severity" "medium"
        "why" "predictable; unfit for keys, tokens or anything an adversary should not guess"
        "names" (vector "rand" "srand" "random" "srandom" "drand48" "lrand48"))
      (obj
        "category" "privilege"
        "severity" "info"
        "why" "changes the process's identity or root; the order and the error checks matter"
        "names" (vector "setuid" "setgid" "seteuid" "setegid" "setreuid" "setregid" "chroot"))
      (obj
        "category" "loading"
        "severity" "medium"
        "why" "loads code chosen at run time; from where is worth tracing"
        "names" (vector "dlopen" "LoadLibraryA" "LoadLibraryW" "LoadLibraryExA" "LoadLibraryExW")))
    "capabilities" (vector
      (obj
        "capability" "network"
        "names" (vector
          "socket" "connect" "bind" "listen" "accept" "send" "sendto" "recv" "recvfrom"
          "getaddrinfo" "gethostbyname" "WSAStartup" "InternetOpenA" "InternetOpenW"
          "InternetOpenUrlA" "InternetOpenUrlW" "InternetConnectA" "InternetConnectW"
          "HttpSendRequestA" "HttpSendRequestW" "WinHttpOpen" "WinHttpConnect" "WinHttpSendRequest"
          "URLDownloadToFileA" "URLDownloadToFileW" "curl_easy_perform" "SSL_connect"))
      (obj
        "capability" "process control"
        "names" (vector
          "fork" "vfork" "clone" "kill" "ptrace" "prctl" "OpenProcess" "TerminateProcess"
          "CreateRemoteThread" "CreateToolhelp32Snapshot" "Process32First" "Process32Next"))
      (obj
        "capability" "code injection"
        "names" (vector
          "VirtualAllocEx" "WriteProcessMemory" "ReadProcessMemory" "CreateRemoteThread"
          "NtUnmapViewOfSection" "ZwUnmapViewOfSection" "QueueUserAPC" "SetThreadContext"
          "SetWindowsHookExA" "SetWindowsHookExW" "process_vm_writev"))
      (obj
        "capability" "memory protection"
        "names" (vector "mprotect" "mmap" "memfd_create" "VirtualProtect" "VirtualProtectEx" "VirtualAlloc"))
      (obj
        "capability" "anti-analysis"
        "names" (vector
          "ptrace" "IsDebuggerPresent" "CheckRemoteDebuggerPresent" "NtQueryInformationProcess"
          "OutputDebugStringA" "OutputDebugStringW" "NtSetInformationThread" "GetTickCount"
          "QueryPerformanceCounter"))
      (obj
        "capability" "persistence"
        "names" (vector
          "RegSetValueExA" "RegSetValueExW" "RegCreateKeyExA" "RegCreateKeyExW" "CreateServiceA"
          "CreateServiceW" "StartServiceA" "StartServiceW" "SetFileAttributesA" "SetFileAttributesW"))
      (obj
        "capability" "cryptography"
        "names" (vector
          "CryptAcquireContextA" "CryptAcquireContextW" "CryptEncrypt" "CryptDecrypt" "CryptGenKey"
          "CryptHashData" "BCryptEncrypt" "BCryptDecrypt" "BCryptGenRandom" "EVP_EncryptInit_ex"
          "EVP_DecryptInit_ex" "EVP_DigestInit_ex" "AES_set_encrypt_key" "AES_encrypt" "MD5_Init"
          "SHA1_Init" "SHA256_Init" "RC4" "DES_ecb_encrypt" "getrandom" "RAND_bytes"))
      (obj
        "capability" "filesystem"
        "names" (vector
          "unlink" "remove" "rename" "chmod" "chown" "opendir" "readdir" "ftw" "nftw" "DeleteFileA"
          "DeleteFileW" "MoveFileA" "MoveFileW" "FindFirstFileA" "FindFirstFileW" "CopyFileA"
          "CopyFileW"))
      (obj
        "capability" "dynamic resolution"
        "names" (vector "dlsym" "GetProcAddress" "LdrGetProcedureAddress")))
    "severityOrder" (vector "high" "medium" "low" "info")
    "importNameRules" (vector
      (obj "rule" "dropThrough" "text" "imp.")
      (obj "rule" "dropPrefix" "text" "__isoc99_")
      (obj "rule" "dropLeading" "text" "_")
      (obj "rule" "dropSuffix" "text" "_chk"))
    "stringInterest" (vector
      (obj
        "kind" "credentials"
        "pattern" "(?i)passw|passphrase|secret|\\btoken\\b|api[_-]?key|private key|credential|\\blogin\\b|\\bauth(?:enticat|oriz)")
      (obj
        "kind" "network"
        "pattern" "(?i)https?://|ftp://|\\b[a-z0-9-]+\\.(?:com|net|org|io|ru|cn|info|biz|xyz|top)\\b|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|user-agent")
      (obj
        "kind" "commands"
        "pattern" "(?i)/bin/sh|/bin/bash|cmd\\.exe|powershell|wget |curl |chmod |\\bnc \\b|schtasks|reg add")
      (obj
        "kind" "paths"
        "pattern" "(?i)^/(?:etc|tmp|var|proc|dev|home|root)/|\\\\(?:windows|system32|appdata|temp)\\\\|HKEY_|\\\\Software\\\\")
      (obj
        "kind" "checks"
        "pattern" "(?i)licen[sc]e|serial|registration|trial|expired|invalid|incorrect|denied|granted|debugger|virtual|sandbox|vmware|vbox"))
    "packerSectionNames" "(?i)upx|aspack|themida|vmp|mpress|petite|\\.packed|\\.enigma"
    "comparingCalls" "(?i)\\b(?:str|strn|strcase|strncase|wcs|wcsn|mem|b)cmp\\b|\\bstrstr\\b|\\bstrchr\\b|lstrcmp|CompareString|RtlCompareMemory|\\bcrc|\\bhash|md5|sha\\d|verify|check|valid"
    "cryptoConstants" (vector
      (obj "algorithm" "AES" "what" "S-box" "hex" "637c777bf26b6fc53001672bfed7ab76")
      (obj "algorithm" "AES" "what" "inverse S-box" "hex" "52096ad53036a538bf40a39e81f3d7fb")
      (obj
        "algorithm" "AES"
        "what" "T-table Te0 (big-endian words)"
        "hex" "c66363a5f87c7c84ee777799f67b7b8d")
      (obj
        "algorithm" "AES"
        "what" "T-table Te0 (little-endian words)"
        "hex" "a56363c6847c7cf8997777ee8d7b7bf6")
      (obj
        "algorithm" "SHA-256"
        "what" "round constants (little-endian words)"
        "hex" "982f8a4291443771cffbc0b5a5dbb5e9")
      (obj
        "algorithm" "SHA-256"
        "what" "round constants (big-endian words)"
        "hex" "428a2f9871374491b5c0fbcfe9b5dba5")
      (obj
        "algorithm" "SHA-256"
        "what" "initial state (little-endian words)"
        "hex" "67e6096a85ae67bb72f36e3c3af54fa5")
      (obj
        "algorithm" "SHA-512"
        "what" "round constants (little-endian words)"
        "hex" "22ae28d7982f8a42cd65ef2391443771")
      (obj
        "algorithm" "SHA-1 / MD5"
        "what" "initial state (little-endian words)"
        "hex" "0123456789abcdeffedcba9876543210")
      (obj "algorithm" "SHA-1" "what" "round constant K1 (little-endian)" "hex" "9979825a")
      (obj
        "algorithm" "MD5"
        "what" "sine table (little-endian words)"
        "hex" "78a46ad756b7c7e8db702024eecebdc1")
      (obj
        "algorithm" "CRC-32"
        "what" "table, polynomial 0xEDB88320 (little-endian words)"
        "hex" "0000000096300777")
      (obj
        "algorithm" "CRC-32"
        "what" "table, polynomial 0x04C11DB7 (big-endian words)"
        "hex" "0000000004c11db7130476dc")
      (obj
        "algorithm" "ChaCha / Salsa20"
        "what" "sigma constant"
        "hex" "657870616e642033322d62797465206b")
      (obj
        "algorithm" "ChaCha / Salsa20"
        "what" "tau constant"
        "hex" "657870616e642031362d62797465206b")
      (obj
        "algorithm" "Blowfish"
        "what" "P-array (big-endian words)"
        "hex" "243f6a8885a308d313198a2e03707344")
      (obj
        "algorithm" "Blowfish"
        "what" "P-array (little-endian words)"
        "hex" "886a3f24d308a3852e8a191344737003")
      (obj "algorithm" "TEA / XTEA" "what" "delta (little-endian)" "hex" "b979379e")
      (obj "algorithm" "TEA / XTEA" "what" "delta (big-endian)" "hex" "9e3779b9")
      (obj
        "algorithm" "DES"
        "what" "initial permutation table"
        "hex" "3a322a221a120a023c342c241c140c04")
      (obj "algorithm" "RC6 / RC5" "what" "P32 and Q32 (little-endian)" "hex" "6351e1b7b979379e")
      (obj
        "algorithm" "Base64"
        "what" "standard alphabet"
        "hex" "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b2f")
      (obj
        "algorithm" "Base64"
        "what" "URL-safe alphabet tail"
        "hex" "7778797a303132333435363738392d5f"))
    "opTypes" (obj
      "call" (vector "call" "ucall" "rcall" "icall" "ccall")
      "decidingCall" (vector "call" "ucall" "rcall" "icall")
      "compare" (vector "cmp" "acmp")
      "branch" (vector "cjmp"))
    "calleeAfter" "call"
    "branchMeanings" (vector
      (obj "mnemonics" (vector "je" "jz") "meaning" "taken when equal / zero")
      (obj "mnemonics" (vector "jne" "jnz") "meaning" "taken when not equal / not zero")
      (obj "mnemonics" (vector "ja" "jnbe") "meaning" "taken when above (unsigned >)")
      (obj
        "mnemonics" (vector "jae" "jnb" "jnc")
        "meaning" "taken when above or equal (unsigned >=)")
      (obj "mnemonics" (vector "jb" "jc" "jnae") "meaning" "taken when below (unsigned <)")
      (obj "mnemonics" (vector "jbe" "jna") "meaning" "taken when below or equal (unsigned <=)")
      (obj "mnemonics" (vector "jg" "jnle") "meaning" "taken when greater (signed >)")
      (obj "mnemonics" (vector "jge" "jnl") "meaning" "taken when greater or equal (signed >=)")
      (obj "mnemonics" (vector "jl" "jnge") "meaning" "taken when less (signed <)")
      (obj "mnemonics" (vector "jle" "jng") "meaning" "taken when less or equal (signed <=)")
      (obj "mnemonics" (vector "js") "meaning" "taken when negative")
      (obj "mnemonics" (vector "jns") "meaning" "taken when not negative"))
    "otherBranch" "conditional"
    "sectionNotes" (obj
      "writableExecutable" "writable+executable"
      "veryHighEntropy" "very high entropy (compressed or encrypted data)"
      "highEntropyForCode" "high entropy for code"
      "packerName" "a name packers use")
    "thresholds" (obj
      "veryHighEntropy" 7.2d0
      "highEntropyForCode" 6.8d0
      "fewImports" 8
      "shortConstantHexDigits" 8)
    "limits" (obj
      "lineWidth" 100
      "triageRiskyImports" 20
      "cryptoMaterial" 40
      "cryptoHits" 60
      "cryptoReferences" 8)
    "whitespace" (vector
      9 10 11 12 13 32 160 5760 8192 8193 8194 8195 8196 8197 8198 8199 8200 8201 8202 8232 8233
      8239 8287 12288 65279)
    "text" (obj
      "more" (vector
        "  … "
        (obj "get" (vector (vector "$" "hidden")) "as" "d")
        " more "
        (obj "get" (vector (vector "$" "what")) "as" "text")
        " not shown")
      "evidenceTaken" "Evidence taken (cite these in record_finding; each is a rizin_command read you can re-run):"
      "evidenceRow" (vector
        "  "
        (obj "get" (vector (vector "." "id")) "as" "text")
        "  "
        (obj "get" (vector (vector "." "label")) "as" "text"))
      "nameless" "?"
      "refusals" (obj
        "notAString" (vector
          "omp-re: "
          (obj "get" (vector (vector "$" "recipe")) "as" "text")
          ": a function is named by a string, not "
          (obj "get" (vector (vector "$" "given")) "as" "text"))
        "optionsNotOneObject" (vector
          "omp-re: "
          (obj "get" (vector (vector "$" "recipe")) "as" "text")
          ": options are one object, e.g. { maxItems: 20 }, not "
          (obj "get" (vector (vector "$" "given")) "as" "text"))
        "noFunction" (vector
          "omp-re: "
          (obj "get" (vector (vector "$" "recipe")) "as" "text")
          ": no function at "
          (obj "get" (vector (vector "$" "addr")) "as" "text")
          " — list them with "
          (obj "get" (vector (vector "$" "listFunctions")) "as" "text")
          ", or define one with define_function")
        "noInstructions" (vector
          "omp-re: "
          (obj "get" (vector (vector "$" "recipe")) "as" "text")
          ": no function at "
          (obj "get" (vector (vector "$" "addr")) "as" "text")
          " — list them with "
          (obj "get" (vector (vector "$" "listFunctions")) "as" "text"))
        "cutOutput" (vector
          "omp-re: "
          (obj "get" (vector (vector "$" "recipe")) "as" "text")
          ": the output of rizin_command "
          (obj "get" (vector (vector "$" "label")) "as" "json")
          " was cut at the size cap and the whole of it could not be read back ("
          (obj "get" (vector (vector "$" "why")) "as" "text")
          "). The recipe needs all of it and will not report from cut JSON — run the reads by hand with narrower commands.")
        "cutNoArtifact" (vector "the engine saved no artifact for it")
        "cutUnreadable" (vector
          "artifact://"
          (obj "get" (vector (vector "$" "artifact")) "as" "text")
          ": "
          (obj "get" (vector (vector "$" "error")) "as" "text"))
        "cutNotText" (vector
          "artifact://"
          (obj "get" (vector (vector "$" "artifact")) "as" "text")
          " did not read as text")))
    "host" (obj "listFunctions" "(re:json \"aflj\")")
    "recipes" (vector
      (obj
        "name" "triage"
        "call" "TRIAGE"
        "takes" nil
        "doc" "A first look at the open binary, composed from rizin's own reads: what it is, which protections the
build has, its sections with entropy, the imports that give it reach, the strings worth a first
look, its largest functions and its entry points. Nothing here is a finding until one is recorded
citing the ids.

MAX-STRINGS (default 25, 1..200): at most this many notable strings are listed.
MAX-FUNCTIONS (default 15, 1..100): at most this many functions are listed."
        "options" (vector
          (obj "name" "maxStrings" "key" "MAX-STRINGS" "default" 25 "least" 1 "most" 200)
          (obj "name" "maxFunctions" "key" "MAX-FUNCTIONS" "default" 15 "least" 1 "most" 100))
        "steps" (vector
          (obj "read" "path" "command" "ij")
          (obj "read" "info" "command" "iIj")
          (obj "read" "sectionData" "command" "iSj entropy")
          (obj "read" "imports" "command" "iij")
          (obj "read" "strings" "command" "izj")
          (obj "read" "functionData" "command" "aflj")
          (obj "read" "entries" "command" "iej")
          (obj "derive" "triage"))
        "title" (vector
          "triage: "
          (obj "get" (vector (vector "$" "path" "core" "file")) "as" "text" "or" "?"))
        "sections" (vector
          (obj
            "title" (vector "Identity " (obj "cite" (vector "$" "@info")))
            "lines" (vector
              (vector
                "  "
                (obj
                  "get" (vector (vector "$" "info" "class") (vector "$" "info" "bintype"))
                  "as" "text"
                  "or" "unknown format")
                ", "
                (obj "get" (vector (vector "$" "info" "arch")) "as" "text" "or" "?")
                " "
                (obj "get" (vector (vector "$" "info" "bits")) "as" "d" "or" "?")
                "-bit "
                (obj "get" (vector (vector "$" "info" "endian")) "as" "text" "or" "")
                ", "
                (obj "get" (vector (vector "$" "info" "os")) "as" "text" "or" "?")
                (obj
                  "group" (vector ", language " (obj "get" (vector (vector "$" "info" "lang")) "as" "text")))
                (obj
                  "group" (vector
                    ", interpreter "
                    (obj "get" (vector (vector "$" "info" "intrp")) "as" "text")))))
            "under" (vector)
            "after" (vector))
          (obj
            "title" (vector "Build protections " (obj "cite" (vector "$" "@info")))
            "lines" (vector
              (vector
                "  stack canary: "
                (obj
                  "choose" (vector "$" "info" "canary")
                  "yes" "yes"
                  "no" "NO — a stack overflow reaches the return address unchecked"))
              (vector
                "  NX: "
                (obj
                  "choose" (vector "$" "info" "nx")
                  "yes" "yes"
                  "no" "NO — data pages are executable"))
              (vector
                "  PIE: "
                (obj
                  "choose" (vector "$" "info" "pie")
                  "yes" "yes"
                  "no" "NO — the image loads at a fixed address"))
              (vector
                "  RELRO: "
                (obj "get" (vector (vector "$" "info" "relro")) "as" "text" "or" "none")
                (obj
                  "group" (vector
                    (obj "if" (vector "$" "info" "relro") "is" "partial")
                    " — the GOT stays writable"))
                (obj
                  "group" (vector
                    (obj "unless" (vector "$" "info" "relro") "is" "partial")
                    (obj "unless" (vector "$" "info" "relro") "is" "full")
                    " — the GOT and other relocated data stay writable")))
              (vector
                "  fortified libc calls: "
                (obj "choose" (vector "$" "info" "fortify_source") "yes" "yes" "no" "no"))
              (vector
                "  stripped: "
                (obj "choose" (vector "$" "info" "stripped") "yes" "yes" "no" "no")
                "   static: "
                (obj "choose" (vector "$" "info" "static") "yes" "yes" "no" "no")))
            "under" (vector)
            "after" (vector))
          (obj
            "title" (vector
              "Sections: "
              (obj "count" (vector "$" "sections"))
              " "
              (obj "cite" (vector "$" "@sectionData")))
            "lines" (vector)
            "rows" (vector "$" "sections")
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "section" "name")) "as" "text" "padRight" 18)
              " "
              (obj "get" (vector (vector "." "section" "perm")) "as" "text" "padRight" 4 "or" "")
              " "
              (obj "get" (vector (vector "." "section" "size")) "as" "d" "padLeft" 9 "or" "0")
              " bytes  entropy "
              (obj "get" (vector (vector "." "entropy")) "as" "f2" "padLeft" 4 "or" "?")
              (obj
                "group" (vector
                  (obj "if" (vector "." "notes"))
                  "  <- "
                  (obj "join" (vector "." "notes") "with" "; "))))
            "under" (vector)
            "after" (vector
              (vector
                (obj
                  "group" (vector
                    (obj "if" (vector "$" "flagged"))
                    "  "
                    (obj "count" (vector "$" "flagged"))
                    " section"
                    (obj "plural" (vector "$" "flagged") "one" "" "many" "s")
                    " stand"
                    (obj "plural" (vector "$" "flagged") "one" "s" "many" "")
                    " out; high entropy in code, or a section both writable and executable, is what a packed or self-modifying binary looks like — read it before trusting the function list.")))))
          (obj
            "title" (vector
              "Imports: "
              (obj "count" (vector "$" "imports"))
              " "
              (obj "cite" (vector "$" "@imports")))
            "lines" (vector
              (vector
                (obj
                  "group" (vector
                    (obj "if" (vector "$" "reach"))
                    "  reach, by what it links: "
                    (obj "join" (vector "$" "reach") "with" ", ")))
                (obj
                  "group" (vector
                    (obj "unless" (vector "$" "reach"))
                    "  none of the capability groups (network, process control, injection, …) is linked")))
              (vector
                (obj
                  "group" (vector
                    (obj "if" (vector "$" "riskyShown"))
                    "  worth a reviewer's look: "
                    (obj "join" (vector "$" "riskyShown") "with" ", ")
                    " — scan_imports says why and who calls them")))
              (vector
                (obj
                  "choose" (vector "$" "fewImports")
                  "yes" "  very few imports for a dynamic binary: resolved at run time, or packed"
                  "no" "")))
            "under" (vector)
            "after" (vector))
          (obj
            "title" (vector
              "Strings: "
              (obj "count" (vector "$" "strings"))
              "; notable "
              (obj "count" (vector "$" "notable"))
              " "
              (obj "cite" (vector "$" "@strings")))
            "lines" (vector)
            "rows" (vector "$" "notable")
            "limit" "maxStrings"
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "kind")) "as" "text" "padRight" 11)
              " "
              (obj "get" (vector (vector "." "entry" "vaddr")) "as" "x" "or" "?")
              "  "
              (obj "get" (vector (vector "." "entry" "string")) "as" "line" "or" ""))
            "under" (vector)
            "more" "notable strings"
            "after" (vector))
          (obj
            "title" (vector
              "Functions: "
              (obj "count" (vector "$" "functions"))
              "; largest by code size "
              (obj "cite" (vector "$" "@functionData")))
            "lines" (vector)
            "rows" (vector "$" "functions")
            "limit" "maxFunctions"
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "offset") (vector "." "addr")) "as" "x" "or" "0x0")
              "  "
              (obj
                "get" (vector (vector "." "realsz") (vector "." "size"))
                "as" "d"
                "padLeft" 7
                "or" "0")
              " bytes  "
              (obj "group" (vector (obj "get" (vector (vector "." "nbbs")) "as" "d") " blocks  "))
              (obj "get" (vector (vector "." "name")) "as" "text" "or" "?"))
            "under" (vector)
            "more" "functions"
            "after" (vector))
          (obj
            "title" (vector "Entry points " (obj "cite" (vector "$" "@entries")))
            "lines" (vector)
            "rows" (vector "$" "entries")
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "vaddr")) "as" "x")
              "  "
              (obj "get" (vector (vector "." "type")) "as" "text" "or" ""))
            "under" (vector)
            "empty" (vector "  none reported")
            "after" (vector))))
      (obj
        "name" "scan_imports"
        "call" "SCAN-IMPORTS"
        "takes" nil
        "doc" "The imports a reviewer would stop at, each with why it matters and who calls it; plus what the
program can reach, read off what it links. An import is a lead, not a bug: whether a call is safe is
decided at its call site, which is what the callers are listed for.

CALLERS (default T; :FALSE for no): list who calls each import.
MAX-CALLERS (default 12, 1..100): at most this many callers are listed for each."
        "options" (vector
          (obj "name" "callers" "key" "CALLERS" "flag" t)
          (obj "name" "maxCallers" "key" "MAX-CALLERS" "default" 12 "least" 1 "most" 100))
        "steps" (vector (obj "read" "imports" "command" "iij") (obj "derive" "scanImports"))
        "title" (vector
          "scan_imports: "
          (obj "count" (vector "$" "imports"))
          " imports, "
          (obj "count" (vector "$" "risky"))
          " worth a look")
        "sections" (vector
          (obj
            "title" (vector "Reach, by what it links " (obj "cite" (vector "$" "@imports")))
            "lines" (vector)
            "rows" (vector "$" "reach")
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "capability")) "as" "text" "padRight" 18)
              " "
              (obj "join" (vector "." "names") "with" ", "))
            "under" (vector)
            "empty" (vector "  none of the capability groups is linked")
            "after" (vector))
          (obj
            "title" (vector "Imports worth a reviewer's look " (obj "cite" (vector "$" "@imports")))
            "lines" (vector)
            "rows" (vector "$" "risky")
            "row" (vector
              "  ["
              (obj "get" (vector (vector "." "severity")) "as" "text")
              "] "
              (obj "get" (vector (vector "." "bare")) "as" "text")
              (obj
                "group" (vector " (linked as " (obj "get" (vector (vector "." "linkedAs")) "as" "text") ")"))
              " ("
              (obj "get" (vector (vector "." "category")) "as" "text")
              ")"
              (obj "group" (vector " @ " (obj "get" (vector (vector "." "plt")) "as" "x")))
              " — "
              (obj "get" (vector (vector "." "why")) "as" "text"))
            "under" (vector
              (obj
                "when" (vector "." "traced")
                "lines" (vector)
                "rows" (vector "." "places")
                "limit" "maxCallers"
                "line" (vector
                  "      called from "
                  (obj "count" (vector "." "places"))
                  " place"
                  (obj "plural" (vector "." "places") "one" "" "many" "s")
                  " "
                  (obj "cite" (vector "." "@places"))
                  ": "
                  (obj "join" (vector "$" "shown") "with" ", "))
                "under" (vector)
                "empty" (vector "      no caller found by analysis " (obj "cite" (vector "." "@places")))
                "more" "callers"
                "after" (vector)))
            "empty" (vector "  none of the imports in the table is linked")
            "after" (vector))
          (obj
            "lines" (vector
              (vector
                "An import is a lead. Read each call site (rizin_command pdg or pdf at the caller) before saying what it does."))
            "under" (vector)
            "after" (vector))))
      (obj
        "name" "inspect_function"
        "call" "INSPECT-FUNCTION"
        "takes" t
        "doc" "One function, read from every side at once: its size, complexity and signature, its variables, who
calls it and what it calls, and the strings it refers to — the context to read before its code.
Follow it with rizin_command pdg at the same address for the code.

ADDR: the function's name or address, a string.
MAX-ITEMS (default 30, 1..300): at most this many of each list are shown."
        "options" (vector (obj "name" "maxItems" "key" "MAX-ITEMS" "default" 30 "least" 1 "most" 300))
        "steps" (vector
          (obj "read" "infoData" "command" "afij" "at" t)
          (obj "derive" "theFunction")
          (obj "read" "body" "command" "pdfj" "at" t)
          (obj "read" "variables" "command" "afvlj" "at" t)
          (obj "read" "strings" "command" "izj")
          (obj "derive" "inspectFunction"))
        "title" (vector
          "inspect_function: "
          (obj "get" (vector (vector "$" "info" "name") (vector "$" "addr")) "as" "text"))
        "sections" (vector
          (obj
            "title" (vector "Shape " (obj "cite" (vector "$" "@infoData")))
            "lines" (vector
              (vector
                "  "
                (obj
                  "get" (vector
                    (vector "$" "info" "signature")
                    (vector "$" "info" "name")
                    (vector "$" "addr"))
                  "as" "text")
                " at "
                (obj
                  "get" (vector (vector "$" "info" "offset") (vector "$" "info" "addr"))
                  "as" "x"
                  "or" "0x0"))
              (vector
                "  "
                (obj
                  "get" (vector (vector "$" "info" "realsz") (vector "$" "info" "size"))
                  "as" "d"
                  "or" "0")
                " bytes of code, "
                (obj "get" (vector (vector "$" "info" "nbbs")) "as" "d" "or" "0")
                " basic blocks, "
                (obj "get" (vector (vector "$" "info" "edges")) "as" "d" "or" "0")
                " edges, cyclomatic complexity "
                (obj "get" (vector (vector "$" "info" "cc")) "as" "d" "or" "0")
                ", "
                (obj "get" (vector (vector "$" "info" "loops")) "as" "d" "or" "0")
                " loop"
                (obj "plural" (vector "$" "info" "loops") "one" "" "many" "s"))
              (vector
                "  calling convention "
                (obj "get" (vector (vector "$" "info" "calltype")) "as" "text" "or" "?")
                ", stack frame "
                (obj "get" (vector (vector "$" "info" "stackframe")) "as" "d" "or" "0")
                " bytes"
                (obj "choose" (vector "$" "info" "noreturn") "yes" ", does not return" "no" "")))
            "under" (vector)
            "after" (vector))
          (obj
            "title" (vector "Body " (obj "cite" (vector "$" "@body")))
            "lines" (vector
              (vector
                "  "
                (obj "count" (vector "$" "ops"))
                " instructions, "
                (obj "get" (vector (vector "$" "compares")) "as" "d")
                " compare"
                (obj "plural" (vector "$" "compares") "one" "" "many" "s")
                ", "
                (obj "get" (vector (vector "$" "branches")) "as" "d")
                " conditional branch"
                (obj "plural" (vector "$" "branches") "one" "" "many" "es")
                " — find_comparisons lists them"))
            "under" (vector)
            "after" (vector))
          (obj
            "title" (vector
              "Variables: "
              (obj "get" (vector (vector "$" "variableCount")) "as" "d")
              " "
              (obj "cite" (vector "$" "@variables")))
            "lines" (vector)
            "under" (vector)
            "after" (vector))
          (obj
            "title" (vector
              "Called from "
              (obj "count" (vector "$" "callers"))
              " place"
              (obj "plural" (vector "$" "callers") "one" "" "many" "s")
              " "
              (obj "cite" (vector "$" "@callers")))
            "lines" (vector)
            "rows" (vector "$" "callers")
            "limit" "maxItems"
            "row" (vector "  " (obj "get" (vector (vector ".")) "as" "text"))
            "under" (vector)
            "more" "callers"
            "after" (vector))
          (obj
            "title" (vector
              "Calls "
              (obj "count" (vector "$" "calls"))
              " distinct target"
              (obj "plural" (vector "$" "calls") "one" "" "many" "s")
              " "
              (obj "cite" (vector "$" "@body")))
            "lines" (vector)
            "rows" (vector "$" "calls")
            "limit" "maxItems"
            "row" (vector "  " (obj "get" (vector (vector ".")) "as" "text"))
            "under" (vector)
            "more" "callees"
            "after" (vector))
          (obj
            "title" (vector
              "Refers to "
              (obj "count" (vector "$" "referenced"))
              " string"
              (obj "plural" (vector "$" "referenced") "one" "" "many" "s")
              " "
              (obj "cite" (vector "$" "@body"))
              " "
              (obj "cite" (vector "$" "@strings")))
            "lines" (vector)
            "rows" (vector "$" "referenced")
            "limit" "maxItems"
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "address")) "as" "x")
              "  "
              (obj "get" (vector (vector "." "text")) "as" "line"))
            "under" (vector)
            "more" "strings"
            "after" (vector))))
      (obj
        "name" "find_comparisons"
        "call" "FIND-COMPARISONS"
        "takes" t
        "doc" "What a function decides on: every compare or test with the conditional branch that follows it (which
way it goes, and where to), every call to something that compares or validates, and the strings on
the way — the static skeleton of validation logic, with no emulation and nothing run. It lists what
is compared, not what the comparison means.

ADDR: the function's name or address, a string.
MAX-ITEMS (default 80, 1..1000): at most this many of each list are shown."
        "options" (vector (obj "name" "maxItems" "key" "MAX-ITEMS" "default" 80 "least" 1 "most" 1000))
        "steps" (vector
          (obj "read" "body" "command" "pdfj" "at" t)
          (obj "derive" "functionBody")
          (obj "read" "strings" "command" "izj")
          (obj "derive" "findComparisons"))
        "title" (vector
          "find_comparisons: "
          (obj "get" (vector (vector "$" "body" "name") (vector "$" "addr")) "as" "text"))
        "sections" (vector
          (obj
            "title" (vector
              "Compares and the branches that follow: "
              (obj "count" (vector "$" "decisions"))
              " "
              (obj "cite" (vector "$" "@body")))
            "lines" (vector)
            "rows" (vector "$" "decisions")
            "limit" "maxItems"
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "op" "offset")) "as" "x" "or" "0x0")
              "  "
              (obj "get" (vector (vector "." "op" "disasm")) "as" "text" "or" "")
              (obj
                "group" (vector " ; \"" (obj "get" (vector (vector "." "printable")) "as" "text") "\""))
              (obj
                "group" (vector
                  "  ->  "
                  (obj "get" (vector (vector "." "next" "disasm")) "as" "text" "or" "")
                  ": "
                  (obj "get" (vector (vector "." "meaning")) "as" "text")
                  (obj
                    "group" (vector ", to " (obj "get" (vector (vector "." "next" "jump")) "as" "x")))
                  (obj
                    "group" (vector ", else " (obj "get" (vector (vector "." "next" "fail")) "as" "x"))))))
            "under" (vector)
            "more" "comparisons"
            "after" (vector))
          (obj
            "title" (vector
              "Calls that compare or validate: "
              (obj "count" (vector "$" "decidingCalls"))
              " "
              (obj "cite" (vector "$" "@body")))
            "lines" (vector)
            "rows" (vector "$" "decidingCalls")
            "limit" "maxItems"
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "offset")) "as" "x" "or" "0x0")
              "  "
              (obj "get" (vector (vector "." "disasm")) "as" "text" "or" ""))
            "under" (vector)
            "empty" (vector "  none by name")
            "after" (vector))
          (obj
            "title" (vector
              "Strings on the way: "
              (obj "count" (vector "$" "onTheWay"))
              " "
              (obj "cite" (vector "$" "@body"))
              " "
              (obj "cite" (vector "$" "@strings")))
            "lines" (vector)
            "rows" (vector "$" "onTheWay")
            "limit" "maxItems"
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "offset")) "as" "x")
              "  refers to "
              (obj "get" (vector (vector "." "target")) "as" "x")
              "  "
              (obj "get" (vector (vector "." "text")) "as" "line"))
            "under" (vector)
            "empty" (vector "  none")
            "after" (vector))
          (obj
            "lines" (vector
              (vector
                "This lists what is compared, not what the comparison means: which branch is the accepting one is for you to read from the code each leads to."))
            "under" (vector)
            "after" (vector))))
      (obj
        "name" "find_crypto"
        "call" "FIND-CRYPTO"
        "takes" nil
        "doc" "Where cryptographic material lies in the open binary: rizin's own search for keys and certificates,
and a search for the published constants of common algorithms, each hit with its address and what
refers to it. A constant's presence says the tables are linked in, not that they are used, nor on
what; a four-byte constant can occur by chance and is marked weak.

REFERENCES (default T; :FALSE for no): say what refers to each hit."
        "options" (vector (obj "name" "references" "key" "REFERENCES" "flag" t))
        "steps" (vector (obj "read" "material" "command" "/cmj") (obj "derive" "findCrypto"))
        "title" (vector
          "find_crypto: "
          (obj "count" (vector "$" "hits"))
          " constant hit"
          (obj "plural" (vector "$" "hits") "one" "" "many" "s"))
        "sections" (vector
          (obj
            "title" (vector
              "rizin's search for keys and certificates "
              (obj "cite" (vector "$" "@material")))
            "lines" (vector)
            "rows" (vector "$" "material")
            "limit" "cryptoMaterial"
            "row" (vector "  " (obj "get" (vector (vector ".")) "as" "json"))
            "under" (vector)
            "empty" (vector "  nothing found")
            "after" (vector))
          (obj
            "title" (vector "Published constants")
            "lines" (vector)
            "rows" (vector "$" "hits")
            "limit" "cryptoHits"
            "row" (vector
              "  "
              (obj "get" (vector (vector "." "address")) "as" "x")
              "  "
              (obj "get" (vector (vector "." "algorithm")) "as" "text")
              " — "
              (obj "get" (vector (vector "." "what")) "as" "text")
              " "
              (obj "cite" (vector "." "@hit"))
              (obj
                "choose" (vector "." "weak")
                "yes" " (weak: four bytes can occur by chance)"
                "no" ""))
            "under" (vector
              (obj
                "when" (vector "." "traced")
                "lines" (vector)
                "rows" (vector "." "places")
                "limit" "cryptoReferences"
                "line" (vector
                  "      referred to from "
                  (obj "join" (vector "$" "shown") "with" ", ")
                  " "
                  (obj "cite" (vector "." "@places")))
                "under" (vector)
                "empty" (vector
                  "      no reference found by analysis "
                  (obj "cite" (vector "." "@places"))
                  " — reached by computed address, or unused")
                "after" (vector)))
            "empty" (vector "  none of the constants in the table was found")
            "after" (vector))
          (obj
            "lines" (vector
              (vector
                "A table's presence shows the algorithm is linked in. What it is used on, and with which key, is in the code that refers to it."))
            "under" (vector)
            "after" (vector))))))
  "The recipes' data, in the shapes decoded JSON has.")
