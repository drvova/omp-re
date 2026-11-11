# recipes.py — wide reads composed over the one read tool, for omp's eval:
# triage, imports, one function, comparisons, cryptographic constants.
# The Python kernel's twin of recipes.js.
#
# SPDX-License-Identifier: MIT
#
# Load it once a session, in a standalone Python eval cell (language: "py"):
#
#   %load skill://re-triage/recipes.py
#
# (or `%load` with this file's path). It defines one global, `omp_re`:
#
#   print(omp_re.triage(max_strings=25, max_functions=15))
#   print(omp_re.scan_imports(callers=True, max_callers=12))
#   print(omp_re.inspect_function("main", max_items=30))
#   print(omp_re.find_comparisons("main", max_items=80))
#   print(omp_re.find_crypto(references=True))
#   print(omp_re.help())
#
# Each answers its report as a string and prints nothing.
#
# THE NAME IS `omp_re`, NOT `re`. In the JavaScript kernel the recipes are the
# global `re`. In omp's Python kernel `re` is already taken: omp's prelude runs
# in the cell namespace and imports the standard library's regex module there
# (eval/py/prelude.py: `import asyncio, …, json, math, re, time, …`), so every
# Python cell starts with `re` bound to it and may use `re.search(…)` without
# an import. Binding the recipes to `re` would take that away from every later
# cell. `omp_re` is the plugin's own name as a Python identifier: no standard
# library module, builtin or omp helper is called that, and it is not a name a
# cell would pick for a variable of its own.
#
# Python helpers in omp's eval are synchronous and take keyword arguments
# (`read(path, offset=…)`), and so do these: no `await` is needed. The one
# asynchronous helper is `tool.<name>(…)`, which answers a coroutine; a recipe
# settles each of its reads before it goes on. Since a cell that awaits its
# tool calls will reach for `await` here too, a report may also be awaited
# (`print(await omp_re.triage())`) and answers the same text.
#
# These are not tools, and nothing here is registered with omp.
# rizin_command is the one way to read the binary and eval is where reads
# are composed; a recipe is that composition, written once: the dozen reads
# every analysis opens with and a plain reading of them. Every read a recipe
# makes is `tool.rizin_command(...)` — a tool call in its own right, approved,
# audited and recorded as evidence like one typed by hand — so a recipe can do
# nothing the model could not, and `/re off` stops it at its first read.
#
# A recipe is not an oracle and must not read like one. Every section names
# the evidence id of the read it rests on, so a line here is a pointer to an
# observation that can be opened, never a conclusion to repeat: a finding
# still has to cite those ids to pass record_finding. The tables are
# judgement, worded as "worth a look", never as a verdict.
#
# recipes.js (the JavaScript kernel) and nodecode/recipes.lisp (the nodecode
# host) are this file's twins. All three answer the same text for the same
# binary, reads and all, and test/recipes-eval.test.ts holds them to it.
#
# What a recipe reads, in which order, how each section is worded, its options
# and their bounds, the tables and every sentence are data: they live in
# recipes/tables.json, and scripts/gen-recipes.ts writes them into the marked
# block below — with each recipe's Python signature — so edit the JSON and run
# the script, never the block. This file keeps what Python forces on it
# (rizin's JSON read as JavaScript would print it, the bridge for one read,
# how a number is printed), the loop that renders a recipe from that data, and
# under FACTS the few things a section needs code for. A change to any of
# those is a change in the other two files.
#
# Where this file and recipes.js differ, because the kernels do:
#  - The global is `omp_re` (above); recipes and options are spelled in
#    snake_case, and options are keyword arguments, not one object. An
#    unknown option is Python's own TypeError; the JavaScript ignores one.
#  - A refusal that says how to list functions names this kernel's call
#    (`await tool.rizin_command({"command": "aflj"})`); help() shows this
#    kernel's call forms.
#  - A refusal is raised as RuntimeError (TypeError for an address that is
#    not a string), with the same message the JavaScript throws.
#  - A report is a `str` whose repr is its own text, so a report left as a
#    cell's last expression is shown as written — as the JavaScript kernel
#    shows a string — instead of as one quoted line.
#
# A note for whoever edits this: omp rewrites a line that begins with `%` or `!`
# as a magic or a shell escape, even inside an expression, so no line here may
# begin with the `%` of a string format.
#
# Nothing but the standard library is imported, and nothing but `omp_re` is
# left in the cell namespace. (omp itself sets `__file__` there for any
# `%load`ed script.) There is no docstring on purpose: one would overwrite the
# namespace's `__doc__`.


def _omp_re_recipes():
    import asyncio
    import contextvars
    import inspect
    import json
    import math
    import re
    import threading
    from decimal import ROUND_HALF_UP, Decimal

# <generated:tables> — from recipes/tables.json by scripts/gen-recipes.ts; do not edit
    TABLES = {
      "riskyImports": [
        {
          "category": "memory",
          "severity": "high",
          "why": "copies with no bound at all; any input longer than the buffer overruns it",
          "names": ["gets"]
        },
        {
          "category": "memory",
          "severity": "high",
          "why": "copies or formats until a terminator with no destination size; safe only if every caller proves the length",
          "names": [
            "strcpy", "strcat", "stpcpy", "sprintf", "vsprintf", "wcscpy", "wcscat", "lstrcpyA",
            "lstrcpyW", "lstrcatA", "lstrcatW", "wsprintfA", "wsprintfW"
          ]
        },
        {
          "category": "memory",
          "severity": "medium",
          "why": "reads into a buffer; a %s or %[ without a width has no bound",
          "names": ["scanf", "sscanf", "fscanf", "vscanf", "vsscanf", "vfscanf"]
        },
        {
          "category": "memory",
          "severity": "medium",
          "why": "the size comes from the caller and is often attacker-influenced",
          "names": ["alloca", "realpath", "getwd"]
        },
        {
          "category": "memory",
          "severity": "low",
          "why": "bounded, but the bound is the caller's to get right (and strncpy leaves no terminator when it fills)",
          "names": ["strncpy", "strncat", "memcpy", "memmove", "bcopy", "wcsncpy", "snprintf", "vsnprintf"]
        },
        {
          "category": "command",
          "severity": "high",
          "why": "hands a string to a shell; anything in it that came from outside is a command",
          "names": [
            "system", "popen", "wordexp", "WinExec", "ShellExecuteA", "ShellExecuteW",
            "ShellExecuteExA", "ShellExecuteExW"
          ]
        },
        {
          "category": "command",
          "severity": "medium",
          "why": "starts another program; what it runs and with which arguments is worth tracing",
          "names": [
            "execl", "execlp", "execle", "execv", "execvp", "execve", "execvpe", "posix_spawn",
            "posix_spawnp", "CreateProcessA", "CreateProcessW"
          ]
        },
        {
          "category": "format",
          "severity": "low",
          "why": "a format string that is not a literal lets its author read and write memory",
          "names": [
            "printf", "fprintf", "dprintf", "vprintf", "vfprintf", "syslog", "vsyslog", "err",
            "errx", "warn", "warnx"
          ]
        },
        {
          "category": "race",
          "severity": "high",
          "why": "chooses a file name before the file exists; another process can take it first",
          "names": ["mktemp", "tmpnam", "tempnam"]
        },
        {
          "category": "race",
          "severity": "low",
          "why": "checks a path, then uses it; the file can change between the two",
          "names": ["access", "stat", "lstat"]
        },
        {
          "category": "integer",
          "severity": "low",
          "why": "reports no error and no overflow; a caller cannot tell a bad number from zero",
          "names": ["atoi", "atol", "atoll", "atof"]
        },
        {
          "category": "randomness",
          "severity": "medium",
          "why": "predictable; unfit for keys, tokens or anything an adversary should not guess",
          "names": ["rand", "srand", "random", "srandom", "drand48", "lrand48"]
        },
        {
          "category": "privilege",
          "severity": "info",
          "why": "changes the process's identity or root; the order and the error checks matter",
          "names": ["setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid", "chroot"]
        },
        {
          "category": "loading",
          "severity": "medium",
          "why": "loads code chosen at run time; from where is worth tracing",
          "names": ["dlopen", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"]
        }
      ],
      "capabilities": [
        {
          "capability": "network",
          "names": [
            "socket", "connect", "bind", "listen", "accept", "send", "sendto", "recv", "recvfrom",
            "getaddrinfo", "gethostbyname", "WSAStartup", "InternetOpenA", "InternetOpenW",
            "InternetOpenUrlA", "InternetOpenUrlW", "InternetConnectA", "InternetConnectW",
            "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen", "WinHttpConnect",
            "WinHttpSendRequest", "URLDownloadToFileA", "URLDownloadToFileW", "curl_easy_perform",
            "SSL_connect"
          ]
        },
        {
          "capability": "process control",
          "names": [
            "fork", "vfork", "clone", "kill", "ptrace", "prctl", "OpenProcess", "TerminateProcess",
            "CreateRemoteThread", "CreateToolhelp32Snapshot", "Process32First", "Process32Next"
          ]
        },
        {
          "capability": "code injection",
          "names": [
            "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
            "SetWindowsHookExA", "SetWindowsHookExW", "process_vm_writev"
          ]
        },
        {
          "capability": "memory protection",
          "names": ["mprotect", "mmap", "memfd_create", "VirtualProtect", "VirtualProtectEx", "VirtualAlloc"]
        },
        {
          "capability": "anti-analysis",
          "names": [
            "ptrace", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
            "NtSetInformationThread", "GetTickCount", "QueryPerformanceCounter"
          ]
        },
        {
          "capability": "persistence",
          "names": [
            "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
            "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
            "SetFileAttributesA", "SetFileAttributesW"
          ]
        },
        {
          "capability": "cryptography",
          "names": [
            "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
            "CryptGenKey", "CryptHashData", "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
            "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_DigestInit_ex", "AES_set_encrypt_key",
            "AES_encrypt", "MD5_Init", "SHA1_Init", "SHA256_Init", "RC4", "DES_ecb_encrypt",
            "getrandom", "RAND_bytes"
          ]
        },
        {
          "capability": "filesystem",
          "names": [
            "unlink", "remove", "rename", "chmod", "chown", "opendir", "readdir", "ftw", "nftw",
            "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW", "FindFirstFileA",
            "FindFirstFileW", "CopyFileA", "CopyFileW"
          ]
        },
        {
          "capability": "dynamic resolution",
          "names": ["dlsym", "GetProcAddress", "LdrGetProcedureAddress"]
        }
      ],
      "severityOrder": ["high", "medium", "low", "info"],
      "importNameRules": [
        {"rule": "dropThrough", "text": "imp."},
        {"rule": "dropPrefix", "text": "__isoc99_"},
        {"rule": "dropLeading", "text": "_"},
        {"rule": "dropSuffix", "text": "_chk"}
      ],
      "stringInterest": [
        {
          "kind": "credentials",
          "pattern": "passw|passphrase|secret|\\btoken\\b|api[_-]?key|private key|credential|\\blogin\\b|\\bauth(?:enticat|oriz)"
        },
        {
          "kind": "network",
          "pattern": "https?://|ftp://|\\b[a-z0-9-]+\\.(?:com|net|org|io|ru|cn|info|biz|xyz|top)\\b|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|user-agent"
        },
        {
          "kind": "commands",
          "pattern": "/bin/sh|/bin/bash|cmd\\.exe|powershell|wget |curl |chmod |\\bnc \\b|schtasks|reg add"
        },
        {
          "kind": "paths",
          "pattern": "^/(?:etc|tmp|var|proc|dev|home|root)/|\\\\(?:windows|system32|appdata|temp)\\\\|HKEY_|\\\\Software\\\\"
        },
        {
          "kind": "checks",
          "pattern": "licen[sc]e|serial|registration|trial|expired|invalid|incorrect|denied|granted|debugger|virtual|sandbox|vmware|vbox"
        }
      ],
      "packerSectionNames": "upx|aspack|themida|vmp|mpress|petite|\\.packed|\\.enigma",
      "comparingCalls": "\\b(?:str|strn|strcase|strncase|wcs|wcsn|mem|b)cmp\\b|\\bstrstr\\b|\\bstrchr\\b|lstrcmp|CompareString|RtlCompareMemory|\\bcrc|\\bhash|md5|sha\\d|verify|check|valid",
      "cryptoConstants": [
        {"algorithm": "AES", "what": "S-box", "hex": "637c777bf26b6fc53001672bfed7ab76"},
        {"algorithm": "AES", "what": "inverse S-box", "hex": "52096ad53036a538bf40a39e81f3d7fb"},
        {
          "algorithm": "AES",
          "what": "T-table Te0 (big-endian words)",
          "hex": "c66363a5f87c7c84ee777799f67b7b8d"
        },
        {
          "algorithm": "AES",
          "what": "T-table Te0 (little-endian words)",
          "hex": "a56363c6847c7cf8997777ee8d7b7bf6"
        },
        {
          "algorithm": "SHA-256",
          "what": "round constants (little-endian words)",
          "hex": "982f8a4291443771cffbc0b5a5dbb5e9"
        },
        {
          "algorithm": "SHA-256",
          "what": "round constants (big-endian words)",
          "hex": "428a2f9871374491b5c0fbcfe9b5dba5"
        },
        {
          "algorithm": "SHA-256",
          "what": "initial state (little-endian words)",
          "hex": "67e6096a85ae67bb72f36e3c3af54fa5"
        },
        {
          "algorithm": "SHA-512",
          "what": "round constants (little-endian words)",
          "hex": "22ae28d7982f8a42cd65ef2391443771"
        },
        {
          "algorithm": "SHA-1 / MD5",
          "what": "initial state (little-endian words)",
          "hex": "0123456789abcdeffedcba9876543210"
        },
        {"algorithm": "SHA-1", "what": "round constant K1 (little-endian)", "hex": "9979825a"},
        {
          "algorithm": "MD5",
          "what": "sine table (little-endian words)",
          "hex": "78a46ad756b7c7e8db702024eecebdc1"
        },
        {
          "algorithm": "CRC-32",
          "what": "table, polynomial 0xEDB88320 (little-endian words)",
          "hex": "0000000096300777"
        },
        {
          "algorithm": "CRC-32",
          "what": "table, polynomial 0x04C11DB7 (big-endian words)",
          "hex": "0000000004c11db7130476dc"
        },
        {
          "algorithm": "ChaCha / Salsa20",
          "what": "sigma constant",
          "hex": "657870616e642033322d62797465206b"
        },
        {
          "algorithm": "ChaCha / Salsa20",
          "what": "tau constant",
          "hex": "657870616e642031362d62797465206b"
        },
        {
          "algorithm": "Blowfish",
          "what": "P-array (big-endian words)",
          "hex": "243f6a8885a308d313198a2e03707344"
        },
        {
          "algorithm": "Blowfish",
          "what": "P-array (little-endian words)",
          "hex": "886a3f24d308a3852e8a191344737003"
        },
        {"algorithm": "TEA / XTEA", "what": "delta (little-endian)", "hex": "b979379e"},
        {"algorithm": "TEA / XTEA", "what": "delta (big-endian)", "hex": "9e3779b9"},
        {
          "algorithm": "DES",
          "what": "initial permutation table",
          "hex": "3a322a221a120a023c342c241c140c04"
        },
        {"algorithm": "RC6 / RC5", "what": "P32 and Q32 (little-endian)", "hex": "6351e1b7b979379e"},
        {
          "algorithm": "Base64",
          "what": "standard alphabet",
          "hex": "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b2f"
        },
        {
          "algorithm": "Base64",
          "what": "URL-safe alphabet tail",
          "hex": "7778797a303132333435363738392d5f"
        }
      ],
      "opTypes": {
        "call": ["call", "ucall", "rcall", "icall", "ccall"],
        "decidingCall": ["call", "ucall", "rcall", "icall"],
        "compare": ["cmp", "acmp"],
        "branch": ["cjmp"]
      },
      "calleeAfter": "call",
      "branchMeanings": [
        {"mnemonics": ["je", "jz"], "meaning": "taken when equal / zero"},
        {"mnemonics": ["jne", "jnz"], "meaning": "taken when not equal / not zero"},
        {"mnemonics": ["ja", "jnbe"], "meaning": "taken when above (unsigned >)"},
        {"mnemonics": ["jae", "jnb", "jnc"], "meaning": "taken when above or equal (unsigned >=)"},
        {"mnemonics": ["jb", "jc", "jnae"], "meaning": "taken when below (unsigned <)"},
        {"mnemonics": ["jbe", "jna"], "meaning": "taken when below or equal (unsigned <=)"},
        {"mnemonics": ["jg", "jnle"], "meaning": "taken when greater (signed >)"},
        {"mnemonics": ["jge", "jnl"], "meaning": "taken when greater or equal (signed >=)"},
        {"mnemonics": ["jl", "jnge"], "meaning": "taken when less (signed <)"},
        {"mnemonics": ["jle", "jng"], "meaning": "taken when less or equal (signed <=)"},
        {"mnemonics": ["js"], "meaning": "taken when negative"},
        {"mnemonics": ["jns"], "meaning": "taken when not negative"}
      ],
      "otherBranch": "conditional",
      "sectionNotes": {
        "writableExecutable": "writable+executable",
        "veryHighEntropy": "very high entropy (compressed or encrypted data)",
        "highEntropyForCode": "high entropy for code",
        "packerName": "a name packers use"
      },
      "thresholds": {
        "veryHighEntropy": 7.2,
        "highEntropyForCode": 6.8,
        "fewImports": 8,
        "shortConstantHexDigits": 8
      },
      "limits": {
        "lineWidth": 100,
        "triageRiskyImports": 20,
        "cryptoMaterial": 40,
        "cryptoHits": 60,
        "cryptoReferences": 8
      },
      "whitespace": [
        9, 10, 11, 12, 13, 32, 160, 5760, 8192, 8193, 8194, 8195, 8196, 8197, 8198, 8199, 8200,
        8201, 8202, 8232, 8233, 8239, 8287, 12288, 65279
      ],
      "text": {
        "more": ["  … ", {"get": ["hidden"], "as": "d"}, " more ", {"get": ["what"]}, " not shown"],
        "evidenceTaken": "Evidence taken (cite these in record_finding; each is a rizin_command read you can re-run):",
        "evidenceRow": ["  ", {"get": [".id"]}, "  ", {"get": [".label"]}],
        "nameless": "?",
        "refusals": {
          "notAString": [
            "omp-re: ",
            {"get": ["recipe"]},
            ": a function is named by a string, not ",
            {"get": ["given"]}
          ],
          "optionsNotOneObject": [
            "omp-re: ",
            {"get": ["recipe"]},
            ": options are one object, e.g. { maxItems: 20 }, not ",
            {"get": ["given"]}
          ],
          "noFunction": [
            "omp-re: ",
            {"get": ["recipe"]},
            ": no function at ",
            {"get": ["addr"]},
            " — list them with ",
            {"get": ["listFunctions"]},
            ", or define one with define_function"
          ],
          "noInstructions": [
            "omp-re: ",
            {"get": ["recipe"]},
            ": no function at ",
            {"get": ["addr"]},
            " — list them with ",
            {"get": ["listFunctions"]}
          ],
          "cutOutput": [
            "omp-re: ",
            {"get": ["recipe"]},
            ": the output of rizin_command ",
            {"get": ["label"], "as": "json"},
            " was cut at the size cap and the whole of it could not be read back (",
            {"get": ["why"]},
            "). The recipe needs all of it and will not report from cut JSON — run the reads by hand with narrower commands."
          ],
          "cutNoArtifact": ["the engine saved no artifact for it"],
          "cutUnreadable": ["artifact://", {"get": ["artifact"]}, ": ", {"get": ["error"]}],
          "cutNotText": ["artifact://", {"get": ["artifact"]}, " did not read as text"]
        }
      },
      "host": {
        "listFunctions": "await tool.rizin_command({\"command\": \"aflj\"})",
        "help": "omp-re recipes — wide reads composed over rizin_command. Not tools: each read a recipe makes is its own\nrizin_command call (approved, audited, recorded as evidence). Each returns its report as a string; print() it.\nOpen a binary first (await tool.open_binary({\"path\": ...})). The recipes themselves need no await.\n\n  omp_re.triage(max_strings=25, max_functions=15)\n      what the binary is, build protections, sections with entropy, imports and what they reach,\n      notable strings, the largest functions, entry points.\n  omp_re.scan_imports(callers=True, max_callers=12)\n      the imports a reviewer stops at, why, and who calls each; what the program can reach.\n  omp_re.inspect_function(\"main\", max_items=30)\n      one function's shape, variables, callers, callees and the strings it refers to.\n  omp_re.find_comparisons(\"main\", max_items=80)\n      every compare with the branch that follows, calls that compare or validate, strings on the way.\n  omp_re.find_crypto(references=True)\n      rizin's key and certificate search, and where published constants of common algorithms lie.\n\nEvery section cites the [evidence xxxxxxxx] id of the read it rests on, and each report ends with the\nreads it took. A line of a report is a lead, not a finding: record_finding with those ids makes it one.",
        "loaded": "omp-re recipes loaded: omp_re.triage, omp_re.scan_imports, omp_re.inspect_function, omp_re.find_comparisons, omp_re.find_crypto — print(omp_re.help()) says what each answers.",
        "shown": "<omp-re recipes: triage, scan_imports, inspect_function, find_comparisons, find_crypto — print(omp_re.help()) says what each answers>"
      },
      "recipes": [
        {
          "name": "triage",
          "call": "triage",
          "takes": False,
          "doc": "A first look at the open binary, composed from rizin's own reads: what it is, which protections the\nbuild has, its sections with entropy, the imports that give it reach, the strings worth a first\nlook, its largest functions and its entry points. Nothing here is a finding until one is recorded\nciting the ids.\n\nmax_strings (default 25, 1..200): at most this many notable strings are listed.\nmax_functions (default 15, 1..100): at most this many functions are listed.",
          "options": [
            {"name": "maxStrings", "key": "max_strings", "default": 25, "least": 1, "most": 200},
            {"name": "maxFunctions", "key": "max_functions", "default": 15, "least": 1, "most": 100}
          ],
          "steps": [
            {"read": "path", "command": "ij"},
            {"read": "info", "command": "iIj"},
            {"read": "sectionData", "command": "iSj entropy"},
            {"read": "imports", "command": "iij"},
            {"read": "strings", "command": "izj"},
            {"read": "functionData", "command": "aflj"},
            {"read": "entries", "command": "iej"},
            {"derive": "triage"}
          ],
          "title": ["triage: ", {"get": ["path.core.file"], "or": "?"}],
          "sections": [
            {
              "title": ["Identity ", {"cite": "@info"}],
              "lines": [
                [
                  "  ",
                  {"get": ["info.class", "info.bintype"], "or": "unknown format"},
                  ", ",
                  {"get": ["info.arch"], "or": "?"},
                  " ",
                  {"get": ["info.bits"], "as": "d", "or": "?"},
                  "-bit ",
                  {"get": ["info.endian"], "or": ""},
                  ", ",
                  {"get": ["info.os"], "or": "?"},
                  {"group": [", language ", {"get": ["info.lang"]}]},
                  {"group": [", interpreter ", {"get": ["info.intrp"]}]}
                ]
              ]
            },
            {
              "title": ["Build protections ", {"cite": "@info"}],
              "lines": [
                [
                  "  stack canary: ",
                  {
                    "choose": "info.canary",
                    "yes": "yes",
                    "no": "NO — a stack overflow reaches the return address unchecked"
                  }
                ],
                [
                  "  NX: ",
                  {"choose": "info.nx", "yes": "yes", "no": "NO — data pages are executable"}
                ],
                [
                  "  PIE: ",
                  {
                    "choose": "info.pie",
                    "yes": "yes",
                    "no": "NO — the image loads at a fixed address"
                  }
                ],
                [
                  "  RELRO: ",
                  {"get": ["info.relro"], "or": "none"},
                  {"group": [{"if": "info.relro", "is": "partial"}, " — the GOT stays writable"]},
                  {
                    "group": [
                      {"unless": "info.relro", "is": "partial"},
                      {"unless": "info.relro", "is": "full"},
                      " — the GOT and other relocated data stay writable"
                    ]
                  }
                ],
                [
                  "  fortified libc calls: ",
                  {"choose": "info.fortify_source", "yes": "yes", "no": "no"}
                ],
                [
                  "  stripped: ",
                  {"choose": "info.stripped", "yes": "yes", "no": "no"},
                  "   static: ",
                  {"choose": "info.static", "yes": "yes", "no": "no"}
                ]
              ]
            },
            {
              "title": ["Sections: ", {"count": "sections"}, " ", {"cite": "@sectionData"}],
              "rows": "sections",
              "row": [
                "  ",
                {"get": [".section.name"], "padRight": 18},
                " ",
                {"get": [".section.perm"], "padRight": 4, "or": ""},
                " ",
                {"get": [".section.size"], "as": "d", "padLeft": 9, "or": "0"},
                " bytes  entropy ",
                {"get": [".entropy"], "as": "f2", "padLeft": 4, "or": "?"},
                {"group": [{"if": ".notes"}, "  <- ", {"join": ".notes", "with": "; "}]}
              ],
              "after": [
                [
                  {
                    "group": [
                      {"if": "flagged"},
                      "  ",
                      {"count": "flagged"},
                      " section",
                      {"plural": "flagged", "one": "", "many": "s"},
                      " stand",
                      {"plural": "flagged", "one": "s", "many": ""},
                      " out; high entropy in code, or a section both writable and executable, is what a packed or self-modifying binary looks like — read it before trusting the function list."
                    ]
                  }
                ]
              ]
            },
            {
              "title": ["Imports: ", {"count": "imports"}, " ", {"cite": "@imports"}],
              "lines": [
                [
                  {
                    "group": [
                      {"if": "reach"},
                      "  reach, by what it links: ",
                      {"join": "reach", "with": ", "}
                    ]
                  },
                  {
                    "group": [
                      {"unless": "reach"},
                      "  none of the capability groups (network, process control, injection, …) is linked"
                    ]
                  }
                ],
                [
                  {
                    "group": [
                      {"if": "riskyShown"},
                      "  worth a reviewer's look: ",
                      {"join": "riskyShown", "with": ", "},
                      " — scan_imports says why and who calls them"
                    ]
                  }
                ],
                [
                  {
                    "choose": "fewImports",
                    "yes": "  very few imports for a dynamic binary: resolved at run time, or packed",
                    "no": ""
                  }
                ]
              ]
            },
            {
              "title": [
                "Strings: ",
                {"count": "strings"},
                "; notable ",
                {"count": "notable"},
                " ",
                {"cite": "@strings"}
              ],
              "rows": "notable",
              "limit": "maxStrings",
              "row": [
                "  ",
                {"get": [".kind"], "padRight": 11},
                " ",
                {"get": [".entry.vaddr"], "as": "x", "or": "?"},
                "  ",
                {"get": [".entry.string"], "as": "line", "or": ""}
              ],
              "more": "notable strings"
            },
            {
              "title": [
                "Functions: ",
                {"count": "functions"},
                "; largest by code size ",
                {"cite": "@functionData"}
              ],
              "rows": "functions",
              "limit": "maxFunctions",
              "row": [
                "  ",
                {"get": [".offset", ".addr"], "as": "x", "or": "0x0"},
                "  ",
                {"get": [".realsz", ".size"], "as": "d", "padLeft": 7, "or": "0"},
                " bytes  ",
                {"group": [{"get": [".nbbs"], "as": "d"}, " blocks  "]},
                {"get": [".name"], "or": "?"}
              ],
              "more": "functions"
            },
            {
              "title": ["Entry points ", {"cite": "@entries"}],
              "rows": "entries",
              "row": ["  ", {"get": [".vaddr"], "as": "x"}, "  ", {"get": [".type"], "or": ""}],
              "empty": ["  none reported"]
            }
          ]
        },
        {
          "name": "scan_imports",
          "call": "scan_imports",
          "takes": False,
          "doc": "The imports a reviewer would stop at, each with why it matters and who calls it; plus what the\nprogram can reach, read off what it links. An import is a lead, not a bug: whether a call is safe is\ndecided at its call site, which is what the callers are listed for.\n\ncallers (default True): list who calls each import.\nmax_callers (default 12, 1..100): at most this many callers are listed for each.",
          "options": [
            {"name": "callers", "key": "callers", "flag": True},
            {"name": "maxCallers", "key": "max_callers", "default": 12, "least": 1, "most": 100}
          ],
          "steps": [{"read": "imports", "command": "iij"}, {"derive": "scanImports"}],
          "title": [
            "scan_imports: ",
            {"count": "imports"},
            " imports, ",
            {"count": "risky"},
            " worth a look"
          ],
          "sections": [
            {
              "title": ["Reach, by what it links ", {"cite": "@imports"}],
              "rows": "reach",
              "row": [
                "  ",
                {"get": [".capability"], "padRight": 18},
                " ",
                {"join": ".names", "with": ", "}
              ],
              "empty": ["  none of the capability groups is linked"]
            },
            {
              "title": ["Imports worth a reviewer's look ", {"cite": "@imports"}],
              "rows": "risky",
              "row": [
                "  [",
                {"get": [".severity"]},
                "] ",
                {"get": [".bare"]},
                {"group": [" (linked as ", {"get": [".linkedAs"]}, ")"]},
                " (",
                {"get": [".category"]},
                ")",
                {"group": [" @ ", {"get": [".plt"], "as": "x"}]},
                " — ",
                {"get": [".why"]}
              ],
              "under": [
                {
                  "when": ".traced",
                  "rows": ".places",
                  "limit": "maxCallers",
                  "line": [
                    "      called from ",
                    {"count": ".places"},
                    " place",
                    {"plural": ".places", "one": "", "many": "s"},
                    " ",
                    {"cite": ".@places"},
                    ": ",
                    {"join": "shown", "with": ", "}
                  ],
                  "empty": ["      no caller found by analysis ", {"cite": ".@places"}],
                  "more": "callers"
                }
              ],
              "empty": ["  none of the imports in the table is linked"]
            },
            {
              "lines": [
                [
                  "An import is a lead. Read each call site (rizin_command pdg or pdf at the caller) before saying what it does."
                ]
              ]
            }
          ]
        },
        {
          "name": "inspect_function",
          "call": "inspect_function",
          "takes": True,
          "doc": "One function, read from every side at once: its size, complexity and signature, its variables, who\ncalls it and what it calls, and the strings it refers to — the context to read before its code.\nFollow it with rizin_command pdg at the same address for the code.\n\naddr: the function's name or address, a string.\nmax_items (default 30, 1..300): at most this many of each list are shown.",
          "options": [{"name": "maxItems", "key": "max_items", "default": 30, "least": 1, "most": 300}],
          "steps": [
            {"read": "infoData", "command": "afij", "at": True},
            {"derive": "theFunction"},
            {"read": "body", "command": "pdfj", "at": True},
            {"read": "variables", "command": "afvlj", "at": True},
            {"read": "strings", "command": "izj"},
            {"derive": "inspectFunction"}
          ],
          "title": ["inspect_function: ", {"get": ["info.name", "addr"]}],
          "sections": [
            {
              "title": ["Shape ", {"cite": "@infoData"}],
              "lines": [
                [
                  "  ",
                  {"get": ["info.signature", "info.name", "addr"]},
                  " at ",
                  {"get": ["info.offset", "info.addr"], "as": "x", "or": "0x0"}
                ],
                [
                  "  ",
                  {"get": ["info.realsz", "info.size"], "as": "d", "or": "0"},
                  " bytes of code, ",
                  {"get": ["info.nbbs"], "as": "d", "or": "0"},
                  " basic blocks, ",
                  {"get": ["info.edges"], "as": "d", "or": "0"},
                  " edges, cyclomatic complexity ",
                  {"get": ["info.cc"], "as": "d", "or": "0"},
                  ", ",
                  {"get": ["info.loops"], "as": "d", "or": "0"},
                  " loop",
                  {"plural": "info.loops", "one": "", "many": "s"}
                ],
                [
                  "  calling convention ",
                  {"get": ["info.calltype"], "or": "?"},
                  ", stack frame ",
                  {"get": ["info.stackframe"], "as": "d", "or": "0"},
                  " bytes",
                  {"choose": "info.noreturn", "yes": ", does not return", "no": ""}
                ]
              ]
            },
            {
              "title": ["Body ", {"cite": "@body"}],
              "lines": [
                [
                  "  ",
                  {"count": "ops"},
                  " instructions, ",
                  {"get": ["compares"], "as": "d"},
                  " compare",
                  {"plural": "compares", "one": "", "many": "s"},
                  ", ",
                  {"get": ["branches"], "as": "d"},
                  " conditional branch",
                  {"plural": "branches", "one": "", "many": "es"},
                  " — find_comparisons lists them"
                ]
              ]
            },
            {
              "title": ["Variables: ", {"get": ["variableCount"], "as": "d"}, " ", {"cite": "@variables"}]
            },
            {
              "title": [
                "Called from ",
                {"count": "callers"},
                " place",
                {"plural": "callers", "one": "", "many": "s"},
                " ",
                {"cite": "@callers"}
              ],
              "rows": "callers",
              "limit": "maxItems",
              "row": ["  ", {"get": ["."]}],
              "more": "callers"
            },
            {
              "title": [
                "Calls ",
                {"count": "calls"},
                " distinct target",
                {"plural": "calls", "one": "", "many": "s"},
                " ",
                {"cite": "@body"}
              ],
              "rows": "calls",
              "limit": "maxItems",
              "row": ["  ", {"get": ["."]}],
              "more": "callees"
            },
            {
              "title": [
                "Refers to ",
                {"count": "referenced"},
                " string",
                {"plural": "referenced", "one": "", "many": "s"},
                " ",
                {"cite": "@body"},
                " ",
                {"cite": "@strings"}
              ],
              "rows": "referenced",
              "limit": "maxItems",
              "row": ["  ", {"get": [".address"], "as": "x"}, "  ", {"get": [".text"], "as": "line"}],
              "more": "strings"
            }
          ]
        },
        {
          "name": "find_comparisons",
          "call": "find_comparisons",
          "takes": True,
          "doc": "What a function decides on: every compare or test with the conditional branch that follows it (which\nway it goes, and where to), every call to something that compares or validates, and the strings on\nthe way — the static skeleton of validation logic, with no emulation and nothing run. It lists what\nis compared, not what the comparison means.\n\naddr: the function's name or address, a string.\nmax_items (default 80, 1..1000): at most this many of each list are shown.",
          "options": [{"name": "maxItems", "key": "max_items", "default": 80, "least": 1, "most": 1000}],
          "steps": [
            {"read": "body", "command": "pdfj", "at": True},
            {"derive": "functionBody"},
            {"read": "strings", "command": "izj"},
            {"derive": "findComparisons"}
          ],
          "title": ["find_comparisons: ", {"get": ["body.name", "addr"]}],
          "sections": [
            {
              "title": [
                "Compares and the branches that follow: ",
                {"count": "decisions"},
                " ",
                {"cite": "@body"}
              ],
              "rows": "decisions",
              "limit": "maxItems",
              "row": [
                "  ",
                {"get": [".op.offset"], "as": "x", "or": "0x0"},
                "  ",
                {"get": [".op.disasm"], "or": ""},
                {"group": [" ; \"", {"get": [".printable"]}, "\""]},
                {
                  "group": [
                    "  ->  ",
                    {"get": [".next.disasm"], "or": ""},
                    ": ",
                    {"get": [".meaning"]},
                    {"group": [", to ", {"get": [".next.jump"], "as": "x"}]},
                    {"group": [", else ", {"get": [".next.fail"], "as": "x"}]}
                  ]
                }
              ],
              "more": "comparisons"
            },
            {
              "title": [
                "Calls that compare or validate: ",
                {"count": "decidingCalls"},
                " ",
                {"cite": "@body"}
              ],
              "rows": "decidingCalls",
              "limit": "maxItems",
              "row": [
                "  ",
                {"get": [".offset"], "as": "x", "or": "0x0"},
                "  ",
                {"get": [".disasm"], "or": ""}
              ],
              "empty": ["  none by name"]
            },
            {
              "title": [
                "Strings on the way: ",
                {"count": "onTheWay"},
                " ",
                {"cite": "@body"},
                " ",
                {"cite": "@strings"}
              ],
              "rows": "onTheWay",
              "limit": "maxItems",
              "row": [
                "  ",
                {"get": [".offset"], "as": "x"},
                "  refers to ",
                {"get": [".target"], "as": "x"},
                "  ",
                {"get": [".text"], "as": "line"}
              ],
              "empty": ["  none"]
            },
            {
              "lines": [
                [
                  "This lists what is compared, not what the comparison means: which branch is the accepting one is for you to read from the code each leads to."
                ]
              ]
            }
          ]
        },
        {
          "name": "find_crypto",
          "call": "find_crypto",
          "takes": False,
          "doc": "Where cryptographic material lies in the open binary: rizin's own search for keys and certificates,\nand a search for the published constants of common algorithms, each hit with its address and what\nrefers to it. A constant's presence says the tables are linked in, not that they are used, nor on\nwhat; a four-byte constant can occur by chance and is marked weak.\n\nreferences (default True): say what refers to each hit.",
          "options": [{"name": "references", "key": "references", "flag": True}],
          "steps": [{"read": "material", "command": "/cmj"}, {"derive": "findCrypto"}],
          "title": [
            "find_crypto: ",
            {"count": "hits"},
            " constant hit",
            {"plural": "hits", "one": "", "many": "s"}
          ],
          "sections": [
            {
              "title": ["rizin's search for keys and certificates ", {"cite": "@material"}],
              "rows": "material",
              "limit": "cryptoMaterial",
              "row": ["  ", {"get": ["."], "as": "json"}],
              "empty": ["  nothing found"]
            },
            {
              "title": ["Published constants"],
              "rows": "hits",
              "limit": "cryptoHits",
              "row": [
                "  ",
                {"get": [".address"], "as": "x"},
                "  ",
                {"get": [".algorithm"]},
                " — ",
                {"get": [".what"]},
                " ",
                {"cite": ".@hit"},
                {"choose": ".weak", "yes": " (weak: four bytes can occur by chance)", "no": ""}
              ],
              "under": [
                {
                  "when": ".traced",
                  "rows": ".places",
                  "limit": "cryptoReferences",
                  "line": [
                    "      referred to from ",
                    {"join": "shown", "with": ", "},
                    " ",
                    {"cite": ".@places"}
                  ],
                  "empty": [
                    "      no reference found by analysis ",
                    {"cite": ".@places"},
                    " — reached by computed address, or unused"
                  ]
                }
              ],
              "empty": ["  none of the constants in the table was found"]
            },
            {
              "lines": [
                [
                  "A table's presence shows the algorithm is linked in. What it is used on, and with which key, is in the code that refers to it."
                ]
              ]
            }
          ]
        }
      ]
    }

    def recipe_functions(run_recipe):
        def triage(*, max_strings=None, max_functions=None):
            return run_recipe("triage", None, {"maxStrings": max_strings, "maxFunctions": max_functions})

        def scan_imports(*, callers=None, max_callers=None):
            return run_recipe("scan_imports", None, {"callers": callers, "maxCallers": max_callers})

        def inspect_function(addr=None, *, max_items=None):
            return run_recipe("inspect_function", addr, {"maxItems": max_items})

        def find_comparisons(addr=None, *, max_items=None):
            return run_recipe("find_comparisons", addr, {"maxItems": max_items})

        def find_crypto(*, references=None):
            return run_recipe("find_crypto", None, {"references": references})

        return [triage, scan_imports, inspect_function, find_comparisons, find_crypto]
# </generated:tables>
    TEXT = TABLES["text"]
    HOST = TABLES["host"]
    LIMITS = TABLES["limits"]
    THRESHOLDS = TABLES["thresholds"]
    OP_TYPES = TABLES["opTypes"]
    NOTES = TABLES["sectionNotes"]
    RECIPES = {recipe["name"]: recipe for recipe in TABLES["recipes"]}
    # The JSON's patterns are written once for every host and matched without regard to case on
    # each. JavaScript's /i without /u folds case for ASCII letters only when the pattern is
    # ASCII, and its \b and \d are ASCII; re.ASCII is what makes Python read them the same way.
    FLAGS = re.IGNORECASE | re.ASCII
    STRING_INTEREST = [(row["kind"], re.compile(row["pattern"], FLAGS)) for row in TABLES["stringInterest"]]
    PACKER_SECTION_NAMES = re.compile(TABLES["packerSectionNames"], FLAGS)
    COMPARING_CALLS = re.compile(TABLES["comparingCalls"], FLAGS)

    # --- rizin's JSON, with its numbers as rizin wrote them ---------------------------------

    def json_number(digits):
        # A number written with a fraction or an exponent. JavaScript has one number type, so
        # 4096.0 is 4096 there and prints as it; keep that by reading a whole value as an int.
        value = float(digits)
        return int(value) if math.isfinite(value) and value == math.floor(value) and abs(value) < 1e21 else value

    def not_json(name):
        raise ValueError(name + " is not JSON")

    def parse_json(text):
        # rizin prints a 64-bit address as a decimal integer — the all-ones vaddr of an unmapped
        # section is 18446744073709551615 — and Python's int holds any of them exactly.
        try:
            return json.loads(text, parse_float=json_number, parse_constant=not_json)
        except (ValueError, RecursionError):
            # Not JSON reads as no data, never as an error: an empty reply is how rizin says "nothing here".
            return None

    def is_number(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    def get(thing, key):
        """A member with null read as absent; absent as soon as `thing` is not an object."""
        return thing.get(key) if isinstance(thing, dict) else None

    def string(thing, key):
        value = get(thing, key)
        return value if isinstance(value, str) else None

    def num(thing, key):
        value = get(thing, key)
        return value if is_number(value) else None

    def rows(data):
        return data if isinstance(data, list) else []

    def first(*values):
        """The first value that is there: JavaScript's `a ?? b ?? c`."""
        for value in values:
            if value is not None:
                return value
        return None

    def number_text(value):
        """A number as JavaScript prints one."""
        if isinstance(value, int):
            return str(value)
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        text = repr(value)
        if "e" not in text:
            return text
        mantissa, exponent = text.split("e")
        if -7 < int(exponent) < 0:
            return format(Decimal(text), "f")
        return mantissa + "e" + ("+" if int(exponent) > 0 else "-") + str(abs(int(exponent)))

    def hexa(value):
        """An address as rizin's `0x…`. A number that is not whole is not an address and is left in decimal."""
        if isinstance(value, int):
            return ("0x-" if value < 0 else "0x") + format(abs(value), "x")
        return "0x" + number_text(value)

    def fixed2(value):
        """A number to two decimal places, a half rounded away from zero: JavaScript's toFixed(2)."""
        if isinstance(value, float) and (not math.isfinite(value) or abs(value) >= 1e21):
            return number_text(value)
        if value == 0:
            return "0.00"
        return str(Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

    LONE_SURROGATE = re.compile("[\ud800-\udfff]")

    def json_string(text):
        """A string as JSON.stringify writes one."""
        return LONE_SURROGATE.sub(lambda match: "\\u%04x" % ord(match.group()), json.dumps(text, ensure_ascii=False))

    def encode(value):
        """A decoded value as compact JSON, in the order rizin gave it."""
        if value is None:
            return "null"
        if value is True:
            return "true"
        if value is False:
            return "false"
        if isinstance(value, (int, float)):
            return number_text(value) if not isinstance(value, float) or math.isfinite(value) else "null"
        if isinstance(value, str):
            return json_string(value)
        if isinstance(value, (list, tuple)):
            return "[" + ",".join(encode(member) for member in value) + "]"
        if isinstance(value, dict):
            return "{" + ",".join(json_string(str(key)) + ":" + encode(member) for key, member in value.items()) + "}"
        return repr(value)

    NUMERIC = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\Z", re.ASCII)

    def number_from_text(text):
        """The number a string of digits spells — rizin writes a section's entropy as one — or nothing."""
        return float(text) if NUMERIC.match(text) else None

    # --- text ---------------------------------------------------------------------------------

    # White space is the data's list on every host, not each language's own idea of it.
    SPACE = "".join(chr(point) for point in TABLES["whitespace"])
    SPACES = re.compile("[" + re.escape(SPACE) + "]+")

    def trim(text):
        return text.strip(SPACE)

    def words(text):
        return [word for word in SPACES.split(text) if word != ""]

    def after_word(text, word):
        """`text` without a leading `word` and the white space after it; as it stands when it does not open that way."""
        rest = text[len(word) :]
        return rest.lstrip(SPACE) if text.startswith(word) and rest[:1] != "" and rest[0] in SPACE else text

    def pad_right(text, width):
        return text + " " * max(0, width - len(text))

    def pad_left(text, width):
        return " " * max(0, width - len(text)) + text

    def one_line(text):
        return text.replace("\n", " ")[: LIMITS["lineWidth"]]

    def unique_first(items, key=lambda item: item):
        """Without duplicates, keeping each value where it first stood."""
        seen = set()
        kept = []
        for item in items:
            if key(item) not in seen:
                seen.add(key(item))
                kept.append(item)
        return kept

    def unique_last(items, key=lambda item: item):
        """Without duplicates, keeping each value where it last stood."""
        return unique_first(list(reversed(items)), key)[::-1]

    def bounded(value, fallback, least, most):
        """`value` when it is a whole number within least..most, the nearer bound when it is outside, `fallback` when it was not given."""
        if not is_number(value):
            return fallback
        if isinstance(value, float):
            if not math.isfinite(value) or value != math.floor(value):
                return fallback
            value = int(value)
        return max(least, min(most, value))

    # --- a template, filled -------------------------------------------------------------------

    # scripts/gen-recipes.ts says what a template may hold; what it writes into the tables is walked here.
    MISSING = object()

    def lookup(path, facts, row):
        """What a path names: a fact, or (when it opens with ".") the row, and then members of it."""
        value = row if path[0] == "." else facts
        for key in path.split("."):
            if key != "":
                value = get(value, key)
        return value

    def there(value):
        return value is True or (isinstance(value, list) and len(value) > 0)

    def size(value):
        return len(value) if isinstance(value, list) else value if is_number(value) else 0

    AS = {
        "text": lambda value: value if isinstance(value, str) else MISSING,
        "d": lambda value: number_text(value) if is_number(value) else MISSING,
        "x": lambda value: hexa(value) if is_number(value) else MISSING,
        "f2": lambda value: fixed2(value) if is_number(value) else MISSING,
        "line": lambda value: one_line(value) if isinstance(value, str) else MISSING,
        "json": encode,
    }

    def piece(node, facts, row):
        if isinstance(node, str):
            return node
        if "group" in node:
            inner = fill(node["group"], facts, row)
            return "" if inner is MISSING else inner
        if "if" in node or "unless" in node:
            value = lookup(node["if"] if "if" in node else node["unless"], facts, row)
            holds = (isinstance(value, str) and value == node["is"]) if "is" in node else there(value)
            return "" if holds == ("if" in node) else MISSING
        if "choose" in node:
            return node["yes"] if there(lookup(node["choose"], facts, row)) else node["no"]
        if "cite" in node:
            # How a line names the read it rests on; nothing when the read left no record.
            evidence_id = lookup(node["cite"], facts, row)
            return "[evidence " + evidence_id + "]" if isinstance(evidence_id, str) else ""
        if "count" in node:
            return str(len(rows(lookup(node["count"], facts, row))))
        if "join" in node:
            return node["with"].join(rows(lookup(node["join"], facts, row)))
        if "plural" in node:
            return node["one"] if size(lookup(node["plural"], facts, row)) == 1 else node["many"]
        text = MISSING
        for path in node["get"]:
            text = AS[node.get("as", "text")](lookup(path, facts, row))
            if text is not MISSING:
                break
        if text is MISSING:
            if "or" not in node:
                return MISSING
            text = node["or"]
        return pad_left(text, node["padLeft"]) if "padLeft" in node else pad_right(text, node["padRight"]) if "padRight" in node else text

    def fill(nodes, facts, row=None):
        """A template's text, or MISSING when something it needs is not there."""
        text = ""
        for node in nodes:
            part = piece(node, facts, row)
            if part is MISSING:
                return MISSING
            text += part
        return text

    def written(nodes, facts, row=None):
        """A template as the lines it adds: one, or none when it cannot be written or comes out empty."""
        text = fill(nodes, facts, row)
        return [] if text is MISSING or text == "" else [text]

    def section_lines(section, facts, row=None):
        """The lines of one section."""
        if "when" in section and not there(lookup(section["when"], facts, row)):
            return []
        lines = written(section["title"], facts, row) if "title" in section else []
        for line in section.get("lines", []):
            lines += written(line, facts, row)
        if "rows" in section:
            everything = rows(lookup(section["rows"], facts, row))
            most = facts[section["limit"]] if "limit" in section else None
            total = len(everything)
            if "line" in section:
                facts["shown"] = everything[:most]
                if total > 0:
                    lines += written(section["line"], facts, row)
            else:
                listed = [(item, text) for item in everything for text in written(section["row"], facts, item)]
                total = len(listed)
                for item, text in listed[:most]:
                    lines.append(text)
                    for inner in section.get("under", []):
                        lines += section_lines(inner, facts, item)
            if total == 0 and "empty" in section:
                lines += written(section["empty"], facts, row)
            # So a short list is never read as a whole one.
            if "more" in section and most is not None and total > most:
                lines += written(TEXT["more"], {"hidden": total - most, "what": section["more"]})
        for line in section.get("after", []):
            lines += written(line, facts, row)
        return lines

    def refusal(name, facts, kind=RuntimeError):
        return kind(fill(TEXT["refusals"][name], facts))

    class Report(str):
        """A recipe's report: its text, shown as written when it is a cell's value, and awaitable for a cell that awaits it."""

        __slots__ = ()

        def __repr__(self):
            return str(self)

        def __await__(self):
            return str(self)
            yield  # what makes this a generator, which is what `await` asks of __await__

    # --- one observation ----------------------------------------------------------------------

    # How much of an evidence record's id the engine shows, in a tag and in a report, and takes in record_finding.
    SHOWN_ID = 8

    def evidence_id_of(details):
        """The id of the evidence record a call left, as it is cited. The engine says it as data: the text is the binary's own and may hold anything."""
        full = details.get("evidenceId")
        return full[:SHOWN_ID] if isinstance(full, str) else None

    def settled(value):
        """
        `value`, or what it resolves to when it is awaitable. In omp's Python kernel `tool.<name>(…)`
        answers a coroutine and the cell runs inside a running event loop, where a synchronous
        function cannot wait for one. So it is run to its end on a thread of its own, under a copy
        of the cell's context — omp attributes a bridged tool call to the running cell through a
        context variable — while this thread waits, as it does inside omp's own `read()`.
        """
        if not inspect.isawaitable(value):
            return value
        context = contextvars.copy_context()
        outcome = {}

        async def wait():
            return await value

        def work():
            try:
                outcome["value"] = context.run(asyncio.run, wait())
            except BaseException as error:  # handed to the caller's thread, where it belongs
                outcome["error"] = error

        worker = threading.Thread(target=work, name="omp-re-recipe-read", daemon=True)
        worker.start()
        worker.join()
        if "error" in outcome:
            raise outcome["error"]
        return outcome.get("value")

    def after_header(full):
        return full[full.index("\n") + 1 :] if "\n" in full else ""

    def whole_output(run, label, text, details):
        """
        The whole of what rizin printed for a call. A result's text is the header line, the output,
        and, when the call left an evidence record, one last line that names it; past the size cap the output in the text is cut — for a `*j` command,
        whose JSON is one line, cut to nothing — and the engine keeps all of it as a session
        artifact, which eval's own read() returns raw. A recipe that parsed cut JSON would report a
        binary with no functions, so when the whole output cannot be had it stops and says so.
        """
        if details.get("truncated") is not True:
            recorded = evidence_id_of(details) is not None and "\n" in text
            return after_header(text[: text.rindex("\n")] if recorded else text)

        def lost(why, more=None):
            return refusal("cutOutput", {"recipe": run["name"], "label": label, "why": fill(TEXT["refusals"][why], more)})

        artifact = details.get("artifactId")
        if not isinstance(artifact, str):
            raise lost("cutNoArtifact")
        try:
            # `read` is omp's helper, a global of the cell namespace; for a bare artifact:// id it returns the file raw and whole.
            full = settled(read("artifact://" + artifact))  # noqa: F821
        except Exception as error:
            raise lost("cutUnreadable", {"artifact": artifact, "error": str(error)}) from None
        if not isinstance(full, str):
            raise lost("cutNotText", {"artifact": artifact})
        return after_header(full)

    def observe(run, command, addr=None):
        """
        One rizin_command call — the same approval, audit line and evidence record as any other —
        answering its whole output and the id of its record. A refused call raises from the tool;
        one rizin answered with an error comes back marked, and is raised here with rizin's words.
        """
        label = command if addr is None else "%s @ %s" % (command, addr)
        # `tool` is omp's helper, a global of the cell namespace.
        result = settled(tool.rizin_command({"command": command} if addr is None else {"command": command, "addr": addr}))  # noqa: F821
        if isinstance(result, str):
            text = result
        else:
            given = get(result, "text")
            text = "" if given is None else given if isinstance(given, str) else str(given)
        details = get(result, "details")
        if not isinstance(details, dict):
            details = {}
        if get(result, "hasError") is True:
            raise RuntimeError(text)
        evidence_id = evidence_id_of(details)
        if evidence_id:
            run["evidence"].append({"label": label, "id": evidence_id})
        # Only a call that printed something carries the command it ran; "(no output)" is the engine's words, not rizin's.
        raw = whole_output(run, label, text, details) if isinstance(details.get("commands"), list) else ""
        return raw, evidence_id

    def observe_json(run, command, addr=None):
        """observe() for a `*j` command: its data, absent when the output was empty or not JSON."""
        raw, evidence_id = observe(run, command, addr)
        return parse_json(trim(raw)), evidence_id

    # --- one recipe, from the data ------------------------------------------------------------

    def run_recipe(name, addr, given):
        """
        A recipe run as the data spells it: its options settled, its steps taken in order — a read,
        or a fact worked out below — and its title and sections filled from what those left, over
        the list of the reads it took, so every line can be traced and cited.
        """
        recipe = RECIPES[name]
        # What one call keeps: the reads it took, the function list once a caller had to be named, and the facts its templates name.
        facts = dict(LIMITS, recipe=name, listFunctions=HOST["listFunctions"])
        run = {"name": name, "evidence": [], "functions": None}
        if recipe["takes"]:
            # The engine judges what may follow `@` on every read, so only what it cannot be asked is refused here.
            if not isinstance(addr, str):
                raise refusal("notAString", dict(facts, given=encode(addr)), TypeError)
            facts["addr"] = addr
        for option in recipe["options"]:
            value = given[option["name"]]
            facts[option["name"]] = value is not False if "flag" in option else bounded(value, option["default"], option["least"], option["most"])
        for step in recipe["steps"]:
            if "derive" in step:
                FACTS[step["derive"]](run, facts)
            else:
                facts[step["read"]], facts["@" + step["read"]] = observe_json(run, step["command"], facts["addr"] if step.get("at") else None)
        lines = written(recipe["title"], facts)
        for section in recipe["sections"]:
            lines.append("")
            lines += section_lines(section, facts)
        lines += ["", TEXT["evidenceTaken"]]
        for taken in run["evidence"]:
            lines += written(TEXT["evidenceRow"], facts, taken)
        return Report("\n".join(lines))

    # --- what an import is called -------------------------------------------------------------

    def drop_leading(name, text):
        while name.startswith(text):
            name = name[len(text) :]
        return name

    IMPORT_NAME_RULES = {
        "dropThrough": lambda name, text: name[name.index(text) + len(text) :] if text in name else name,
        "dropPrefix": lambda name, text: name[len(text) :] if name.startswith(text) else name,
        "dropLeading": drop_leading,
        "dropSuffix": lambda name, text: name[: -len(text)] if name.endswith(text) else name,
    }

    def bare_import_name(given):
        """An import's name as the tables spell it: the decorations a linker or a fortified libc adds are taken off, by the data's rules in their order."""
        name = given or ""
        for rule in TABLES["importNameRules"]:
            name = IMPORT_NAME_RULES[rule["rule"]](name, rule["text"])
        return name

    def risky_import(bare):
        for row in TABLES["riskyImports"]:
            if bare in row["names"]:
                return row
        return None

    def import_capabilities(bare):
        return [row["capability"] for row in TABLES["capabilities"] if bare in row["names"]]

    def function_containing(run, address):
        """`address` as "function+0xoffset" when it lies in a function rizin found, else as the bare address. The function list is one more read, taken the first time a name is wanted."""
        if run["functions"] is None:
            run["functions"] = []
            for fn in rows(observe_json(run, "aflj")[0]):
                low = first(num(fn, "offset"), num(fn, "addr"))
                high = first(num(fn, "maxbound"), None if low is None else low + first(num(fn, "size"), 0))
                if low is not None and high is not None:
                    run["functions"].append((low, high, first(string(fn, "name"), TEXT["nameless"])))
        for low, high, name in run["functions"]:
            if low <= address < high:
                return name if address == low else "%s+%s" % (name, hexa(address - low))
        return hexa(address)

    def traced_to(run, address):
        """Where `address` is referenced from, each as "function+0xoffset", with the evidence id of the read: what a row is traced with."""
        data, evidence_id = observe_json(run, "axtj", hexa(address))
        places = []
        for row in rows(data):
            origin = num(row, "from")
            if origin is not None:
                places.append(function_containing(run, origin))
        return {"traced": True, "places": unique_first(places), "@places": evidence_id}

    # --- what a pdfj reply holds --------------------------------------------------------------

    def function_ops(body):
        return rows(get(body, "ops"))

    def op_is(op, kind):
        return string(op, "type") in OP_TYPES[kind]

    def op_targets(op):
        """Every address an instruction refers to."""
        referred = [num(reference, "addr") for reference in rows(get(op, "xrefs_from")) + rows(get(op, "refs"))]
        return [target for target in [num(op, "ptr"), num(op, "jump")] + referred if target is not None]

    def strings_by_address(data):
        """The strings rizin found, by where each lies."""
        table = {}
        for entry in rows(data):
            if num(entry, "vaddr") is not None:
                table[num(entry, "vaddr")] = string(entry, "string")
        return table

    def string_references(ops, string_data):
        """Each string an instruction of `ops` refers to, as (op, target, text)."""
        string_at = strings_by_address(string_data)
        return [(op, target, string_at[target]) for op in ops for target in op_targets(op) if string_at.get(target) is not None]

    # --- the facts a section needs code for -----------------------------------------------------

    # Each is a step some recipe names in the data; it leaves the facts the data's `facts` lists for it.

    def triage_facts(run, facts):
        sections = []
        for section in rows(facts["sectionData"]):
            if trim(first(string(section, "name"), "")) == "":
                continue
            perm = first(string(section, "perm"), "")
            given = get(section, "entropy")
            entropy = given if is_number(given) else number_from_text(trim(given)) if isinstance(given, str) else None
            # What stands out: writable and executable at once, or data that looks compressed or encrypted where code should be.
            notes = []
            if "w" in perm and "x" in perm:
                notes.append(NOTES["writableExecutable"])
            if entropy is not None and entropy >= THRESHOLDS["veryHighEntropy"]:
                notes.append(NOTES["veryHighEntropy"])
            elif entropy is not None and entropy >= THRESHOLDS["highEntropyForCode"] and "x" in perm:
                notes.append(NOTES["highEntropyForCode"])
            if PACKER_SECTION_NAMES.search(string(section, "name")):
                notes.append(NOTES["packerName"])
            sections.append({"section": section, "entropy": entropy, "notes": notes})
        imports = rows(facts["imports"])
        bare = [bare_import_name(string(entry, "name")) for entry in imports]
        facts["sections"] = sections
        facts["flagged"] = [section for section in sections if section["notes"]]
        facts["reach"] = unique_first([capability for name in bare for capability in import_capabilities(name)])
        facts["riskyShown"] = unique_last([name for name in bare if risky_import(name)])[: LIMITS["triageRiskyImports"]]
        facts["fewImports"] = len(imports) < THRESHOLDS["fewImports"] and get(facts["info"], "static") is not True
        facts["notable"] = [{"kind": kind, "entry": entry} for kind, pattern in STRING_INTEREST for entry in rows(facts["strings"]) if pattern.search(first(string(entry, "string"), ""))]
        # Largest first; functions of one size stay in rizin's order.
        facts["functions"] = sorted(rows(facts["functionData"]), key=lambda fn: first(num(fn, "realsz"), num(fn, "size"), 0), reverse=True)

    def scan_imports_facts(run, facts):
        named = [(entry, bare_import_name(string(entry, "name"))) for entry in rows(facts["imports"])]
        risky = [(entry, bare, risky_import(bare)) for entry, bare in named if risky_import(bare)]
        risky.sort(key=lambda item: TABLES["severityOrder"].index(item[2]["severity"]))
        facts["reach"] = []
        for row in TABLES["capabilities"]:
            linked = unique_last([bare for _, bare in named if bare in row["names"]])
            if linked:
                facts["reach"].append({"capability": row["capability"], "names": linked})
        facts["risky"] = []
        for entry, bare, verdict in risky:
            plt = num(entry, "plt")
            # An import rizin gives no name is its own bare name: nothing to say it was linked as.
            linked = first(string(entry, "name"), bare)
            traced = traced_to(run, plt) if facts["callers"] and plt is not None else {}
            facts["risky"].append(dict(traced, severity=verdict["severity"], category=verdict["category"], why=verdict["why"], bare=bare, linkedAs=None if linked == bare else linked, plt=plt))

    def the_function(run, facts):
        found = rows(facts["infoData"])
        facts["info"] = found[0] if found else None
        if not isinstance(facts["info"], dict):
            raise refusal("noFunction", facts)

    def inspect_function_facts(run, facts):
        ops = function_ops(facts["body"])
        traced = traced_to(run, first(num(facts["info"], "offset"), num(facts["info"], "addr"), 0))
        variables = facts["variables"]
        facts["callers"] = traced["places"]
        facts["@callers"] = traced["@places"]
        facts["ops"] = ops
        facts["calls"] = unique_first([after_word(first(string(op, "disasm"), ""), TABLES["calleeAfter"]) for op in ops if op_is(op, "call")])
        facts["compares"] = sum(1 for op in ops if op_is(op, "compare"))
        facts["branches"] = sum(1 for op in ops if op_is(op, "branch"))
        facts["variableCount"] = sum(len(rows(kind)) for kind in variables.values()) if isinstance(variables, dict) else 0
        facts["referenced"] = unique_last([{"address": target, "text": text} for _, target, text in string_references(ops, facts["strings"])], key=lambda reference: reference["address"])

    def function_body(run, facts):
        facts["ops"] = function_ops(facts["body"])
        if not facts["ops"]:
            raise refusal("noInstructions", facts)

    def branch_meaning(mnemonic):
        for row in TABLES["branchMeanings"]:
            if mnemonic in row["mnemonics"]:
                return row["meaning"]
        return TABLES["otherBranch"]

    def find_comparisons_facts(run, facts):
        ops = facts["ops"]
        facts["decisions"] = []
        for index, op in enumerate(ops):
            if not op_is(op, "compare"):
                continue
            # The branch that follows it, when one does: which way it goes is the mnemonic's to say.
            following = ops[index + 1] if index + 1 < len(ops) and op_is(ops[index + 1], "branch") else None
            mnemonic = (words(first(string(following, "disasm"), "")) or [""])[0].lower()
            # A compare against a printable character says which: a run of these is a string compared a byte at a time.
            value = first(num(op, "val"), num(op, "ptr"))
            printable = re.sub(r'(["\\])', r"\\\1", chr(value)) if isinstance(value, int) and 32 <= value <= 126 else None
            facts["decisions"].append({"op": op, "printable": printable, "next": following, "meaning": branch_meaning(mnemonic) if following is not None else None})
        facts["decidingCalls"] = [op for op in ops if op_is(op, "decidingCall") and COMPARING_CALLS.search(first(string(op, "disasm"), ""))]
        facts["onTheWay"] = unique_last(
            [{"offset": first(num(op, "offset"), 0), "target": target, "text": text} for op, target, text in string_references(ops, facts["strings"])],
            key=lambda reference: (reference["offset"], reference["target"]),
        )

    def find_crypto_facts(run, facts):
        facts["hits"] = []
        for constant in TABLES["cryptoConstants"]:
            # Each search is a read on the record whether or not it finds anything; only a hit is reported.
            data, evidence_id = observe_json(run, "/xj " + constant["hex"])
            for row in rows(data):
                address = first(num(row, "address"), num(row, "offset"), num(row, "addr"))
                if address is not None:
                    # So few bytes occur by chance: a hit means little on its own.
                    weak = len(constant["hex"]) <= THRESHOLDS["shortConstantHexDigits"]
                    facts["hits"].append({"algorithm": constant["algorithm"], "what": constant["what"], "address": address, "@hit": evidence_id, "weak": weak})
        if facts["references"]:
            for hit in facts["hits"][: LIMITS["cryptoHits"]]:
                hit.update(traced_to(run, hit["address"]))

    FACTS = {
        "triage": triage_facts,
        "scanImports": scan_imports_facts,
        "theFunction": the_function,
        "inspectFunction": inspect_function_facts,
        "functionBody": function_body,
        "findComparisons": find_comparisons_facts,
        "findCrypto": find_crypto_facts,
    }

    # --- what is handed to eval -----------------------------------------------------------------

    class Recipes:
        """omp-re's recipes for omp's Python kernel; help() says what each answers."""

        __slots__ = ()

        def __repr__(self):
            return HOST["shown"]

    def help():  # noqa: A001 - the name the JavaScript twin gives it; it shadows nothing outside this function
        """What each recipe answers, and how each is called."""
        return Report(HOST["help"])

    for recipe in recipe_functions(run_recipe) + [help]:
        if recipe.__name__ in RECIPES:
            recipe.__doc__ = RECIPES[recipe.__name__]["doc"]
        # So that Python's own complaint about a call names what was called: "omp_re.triage() got an unexpected keyword argument …".
        recipe.__qualname__ = "omp_re." + recipe.__name__
        setattr(Recipes, recipe.__name__, staticmethod(recipe))
    # A %load cell shows what the script printed, and the source is not echoed: say what now exists.
    print(HOST["loaded"])
    return Recipes()


try:
    omp_re = _omp_re_recipes()
finally:
    del _omp_re_recipes
