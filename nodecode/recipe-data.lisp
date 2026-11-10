;;;; recipe-data.lisp --- GENERATED from recipes/tables.json. Do not edit.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Regenerate with: bun scripts/gen-recipes.ts
;;;; The judgement the recipes rest on, kept as data so it can be argued with
;;;; and so the Lisp verbs and omp's eval script (skills/re-triage/recipes.js)
;;;; read the same tables. recipes.lisp is the code over them.

(in-package #:nodecode-re)

(defparameter *risky-imports*
  ;; (CATEGORY SEVERITY WHY NAME...) — what a reviewer would stop at, and the
  ;; reason in a line. Severity is how little the caller can do to make the
  ;; call safe, not how likely a bug is.
  '(("memory" "high" "copies with no bound at all; any input longer than the buffer overruns it"
     "gets")
    ("memory" "high" "copies or formats until a terminator with no destination size; safe only if every caller proves the length"
     "strcpy" "strcat" "stpcpy" "sprintf" "vsprintf" "wcscpy" "wcscat" "lstrcpyA" "lstrcpyW"
     "lstrcatA" "lstrcatW" "wsprintfA" "wsprintfW")
    ("memory" "medium" "reads into a buffer; a %s or %[ without a width has no bound"
     "scanf" "sscanf" "fscanf" "vscanf" "vsscanf" "vfscanf")
    ("memory" "medium" "the size comes from the caller and is often attacker-influenced"
     "alloca" "realpath" "getwd")
    ("memory" "low" "bounded, but the bound is the caller's to get right (and strncpy leaves no terminator when it fills)"
     "strncpy" "strncat" "memcpy" "memmove" "bcopy" "wcsncpy" "snprintf" "vsnprintf")
    ("command" "high" "hands a string to a shell; anything in it that came from outside is a command"
     "system" "popen" "wordexp" "WinExec" "ShellExecuteA" "ShellExecuteW" "ShellExecuteExA"
     "ShellExecuteExW")
    ("command" "medium" "starts another program; what it runs and with which arguments is worth tracing"
     "execl" "execlp" "execle" "execv" "execvp" "execve" "execvpe" "posix_spawn" "posix_spawnp"
     "CreateProcessA" "CreateProcessW")
    ("format" "low" "a format string that is not a literal lets its author read and write memory"
     "printf" "fprintf" "dprintf" "vprintf" "vfprintf" "syslog" "vsyslog" "err" "errx" "warn"
     "warnx")
    ("race" "high" "chooses a file name before the file exists; another process can take it first"
     "mktemp" "tmpnam" "tempnam")
    ("race" "low" "checks a path, then uses it; the file can change between the two"
     "access" "stat" "lstat")
    ("integer" "low" "reports no error and no overflow; a caller cannot tell a bad number from zero"
     "atoi" "atol" "atoll" "atof")
    ("randomness" "medium" "predictable; unfit for keys, tokens or anything an adversary should not guess"
     "rand" "srand" "random" "srandom" "drand48" "lrand48")
    ("privilege" "info" "changes the process's identity or root; the order and the error checks matter"
     "setuid" "setgid" "seteuid" "setegid" "setreuid" "setregid" "chroot")
    ("loading" "medium" "loads code chosen at run time; from where is worth tracing"
     "dlopen" "LoadLibraryA" "LoadLibraryW" "LoadLibraryExA" "LoadLibraryExW"))
  "Imports a reviewer stops at.")

(defparameter *capability-imports*
  ;; (CAPABILITY NAME...) — what the program can reach, read off what it links.
  '(("network"
     "socket" "connect" "bind" "listen" "accept" "send" "sendto" "recv" "recvfrom" "getaddrinfo"
     "gethostbyname" "WSAStartup" "InternetOpenA" "InternetOpenW" "InternetOpenUrlA"
     "InternetOpenUrlW" "InternetConnectA" "InternetConnectW" "HttpSendRequestA" "HttpSendRequestW"
     "WinHttpOpen" "WinHttpConnect" "WinHttpSendRequest" "URLDownloadToFileA" "URLDownloadToFileW"
     "curl_easy_perform" "SSL_connect")
    ("process control"
     "fork" "vfork" "clone" "kill" "ptrace" "prctl" "OpenProcess" "TerminateProcess"
     "CreateRemoteThread" "CreateToolhelp32Snapshot" "Process32First" "Process32Next")
    ("code injection"
     "VirtualAllocEx" "WriteProcessMemory" "ReadProcessMemory" "CreateRemoteThread"
     "NtUnmapViewOfSection" "ZwUnmapViewOfSection" "QueueUserAPC" "SetThreadContext"
     "SetWindowsHookExA" "SetWindowsHookExW" "process_vm_writev")
    ("memory protection"
     "mprotect" "mmap" "memfd_create" "VirtualProtect" "VirtualProtectEx" "VirtualAlloc")
    ("anti-analysis"
     "ptrace" "IsDebuggerPresent" "CheckRemoteDebuggerPresent" "NtQueryInformationProcess"
     "OutputDebugStringA" "OutputDebugStringW" "NtSetInformationThread" "GetTickCount"
     "QueryPerformanceCounter")
    ("persistence"
     "RegSetValueExA" "RegSetValueExW" "RegCreateKeyExA" "RegCreateKeyExW" "CreateServiceA"
     "CreateServiceW" "StartServiceA" "StartServiceW" "SetFileAttributesA" "SetFileAttributesW")
    ("cryptography"
     "CryptAcquireContextA" "CryptAcquireContextW" "CryptEncrypt" "CryptDecrypt" "CryptGenKey"
     "CryptHashData" "BCryptEncrypt" "BCryptDecrypt" "BCryptGenRandom" "EVP_EncryptInit_ex"
     "EVP_DecryptInit_ex" "EVP_DigestInit_ex" "AES_set_encrypt_key" "AES_encrypt" "MD5_Init"
     "SHA1_Init" "SHA256_Init" "RC4" "DES_ecb_encrypt" "getrandom" "RAND_bytes")
    ("filesystem"
     "unlink" "remove" "rename" "chmod" "chown" "opendir" "readdir" "ftw" "nftw" "DeleteFileA"
     "DeleteFileW" "MoveFileA" "MoveFileW" "FindFirstFileA" "FindFirstFileW" "CopyFileA" "CopyFileW")
    ("dynamic resolution"
     "dlsym" "GetProcAddress" "LdrGetProcedureAddress"))
  "What a program can do, read off what it imports. A capability is not an intent.")

(defparameter *severity-order* '("high" "medium" "low" "info")
  "Severities, the one to read first first.")

(defparameter *string-interest*
  '(("credentials" "(?i)passw|passphrase|secret|\\btoken\\b|api[_-]?key|private key|credential|\\blogin\\b|\\bauth(?:enticat|oriz)")
    ("network" "(?i)https?://|ftp://|\\b[a-z0-9-]+\\.(?:com|net|org|io|ru|cn|info|biz|xyz|top)\\b|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|user-agent")
    ("commands" "(?i)/bin/sh|/bin/bash|cmd\\.exe|powershell|wget |curl |chmod |\\bnc \\b|schtasks|reg add")
    ("paths" "(?i)^/(?:etc|tmp|var|proc|dev|home|root)/|\\\\(?:windows|system32|appdata|temp)\\\\|HKEY_|\\\\Software\\\\")
    ("checks" "(?i)licen[sc]e|serial|registration|trial|expired|invalid|incorrect|denied|granted|debugger|virtual|sandbox|vmware|vbox"))
  "What makes a string worth a first look, by the kind of lead it is.")

(defparameter +packer-section-names+
  "(?i)upx|aspack|themida|vmp|mpress|petite|\\.packed|\\.enigma"
  "Section names packers and protectors leave behind.")

(defparameter +comparing-calls+
  "(?i)\\b(?:str|strn|strcase|strncase|wcs|wcsn|mem|b)cmp\\b|\\bstrstr\\b|\\bstrchr\\b|lstrcmp|CompareString|RtlCompareMemory|\\bcrc|\\bhash|md5|sha\\d|verify|check|valid"
  "Calls that decide something about their input: comparisons by name, and names that say they validate.")

(defparameter *crypto-constants*
  ;; (ALGORITHM WHAT HEX) — byte strings as they lie in memory; a table of
  ;; words is listed in both byte orders. These are published constants.
  '(("AES" "S-box" "637c777bf26b6fc53001672bfed7ab76")
    ("AES" "inverse S-box" "52096ad53036a538bf40a39e81f3d7fb")
    ("AES" "T-table Te0 (big-endian words)" "c66363a5f87c7c84ee777799f67b7b8d")
    ("AES" "T-table Te0 (little-endian words)" "a56363c6847c7cf8997777ee8d7b7bf6")
    ("SHA-256" "round constants (little-endian words)" "982f8a4291443771cffbc0b5a5dbb5e9")
    ("SHA-256" "round constants (big-endian words)" "428a2f9871374491b5c0fbcfe9b5dba5")
    ("SHA-256" "initial state (little-endian words)" "67e6096a85ae67bb72f36e3c3af54fa5")
    ("SHA-512" "round constants (little-endian words)" "22ae28d7982f8a42cd65ef2391443771")
    ("SHA-1 / MD5" "initial state (little-endian words)" "0123456789abcdeffedcba9876543210")
    ("SHA-1" "round constant K1 (little-endian)" "9979825a")
    ("MD5" "sine table (little-endian words)" "78a46ad756b7c7e8db702024eecebdc1")
    ("CRC-32" "table, polynomial 0xEDB88320 (little-endian words)" "0000000096300777")
    ("CRC-32" "table, polynomial 0x04C11DB7 (big-endian words)" "0000000004c11db7130476dc")
    ("ChaCha / Salsa20" "sigma constant" "657870616e642033322d62797465206b")
    ("ChaCha / Salsa20" "tau constant" "657870616e642031362d62797465206b")
    ("Blowfish" "P-array (big-endian words)" "243f6a8885a308d313198a2e03707344")
    ("Blowfish" "P-array (little-endian words)" "886a3f24d308a3852e8a191344737003")
    ("TEA / XTEA" "delta (little-endian)" "b979379e")
    ("TEA / XTEA" "delta (big-endian)" "9e3779b9")
    ("DES" "initial permutation table" "3a322a221a120a023c342c241c140c04")
    ("RC6 / RC5" "P32 and Q32 (little-endian)" "6351e1b7b979379e")
    ("Base64" "standard alphabet" "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b2f")
    ("Base64" "URL-safe alphabet tail" "7778797a303132333435363738392d5f"))
  "Byte strings whose presence says an algorithm's tables are in the binary.")
