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
# host) are this file's twins. All three must answer the same text for the
# same binary, line for line, and test/recipes-eval.test.ts holds them to it;
# so a change to the wording or the order of reads here is a change there.
# The tables all three read are generated from recipes/tables.json by
# scripts/gen-recipes.ts, which rewrites the marked block below — edit the
# JSON and run the script, never the block.
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
# Where both differ from the Lisp, for the reasons recipes.js gives:
#  - find_crypto records every constant search as a read, misses included,
#    and "Evidence taken" lists them.
#  - triage takes one read more (`ij`), listed first, to name the open file.
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
          "names": [
            "gets"
          ]
        },
        {
          "category": "memory",
          "severity": "high",
          "why": "copies or formats until a terminator with no destination size; safe only if every caller proves the length",
          "names": [
            "strcpy",
            "strcat",
            "stpcpy",
            "sprintf",
            "vsprintf",
            "wcscpy",
            "wcscat",
            "lstrcpyA",
            "lstrcpyW",
            "lstrcatA",
            "lstrcatW",
            "wsprintfA",
            "wsprintfW"
          ]
        },
        {
          "category": "memory",
          "severity": "medium",
          "why": "reads into a buffer; a %s or %[ without a width has no bound",
          "names": [
            "scanf",
            "sscanf",
            "fscanf",
            "vscanf",
            "vsscanf",
            "vfscanf"
          ]
        },
        {
          "category": "memory",
          "severity": "medium",
          "why": "the size comes from the caller and is often attacker-influenced",
          "names": [
            "alloca",
            "realpath",
            "getwd"
          ]
        },
        {
          "category": "memory",
          "severity": "low",
          "why": "bounded, but the bound is the caller's to get right (and strncpy leaves no terminator when it fills)",
          "names": [
            "strncpy",
            "strncat",
            "memcpy",
            "memmove",
            "bcopy",
            "wcsncpy",
            "snprintf",
            "vsnprintf"
          ]
        },
        {
          "category": "command",
          "severity": "high",
          "why": "hands a string to a shell; anything in it that came from outside is a command",
          "names": [
            "system",
            "popen",
            "wordexp",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW"
          ]
        },
        {
          "category": "command",
          "severity": "medium",
          "why": "starts another program; what it runs and with which arguments is worth tracing",
          "names": [
            "execl",
            "execlp",
            "execle",
            "execv",
            "execvp",
            "execve",
            "execvpe",
            "posix_spawn",
            "posix_spawnp",
            "CreateProcessA",
            "CreateProcessW"
          ]
        },
        {
          "category": "format",
          "severity": "low",
          "why": "a format string that is not a literal lets its author read and write memory",
          "names": [
            "printf",
            "fprintf",
            "dprintf",
            "vprintf",
            "vfprintf",
            "syslog",
            "vsyslog",
            "err",
            "errx",
            "warn",
            "warnx"
          ]
        },
        {
          "category": "race",
          "severity": "high",
          "why": "chooses a file name before the file exists; another process can take it first",
          "names": [
            "mktemp",
            "tmpnam",
            "tempnam"
          ]
        },
        {
          "category": "race",
          "severity": "low",
          "why": "checks a path, then uses it; the file can change between the two",
          "names": [
            "access",
            "stat",
            "lstat"
          ]
        },
        {
          "category": "integer",
          "severity": "low",
          "why": "reports no error and no overflow; a caller cannot tell a bad number from zero",
          "names": [
            "atoi",
            "atol",
            "atoll",
            "atof"
          ]
        },
        {
          "category": "randomness",
          "severity": "medium",
          "why": "predictable; unfit for keys, tokens or anything an adversary should not guess",
          "names": [
            "rand",
            "srand",
            "random",
            "srandom",
            "drand48",
            "lrand48"
          ]
        },
        {
          "category": "privilege",
          "severity": "info",
          "why": "changes the process's identity or root; the order and the error checks matter",
          "names": [
            "setuid",
            "setgid",
            "seteuid",
            "setegid",
            "setreuid",
            "setregid",
            "chroot"
          ]
        },
        {
          "category": "loading",
          "severity": "medium",
          "why": "loads code chosen at run time; from where is worth tracing",
          "names": [
            "dlopen",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW"
          ]
        }
      ],
      "capabilities": [
        {
          "capability": "network",
          "names": [
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "sendto",
            "recv",
            "recvfrom",
            "getaddrinfo",
            "gethostbyname",
            "WSAStartup",
            "InternetOpenA",
            "InternetOpenW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "curl_easy_perform",
            "SSL_connect"
          ]
        },
        {
          "capability": "process control",
          "names": [
            "fork",
            "vfork",
            "clone",
            "kill",
            "ptrace",
            "prctl",
            "OpenProcess",
            "TerminateProcess",
            "CreateRemoteThread",
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32Next"
          ]
        },
        {
          "capability": "code injection",
          "names": [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "QueueUserAPC",
            "SetThreadContext",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "process_vm_writev"
          ]
        },
        {
          "capability": "memory protection",
          "names": [
            "mprotect",
            "mmap",
            "memfd_create",
            "VirtualProtect",
            "VirtualProtectEx",
            "VirtualAlloc"
          ]
        },
        {
          "capability": "anti-analysis",
          "names": [
            "ptrace",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "NtSetInformationThread",
            "GetTickCount",
            "QueryPerformanceCounter"
          ]
        },
        {
          "capability": "persistence",
          "names": [
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "CreateServiceA",
            "CreateServiceW",
            "StartServiceA",
            "StartServiceW",
            "SetFileAttributesA",
            "SetFileAttributesW"
          ]
        },
        {
          "capability": "cryptography",
          "names": [
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptGenKey",
            "CryptHashData",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "BCryptGenRandom",
            "EVP_EncryptInit_ex",
            "EVP_DecryptInit_ex",
            "EVP_DigestInit_ex",
            "AES_set_encrypt_key",
            "AES_encrypt",
            "MD5_Init",
            "SHA1_Init",
            "SHA256_Init",
            "RC4",
            "DES_ecb_encrypt",
            "getrandom",
            "RAND_bytes"
          ]
        },
        {
          "capability": "filesystem",
          "names": [
            "unlink",
            "remove",
            "rename",
            "chmod",
            "chown",
            "opendir",
            "readdir",
            "ftw",
            "nftw",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileA",
            "MoveFileW",
            "FindFirstFileA",
            "FindFirstFileW",
            "CopyFileA",
            "CopyFileW"
          ]
        },
        {
          "capability": "dynamic resolution",
          "names": [
            "dlsym",
            "GetProcAddress",
            "LdrGetProcedureAddress"
          ]
        }
      ],
      "severityOrder": [
        "high",
        "medium",
        "low",
        "info"
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
        {
          "algorithm": "AES",
          "what": "S-box",
          "hex": "637c777bf26b6fc53001672bfed7ab76"
        },
        {
          "algorithm": "AES",
          "what": "inverse S-box",
          "hex": "52096ad53036a538bf40a39e81f3d7fb"
        },
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
        {
          "algorithm": "SHA-1",
          "what": "round constant K1 (little-endian)",
          "hex": "9979825a"
        },
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
        {
          "algorithm": "TEA / XTEA",
          "what": "delta (little-endian)",
          "hex": "b979379e"
        },
        {
          "algorithm": "TEA / XTEA",
          "what": "delta (big-endian)",
          "hex": "9e3779b9"
        },
        {
          "algorithm": "DES",
          "what": "initial permutation table",
          "hex": "3a322a221a120a023c342c241c140c04"
        },
        {
          "algorithm": "RC6 / RC5",
          "what": "P32 and Q32 (little-endian)",
          "hex": "6351e1b7b979379e"
        },
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
      ]
    }
# </generated:tables>

    RISKY = TABLES["riskyImports"]
    CAPABILITIES = TABLES["capabilities"]
    SEVERITY_ORDER = TABLES["severityOrder"]
    # The JSON's patterns are written once for every host and matched without regard to case on
    # each. JavaScript's /i without /u folds case for ASCII letters only when the pattern is
    # ASCII, and its \b and \d are ASCII; re.ASCII is what makes Python read them the same way.
    FLAGS = re.IGNORECASE | re.ASCII
    STRING_INTEREST = [(row["kind"], re.compile(row["pattern"], FLAGS)) for row in TABLES["stringInterest"]]
    PACKER_SECTION_NAMES = re.compile(TABLES["packerSectionNames"], FLAGS)
    COMPARING_CALLS = re.compile(TABLES["comparingCalls"], FLAGS)
    CRYPTO_CONSTANTS = TABLES["cryptoConstants"]
    # A constant this many hex digits or fewer is four bytes: common enough by chance that a hit means little on its own.
    SHORT_CONSTANT = 8

    # --- rizin's JSON, with its numbers as rizin wrote them ---------------------------------

    # What JavaScript calls white space, for the places recipes.js trims or splits: Python's own
    # idea of it differs at the edges (U+FEFF, U+001C..U+001F).
    JS_SPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

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

    def get(thing, key):
        """A member with null read as absent; absent as soon as `thing` is not an object."""
        return thing.get(key) if isinstance(thing, dict) else None

    def string(thing, key):
        value = get(thing, key)
        return value if isinstance(value, str) else None

    def num(thing, key):
        value = get(thing, key)
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None

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

    # --- text ---------------------------------------------------------------------------------

    def pad_right(text, width):
        return text + " " * max(0, width - len(text))

    def pad_left(text, width):
        return " " * max(0, width - len(text)) + text

    def one_line(text):
        """A string as one line of at most a hundred characters."""
        return text.replace("\n", " ")[:100]

    def plural(n, one="", many="s"):
        return one if n == 1 else many

    def words(text):
        return [word for word in re.split("[ \t\n\r]+", text) if word != ""]

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
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return fallback
        if isinstance(value, float):
            if not math.isfinite(value) or value != math.floor(value):
                return fallback
            value = int(value)
        return max(least, min(most, value))

    def cite(evidence_id):
        """How a line names the read it rests on; nothing when the read left no record."""
        return "[evidence %s]" % evidence_id if evidence_id else ""

    def more_line(shown, total, what):
        """The line that says a list was cut, so a short list is never read as a whole one."""
        return ["  … %d more %s not shown" % (total - shown, what)] if total > shown else []

    class Report(str):
        """A recipe's report: its text, shown as written when it is a cell's value, and awaitable for a cell that awaits it."""

        __slots__ = ()

        def __repr__(self):
            return str(self)

        def __await__(self):
            return str(self)
            yield  # what makes this a generator, which is what `await` asks of __await__

    # --- one observation ----------------------------------------------------------------------

    # The id is read off the last line only: the body is the binary's own text and may hold anything.
    EVIDENCE_TAG = re.compile(r"\n\[evidence ([0-9a-f]{8})\b[^\n]*\]\Z", re.ASCII)

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
        and the evidence tag; past the size cap the output in the text is cut — for a `*j` command,
        whose JSON is one line, cut to nothing — and the engine keeps all of it as a session
        artifact, which eval's own read() returns raw. A recipe that parsed cut JSON would report a
        binary with no functions, so when the whole output cannot be had it stops and says so.
        """
        if details.get("truncated") is not True:
            return after_header(EVIDENCE_TAG.sub("", text, count=1))

        def lost(why):
            return RuntimeError(
                "omp-re: %s: the output of rizin_command %s was cut at the size cap and the whole of it could not be read back (%s). "
                "The recipe needs all of it and will not report from cut JSON — run the reads by hand with narrower commands." % (run["name"], json_string(label), why)
            )

        artifact = details.get("artifactId")
        if not isinstance(artifact, str):
            raise lost("the engine saved no artifact for it")
        try:
            # `read` is omp's helper, a global of the cell namespace; for a bare artifact:// id it returns the file raw and whole.
            full = settled(read("artifact://" + artifact))  # noqa: F821
        except Exception as error:
            raise lost("artifact://%s: %s" % (artifact, error)) from None
        if not isinstance(full, str):
            raise lost("artifact://%s did not read as text" % artifact)
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
        tag = EVIDENCE_TAG.search(text)
        evidence_id = tag.group(1) if tag else None
        if evidence_id:
            run["evidence"].append((label, evidence_id))
        # Only a call that printed something carries the command it ran; "(no output)" is the engine's words, not rizin's.
        raw = whole_output(run, label, text, details) if isinstance(details.get("commands"), list) else ""
        return raw, evidence_id

    def observe_json(run, command, addr=None):
        """observe() for a `*j` command: its data, absent when the output was empty or not JSON."""
        raw, evidence_id = observe(run, command, addr)
        return parse_json(raw.strip(JS_SPACE)), evidence_id

    def recipe_text(run, title, sections):
        """`title` over `sections` — lists of lines — and the reads the recipe took, so every line can be traced and cited."""
        lines = [title]
        for section in sections:
            lines.append("")
            lines.extend(section)
        lines.append("")
        lines.append("Evidence taken (cite these in record_finding; each is a rizin_command read you can re-run):")
        lines.extend("  %s  %s" % (evidence_id, label) for label, evidence_id in run["evidence"])
        return Report("\n".join(lines))

    def start(name):
        """What one call of a recipe keeps: the reads it took, and the function list once a caller had to be named."""
        return {"name": name, "evidence": [], "functions": None}

    def function_name(recipe, addr):
        """The address or name a function was asked for by. The engine judges what may follow `@` on every read, so that rule is not kept twice."""
        if not isinstance(addr, str):
            raise TypeError("omp-re: %s: a function is named by a string, not %s" % (recipe, encode(addr)))
        return addr

    # --- what an import is called -------------------------------------------------------------

    def bare_import_name(given):
        """An import's name as the tables spell it: decorations a linker or a fortified libc adds are taken off, so __strcpy_chk, _strcpy and __isoc99_scanf read as strcpy, strcpy and scanf."""
        name = given or ""
        at = name.find("imp.")
        if at != -1:
            name = name[at + 4 :]
        if name.startswith("__isoc99_"):
            name = name[9:]
        name = name.lstrip("_")
        if name.endswith("_chk"):
            name = name[:-4]
        return name

    def risky_import(bare):
        for row in RISKY:
            if bare in row["names"]:
                return row
        return None

    def import_capabilities(bare):
        return [row["capability"] for row in CAPABILITIES if bare in row["names"]]

    def function_containing(run, address):
        """`address` as "function+0xoffset" when it lies in a function rizin found, else as the bare address. The function list is one more read, taken the first time a name is wanted."""
        if run["functions"] is None:
            run["functions"] = []
            for fn in rows(observe_json(run, "aflj")[0]):
                low = first(num(fn, "offset"), num(fn, "addr"))
                high = first(num(fn, "maxbound"), None if low is None else low + first(num(fn, "size"), 0))
                if low is not None and high is not None:
                    run["functions"].append((low, high, first(string(fn, "name"), "?")))
        for low, high, name in run["functions"]:
            if low <= address < high:
                return name if address == low else "%s+%s" % (name, hexa(address - low))
        return hexa(address)

    def callers_of(run, address):
        """Where `address` is referenced from, each as "function+0xoffset", with the evidence id of the read."""
        data, evidence_id = observe_json(run, "axtj", hexa(address))
        places = []
        for row in rows(data):
            origin = num(row, "from")
            if origin is not None:
                places.append(function_containing(run, origin))
        return unique_first(places), evidence_id

    # --- triage ---------------------------------------------------------------------------------

    def mitigation_lines(info):
        """The build's protections, read from rizin's own fields rather than scraped from text, each with what its absence would mean."""

        def yes(key):
            return get(info, key) is True

        relro = first(string(info, "relro"), "none")
        relro_means = "" if relro == "full" else " — the GOT stays writable" if relro == "partial" else " — the GOT and other relocated data stay writable"
        return [
            "  stack canary: " + ("yes" if yes("canary") else "NO — a stack overflow reaches the return address unchecked"),
            "  NX: " + ("yes" if yes("nx") else "NO — data pages are executable"),
            "  PIE: " + ("yes" if yes("pie") else "NO — the image loads at a fixed address"),
            "  RELRO: " + relro + relro_means,
            "  fortified libc calls: " + ("yes" if yes("fortify_source") else "no"),
            "  stripped: %s   static: %s" % ("yes" if yes("stripped") else "no", "yes" if yes("static") else "no"),
        ]

    NUMERIC = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\Z", re.ASCII)

    def section_entropy(section):
        value = get(section, "entropy")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
        # rizin writes it as a string of digits.
        if isinstance(value, str) and NUMERIC.match(value.strip(JS_SPACE)):
            return float(value.strip(JS_SPACE))
        return None

    def section_notes(section):
        """What stands out about a section: writable and executable at once, or data that looks compressed or encrypted where code should be."""
        perm = first(string(section, "perm"), "")
        entropy = section_entropy(section)
        notes = []
        if "w" in perm and "x" in perm:
            notes.append("writable+executable")
        if entropy is not None and entropy >= 7.2:
            notes.append("very high entropy (compressed or encrypted data)")
        if entropy is not None and 6.8 <= entropy < 7.2 and "x" in perm:
            notes.append("high entropy for code")
        if PACKER_SECTION_NAMES.search(first(string(section, "name"), "").lower()):
            notes.append("a name packers use")
        return notes

    def code_size(fn):
        return first(num(fn, "realsz"), num(fn, "size"), 0)

    def triage(*, max_strings=None, max_functions=None):
        """
        A first look at the open binary, composed from rizin's own reads: what it is, which
        protections the build has, its sections with entropy, the imports that give it reach, the
        strings worth a first look, its largest functions and its entry points. Nothing here is a
        finding until one is recorded citing the ids.

        max_strings (default 25, 1..200) and max_functions (default 15, 1..100) bound the two lists.
        """
        run = start("triage")
        most_strings = bounded(max_strings, 25, 1, 200)
        most_functions = bounded(max_functions, 15, 1, 100)
        # Which file is open is the engine's to know and nothing tells eval; rizin does.
        path = first(string(get(observe_json(run, "ij")[0], "core"), "file"), "?")
        info, info_id = observe_json(run, "iIj")
        section_data, sections_id = observe_json(run, "iSj entropy")
        import_data, imports_id = observe_json(run, "iij")
        string_data, strings_id = observe_json(run, "izj")
        function_data, functions_id = observe_json(run, "aflj")
        entry_data, entries_id = observe_json(run, "iej")

        sections = [section for section in rows(section_data) if first(string(section, "name"), "").strip(JS_SPACE) != ""]
        flagged = [section for section in sections if section_notes(section)]
        imports = rows(import_data)
        bare = [bare_import_name(string(entry, "name")) for entry in imports]
        risky = unique_last([name for name in bare if risky_import(name)])
        capabilities = unique_first([capability for name in bare for capability in import_capabilities(name)])
        strings = rows(string_data)
        notable = [(kind, entry) for kind, pattern in STRING_INTEREST for entry in strings if pattern.search(first(string(entry, "string"), ""))]
        # Largest first; functions of one size stay in rizin's order.
        functions = sorted(rows(function_data), key=code_size, reverse=True)

        language = string(info, "lang")
        interpreter = string(info, "intrp")
        bits = num(info, "bits")

        def section_line(section):
            entropy = section_entropy(section)
            notes = section_notes(section)
            return (
                "  %s %s %s bytes" % (pad_right(string(section, "name"), 18), pad_right(first(string(section, "perm"), ""), 4), pad_left(number_text(first(num(section, "size"), 0)), 9))
                + "  entropy "
                + ("   ?" if entropy is None else pad_left(fixed2(entropy), 4))
                + ("  <- " + "; ".join(notes) if notes else "")
            )

        def function_line(fn):
            blocks = num(fn, "nbbs")
            return "  %s  %s bytes  %s%s" % (
                hexa(first(num(fn, "offset"), num(fn, "addr"), 0)),
                pad_left(number_text(code_size(fn)), 7),
                "" if blocks is None else number_text(blocks) + " blocks  ",
                first(string(fn, "name"), "?"),
            )

        identity = "  %s, %s %s-bit %s, %s" % (
            first(string(info, "class"), string(info, "bintype"), "unknown format"),
            first(string(info, "arch"), "?"),
            "?" if bits is None else number_text(bits),
            first(string(info, "endian"), ""),
            first(string(info, "os"), "?"),
        )
        stand_out = "  %d section%s stand%s out; high entropy in code, or a section both writable and executable, is what a packed or self-modifying binary looks like — read it before trusting the function list." % (
            len(flagged),
            plural(len(flagged)),
            plural(len(flagged), "s", ""),
        )
        entry_lines = ["  %s  %s" % (hexa(num(entry, "vaddr")), first(string(entry, "type"), "")) for entry in rows(entry_data) if num(entry, "vaddr") is not None]
        return recipe_text(
            run,
            "triage: " + path,
            [
                [
                    "Identity " + cite(info_id),
                    identity + ("" if language is None else ", language " + language) + ("" if interpreter is None else ", interpreter " + interpreter),
                ],
                ["Build protections " + cite(info_id)] + mitigation_lines(info),
                ["Sections: %d %s" % (len(sections), cite(sections_id))]
                + [section_line(section) for section in sections]
                + ([stand_out] if flagged else []),
                ["Imports: %d %s" % (len(imports), cite(imports_id))]
                + ["  reach, by what it links: " + ", ".join(capabilities) if capabilities else "  none of the capability groups (network, process control, injection, …) is linked"]
                + (["  worth a reviewer's look: %s — scan_imports says why and who calls them" % ", ".join(risky[:20])] if risky else [])
                + (["  very few imports for a dynamic binary: resolved at run time, or packed"] if len(imports) < 8 and get(info, "static") is not True else []),
                ["Strings: %d; notable %d %s" % (len(strings), len(notable), cite(strings_id))]
                + [
                    "  %s %s  %s" % (pad_right(kind, 11), "?" if num(entry, "vaddr") is None else hexa(num(entry, "vaddr")), one_line(first(string(entry, "string"), "")))
                    for kind, entry in notable[:most_strings]
                ]
                + more_line(min(most_strings, len(notable)), len(notable), "notable strings"),
                ["Functions: %d; largest by code size %s" % (len(functions), cite(functions_id))]
                + [function_line(fn) for fn in functions[:most_functions]]
                + more_line(min(most_functions, len(functions)), len(functions), "functions"),
                ["Entry points " + cite(entries_id)] + (entry_lines or ["  none reported"]),
            ],
        )

    # --- scan_imports ---------------------------------------------------------------------------

    def scan_imports(*, callers=None, max_callers=None):
        """
        The imports a reviewer would stop at, each with why it matters and who calls it; plus what
        the program can reach, read off what it links. An import is a lead, not a bug: whether a
        call is safe is decided at its call site, which is what the callers are listed for.

        callers (default True): list who calls each; max_callers (default 12, 1..100) bounds each list.
        """
        run = start("scan_imports")
        with_callers = callers is not False
        most_callers = bounded(max_callers, 12, 1, 100)
        data, imports_id = observe_json(run, "iij")
        imports = rows(data)

        def severity_rank(severity):
            return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 9

        named = [(entry, bare_import_name(string(entry, "name"))) for entry in imports]
        risky = [(entry, bare, risky_import(bare)) for entry, bare in named if risky_import(bare)]
        risky.sort(key=lambda item: severity_rank(item[2]["severity"]))
        reach = []
        for row in CAPABILITIES:
            names = unique_last([bare for _, bare in named if row["capability"] in import_capabilities(bare)])
            if names:
                reach.append((row["capability"], names))

        risky_lines = []
        for entry, bare, verdict in risky:
            address = num(entry, "plt")
            # An import rizin gives no name is its own bare name: nothing to say it was linked as.
            linked = string(entry, "name")
            if linked is None:
                linked = bare
            risky_lines.append(
                "  [%s] %s%s (%s)%s — %s" % (verdict["severity"], bare, "" if bare == linked else " (linked as %s)" % linked, verdict["category"], "" if address is None else " @ " + hexa(address), verdict["why"])
            )
            if not with_callers or address is None:
                continue
            places, evidence_id = callers_of(run, address)
            risky_lines.append(
                "      called from %d place%s %s: %s" % (len(places), plural(len(places)), cite(evidence_id), ", ".join(places[:most_callers]))
                if places
                else "      no caller found by analysis " + cite(evidence_id)
            )
            risky_lines.extend(more_line(min(most_callers, len(places)), len(places), "callers"))
        return recipe_text(
            run,
            "scan_imports: %d imports, %d worth a look" % (len(imports), len(risky)),
            [
                ["Reach, by what it links " + cite(imports_id)] + (["  %s %s" % (pad_right(capability, 18), ", ".join(names)) for capability, names in reach] or ["  none of the capability groups is linked"]),
                ["Imports worth a reviewer's look " + cite(imports_id)] + (risky_lines or ["  none of the imports in the table is linked"]),
                ["An import is a lead. Read each call site (rizin_command pdg or pdf at the caller) before saying what it does."],
            ],
        )

    # --- inspect_function -----------------------------------------------------------------------

    def function_ops(body):
        """The instruction objects of a pdfj reply."""
        return rows(get(body, "ops"))

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

    CALL_PREFIX = re.compile("^call[" + JS_SPACE + "]+")

    def inspect_function(addr=None, *, max_items=None):
        """
        One function, read from every side at once: its size, complexity and signature, its
        variables, who calls it and what it calls, and the strings it refers to — the context to
        read before its code. Follow it with rizin_command pdg at the same address for the code.

        addr: the function's name or address, a string; max_items (default 30, 1..300) bounds each list.
        """
        run = start("inspect_function")
        at = function_name("inspect_function", addr)
        limit = bounded(max_items, 30, 1, 300)
        info_data, info_id = observe_json(run, "afij", at)
        info = rows(info_data)[0] if rows(info_data) else None
        if info is None or info is False or info == 0 or info == "":
            raise RuntimeError('omp-re: inspect_function: no function at %s — list them with await tool.rizin_command({"command": "aflj"}), or define one with define_function' % at)
        body, body_id = observe_json(run, "pdfj", at)
        variables, variables_id = observe_json(run, "afvlj", at)
        string_data, strings_id = observe_json(run, "izj")
        entry = first(num(info, "offset"), num(info, "addr"), 0)
        callers, callers_id = callers_of(run, entry)

        ops = function_ops(body)
        string_at = strings_by_address(string_data)
        referenced = unique_last([(target, string_at[target]) for op in ops for target in op_targets(op) if string_at.get(target) is not None], key=lambda reference: reference[0])
        calls = unique_first([CALL_PREFIX.sub("", first(string(op, "disasm"), ""), count=1) for op in ops if string(op, "type") in ("call", "ucall", "rcall", "icall", "ccall")])
        compares = sum(1 for op in ops if string(op, "type") in ("cmp", "acmp"))
        branches = sum(1 for op in ops if string(op, "type") == "cjmp")
        variable_count = sum(len(kind) for kind in variables.values() if isinstance(kind, list)) if isinstance(variables, dict) else 0
        loops = first(num(info, "loops"), 0)

        def count(key):
            return number_text(first(num(info, key), 0))

        size_line = "  %s bytes of code, %s basic blocks, %s edges, cyclomatic complexity %s, %s loop%s" % (
            number_text(first(num(info, "realsz"), num(info, "size"), 0)),
            count("nbbs"),
            count("edges"),
            count("cc"),
            number_text(loops),
            plural(loops),
        )
        return recipe_text(
            run,
            "inspect_function: " + first(string(info, "name"), at),
            [
                [
                    "Shape " + cite(info_id),
                    "  %s at %s" % (first(string(info, "signature"), string(info, "name"), at), hexa(entry)),
                    size_line,
                    "  calling convention %s, stack frame %s bytes%s" % (first(string(info, "calltype"), "?"), count("stackframe"), ", does not return" if get(info, "noreturn") is True else ""),
                ],
                [
                    "Body " + cite(body_id),
                    "  %d instructions, %d compare%s, %d conditional branch%s — find_comparisons lists them" % (len(ops), compares, plural(compares), branches, plural(branches, "", "es")),
                ],
                ["Variables: %d %s" % (variable_count, cite(variables_id))],
                ["Called from %d place%s %s" % (len(callers), plural(len(callers)), cite(callers_id))] + ["  " + caller for caller in callers[:limit]] + more_line(min(limit, len(callers)), len(callers), "callers"),
                ["Calls %d distinct target%s %s" % (len(calls), plural(len(calls)), cite(body_id))] + ["  " + call for call in calls[:limit]] + more_line(min(limit, len(calls)), len(calls), "callees"),
                ["Refers to %d string%s %s %s" % (len(referenced), plural(len(referenced)), cite(body_id), cite(strings_id))]
                + ["  %s  %s" % (hexa(address), one_line(text)) for address, text in referenced[:limit]]
                + more_line(min(limit, len(referenced)), len(referenced), "strings"),
            ],
        )

    # --- find_comparisons -----------------------------------------------------------------------

    BRANCH_MEANINGS = [
        (("je", "jz"), "taken when equal / zero"),
        (("jne", "jnz"), "taken when not equal / not zero"),
        (("ja", "jnbe"), "taken when above (unsigned >)"),
        (("jae", "jnb", "jnc"), "taken when above or equal (unsigned >=)"),
        (("jb", "jc", "jnae"), "taken when below (unsigned <)"),
        (("jbe", "jna"), "taken when below or equal (unsigned <=)"),
        (("jg", "jnle"), "taken when greater (signed >)"),
        (("jge", "jnl"), "taken when greater or equal (signed >=)"),
        (("jl", "jnge"), "taken when less (signed <)"),
        (("jle", "jng"), "taken when less or equal (signed <=)"),
        (("js",), "taken when negative"),
        (("jns",), "taken when not negative"),
    ]

    def branch_meaning(mnemonic):
        """What a conditional jump tests, in words."""
        for names, meaning in BRANCH_MEANINGS:
            if (mnemonic or "").lower() in names:
                return meaning
        return "conditional"

    def printable_note(op):
        """When an instruction compares against a constant that is a printable character, say which: a run of these is a string compared a byte at a time."""
        value = first(num(op, "val"), num(op, "ptr"))
        if not isinstance(value, int) or value < 32 or value > 126:
            return ""
        return ' ; "%s"' % re.sub(r'(["\\])', r"\\\1", chr(value))

    def find_comparisons(addr=None, *, max_items=None):
        """
        What a function decides on: every compare or test with the conditional branch that follows
        it (which way it goes, and where to), every call to something that compares or validates,
        and the strings on the way — the static skeleton of validation logic, with no emulation and
        nothing run. It lists what is compared, not what the comparison means.

        addr: the function's name or address, a string; max_items (default 80, 1..1000) bounds each list.
        """
        run = start("find_comparisons")
        at = function_name("find_comparisons", addr)
        limit = bounded(max_items, 80, 1, 1000)
        body, body_id = observe_json(run, "pdfj", at)
        ops = function_ops(body)
        if not ops:
            raise RuntimeError('omp-re: find_comparisons: no function at %s — list them with await tool.rizin_command({"command": "aflj"})' % at)
        string_data, strings_id = observe_json(run, "izj")
        string_at = strings_by_address(string_data)

        def where(op):
            return hexa(first(num(op, "offset"), 0))

        decisions = []
        for index, op in enumerate(ops):
            if string(op, "type") not in ("cmp", "acmp"):
                continue
            following = ops[index + 1] if index + 1 < len(ops) else None
            branch = ""
            if string(following, "type") == "cjmp":
                disasm = first(string(following, "disasm"), "")
                taken = num(following, "jump")
                otherwise = num(following, "fail")
                branch = "  ->  %s: %s%s%s" % (disasm, branch_meaning((words(disasm) or [None])[0]), "" if taken is None else ", to " + hexa(taken), "" if otherwise is None else ", else " + hexa(otherwise))
            decisions.append("  %s  %s%s%s" % (where(op), first(string(op, "disasm"), ""), printable_note(op), branch))
        deciding_calls = [
            "  %s  %s" % (where(op), first(string(op, "disasm"), "")) for op in ops if string(op, "type") in ("call", "ucall", "rcall", "icall") and COMPARING_CALLS.search(first(string(op, "disasm"), ""))
        ]
        referenced = unique_last(["  %s  refers to %s  %s" % (where(op), hexa(target), one_line(string_at[target])) for op in ops for target in op_targets(op) if string_at.get(target) is not None])

        return recipe_text(
            run,
            "find_comparisons: " + first(string(body, "name"), at),
            [
                ["Compares and the branches that follow: %d %s" % (len(decisions), cite(body_id))] + decisions[:limit] + more_line(min(limit, len(decisions)), len(decisions), "comparisons"),
                ["Calls that compare or validate: %d %s" % (len(deciding_calls), cite(body_id))] + (deciding_calls[:limit] or ["  none by name"]),
                ["Strings on the way: %d %s %s" % (len(referenced), cite(body_id), cite(strings_id))] + (referenced[:limit] or ["  none"]),
                ["This lists what is compared, not what the comparison means: which branch is the accepting one is for you to read from the code each leads to."],
            ],
        )

    # --- find_crypto ----------------------------------------------------------------------------

    def find_crypto(*, references=None):
        """
        Where cryptographic material lies in the open binary: rizin's own search for keys and
        certificates, and a search for the published constants of common algorithms, each hit with
        its address and what refers to it. A constant's presence says the tables are linked in, not
        that they are used, nor on what; a four-byte constant can occur by chance and is marked weak.

        references (default True): say what refers to each hit.
        """
        run = start("find_crypto")
        with_references = references is not False
        material, material_id = observe_json(run, "/cmj")
        hits = []
        for constant in CRYPTO_CONSTANTS:
            # Each search is a read on the record whether or not it finds anything; only a hit is reported below.
            data, evidence_id = observe_json(run, "/xj " + constant["hex"])
            for row in rows(data):
                address = first(num(row, "address"), num(row, "offset"), num(row, "addr"))
                if address is not None:
                    hits.append((constant["algorithm"], constant["what"], address, evidence_id, len(constant["hex"]) <= SHORT_CONSTANT))
        constant_lines = []
        for algorithm, what, address, evidence_id, weak in hits[:60]:
            constant_lines.append("  %s  %s — %s %s%s" % (hexa(address), algorithm, what, cite(evidence_id), " (weak: four bytes can occur by chance)" if weak else ""))
            if not with_references:
                continue
            places, places_id = callers_of(run, address)
            constant_lines.append(
                "      referred to from %s %s" % (", ".join(places[:8]), cite(places_id)) if places else "      no reference found by analysis %s — reached by computed address, or unused" % cite(places_id)
            )
        material_lines = ["  " + encode(row) for row in rows(material)[:40]]
        return recipe_text(
            run,
            "find_crypto: %d constant hit%s" % (len(hits), plural(len(hits))),
            [
                ["rizin's search for keys and certificates " + cite(material_id)] + (material_lines or ["  nothing found"]),
                ["Published constants"] + (constant_lines or ["  none of the constants in the table was found"]),
                ["A table's presence shows the algorithm is linked in. What it is used on, and with which key, is in the code that refers to it."],
            ],
        )

    # --- what is handed to eval -----------------------------------------------------------------

    HELP = "\n".join(
        [
            "omp-re recipes — wide reads composed over rizin_command. Not tools: each read a recipe makes is its own",
            "rizin_command call (approved, audited, recorded as evidence). Each returns its report as a string; print() it.",
            'Open a binary first (await tool.open_binary({"path": ...})). The recipes themselves need no await.',
            "",
            "  omp_re.triage(max_strings=25, max_functions=15)",
            "      what the binary is, build protections, sections with entropy, imports and what they reach,",
            "      notable strings, the largest functions, entry points.",
            "  omp_re.scan_imports(callers=True, max_callers=12)",
            "      the imports a reviewer stops at, why, and who calls each; what the program can reach.",
            '  omp_re.inspect_function("main", max_items=30)',
            "      one function's shape, variables, callers, callees and the strings it refers to.",
            '  omp_re.find_comparisons("main", max_items=80)',
            "      every compare with the branch that follows, calls that compare or validate, strings on the way.",
            "  omp_re.find_crypto(references=True)",
            "      rizin's key and certificate search, and where published constants of common algorithms lie.",
            "",
            "Every section cites the [evidence xxxxxxxx] id of the read it rests on, and each report ends with the",
            "reads it took. A line of a report is a lead, not a finding: record_finding with those ids makes it one.",
        ]
    )

    class Recipes:
        """omp-re's recipes for omp's Python kernel; help() says what each answers."""

        __slots__ = ()

        def __repr__(self):
            return "<omp-re recipes: triage, scan_imports, inspect_function, find_comparisons, find_crypto — print(omp_re.help()) says what each answers>"

    def help():  # noqa: A001 - the name the JavaScript twin gives it; it shadows nothing outside this function
        """What each recipe answers, and how each is called."""
        return Report(HELP)

    for recipe in (triage, scan_imports, inspect_function, find_comparisons, find_crypto, help):
        # So that Python's own complaint about a call names what was called: "omp_re.triage() got an unexpected keyword argument …".
        recipe.__qualname__ = "omp_re." + recipe.__name__
        setattr(Recipes, recipe.__name__, staticmethod(recipe))
    return Recipes()


try:
    omp_re = _omp_re_recipes()
finally:
    del _omp_re_recipes

# A %load cell shows what the script printed, and the source is not echoed: say what now exists.
print("omp-re recipes loaded: omp_re.triage, omp_re.scan_imports, omp_re.inspect_function, omp_re.find_comparisons, omp_re.find_crypto — print(omp_re.help()) says what each answers.")
