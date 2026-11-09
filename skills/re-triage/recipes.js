/*
 * recipes.js — wide reads composed over the one read tool, for omp's eval:
 * triage, imports, one function, comparisons, cryptographic constants.
 *
 * SPDX-License-Identifier: MIT
 *
 * Load it once a session, in a standalone JavaScript eval cell:
 *
 *   %load skill://re-triage/recipes.js
 *
 * (or `%load` with this file's path). It defines one global, `re`:
 *
 *   print(await re.triage({ maxStrings, maxFunctions }));
 *   print(await re.scanImports({ callers, maxCallers }));
 *   print(await re.inspectFunction("main", { maxItems }));
 *   print(await re.findComparisons("main", { maxItems }));
 *   print(await re.findCrypto({ references }));
 *   print(re.help());
 *
 * Each answers its report as a string and prints nothing.
 *
 * These are not tools, and nothing here is registered with omp.
 * rizin_command is the one way to read the binary and eval is where reads
 * are composed; a recipe is that composition, written once: the dozen reads
 * every analysis opens with and a plain reading of them. Every read a recipe
 * makes is `await tool.rizin_command(...)` — a tool call in its own right,
 * approved, audited and recorded as evidence like one typed by hand — so a
 * recipe can do nothing the model could not, and `/re off` stops it at its
 * first read.
 *
 * A recipe is not an oracle and must not read like one. Every section names
 * the evidence id of the read it rests on, so a line here is a pointer to an
 * observation that can be opened, never a conclusion to repeat: a finding
 * still has to cite those ids to pass record_finding. The tables are
 * judgement, worded as "worth a look", never as a verdict.
 *
 * This file has two twins: recipes.py beside it, the same five for omp's
 * Python kernel (as `omp_re`, since `re` there is the regex module), and
 * nodecode/recipes.lisp, the same five as Lisp verbs for the nodecode host.
 * All three must answer the same text for the same binary, line for line,
 * and test/recipes-eval.test.ts holds them to it; so a change to the wording
 * or the order of reads here is a change in the other two. The tables all
 * three read are generated from recipes/tables.json by
 * scripts/gen-recipes.ts, which rewrites the marked block below — edit the
 * JSON and run the script, never the block.
 *
 * Where the two differ, because the hosts do:
 *  - find_crypto. The Lisp probes each constant quietly and records only the
 *    searches that hit. Here every search is a tool call, so a search that
 *    finds nothing is a recorded read too, and "Evidence taken" lists it:
 *    an id to cite for "the SHA-1 constants are not in this binary". The
 *    hits listed under "Published constants" are the same.
 *  - triage. Its title names the open binary, and code in eval has no way
 *    to ask the engine which that is; rizin is asked instead (`ij`), which
 *    is one read more than the Lisp takes, listed first.
 *  - A refusal that says how to list functions names this host's call
 *    (`tool.rizin_command`) where the Lisp names its own (`re:json`).
 */
globalThis.re = (() => {
// <generated:tables> — from recipes/tables.json by scripts/gen-recipes.ts; do not edit
const TABLES = {
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
};
// </generated:tables>

	const RISKY = TABLES.riskyImports;
	const CAPABILITIES = TABLES.capabilities;
	const SEVERITY_ORDER = TABLES.severityOrder;
	// The JSON's patterns are written once for both hosts and matched without regard to case on both.
	const STRING_INTEREST = TABLES.stringInterest.map((row) => ({ kind: row.kind, pattern: new RegExp(row.pattern, "i") }));
	const PACKER_SECTION_NAMES = new RegExp(TABLES.packerSectionNames, "i");
	const COMPARING_CALLS = new RegExp(TABLES.comparingCalls, "i");
	const CRYPTO_CONSTANTS = TABLES.cryptoConstants;
	/** A constant this many hex digits or fewer is four bytes: common enough by chance that a hit means little on its own. */
	const SHORT_CONSTANT = 8;

	// --- rizin's JSON, with its addresses whole ------------------------------------------

	// rizin prints a 64-bit address as a decimal integer, and JSON.parse rounds any past 2^53 — a
	// kernel image's addresses, or the all-ones vaddr of an unmapped section. An address a recipe
	// prints must be the one rizin printed, so an integer too long to be safe is carried through
	// the parse as a marked string and comes out a BigInt. Strings are matched first, so digits
	// inside one are left alone; a real string that begins with the marker's NUL is re-marked.
	const LONG_INTEGER = /"(?:[^"\\]|\\.)*"|(?<![\d.])-?\d{16,}(?![\d.eE])/g;
	const NUL = "\\u0000";

	function parseJson(text) {
		const marked = text.replace(LONG_INTEGER, (token) => {
			if (token[0] !== '"') return `"${NUL}n${token}"`;
			return token.startsWith(`"${NUL}`) ? `"${NUL}s${token.slice(1)}` : token;
		});
		try {
			return JSON.parse(marked, (_key, value) => {
				if (typeof value !== "string" || value[0] !== "\u0000") return value;
				if (value[1] === "s") return value.slice(2);
				if (value[1] !== "n") return value;
				const whole = BigInt(value.slice(2));
				return Number.isSafeInteger(Number(whole)) ? Number(whole) : whole;
			});
		} catch {
			// Not JSON reads as no data, never as an error: an empty reply is how rizin says "nothing here".
			return undefined;
		}
	}

	const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
	/** A member with null read as absent; absent as soon as `object` is not an object. */
	const get = (object, key) => (isObject(object) ? (object[key] ?? undefined) : undefined);
	const str = (object, key) => (typeof get(object, key) === "string" ? get(object, key) : undefined);
	const num = (object, key) => (typeof get(object, key) === "number" || typeof get(object, key) === "bigint" ? get(object, key) : undefined);
	const rows = (data) => (Array.isArray(data) ? data : []);

	// Arithmetic that holds when either side is a BigInt; comparisons already do.
	const wide = (value) => (typeof value === "bigint" ? value : BigInt(Math.trunc(value)));
	const plus = (a, b) => (typeof a === "bigint" || typeof b === "bigint" ? wide(a) + wide(b) : a + b);
	const minus = (a, b) => (typeof a === "bigint" || typeof b === "bigint" ? wide(a) - wide(b) : a - b);
	const hex = (value) => `0x${value.toString(16)}`;

	/** A decoded value as compact JSON, in the order rizin gave it. JSON.stringify refuses a BigInt, which is the one thing this adds. */
	function encode(value) {
		if (typeof value === "bigint") return value.toString();
		if (Array.isArray(value)) return `[${value.map(encode).join(",")}]`;
		if (isObject(value)) {
			return `{${Object.entries(value)
				.map(([key, member]) => `${JSON.stringify(key)}:${encode(member)}`)
				.join(",")}}`;
		}
		return JSON.stringify(value) ?? "null";
	}

	// --- text ------------------------------------------------------------------------------

	// Widths and cuts count characters, as the Lisp twin's do, not UTF-16 units.
	const count = (text) => Array.from(text).length;
	const padRight = (text, width) => text + " ".repeat(Math.max(0, width - count(text)));
	const padLeft = (text, width) => " ".repeat(Math.max(0, width - count(text))) + text;
	const cut = (text, most) => (text.length <= most ? text : Array.from(text).slice(0, most).join(""));
	/** A string as one line of at most a hundred characters. */
	const oneLine = (text) => cut(text.replaceAll("\n", " "), 100);
	const plural = (n, one = "", many = "s") => (n === 1 ? one : many);
	const take = (most, list) => list.slice(0, most);
	const words = (text) => text.split(/[ \t\n\r]+/).filter((word) => word !== "");

	/** Without duplicates, keeping each value where it first stood. */
	function uniqueFirst(list, key = (item) => item) {
		const seen = new Set();
		return list.filter((item) => !seen.has(key(item)) && seen.add(key(item)));
	}
	/** Without duplicates, keeping each value where it last stood. */
	const uniqueLast = (list, key) => uniqueFirst([...list].reverse(), key).reverse();

	/** `value` when it is an integer within least..most, the nearer bound when it is outside, `fallback` when it was not given. */
	const bounded = (value, fallback, least, most) => (Number.isInteger(value) ? Math.max(least, Math.min(most, value)) : fallback);

	/** How a line names the read it rests on; nothing when the read left no record. */
	const cite = (id) => (id ? `[evidence ${id}]` : "");

	/** The line that says a list was cut, so a short list is never read as a whole one. */
	const moreLine = (shown, total, what) => (total > shown ? [`  … ${total - shown} more ${what} not shown`] : []);

	// --- one observation -----------------------------------------------------------------------

	// The id is read off the last line only: the body is the binary's own text and may hold anything.
	const EVIDENCE_TAG = /\n\[evidence ([0-9a-f]{8})\b[^\n]*\]$/;

	/**
	 * The whole of what rizin printed for a call. A result's text is the header line, the output,
	 * and the evidence tag; past the size cap the output in the text is cut — for a `*j` command,
	 * whose JSON is one line, cut to nothing — and the engine keeps all of it as a session
	 * artifact, which eval's own read() returns raw. A recipe that parsed cut JSON would report a
	 * binary with no functions, so when the whole output cannot be had it stops and says so.
	 */
	async function wholeOutput(run, label, text, details) {
		const afterHeader = (full) => (full.includes("\n") ? full.slice(full.indexOf("\n") + 1) : "");
		if (details.truncated !== true) return afterHeader(text.replace(EVIDENCE_TAG, ""));
		const lost = (why) =>
			new Error(
				`omp-re: ${run.name}: the output of rizin_command ${JSON.stringify(label)} was cut at the size cap and the whole of it could not be read back (${why}). The recipe needs all of it and will not report from cut JSON — run the reads by hand with narrower commands.`,
			);
		if (typeof details.artifactId !== "string") throw lost("the engine saved no artifact for it");
		let full;
		try {
			full = await read(`artifact://${details.artifactId}`);
		} catch (error) {
			throw lost(`artifact://${details.artifactId}: ${error instanceof Error ? error.message : String(error)}`);
		}
		if (typeof full !== "string") throw lost(`artifact://${details.artifactId} did not read as text`);
		return afterHeader(full);
	}

	/**
	 * One rizin_command call — the same approval, audit line and evidence record as any other —
	 * answering its whole output and the id of its record. A refused call throws from the tool;
	 * one rizin answered with an error comes back marked, and is thrown here with rizin's words.
	 */
	async function observe(run, command, addr) {
		const label = addr === undefined ? command : `${command} @ ${addr}`;
		const result = await tool.rizin_command(addr === undefined ? { command } : { command, addr });
		const text = typeof result === "string" ? result : String(result?.text ?? "");
		const details = isObject(result) && isObject(result.details) ? result.details : {};
		if (isObject(result) && result.hasError === true) throw new Error(text);
		const id = EVIDENCE_TAG.exec(text)?.[1];
		if (id) run.evidence.push({ label, id });
		// Only a call that printed something carries the command it ran; "(no output)" is the engine's words, not rizin's.
		const raw = Array.isArray(details.commands) ? await wholeOutput(run, label, text, details) : "";
		return { raw, id };
	}

	/** observe() for a `*j` command: its data, absent when the output was empty or not JSON. */
	async function observeJson(run, command, addr) {
		const { raw, id } = await observe(run, command, addr);
		return { data: parseJson(raw.trim()), id };
	}

	/** `title` over `sections` — lists of lines — and the reads the recipe took, so every line can be traced and cited. */
	function recipeText(run, title, sections) {
		return [
			title,
			...sections.flatMap((section) => ["", ...section]),
			"",
			"Evidence taken (cite these in record_finding; each is a rizin_command read you can re-run):",
			...run.evidence.map(({ label, id }) => `  ${id}  ${label}`),
		].join("\n");
	}

	/** What one call of a recipe keeps: the reads it took, and the function list once a caller had to be named. */
	const start = (name) => ({ name, evidence: [], functions: undefined });

	function options(name, given) {
		if (given === undefined || given === null) return {};
		if (!isObject(given)) throw new Error(`omp-re: ${name}: options are one object, e.g. { maxItems: 20 }, not ${JSON.stringify(given) ?? String(given)}`);
		return given;
	}

	/** The address or name a function was asked for by. The engine judges what may follow `@` on every read, so that rule is not kept twice. */
	function functionName(addr) {
		if (typeof addr !== "string") throw new Error(`a function is named by a string, not ${encode(addr) ?? String(addr)}`);
		return addr;
	}

	// --- what an import is called ----------------------------------------------------------------

	/** An import's name as the tables spell it: decorations a linker or a fortified libc adds are taken off, so __strcpy_chk, _strcpy and __isoc99_scanf read as strcpy, strcpy and scanf. */
	function bareImportName(given) {
		let name = given ?? "";
		const at = name.indexOf("imp.");
		if (at !== -1) name = name.slice(at + 4);
		if (name.startsWith("__isoc99_")) name = name.slice(9);
		name = name.replace(/^_+/, "");
		if (name.endsWith("_chk")) name = name.slice(0, -4);
		return name;
	}

	const riskyImport = (bare) => RISKY.find((row) => row.names.includes(bare));
	const importCapabilities = (bare) => CAPABILITIES.filter((row) => row.names.includes(bare)).map((row) => row.capability);

	/** `address` as "function+0xoffset" when it lies in a function rizin found, else as the bare address. The function list is one more read, taken the first time a name is wanted. */
	async function functionContaining(run, address) {
		if (run.functions === undefined) {
			run.functions = [];
			for (const fn of rows((await observeJson(run, "aflj")).data)) {
				const low = num(fn, "offset") ?? num(fn, "addr");
				const high = num(fn, "maxbound") ?? (low === undefined ? undefined : plus(low, num(fn, "size") ?? 0));
				if (low !== undefined && high !== undefined) run.functions.push({ low, high, name: str(fn, "name") ?? "?" });
			}
		}
		const fn = run.functions.find((row) => row.low <= address && address < row.high);
		if (!fn) return hex(address);
		return address == fn.low ? fn.name : `${fn.name}+${hex(minus(address, fn.low))}`;
	}

	/** Where `address` is referenced from, each as "function+0xoffset", with the evidence id of the read. */
	async function callersOf(run, address) {
		const { data, id } = await observeJson(run, "axtj", hex(address));
		const places = [];
		for (const row of rows(data)) {
			const from = num(row, "from");
			if (from !== undefined) places.push(await functionContaining(run, from));
		}
		return { places: uniqueFirst(places), id };
	}

	// --- triage ----------------------------------------------------------------------------------

	/** The build's protections, read from rizin's own fields rather than scraped from text, each with what its absence would mean. */
	function mitigationLines(info) {
		const yes = (key) => get(info, key) === true;
		const relro = str(info, "relro") ?? "none";
		const relroMeans = relro === "full" ? "" : relro === "partial" ? " — the GOT stays writable" : " — the GOT and other relocated data stay writable";
		return [
			`  stack canary: ${yes("canary") ? "yes" : "NO — a stack overflow reaches the return address unchecked"}`,
			`  NX: ${yes("nx") ? "yes" : "NO — data pages are executable"}`,
			`  PIE: ${yes("pie") ? "yes" : "NO — the image loads at a fixed address"}`,
			`  RELRO: ${relro}${relroMeans}`,
			`  fortified libc calls: ${yes("fortify_source") ? "yes" : "no"}`,
			`  stripped: ${yes("stripped") ? "yes" : "no"}   static: ${yes("static") ? "yes" : "no"}`,
		];
	}

	function sectionEntropy(section) {
		const value = get(section, "entropy");
		if (typeof value === "number") return value;
		// rizin writes it as a string of digits.
		return typeof value === "string" && /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(value.trim()) ? Number(value) : undefined;
	}

	/** What stands out about a section: writable and executable at once, or data that looks compressed or encrypted where code should be. */
	function sectionNotes(section) {
		const perm = str(section, "perm") ?? "";
		const entropy = sectionEntropy(section);
		const notes = [];
		if (perm.includes("w") && perm.includes("x")) notes.push("writable+executable");
		if (entropy !== undefined && entropy >= 7.2) notes.push("very high entropy (compressed or encrypted data)");
		if (entropy !== undefined && entropy >= 6.8 && entropy < 7.2 && perm.includes("x")) notes.push("high entropy for code");
		if (PACKER_SECTION_NAMES.test((str(section, "name") ?? "").toLowerCase())) notes.push("a name packers use");
		return notes;
	}

	const codeSize = (fn) => num(fn, "realsz") ?? num(fn, "size") ?? 0;

	/**
	 * A first look at the open binary, composed from rizin's own reads: what it is, which
	 * protections the build has, its sections with entropy, the imports that give it reach, the
	 * strings worth a first look, its largest functions and its entry points. Nothing here is a
	 * finding until one is recorded citing the ids.
	 */
	async function triage(given) {
		const { maxStrings, maxFunctions } = options("triage", given);
		const run = start("triage");
		const mostStrings = bounded(maxStrings, 25, 1, 200);
		const mostFunctions = bounded(maxFunctions, 15, 1, 100);
		// Which file is open is the engine's to know and nothing tells eval; rizin does.
		const path = str(get((await observeJson(run, "ij")).data, "core"), "file") ?? "?";
		const { data: info, id: infoId } = await observeJson(run, "iIj");
		const { data: sectionData, id: sectionsId } = await observeJson(run, "iSj entropy");
		const { data: importData, id: importsId } = await observeJson(run, "iij");
		const { data: stringData, id: stringsId } = await observeJson(run, "izj");
		const { data: functionData, id: functionsId } = await observeJson(run, "aflj");
		const { data: entryData, id: entriesId } = await observeJson(run, "iej");

		const sections = rows(sectionData).filter((section) => (str(section, "name") ?? "").trim() !== "");
		const flagged = sections.filter((section) => sectionNotes(section).length > 0);
		const imports = rows(importData);
		const bare = imports.map((entry) => bareImportName(str(entry, "name")));
		const risky = uniqueLast(bare.filter((name) => riskyImport(name)));
		const capabilities = uniqueFirst(bare.flatMap(importCapabilities));
		const strings = rows(stringData);
		const notable = STRING_INTEREST.flatMap(({ kind, pattern }) => strings.filter((entry) => pattern.test(str(entry, "string") ?? "")).map((entry) => ({ kind, entry })));
		const functions = [...rows(functionData)].sort((a, b) => (codeSize(b) > codeSize(a) ? 1 : codeSize(b) < codeSize(a) ? -1 : 0));

		const language = str(info, "lang");
		const interpreter = str(info, "intrp");
		return recipeText(run, `triage: ${path}`, [
			[
				`Identity ${cite(infoId)}`,
				`  ${str(info, "class") ?? str(info, "bintype") ?? "unknown format"}, ${str(info, "arch") ?? "?"} ${num(info, "bits") ?? "?"}-bit ${str(info, "endian") ?? ""}, ${str(info, "os") ?? "?"}` +
					(language === undefined ? "" : `, language ${language}`) +
					(interpreter === undefined ? "" : `, interpreter ${interpreter}`),
			],
			[`Build protections ${cite(infoId)}`, ...mitigationLines(info)],
			[
				`Sections: ${sections.length} ${cite(sectionsId)}`,
				...sections.map((section) => {
					const entropy = sectionEntropy(section);
					const notes = sectionNotes(section);
					return (
						`  ${padRight(str(section, "name"), 18)} ${padRight(str(section, "perm") ?? "", 4)} ${padLeft(String(num(section, "size") ?? 0), 9)} bytes` +
						`  entropy ${entropy === undefined ? "   ?" : padLeft(entropy.toFixed(2), 4)}` +
						(notes.length > 0 ? `  <- ${notes.join("; ")}` : "")
					);
				}),
				...(flagged.length > 0
					? [
							`  ${flagged.length} section${plural(flagged.length)} stand${plural(flagged.length, "s", "")} out; high entropy in code, or a section both writable and executable, is what a packed or self-modifying binary looks like — read it before trusting the function list.`,
						]
					: []),
			],
			[
				`Imports: ${imports.length} ${cite(importsId)}`,
				capabilities.length > 0 ? `  reach, by what it links: ${capabilities.join(", ")}` : "  none of the capability groups (network, process control, injection, …) is linked",
				...(risky.length > 0 ? [`  worth a reviewer's look: ${take(20, risky).join(", ")} — scan_imports says why and who calls them`] : []),
				...(imports.length < 8 && get(info, "static") !== true ? ["  very few imports for a dynamic binary: resolved at run time, or packed"] : []),
			],
			[
				`Strings: ${strings.length}; notable ${notable.length} ${cite(stringsId)}`,
				...take(mostStrings, notable).map(({ kind, entry }) => `  ${padRight(kind, 11)} ${num(entry, "vaddr") === undefined ? "?" : hex(num(entry, "vaddr"))}  ${oneLine(str(entry, "string") ?? "")}`),
				...moreLine(Math.min(mostStrings, notable.length), notable.length, "notable strings"),
			],
			[
				`Functions: ${functions.length}; largest by code size ${cite(functionsId)}`,
				...take(mostFunctions, functions).map((fn) => {
					const blocks = num(fn, "nbbs");
					return `  ${hex(num(fn, "offset") ?? num(fn, "addr") ?? 0)}  ${padLeft(String(codeSize(fn)), 7)} bytes  ${blocks === undefined ? "" : `${blocks} blocks  `}${str(fn, "name") ?? "?"}`;
				}),
				...moreLine(Math.min(mostFunctions, functions.length), functions.length, "functions"),
			],
			[
				`Entry points ${cite(entriesId)}`,
				...(() => {
					const lines = rows(entryData)
						.filter((entry) => num(entry, "vaddr") !== undefined)
						.map((entry) => `  ${hex(num(entry, "vaddr"))}  ${str(entry, "type") ?? ""}`);
					return lines.length > 0 ? lines : ["  none reported"];
				})(),
			],
		]);
	}

	// --- scan_imports ------------------------------------------------------------------------------

	/**
	 * The imports a reviewer would stop at, each with why it matters and who calls it; plus what
	 * the program can reach, read off what it links. An import is a lead, not a bug: whether a
	 * call is safe is decided at its call site, which is what the callers are listed for.
	 */
	async function scanImports(given) {
		const { callers, maxCallers } = options("scan_imports", given);
		const run = start("scan_imports");
		const withCallers = (callers ?? true) !== false;
		const mostCallers = bounded(maxCallers, 12, 1, 100);
		const { data, id: importsId } = await observeJson(run, "iij");
		const imports = rows(data);
		const severityRank = (severity) => (SEVERITY_ORDER.includes(severity) ? SEVERITY_ORDER.indexOf(severity) : 9);
		const risky = imports
			.map((entry) => ({ entry, bare: bareImportName(str(entry, "name")) }))
			.map(({ entry, bare }) => ({ entry, bare, verdict: riskyImport(bare) }))
			.filter(({ verdict }) => verdict)
			.sort((a, b) => severityRank(a.verdict.severity) - severityRank(b.verdict.severity));
		const reach = CAPABILITIES.map(({ capability }) => ({
			capability,
			names: uniqueLast(imports.map((entry) => bareImportName(str(entry, "name"))).filter((bare) => importCapabilities(bare).includes(capability))),
		})).filter(({ names }) => names.length > 0);

		const riskyLines = [];
		for (const { entry, bare, verdict } of risky) {
			const address = num(entry, "plt");
			const linked = str(entry, "name");
			riskyLines.push(
				`  [${verdict.severity}] ${bare}${bare === linked ? "" : ` (linked as ${linked})`} (${verdict.category})${address === undefined ? "" : ` @ ${hex(address)}`} — ${verdict.why}`,
			);
			if (!withCallers || address === undefined) continue;
			const { places, id } = await callersOf(run, address);
			riskyLines.push(
				places.length > 0
					? `      called from ${places.length} place${plural(places.length)} ${cite(id)}: ${take(mostCallers, places).join(", ")}`
					: `      no caller found by analysis ${cite(id)}`,
				...moreLine(Math.min(mostCallers, places.length), places.length, "callers"),
			);
		}
		return recipeText(run, `scan_imports: ${imports.length} imports, ${risky.length} worth a look`, [
			[
				`Reach, by what it links ${cite(importsId)}`,
				...(reach.length > 0 ? reach.map(({ capability, names }) => `  ${padRight(capability, 18)} ${names.join(", ")}`) : ["  none of the capability groups is linked"]),
			],
			[`Imports worth a reviewer's look ${cite(importsId)}`, ...(riskyLines.length > 0 ? riskyLines : ["  none of the imports in the table is linked"])],
			["An import is a lead. Read each call site (rizin_command pdg or pdf at the caller) before saying what it does."],
		]);
	}

	// --- inspect_function --------------------------------------------------------------------------

	/** The instruction objects of a pdfj reply. */
	const functionOps = (body) => rows(get(body, "ops"));

	/** Every address an instruction refers to. */
	function opTargets(op) {
		const referred = [...rows(get(op, "xrefs_from")), ...rows(get(op, "refs"))].map((reference) => num(reference, "addr"));
		return [num(op, "ptr"), num(op, "jump"), ...referred].filter((target) => target !== undefined);
	}

	/** The strings rizin found, by where each lies. */
	function stringsByAddress(data) {
		const table = new Map();
		for (const entry of rows(data)) if (num(entry, "vaddr") !== undefined) table.set(num(entry, "vaddr"), str(entry, "string"));
		return table;
	}

	/**
	 * One function, read from every side at once: its size, complexity and signature, its
	 * variables, who calls it and what it calls, and the strings it refers to — the context to
	 * read before its code. Follow it with rizin_command pdg at the same address for the code.
	 */
	async function inspectFunction(addr, given) {
		const { maxItems } = options("inspect_function", given);
		const run = start("inspect_function");
		const at = functionName(addr);
		const limit = bounded(maxItems, 30, 1, 300);
		const { data: infoData, id: infoId } = await observeJson(run, "afij", at);
		const info = rows(infoData)[0];
		if (!info) {
			throw new Error(`omp-re: inspect_function: no function at ${at} — list them with await tool.rizin_command({ command: "aflj" }), or define one with define_function`);
		}
		const { data: body, id: bodyId } = await observeJson(run, "pdfj", at);
		const { data: variables, id: variablesId } = await observeJson(run, "afvlj", at);
		const { data: stringData, id: stringsId } = await observeJson(run, "izj");
		const entry = num(info, "offset") ?? num(info, "addr") ?? 0;
		const { places: callers, id: callersId } = await callersOf(run, entry);

		const ops = functionOps(body);
		const stringAt = stringsByAddress(stringData);
		const referenced = uniqueLast(
			ops.flatMap((op) => opTargets(op).flatMap((target) => (stringAt.get(target) === undefined ? [] : [{ address: target, text: stringAt.get(target) }]))),
			(reference) => reference.address,
		);
		const calls = uniqueFirst(ops.filter((op) => ["call", "ucall", "rcall", "icall", "ccall"].includes(str(op, "type"))).map((op) => (str(op, "disasm") ?? "").replace(/^call\s+/, "")));
		const compares = ops.filter((op) => ["cmp", "acmp"].includes(str(op, "type"))).length;
		const branches = ops.filter((op) => str(op, "type") === "cjmp").length;
		const variableCount = isObject(variables) ? Object.values(variables).reduce((sum, kind) => sum + (Array.isArray(kind) ? kind.length : 0), 0) : 0;
		const loops = num(info, "loops") ?? 0;

		return recipeText(run, `inspect_function: ${str(info, "name") ?? at}`, [
			[
				`Shape ${cite(infoId)}`,
				`  ${str(info, "signature") ?? str(info, "name") ?? at} at ${hex(entry)}`,
				`  ${num(info, "realsz") ?? num(info, "size") ?? 0} bytes of code, ${num(info, "nbbs") ?? 0} basic blocks, ${num(info, "edges") ?? 0} edges, cyclomatic complexity ${num(info, "cc") ?? 0}, ${loops} loop${plural(Number(loops))}`,
				`  calling convention ${str(info, "calltype") ?? "?"}, stack frame ${num(info, "stackframe") ?? 0} bytes${get(info, "noreturn") === true ? ", does not return" : ""}`,
			],
			[`Body ${cite(bodyId)}`, `  ${ops.length} instructions, ${compares} compare${plural(compares)}, ${branches} conditional branch${plural(branches, "", "es")} — find_comparisons lists them`],
			[`Variables: ${variableCount} ${cite(variablesId)}`],
			[`Called from ${callers.length} place${plural(callers.length)} ${cite(callersId)}`, ...take(limit, callers).map((caller) => `  ${caller}`), ...moreLine(Math.min(limit, callers.length), callers.length, "callers")],
			[`Calls ${calls.length} distinct target${plural(calls.length)} ${cite(bodyId)}`, ...take(limit, calls).map((call) => `  ${call}`), ...moreLine(Math.min(limit, calls.length), calls.length, "callees")],
			[
				`Refers to ${referenced.length} string${plural(referenced.length)} ${cite(bodyId)} ${cite(stringsId)}`,
				...take(limit, referenced).map(({ address, text }) => `  ${hex(address)}  ${oneLine(text)}`),
				...moreLine(Math.min(limit, referenced.length), referenced.length, "strings"),
			],
		]);
	}

	// --- find_comparisons --------------------------------------------------------------------------

	const BRANCH_MEANINGS = [
		[["je", "jz"], "taken when equal / zero"],
		[["jne", "jnz"], "taken when not equal / not zero"],
		[["ja", "jnbe"], "taken when above (unsigned >)"],
		[["jae", "jnb", "jnc"], "taken when above or equal (unsigned >=)"],
		[["jb", "jc", "jnae"], "taken when below (unsigned <)"],
		[["jbe", "jna"], "taken when below or equal (unsigned <=)"],
		[["jg", "jnle"], "taken when greater (signed >)"],
		[["jge", "jnl"], "taken when greater or equal (signed >=)"],
		[["jl", "jnge"], "taken when less (signed <)"],
		[["jle", "jng"], "taken when less or equal (signed <=)"],
		[["js"], "taken when negative"],
		[["jns"], "taken when not negative"],
	];

	/** What a conditional jump tests, in words. */
	const branchMeaning = (mnemonic) => BRANCH_MEANINGS.find(([names]) => names.includes((mnemonic ?? "").toLowerCase()))?.[1] ?? "conditional";

	/** When an instruction compares against a constant that is a printable character, say which: a run of these is a string compared a byte at a time. */
	function printableNote(op) {
		const value = num(op, "val") ?? num(op, "ptr");
		if (value === undefined || typeof value !== "number" || !Number.isInteger(value) || value < 32 || value > 126) return "";
		return ` ; "${String.fromCharCode(value).replace(/["\\]/g, "\\$&")}"`;
	}

	/**
	 * What a function decides on: every compare or test with the conditional branch that follows
	 * it (which way it goes, and where to), every call to something that compares or validates,
	 * and the strings on the way — the static skeleton of validation logic, with no emulation and
	 * nothing run. It lists what is compared, not what the comparison means.
	 */
	async function findComparisons(addr, given) {
		const { maxItems } = options("find_comparisons", given);
		const run = start("find_comparisons");
		const at = functionName(addr);
		const limit = bounded(maxItems, 80, 1, 1000);
		const { data: body, id: bodyId } = await observeJson(run, "pdfj", at);
		const ops = functionOps(body);
		if (ops.length === 0) throw new Error(`omp-re: find_comparisons: no function at ${at} — list them with await tool.rizin_command({ command: "aflj" })`);
		const { data: stringData, id: stringsId } = await observeJson(run, "izj");
		const stringAt = stringsByAddress(stringData);
		const where = (op) => hex(num(op, "offset") ?? 0);

		const decisions = [];
		ops.forEach((op, index) => {
			if (!["cmp", "acmp"].includes(str(op, "type"))) return;
			const next = ops[index + 1];
			let branch = "";
			if (next && str(next, "type") === "cjmp") {
				const disasm = str(next, "disasm") ?? "";
				const taken = num(next, "jump");
				const otherwise = num(next, "fail");
				branch = `  ->  ${disasm}: ${branchMeaning(words(disasm)[0])}${taken === undefined ? "" : `, to ${hex(taken)}`}${otherwise === undefined ? "" : `, else ${hex(otherwise)}`}`;
			}
			decisions.push(`  ${where(op)}  ${str(op, "disasm") ?? ""}${printableNote(op)}${branch}`);
		});
		const decidingCalls = ops
			.filter((op) => ["call", "ucall", "rcall", "icall"].includes(str(op, "type")) && COMPARING_CALLS.test(str(op, "disasm") ?? ""))
			.map((op) => `  ${where(op)}  ${str(op, "disasm") ?? ""}`);
		const referenced = uniqueLast(
			ops.flatMap((op) => opTargets(op).flatMap((target) => (stringAt.get(target) === undefined ? [] : [`  ${where(op)}  refers to ${hex(target)}  ${oneLine(stringAt.get(target))}`]))),
		);

		return recipeText(run, `find_comparisons: ${str(body, "name") ?? at}`, [
			[`Compares and the branches that follow: ${decisions.length} ${cite(bodyId)}`, ...take(limit, decisions), ...moreLine(Math.min(limit, decisions.length), decisions.length, "comparisons")],
			[`Calls that compare or validate: ${decidingCalls.length} ${cite(bodyId)}`, ...(decidingCalls.length > 0 ? take(limit, decidingCalls) : ["  none by name"])],
			[`Strings on the way: ${referenced.length} ${cite(bodyId)} ${cite(stringsId)}`, ...(referenced.length > 0 ? take(limit, referenced) : ["  none"])],
			["This lists what is compared, not what the comparison means: which branch is the accepting one is for you to read from the code each leads to."],
		]);
	}

	// --- find_crypto -------------------------------------------------------------------------------

	/**
	 * Where cryptographic material lies in the open binary: rizin's own search for keys and
	 * certificates, and a search for the published constants of common algorithms, each hit with
	 * its address and what refers to it. A constant's presence says the tables are linked in, not
	 * that they are used, nor on what; a four-byte constant can occur by chance and is marked weak.
	 */
	async function findCrypto(given) {
		const { references } = options("find_crypto", given);
		const run = start("find_crypto");
		const withReferences = (references ?? true) !== false;
		const { data: material, id: materialId } = await observeJson(run, "/cmj");
		const hits = [];
		for (const { algorithm, what, hex: bytes } of CRYPTO_CONSTANTS) {
			// Each search is a read on the record whether or not it finds anything; only a hit is reported below.
			const { data, id } = await observeJson(run, `/xj ${bytes}`);
			for (const row of rows(data)) {
				const address = num(row, "address") ?? num(row, "offset") ?? num(row, "addr");
				if (address !== undefined) hits.push({ algorithm, what, address, id, weak: bytes.length <= SHORT_CONSTANT });
			}
		}
		const constantLines = [];
		for (const { algorithm, what, address, id, weak } of take(60, hits)) {
			constantLines.push(`  ${hex(address)}  ${algorithm} — ${what} ${cite(id)}${weak ? " (weak: four bytes can occur by chance)" : ""}`);
			if (!withReferences) continue;
			const { places, id: placesId } = await callersOf(run, address);
			constantLines.push(
				places.length > 0
					? `      referred to from ${take(8, places).join(", ")} ${cite(placesId)}`
					: `      no reference found by analysis ${cite(placesId)} — reached by computed address, or unused`,
			);
		}
		const materialLines = take(40, rows(material)).map((row) => `  ${encode(row)}`);
		return recipeText(run, `find_crypto: ${hits.length} constant hit${plural(hits.length)}`, [
			[`rizin's search for keys and certificates ${cite(materialId)}`, ...(materialLines.length > 0 ? materialLines : ["  nothing found"])],
			["Published constants", ...(constantLines.length > 0 ? constantLines : ["  none of the constants in the table was found"])],
			["A table's presence shows the algorithm is linked in. What it is used on, and with which key, is in the code that refers to it."],
		]);
	}

	// --- what is handed to eval ----------------------------------------------------------------------

	const HELP = [
		"omp-re recipes — wide reads composed over rizin_command. Not tools: each read a recipe makes is its own",
		"rizin_command call (approved, audited, recorded as evidence). Each returns its report as a string; print() it.",
		"Open a binary first (await tool.open_binary({ path })).",
		"",
		"  await re.triage({ maxStrings = 25, maxFunctions = 15 })",
		"      what the binary is, build protections, sections with entropy, imports and what they reach,",
		"      notable strings, the largest functions, entry points.",
		"  await re.scanImports({ callers = true, maxCallers = 12 })",
		"      the imports a reviewer stops at, why, and who calls each; what the program can reach.",
		'  await re.inspectFunction("main", { maxItems = 30 })',
		"      one function's shape, variables, callers, callees and the strings it refers to.",
		'  await re.findComparisons("main", { maxItems = 80 })',
		"      every compare with the branch that follows, calls that compare or validate, strings on the way.",
		"  await re.findCrypto({ references = true })",
		"      rizin's key and certificate search, and where published constants of common algorithms lie.",
		"",
		"Every section cites the [evidence xxxxxxxx] id of the read it rests on, and each report ends with the",
		"reads it took. A line of a report is a lead, not a finding: record_finding with those ids makes it one.",
	].join("\n");

	return {
		triage,
		scanImports,
		inspectFunction,
		findComparisons,
		findCrypto,
		help: () => HELP,
	};
})();

// A %load cell shows the value of the script's last expression, and the source is not echoed: say what now exists.
"omp-re recipes loaded: re.triage, re.scanImports, re.inspectFunction, re.findComparisons, re.findCrypto — print(re.help()) says what each answers.";
