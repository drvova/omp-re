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
 * All three answer the same text for the same binary, reads and all, and
 * test/recipes-eval.test.ts holds them to it.
 *
 * What a recipe reads, in which order, how each section is worded, its
 * options and their bounds, the tables and every sentence are data: they
 * live in recipes/tables.json, and scripts/gen-recipes.ts writes them into
 * the marked block below — edit the JSON and run the script, never the
 * block. This file keeps what JavaScript forces on it (rizin's JSON with its
 * integers whole, the bridge for one read, how a number is printed), the
 * loop that renders a recipe from that data, and under FACTS the few things
 * a section needs code for. A change to any of those is a change in the
 * other two files.
 *
 * The one place the three hosts' words differ is a refusal that says how to
 * list functions: each names its own call (the data's `host.listFunctions`).
 */
(() => {
// <generated:tables> — from recipes/tables.json by scripts/gen-recipes.ts; do not edit
const TABLES = {
  riskyImports: [{category:"memory",severity:"high",why:"copies with no bound at all; any input longer than the buffer overruns it",names:["gets"]},{category:"memory",severity:"high",why:"copies or formats until a terminator with no destination size; safe only if every caller proves the length",names:["strcpy","strcat","stpcpy","sprintf","vsprintf","wcscpy","wcscat","lstrcpyA","lstrcpyW","lstrcatA","lstrcatW","wsprintfA","wsprintfW"]},{category:"memory",severity:"medium",why:"reads into a buffer; a %s or %[ without a width has no bound",names:["scanf","sscanf","fscanf","vscanf","vsscanf","vfscanf"]},{category:"memory",severity:"medium",why:"the size comes from the caller and is often attacker-influenced",names:["alloca","realpath","getwd"]},{category:"memory",severity:"low",why:"bounded, but the bound is the caller's to get right (and strncpy leaves no terminator when it fills)",names:["strncpy","strncat","memcpy","memmove","bcopy","wcsncpy","snprintf","vsnprintf"]},{category:"command",severity:"high",why:"hands a string to a shell; anything in it that came from outside is a command",names:["system","popen","wordexp","WinExec","ShellExecuteA","ShellExecuteW","ShellExecuteExA","ShellExecuteExW"]},{category:"command",severity:"medium",why:"starts another program; what it runs and with which arguments is worth tracing",names:["execl","execlp","execle","execv","execvp","execve","execvpe","posix_spawn","posix_spawnp","CreateProcessA","CreateProcessW"]},{category:"format",severity:"low",why:"a format string that is not a literal lets its author read and write memory",names:["printf","fprintf","dprintf","vprintf","vfprintf","syslog","vsyslog","err","errx","warn","warnx"]},{category:"race",severity:"high",why:"chooses a file name before the file exists; another process can take it first",names:["mktemp","tmpnam","tempnam"]},{category:"race",severity:"low",why:"checks a path, then uses it; the file can change between the two",names:["access","stat","lstat"]},{category:"integer",severity:"low",why:"reports no error and no overflow; a caller cannot tell a bad number from zero",names:["atoi","atol","atoll","atof"]},{category:"randomness",severity:"medium",why:"predictable; unfit for keys, tokens or anything an adversary should not guess",names:["rand","srand","random","srandom","drand48","lrand48"]},{category:"privilege",severity:"info",why:"changes the process's identity or root; the order and the error checks matter",names:["setuid","setgid","seteuid","setegid","setreuid","setregid","chroot"]},{category:"loading",severity:"medium",why:"loads code chosen at run time; from where is worth tracing",names:["dlopen","LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW"]}],
  capabilities: [{capability:"network",names:["socket","connect","bind","listen","accept","send","sendto","recv","recvfrom","getaddrinfo","gethostbyname","WSAStartup","InternetOpenA","InternetOpenW","InternetOpenUrlA","InternetOpenUrlW","InternetConnectA","InternetConnectW","HttpSendRequestA","HttpSendRequestW","WinHttpOpen","WinHttpConnect","WinHttpSendRequest","URLDownloadToFileA","URLDownloadToFileW","curl_easy_perform","SSL_connect"]},{capability:"process control",names:["fork","vfork","clone","kill","ptrace","prctl","OpenProcess","TerminateProcess","CreateRemoteThread","CreateToolhelp32Snapshot","Process32First","Process32Next"]},{capability:"code injection",names:["VirtualAllocEx","WriteProcessMemory","ReadProcessMemory","CreateRemoteThread","NtUnmapViewOfSection","ZwUnmapViewOfSection","QueueUserAPC","SetThreadContext","SetWindowsHookExA","SetWindowsHookExW","process_vm_writev"]},{capability:"memory protection",names:["mprotect","mmap","memfd_create","VirtualProtect","VirtualProtectEx","VirtualAlloc"]},{capability:"anti-analysis",names:["ptrace","IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugStringA","OutputDebugStringW","NtSetInformationThread","GetTickCount","QueryPerformanceCounter"]},{capability:"persistence",names:["RegSetValueExA","RegSetValueExW","RegCreateKeyExA","RegCreateKeyExW","CreateServiceA","CreateServiceW","StartServiceA","StartServiceW","SetFileAttributesA","SetFileAttributesW"]},{capability:"cryptography",names:["CryptAcquireContextA","CryptAcquireContextW","CryptEncrypt","CryptDecrypt","CryptGenKey","CryptHashData","BCryptEncrypt","BCryptDecrypt","BCryptGenRandom","EVP_EncryptInit_ex","EVP_DecryptInit_ex","EVP_DigestInit_ex","AES_set_encrypt_key","AES_encrypt","MD5_Init","SHA1_Init","SHA256_Init","RC4","DES_ecb_encrypt","getrandom","RAND_bytes"]},{capability:"filesystem",names:["unlink","remove","rename","chmod","chown","opendir","readdir","ftw","nftw","DeleteFileA","DeleteFileW","MoveFileA","MoveFileW","FindFirstFileA","FindFirstFileW","CopyFileA","CopyFileW"]},{capability:"dynamic resolution",names:["dlsym","GetProcAddress","LdrGetProcedureAddress"]}],
  severityOrder: ["high","medium","low","info"],
  importNameRules: [{rule:"dropThrough",text:"imp."},{rule:"dropPrefix",text:"__isoc99_"},{rule:"dropLeading",text:"_"},{rule:"dropSuffix",text:"_chk"}],
  stringInterest: [{kind:"credentials",pattern:"passw|passphrase|secret|\\btoken\\b|api[_-]?key|private key|credential|\\blogin\\b|\\bauth(?:enticat|oriz)"},{kind:"network",pattern:"https?://|ftp://|\\b[a-z0-9-]+\\.(?:com|net|org|io|ru|cn|info|biz|xyz|top)\\b|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|user-agent"},{kind:"commands",pattern:"/bin/sh|/bin/bash|cmd\\.exe|powershell|wget |curl |chmod |\\bnc \\b|schtasks|reg add"},{kind:"paths",pattern:"^/(?:etc|tmp|var|proc|dev|home|root)/|\\\\(?:windows|system32|appdata|temp)\\\\|HKEY_|\\\\Software\\\\"},{kind:"checks",pattern:"licen[sc]e|serial|registration|trial|expired|invalid|incorrect|denied|granted|debugger|virtual|sandbox|vmware|vbox"}],
  packerSectionNames: "upx|aspack|themida|vmp|mpress|petite|\\.packed|\\.enigma",
  comparingCalls: "\\b(?:str|strn|strcase|strncase|wcs|wcsn|mem|b)cmp\\b|\\bstrstr\\b|\\bstrchr\\b|lstrcmp|CompareString|RtlCompareMemory|\\bcrc|\\bhash|md5|sha\\d|verify|check|valid",
  cryptoConstants: [{algorithm:"AES",what:"S-box",hex:"637c777bf26b6fc53001672bfed7ab76"},{algorithm:"AES",what:"inverse S-box",hex:"52096ad53036a538bf40a39e81f3d7fb"},{algorithm:"AES",what:"T-table Te0 (big-endian words)",hex:"c66363a5f87c7c84ee777799f67b7b8d"},{algorithm:"AES",what:"T-table Te0 (little-endian words)",hex:"a56363c6847c7cf8997777ee8d7b7bf6"},{algorithm:"SHA-256",what:"round constants (little-endian words)",hex:"982f8a4291443771cffbc0b5a5dbb5e9"},{algorithm:"SHA-256",what:"round constants (big-endian words)",hex:"428a2f9871374491b5c0fbcfe9b5dba5"},{algorithm:"SHA-256",what:"initial state (little-endian words)",hex:"67e6096a85ae67bb72f36e3c3af54fa5"},{algorithm:"SHA-512",what:"round constants (little-endian words)",hex:"22ae28d7982f8a42cd65ef2391443771"},{algorithm:"SHA-1 / MD5",what:"initial state (little-endian words)",hex:"0123456789abcdeffedcba9876543210"},{algorithm:"SHA-1",what:"round constant K1 (little-endian)",hex:"9979825a"},{algorithm:"MD5",what:"sine table (little-endian words)",hex:"78a46ad756b7c7e8db702024eecebdc1"},{algorithm:"CRC-32",what:"table, polynomial 0xEDB88320 (little-endian words)",hex:"0000000096300777"},{algorithm:"CRC-32",what:"table, polynomial 0x04C11DB7 (big-endian words)",hex:"0000000004c11db7130476dc"},{algorithm:"ChaCha / Salsa20",what:"sigma constant",hex:"657870616e642033322d62797465206b"},{algorithm:"ChaCha / Salsa20",what:"tau constant",hex:"657870616e642031362d62797465206b"},{algorithm:"Blowfish",what:"P-array (big-endian words)",hex:"243f6a8885a308d313198a2e03707344"},{algorithm:"Blowfish",what:"P-array (little-endian words)",hex:"886a3f24d308a3852e8a191344737003"},{algorithm:"TEA / XTEA",what:"delta (little-endian)",hex:"b979379e"},{algorithm:"TEA / XTEA",what:"delta (big-endian)",hex:"9e3779b9"},{algorithm:"DES",what:"initial permutation table",hex:"3a322a221a120a023c342c241c140c04"},{algorithm:"RC6 / RC5",what:"P32 and Q32 (little-endian)",hex:"6351e1b7b979379e"},{algorithm:"Base64",what:"standard alphabet",hex:"4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b2f"},{algorithm:"Base64",what:"URL-safe alphabet tail",hex:"7778797a303132333435363738392d5f"}],
  opTypes: {call:["call","ucall","rcall","icall","ccall"],decidingCall:["call","ucall","rcall","icall"],compare:["cmp","acmp"],branch:["cjmp"]},
  calleeAfter: "call",
  branchMeanings: [{mnemonics:["je","jz"],meaning:"taken when equal / zero"},{mnemonics:["jne","jnz"],meaning:"taken when not equal / not zero"},{mnemonics:["ja","jnbe"],meaning:"taken when above (unsigned >)"},{mnemonics:["jae","jnb","jnc"],meaning:"taken when above or equal (unsigned >=)"},{mnemonics:["jb","jc","jnae"],meaning:"taken when below (unsigned <)"},{mnemonics:["jbe","jna"],meaning:"taken when below or equal (unsigned <=)"},{mnemonics:["jg","jnle"],meaning:"taken when greater (signed >)"},{mnemonics:["jge","jnl"],meaning:"taken when greater or equal (signed >=)"},{mnemonics:["jl","jnge"],meaning:"taken when less (signed <)"},{mnemonics:["jle","jng"],meaning:"taken when less or equal (signed <=)"},{mnemonics:["js"],meaning:"taken when negative"},{mnemonics:["jns"],meaning:"taken when not negative"}],
  otherBranch: "conditional",
  sectionNotes: {writableExecutable:"writable+executable",veryHighEntropy:"very high entropy (compressed or encrypted data)",highEntropyForCode:"high entropy for code",packerName:"a name packers use"},
  thresholds: {veryHighEntropy:7.2,highEntropyForCode:6.8,fewImports:8,shortConstantHexDigits:8},
  limits: {lineWidth:100,triageRiskyImports:20,cryptoMaterial:40,cryptoHits:60,cryptoReferences:8},
  whitespace: [9,10,11,12,13,32,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288,65279],
  text: {more:["  … ",{get:["hidden"],as:"d"}," more ",{get:["what"]}," not shown"],evidenceTaken:"Evidence taken (cite these in record_finding; each is a rizin_command read you can re-run):",evidenceRow:["  ",{get:[".id"]},"  ",{get:[".label"]}],nameless:"?",refusals:{notAString:["omp-re: ",{get:["recipe"]},": a function is named by a string, not ",{get:["given"]}],optionsNotOneObject:["omp-re: ",{get:["recipe"]},": options are one object, e.g. { maxItems: 20 }, not ",{get:["given"]}],noFunction:["omp-re: ",{get:["recipe"]},": no function at ",{get:["addr"]}," — list them with ",{get:["listFunctions"]},", or define one with define_function"],noInstructions:["omp-re: ",{get:["recipe"]},": no function at ",{get:["addr"]}," — list them with ",{get:["listFunctions"]}],cutOutput:["omp-re: ",{get:["recipe"]},": the output of rizin_command ",{get:["label"],as:"json"}," was cut at the size cap and the whole of it could not be read back (",{get:["why"]},"). The recipe needs all of it and will not report from cut JSON — run the reads by hand with narrower commands."],cutNoArtifact:["the engine saved no artifact for it"],cutUnreadable:["artifact://",{get:["artifact"]},": ",{get:["error"]}],cutNotText:["artifact://",{get:["artifact"]}," did not read as text"]}},
  host: {listFunctions:"await tool.rizin_command({ command: \"aflj\" })",help:"omp-re recipes — wide reads composed over rizin_command. Not tools: each read a recipe makes is its own\nrizin_command call (approved, audited, recorded as evidence). Each returns its report as a string; print() it.\nOpen a binary first (await tool.open_binary({ path })).\n\n  await re.triage({ maxStrings = 25, maxFunctions = 15 })\n      what the binary is, build protections, sections with entropy, imports and what they reach,\n      notable strings, the largest functions, entry points.\n  await re.scanImports({ callers = true, maxCallers = 12 })\n      the imports a reviewer stops at, why, and who calls each; what the program can reach.\n  await re.inspectFunction(\"main\", { maxItems = 30 })\n      one function's shape, variables, callers, callees and the strings it refers to.\n  await re.findComparisons(\"main\", { maxItems = 80 })\n      every compare with the branch that follows, calls that compare or validate, strings on the way.\n  await re.findCrypto({ references = true })\n      rizin's key and certificate search, and where published constants of common algorithms lie.\n\nEvery section cites the [evidence xxxxxxxx] id of the read it rests on, and each report ends with the\nreads it took. A line of a report is a lead, not a finding: record_finding with those ids makes it one.",loaded:"omp-re recipes loaded: re.triage, re.scanImports, re.inspectFunction, re.findComparisons, re.findCrypto — print(re.help()) says what each answers."},
  recipes: [
    {name:"triage",call:"triage",takes:false,options:[{name:"maxStrings",default:25,least:1,most:200},{name:"maxFunctions",default:15,least:1,most:100}],steps:[{read:"path",command:"ij"},{read:"info",command:"iIj"},{read:"sectionData",command:"iSj entropy"},{read:"imports",command:"iij"},{read:"strings",command:"izj"},{read:"functionData",command:"aflj"},{read:"entries",command:"iej"},{derive:"triage"}],title:["triage: ",{get:["path.core.file"],or:"?"}],sections:[{title:["Identity ",{cite:"@info"}],lines:[["  ",{get:["info.class","info.bintype"],or:"unknown format"},", ",{get:["info.arch"],or:"?"}," ",{get:["info.bits"],as:"d",or:"?"},"-bit ",{get:["info.endian"],or:""},", ",{get:["info.os"],or:"?"},{group:[", language ",{get:["info.lang"]}]},{group:[", interpreter ",{get:["info.intrp"]}]}]]},{title:["Build protections ",{cite:"@info"}],lines:[["  stack canary: ",{choose:"info.canary",yes:"yes",no:"NO — a stack overflow reaches the return address unchecked"}],["  NX: ",{choose:"info.nx",yes:"yes",no:"NO — data pages are executable"}],["  PIE: ",{choose:"info.pie",yes:"yes",no:"NO — the image loads at a fixed address"}],["  RELRO: ",{get:["info.relro"],or:"none"},{group:[{if:"info.relro",is:"partial"}," — the GOT stays writable"]},{group:[{unless:"info.relro",is:"partial"},{unless:"info.relro",is:"full"}," — the GOT and other relocated data stay writable"]}],["  fortified libc calls: ",{choose:"info.fortify_source",yes:"yes",no:"no"}],["  stripped: ",{choose:"info.stripped",yes:"yes",no:"no"},"   static: ",{choose:"info.static",yes:"yes",no:"no"}]]},{title:["Sections: ",{count:"sections"}," ",{cite:"@sectionData"}],rows:"sections",row:["  ",{get:[".section.name"],padRight:18}," ",{get:[".section.perm"],padRight:4,or:""}," ",{get:[".section.size"],as:"d",padLeft:9,or:"0"}," bytes  entropy ",{get:[".entropy"],as:"f2",padLeft:4,or:"?"},{group:[{if:".notes"},"  <- ",{join:".notes",with:"; "}]}],after:[[{group:[{if:"flagged"},"  ",{count:"flagged"}," section",{plural:"flagged",one:"",many:"s"}," stand",{plural:"flagged",one:"s",many:""}," out; high entropy in code, or a section both writable and executable, is what a packed or self-modifying binary looks like — read it before trusting the function list."]}]]},{title:["Imports: ",{count:"imports"}," ",{cite:"@imports"}],lines:[[{group:[{if:"reach"},"  reach, by what it links: ",{join:"reach",with:", "}]},{group:[{unless:"reach"},"  none of the capability groups (network, process control, injection, …) is linked"]}],[{group:[{if:"riskyShown"},"  worth a reviewer's look: ",{join:"riskyShown",with:", "}," — scan_imports says why and who calls them"]}],[{choose:"fewImports",yes:"  very few imports for a dynamic binary: resolved at run time, or packed",no:""}]]},{title:["Strings: ",{count:"strings"},"; notable ",{count:"notable"}," ",{cite:"@strings"}],rows:"notable",limit:"maxStrings",row:["  ",{get:[".kind"],padRight:11}," ",{get:[".entry.vaddr"],as:"x",or:"?"},"  ",{get:[".entry.string"],as:"line",or:""}],more:"notable strings"},{title:["Functions: ",{count:"functions"},"; largest by code size ",{cite:"@functionData"}],rows:"functions",limit:"maxFunctions",row:["  ",{get:[".offset",".addr"],as:"x",or:"0x0"},"  ",{get:[".realsz",".size"],as:"d",padLeft:7,or:"0"}," bytes  ",{group:[{get:[".nbbs"],as:"d"}," blocks  "]},{get:[".name"],or:"?"}],more:"functions"},{title:["Entry points ",{cite:"@entries"}],rows:"entries",row:["  ",{get:[".vaddr"],as:"x"},"  ",{get:[".type"],or:""}],empty:["  none reported"]}]},
    {name:"scan_imports",call:"scanImports",takes:false,options:[{name:"callers",flag:true},{name:"maxCallers",default:12,least:1,most:100}],steps:[{read:"imports",command:"iij"},{derive:"scanImports"}],title:["scan_imports: ",{count:"imports"}," imports, ",{count:"risky"}," worth a look"],sections:[{title:["Reach, by what it links ",{cite:"@imports"}],rows:"reach",row:["  ",{get:[".capability"],padRight:18}," ",{join:".names",with:", "}],empty:["  none of the capability groups is linked"]},{title:["Imports worth a reviewer's look ",{cite:"@imports"}],rows:"risky",row:["  [",{get:[".severity"]},"] ",{get:[".bare"]},{group:[" (linked as ",{get:[".linkedAs"]},")"]}," (",{get:[".category"]},")",{group:[" @ ",{get:[".plt"],as:"x"}]}," — ",{get:[".why"]}],under:[{when:".traced",rows:".places",limit:"maxCallers",line:["      called from ",{count:".places"}," place",{plural:".places",one:"",many:"s"}," ",{cite:".@places"},": ",{join:"shown",with:", "}],empty:["      no caller found by analysis ",{cite:".@places"}],more:"callers"}],empty:["  none of the imports in the table is linked"]},{lines:[["An import is a lead. Read each call site (rizin_command pdg or pdf at the caller) before saying what it does."]]}]},
    {name:"inspect_function",call:"inspectFunction",takes:true,options:[{name:"maxItems",default:30,least:1,most:300}],steps:[{read:"infoData",command:"afij",at:true},{derive:"theFunction"},{read:"body",command:"pdfj",at:true},{read:"variables",command:"afvlj",at:true},{read:"strings",command:"izj"},{derive:"inspectFunction"}],title:["inspect_function: ",{get:["info.name","addr"]}],sections:[{title:["Shape ",{cite:"@infoData"}],lines:[["  ",{get:["info.signature","info.name","addr"]}," at ",{get:["info.offset","info.addr"],as:"x",or:"0x0"}],["  ",{get:["info.realsz","info.size"],as:"d",or:"0"}," bytes of code, ",{get:["info.nbbs"],as:"d",or:"0"}," basic blocks, ",{get:["info.edges"],as:"d",or:"0"}," edges, cyclomatic complexity ",{get:["info.cc"],as:"d",or:"0"},", ",{get:["info.loops"],as:"d",or:"0"}," loop",{plural:"info.loops",one:"",many:"s"}],["  calling convention ",{get:["info.calltype"],or:"?"},", stack frame ",{get:["info.stackframe"],as:"d",or:"0"}," bytes",{choose:"info.noreturn",yes:", does not return",no:""}]]},{title:["Body ",{cite:"@body"}],lines:[["  ",{count:"ops"}," instructions, ",{get:["compares"],as:"d"}," compare",{plural:"compares",one:"",many:"s"},", ",{get:["branches"],as:"d"}," conditional branch",{plural:"branches",one:"",many:"es"}," — find_comparisons lists them"]]},{title:["Variables: ",{get:["variableCount"],as:"d"}," ",{cite:"@variables"}]},{title:["Called from ",{count:"callers"}," place",{plural:"callers",one:"",many:"s"}," ",{cite:"@callers"}],rows:"callers",limit:"maxItems",row:["  ",{get:["."]}],more:"callers"},{title:["Calls ",{count:"calls"}," distinct target",{plural:"calls",one:"",many:"s"}," ",{cite:"@body"}],rows:"calls",limit:"maxItems",row:["  ",{get:["."]}],more:"callees"},{title:["Refers to ",{count:"referenced"}," string",{plural:"referenced",one:"",many:"s"}," ",{cite:"@body"}," ",{cite:"@strings"}],rows:"referenced",limit:"maxItems",row:["  ",{get:[".address"],as:"x"},"  ",{get:[".text"],as:"line"}],more:"strings"}]},
    {name:"find_comparisons",call:"findComparisons",takes:true,options:[{name:"maxItems",default:80,least:1,most:1000}],steps:[{read:"body",command:"pdfj",at:true},{derive:"functionBody"},{read:"strings",command:"izj"},{derive:"findComparisons"}],title:["find_comparisons: ",{get:["body.name","addr"]}],sections:[{title:["Compares and the branches that follow: ",{count:"decisions"}," ",{cite:"@body"}],rows:"decisions",limit:"maxItems",row:["  ",{get:[".op.offset"],as:"x",or:"0x0"},"  ",{get:[".op.disasm"],or:""},{group:[" ; \"",{get:[".printable"]},"\""]},{group:["  ->  ",{get:[".next.disasm"],or:""},": ",{get:[".meaning"]},{group:[", to ",{get:[".next.jump"],as:"x"}]},{group:[", else ",{get:[".next.fail"],as:"x"}]}]}],more:"comparisons"},{title:["Calls that compare or validate: ",{count:"decidingCalls"}," ",{cite:"@body"}],rows:"decidingCalls",limit:"maxItems",row:["  ",{get:[".offset"],as:"x",or:"0x0"},"  ",{get:[".disasm"],or:""}],empty:["  none by name"]},{title:["Strings on the way: ",{count:"onTheWay"}," ",{cite:"@body"}," ",{cite:"@strings"}],rows:"onTheWay",limit:"maxItems",row:["  ",{get:[".offset"],as:"x"},"  refers to ",{get:[".target"],as:"x"},"  ",{get:[".text"],as:"line"}],empty:["  none"]},{lines:[["This lists what is compared, not what the comparison means: which branch is the accepting one is for you to read from the code each leads to."]]}]},
    {name:"find_crypto",call:"findCrypto",takes:false,options:[{name:"references",flag:true}],steps:[{read:"material",command:"/cmj"},{derive:"findCrypto"}],title:["find_crypto: ",{count:"hits"}," constant hit",{plural:"hits",one:"",many:"s"}],sections:[{title:["rizin's search for keys and certificates ",{cite:"@material"}],rows:"material",limit:"cryptoMaterial",row:["  ",{get:["."],as:"json"}],empty:["  nothing found"]},{title:["Published constants"],rows:"hits",limit:"cryptoHits",row:["  ",{get:[".address"],as:"x"},"  ",{get:[".algorithm"]}," — ",{get:[".what"]}," ",{cite:".@hit"},{choose:".weak",yes:" (weak: four bytes can occur by chance)",no:""}],under:[{when:".traced",rows:".places",limit:"cryptoReferences",line:["      referred to from ",{join:"shown",with:", "}," ",{cite:".@places"}],empty:["      no reference found by analysis ",{cite:".@places"}," — reached by computed address, or unused"]}],empty:["  none of the constants in the table was found"]},{lines:[["A table's presence shows the algorithm is linked in. What it is used on, and with which key, is in the code that refers to it."]]}]}
  ]
};
// </generated:tables>

	const { text: TEXT, host: HOST, limits: LIMITS, thresholds: THRESHOLDS, opTypes: OP_TYPES, sectionNotes: NOTES } = TABLES;
	// The JSON's patterns are written once for every host and matched without regard to case on each.
	const pattern = (source) => new RegExp(source, "i");
	const STRING_INTEREST = TABLES.stringInterest.map((row) => ({ kind: row.kind, pattern: pattern(row.pattern) }));
	const PACKER_SECTION_NAMES = pattern(TABLES.packerSectionNames);
	const COMPARING_CALLS = pattern(TABLES.comparingCalls);

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
	const isNumber = (value) => typeof value === "number" || typeof value === "bigint";
	/** A member with null read as absent; absent as soon as `object` is not an object. */
	const get = (object, key) => (isObject(object) ? (object[key] ?? undefined) : undefined);
	const str = (object, key) => (typeof get(object, key) === "string" ? get(object, key) : undefined);
	const num = (object, key) => (isNumber(get(object, key)) ? get(object, key) : undefined);
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

	/** The number a string of digits spells — rizin writes a section's entropy as one — or nothing. */
	const numberFromText = (text) => (/^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(text) ? Number(text) : undefined);

	// --- text ------------------------------------------------------------------------------

	// White space is the data's list on every host, not each language's own idea of it.
	const SPACE = new Set(TABLES.whitespace.map((point) => String.fromCharCode(point)));

	function trim(text) {
		let from = 0;
		let to = text.length;
		while (from < to && SPACE.has(text[from])) from += 1;
		while (to > from && SPACE.has(text[to - 1])) to -= 1;
		return text.slice(from, to);
	}

	function words(text) {
		const found = [];
		let word = "";
		for (const character of `${text} `) {
			if (!SPACE.has(character)) word += character;
			else if (word !== "") {
				found.push(word);
				word = "";
			}
		}
		return found;
	}

	/** `text` without a leading `word` and the white space after it; as it stands when it does not open that way. */
	function afterWord(text, word) {
		if (!text.startsWith(word) || !SPACE.has(text[word.length])) return text;
		let at = word.length;
		while (SPACE.has(text[at])) at += 1;
		return text.slice(at);
	}

	// Widths and cuts count characters, as the twins' do, not UTF-16 units.
	const count = (text) => Array.from(text).length;
	const padRight = (text, width) => text + " ".repeat(Math.max(0, width - count(text)));
	const padLeft = (text, width) => " ".repeat(Math.max(0, width - count(text))) + text;
	const cut = (text, most) => (text.length <= most ? text : Array.from(text).slice(0, most).join(""));
	const oneLine = (text) => cut(text.replaceAll("\n", " "), LIMITS.lineWidth);
	const take = (most, list) => list.slice(0, most);

	/** Without duplicates, keeping each value where it first stood. */
	function uniqueFirst(list, key = (item) => item) {
		const seen = new Set();
		return list.filter((item) => !seen.has(key(item)) && seen.add(key(item)));
	}
	/** Without duplicates, keeping each value where it last stood. */
	const uniqueLast = (list, key) => uniqueFirst([...list].reverse(), key).reverse();

	/** `value` when it is an integer within least..most, the nearer bound when it is outside, `fallback` when it was not given. */
	const bounded = (value, fallback, least, most) => (Number.isInteger(value) ? Math.max(least, Math.min(most, value)) : fallback);

	// --- a template, filled --------------------------------------------------------------------

	// scripts/gen-recipes.ts says what a template may hold; what it writes into the tables is walked here.
	const MISSING = Symbol("missing");

	/** What a path names: a fact, or (when it opens with ".") the row, and then members of it. */
	const lookup = (path, facts, row) => path.split(".").reduce((value, key) => (key === "" ? value : get(value, key)), path[0] === "." ? row : facts);
	const there = (value) => value === true || (Array.isArray(value) && value.length > 0);
	const size = (value) => (Array.isArray(value) ? value.length : isNumber(value) ? Number(value) : 0);

	const AS = {
		text: (value) => (typeof value === "string" ? value : MISSING),
		d: (value) => (isNumber(value) ? String(value) : MISSING),
		x: (value) => (isNumber(value) ? hex(value) : MISSING),
		f2: (value) => (isNumber(value) ? Number(value).toFixed(2) : MISSING),
		line: (value) => (typeof value === "string" ? oneLine(value) : MISSING),
		json: encode,
	};

	function piece(node, facts, row) {
		if (typeof node === "string") return node;
		if (node.group) {
			const inner = fill(node.group, facts, row);
			return inner === MISSING ? "" : inner;
		}
		if (node.if || node.unless) {
			const value = lookup(node.if ?? node.unless, facts, row);
			const holds = node.is === undefined ? there(value) : value === node.is;
			return holds === (node.if !== undefined) ? "" : MISSING;
		}
		if (node.choose) return there(lookup(node.choose, facts, row)) ? node.yes : node.no;
		if (node.cite) {
			// How a line names the read it rests on; nothing when the read left no record.
			const id = lookup(node.cite, facts, row);
			return typeof id === "string" ? `[evidence ${id}]` : "";
		}
		if (node.count) return String(rows(lookup(node.count, facts, row)).length);
		if (node.join) return rows(lookup(node.join, facts, row)).join(node.with);
		if (node.plural) return size(lookup(node.plural, facts, row)) === 1 ? node.one : node.many;
		let text = MISSING;
		for (const path of node.get) {
			text = AS[node.as ?? "text"](lookup(path, facts, row));
			if (text !== MISSING) break;
		}
		if (text === MISSING) {
			if (node.or === undefined) return MISSING;
			text = node.or;
		}
		return node.padLeft ? padLeft(text, node.padLeft) : node.padRight ? padRight(text, node.padRight) : text;
	}

	/** A template's text, or MISSING when something it needs is not there. */
	function fill(nodes, facts, row) {
		let text = "";
		for (const node of nodes) {
			const part = piece(node, facts, row);
			if (part === MISSING) return MISSING;
			text += part;
		}
		return text;
	}

	/** A template as the lines it adds: one, or none when it cannot be written or comes out empty. */
	function written(nodes, facts, row) {
		const text = fill(nodes, facts, row);
		return text === MISSING || text === "" ? [] : [text];
	}

	/** The lines of one section. */
	function sectionLines(section, facts, row) {
		if (section.when && !there(lookup(section.when, facts, row))) return [];
		const each = (templates) => (templates ?? []).flatMap((line) => written(line, facts, row));
		const lines = [...(section.title ? written(section.title, facts, row) : []), ...each(section.lines)];
		if (section.rows) {
			const all = rows(lookup(section.rows, facts, row));
			const most = section.limit === undefined ? Infinity : facts[section.limit];
			let total = all.length;
			if (section.line) {
				facts.shown = take(most, all);
				if (total > 0) lines.push(...written(section.line, facts, row));
			} else {
				const listed = all.flatMap((item) => written(section.row, facts, item).map((text) => ({ item, text })));
				total = listed.length;
				for (const { item, text } of take(most, listed)) lines.push(text, ...(section.under ?? []).flatMap((inner) => sectionLines(inner, facts, item)));
			}
			if (total === 0 && section.empty) lines.push(...written(section.empty, facts, row));
			// So a short list is never read as a whole one.
			if (section.more && total > most) lines.push(...written(TEXT.more, { hidden: total - most, what: section.more }));
		}
		return [...lines, ...each(section.after)];
	}

	const refusal = (name, facts) => new Error(fill(TEXT.refusals[name], facts));

	// --- one observation -----------------------------------------------------------------------

	// How much of an evidence record's id the engine shows, in a tag and in a report, and takes in record_finding.
	const SHOWN_ID = 8;

	/** The id of the evidence record a call left, as it is cited. The engine says it as data: the text is the binary's own and may hold anything. */
	const evidenceId = (details) => (typeof details.evidenceId === "string" ? details.evidenceId.slice(0, SHOWN_ID) : undefined);

	/**
	 * The whole of what rizin printed for a call. A result's text is the header line, the output,
	 * and, when the call left an evidence record, one last line that names it; past the size cap the output in the text is cut — for a `*j` command,
	 * whose JSON is one line, cut to nothing — and the engine keeps all of it as a session
	 * artifact, which eval's own read() returns raw. A recipe that parsed cut JSON would report a
	 * binary with no functions, so when the whole output cannot be had it stops and says so.
	 */
	async function wholeOutput(run, label, text, details) {
		const afterHeader = (full) => (full.includes("\n") ? full.slice(full.indexOf("\n") + 1) : "");
		const recorded = evidenceId(details) !== undefined && text.includes("\n");
		if (details.truncated !== true) return afterHeader(recorded ? text.slice(0, text.lastIndexOf("\n")) : text);
		const lost = (why, more) => refusal("cutOutput", { recipe: run.name, label, why: fill(TEXT.refusals[why], more) });
		const artifact = details.artifactId;
		if (typeof artifact !== "string") throw lost("cutNoArtifact");
		let full;
		try {
			full = await read(`artifact://${artifact}`);
		} catch (error) {
			throw lost("cutUnreadable", { artifact, error: error instanceof Error ? error.message : String(error) });
		}
		if (typeof full !== "string") throw lost("cutNotText", { artifact });
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
		const id = evidenceId(details);
		if (id) run.evidence.push({ label, id });
		// Only a call that printed something carries the command it ran; "(no output)" is the engine's words, not rizin's.
		const raw = Array.isArray(details.commands) ? await wholeOutput(run, label, text, details) : "";
		return { raw, id };
	}

	/** observe() for a `*j` command: its data, absent when the output was empty or not JSON. */
	async function observeJson(run, command, addr) {
		const { raw, id } = await observe(run, command, addr);
		return { data: parseJson(trim(raw)), id };
	}

	// --- one recipe, from the data ---------------------------------------------------------------

	/**
	 * A recipe run as the data spells it: its options settled, its steps taken in order — a read,
	 * or a fact worked out below — and its title and sections filled from what those left, over
	 * the list of the reads it took, so every line can be traced and cited.
	 */
	async function runRecipe(recipe, addr, given) {
		// What one call keeps: the reads it took, the function list once a caller had to be named, and the facts its templates name.
		const facts = { ...LIMITS, recipe: recipe.name, listFunctions: HOST.listFunctions };
		const run = { name: recipe.name, evidence: [], functions: undefined, facts };
		if (given !== undefined && given !== null && !isObject(given)) throw refusal("optionsNotOneObject", { ...facts, given: JSON.stringify(given) ?? String(given) });
		if (recipe.takes) {
			// The engine judges what may follow `@` on every read, so only what it cannot be asked is refused here.
			if (typeof addr !== "string") throw refusal("notAString", { ...facts, given: encode(addr) });
			facts.addr = addr;
		}
		for (const option of recipe.options) {
			const value = get(given, option.name);
			facts[option.name] = option.flag ? value !== false : bounded(value, option.default, option.least, option.most);
		}
		for (const step of recipe.steps) {
			if (step.derive) await FACTS[step.derive](run, facts);
			else {
				const { data, id } = await observeJson(run, step.command, step.at ? facts.addr : undefined);
				facts[step.read] = data;
				facts[`@${step.read}`] = id;
			}
		}
		return [
			...written(recipe.title, facts),
			...recipe.sections.flatMap((section) => ["", ...sectionLines(section, facts)]),
			"",
			TEXT.evidenceTaken,
			...run.evidence.flatMap((read) => written(TEXT.evidenceRow, facts, read)),
		].join("\n");
	}

	// --- what an import is called ----------------------------------------------------------------

	const IMPORT_NAME_RULES = {
		dropThrough: (name, text) => (name.includes(text) ? name.slice(name.indexOf(text) + text.length) : name),
		dropPrefix: (name, text) => (name.startsWith(text) ? name.slice(text.length) : name),
		dropLeading: (name, text) => {
			let at = 0;
			while (name.startsWith(text, at)) at += text.length;
			return name.slice(at);
		},
		dropSuffix: (name, text) => (name.endsWith(text) ? name.slice(0, -text.length) : name),
	};

	/** An import's name as the tables spell it: the decorations a linker or a fortified libc adds are taken off, by the data's rules in their order. */
	const bareImportName = (given) => TABLES.importNameRules.reduce((name, { rule, text }) => IMPORT_NAME_RULES[rule](name, text), given ?? "");

	const riskyImport = (bare) => TABLES.riskyImports.find((row) => row.names.includes(bare));
	const importCapabilities = (bare) => TABLES.capabilities.filter((row) => row.names.includes(bare)).map((row) => row.capability);

	/** `address` as "function+0xoffset" when it lies in a function rizin found, else as the bare address. The function list is one more read, taken the first time a name is wanted. */
	async function functionContaining(run, address) {
		if (run.functions === undefined) {
			run.functions = [];
			for (const fn of rows((await observeJson(run, "aflj")).data)) {
				const low = num(fn, "offset") ?? num(fn, "addr");
				const high = num(fn, "maxbound") ?? (low === undefined ? undefined : plus(low, num(fn, "size") ?? 0));
				if (low !== undefined && high !== undefined) run.functions.push({ low, high, name: str(fn, "name") ?? TEXT.nameless });
			}
		}
		const fn = run.functions.find((row) => row.low <= address && address < row.high);
		if (!fn) return hex(address);
		return address == fn.low ? fn.name : `${fn.name}+${hex(minus(address, fn.low))}`;
	}

	/** Where `address` is referenced from, each as "function+0xoffset", with the evidence id of the read: what a row is traced with. */
	async function tracedTo(run, address) {
		const { data, id } = await observeJson(run, "axtj", hex(address));
		const places = [];
		for (const row of rows(data)) {
			const from = num(row, "from");
			if (from !== undefined) places.push(await functionContaining(run, from));
		}
		return { traced: true, places: uniqueFirst(places), "@places": id };
	}

	// --- what a pdfj reply holds -------------------------------------------------------------------

	const functionOps = (body) => rows(get(body, "ops"));
	const opIs = (op, kind) => OP_TYPES[kind].includes(str(op, "type"));

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

	/** Each string an instruction of `ops` refers to, as { op, target, text }. */
	function stringReferences(ops, stringData) {
		const stringAt = stringsByAddress(stringData);
		return ops.flatMap((op) => opTargets(op).flatMap((target) => (stringAt.get(target) === undefined ? [] : [{ op, target, text: stringAt.get(target) }])));
	}

	// --- the facts a section needs code for ----------------------------------------------------------

	// Each is a step some recipe names in the data; it leaves the facts the data's `facts` lists for it.
	const FACTS = {
		triage(_run, facts) {
			const sections = rows(facts.sectionData)
				.filter((section) => trim(str(section, "name") ?? "") !== "")
				.map((section) => {
					const perm = str(section, "perm") ?? "";
					const given = get(section, "entropy");
					const entropy = typeof given === "number" ? given : typeof given === "string" ? numberFromText(trim(given)) : undefined;
					// What stands out: writable and executable at once, or data that looks compressed or encrypted where code should be.
					const notes = [];
					if (perm.includes("w") && perm.includes("x")) notes.push(NOTES.writableExecutable);
					if (entropy !== undefined && entropy >= THRESHOLDS.veryHighEntropy) notes.push(NOTES.veryHighEntropy);
					else if (entropy !== undefined && entropy >= THRESHOLDS.highEntropyForCode && perm.includes("x")) notes.push(NOTES.highEntropyForCode);
					if (PACKER_SECTION_NAMES.test(str(section, "name"))) notes.push(NOTES.packerName);
					return { section, entropy, notes };
				});
			const imports = rows(facts.imports);
			const bare = imports.map((entry) => bareImportName(str(entry, "name")));
			const codeSize = (fn) => num(fn, "realsz") ?? num(fn, "size") ?? 0;
			facts.sections = sections;
			facts.flagged = sections.filter(({ notes }) => notes.length > 0);
			facts.reach = uniqueFirst(bare.flatMap(importCapabilities));
			facts.riskyShown = take(LIMITS.triageRiskyImports, uniqueLast(bare.filter(riskyImport)));
			facts.fewImports = imports.length < THRESHOLDS.fewImports && get(facts.info, "static") !== true;
			facts.notable = STRING_INTEREST.flatMap(({ kind, pattern }) => rows(facts.strings).flatMap((entry) => (pattern.test(str(entry, "string") ?? "") ? [{ kind, entry }] : [])));
			// Largest first; functions of one size stay in rizin's order.
			facts.functions = [...rows(facts.functionData)].sort((a, b) => (codeSize(b) > codeSize(a) ? 1 : codeSize(b) < codeSize(a) ? -1 : 0));
		},

		async scanImports(run, facts) {
			const named = rows(facts.imports).map((entry) => ({ entry, bare: bareImportName(str(entry, "name")) }));
			const rank = ({ verdict }) => TABLES.severityOrder.indexOf(verdict.severity);
			const risky = named.flatMap(({ entry, bare }) => (riskyImport(bare) ? [{ entry, bare, verdict: riskyImport(bare) }] : [])).sort((a, b) => rank(a) - rank(b));
			facts.reach = TABLES.capabilities.flatMap(({ capability, names }) => {
				const linked = uniqueLast(named.map(({ bare }) => bare).filter((bare) => names.includes(bare)));
				return linked.length > 0 ? [{ capability, names: linked }] : [];
			});
			facts.risky = [];
			for (const { entry, bare, verdict } of risky) {
				const plt = num(entry, "plt");
				// An import rizin gives no name is its own bare name: nothing to say it was linked as.
				const linked = str(entry, "name") ?? bare;
				const traced = facts.callers && plt !== undefined ? await tracedTo(run, plt) : {};
				facts.risky.push({ severity: verdict.severity, category: verdict.category, why: verdict.why, bare, linkedAs: linked === bare ? undefined : linked, plt, ...traced });
			}
		},

		theFunction(_run, facts) {
			facts.info = rows(facts.infoData)[0];
			if (!isObject(facts.info)) throw refusal("noFunction", facts);
		},

		async inspectFunction(run, facts) {
			const ops = functionOps(facts.body);
			const { places, "@places": id } = await tracedTo(run, num(facts.info, "offset") ?? num(facts.info, "addr") ?? 0);
			facts.callers = places;
			facts["@callers"] = id;
			facts.ops = ops;
			facts.calls = uniqueFirst(ops.filter((op) => opIs(op, "call")).map((op) => afterWord(str(op, "disasm") ?? "", TABLES.calleeAfter)));
			facts.compares = ops.filter((op) => opIs(op, "compare")).length;
			facts.branches = ops.filter((op) => opIs(op, "branch")).length;
			facts.variableCount = isObject(facts.variables) ? Object.values(facts.variables).reduce((sum, kind) => sum + rows(kind).length, 0) : 0;
			facts.referenced = uniqueLast(
				stringReferences(ops, facts.strings).map(({ target, text }) => ({ address: target, text })),
				(reference) => reference.address,
			);
		},

		functionBody(_run, facts) {
			facts.ops = functionOps(facts.body);
			if (facts.ops.length === 0) throw refusal("noInstructions", facts);
		},

		findComparisons(_run, facts) {
			const { ops } = facts;
			facts.decisions = ops.flatMap((op, index) => {
				if (!opIs(op, "compare")) return [];
				// The branch that follows it, when one does: which way it goes is the mnemonic's to say.
				const next = isObject(ops[index + 1]) && opIs(ops[index + 1], "branch") ? ops[index + 1] : undefined;
				const mnemonic = (words(str(next, "disasm") ?? "")[0] ?? "").toLowerCase();
				const meaning = next && (TABLES.branchMeanings.find((row) => row.mnemonics.includes(mnemonic))?.meaning ?? TABLES.otherBranch);
				// A compare against a printable character says which: a run of these is a string compared a byte at a time.
				const value = num(op, "val") ?? num(op, "ptr");
				const printable = Number.isInteger(value) && value >= 32 && value <= 126 ? String.fromCharCode(value).replace(/["\\]/g, "\\$&") : undefined;
				return [{ op, printable, next, meaning }];
			});
			facts.decidingCalls = ops.filter((op) => opIs(op, "decidingCall") && COMPARING_CALLS.test(str(op, "disasm") ?? ""));
			facts.onTheWay = uniqueLast(
				stringReferences(ops, facts.strings).map(({ op, target, text }) => ({ offset: num(op, "offset") ?? 0, target, text })),
				(reference) => `${reference.offset} ${reference.target}`,
			);
		},

		async findCrypto(run, facts) {
			facts.hits = [];
			for (const { algorithm, what, hex: bytes } of TABLES.cryptoConstants) {
				// Each search is a read on the record whether or not it finds anything; only a hit is reported.
				const { data, id } = await observeJson(run, `/xj ${bytes}`);
				for (const row of rows(data)) {
					const address = num(row, "address") ?? num(row, "offset") ?? num(row, "addr");
					// So few bytes occur by chance: a hit means little on its own.
					if (address !== undefined) facts.hits.push({ algorithm, what, address, "@hit": id, weak: bytes.length <= THRESHOLDS.shortConstantHexDigits });
				}
			}
			if (facts.references) for (const hit of take(LIMITS.cryptoHits, facts.hits)) Object.assign(hit, await tracedTo(run, hit.address));
		},
	};

	// --- what is handed to eval ----------------------------------------------------------------------

	globalThis.re = {
		...Object.fromEntries(TABLES.recipes.map((recipe) => [recipe.call, recipe.takes ? async (addr, given) => runRecipe(recipe, addr, given) : async (given) => runRecipe(recipe, undefined, given)])),
		help: () => HOST.help,
	};
	// A %load cell shows the value of the script's last expression, and the source is not echoed: say what now exists.
	return HOST.loaded;
})();
