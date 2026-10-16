/**
 * rizin's own command catalog, and the policy for running rizin commands the
 * dedicated tools don't cover.
 *
 * rizin documents itself: `?*j` lists every command the installed build has
 * (plugins included) with its typed arguments and a summary. omp-re reads that
 * catalog from the user's own rizin instead of hardcoding a command list, so
 * `rizin_help` answers for exactly the version installed, `rizin_command`
 * rejects commands that build doesn't have, and the compatibility check can
 * tell the user when their rizin lacks something omp-re depends on.
 */
import { resolveRizinPath, validateAddr } from "./rizin.ts";

export interface RzArgSpec {
	type: string;
	name: string;
	required?: boolean;
	is_array?: boolean;
	is_last?: boolean;
	default?: string;
	choices?: string[];
}

export interface RzCommandSpec {
	cmd: string;
	type?: string;
	args_str?: string;
	args?: RzArgSpec[];
	summary?: string;
	description?: string;
	details?: unknown[];
}

export type RzCatalog = ReadonlyMap<string, RzCommandSpec>;

const catalogs = new Map<string, Promise<RzCatalog>>();

/** The catalog of the rizin at `rizinPath` (default: the configured one), read once per process with no binary open (`rizin -qc '?*j' --`). */
export function loadCatalog(rizinPath = resolveRizinPath()): Promise<RzCatalog> {
	let cached = catalogs.get(rizinPath);
	if (!cached) {
		cached = readCatalog(rizinPath);
		catalogs.set(rizinPath, cached);
		// A failed read (rizin missing) must not be cached: installing rizin mid-session should work.
		cached.catch(() => catalogs.delete(rizinPath));
	}
	return cached;
}

async function readCatalog(rizinPath: string): Promise<RzCatalog> {
	// `-N` (skip user rizinrc) unless overridden, so the catalog reflects the same stock command set the session spawns with; plugins still load, so plugin commands (pdg, …) appear.
	const noUserConfig = !/^(1|true|yes|on)$/i.test((process.env.OMPRE_RIZIN_LOAD_USER_CONFIG ?? "").trim());
	const proc = Bun.spawn([rizinPath, "-e", "scr.color=0", ...(noUserConfig ? ["-N"] : []), "-qc", "?*j", "--"], { stdout: "pipe", stderr: "ignore", stdin: "ignore" });
	const out = await new Response(proc.stdout).text();
	await proc.exited;
	const parsed = JSON.parse(out) as Record<string, RzCommandSpec | null>;
	const catalog = new Map<string, RzCommandSpec>();
	for (const [cmd, spec] of Object.entries(parsed)) {
		if (spec && typeof spec === "object") catalog.set(cmd, { ...spec, cmd });
	}
	return catalog;
}

/** Whether `name` is a command in the catalog, or a command group whose subcommands are (rizin lists `iz` only as `izj`, `izq`, …). */
export function isKnownCommand(catalog: RzCatalog, name: string): boolean {
	if (catalog.has(name)) return true;
	for (const cmd of catalog.keys()) if (cmd.startsWith(name)) return true;
	return false;
}

/** Every rizin command omp-re's own tools send. Checked against the installed rizin at open and by `/re status`. */
export const REQUIRED_COMMANDS: readonly string[] = [
	"aaa",
	"aflj",
	"aflc",
	"afij",
	"pdfj",
	"axtj",
	"axfj",
	"iij",
	"iEj",
	"isj",
	"izj",
	"iSj",
	"ij",
	"iej",
	"afvlj",
	"afn",
	"afvn",
	"afvt",
	"afs",
	"CC",
	"CC-",
	"CC.",
	"fdj",
	"%v",
	"echo",
// search tools: /xj search family; /R+/C prime the gadget cache for /Rj+/Cj
"/xj",
"/xrj",
"/aj",
"/vj",
"/v1j",
"/v2j",
"/v4j",
"/v8j",
"/V1j",
"/V2j",
"/V4j",
"/V8j",
"/R",
"/Rj",
"/C",
"/Cj",
// type tools
"tsj",
"tej",
"ttj",
"tfj",
"td",
"tp",
// syscall tools
"aslj",
"asn",
"asr",
// binary-info tools
"iIj",
"iej",
"irj",
"flj",
"icj",
// deobfuscate tool: block transforms + decrypt under the write cache
"wox",
"woD",
"wc-",
];

export function missingRequiredCommands(catalog: RzCatalog): string[] {
	return REQUIRED_COMMANDS.filter((cmd) => !catalog.has(cmd));
}

/**
 * Read-only commands that the family-shaped {@link ALLOWED_COMMAND} regex does
 * not cover, allowed by exact name. Every entry was confirmed read-only
 * against rizin 0.9.1 by running it on a sample: it either lists/shows or
 * returns a benign "needs an argument" usage, and never mutates. Grouped by
 * the book chapter that documents the family.
 *
 * The get/set duals are handled separately: `e <key>` (Configuration) reads a
 * value, and a `key=value` argument — the only way `e` writes — is refused in
 * {@link checkRizinCommand}; the positional duals (`tn`, `Ld`, `Lo`) live in
 * {@link NOARG_DUALS} and run only with no argument.
 */
export const READ_ONLY_EXTRAS: ReadonlySet<string> = new Set([
	// Configuration (book: configuration/*) — read a value / list / type / spaces.
	"e", "el", "elj", "elq", "ell", "elJ", "et", "es",
	// Analysis hints (book: analysis/code_analysis) — list only; the aha/ahb/… setters and ah- stay out.
	"ahl", "ahlj", "ahl.", "ahl.j",
	// Address information (book: analysis/code_analysis) — `aii` (add global import) stays out.
	"ai", "aij",
	// Classes (book: analysis/vtables) — the list/show/graph reads; bare `ac`/`acn`/`acm`/`acb`/`acv` add or rename.
	"acl", "aclj", "acll", "aci", "acij", "acil", "acg", "acbl", "acvl", "acvf",
	// Metadata & strings (book: disassembling/adding_metadata) — list/show forms; the setters (Cs/Cd/Ch/Cm/Ct/Cf, CS create, C-) stay out, and comments go through set_comment.
	"C", "Cj", "Cl",
	"Csl", "Cslj", "Cslq", "Cs.", "Cs.j", "Cs.q", "Cs.l",
	"Cdl", "Cdlj", "Cd.", "Cfl", "Cflj", "Chl", "Chlj", "Cml", "Cmlj", "Ctl", "Ctlj", "CSl", "CSlj", "CSlq",
	// Types (book: analysis/types) — lists, unions, enums, typedefs, calling-convention lists, type xrefs, typeclass reads.
	// The writers stay out: td/tdf (define → define_types tool), tfc (set cc), tn (NOARG_DUALS), tks (set typeclass), to/toe/tos (load file), tr (rename), t- (delete).
	"t", "tj", "tl",
	"tu", "tuj", "tul", "tuc", "tud",
	"te", "tej", "teb", "tec", "ted", "tef",
	"tt", "ttj", "ttc",
	"tf", "tfj", "tc", "tcd", "tcc", "tccj", "tcck", "tccl",
	"tx", "txf", "txg", "txl",
	"tk", "tkl", "tklj", "tkll", "tklt",
	// Plugin listings (book: plugins/*) — list only. The bare `L`/`L-` load/unload a plugin file; `Lo`/`Ld` are in NOARG_DUALS.
	"Ll", "Llj", "Llq", "Llt", "La", "Laj", "Laq", "Lat", "Lac", "Lacj",
	"Lc", "Lcj", "Lcq", "Lct", "LC", "LCj", "LCq", "LCt", "Lh", "Lhj", "Lhq", "Lht",
	"Li", "Lij", "Liq", "Lit", "Lp", "Lpj", "Lpq", "Lpt", "LD", "LDj", "LDq", "LDt",
	// Signatures (book: analysis/signatures) — list the FLIRT sigdb. Applying is the apply_signatures tool; Fc/Fd/Fs/Ff read or write a file.
	"Flt",
]);

/**
 * Commands that list when given no argument and mutate when given one:
 * `tn[j]` lists noreturn functions / adds one, `Ld[jqt]`/`Lo[jqt]` list
 * debug/IO plugins / set the backend or register a plugin. They run through
 * `rizin_command` only with no argument; {@link checkRizinCommand} refuses
 * them with an argument.
 */
export const NOARG_DUALS: ReadonlySet<string> = new Set([
	"tn", "tnj",
	"Ld", "Ldj", "Ldq", "Ldt",
	"Lo", "Loj", "Loq", "Lot",
]);

/**
 * Commands `rizin_command` may run: read-only families — print (`p`), info
 * (`i`), search (`/`), graphs and listings under `a`, comment and flag
 * queries. Everything else (writes `w`, config `e`, open `o`, shell `!`,
 * scripting `#!`/`.`/`(`, debugger `d`, seek, and every analysis mutation) is
 * refused; annotations go through the dedicated, undoable mutate tools.
 * Inside `ax`, only the read-only listings pass: `axt`/`axf` (refs to/from),
 * `axl[jq]` (all refs), `axgj?` (refs graph) — `ax`/`axc`/`axC`/`axd`/`axs`
 * add refs, `ax-` deletes, `axm` copies. Other verified read-only singles:
 * analysis state and coverage (`aai[j]?`, `aau`), function views (`afbr`
 * exits, `afns[j]?` strings, `afsb[j]?` signature bytes, `afcl[jlk]?`
 * calling conventions, `afcr[j]?` register usage, `afd` function+delta,
 * `afvf`/`afvc[j]?` stackframe and constraints), flag listings (`fl[jqt.]?`,
 * `f.l[jq]?`, `fi[jqt]?`, `fg`, `fsl[jq]?`, `fssl[j]?`, `ftl[jl]?`,
 * `fz.[j]?`, `fzl[j]?` — the get/set duals `fL/fN/fc/fC/ft/fs` stay out),
 * and DWARF line info (`id[jq]?` — `idp*` still refuses the PDB loads).
 * From the full-book sweep (research log in .scratch/rizin-native-feature-map.md),
 * exact-key additions (anchored `$` — the STATEFUL siblings stay out):
 * compares (`cc`, `ccc`, `ccd`, `cX[j]`, `cu[1248d]?` —
 * `cf[j]` reads its `<file>` argument from disk and stays out with `/F`;
 * `ca/cat/cb/c1/cj` unverified, stay out), expression
 * evaluators (`%v`, `%vi[1248]?`, `%X/%x/%b64/%b/%o/%u/%l[q]?/%h/%f/%s/%btw`,
 * `%P/%p/%w`, `%B[jqt]?` boundary listings, `%$`, `%j` — the `$?`-writers
 * (`%=`/`%==`/`%+`/`%-`/`%!`/`%%`), tabs (`%0/%1`) and input forms
 * (`%i*`) stay out), yank reads (`y/yj/yq/ys/yx` — `yp` prints raw bytes
 * like `pr`, `yy/yt/yz/yf` write), syscall lookups (`as/asl[j]/asn/asr` — `asc/asca` write files), IO
 * listings (`ol[jqt]?`, `obl[jqt]?`, `oml[jqQt]?` — bare `om` creates maps),
 * mark/meta reads (`md[jt]?`, `mi[jqt]?`, `ml[jqt]?`, `C.[jl]?` — `m/m+/m-`
 * write marks), seek-history listing (`sh/shj` — `shu/shr` move), `px`
 * aliases (`x/xj/xc`) and analysis-plugin listing (`aL[jc]?`). The `pf` read
 * forms pass with the print family; DENIED's lookahead keeps the
 * definition/write/load forms (`pfa/pfo/pfw/pfn/pf-`) out. C++ vtable/RTTI
 * reads (`av[j]?`, `avx[t]?`, `avrD` demangler, `avg` global listings
 * `avg[l[jqt]?|p|x[jq]?|c[j]?]` — the parsers `avr/avra/avrr`, `avD`
 * devirtualizer and `avg*` setters stay out), type prints (`tp[vx]?`,
 * `ts[jlcd]?`), sdb namespace dump (`kj`) and magic search (`pm[j]?` —
 * bare-only: the fileArg mechanism refuses its `<file/directory>` form like
 * `/m`, so DENIED no longer needs `pm`).
 *
 * Commands whose shape this family regex can't capture are listed by exact
 * name in {@link READ_ONLY_EXTRAS} (config/hints/meta/classes/types/plugin
 * listings) and {@link NOARG_DUALS} (list-vs-set positional duals), both
 * checked by {@link isRunnable} and gated in {@link checkRizinCommand}.
 */
const ALLOWED_COMMAND = /^(p|i|\/|ag|ao|ab|ax[tf]|axl[jq]?|axgj?|aai[j]?|aau|afbr|afns[j]?|afsb[j]?|afcl[jlk]?|afcr[j]?|afd|afvf|afvc[j]?|id[jq]?|f(\.l[jq]?|l[jqt.]?|i[jqt]?|g|sl[jq]?|ssl[j]?|tl[jl]?|z\.[j]?|zl[j]?)|af(l|i|b|x|vl|vx|vR|vW|vd|o|M)|CC\.|CCl|CCf|fd|c(c[jd]?|cc|X[j]?|u([1248]?|d))$|avj?$|avxt?$|avrD$|avg(l[jqt]?|p|x[jq]?|c[j]?)$|tp[vx]?$|ts[jlcd]?$|kj$|pmj?$|%(v|vi[1248]?|X|x|b64|b|o|u|lq?|h|f|s|btw|P|p|w|B[jqt]?|\$|j)$|y[jqxs]?$|as(lj?|n|r)?$|ol[jqt]?$|obl[jqt]?$|oml[jqQt]?$|md[jt]?$|mi[jqt]?$|ml[jqt]?$|C\.[jl]?$|shj?$|x[jc]?$|aL[jc]?$)/;

/**
 * Exceptions inside the allowed families, each from rizin's own summaries:
 * `po` writes operations
 * into the buffer, `pkill` kills processes, `pr`/`prz`/`prg` and `p6d` print
 * raw bytes (a NUL byte ends a `-q0` frame
 * and desyncs the session; `px`, `p8`, `prx` show the same bytes), `/F`
 * searches for a file's content, `ag[enw]` edit the custom graph or write a
 * file, `afb[ce]` set block colors/edges (`afbr` lists exits — read-only),
 * `afii` adds imports, `ica` applies
 * class flags, `idp` loads/downloads/extracts PDB files. A command name
 * carrying `+ - = ! *` adds, removes, or sets. The `pf` read forms
 * (`pf[jq]`, `pf.[jq]`, `pfc`, `pfd`, `pfs`, `pfv`, and bare `pf`) are
 * allowed by the print family above; the lookahead exempts exactly those
 * endings so every other `pf*` — `pfa` (defines flag names), `pfo` (loads a
 * format file), `pfw` (writes data), `pfn` (defines formats), `pf-` — is
 * still denied.
 */
const DENIED_COMMAND = /^(po|pw|pkill|pr(?![xc])|p6d|pf(?![jq]?$|\.[jq]?$|c$|d$|s$|v$)|\/F|ag[enw]|afb[ce]|afii|ica|idp)|[+\-=!*]/;

/**
 * The `p=`/`p==` statistical-histogram family (book: print_modes) — entropy
 * (`p=e`, `p=rj` rising/falling), chi-square, printable, strings, 0x00/0xFF
 * density, and the byte histogram — all read-only prints over the current
 * block/range. They carry `=` in the command name, which {@link
 * DENIED_COMMAND}'s get/set guard would otherwise veto, so {@link isRunnable}
 * allows them by this pattern instead. The interactive visual variants (the
 * `…v` forms, which drive an ncurses UI and would block the pipe) are excluded
 * by the trailing-`v` negative lookahead.
 */
const ENTROPY_MAP = /^p={1,2}(?![0-9A-Za-z]*v$)[0-9A-Za-z]*$/;

/**
 * Syntax refused anywhere in a raw command, because it would leave the single
 * read-only command: `;` chains, `|` pipes to a shell, `>`/`<` redirect,
 * backticks and `$(`/`${` substitute, `~` greps (and breaks `-q0` framing),
 * `@` modifiers (`@@` iterators run commands; `@f:` reads files; `@e:` sets
 * config — the tool's `addr` parameter is the only way to seek; the one
 * modifier allowed is `@!<n>`, a temporary block size, which `ph` and the
 * print commands use), `"` quotes a whole command line, `#` starts a script,
 * `\` escapes, and line breaks end the pipe line.
 */
const FORBIDDEN_SYNTAX: readonly [RegExp, string][] = [
	[/;/, "`;` (command chaining)"],
	[/\|/, "`|` (pipes)"],
	[/[<>]/, "`<`/`>` (redirection)"],
	[/`/, "backticks (command substitution)"],
	[/\$[({]/, "`$(`/`${` (substitution)"],
	[/~/, "`~` (grep)"],
	[/@(?!!(?:0x[0-9a-fA-F]+|\d+)(?:\s|$))/, "`@` modifiers other than `@!<blocksize>` (use the addr parameter to seek)"],
	[/"/, "double quotes (use single quotes)"],
	[/#/, "`#`"],
	[/\\/, "backslashes"],
	[/[\n\r\0]/, "line breaks or NUL"],
];

export type CommandCheck = { ok: true; name: string; line: string } | { ok: false; reason: string };

/** Decide whether `command` (plus an optional `addr` to run it at) may run through `rizin_command`, and build the exact line sent to rizin. */
export function checkRizinCommand(catalog: RzCatalog, command: string, addr?: string): CommandCheck {
	const trimmed = command.trim();
	if (trimmed === "") return { ok: false, reason: "omp-re: rizin_command: empty command" };
	for (const [pattern, label] of FORBIDDEN_SYNTAX) {
		if (pattern.test(trimmed)) return { ok: false, reason: `omp-re: rizin_command: ${label} is not allowed in a command` };
	}
	const name = trimmed.split(/\s+/, 1)[0]!;
	// Table-query suffix (book: tools/rz-bin/tables.md): `cmd:spec[:spec...]`
	// sorts/filters/paginates/reformats the command's table. Only the head must
	// be runnable and known; every spec part must be table-grammar-shaped
	// (column names, /sort//page//head//csv word grammar) — no paths, no
	// quoting. FORBIDDEN_SYNTAX above already removed the worst characters.
	// The spec tail rides along in the line verbatim.
	let specNote = "";
	let checked = name;
	if (checked.includes(":")) {
		const head = checked.slice(0, checked.indexOf(":"));
		const specs = checked.slice(checked.indexOf(":") + 1).split(":");
		if (!specs.every((s) => /^[A-Za-z0-9_*/.-]+$/.test(s))) {
			return { ok: false, reason: "omp-re: rizin_command: table spec parts must match [A-Za-z0-9_*/.-] (see the table query grammar)" };
		}
		checked = head;
		specNote = " (table spec)";
	}
	if (!isRunnable(checked)) {
		return {
			ok: false,
			reason: `omp-re: rizin_command: ${JSON.stringify(name)} is not available here: only read-only print, info, search, graph, and listing commands run through this tool. Use rename_function, set_comment, set_prototype, rename_variable, or set_variable_type to annotate.`,
		};
	}
	if (!isKnownCommand(catalog, checked)) {
		return { ok: false, reason: `omp-re: rizin_command: this rizin has no command ${JSON.stringify(checked)} — look it up with rizin_help` };
	}
	if (/(^|\s)interactive(\s|$)/.test(trimmed)) {
		return { ok: false, reason: "omp-re: rizin_command: interactive output modes would wait for keyboard input" };
	}
	// The argument text after the command name (table spec already stripped from `checked`).
	const argPortion = trimmed.slice(name.length).trim();
	// Configuration: `e <key>` reads a value; `e <key>=<value>` sets it. Reading is fine; setting is a write.
	if (checked === "e" && argPortion.includes("=")) {
		return { ok: false, reason: "omp-re: rizin_command: setting config variables (`e key=value`) is a write and is not allowed; `e <key>` reads a value, `el`/`elj` list them" };
	}
	// Get/set positional duals: they list with no argument and mutate with one.
	if (NOARG_DUALS.has(checked) && argPortion !== "") {
		return { ok: false, reason: `omp-re: rizin_command: ${checked} runs read-only only with no argument (an argument makes it set/add); it lists when run bare` };
	}
	// A command whose catalog entry takes a file or path argument (`/m <magic-file>`) reads from disk; it runs only with none given.
	const fileArg = catalog.get(checked)?.args?.find((arg) => /file|path|dir/i.test(arg.name));
	if (fileArg && trimmed !== name) {
		return { ok: false, reason: `omp-re: rizin_command: ${checked} reads <${fileArg.name}> from disk; run it without arguments or not at all` };
	}
	return { ok: true, name: specNote ? `${checked}${specNote}` : checked, line: addr ? `${trimmed} @ ${validateAddr(addr)}` : trimmed };
}

/** Whether `rizin_command` would run this command name (used to mark entries in `rizin_help`). The NOARG_DUALS run read-only with no argument, so they count as runnable here; `checkRizinCommand` enforces the no-argument constraint. */
export function isRunnable(name: string): boolean {
	if (READ_ONLY_EXTRAS.has(name) || NOARG_DUALS.has(name)) return true;
	if (ENTROPY_MAP.test(name)) return true;
	return ALLOWED_COMMAND.test(name) && !DENIED_COMMAND.test(name);
}

/**
 * Read-only debugger-state commands a breakpoint on-hit command (`dbc`, the
 * `break_command` debug action) may run. The static {@link checkRizinCommand}
 * policy refuses the whole `d*` family because `rizin_command` drives a static
 * session; but an on-hit command runs inside the live debugger, where logging
 * registers, maps, the backtrace, or heap state on each hit is the point.
 *
 * Every entry here was read off rizin 0.9.1's own `?*j` summaries as a pure
 * read: register/arena views (`dr*` show forms — the assign dual `dr reg=val`
 * carries `=`, refused below), memory-map/module/library listings (`dm*`
 * list/show — the `dm+`/`dm-`/`dmp`/`dml`/`dmd*` allocate/map/dump forms are
 * distinct tokens left out), heap reads (`dmhg*`/`dmhj*`), backtrace (`dbt*`
 * display — not the `dbtd`/`dbte`/`dbts` trace toggles), process/thread and
 * debug-info listings (`dp`/`dpt`/`dpl`/`dpT`/`dpe`, `di*` — not `dpa`/`dpf`
 * attach, `dpk` signal, `dp-` detach), the signal-handler listings and name/
 * number resolvers (`dkl*`/`dkN`/`dkn` — not `dk` send, `dko` set), and the
 * file-descriptor listing (`ddl*` only — `ddr`/`ddw`/`dds`/`ddd`/`dd` read/
 * write/seek/open fds, left out). Matched by exact first token, so a setter
 * sibling (`dra+`, `draw`, `drx`, `drpo`) never slips through, and any `=`
 * (register assignment, `dm=`/`dr=`/`dp=` select/display) is refused outright.
 */
const DEBUG_READ_COMMANDS: ReadonlySet<string> = new Set([
	// Registers & arenas (show forms; `dr reg=val` assign carries `=`, refused below).
	"dr", "drj", "drq", "drt", "drr", "drrj", "dro", "droj", "droq", "drot",
	"drd", "dri", "drc", "drcc", "drA", "drAj", "drF", "drR", "drT",
	"drp", "drpj", "drpc", "dra", "draS", "drab",
	// Memory maps, modules, libraries, sections.
	"dm", "dmj", "dmq", "dmt", "dm.", "dmm", "dmmj", "dmm.", "dmm.j",
	"dmi", "dmij", "dmiq", "dmi.", "dmi.j", "dmia", "dmiaj", "dmiaq", "dmS", "dmSj",
	// Heap reads.
	"dmh", "dmhg", "dmhgj", "dmhgb", "dmhgc", "dmhgm", "dmhgl", "dmhgt", "dmhja", "dmhjb", "dmhjc",
	// Backtrace display.
	"dbt", "dbtj", "dbtq", "dbtt", "dbtv", "dbta",
	// Process / threads / debug info.
	"dp", "dpj", "dpt", "dpe", "dpl", "dplj", "dplt", "dpT", "dpTj", "dpTt", "di", "dij", "diq",
	// Signal-handler listings and name/number resolvers.
	"dkl", "dklj", "dklq", "dklt", "dkN", "dkn",
	// File-descriptor listing (list only).
	"ddl", "ddlj", "ddlt",
]);

/**
 * Decide whether `command` may run as a breakpoint on-hit command (`dbc`). It
 * accepts either a vetted read-only debugger-state read ({@link
 * DEBUG_READ_COMMANDS}) or anything the static read-only policy already allows
 * (print/info/search), so an on-hit command can log the debugger's live state
 * or a static view. The forbidden-syntax guards apply either way, and any `=`
 * is refused so the register-assign dual (`dr rax=0`) can never write.
 */
export function checkDebugOnHitCommand(catalog: RzCatalog, command: string): CommandCheck {
	const trimmed = command.trim();
	if (trimmed === "") return { ok: false, reason: "omp-re: break_command: empty command" };
	for (const [pattern, label] of FORBIDDEN_SYNTAX) {
		if (pattern.test(trimmed)) return { ok: false, reason: `omp-re: break_command: ${label} is not allowed in an on-hit command` };
	}
	const name = trimmed.split(/\s+/, 1)[0]!;
	if (DEBUG_READ_COMMANDS.has(name)) {
		// `=` is the only way these turn into a write (register assignment) or a stateful select (`dm=`/`dp=`); refuse it.
		if (trimmed.includes("=")) {
			return { ok: false, reason: `omp-re: break_command: ${JSON.stringify(name)} with \`=\` would assign/select (a write); use the bare read form to log state` };
		}
		if (!isKnownCommand(catalog, name)) {
			return { ok: false, reason: `omp-re: break_command: this rizin has no command ${JSON.stringify(name)} — look it up with rizin_help` };
		}
		return { ok: true, name, line: trimmed };
	}
	// Not a debugger read — fall back to the static read-only policy (print/info/search), which does its own validation.
	const check = checkRizinCommand(catalog, command);
	if (check.ok) return check;
	return {
		ok: false,
		reason: `omp-re: break_command: ${JSON.stringify(name)} is not a read-only on-hit command. Allowed: read-only debugger state (registers \`drj\`/\`drr\`, maps \`dmj\`, modules \`dmmj\`, backtrace \`dbtj\`, heap \`dmhg\`), or a static read (print/info/search).`,
	};
}

function describeArgs(spec: RzCommandSpec): string[] {
	return (spec.args ?? []).map((arg) => {
		const facts = [
			arg.type,
			arg.required ? "required" : "optional",
			...(arg.is_array ? ["repeatable"] : []),
			...(arg.default !== undefined ? [`default ${arg.default}`] : []),
			...(arg.choices ? [`one of: ${arg.choices.join(", ")}`] : []),
		];
		return `  <${arg.name}>: ${facts.join(", ")}`;
	});
}

function oneLine(spec: RzCommandSpec): string {
	const runnable = isRunnable(spec.cmd) ? "" : "  [not runnable via rizin_command]";
	return `${spec.cmd}${spec.args_str ?? ""} — ${spec.summary ?? ""}${runnable}`;
}

/**
 * Answer a help query from the catalog. A query that names a command or
 * prefix (`afv`, `pd`, `/R`) lists that family, with full argument detail for
 * an exact match; anything else is a keyword search over summaries and
 * descriptions (`entropy`, `rop gadgets`), best matches first.
 */
export function searchCatalog(catalog: RzCatalog, query: string, limit = 60): { header: string; lines: string[] } {
	const q = query.trim();
	const exact = catalog.get(q);
	const family = [...catalog.values()].filter((spec) => spec.cmd.startsWith(q) && q !== "").sort((a, b) => a.cmd.localeCompare(b.cmd));
	if (exact || family.length > 0) {
		const lines: string[] = [];
		if (exact) {
			lines.push(oneLine(exact), ...describeArgs(exact));
			if (exact.description) lines.push(`  ${exact.description}`);
			if (Array.isArray(exact.details) && exact.details.length > 0) lines.push(`  details: ${JSON.stringify(exact.details)}`);
			if (family.length > 1) lines.push("", "related:");
		}
		const rest = family.filter((spec) => spec.cmd !== q);
		lines.push(...rest.slice(0, limit).map(oneLine));
		if (rest.length > limit) lines.push(`… ${rest.length - limit} more; narrow the prefix`);
		return { header: `rizin help: ${q} (${family.length} command${family.length === 1 ? "" : "s"})`, lines };
	}

	const words = q.toLowerCase().split(/\s+/).filter(Boolean);
	const scored = [...catalog.values()]
		.map((spec) => {
			const summary = (spec.summary ?? "").toLowerCase();
			const description = (spec.description ?? "").toLowerCase();
			let score = 0;
			for (const word of words) {
				if (summary.includes(word)) score += 2;
				else if (description.includes(word)) score += 1;
				else return { spec, score: 0 };
			}
			// Prefer the plain form over its j/q/t output-mode twins.
			return { spec, score: score - spec.cmd.length * 0.01 };
		})
		.filter((entry) => entry.score > 0)
		.sort((a, b) => b.score - a.score);
	return {
		header: `rizin help search: ${JSON.stringify(q)} (${scored.length} match${scored.length === 1 ? "" : "es"})`,
		lines: scored.length > 0 ? scored.slice(0, limit).map((entry) => oneLine(entry.spec)) : ["no command matches; try a shorter keyword or a command prefix such as p, i, /, a"],
	};
}
