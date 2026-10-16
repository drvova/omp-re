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
];

export function missingRequiredCommands(catalog: RzCatalog): string[] {
	return REQUIRED_COMMANDS.filter((cmd) => !catalog.has(cmd));
}

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
	// A command whose catalog entry takes a file or path argument (`/m <magic-file>`) reads from disk; it runs only with none given.
	const fileArg = catalog.get(checked)?.args?.find((arg) => /file|path|dir/i.test(arg.name));
	if (fileArg && trimmed !== name) {
		return { ok: false, reason: `omp-re: rizin_command: ${checked} reads <${fileArg.name}> from disk; run it without arguments or not at all` };
	}
	return { ok: true, name: specNote ? `${checked}${specNote}` : checked, line: addr ? `${trimmed} @ ${validateAddr(addr)}` : trimmed };
}

/** Whether `rizin_command` would run this command name (used to mark entries in `rizin_help`). */
export function isRunnable(name: string): boolean {
	return ALLOWED_COMMAND.test(name) && !DENIED_COMMAND.test(name);
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
