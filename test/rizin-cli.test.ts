/**
 * The rizin CLI bridge: catalog.ts's command policy and help search, checked
 * against a small synthetic catalog (no rizin needed), then rizin_help,
 * rizin_command, and the required-command compatibility check against the
 * installed rizin's real `?*j` catalog.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
	checkRizinCommand,
	isKnownCommand,
	isRunnable,
	loadCatalog,
	missingRequiredCommands,
	REQUIRED_COMMANDS,
	type RzCatalog,
	type RzCommandSpec,
	searchCatalog,
} from "../extensions/re/catalog.ts";
import { addrOf, eaFromOffset, RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import { cleanStderr, registerRizinTools } from "../extensions/re/tools-rizin.ts";
import { canRunRizin, captureError, logSkip, makeHarness, rizinAvailable, rizinPath, TEST_BINARY, textOf } from "./helpers.ts";

logSkip("rizin CLI integration tests");

const SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
	pd: { args_str: " [<n>]", summary: "Disassemble N instructions", args: [{ type: "number", name: "n" }] },
	pdf: { args_str: "", summary: "Disassemble a function" },
	pdsf: { args_str: "", summary: "Summarize the current function" },
	px: { args_str: " [<n>]", summary: "Show hexdump", args: [{ type: "number", name: "n" }] },
	pr: { args_str: " [<n>]", summary: "Print raw bytes" },
	prx: { args_str: " [<n>]", summary: "Printable chars with real offset" },
	p6d: { args_str: " [<n>]", summary: "Base64 decoding" },
	ph: {
		args_str: " <algo>",
		summary: "Prints a hash/message digest or entropy (use @! to change the block size)",
		args: [{ type: "choice", name: "algo", required: true, choices: ["md5", "entropy"] }],
	},
	pfw: { summary: "Write a format" },
	"/x": { args_str: " <hex>", summary: "Search hex string", args: [{ type: "string", name: "hex", required: true }] },
	"/F": { args_str: " <file>", summary: "Search the content of a file.", args: [{ type: "string", name: "file", required: true }] },
	"/m": { args_str: " [<magic-file>]", summary: "Magic constants search.", args: [{ type: "string", name: "magic-file" }] },
	axl: { summary: "List all xrefs" },
	axlj: { summary: "List all xrefs (JSON mode)" },
	axlq: { summary: "List all xrefs (quiet mode)" },
	axg: { summary: "Show xrefs graph to reach function at current seek" },
	axgj: { summary: "Show xrefs graph to reach function at current seek (JSON mode)" },
	aai: { summary: "Print preformed analysis details" },
	aaij: { summary: "Print preformed analysis details (JSON mode)" },
	aau: { summary: "Print memory areas not covered by functions" },
	afbr: { summary: "Show addresses of instructions which leave the function" },
	afns: { summary: "Print all strings referenced by the function in current seek" },
	afnsj: { summary: "Print all strings referenced by the function in current seek (JSON mode)" },
	afsb: { summary: "Outputs the function signature bytes, mask and search mask at current address" },
	afsbj: { summary: "Outputs the function signature bytes, mask and search mask at current address (JSON mode)" },
	afcl: { summary: "List all available calling conventions" },
	afclj: { summary: "List all available calling conventions (JSON mode)" },
	afcr: { summary: "Show register usage for the current function" },
	afcrj: { summary: "Show register usage for the current function (JSON mode)" },
	afx: { summary: "Info all fcn variables/args" },
	afd: { summary: "Show function + delta for given offset" },
	afvf: { summary: "Show BP relative stackframe variables" },
	afvc: { summary: "List value constraints of all variables / of the given one" },
	afvcj: { summary: "List value constraints of all variables / of the given one (JSON mode)" },
	idj: { summary: "Show DWARF source lines information (JSON mode)" },
	idq: { summary: "Show DWARF source lines information (quiet mode)" },
	id: { summary: "Show DWARF source lines information" },
	idp: { summary: "Load PDB file information" },
	fl: { summary: "List all flags" },
	"fl.": { summary: "List all flags at the current offset" },
	"fd.": { summary: "Describe flags for the current offset" },
	fi: { summary: "Show the flags in the block or custom range" },
	fg: { summary: "Show the flag graph" },
	fsl: { summary: "Display flagspaces" },
	fssl: { summary: "Display flagspace stack" },
	ftl: { summary: "List all flag tags" },
	"fz.": { summary: "Show around flag zone context" },
	"afclk": { summary: "List all available calling conventions (sdb mode)" },
	"afcll": { summary: "List all available calling conventions (verbose mode)" },
	"flj": { summary: "List all flags (JSON mode)" },
	"flq": { summary: "List all flags (quiet mode)" },
	"flt": { summary: "List all flags (table mode)" },
	"f.l": { summary: "List the local flags for the function" },
	"f.lj": { summary: "List the local flags for the function (JSON mode)" },
	"f.lq": { summary: "List the local flags for the function (quiet mode)" },
	"fij": { summary: "Show the flags in the block or custom range (JSON mode)" },
	"fiq": { summary: "Show the flags in the block or custom range (quiet mode)" },
	"fit": { summary: "Show the flags in the block or custom range (table mode)" },
	"fslj": { summary: "Display flagspaces (JSON mode)" },
	"fslq": { summary: "Display flagspaces (quiet mode)" },
	"fsslj": { summary: "Display flagspace stack (JSON mode)" },
	"ftlj": { summary: "List all flag tags (JSON mode)" },
	"ftll": { summary: "List all flag tags (verbose mode)" },
	"fzlj": { summary: "List all flag zones (JSON mode)" },
	fzl: { summary: "List all flag zones" },
	fL: { summary: "Show the flag length / Set the flag length" },
	fN: { summary: "Show the realname of the flag / Set the realname of the flag" },
	fs: { summary: "Select flagspace" },
	"/R": { args_str: " [<re>]", summary: "Search rop gadgets", description: "Find gadgets ending in ret" },
	izj: { summary: "List strings in data sections (JSON mode)" },
	agc: { args_str: " [<format>]", summary: "Global callgraph" },
	agw: { summary: "Write graph to file" },
	afn: { summary: "Rename function" },
	CC: { summary: "Add comment" },
	wx: { summary: "Write hex" },
	e: { summary: "Get/set config" },
	o: { summary: "Open file" },
	s: { summary: "Seek" },
	aoe: { summary: "Emulate op" },
	"cc": { summary: "Compare hexdump of data of block size at <addr> with the data at current offset" },
	"ccc": { summary: "Show different lines between hexdump of a block of data at <addr> wth the data at current offset" },
	"ccd": { summary: "Compare disassembly of block size at <addr> and at the current offset" },
	"cX": { summary: "Compare hexdump of data of block size at <addr> with the data at current offset using hexdiff output" },
	"cXj": { summary: "Compare hexdump of data of block size at <addr> with the data at current offset using hexdiff output (JSON mode)" },
	"cfj": { summary: "Compare the contents of <file> with the data at current offset (JSON mode)" },
	"cu": { summary: "Compare data at <offset> with the current offset" },
	"cu1": { summary: "Compare bytes at <offset> with the current offset" },
	"cu2": { summary: "Compare words (16-bit) at <offset> with the current offset" },
	"cu4": { summary: "Compare dwords (32-bit) at <offset> with the current offset" },
	"cu8": { summary: "Compare qwords (64-bit) at <offset> with the current offset" },
	"cud": { summary: "Compare disassembly at <offset> with the current offset" },
	"%v": { summary: "Show last expression ($?) or currently evaluated <expr>" },
	"%vi": { summary: "Show last expression ($?) or currently evaluated <expr> as integer" },
	"%vi1": { summary: "Show last expression ($?) or currently evaluated <expr> as 1 byte integer" },
	"%vi2": { summary: "Show last expression ($?) or currently evaluated <expr> as 2 bytes integer" },
	"%vi4": { summary: "Show last expression ($?) or currently evaluated <expr> as 4 bytes integer" },
	"%vi8": { summary: "Show last expression ($?) or currently evaluated <expr> as 8 bytes integer" },
	"%X": { summary: "Show evaluated expression <expr> in hex" },
	"%x": { summary: "ASCII string to hex string" },
	"%b64": { summary: "Encode <str> in Base64" },
	"%b": { summary: "Print <expr> in binary format" },
	"%o": { summary: "Print <expr> in octal format" },
	"%u": { summary: "Convert <expr> to K, M, G, T etc... units" },
	"%l": { summary: "Calculate length of string <str>. Quiet mode stores value in `$?` register." },
	"%lq": { summary: "Calculate length of string <str>. Quiet mode stores value in `$?` register. (quiet mode)" },
	"%h": { summary: "Print hash value of string <str>" },
	"%f": { summary: "Treat given string as bitstring and get selected characters from bitstring using given value. Bits that are flagged in value are used to get characters from given string. Bitstring is treated in big-endian format" },
	"%s": { summary: "Generate sequence of numbers from <start> to <stop> with <step> increments" },
	"%btw": { summary: "Check if <middle> number is between <first> and <last>" },
	"%P": { summary: "Convert physical to virtual address" },
	"%p": { summary: "Virtual to physical address conversion" },
	"%w": { summary: "Get references of given address" },
	"%B": { summary: "There are multiple search modes in Rizin that can be listed using the command `e search.in=?`. This command can be used to get boundaries of those search modes." },
	"%Bj": { summary: "There are multiple search modes in Rizin that can be listed using the command `e search.in=?`. This command can be used to get boundaries of those search modes." },
	"%Bt": { summary: "There are multiple search modes in Rizin that can be listed using the command `e search.in=?`. This command can be used to get boundaries of those search modes." },
	"%$": { summary: "Print Rizin variables and their values" },
	"%j": { summary: "Evaluate numerical expression <expr> (JSON mode)" },
	"y": { summary: "Yank bytes / Show yank contents" },
	"yj": { summary: "Yank bytes / Show yank contents (JSON mode)" },
	"yq": { summary: "Yank bytes / Show yank contents (quiet mode)" },
	"ys": { summary: "Print contents of clipboards as string" },
	"yx": { summary: "Print contents of clipboard in hexadecimal" },
	"as": { summary: "Show syscall and arguments" },
	"asl": { summary: "List syscalls" },
	"aslj": { summary: "List syscalls (JSON mode)" },
	"asn": { summary: "Returns the syscall number by the name" },
	"asr": { summary: "Returns the syscall name by the number" },
	"ol": { summary: "List opened files" },
	"olj": { summary: "List opened files (JSON mode)" },
	"olq": { summary: "List opened files (quiet mode)" },
	"olt": { summary: "List opened files (table mode)" },
	"obl": { summary: "List opened binary files" },
	"oblj": { summary: "List opened binary files (JSON mode)" },
	"oblq": { summary: "List opened binary files (quiet mode)" },
	"oblt": { summary: "List opened binary files (table mode)" },
	"oml": { summary: "List maps of all file descriptor or only the specified <fd>" },
	"omlj": { summary: "List maps of all file descriptor or only the specified <fd> (JSON mode)" },
	"omlq": { summary: "List maps of all file descriptor or only the specified <fd> (quiet mode)" },
	"omlQ": { summary: "List maps of all file descriptor or only the specified <fd> (quietest mode)" },
	"omlt": { summary: "List maps of all file descriptor or only the specified <fd> (table mode)" },
	"md": { summary: "Displays information about marks. Without arguments, it describes all marks that contain the current offset. With a <name> argument, it shows details of that mark and the distance in bytes from the current offset to reach the mark. If the mark begins after the current offset, it shows <name> - <bytes> (distance from current offset to  start of the mark). If the mark ends before the current offset, it shows  <name> + <bytes> (distance from current offset to the end of the mark)." },
	"mdj": { summary: "Displays information about marks. Without arguments, it describes all marks that contain the current offset. With a <name> argument, it shows details of that mark and the distance in bytes from the current offset to reach the mark. If the mark begins after the current offset, it shows <name> - <bytes> (distance from current offset to  start of the mark). If the mark ends before the current offset, it shows  <name> + <bytes> (distance from current offset to the end of the mark)." },
	"mdt": { summary: "Displays information about marks. Without arguments, it describes all marks that contain the current offset. With a <name> argument, it shows details of that mark and the distance in bytes from the current offset to reach the mark. If the mark begins after the current offset, it shows <name> - <bytes> (distance from current offset to  start of the mark). If the mark ends before the current offset, it shows  <name> + <bytes> (distance from current offset to the end of the mark)." },
	"mi": { summary: "Show marks in the current block or in the next <size> bytes." },
	"mij": { summary: "Show marks in the current block or in the next <size> bytes. (JSON mode)" },
	"miq": { summary: "Show marks in the current block or in the next <size> bytes. (quiet mode)" },
	"mit": { summary: "Show marks in the current block or in the next <size> bytes. (table mode)" },
	"ml": { summary: "List all marks." },
	"mlj": { summary: "List all marks. (JSON mode)" },
	"mlq": { summary: "List all marks. (quiet mode)" },
	"mlt": { summary: "List all marks. (table mode)" },
	"C.": { summary: "Show all meta information at current address" },
	"C.j": { summary: "Show all meta information at current address (JSON mode)" },
	"C.l": { summary: "Show all meta information at current address (verbose mode)" },
	"sh": { summary: "List undo seek history" },
	"shj": { summary: "List undo seek history (JSON mode)" },
	"x": { summary: "Alias for 'px' (print hexdump)." },
	"xj": { summary: "Alias for 'px' (print hexdump). (JSON mode)" },
	"xc": { summary: "Alias for 'pxc' (show hexdump with comments)." },
	"aL": { summary: "List all asm/analysis plugins (e asm.arch=?) or CPU details for a plugin." },
	"aLj": { summary: "List all asm/analysis plugins (e asm.arch=?) or CPU details for a plugin. (JSON mode)" },
	"aLc": { summary: "Shows the CPU details for a specific plugin." },
	"pf": { summary: "Show data using given format string" },
	"pfj": { summary: "Show data using given format string (JSON mode)" },
	"pfq": { summary: "Show data using given format string (quiet mode)" },
	"pf.": { summary: "Show data using given named format" },
	"pf.j": { summary: "Show data using given named format (JSON mode)" },
	"pf.q": { summary: "Show data using given named format (quiet mode)" },
	"pfc": { summary: "Show data using given format string with C syntax" },
	"pfd": { summary: "Show data using given format string as DOT" },
	"pfs": { summary: "Print the size of format in bytes" },
	"pfv": { summary: "Print the value for named format" },
};
const CATALOG: RzCatalog = new Map(Object.entries(SPECS).map(([cmd, spec]) => [cmd, { ...spec, cmd }]));

function refusal(command: string, addr?: string): string {
	const check = checkRizinCommand(CATALOG, command, addr);
	if (check.ok) throw new Error(`expected ${JSON.stringify(command)} to be refused, got line ${JSON.stringify(check.line)}`);
	return check.reason;
}

describe("checkRizinCommand (no rizin needed)", () => {
	test("allows read-only commands and appends addr as the only seek", () => {
		expect(checkRizinCommand(CATALOG, "pdsf")).toEqual({ ok: true, name: "pdsf", line: "pdsf" });
		expect(checkRizinCommand(CATALOG, "  px 64 ", "main")).toEqual({ ok: true, name: "px", line: "px 64 @ main" });
		expect(checkRizinCommand(CATALOG, "/x 4889e5")).toMatchObject({ ok: true, line: "/x 4889e5" });
		expect(checkRizinCommand(CATALOG, "agc ascii", "0x401000")).toMatchObject({ ok: true, line: "agc ascii @ 0x401000" });
		// rizin lists `iz` only as its mode variants; the group name still counts as known.
		expect(checkRizinCommand(CATALOG, "iz")).toMatchObject({ ok: true, line: "iz" });
	});

	test("allows the one `@` modifier, a temporary block size", () => {
		expect(checkRizinCommand(CATALOG, "ph entropy @!4096")).toMatchObject({ ok: true, line: "ph entropy @!4096" });
		expect(checkRizinCommand(CATALOG, "ph md5 @!0x100", "main")).toMatchObject({ ok: true, line: "ph md5 @!0x100 @ main" });
	});

	test("refuses every way out of a single read-only command", () => {
		for (const [command, label] of [
			["px 16; !id", "`;`"],
			["px 16 | sh", "`|`"],
			["px 16 > /tmp/x", "redirection"],
			["px 16 < /etc/passwd", "redirection"],
			["px `!id`", "backticks"],
			["px $(id)", "substitution"],
			["px ${HOME}", "substitution"],
			["izj~password", "`~`"],
			["pdf @@ sym.*", "`@` modifiers"],
			["pdf @ main", "`@` modifiers"],
			["px @f:/etc/passwd", "`@` modifiers"],
			["px @e:io.cache=0", "`@` modifiers"],
			["px @x:9090 @ main", "`@` modifiers"], // temp-block-replace modifier
			["px @r:rsp", "`@` modifiers"], // seek-to-register modifier
			["ph entropy @!4096x", "`@` modifiers"],
			["iij 2> /tmp/x", "redirection"], // stderr redirect
			["iij H> /tmp/x", "redirection"], // html redirect
			['"px 16 !id"', "double quotes"],
			["px #!pipe sh", "`#`"],
			["px 16\\x3b", "backslashes"],
			["px 16\n!id", "line breaks"],
		] as const) {
			expect(refusal(command)).toContain(label);
		}
	});

	test("refuses every non-read-only command head, including the task (`&`) and shell (`!`) operators", () => {
		// Validated against rizin's documented prompt grammar (book: first_steps/commandline_rizin).
		for (const command of ["!id", "!!id", "& dc", "&t dc", "&= 0", "3 px", "wx 90", "e io.cache=true", "o /etc/passwd", "s main", "afn evil", "CC note", "pfw x", "agw /tmp/g", "idp /tmp/x.pdb", "$a=!id", ".!id", "(m;!id)"]) {
			const reason = refusal(command);
			expect(reason).toMatch(/is not available here|is not allowed in a command/);
		}
		expect(refusal("afn evil")).toContain("rename_function");
	});

	test("inside ax, only the read-only listings run; adds, deletes, and copies stay refused", () => {
		for (const command of ["axl", "axlj", "axlq", "axg", "axgj"]) {
			expect(checkRizinCommand(CATALOG, command)).toMatchObject({ ok: true, name: command });
		}
		for (const command of ["ax 0x40", "axc 0x40", "axC 0x40", "axd 0x40", "axs 0x40", "ax- 0x40", "ax-*", "axm 0x40"]) {
			expect(refusal(command)).toMatch(/is not available here/);
		}
	});

	test("verified read-only listings run; get/set duals and PDB loads stay refused", () => {
		for (const command of ["aai", "aaij", "aau", "afbr", "afns", "afnsj", "afsb", "afsbj", "afcl", "afclj", "afcr", "afcrj", "afd", "afvf", "afvc", "id", "idj", "idq", "fl", "flj", "flq", "flt", "fl.", "f.l", "f.lj", "fi", "fij", "fit", "fg", "fsl", "fslj", "fssl", "fsslj", "ftl", "ftlj", "ftll", "fz.", "fzl", "fzlj", "cc", "ccc", "ccd", "cX", "cXj", "cu", "cu1", "cu2", "cu4", "cu8", "cud", "%v", "%vi", "%vi4", "%X", "%x", "%b64", "%b", "%o", "%u", "%l", "%lq", "%h", "%f", "%s", "%btw", "%P", "%p", "%w", "%B", "%Bj", "%Bt", "%$", "%j", "y", "yj", "yq", "ys", "yx", "as", "asl", "aslj", "asn", "asr", "ol", "olj", "olq", "olt", "obl", "oblj", "oml", "omlj", "omlQ", "omlt", "md", "mdj", "mdt", "mi", "mij", "miq", "mit", "ml", "mlj", "mlq", "mlt", "C.", "C.j", "C.l", "sh", "shj", "x", "xj", "xc", "aL", "aLj", "aLc", "pf", "pfj", "pfq", "pf.", "pf.j", "pf.q", "pfc", "pfd", "pfs", "pfv"]) {
			expect(checkRizinCommand(CATALOG, command)).toMatchObject({ ok: true, name: command });
		}
		// get/set duals: bare form reads, but the same name with an argument writes
		for (const command of ["fL", "fN", "fs x", "fc x", "fC x", "ft x", "afvs", "afvr", "afs", "afsj", "aezv", "ar", "arj", "arr", "shu", "shr", "yy", "yt", "yz", "om /tmp/x", "asca", "m x", "pfa x", "pfo /tmp/f", "pfn fmt body", "cf /etc/passwd", "cfj /etc/passwd", "%= 1", "%0", "L /tmp/p.dll", "yp", "yf", "p6d 16"]) {
			expect(refusal(command)).toMatch(/is not available here/);
		}
		// DWARF line info reads, but PDB loading/downloading stays out
		expect(refusal("idp /tmp/x.pdb")).toMatch(/is not available here/);
		expect(refusal("idpd")).toMatch(/is not available here/);
	});

	test("refuses raw-byte printers, which would break the NUL-framed pipe", () => {
		expect(refusal("pr 64")).toContain("is not available here");
		expect(refusal("p6d 16")).toContain("is not available here");
		expect(checkRizinCommand(CATALOG, "prx 32")).toMatchObject({ ok: true });
	});

	test("refuses commands that would read a file from disk", () => {
		expect(refusal("/F /etc/passwd")).toContain("is not available here");
		expect(refusal("/m /tmp/magic")).toBe("omp-re: rizin_command: /m reads <magic-file> from disk; run it without arguments or not at all");
		expect(checkRizinCommand(CATALOG, "/m")).toMatchObject({ ok: true, line: "/m" });
	});

	test("refuses commands this rizin doesn't have, and interactive modes", () => {
		expect(refusal("pdzz")).toBe('omp-re: rizin_command: this rizin has no command "pdzz" — look it up with rizin_help');
		expect(refusal("agc interactive")).toContain("keyboard input");
		expect(refusal("   ")).toBe("omp-re: rizin_command: empty command");
	});

	test("validates addr with the same allowlist as every other tool", () => {
		expect(() => checkRizinCommand(CATALOG, "px 16", "main;!id")).toThrow("omp-re: invalid address or expression");
	});

	test("isRunnable and isKnownCommand", () => {
		expect(["pdf", "pdsf", "px", "ph", "/x", "/R", "agc", "aoe", "izj", "prx"].every(isRunnable)).toBe(true);
		expect(["pr", "prz", "p6d", "pfw", "wx", "e", "afn", "CC", "/F", "ps+", "iz-"].some(isRunnable)).toBe(false);
		expect(isKnownCommand(CATALOG, "iz")).toBe(true);
		expect(isKnownCommand(CATALOG, "pdzz")).toBe(false);
	});
});

describe("searchCatalog (no rizin needed)", () => {
	test("an exact command shows its usage and typed arguments, then its family", () => {
		const { header, lines } = searchCatalog(CATALOG, "pd");
		expect(header).toBe("rizin help: pd (3 commands)");
		expect(lines[0]).toBe("pd [<n>] — Disassemble N instructions");
		expect(lines[1]).toBe("  <n>: number, optional");
		expect(lines).toContain("related:");
		expect(lines).toContain("pdf — Disassemble a function");
	});

	test("choices and required flags are spelled out", () => {
		const { lines } = searchCatalog(CATALOG, "ph");
		expect(lines[1]).toBe("  <algo>: choice, required, one of: md5, entropy");
	});

	test("commands rizin_command refuses are marked", () => {
		const { lines } = searchCatalog(CATALOG, "pr");
		expect(lines[0]).toBe("pr [<n>] — Print raw bytes  [not runnable via rizin_command]");
		expect(lines).toContain("prx [<n>] — Printable chars with real offset");
	});

	test("keywords search summaries first, then descriptions", () => {
		const { header, lines } = searchCatalog(CATALOG, "gadgets");
		expect(header).toBe('rizin help search: "gadgets" (1 match)');
		expect(lines).toEqual(["/R [<re>] — Search rop gadgets"]);
		expect(searchCatalog(CATALOG, "zzz nothing").lines[0]).toStartWith("no command matches");
	});
});

describe("missingRequiredCommands and cleanStderr (no rizin needed)", () => {
	test("names each required command a catalog lacks", () => {
		const full: RzCatalog = new Map(REQUIRED_COMMANDS.map((cmd) => [cmd, { cmd }]));
		expect(missingRequiredCommands(full)).toEqual([]);
		const partial = new Map(full);
		partial.delete("afvlj");
		partial.delete("%v");
		expect(missingRequiredCommands(partial)).toEqual(["afvlj", "%v"]);
	});

	test("drops terminal control sequences and blank lines, keeps messages", () => {
		expect(cleanStderr("\x1b[2K\r\x1b[2K\r")).toBe("");
		expect(cleanStderr("\x1b[2K\rERROR: Flag combination '4' is invalid.\n")).toBe("ERROR: Flag combination '4' is invalid.");
	});
});

describe.skipIf(!rizinAvailable)("the installed rizin's catalog", () => {
	test("has every command omp-re's own tools send", async () => {
		const catalog = await loadCatalog(rizinPath);
		expect(catalog.size).toBeGreaterThan(1000);
		expect(missingRequiredCommands(catalog)).toEqual([]);
	});

	test("rizin_help answers from it, with argument detail", async () => {
		const catalog = await loadCatalog(rizinPath);
		const { header, lines } = searchCatalog(catalog, "ph");
		expect(header).toStartWith("rizin help: ph (");
		expect(lines[0]).toStartWith("ph ");
		expect(lines.some((line) => line.startsWith("  <"))).toBe(true);
	});
});

const harness = makeHarness("rizin-cli-test-session");
const { ctx } = harness;
const run = (name: string, params: Record<string, unknown>) => harness.tool(name).execute(`t-${name}`, params, undefined, undefined, ctx);

describe.skipIf(!canRunRizin)("rizin_help and rizin_command against rizin", () => {
	let session: RzSession;
	let mainEa: string;

	beforeAll(async () => {
		const binaryPath = await resolveBinaryPath(TEST_BINARY);
		session = await RzSession.spawn(rizinPath, binaryPath);
		const state = getState(ctx);
		state.rz = session;
		state.binaryPath = binaryPath;
		registerRizinTools(harness.pi);
		const fns = JSON.parse((await session.cmd("aflj")).trim()) as { name: string; offset?: number; addr?: number }[];
		const main = fns.find((fn) => fn.name === "main");
		if (!main) throw new Error(`rizin-cli.test setup: fixture ${TEST_BINARY} has no function named 'main'`);
		mainEa = eaFromOffset(addrOf(main)!);
	});

	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
	});

	test("rizin_help is read-tier; rizin_command asks for exec approval naming the command", () => {
		expect(harness.tool("rizin_help").approval).toBe("read");
		const approval = harness.tool("rizin_command").approval as (args: unknown) => { tier: string; reason: string };
		expect(approval({ command: "px 16", addr: "main" })).toEqual({ tier: "exec", reason: 'Run the rizin command "px 16 @ main" on the open binary.' });
	});

	test("rizin_help looks up a family and searches keywords", async () => {
		expect(textOf(await run("rizin_help", { query: "/R" }))).toStartWith("rizin help: /R (");
		const search = textOf(await run("rizin_help", { query: "entropy" }));
		expect(search).toStartWith('rizin help search: "entropy"');
		expect(search).toContain("ph ");
	});

	test("rizin_command output matches rizin's own, at the given address", async () => {
		const expected = (await session.cmd(`px 32 @ ${mainEa}`)).replace(/\n+$/, "");
		const result = await run("rizin_command", { command: "px 32", addr: mainEa });
		expect(textOf(result)).toBe(`rizin> px 32 @ ${mainEa}\n${expected}`);
		expect(result.details?.ea).toBe(mainEa);
	});

	test("rizin_command runs function summaries and block-size-scoped entropy", async () => {
		expect(textOf(await run("rizin_command", { command: "pdsf", addr: "main" })).split("\n").length).toBeGreaterThan(1);
		const entropy = textOf(await run("rizin_command", { command: "ph entropy @!4096", addr: "main" }));
		expect(entropy).toMatch(/^rizin> ph entropy @!4096 @ main\n\d+\.\d+$/);
	});

	test("a search with no hits is empty output, not an error", async () => {
		const result = await run("rizin_command", { command: "/x deadbeefcafebabe1337" });
		expect(textOf(result)).toBe("rizin> /x deadbeefcafebabe1337\n(no output)");
		expect(result.isError).toBeFalsy();
	});

	test("rizin's own error text comes back when it rejects the arguments", async () => {
		const result = await run("rizin_command", { command: "/z nosuchstring 4 20" });
		expect(result.isError).toBe(true);
		expect(textOf(result)).toContain("(no output; rizin said:)");
		expect(textOf(result)).toContain("ERROR:");
	});

	test("a refused command never reaches rizin, and the session survives every case", async () => {
		const err = await captureError(run("rizin_command", { command: "pr 64" }));
		expect(err.message).toContain('"pr" is not available here');
		expect((await session.cmd("echo alive")).trim()).toBe("alive");
		expect(session.isClosed).toBe(false);
	});
});
