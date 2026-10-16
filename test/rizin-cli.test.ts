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
	id: { summary: "Load PDB" },
	aoe: { summary: "Emulate op" },
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
		for (const command of ["!id", "!!id", "& dc", "&t dc", "&= 0", "3 px", "wx 90", "e io.cache=true", "o /etc/passwd", "s main", "afn evil", "CC note", "pfw x", "agw /tmp/g", "id /tmp/x.pdb", "$a=!id", ".!id", "(m;!id)"]) {
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
