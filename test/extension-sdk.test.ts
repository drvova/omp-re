/**
 * Loads extensions/re through omp's real SDK and extension runner — the same
 * loader and event dispatch an interactive session uses — with the real
 * engine behind it: an SBCL child the extension starts, and, in the second
 * half, a real rizin. Nothing here calls a model: everything is asked the way
 * a model asks it, from cells of omp's own `eval` tool, in both of its
 * kernels, through the library the re-triage skill loads there.
 *
 * This is the suite that catches host API drift, and that the extension, the
 * library and the engine still agree on the two wires between them.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { boot, bootLoaded, canRunRizin, caught, evalJs, evalPy, LOAD, logSkip, ownSession, pythonKernel, registeredByRe, runCell, type SdkHarness, scratchAgentDir, TEST_BINARY } from "./helpers.ts";

logSkip("extension-sdk rizin tests");

const agentDir = scratchAgentDir("sdk-test");
const python = await pythonKernel();
if (!python.ok) console.log(`omp-re: skipping the Python cells of extension-sdk — ${python.reason ?? "omp found no Python"}`);

describe("loaded by omp's SDK (no rizin needed)", () => {
	let h: SdkHarness;

	beforeAll(async () => {
		h = await bootLoaded(agentDir());
	});

	afterAll(async () => {
		await h.shutdown();
	});

	test("registers nothing a model or an operator calls: no tool, no slash command, no flag — and so nothing of its own under xd://", async () => {
		const bare = await boot(await ownSession(agentDir()), { extensions: [] });
		try {
			// A session without the plugin has the same commands: none of them is the plugin's.
			expect(registeredByRe(h.session)).toEqual({ tools: [], commands: registeredByRe(bare.session).commands, flags: [] });
			expect(registeredByRe(h.session).commands).not.toContain("re");
			expect(h.session.getAllToolNames().sort()).toEqual(bare.session.getAllToolNames().sort());
			expect(h.session.getMountedXdevToolNames().sort()).toEqual(bare.session.getMountedXdevToolNames().sort());
		} finally {
			await bare.shutdown();
		}
	});

	test("omp's eval reaches the engine through the library, and a refusal is an error the cell can catch", async () => {
		expect((await evalJs(h.session, caught('await re.cmd("aflj")'))).text).toBe('omp-re: no binary open — open one first: await re.open("/path/to/binary") — in Python, omp_re.open("/path/to/binary")');
		const uncaught = await evalJs(h.session, 'await re.cmd("aflj")');
		expect(uncaught.isError).toBe(true);
		expect(uncaught.text).toContain("omp-re: no binary open");
	});

	test("re.help() is the engine's manual in omp's voice, and needs no binary or rizin", async () => {
		const out = await evalJs(h.session, "const manual = await re.help(); print(manual.slice(0, 2000)); [manual.includes(\"%load skill://re-triage/recipes.py\"), manual.includes('await re.slash(\"<line>\")'), manual === await re.cmd(\"\")]");
		expect(out.isError).toBe(false);
		expect(out.text).toContain("omp-re — reverse engineering with rizin, driven from code in omp's eval.");
		expect(out.text).toContain('await re.open("/path/to/binary")');
		expect(out.text).toContain("true,\n  true,\n  true");
	});

	test("re.tools() and re.doc() are the engine's own account of its tools; a tool it does not have is refused by name", async () => {
		const tools = (await evalJs(h.session, "await re.tools()")).text.split("\n");
		expect(tools.map((line) => line.split(" — ")[0])).toEqual(expect.arrayContaining(["open_binary", "rizin_command", "rizin_help", "record_finding", "rename_function"]));
		const doc = (await evalJs(h.session, 'await re.doc("rename_function")')).text;
		expect(doc).toStartWith("rename_function\n");
		expect(doc).toContain('await re.call("rename_function", { name: value, … }) — in Python omp_re.call("rename_function", name=value, …) — takes:');
		expect(doc).toContain("\n  addr  string, required — ");
		expect((await evalJs(h.session, caught('await re.doc("no_such_tool")'))).text).toBe('omp-re: no tool named "no_such_tool" — re.tools() lists them');
		expect((await evalJs(h.session, caught('await re.call("no_such_tool", {})'))).text).toBe('omp-re: no tool named "no_such_tool" — re.tools() lists them');
	});

	test("a line the engine does not have, and one that fails, are errors in the cell; no line switches the plugin off or on", async () => {
		expect((await evalJs(h.session, caught('await re.slash("bogus")'))).text).toBe('omp-re: unknown /re subcommand "bogus" — try /re help');
		expect((await evalJs(h.session, caught('await re.slash("undo")'))).text).toBe("omp-re: no annotation left to undo");
		expect((await evalJs(h.session, caught('await re.slash("off")'))).text).toBe('omp-re: unknown /re subcommand "off" — try /re help');
		const help = (await evalJs(h.session, 'await re.slash("help")')).text;
		expect(help).toContain("/re open <path>            open a binary and analyze it with rizin");
		expect(help).not.toContain("alt+");
	});

	test("a verb given what it cannot take refuses before anything is asked of the engine, in the same words on every host", async () => {
		expect((await evalJs(h.session, caught("await re.cmd(42)"))).text).toBe("a rizin command is a string, not 42");
		expect((await evalJs(h.session, caught('await re.open("  ")'))).text).toBe('a path must be a non-empty string, not "  "');
		expect((await evalJs(h.session, caught("await re.call({})"))).text).toBe("a tool is named by a string, as await re.tools() lists them, not {}");
		expect((await evalJs(h.session, caught('await re.call("rizin_help", "pdf")'))).text).toBe('arguments are one object, e.g. { name: value }, not "pdf"');
	});

	test("a cell that uses the library in a kernel that has not loaded it is told the line that loads it; the model's code is run as written", async () => {
		const fresh = await boot(await ownSession(agentDir()), { skills: true });
		try {
			const unloaded = await evalJs(fresh.session, "await re.status()");
			expect(unloaded.isError).toBe(true);
			expect(unloaded.text).toContain("re is not defined");
			expect(unloaded.text).toEndWith(`omp-re: its library is not loaded in this kernel. Run a cell that holds only this line, then run yours again: ${LOAD.js}`);
			// Any other error is left as it is.
			expect((await evalJs(fresh.session, "nothingOfTheKind()")).text).not.toContain("omp-re:");
			expect((await evalJs(fresh.session, LOAD.js)).text).toStartWith("omp-re loaded: re.open, re.cmd, re.json, re.call, re.tools, re.doc, re.slash, re.status, re.help, and the recipes re.triage, ");
			expect((await evalJs(fresh.session, "typeof (await re.status())")).text).toBe("string");
		} finally {
			await fresh.shutdown();
		}
	});

	test.skipIf(!python.ok)("the Python kernel has the same verbs as `omp_re`, called plainly, and is told its own load line", async () => {
		const unloaded = await evalPy(h.session, "omp_re.status()");
		expect(unloaded.isError).toBe(true);
		expect(unloaded.text).toEndWith(`omp-re: its library is not loaded in this kernel. Run a cell that holds only this line, then run yours again: ${LOAD.py}`);
		expect((await evalPy(h.session, LOAD.py)).text).toStartWith("omp-re loaded: omp_re.open, omp_re.cmd, omp_re.json, omp_re.call, omp_re.tools, omp_re.doc, omp_re.slash, omp_re.status, omp_re.help, and the recipes omp_re.triage, ");
		// A text is shown as written, not as one quoted line.
		expect((await evalPy(h.session, "omp_re.status()")).text).toContain("\nbinary: none — open one first");
		const refused = await evalPy(h.session, 'try:\n    omp_re.cmd("aflj")\nexcept RuntimeError as error:\n    print(type(error).__name__, error)');
		expect(refused.text).toStartWith("RuntimeError omp-re: no binary open — open one first");
		expect((await evalPy(h.session, "try:\n    omp_re.cmd(42)\nexcept TypeError as error:\n    print(error)")).text).toBe("a rizin command is a string, not 42");
		expect((await evalPy(h.session, 'try:\n    omp_re.call("rizin_help", "pdf")\nexcept TypeError as error:\n    print(error)')).text).toBe('arguments are keywords, or one dict before them, e.g. {"name": value}, not "pdf"');
		expect((await evalPy(h.session, 'print(omp_re.help() == omp_re.cmd(""), omp_re.tools() == omp_re.slash("tools"))')).text).toBe("True True");
		// The engine's own regex module is still the kernel's `re`.
		expect((await evalPy(h.session, 'print(re.search("b+", "abbc").group())')).text).toBe("bb");
	}, 30_000);
});

describe.skipIf(!canRunRizin)("loaded by omp's SDK, against rizin", () => {
	const open = `await re.open(${JSON.stringify(TEST_BINARY)})`;

	// Opens the binary (full `aaa`) once, then replays into a freshly reopened
	// session (another `aaa`); on a cold CI/container host each analysis is a
	// few seconds, so the default 5s budget is too tight.
	test("open, annotate, and resume through eval: the reopened session replays the annotation into a fresh rizin, and a call made while it does waits for it", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const manager = (await ownSession(agentDir())) as { ensureOnDisk(): Promise<void>; getSessionFile(): string; getCwd(): string };
		await manager.ensureOnDisk();
		const first = await boot(manager, { skills: true });
		expect((await evalJs(first.session, LOAD.js)).isError).toBe(false);
		const opened = await evalJs(first.session, `${open}\nawait re.call("rename_function", { addr: "main", new: "omp_re_sdk_main" })`);
		expect(opened.isError).toBe(false);
		const file = manager.getSessionFile();
		await first.shutdown();

		// session_start brings the binary back in the background; the call below is made before that can have finished.
		const second = await boot(await SessionManager.open(file), { skills: true });
		try {
			expect((await evalJs(second.session, LOAD.js)).isError).toBe(false);
			// The engine records a read as evidence and says so twice: the id of the record as data, beside the data
			// re.json answers, and for the model a last line of the text that shows the same id.
			const result = await evalJs(
				second.session,
				'const text = await re.cmd("afij", "omp_re_sdk_main"); const lines = text.split("\\n"); JSON.stringify({ first: lines[0], last: lines.at(-1), renamed: lines.slice(1, -1).join("").includes("omp_re_sdk_main"), rows: JSON.parse(lines.slice(1, -1).join("\\n")).length })',
			);
			const { first: header, last, renamed, rows } = JSON.parse(result.text) as { first: string; last: string; renamed: boolean; rows: number };
			expect(header).toBe("rizin> afij @ omp_re_sdk_main");
			expect(renamed).toBe(true); // the replayed rename shows in rizin's own output
			expect(rows).toBeGreaterThanOrEqual(1);
			const evidence = (await evalJs(second.session, '(await re.json("afij", "omp_re_sdk_main")).evidence')).text;
			expect(evidence).toMatch(/^[0-9a-f]{8}$/);
			expect(last).toMatch(/^\[evidence [0-9a-f]{8} — cite it in record_finding\]$/);
			const recorded = second.session.sessionManager
				.getEntries()
				.filter((e) => e.type === "custom" && (e as { customType?: string }).customType === "re.evidence")
				.map((e) => (e as { data?: { id: string; tool: string } }).data!);
			expect(recorded).toContainEqual(expect.objectContaining({ tool: "rizin_command", id: expect.stringMatching(new RegExp(`^${evidence}`)) }));
			expect(second.notes.filter((n) => n.startsWith("[runtime]"))).toEqual([]);
		} finally {
			await second.shutdown();
		}
	}, 30_000);

	test("a whole analysis from JavaScript cells: open, read, read as data, record a finding, list it, write the report — the record is omp's session and the band follows", async () => {
		const h = await bootLoaded(agentDir());
		try {
			expect((await evalJs(h.session, open)).text).toStartWith("Binary opened: ");
			// How many commands the engine sends grows as tool families are added: the shape, not a frozen number.
			expect((await evalJs(h.session, "await re.status()")).text).toMatch(/rizin commands: all \d+ omp-re sends are present/);
			expect((await evalJs(h.session, 'await re.cmd("pdsf", "main")')).text).toStartWith("rizin> pdsf @ main\n");
			// re.json answers the data whole though the text of the same read is cut at the size cap, with no artifact read back.
			const big = await evalJs(h.session, 'const cut = await re.cmd("aflj"); const { data, evidence } = await re.json("aflj"); [cut.includes("[Output truncated"), Array.isArray(data) && data.length > 50, /^[0-9a-f]{8}$/.test(evidence)].join(" ")');
			expect(big.text).toBe("true true true");
			const recorded = await evalJs(h.session, 'const { evidence } = await re.json("ij"); await re.call("record_finding", { claim: "The file is a program.", evidence: [evidence], confidence: "likely" })');
			expect(recorded.text).toMatch(/^record_finding: recorded [0-9a-f]{8}\n/);
			expect((await evalJs(h.session, 'await re.slash("findings")')).text).toMatch(/^omp-re: findings\n\[[0-9a-f]{8}\] The file is a program\./);
			expect((await evalJs(h.session, 'await re.slash("report")')).text).toContain("The file is a program.");
			const kinds = h.session.sessionManager.getBranch().flatMap((entry) => (entry.type === "custom" ? [entry.customType] : []));
			expect(kinds).toEqual(expect.arrayContaining(["re.binary", "re.evidence", "re.finding"]));
			expect(h.widget("re.hud")![1]).toMatch(/^[1-9]\d* fn · 1 findings · [1-9]\d* evidence$/);
			// rizin_cli is offered when the rz-* programs are present (they ship with rizin).
			expect((await evalJs(h.session, "await re.tools()")).text).toContain("\nrizin_cli — ");
			expect(h.notes.filter((note) => note.startsWith("[runtime]") || note.startsWith("[error]"))).toEqual([]);
		} finally {
			await h.shutdown();
		}
	}, 60_000);

	test.skipIf(!python.ok)("the same analysis from Python cells, in the same session: both kernels act on the one binary and the one record", async () => {
		const h = await bootLoaded(agentDir());
		try {
			expect((await evalPy(h.session, LOAD.py)).isError).toBe(false);
			expect((await evalPy(h.session, `omp_re.open(${JSON.stringify(TEST_BINARY)})`)).text).toStartWith("Binary opened: ");
			// What Python opened is open for the JavaScript kernel: the session is one.
			expect((await evalJs(h.session, 'await re.cmd("afij", "main")')).text).toStartWith("rizin> afij @ main\n");
			expect((await evalPy(h.session, 'print(omp_re.cmd("pdsf", "main")[:18])')).text).toBe("rizin> pdsf @ main");
			expect((await evalPy(h.session, 'cut = omp_re.cmd("aflj")\ndata, evidence = omp_re.json("aflj")\nprint("[Output truncated" in cut, isinstance(data, list) and len(data) > 50, len(evidence))')).text).toBe("True True 8");
			// A raw or headerless file's options are keywords here, one object in JavaScript; an option the tool does not have is the engine's to refuse.
			expect((await evalPy(h.session, `try:\n    omp_re.open(${JSON.stringify(TEST_BINARY)}, bits="64")\nexcept RuntimeError as error:\n    print(error)`)).text).toContain("bits must be an integer");
			const recorded = await evalPy(h.session, 'read = omp_re.json("ij")\nprint(omp_re.call("record_finding", claim="The file is a program.", evidence=[read.evidence], confidence="likely"))');
			expect(recorded.text).toMatch(/^record_finding: recorded [0-9a-f]{8}\n/);
			expect((await evalPy(h.session, 'omp_re.slash("findings")')).text).toMatch(/^omp-re: findings\n\[[0-9a-f]{8}\] The file is a program\./);
			expect((await evalJs(h.session, 'await re.slash("findings")')).text).toMatch(/^omp-re: findings\n\[[0-9a-f]{8}\] The file is a program\./);
			expect(h.widget("re.hud")![1]).toMatch(/^[1-9]\d* fn · 1 findings · [1-9]\d* evidence$/);
		} finally {
			await h.shutdown();
		}
	}, 60_000);

	test("the debugger is a tool only when the operator opted in, and then it runs through a cell", async () => {
		const off = await bootLoaded(agentDir());
		try {
			expect((await evalJs(off.session, "await re.tools()")).text).not.toContain("rizin_debug");
			expect((await evalJs(off.session, caught('await re.call("rizin_debug", { action: "start" })'))).text).toBe('omp-re: no tool named "rizin_debug" — re.tools() lists them');
		} finally {
			await off.shutdown();
		}

		const prev = process.env.OMPRE_ENABLE_DEBUGGER;
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		const on = await bootLoaded(agentDir());
		try {
			expect((await evalJs(on.session, "await re.tools()")).text).toContain("\nrizin_debug — ");
			await evalJs(on.session, open);
			expect((await evalJs(on.session, 'await re.call("rizin_debug", { action: "start" })')).text).toContain("RUNNING under a debugger");
			await evalJs(on.session, 'await re.call("rizin_debug", { action: "stop" })');
		} finally {
			await on.shutdown();
			if (prev === undefined) delete process.env.OMPRE_ENABLE_DEBUGGER;
			else process.env.OMPRE_ENABLE_DEBUGGER = prev;
		}
	}, 30_000); // two full SDK boots plus a real launch; the default 5s is too tight

	test("a session omp keeps no file for reads whole data too: nothing the library needs is an artifact", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const { mkdtempSync } = await import("node:fs");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const cwd = mkdtempSync(join(tmpdir(), "omp-re-fileless-"));
		const h = await boot(SessionManager.inMemory(cwd), { skills: true, cwd });
		try {
			expect((await runCell(h.session, "js", LOAD.js)).isError).toBe(false);
			expect((await evalJs(h.session, `${open}; const { data } = await re.json("aflj"); data.length > 50`)).text).toBe("true");
		} finally {
			await h.shutdown();
		}
	}, 30_000);
});
