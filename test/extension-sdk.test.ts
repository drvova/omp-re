/**
 * Loads extensions/re through omp's real SDK and extension runner — the same
 * loader, tool wrappers (approval and tool events), and command dispatch an
 * interactive session uses — with the real engine behind it: an SBCL child
 * the extension starts, and, in the second half, a real rizin. Nothing here
 * calls a model: slash commands are handled locally and tools are executed
 * straight from the session's tool registry.
 *
 * This is the suite that catches host API drift, and that the extension and
 * the engine still agree on the wire between them.
 *
 * Every RE tool is `discoverable` (render.ts `RE_LOAD_MODE`), so omp mounts it
 * as an `xd://` device rather than listing it top-level, and the model drives
 * it from omp's own `eval` tool as `await tool.<name>({ ... })`. These tests go
 * through that same path.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { engine, outside } from "../extensions/re/host.ts";
import { activeRe, boot, canRunRizin, caught, evalJs, logSkip, mountedRe, reTools, type SdkHarness, scratchAgentDir, TEST_BINARY } from "./helpers.ts";

logSkip("extension-sdk rizin tests");

const agentDir = scratchAgentDir("sdk-test");

describe("loaded by omp's SDK (no rizin needed)", () => {
	let h: SdkHarness;

	beforeAll(async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		h = await boot(SessionManager.inMemory());
	});

	afterAll(async () => {
		await h.shutdown();
	});

	test("registers exactly the tools the engine describes, each as an xd:// device — none in the top-level tool list", async () => {
		const described = (await engine().request("describe", {})).tools.map((tool) => tool.name).sort();
		// The ones every session has, whatever is installed: a sample, so an engine that describes nothing does not pass.
		expect(described).toEqual(expect.arrayContaining(["open_binary", "rizin_command", "rizin_help", "record_finding", "rename_function"]));
		expect(reTools(h.session).map((tool) => tool.definition.name).sort()).toEqual(described);
		expect(mountedRe(h.session).sort()).toEqual(described);
		expect(activeRe(h.session)).toEqual([]);
	});

	test("omp's eval reaches an RE tool as tool.<name>(), and its error is catchable in the cell", async () => {
		expect((await evalJs(h.session, caught('await tool.rizin_command({ command: "aflj" })'))).text).toBe("omp-re: no binary open — use /re open <path>, open_binary, or --binary <path> first");
	});

	test("an empty rizin_command returns the omp-re manual — the one-tool entry, no binary or rizin needed", async () => {
		const out = await evalJs(h.session, '(await tool.rizin_command({ command: "" })).text');
		expect(out.isError).toBe(false);
		expect(out.text).toContain("omp-re — reverse engineering with rizin");
		expect(out.text).toContain("await tool.rizin_command(");
		expect(out.text).toContain("await tool.rizin_help(");
	});

	test("/re off refuses RE tool calls from eval while the devices stay mounted, and /re on lifts it", async () => {
		await h.session.prompt("/re off");
		expect((await evalJs(h.session, caught('await tool.rizin_command({ command: "aflj" })'))).text).toBe("omp-re: RE tools are off for this session — the user can re-enable them with /re on");
		expect(mountedRe(h.session)).toContain("rizin_command");
		await h.session.prompt("/re on");
		expect(h.notes.at(-1)).toBe("[info] omp-re: RE tools enabled for this session");
		expect((await evalJs(h.session, caught('await tool.rizin_command({ command: "aflj" })'))).text).toContain("omp-re: no binary open");
		expect(activeRe(h.session)).toEqual([]);
	});

	test("/re completes subcommands", () => {
		const command = h.session.extensionRunner!.getCommand("re")!;
		expect(command.getArgumentCompletions!("st")).toEqual([
			expect.objectContaining({ value: "strings ", label: "strings" }),
			expect.objectContaining({ value: "status ", label: "status" }),
		]);
	});

	test("bare /re shows help, an unknown subcommand is an error, and undo with nothing open says so", async () => {
		await h.session.prompt("/re");
		expect(h.notes.at(-1)).toContain("/re open <path>            open a binary and analyze it with rizin");
		expect(h.notes.at(-1)).toContain("alt+g functions");
		await h.session.prompt("/re bogus");
		expect(h.notes.at(-1)).toBe('[error] omp-re: unknown /re subcommand "bogus" — try /re help');
		await h.session.prompt("/re undo");
		expect(h.notes.at(-1)).toBe("[error] omp-re: no annotation left to undo");
	});

	test("headless (omp -p), a /re error goes to stderr with a non-zero exit code instead of vanishing", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const headless = await boot(SessionManager.inMemory(), { headless: true });
		// What a headless run writes for a pipeline, taken here instead of this test run's own output and exit status.
		const { print, printError, failExit } = outside;
		const said: string[] = [];
		outside.print = (text) => void said.push(`stdout: ${text}`);
		outside.printError = (text) => void said.push(`stderr: ${text}`);
		outside.failExit = () => void said.push("exit status: failing");
		try {
			await headless.session.prompt("/re bogus");
			await headless.session.prompt("/re on");
			expect(said).toEqual(['stderr: omp-re: unknown /re subcommand "bogus" — try /re help', "exit status: failing", "stdout: omp-re: RE tools enabled for this session"]);
		} finally {
			Object.assign(outside, { print, printError, failExit });
			await headless.shutdown();
		}
	});

	test("a tool called with no binary open fails with omp-re's guidance", async () => {
		await expect(h.session.getToolByName("rizin_command")!.execute("t-nobin", { command: "aflj" })).rejects.toThrow("omp-re: no binary open");
	});
});

describe.skipIf(!canRunRizin)("loaded by omp's SDK, against rizin", () => {
	// Opens the binary (full `aaa`) once, then replays into a freshly reopened
	// session (another `aaa`); on a cold CI/container host each analysis is a
	// few seconds, so the default 5s budget is too tight.
	test("open, annotate, and resume through eval: the reopened session replays the annotation into a fresh rizin", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const sessionDir = join(agentDir(), "sessions");
		const first = await boot(SessionManager.create(tmpdir(), sessionDir));
		await first.session.sessionManager.ensureOnDisk();

		const opened = await evalJs(first.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })\nawait tool.rename_function({ addr: "main", new: "omp_re_sdk_main" })`);
		expect(opened.isError).toBe(false);
		const file = first.session.sessionManager.getSessionFile()!;
		await first.shutdown();

		const second = await boot(await SessionManager.open(file));
		try {
			// The engine records a read as evidence and says so twice: the id of the record as data, in the details a cell
			// gets beside the text, and for the model a last line of the text that shows the id's start.
			// (What a cell returns is cut for a model's eyes, so the cell answers the few things compared.)
			const result = await evalJs(
				second.session,
				'const r = await tool.rizin_command({ command: "afij", addr: "omp_re_sdk_main" }); const lines = r.text.split("\\n"); JSON.stringify({ id: r.details.evidenceId, first: lines[0], last: lines.at(-1), renamed: lines.slice(1, -1).join("").includes("omp_re_sdk_main") })',
			);
			const { id, first, last, renamed } = JSON.parse(result.text) as { id: string; first: string; last: string; renamed: boolean };
			expect(first).toBe("rizin> afij @ omp_re_sdk_main");
			expect(renamed).toBe(true); // the replayed rename shows in rizin's own output
			expect(last).toBe(`[evidence ${id.slice(0, 8)} — cite it in record_finding]`);
			const recorded = second.session.sessionManager
				.getEntries()
				.filter((e) => e.type === "custom" && (e as { customType?: string }).customType === "re.evidence")
				.map((e) => (e as { data?: { id: string; tool: string } }).data!);
			expect(recorded).toContainEqual(expect.objectContaining({ tool: "rizin_command", id }));
			// A read's text is header line, JSON body, then the [evidence] tag line: drop the first and last to parse
			// the body. Use a bounded command (afij = one function) so the size cap never truncates it to invalid JSON.
			const rows = await evalJs(second.session, 'const t = (await tool.rizin_command({ command: "afij", addr: "omp_re_sdk_main" })).text; JSON.parse(t.split("\\n").slice(1, -1).join("\\n")).length >= 1');
			expect(rows.text).toBe("true");
			expect(second.notes.filter((n) => n.startsWith("[runtime]"))).toEqual([]);
		} finally {
			await second.shutdown();
		}
	}, 30_000);

	test("a tool call made while --binary is still analyzing waits for that open instead of failing", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		// session_start opens the binary in the background; the call below is made before that open can have finished.
		const h = await boot(SessionManager.inMemory(), { flags: { binary: TEST_BINARY } });
		try {
			const result = await evalJs(h.session, '(await tool.rizin_command({ command: "ij" })).text');
			expect(result.isError).toBe(false);
			expect(result.text.startsWith("rizin> ij\n")).toBe(true); // the binary-needing call waited for the background open and ran
		} finally {
			await h.shutdown();
		}
	}, 30_000);

	test("/re status reports the rizin compatibility check, and rizin_command runs through the host", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const h = await boot(SessionManager.inMemory());
		try {
			await evalJs(h.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`);
			await h.session.prompt("/re status");
			// How many commands the engine sends grows as tool families are added: the shape, not a frozen number.
			expect(h.notes.at(-1)).toMatch(/rizin commands: all \d+ omp-re sends are present/);
			const result = await evalJs(h.session, '(await tool.rizin_command({ command: "pdsf", addr: "main" })).text');
			expect(result.text.startsWith("rizin> pdsf @ main\n")).toBe(true);
			// rizin_cli registers through the real runner when the rz-* tools are present (they ship with rizin).
			expect(h.session.getToolByName("rizin_cli")).toBeDefined();
		} finally {
			await h.shutdown();
		}
	});

	test("the debugger registers through the real runner only when opted in, and its enum schema loads", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const off = await boot(SessionManager.inMemory());
		try {
			expect(off.session.getToolByName("rizin_debug")).toBeUndefined();
		} finally {
			await off.shutdown();
		}

		const prev = process.env.OMPRE_ENABLE_DEBUGGER;
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		const on = await boot(SessionManager.inMemory());
		try {
			expect(on.session.getToolByName("rizin_debug")).toBeDefined();
			await evalJs(on.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`);
			expect((await evalJs(on.session, '(await tool.rizin_debug({ action: "start" })).text')).text).toContain("RUNNING under a debugger");
			await evalJs(on.session, 'await tool.rizin_debug({ action: "stop" })');
		} finally {
			await on.shutdown();
			if (prev === undefined) delete process.env.OMPRE_ENABLE_DEBUGGER;
			else process.env.OMPRE_ENABLE_DEBUGGER = prev;
		}
	}, 30_000); // two full SDK boots plus a real launch; the default 5s is too tight
});
